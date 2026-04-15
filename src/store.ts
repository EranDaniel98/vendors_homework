import { logger } from './config.js';
import { parseDbFile } from './parser.js';
import {
  SEVERITIES,
  STATUSES,
  type ListResult,
  type Severity,
  type StatsGroupBy,
  type StatsResult,
  type Status,
  type Vendor,
  type VendorRef,
  type Vulnerability,
  type VulnerabilityWithVendor,
} from './types.js';

export interface ListVulnerabilitiesFilters {
  vendor_id?: string;
  vendor_name?: string;
  severity?: Severity;
  status?: Status;
  title_contains?: string;
  cve_contains?: string;
  affected_versions_contains?: string;
  min_cvss?: number;
  max_cvss?: number;
  published_after?: string;
  published_before?: string;
  year?: number;
  sort_by?: 'published' | 'cvss_score';
  sort_order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

export interface ListVendorsFilters {
  category?: string;
  name_contains?: string;
  limit?: number;
  offset?: number;
}

export interface StatsInput {
  group_by: StatsGroupBy;
  filters?: Omit<ListVulnerabilitiesFilters, 'sort_by' | 'sort_order' | 'limit' | 'offset'>;
}

export interface GetVulnerabilityInput {
  id?: string;
  cve_id?: string;
}

const REQUIRED_VENDOR_COLS = ['type', 'id', 'name', 'category', 'hq', 'founded'];
const REQUIRED_VULN_COLS = [
  'type',
  'id',
  'cve_id',
  'title',
  'vendor_id',
  'severity',
  'cvss_score',
  'affected_versions',
  'status',
  'published',
];

function requireColumns(found: string[], required: string[], file: string): void {
  const missing = required.filter((c) => !found.includes(c));
  if (missing.length > 0) {
    throw new Error(`Missing required columns in ${file}: ${missing.join(', ')}`);
  }
}

function isSeverity(v: string): v is Severity {
  return (SEVERITIES as readonly string[]).includes(v);
}

function isStatus(v: string): v is Status {
  return (STATUSES as readonly string[]).includes(v);
}

export class VulnerabilityStore {
  readonly vendors = new Map<string, Vendor>();
  readonly vulns = new Map<string, Vulnerability>();
  readonly byCve = new Map<string, Vulnerability>();
  readonly byVendor = new Map<string, Vulnerability[]>();
  readonly bySeverity = new Map<Severity, Vulnerability[]>();
  readonly byStatus = new Map<Status, Vulnerability[]>();

  get vendorCount(): number {
    return this.vendors.size;
  }

  get vulnCount(): number {
    return this.vulns.size;
  }

  async load(vendorsPath: string, vulnsPath: string): Promise<void> {
    const vendorsParse = await parseDbFile(vendorsPath);
    requireColumns(vendorsParse.columns, REQUIRED_VENDOR_COLS, vendorsPath);

    for (const row of vendorsParse.rows) {
      if (row.type !== 'VENDOR') {
        logger.error('load: non-VENDOR row in vendors file', { id: row.id, type: row.type });
        continue;
      }
      const founded = Number(row.founded);
      if (!Number.isFinite(founded)) {
        logger.error('load: invalid founded year, skipping vendor', { id: row.id });
        continue;
      }
      const vendor: Vendor = {
        id: row.id ?? '',
        name: row.name ?? '',
        category: row.category ?? '',
        hq: row.hq ?? '',
        founded,
      };
      if (!vendor.id) {
        logger.error('load: vendor missing id, skipping', row);
        continue;
      }
      this.vendors.set(vendor.id, vendor);
    }

    const vulnsParse = await parseDbFile(vulnsPath);
    requireColumns(vulnsParse.columns, REQUIRED_VULN_COLS, vulnsPath);

    const missingVendorRefs = new Set<string>();

    for (const row of vulnsParse.rows) {
      if (row.type !== 'VULN') {
        logger.error('load: non-VULN row in vulnerabilities file', { id: row.id, type: row.type });
        continue;
      }
      const severity = (row.severity ?? '').toLowerCase();
      const status = (row.status ?? '').toLowerCase();
      if (!isSeverity(severity)) {
        logger.error('load: unknown severity, skipping vuln', { id: row.id, severity });
        continue;
      }
      if (!isStatus(status)) {
        logger.error('load: unknown status, skipping vuln', { id: row.id, status });
        continue;
      }
      const cvss = Number(row.cvss_score);
      if (!Number.isFinite(cvss)) {
        logger.error('load: invalid cvss_score, skipping vuln', { id: row.id });
        continue;
      }
      const published = row.published ?? '';
      const year = Number(published.slice(0, 4));
      if (!Number.isFinite(year)) {
        logger.error('load: invalid published year, skipping vuln', { id: row.id, published });
        continue;
      }
      const vuln: Vulnerability = {
        id: row.id ?? '',
        cve_id: row.cve_id ?? '',
        title: row.title ?? '',
        vendor_id: row.vendor_id ?? '',
        severity,
        cvss_score: cvss,
        affected_versions: row.affected_versions ?? '',
        status,
        published,
        publishedYear: year,
      };
      if (!vuln.id) {
        logger.error('load: vuln missing id, skipping', row);
        continue;
      }

      this.vulns.set(vuln.id, vuln);
      if (vuln.cve_id) this.byCve.set(vuln.cve_id, vuln);

      if (!this.vendors.has(vuln.vendor_id)) {
        missingVendorRefs.add(vuln.vendor_id);
      }

      pushToMap(this.byVendor, vuln.vendor_id, vuln);
      pushToMap(this.bySeverity, vuln.severity, vuln);
      pushToMap(this.byStatus, vuln.status, vuln);
    }

    if (missingVendorRefs.size > 0) {
      logger.info('load: some vulns reference unknown vendor_ids', {
        count: missingVendorRefs.size,
        ids: [...missingVendorRefs],
      });
    }
  }

  private vendorRef(vendor_id: string): VendorRef | null {
    const v = this.vendors.get(vendor_id);
    if (!v) return null;
    return { id: v.id, name: v.name, category: v.category };
  }

  private withVendor(v: Vulnerability): VulnerabilityWithVendor {
    return { ...v, vendor: this.vendorRef(v.vendor_id) };
  }

  getVendor(id: string): Vendor | null {
    return this.vendors.get(id) ?? null;
  }

  listVendors(filters: ListVendorsFilters = {}): ListResult<Vendor> {
    const { category, name_contains, limit, offset } = filters;
    let items = [...this.vendors.values()];
    if (category) {
      const cLow = category.toLowerCase();
      items = items.filter((v) => v.category.toLowerCase() === cLow);
    }
    if (name_contains) {
      const n = name_contains.toLowerCase();
      items = items.filter((v) => v.name.toLowerCase().includes(n));
    }
    const total = items.length;
    const off = offset ?? 0;
    const lim = limit ?? total;
    return { items: items.slice(off, off + lim), total, limit: lim, offset: off };
  }

  getVulnerability(input: GetVulnerabilityInput): VulnerabilityWithVendor | null {
    const { id, cve_id } = input;
    if ((id && cve_id) || (!id && !cve_id)) {
      throw new Error('get_vulnerability requires exactly one of { id, cve_id }');
    }
    const found = id ? this.vulns.get(id) : cve_id ? this.byCve.get(cve_id) : undefined;
    return found ? this.withVendor(found) : null;
  }

  listVulnerabilities(filters: ListVulnerabilitiesFilters = {}): ListResult<VulnerabilityWithVendor> {
    let items = this.filterVulns(filters);

    const sortBy = filters.sort_by;
    if (sortBy) {
      const dir = filters.sort_order === 'asc' ? 1 : -1;
      items = [...items].sort((a, b) => {
        if (sortBy === 'cvss_score') return (a.cvss_score - b.cvss_score) * dir;
        return a.published < b.published ? -dir : a.published > b.published ? dir : 0;
      });
    }

    const total = items.length;
    const off = filters.offset ?? 0;
    const lim = filters.limit ?? total;
    const page = items.slice(off, off + lim).map((v) => this.withVendor(v));
    return { items: page, total, limit: lim, offset: off };
  }

  stats(input: StatsInput): StatsResult {
    const items = this.filterVulns(input.filters ?? {});
    const counts = new Map<string, number>();

    for (const v of items) {
      const key = this.groupKey(v, input.group_by);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }

    const groups = [...counts.entries()]
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));

    return { total: items.length, group_by: input.group_by, groups };
  }

  private groupKey(v: Vulnerability, by: StatsGroupBy): string {
    switch (by) {
      case 'severity':
        return v.severity;
      case 'status':
        return v.status;
      case 'year':
        return String(v.publishedYear);
      case 'vendor': {
        const ref = this.vendors.get(v.vendor_id);
        return ref ? ref.name : `unknown:${v.vendor_id}`;
      }
    }
  }

  private filterVulns(f: ListVulnerabilitiesFilters): Vulnerability[] {
    const base: Vulnerability[] = f.vendor_id
      ? (this.byVendor.get(f.vendor_id) ?? [])
      : f.severity
        ? (this.bySeverity.get(f.severity) ?? [])
        : f.status
          ? (this.byStatus.get(f.status) ?? [])
          : [...this.vulns.values()];

    const vendorNameLow = f.vendor_name?.toLowerCase();
    const titleLow = f.title_contains?.toLowerCase();
    const cveLow = f.cve_contains?.toLowerCase();
    const versLow = f.affected_versions_contains?.toLowerCase();

    const matchedVendorIds = vendorNameLow
      ? new Set(
          [...this.vendors.values()]
            .filter((v) => v.name.toLowerCase().includes(vendorNameLow))
            .map((v) => v.id),
        )
      : null;

    return base.filter((v) => {
      if (f.vendor_id && v.vendor_id !== f.vendor_id) return false;
      if (f.severity && v.severity !== f.severity) return false;
      if (f.status && v.status !== f.status) return false;
      if (matchedVendorIds && !matchedVendorIds.has(v.vendor_id)) return false;
      if (titleLow && !v.title.toLowerCase().includes(titleLow)) return false;
      if (cveLow && !v.cve_id.toLowerCase().includes(cveLow)) return false;
      if (versLow && !v.affected_versions.toLowerCase().includes(versLow)) return false;
      if (f.min_cvss !== undefined && v.cvss_score < f.min_cvss) return false;
      if (f.max_cvss !== undefined && v.cvss_score > f.max_cvss) return false;
      if (f.published_after && v.published < f.published_after) return false;
      if (f.published_before && v.published > f.published_before) return false;
      if (f.year !== undefined && v.publishedYear !== f.year) return false;
      return true;
    });
  }
}

function pushToMap<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const arr = map.get(key);
  if (arr) arr.push(value);
  else map.set(key, [value]);
}
