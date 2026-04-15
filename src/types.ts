export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Status = 'open' | 'patched';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'] as const;
export const STATUSES: readonly Status[] = ['open', 'patched'] as const;

export interface Vendor {
  id: string;
  name: string;
  category: string;
  hq: string;
  founded: number;
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  vendor_id: string;
  severity: Severity;
  cvss_score: number;
  affected_versions: string;
  status: Status;
  published: string;
  publishedYear: number;
}

export type VendorRef = Pick<Vendor, 'id' | 'name' | 'category'>;

export interface VulnerabilityWithVendor extends Vulnerability {
  vendor: VendorRef | null;
}

export interface ParseError {
  line: number;
  raw: string;
  reason: string;
}

export interface ParseResult {
  version: string;
  columns: string[];
  rows: Record<string, string>[];
  errors: ParseError[];
}

export interface PageInfo {
  total: number;
  limit: number;
  offset: number;
}

export interface ListResult<T> extends PageInfo {
  items: T[];
}

export type StatsGroupBy = 'severity' | 'status' | 'vendor' | 'year';

export interface StatsResult {
  total: number;
  group_by: StatsGroupBy;
  groups: { key: string; count: number }[];
}
