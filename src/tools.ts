import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { config, logger } from './config.js';
import type { StatsInput, VulnerabilityStore } from './store.js';

// MCP SDK 1.29.x: `inputSchema` accepts a raw zod shape (e.g. { k: z.string() })
// OR an AnySchema (e.g. z.object({...})). We use the raw shape form throughout —
// verified end-to-end via in-memory transport: the SDK converts the shape to a
// ZodObject internally and emits a correct JSON Schema in tools/list.
// Double-wrapping (passing `z.object(shape)` as inputSchema) also works in 1.29.0
// but produces noisier types; prefer raw shape.

const isoDate = (s: string): string => {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`invalid date: ${s}`);
  }
  return d.toISOString().slice(0, 10);
};

const DateString = z.string().transform(isoDate);
const SeverityEnum = z.preprocess(
  (v) => (typeof v === 'string' ? v.toLowerCase() : v),
  z.enum(['critical', 'high', 'medium', 'low']),
);
const StatusEnum = z.preprocess(
  (v) => (typeof v === 'string' ? v.toLowerCase() : v),
  z.enum(['open', 'patched']),
);

const PaginationShape = {
  limit: z.number().int().positive().optional().describe('Max items to return'),
  offset: z.number().int().min(0).optional().describe('Page offset'),
};

const VendorIdShape = {
  vendor_id: z.string().min(1).describe('Vendor primary key, e.g. "V1"'),
};

const GetVulnShape = {
  id: z.string().min(1).optional().describe('Internal record id, e.g. "CVE001"'),
  cve_id: z.string().min(1).optional().describe('Official CVE identifier, e.g. "CVE-2021-44228"'),
};

const ListVulnShape = {
  vendor_id: z.string().optional(),
  vendor_name: z.string().optional().describe('Case-insensitive substring match on vendor name'),
  severity: SeverityEnum.optional(),
  status: StatusEnum.optional(),
  title_contains: z.string().optional().describe('Case-insensitive substring match on title'),
  cve_contains: z.string().optional().describe('Case-insensitive substring match on CVE id'),
  affected_versions_contains: z
    .string()
    .optional()
    .describe('Substring match in the free-text affected_versions field'),
  min_cvss: z.number().min(0).max(10).optional(),
  max_cvss: z.number().min(0).max(10).optional(),
  published_after: DateString.optional().describe('Inclusive lower bound (YYYY-MM-DD or ISO)'),
  published_before: DateString.optional().describe('Inclusive upper bound (YYYY-MM-DD or ISO)'),
  year: z.number().int().optional(),
  sort_by: z.enum(['published', 'cvss_score']).optional(),
  sort_order: z.enum(['asc', 'desc']).optional(),
  ...PaginationShape,
};

const ListVendorsShape = {
  category: z.string().optional(),
  name_contains: z.string().optional(),
  ...PaginationShape,
};

const StatsShape = {
  group_by: z.enum(['severity', 'status', 'vendor', 'year']),
  filters: z
    .object({
      vendor_id: z.string().optional(),
      vendor_name: z.string().optional(),
      severity: SeverityEnum.optional(),
      status: StatusEnum.optional(),
      title_contains: z.string().optional(),
      cve_contains: z.string().optional(),
      min_cvss: z.number().min(0).max(10).optional(),
      max_cvss: z.number().min(0).max(10).optional(),
      published_after: DateString.optional(),
      published_before: DateString.optional(),
      year: z.number().int().optional(),
    })
    .strict()
    .optional(),
};

export function registerTools(server: McpServer, store: VulnerabilityStore): void {
  server.registerTool(
    'get_vendor',
    {
      description:
        'Fetch a single vendor by its primary id (e.g. "V1"). For searching vendors by name or category, use list_vendors.',
      inputSchema: VendorIdShape,
    },
    async ({ vendor_id }) => {
      try {
        const vendor = store.getVendor(vendor_id);
        if (!vendor) return notFound(`vendor_id=${vendor_id}`);
        return successResponse(vendor);
      } catch (err) {
        return unexpectedError('get_vendor', err);
      }
    },
  );

  server.registerTool(
    'list_vendors',
    {
      description:
        'List vendors, optionally filtered by category or substring of name. For a single vendor by id, use get_vendor.',
      inputSchema: ListVendorsShape,
    },
    async (args) => {
      try {
        const limit = clampLimit(args.limit);
        const result = store.listVendors({
          ...optional('category', args.category),
          ...optional('name_contains', args.name_contains),
          limit,
          offset: args.offset ?? 0,
        });
        return successResponse(result);
      } catch (err) {
        return unexpectedError('list_vendors', err);
      }
    },
  );

  server.registerTool(
    'get_vulnerability',
    {
      description:
        'Fetch a single vulnerability by internal id OR by official cve_id (e.g. "CVE-2021-44228"). Provide exactly one. For name/title searches (e.g. "Log4Shell") use list_vulnerabilities with title_contains instead.',
      inputSchema: GetVulnShape,
    },
    async ({ id, cve_id }) => {
      try {
        if ((id && cve_id) || (!id && !cve_id)) {
          return {
            isError: true,
            content: [
              {
                type: 'text',
                text: 'Provide exactly one of { id, cve_id }.',
              },
            ],
          };
        }
        const input = id ? { id } : { cve_id: cve_id! };
        const found = store.getVulnerability(input);
        if (!found) return notFound(id ? `id=${id}` : `cve_id=${cve_id}`);
        return successResponse(found);
      } catch (err) {
        return unexpectedError('get_vulnerability', err);
      }
    },
  );

  server.registerTool(
    'list_vulnerabilities',
    {
      description:
        'Search/filter vulnerabilities. Supports vendor (id or name substring), severity, status, title/CVE/version substring, CVSS range, date range, year, and sort by published or cvss_score. For counts or aggregates, use stats instead. Responses inline vendor metadata (id, name, category) under vendor.',
      inputSchema: ListVulnShape,
    },
    async (args) => {
      try {
        const limit = clampLimit(args.limit);
        const filters = {
          ...optional('vendor_id', args.vendor_id),
          ...optional('vendor_name', args.vendor_name),
          ...optional('severity', args.severity),
          ...optional('status', args.status),
          ...optional('title_contains', args.title_contains),
          ...optional('cve_contains', args.cve_contains),
          ...optional('affected_versions_contains', args.affected_versions_contains),
          ...optional('min_cvss', args.min_cvss),
          ...optional('max_cvss', args.max_cvss),
          ...optional('published_after', args.published_after),
          ...optional('published_before', args.published_before),
          ...optional('year', args.year),
          ...optional('sort_by', args.sort_by),
          ...optional('sort_order', args.sort_order),
          limit,
          offset: args.offset ?? 0,
        };
        const result = store.listVulnerabilities(filters);
        return successResponse(result);
      } catch (err) {
        return unexpectedError('list_vulnerabilities', err);
      }
    },
  );

  server.registerTool(
    'stats',
    {
      description:
        'Count vulnerabilities grouped by severity, status, vendor, or published year. Use this for ALL "how many" / count questions — much more efficient than fetching records and counting client-side. Supports the same filters as list_vulnerabilities (without pagination/sort).',
      inputSchema: StatsShape,
    },
    async (args) => {
      try {
        const cleanFilters = args.filters
          ? (stripUndefined(args.filters) as StatsInput['filters'])
          : undefined;
        const result = store.stats({
          group_by: args.group_by,
          ...(cleanFilters ? { filters: cleanFilters } : {}),
        });
        return successResponse(result);
      } catch (err) {
        return unexpectedError('stats', err);
      }
    },
  );
}

function optional<K extends string, V>(key: K, value: V | undefined): Partial<Record<K, V>> {
  return value === undefined ? {} : ({ [key]: value } as Partial<Record<K, V>>);
}

function stripUndefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  }
  return out;
}

export function successResponse(result: unknown): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    structuredContent: { result } as Record<string, unknown>,
  };
}

export function unexpectedError(tool: string, err: unknown): CallToolResult {
  logger.error(`tool ${tool} threw`, err);
  const msg = err instanceof Error ? err.message : String(err);
  return {
    isError: true,
    content: [{ type: 'text', text: `Internal error in ${tool}: ${msg}` }],
  };
}

export function notFound(msg: string): CallToolResult {
  return { isError: true, content: [{ type: 'text', text: `Not found: ${msg}` }] };
}

export function clampLimit(limit: number | undefined): number {
  const lim = limit ?? config.defaultPageLimit;
  return Math.min(Math.max(lim, 1), config.maxPageLimit);
}
