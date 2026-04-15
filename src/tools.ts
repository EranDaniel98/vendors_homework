import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { config, logger } from './config.js';
import type { VulnerabilityStore } from './store.js';

// MCP SDK 1.29.x accepts either a raw zod shape or a z.object() for inputSchema.
// We use the raw shape form — simpler, and double-wrapping nests the schema
// under a `{ <paramName>: { type: 'object', ... } }` that never validates.
// Verified against @modelcontextprotocol/sdk 1.29.0.

const VendorIdShape = {
  vendor_id: z.string().min(1).describe('Vendor primary key, e.g. "V1"'),
};

export function registerTools(server: McpServer, store: VulnerabilityStore): void {
  server.registerTool(
    'get_vendor',
    {
      description:
        'Fetch a single vendor by its primary id (e.g. "V1"). For searching vendors by name or category, use list_vendors with name_contains or category.',
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
