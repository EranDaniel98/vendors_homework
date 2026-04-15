import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { VulnerabilityStore } from '../src/store.js';
import { registerTools } from '../src/tools.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, 'fixtures');

interface CallToolArgs {
  [key: string]: unknown;
}

interface ToolContent {
  type: string;
  text?: string;
}

interface CallToolResp {
  content?: ToolContent[];
  structuredContent?: unknown;
  isError?: boolean;
}

async function setup(): Promise<{
  client: Client;
  server: McpServer;
  close: () => Promise<void>;
}> {
  const store = new VulnerabilityStore();
  await store.load(path.join(fixtures, 'vendors.db'), path.join(fixtures, 'vulnerabilities.db'));

  const server = new McpServer({ name: 'test', version: '0.0.0' });
  registerTools(server, store);

  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'c', version: '0' });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);

  return {
    client,
    server,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

async function call(client: Client, name: string, args: CallToolArgs): Promise<CallToolResp> {
  return (await client.callTool({ name, arguments: args })) as CallToolResp;
}

test('tools/list exposes exactly five tools with populated schemas', async () => {
  const { client, close } = await setup();
  try {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 5);
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, [
      'get_vendor',
      'get_vulnerability',
      'list_vendors',
      'list_vulnerabilities',
      'stats',
    ]);
    for (const t of tools) {
      assert.equal(t.inputSchema.type, 'object');
      assert.ok(t.description && t.description.length > 0);
    }
  } finally {
    await close();
  }
});

test('list_vulnerabilities with vendor_id + severity returns expected subset', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vulnerabilities', {
      vendor_id: 'V1',
      severity: 'CRITICAL',
    });
    assert.equal(res.isError, undefined);
    const text = res.content?.[0]?.text ?? '';
    const parsed = JSON.parse(text);
    assert.equal(parsed.total, 1);
    assert.equal(parsed.items[0].cve_id, 'CVE-2023-0001');
    assert.equal(parsed.items[0].vendor.name, 'Acme');
  } finally {
    await close();
  }
});

test('stats with no filter totals equal vuln count', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'stats', { group_by: 'severity' });
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    assert.equal(parsed.total, 4);
    const sum = parsed.groups.reduce((a: number, g: { count: number }) => a + g.count, 0);
    assert.equal(sum, 4);
  } finally {
    await close();
  }
});

test('get_vulnerability with unknown cve_id returns isError', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'get_vulnerability', { cve_id: 'CVE-X-NONE' });
    assert.equal(res.isError, true);
    assert.match(res.content?.[0]?.text ?? '', /Not found/);
  } finally {
    await close();
  }
});

test('get_vulnerability with both id and cve_id is a tool error', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'get_vulnerability', { id: 'CVE001', cve_id: 'CVE-X' });
    assert.equal(res.isError, true);
  } finally {
    await close();
  }
});

test('list_vulnerabilities with no match returns empty, not an error', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vulnerabilities', { title_contains: 'nothing-matches' });
    assert.equal(res.isError, undefined);
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    assert.equal(parsed.total, 0);
    assert.deepEqual(parsed.items, []);
  } finally {
    await close();
  }
});

test('list_vulnerabilities sort_by cvss_score desc returns sorted result', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vulnerabilities', {
      sort_by: 'cvss_score',
      sort_order: 'desc',
    });
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    for (let i = 1; i < parsed.items.length; i++) {
      assert.ok(parsed.items[i - 1].cvss_score >= parsed.items[i].cvss_score);
    }
  } finally {
    await close();
  }
});

test('get_vendor success path exposes structuredContent', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'get_vendor', { vendor_id: 'V1' });
    assert.equal(res.isError, undefined);
    assert.ok(res.structuredContent);
    const text = res.content?.[0]?.text ?? '';
    assert.match(text, /Acme/);
  } finally {
    await close();
  }
});

test('stats with filters scopes the count', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'stats', {
      group_by: 'severity',
      filters: { vendor_id: 'V1' },
    });
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    assert.equal(parsed.total, 2);
  } finally {
    await close();
  }
});

test('list_vendors with name_contains filter', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vendors', { name_contains: 'acme' });
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    assert.equal(parsed.total, 1);
    assert.equal(parsed.items[0].id, 'V1');
  } finally {
    await close();
  }
});

test('list_vulnerabilities with date range filter', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vulnerabilities', {
      published_after: '2024-01-01',
      published_before: '2024-12-31',
    });
    const parsed = JSON.parse(res.content?.[0]?.text ?? '');
    for (const v of parsed.items) {
      assert.ok(v.published >= '2024-01-01' && v.published <= '2024-12-31');
    }
  } finally {
    await close();
  }
});

test('list_vulnerabilities severity enum rejects invalid values', async () => {
  const { client, close } = await setup();
  try {
    const res = await call(client, 'list_vulnerabilities', { severity: 'super-bad' });
    assert.equal(res.isError, true);
  } finally {
    await close();
  }
});
