import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { VulnerabilityStore } from '../src/store.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, 'fixtures');

async function loadStore(): Promise<VulnerabilityStore> {
  const s = new VulnerabilityStore();
  await s.load(path.join(fixtures, 'vendors.db'), path.join(fixtures, 'vulnerabilities.db'));
  return s;
}

test('load populates all maps', async () => {
  const s = await loadStore();
  assert.equal(s.vendorCount, 2);
  assert.equal(s.vulnCount, 4);
  assert.equal(s.byCve.size, 4);
  assert.equal(s.byVendor.get('V1')?.length, 2);
  assert.equal(s.bySeverity.get('critical')?.length, 1);
  assert.equal(s.byStatus.get('open')?.length, 3);
});

test('FK join: unknown vendor_id yields vendor: null', async () => {
  const s = await loadStore();
  const result = s.listVulnerabilities({ cve_contains: 'CVE-2024-0004' });
  assert.equal(result.total, 1);
  assert.equal(result.items[0]?.vendor, null);
});

test('severity filter is case-insensitive via coerced store values', async () => {
  const s = await loadStore();
  const res = s.listVulnerabilities({ severity: 'critical' });
  assert.equal(res.total, 1);
  assert.equal(res.items[0]?.cve_id, 'CVE-2023-0001');
});

test('stats by severity totals equal vuln count', async () => {
  const s = await loadStore();
  const stats = s.stats({ group_by: 'severity' });
  assert.equal(stats.total, s.vulnCount);
  const sum = stats.groups.reduce((a, g) => a + g.count, 0);
  assert.equal(sum, s.vulnCount);
});

test('get_vulnerability requires exactly one id/cve_id', async () => {
  const s = await loadStore();
  assert.throws(() => s.getVulnerability({}), /exactly one/);
  assert.throws(() => s.getVulnerability({ id: 'CVE001', cve_id: 'x' }), /exactly one/);
  assert.equal(s.getVulnerability({ cve_id: 'missing' }), null);
  const found = s.getVulnerability({ cve_id: 'CVE-2023-0001' });
  assert.equal(found?.id, 'CVE001');
  assert.equal(found?.vendor?.name, 'Acme');
});

test('sort_by cvss_score desc returns highest first', async () => {
  const s = await loadStore();
  const res = s.listVulnerabilities({ sort_by: 'cvss_score', sort_order: 'desc' });
  assert.ok(res.items[0]!.cvss_score >= res.items[1]!.cvss_score);
});

test('year filter selects only matching year', async () => {
  const s = await loadStore();
  const res = s.listVulnerabilities({ year: 2024 });
  assert.ok(res.total >= 1);
  for (const v of res.items) {
    assert.equal(v.publishedYear, 2024);
  }
});

test('vendor_name substring filter resolves via vendor map', async () => {
  const s = await loadStore();
  const res = s.listVulnerabilities({ vendor_name: 'acme' });
  assert.ok(res.total >= 1);
  for (const v of res.items) {
    assert.equal(v.vendor_id, 'V1');
  }
});
