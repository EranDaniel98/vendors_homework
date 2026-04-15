import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { parseDbFile } from '../src/parser.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, 'fixtures');

test('parses vendors fixture header dynamically', async () => {
  const result = await parseDbFile(path.join(fixtures, 'vendors.db'));
  assert.equal(result.version, '1.0');
  assert.deepEqual(result.columns, ['type', 'id', 'name', 'category', 'hq', 'founded']);
  assert.equal(result.rows.length, 2);
  assert.equal(result.rows[0]?.id, 'V1');
  assert.equal(result.rows[0]?.name, 'Acme');
  assert.equal(result.errors.length, 0);
});

test('malformed row populates errors[] without throwing; good rows survive', async () => {
  const result = await parseDbFile(path.join(fixtures, 'vulnerabilities.db'));
  assert.equal(result.rows.length, 4);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0]!.reason, /expected 10 columns/);
});

test('missing FORMAT header throws with path in message', async () => {
  await assert.rejects(
    () => parseDbFile(path.join(fixtures, 'missing_format.db')),
    /Missing '# FORMAT:'/,
  );
});

test('BOM prefix and CRLF line endings are tolerated', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vuln-parser-'));
  const file = path.join(dir, 'bom.db');
  const content =
    '\uFEFF# METADATA\r\n' +
    '# FORMAT: type|id|name|category|hq|founded\r\n' +
    '# VERSION: 2.1\r\n' +
    '\r\n' +
    'VENDOR|V1|Acme|Software|HQ|1990\r\n';
  await writeFile(file, content, 'utf8');
  try {
    const result = await parseDbFile(file);
    assert.equal(result.version, '2.1');
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0]?.name, 'Acme');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('throws when column 0 is not "type"', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'vuln-parser-'));
  const file = path.join(dir, 'bad.db');
  await writeFile(
    file,
    '# METADATA\n# FORMAT: id|name\n# VERSION: 1.0\n\nVENDOR|V1|Acme\n',
    'utf8',
  );
  try {
    await assert.rejects(() => parseDbFile(file), /column 0/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
