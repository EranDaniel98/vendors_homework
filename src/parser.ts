import { readFile } from 'node:fs/promises';
import { logger } from './config.js';
import type { ParseError, ParseResult } from './types.js';

const BOM = '\uFEFF';

export async function parseDbFile(absPath: string): Promise<ParseResult> {
  const raw = await readFile(absPath, 'utf8');
  const text = raw.startsWith(BOM) ? raw.slice(1) : raw;
  const lines = text.split(/\r?\n/);

  let version: string | null = null;
  let columns: string[] | null = null;
  let sawMetadata = false;

  let dataStart = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    if (trimmed === '') {
      continue;
    }
    if (!trimmed.startsWith('#')) {
      dataStart = i;
      break;
    }
    const body = trimmed.replace(/^#\s*/, '');
    if (body === 'METADATA') {
      sawMetadata = true;
      continue;
    }
    const colon = body.indexOf(':');
    if (colon === -1) continue;
    const key = body.slice(0, colon).trim().toUpperCase();
    const value = body.slice(colon + 1).trim();
    if (key === 'FORMAT') {
      columns = value.split('|').map((c) => c.trim());
    } else if (key === 'VERSION') {
      version = value;
    }
  }

  if (!sawMetadata) {
    throw new Error(`Missing '# METADATA' header in ${absPath}`);
  }
  if (columns === null || columns.length === 0) {
    throw new Error(`Missing '# FORMAT:' header in ${absPath}`);
  }
  if (version === null) {
    throw new Error(`Missing '# VERSION:' header in ${absPath}`);
  }
  if (columns[0] !== 'type') {
    throw new Error(
      `Expected 'type' as column 0 in FORMAT header of ${absPath}, got '${columns[0]}'`,
    );
  }

  const rows: Record<string, string>[] = [];
  const errors: ParseError[] = [];

  for (let i = dataStart; i < lines.length; i++) {
    const raw = lines[i] ?? '';
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const parts = trimmed.split('|');
    if (parts.length !== columns.length) {
      const err: ParseError = {
        line: i + 1,
        raw: trimmed,
        reason: `expected ${columns.length} columns, got ${parts.length}`,
      };
      errors.push(err);
      logger.error(`parse: malformed row in ${absPath}:${err.line}`, err);
      continue;
    }

    const row: Record<string, string> = {};
    for (let c = 0; c < columns.length; c++) {
      const key = columns[c] ?? '';
      row[key] = (parts[c] ?? '').trim();
    }
    rows.push(row);
  }

  return { version, columns, rows, errors };
}
