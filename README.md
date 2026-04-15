# Vulnerability Registry MCP Server

> Read-only MCP server over a legacy pipe-delimited CVE + vendor registry.

![Node](https://img.shields.io/badge/node-%3E%3D20-3c873a)
![MCP SDK](https://img.shields.io/badge/%40modelcontextprotocol%2Fsdk-%5E1.0.4-6e40c9)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen)

## TL;DR

TypeScript MCP server that parses `vendors.db` and `vulnerabilities.db` (pipe-delimited, dynamic `# FORMAT:` header) into memory and serves them over stdio. Intended to be called by an MCP-compatible LLM client such as Claude Desktop. Exposes **5 tools**: `get_vendor`, `list_vendors`, `get_vulnerability`, `list_vulnerabilities`, `stats`.

## Quickstart

```bash
git clone https://github.com/EranDaniel98/vendors_homework.git
cd vendors_homework
npm install
npm run build
node dist/index.js
```

The server speaks stdio — it isn't useful on its own. Point an MCP client at the built `dist/index.js`; see [Claude Desktop integration (Phase 2)](#claude-desktop-integration-phase-2) for the exact config block.

## Table of contents

- [Quickstart](#quickstart)
- [Tools](#tools)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Example questions](#example-questions)
- [Claude Desktop integration (Phase 2)](#claude-desktop-integration-phase-2)
- [Design notes](#design-notes)
- [With more time](#with-more-time)
- [Known limitations](#known-limitations)

## Tools

All tools return a dual-shape response: a pretty-printed JSON `text` block for human/Claude-Desktop rendering, plus a `structuredContent.result` object for clients that consume the MCP 2025-06 structured-content extension. List tools return `{ items, total, limit, offset }`; all string filters use case-insensitive substring matching unless noted otherwise.

### `get_vendor`

Fetch a single vendor by its primary id.

| Param | Type | Required | Notes |
|---|---|---|---|
| `vendor_id` | string | yes | Vendor primary key, e.g. `"V1"` |

**Returns:** the vendor record as a single object under `result`.
**Errors:** `isError: true` with `Not found: vendor_id=...` when the id is unknown; zod `-32602` for schema violations.

### `list_vendors`

List vendors, optionally filtered by category or name substring.

| Param | Type | Required | Notes |
|---|---|---|---|
| `category` | string | no | Filter by category |
| `name_contains` | string | no | Substring match on vendor name |
| `limit` | integer | no | Max items to return (clamped to `MAX_PAGE_LIMIT`) |
| `offset` | integer | no | Page offset (>= 0) |

**Returns:** `{ items, total, limit, offset }` under `result`.
**Errors:** zod `-32602` for protocol errors (e.g. unknown top-level keys, wrong types); never `isError` for empty matches.

### `get_vulnerability`

Fetch a single vulnerability by internal id or by official CVE id — provide exactly one.

| Param | Type | Required | Notes |
|---|---|---|---|
| `id` | string | no\* | Internal record id, e.g. `"CVE001"` |
| `cve_id` | string | no\* | Official CVE identifier, e.g. `"CVE-2021-44228"` |

\* Exactly one of `id` or `cve_id` must be supplied.

**Returns:** the vulnerability record with inlined `vendor` metadata (`id`, `name`, `category`) under `result`.
**Errors:** `isError: true` with `Provide exactly one of { id, cve_id }.` when both or neither are given; `isError: true` with `Not found: ...` when no record matches; zod `-32602` for schema violations.

### `list_vulnerabilities`

Search and filter vulnerabilities with sort and pagination; vendor metadata is inlined on every item.

| Param | Type | Required | Notes |
|---|---|---|---|
| `vendor_id` | string | no | Exact vendor id match |
| `vendor_name` | string | no | Case-insensitive substring match on vendor name |
| `severity` | enum | no | `critical` \| `high` \| `medium` \| `low` (case-insensitive) |
| `status` | enum | no | `open` \| `patched` (case-insensitive) |
| `title_contains` | string | no | Case-insensitive substring match on title |
| `cve_contains` | string | no | Case-insensitive substring match on CVE id |
| `affected_versions_contains` | string | no | Substring match in the free-text `affected_versions` field |
| `min_cvss` | number | no | 0–10 |
| `max_cvss` | number | no | 0–10 |
| `published_after` | date | no | Inclusive lower bound (YYYY-MM-DD or ISO) |
| `published_before` | date | no | Inclusive upper bound (YYYY-MM-DD or ISO) |
| `year` | integer | no | Filter by published year |
| `sort_by` | enum | no | `published` \| `cvss_score` |
| `sort_order` | enum | no | `asc` \| `desc` |
| `limit` | integer | no | Max items to return (clamped to `MAX_PAGE_LIMIT`) |
| `offset` | integer | no | Page offset (>= 0) |

**Returns:** `{ items, total, limit, offset }` under `result`, each item with inlined `vendor`.
**Errors:** zod `-32602` for protocol errors (unknown keys, invalid enum, bad date, CVSS out of range); empty matches return `{ items: [], total: 0 }`, not an error.

### `stats`

Count vulnerabilities grouped by a facet, using the same filter set as `list_vulnerabilities` (no sort/pagination).

| Param | Type | Required | Notes |
|---|---|---|---|
| `group_by` | enum | yes | `severity` \| `status` \| `vendor` \| `year` |
| `filters` | object | no | Subset of `list_vulnerabilities` filters: `vendor_id`, `vendor_name`, `severity`, `status`, `title_contains`, `cve_contains`, `min_cvss`, `max_cvss`, `published_after`, `published_before`, `year` |

**Returns:** `{ total, group_by, groups: [{ key, count }] }` under `result`, sorted by count desc.
**Errors:** zod `-32602` for protocol errors (missing `group_by`, unknown keys in `filters`, invalid enum or date).

## Architecture

### Project layout

```
vendors_homework/
  src/                               — TypeScript source for the MCP server
    index.ts                         — entry point; boots store, wires stdio transport
    config.ts                        — sole reader of process.env; exports config + stderr logger
    parser.ts                        — parses pipe-delimited .db files using the # FORMAT: header
    store.ts                         — in-memory VulnerabilityStore with Maps + secondary indexes
    tools.ts                         — registers the 5 MCP tools and their zod input schemas
    types.ts                         — shared domain types (Vendor, Vulnerability, enums)
  data/                              — runtime data files loaded at startup
    vendors.db                       — VENDOR records (id, name, category, hq, founded)
    vulnerabilities.db               — VULN records, vendor_id FK into vendors.db
  tests/                             — node --test suites (no extra runner)
    fixtures/                        — small .db files for parser/store tests
    parser.test.ts                   — header parsing + row splitting + BOM/CRLF
    store.test.ts                    — load, filter, sort, stats, pagination
    tools.test.ts                    — full MCP round-trip via in-memory transport
  docs/                              — specs and design notes
    english_instruction.md           — authoritative homework spec
    hebrew_instruction.md            — mirror of spec (HE)
    DECISIONS.md                     — architecture decision log
  claude_desktop_config.sample.json  — example MCP client config for Claude Desktop
  package.json / tsconfig.json       — scripts + deps + TS compiler config (ESM, NodeNext)
  eslint.config.js / .prettierrc     — lint + format config
  .github/workflows/ci.yml           — CI: lint + build + tests (Node 20 + 22)
```

### Request flow

```
stdin (JSON-RPC)
    |
    v
[StdioServerTransport] --> [McpServer: index.ts]
                                |
                                v
                        [tools.ts: zod-validated handler]
                                |
                                v
                        [store.ts: VulnerabilityStore]
                                |
                                v
   in-memory Maps: vendors, vulns, byCve, byVendor, bySeverity, byStatus
                                |
                                v
                        [tools.ts: shape JSON response]
                                |
                                v
                     stdout (JSON-RPC)     stderr (logs)
```

- Load-once at startup: both `.db` files are parsed into Maps in `VulnerabilityStore.load()`; no per-request re-reads.
- Queries are O(1) point lookups (`getVendor`, `getVulnerability` by id/cve) or O(n) scans over pre-bucketed secondary indexes (`byVendor`, `bySeverity`, `byStatus`).
- stdout is reserved for JSON-RPC frames; all logging goes to stderr via `logger` in `config.ts`.
- Only `src/config.ts` reads `process.env` — everything else receives values through the exported `config` object.

## Configuration

Environment variables are validated at startup via zod (see `src/config.ts`); invalid values abort the process with a descriptive error. `src/config.ts` is the only file permitted to read `process.env` — enforced by an ESLint `no-restricted-properties` rule.

| Variable | Default | Description |
| --- | --- | --- |
| `VULN_DB_DIR` | `<repo>/data` | Directory containing the two `.db` files. Resolved to an absolute path. |
| `VENDORS_FILE` | `vendors.db` | Vendor master filename, resolved relative to `VULN_DB_DIR`. |
| `VULNS_FILE` | `vulnerabilities.db` | Vulnerability records filename, resolved relative to `VULN_DB_DIR`. |
| `SERVER_NAME` | `vulnerability-registry` | MCP server name advertised on the initialize handshake. |
| `SERVER_VERSION` | `1.0.0` | MCP server version advertised on the initialize handshake. |
| `DEFAULT_PAGE_LIMIT` | `50` | Page size used when a tool call omits `limit`. |
| `MAX_PAGE_LIMIT` | `500` | Hard ceiling for `limit`; larger values are clamped. |
| `LOG_LEVEL` | `info` | One of `silent`, `error`, `info`, `debug`. Logs go to stderr. |

## Example questions

Sample answers below are grounded in the actual `data/*.db` shipped with the repo.

1. *"How many critical vulnerabilities are still open?"*
   `stats({ group_by: 'severity', filters: { status: 'open' } })`
   → `groups` includes `{ key: 'critical', count: 2 }` (CVE-2024-27198 TeamCity, CVE-2024-21762 Fortinet).

2. *"What's the CVSS score of Log4Shell?"*
   `list_vulnerabilities({ title_contains: 'Log4Shell' })`
   → 1 match, CVE-2021-44228, `cvss_score: 10.0`, vendor Apache Software Foundation, status patched.

3. *"Which CVEs were found in the Linux Kernel?"*
   `list_vulnerabilities({ vendor_name: 'Linux Kernel' })`
   → 4 records — Dirty COW, Dirty Pipe, Linux Race Condition, Linux Netfilter UAF.

4. *"Microsoft's 3 most recent CVEs?"*
   `list_vulnerabilities({ vendor_name: 'Microsoft', sort_by: 'published', sort_order: 'desc', limit: 3 })`
   → CVE-2024-27198 (2024-03-04), CVE-2021-34527 (2021-07-01), CVE-2021-1675 (2021-06-29).

5. *"Which vendor has the most vulnerabilities?"*
   `stats({ group_by: 'vendor' })`
   → Microsoft leads with 5; Apache, Google, and Linux Kernel Organization each have 4; OpenSSL has 3.

## Claude Desktop integration (Phase 2)

This section is the Phase 2 deliverable: the task brief lists Claude Desktop by name as a free agent client option, and the steps below wire this server into it end-to-end.

1. Build once: `npm install && npm run build`.
2. Open Claude Desktop's config file:
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Copy the `mcpServers.vulnerability-registry` block from `claude_desktop_config.sample.json` (at the repo root) into that file, merging under any existing `mcpServers` key.
4. Replace `<ABSOLUTE_PATH_TO_REPO>` with the absolute path to your checkout (forward slashes work on both platforms).
5. **Fully quit** Claude Desktop (Windows tray icon → Quit; macOS menu bar → Quit) and relaunch — MCP servers are only re-read on a cold start.

Dev shortcut: swap `node dist/index.js` for `npx tsx src/index.ts` in the config to skip the build step on every change.

### Verify it works

1. `vulnerability-registry` appears in Claude Desktop's tools/plug icon list.
2. `tools/list` (via MCP Inspector or the client) shows 5 tools.
3. Asking *"how many critical vulnerabilities are still open?"* returns a number (routed through `stats`).
4. Multi-step questions like *"highest-CVSS unpatched Microsoft vuln"* resolve in one call via `list_vulnerabilities` with `vendor_name`, `status`, and `sort_by=cvss_score`.

## Design notes

- Five focused tools (`list_*`, `get_*`, `stats`) over a generic `query` — better LLM tool-picking than a filter DSL.
- Vuln responses inline `vendor: { id, name, category }` — removes an LLM round-trip on the most common question shape.
- Dynamic `# FORMAT:` parsing into a name-keyed row map — no hardcoded column indexes, honours the spec's `# VERSION` signal.
- Strict-at-load, lenient-per-row parser — fail loudly on structural drift, skip and log a single malformed row.
- `src/config.ts` is the only file allowed to touch `process.env`, enforced by an ESLint `no-restricted-properties` rule.

See [`docs/DECISIONS.md`](./docs/DECISIONS.md) for the full decision log with alternatives considered and tradeoffs accepted.

## With more time

1. Add `sort_by` + metadata filters on `list_vendors` (`founded_before`, `hq_contains`) to answer "vendors founded before 1990" in one call.
2. Expose `category` as a `stats.group_by` facet to answer "which category has the most CVEs".
3. Add a product/CPE layer, since current data has no product entity — only vendor plus free-text `affected_versions`.
4. Add MCP `resources/*` support to expose each CVE as a URI the LLM can attach to context.
5. Ship an alias map ("Log4Shell" → `CVE-2021-44228`, etc.) to close the biggest tool-picking risk.

## Known limitations

- **No `affected_versions` range parsing.** Free-text field per spec; `affected_versions_contains` is substring only.
- **No hot-reload.** Files load once at startup; restart to re-read.
- **Substring search only.** No fuzzy or full-text index; sub-millisecond at 10k rows, revisit when it stops being.
