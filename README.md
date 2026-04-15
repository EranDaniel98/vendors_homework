# Vulnerability Registry MCP Server

An MCP (Model Context Protocol) server that wraps a legacy pipe-delimited vulnerability registry and exposes it as tools any MCP-compatible LLM client can call. Written in TypeScript; loads the data into memory at startup and serves it over stdio.

## Requirements

- Node.js **>= 20** (tested on 22 and 24)
- npm (ships with Node)

## Install

```bash
npm install
```

## Run

Development (no build, runs TypeScript directly):

```bash
npm start
```

Production (compile to `dist/`, then run):

```bash
npm run build
node dist/index.js
```

Tests, lint, formatter:

```bash
npm test
npm run lint
npm run format
```

On startup the server logs `ready {vendors,vulns}` to **stderr** and listens on **stdin/stdout** for JSON-RPC traffic. Nothing is ever written to stdout by application code — stdout is reserved for the MCP protocol.

## Environment variables

All tunables are validated at startup via zod; unknown values produce a fatal error with the offending key named.

| Name | Default | Purpose |
|---|---|---|
| `VULN_DB_DIR` | `<repo-root>/data` | Directory containing the data files. Overrides path resolution for both files at once. |
| `VENDORS_FILE` | `vendors.db` | Filename of the vendor master (relative to `VULN_DB_DIR`). |
| `VULNS_FILE` | `vulnerabilities.db` | Filename of the vulnerability list. |
| `SERVER_NAME` | `vulnerability-registry` | `name` field advertised to MCP clients. |
| `SERVER_VERSION` | `1.0.0` | `version` field advertised to MCP clients. |
| `DEFAULT_PAGE_LIMIT` | `50` | Default `limit` applied to list tools when the caller doesn't specify one. |
| `MAX_PAGE_LIMIT` | `500` | Upper clamp on any caller-supplied `limit`. |
| `LOG_LEVEL` | `info` | One of `silent`, `error`, `info`, `debug`. Log output goes to **stderr** only. |

`src/config.ts` is the **only** file permitted to read `process.env` — this is enforced by an ESLint rule (`no-restricted-properties` on `process.env` everywhere except `src/config.ts`). If you want to add a setting, extend the zod schema there.

## Tools

Five tools are exposed. Each returns a dual-shape response: a pretty-printed JSON `text` block for human/Claude-Desktop rendering and a `structuredContent` object (under a `result` key) for clients that consume the MCP 2025-06 structured-content extension.

### `get_vendor`

Fetch a single vendor by primary id.

| Param | Type | Req | Notes |
|---|---|---|---|
| `vendor_id` | string | yes | e.g. `"V1"` |

Error shape: `{ isError: true }` with a `Not found: vendor_id=...` message if the id is unknown.

### `list_vendors`

List vendors with optional filters. Pagination clamps to `MAX_PAGE_LIMIT`.

| Param | Type | Notes |
|---|---|---|
| `category` | string | Exact match, case-insensitive |
| `name_contains` | string | Substring, case-insensitive |
| `limit`, `offset` | number | Pagination |

### `get_vulnerability`

Fetch a single vulnerability by internal id **or** by official CVE id. Provide exactly one.

| Param | Type | Notes |
|---|---|---|
| `id` | string | Internal record id, e.g. `"CVE001"` |
| `cve_id` | string | Official CVE identifier, e.g. `"CVE-2021-44228"` |

For name/title searches ("Log4Shell", "PrintNightmare") use `list_vulnerabilities` with `title_contains` — the tool description reinforces this to the LLM to avoid a common miss-pick.

### `list_vulnerabilities`

Search/filter the full vulnerability list. Vendor metadata (`id`, `name`, `category`) is inlined under `vendor` on every result — saves the LLM a follow-up `get_vendor` call.

| Param | Type | Notes |
|---|---|---|
| `vendor_id` | string | Exact |
| `vendor_name` | string | Case-insensitive substring match on vendor name |
| `severity` | enum | `critical` \| `high` \| `medium` \| `low` (case-insensitive) |
| `status` | enum | `open` \| `patched` (case-insensitive) |
| `title_contains` | string | Substring on title |
| `cve_contains` | string | Substring on CVE id |
| `affected_versions_contains` | string | Substring on free-text version field |
| `min_cvss`, `max_cvss` | number | 0–10 |
| `published_after`, `published_before` | ISO date | Inclusive |
| `year` | number | Published year |
| `sort_by` | enum | `published` \| `cvss_score` |
| `sort_order` | enum | `asc` \| `desc` (default `desc`) |
| `limit`, `offset` | number | Pagination |

Empty match is **not** an error; returns `{ items: [], total: 0 }`.

### `stats`

Count vulnerabilities grouped by a facet, with the same filters as `list_vulnerabilities` (minus pagination/sort). The tool description tells the LLM: *"Use this for ALL 'how many' / count questions"* — much cheaper than fetching records and counting client-side.

| Param | Type | Notes |
|---|---|---|
| `group_by` | enum | `severity` \| `status` \| `vendor` \| `year` |
| `filters` | object | Same shape as `list_vulnerabilities` filters, sans `sort_*`/`limit`/`offset` |

Returns `{ total, group_by, groups: [{ key, count }] }` sorted by count desc.

## Example questions the tool surface answers

- *"How many critical vulnerabilities are still open?"* → `stats({ group_by: 'severity', filters: { status: 'open' } })`
- *"Which CVEs were found in the Linux Kernel in the past year?"* → `list_vulnerabilities({ vendor_name: 'Linux', published_after: '2025-04-15' })`
- *"What's the CVSS score of Log4Shell?"* → `list_vulnerabilities({ title_contains: 'Log4Shell' })`
- *"Highest-CVSS unpatched vulnerability"* → `list_vulnerabilities({ status: 'open', sort_by: 'cvss_score', sort_order: 'desc', limit: 1 })`
- *"Microsoft's 3 most recent CVEs"* → `list_vulnerabilities({ vendor_id: 'V1', sort_by: 'published', sort_order: 'desc', limit: 3 })`

## Design notes

Five focused tools instead of one generic `query` — the LLM picks from distinct semantic signatures rather than inventing a filter DSL. Vendor info is inlined into every vuln response to save round-trips. Every numeric / enum field is coerced at parse time so queries never do per-row conversion. The `# FORMAT:` header is parsed dynamically, and the spec's `# VERSION` field is surfaced — the parser never hardcodes column indexes. Strict-at-load, lenient-per-row: a missing header aborts startup, but a malformed data row is logged to stderr and skipped so one bad line can't brick the server.

The full rationale — including options considered and rejected — lives in [`docs/DECISIONS.md`](./docs/DECISIONS.md).

## With more time

1. `sort_by` + metadata filters on `list_vendors` (`founded_before`, `hq_contains`) to unblock "vendors founded before 1990" in a single call.
2. `category` as a `stats.group_by` facet — answers "which category has the most CVEs."
3. A proper product/CPE layer. The current data has only vendor + free-text `affected_versions`; a real registry would normalize to CPE identifiers.
4. MCP `resources/*` support — expose each CVE as a URI the LLM can attach to conversation context.
5. A small alias map for "Log4Shell" → `CVE-2021-44228`, "Heartbleed" → `CVE-2014-0160`, etc., to close the biggest tool-picking risk.
6. Integration tests that spawn the server as a real child process and round-trip `tools/list` + `tools/call` over stdio. (The in-memory transport covers the API surface today; the child-process test would catch transport-layer regressions.)
7. Structured JSON-lines logs to stderr instead of the current plain strings, for observability when run as a managed service.

## Claude Desktop integration (Phase 2)

This is also the **Phase 2 agent client** deliverable. The spec lists Claude Desktop by name as one of the free LLM options that "connects directly to MCP Servers, no API key needed at all" — wiring it up as described below gives you the full natural-language analyst experience: ask *"how many critical vulnerabilities are still open?"* and Claude chooses the right tool, calls it, and synthesizes the answer. Multi-step questions that require chaining tools ("highest-CVSS unpatched Microsoft vuln") work too.

See [`claude_desktop_config.sample.json`](./claude_desktop_config.sample.json). Copy the `mcpServers.vulnerability-registry` entry into your `claude_desktop_config.json` (on Windows: `%APPDATA%\Claude\claude_desktop_config.json`; on macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`), replace `<ABSOLUTE_PATH_TO_REPO>` with the path to this repo, and fully quit + relaunch Claude Desktop. During development you can point the `command`/`args` at `npx tsx src/index.ts` instead of `node dist/index.js` to skip the build step.

## Known limitations

- **No `affected_versions` range parsing.** Free-text field per the spec; we expose `affected_versions_contains` (substring) only. Parsing `"Chrome < 88.0.4324.150"` into structured ranges is a rabbit hole.
- **No hot-reload.** Files load once at startup; restart to re-read.
- **Substring search only.** No fuzzy / trigram / full-text index. At 10k rows `.toLowerCase().includes()` finishes in microseconds — when that stops being true, add a proper index.
