# Design Decisions

Decision log for the Vulnerability Registry MCP Server. This document is the long-form companion to the README's "Design Notes" paragraph — it records *why* each choice was made, what alternatives were considered, and which tradeoffs were accepted.

---

## How this file is maintained

Living log — appended as decisions are made, not retrofitted at the end. A new `D<N>` entry is added whenever a judgement call is settled that would be hard to reconstruct from the code alone: a library pin, a tradeoff discovered during implementation, a deviation from the plan, or a design call that has a defensible alternative. Mechanical choices (variable names, obvious control flow) stay out.

## Context

Deloitte-assigned homework: build a TypeScript MCP server that wraps two legacy pipe-delimited text files (`vendors.db`, `vulnerabilities.db`) and exposes them as tools an LLM client can call. Estimated scope: 3–5 hours. The spec explicitly grants "full freedom" in designing the tool surface, which is the single most judgement-heavy part of the build.

---

## Process

Design was informed by two rounds of multi-agent exploration, run before any code was written:

### Round 1 — 8 design agents (parallel, independent contexts)

| # | Angle | Key output |
|---|---|---|
| 1 | MCP tool surface | Proposed 5 focused tools over a generic `query`; walkthroughs of spec example questions |
| 2 | In-memory data model | TypeScript types, secondary indexes (`byCve`, `byVendor`, `bySeverity`, `byStatus`), parse-time coercion |
| 3 | Dynamic parser | **Confirmed `type` is column 0 in FORMAT header** (a regular column, not a prefix); caught a bug in the original CLAUDE.md schema description |
| 4 | zod validation | Enum + preprocess-lowercase pattern; flagged the SDK gotcha about passing raw zod shape vs `z.object(...)` |
| 5 | Query semantics | Case-insensitive substring; ISO dates only; `affected_versions` substring filter with no range parsing |
| 6 | MCP protocol wiring | stdio only; dual `content` + `structuredContent` response shape; never `console.log` (stdout is JSON-RPC) |
| 7 | Testing strategy | `node --test` + inline fixtures; skip stdio round-trip tests; Inspector screenshot beats test harness for reviewer signal |
| 8 | Project structure | 5 flat source files (`index`, `parser`, `store`, `tools`, `types`); class-based store passed explicitly |

### Round 2 — 3 critique agents stress-testing the tool surface

| # | Angle | Key finding |
|---|---|---|
| 1 | LLM tool-picking simulation | 7/10 questions got clear picks; 3 risks surfaced — Log4Shell lookup, product-level search gap, list-vs-stats ambiguity for counts. All fixable with description wording. |
| 2 | Minimalism critique | Rejected collapsing `get_*` into `list_*` (shape/not-found semantics), rejected mode params on `list_vulnerabilities` (LLM traps). Concluded 5 tools is defensible. |
| 3 | Coverage gaps | 2/12 questions answerable in 1 call with the baseline surface. Highest-value add: `sort_by`/`sort_order` on list tools. Medium-value: vendor metadata filters, `category` in stats grouping. |

---

## Decisions

### D1 — Tool surface: 5 focused tools

**Chosen:** `list_vulnerabilities`, `get_vulnerability`, `list_vendors`, `get_vendor`, `stats`.

**Rationale:** A single generic `query` tool forces the LLM to invent filter DSL on the fly and hallucinate column names. A large catalog (10+) dilutes tool-picking accuracy. Five focused tools, each answering one clear question type, is the sweet spot for an LLM's decision tree.

**Alternatives rejected:**
- *One `query` tool with SQL-ish filters* — leaks schema, punts design problem back to the model.
- *Collapse `get_*` into `list_*` with `limit=1`* — response shape differs (scalar vs array), not-found semantics get muddled, trains bad habits across tool families.
- *Collapse `stats` into `list_vulnerabilities` via `count_only: true`* — mode params mutate response shape and are known LLM traps.

**Tradeoff:** Five tools means slightly more to document. Accepted because each has a distinct semantic signature the LLM can pick from reliably.

---

### D2 — Tool descriptions steer the LLM away from failure modes

**Chosen wording (excerpts):**
- `get_vulnerability`: "For name/title searches (e.g. 'Log4Shell') use `list_vulnerabilities` with `title_contains` instead."
- `stats`: "Use this for ALL 'how many' / count questions — more efficient than fetching records."
- `list_vulnerabilities`: "For counts or aggregates, use `stats` instead."

**Rationale:** Critique Agent 1 simulated the LLM trying `get_vulnerability(cve_id="Log4Shell")` — a title, not a CVE id — and silently failing. Steering descriptions are a zero-cost fix that redirect the LLM to the right tool.

---

### D3 — Add `sort_by`/`sort_order` to `list_vulnerabilities` only

**Chosen:** Sort parameters on vulnerabilities list; **skipped** on vendors list for scope.

**Rationale:** Critique Agent 3 showed two of twelve analyst questions ("highest-CVSS unpatched vuln", "Microsoft's 3 most recent CVEs") need sorting to answer in one call; without it, they take two calls and client-side sort. Vendor sorting is lower-value (5 vendors in sample data).

**Tradeoff:** Asymmetric API — `list_vendors` has no sort. Accepted for scope; listed as a stretch addition.

---

### D4 — Data model: Map-keyed indexes, parse-time coercion

**Chosen:**
```ts
vendors:    Map<string, Vendor>
vulns:      Map<string, Vulnerability>
byCve:      Map<string, Vulnerability>
byVendor:   Map<string, Vulnerability[]>
bySeverity: Map<Severity, Vulnerability[]>
byStatus:   Map<Status, Vulnerability[]>
```

- `cvss_score` and `founded` → `number` at parse time
- `severity` and `status` lowercased at parse time
- `publishedYear` derived once and cached
- `published` (ISO date) and `affected_versions` (free text) stay as strings

**Alternatives rejected:**
- *No secondary indexes, scan every query* — works at 20 rows, but scaling clause in spec ("thousands of records") makes the index work trivial insurance.
- *Index by published-year* — skipped; date-range queries rarely align to year boundaries, linear scan is sub-millisecond at target scale.
- *Full-text / trigram index on title* — overkill for scope. `toLowerCase().includes()` on ~10k rows finishes in microseconds.

**Tradeoff:** Memory footprint roughly doubles vs storing only the primary Maps. At target scale (~5 MB) this is irrelevant.

---

### D5 — Inline vendor info into vuln responses

**Chosen:** Every vuln row returned from the server carries `vendor: { id, name, category }` pre-joined.

**Rationale:** Removes an LLM round-trip for the most common question shape ("CVEs for vendor X"). Payload size increase is negligible.

**Alternative rejected:** *Return `vendor_id` only, let the LLM call `get_vendor` to enrich.* Adds token cost and latency for zero correctness gain.

---

### D6 — Parser: dynamic FORMAT, strict at load, lenient on rows

**Chosen:**
- Parse `# FORMAT:` header into a column array; rows become `Record<string, string>` keyed by those column names.
- At load, assert that required **logical** fields (`type`, `id`, plus vuln-specific ones) are present. If not, fail loudly with file path and version.
- On a malformed data row (wrong column count), log to stderr and skip; continue parsing.
- Unknown extra columns are kept in the row map and ignored by tools.

**Rationale:** The spec explicitly calls out `# VERSION` as a signal the format may change. Hardcoding columns defeats the point. Strict-at-load + lenient-on-rows balances "fail fast on structural drift" against "one legacy bad row shouldn't brick the server."

**Alternatives rejected:**
- *Hardcoded column indexes* — violates explicit spec constraint.
- *Strict on rows (abort on first malformed line)* — too fragile for legacy data.
- *Fully tolerant (parse whatever)* — silent data corruption is worse than loud failure.

**Note:** Confirmed from the real data that the format uses no pipe-escaping. A future row containing `|` inside a field would fail the column-count check loudly — the desired behavior.

---

### D7 — zod validation with case-preserving preprocess

**Chosen:** `z.enum(["critical","high","medium","low"])` and `z.enum(["open","patched"])`, each wrapped in a `.preprocess` that lowercases string inputs. `z.coerce.date()` for dates. All filters `.optional()`, every tool's schema `.strict()`.

**Rationale:** Enums expose allowed values to the LLM in the generated JSON Schema — better tool-picking accuracy than `z.string()`. Preprocess accepts `"CRITICAL"` from an LLM without forcing case on the human-written data. `.strict()` catches LLM typos (`severityy`) loudly.

**Gotcha documented inline in the code:** `server.registerTool(name, { inputSchema: SHAPE }, handler)` expects the raw zod shape object, **not** `z.object(...)`. Double-wrapping produces a nested schema that never validates.

---

### D8 — MCP response shape: dual text + structured content

**Chosen:** Every tool response returns both:
```ts
{
  content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  structuredContent: result
}
```

**Rationale:** Claude Desktop currently renders the `text` block (pretty-printed JSON is human-readable in its collapsible view). Forward-looking clients that speak the 2025-06 MCP spec consume `structuredContent` directly without re-parsing. Cheap insurance against client evolution.

**Alternative rejected:** *Markdown tables* — look nicer for 3-column rows but wrap badly for 9+ columns and cost tokens.

---

### D9 — Error handling: two tiers

**Chosen:**
- **Tool errors** (unknown vendor_id, empty result on a get_*): return `{ isError: true, content: [...] }`. The LLM sees the error and can recover.
- **Protocol errors** (malformed args, wrong types): let zod/SDK throw. Surfaces as JSON-RPC `InvalidParams`.
- **"No results" on list tools**: NOT an error. Return `{ items: [], total: 0 }`. Empty is a valid answer.
- **File parse failure at startup**: throw before `connect()`. Server refuses to start rather than serve stale data.
- **Unexpected exception in handler**: catch, return `isError: true` with safe message. Never let stack traces cross the wire.

---

### D10 — Project structure: 5 flat files under `src/`

**Chosen:**
```
src/
  index.ts    — entry: load store, register tools, start stdio
  parser.ts   — parseDbFile(path) → { version, columns, rows, errors }
  store.ts    — class VulnerabilityStore with load + indexes + query methods
  tools.ts    — registerTools(server, store): 5 server.registerTool() calls
  types.ts    — Vendor, Vulnerability, Severity, Status, response shapes
```

**Rationale:** A single file hides the parser/store/tool seams a reviewer wants to grade. Three files overload `db.ts` with parsing + storage + querying. Five earns its weight because each file maps to one reviewable concern (I/O, state, protocol surface, types).

**Alternative rejected:** *`src/lib/` subdirectory* — signals "I thought this was bigger than it is." Flat structure lets a reviewer `ls src/` and see the whole program.

---

### D11 — State via explicit class instance, not module singleton

**Chosen:** `index.ts` constructs one `VulnerabilityStore` at startup and passes it to `registerTools(server, store)`.

**Rationale:** Module-level singletons hide lifecycle and hurt testability. A DI framework is overkill. The explicit wire is grep-able and obvious at a glance.

---

### D12 — Testing: `node --test` with inline fixtures

**Chosen:** Node's built-in test runner, TypeScript via `tsx`. 3 test files covering:
- `parser.test.ts` — dynamic FORMAT parsing, malformed-row skip, BOM/CRLF safety
- `store.test.ts` — index correctness, FK join with missing vendor
- `tools.test.ts` — one end-to-end handler (`list_vulnerabilities` with filters + `stats`)

**Alternatives rejected:**
- *Vitest* — nicer DX but adds a config, a dep, and ~3 minutes of setup not recouped over ~6 tests.
- *Jest* — slow cold-start, heavyweight for this scope.
- *MCP stdio round-trip tests* — high setup cost, low reviewer signal. MCP Inspector does the same thing manually, better.
- *No tests, README-only* — viable if time-crunched, but tests signal professional habits without padding.

---

### D13 — No hot-reload, restart on file change

**Chosen:** Files load once at startup into the in-memory store. `fs.watch` is not used.

**Rationale:** Spec is a read-only analyst-facing server. Watchers add race-condition surface (partial writes mid-parse) for near-zero benefit. Claude Desktop restart is cheap. Document in README.

---

## What was explicitly rejected

| Rejected | Why |
|---|---|
| `product_contains` parameter | Would overlap with vendor_name, title, and affected_versions simultaneously — brittle and confusing. Document the limitation in README instead. |
| `title?` param on `get_vulnerability` | Breaks the get-by-identity contract. Steering description redirects to `list_vulnerabilities(title_contains=...)` for the same effect. |
| `avg/max/min` aggregates in `stats` | Scope creep. Count-only covers the spec's example "how many" question. |
| Sub-year temporal grouping (quarter, month) in `stats` | Only one of twelve tested analyst questions needs it. Year-level is sufficient. |
| Version-range parsing of `affected_versions` | Spec explicitly flags this field as free text. Parsing `"Chrome < 88.0.4324.150"`, `"Windows 7-Server 2008"`, `"SSLv3"` into structured ranges is a rabbit hole. |
| `fs.watch` for hot-reload | Race conditions on partial writes; restart is free. |
| ESLint + Prettier | Out of scope for a 3–5 hour homework; adds setup time that doesn't show in the final artifact. |
| CI pipeline | Submission is a public repo only — no deployment target. |
| `src/lib/` subdirectory | 5 files don't justify a sub-namespace. |

---

## What I'd add with more time (also lands in README)

1. **Sort + metadata filters on `list_vendors`** — `sort_by`, `founded_before`, `founded_after`, `hq_contains`. Unblocks "vendors founded before 1990" and "vendors outside the US" in 1 call.
2. **`category` in `stats.group_by`** — enables "which vendor category has the most CVEs."
3. **Proper product/CPE layer** — the data has no product entity, only vendor + free-text `affected_versions`. A real registry would normalize to CPE identifiers.
4. **Resource support (MCP `resources/*`)** — expose each vuln as a URI so the LLM can attach it to conversation context.
5. **Fuzzy match on vendor/title** — substring is fragile; a small dictionary of known CVE aliases ("Log4Shell" → "CVE-2021-44228") would close the biggest tool-picking risk.
6. **Integration test via stdio round-trip** — spawn the server as a child process, call `tools/list` and `tools/call`, assert the JSON-RPC envelope.
7. **Structured logging to stderr** — currently plain strings; a JSON-lines format would help observability if this were ever run as a managed service.
