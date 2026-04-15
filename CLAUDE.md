# Vulnerability Registry MCP Server — Codebase Guide

## 1. Tech Stack

**Language:** TypeScript (required by spec)
**Runtime:** Node.js — version TBD, no `package.json` yet
**MCP SDK:** `@modelcontextprotocol/sdk` (to be added)
**Data:** two pipe-delimited text files at project root — no DB engine, no ORM
**Frontend / backend framework / auth / cache / queue / logging:** none — scope is a single local MCP server

## 2. Project Layout

```
vendors_homework/
  CLAUDE.md                         — this file
  README.md                         — setup + tool reference + design notes
  package.json, tsconfig.json       — project config
  eslint.config.js, .prettierrc     — lint/format config
  claude_desktop_config.sample.json — drop-in MCP client config
  src/                              — TypeScript source (config, parser, store, tools, types, index)
  tests/                            — node --test suites + fixtures
  data/
    vendors.db                      — vendor master, pipe-delimited
    vulnerabilities.db              — CVE records, pipe-delimited, FK → vendors.db
  docs/
    DECISIONS.md                    — decision log (D1–D14)
    english_instruction.md          — homework spec (EN, authoritative)
    hebrew_instruction.md           — homework spec (HE, mirror)
  .github/workflows/ci.yml          — lint + build + test on PR / main
```

## 3. Backend Conventions

No code written yet. Constraints from spec:

- Load both `.db` files at startup; parse in-memory for fast query
- Parse the `# FORMAT:` header dynamically — do **not** hardcode columns (`# VERSION` exists so format can change)
- Must scale to thousands of records
- Expose MCP tools; tool surface is the implementer's design choice
- Must be connectable from Claude Desktop or any MCP-compatible client

**Data file format** (both files):

```
# METADATA
# FORMAT: <pipe-delimited column names>
# VERSION: <x.y>

<RECORD_TYPE>|<col1>|<col2>|...
```

| File | `type` value | Columns (in order) |
|------|--------------|--------------------|
| `vendors.db` | `VENDOR` | `type`, `id`, `name`, `category`, `hq`, `founded` |
| `vulnerabilities.db` | `VULN` | `type`, `id`, `cve_id`, `title`, `vendor_id`, `severity`, `cvss_score`, `affected_versions`, `status`, `published` |

- `type` is **column 0** — a regular column in `# FORMAT:`, not a prefix. Use it to route rows between vendors and vulns buckets after parse.

- `vulnerabilities.vendor_id` → `vendors.id`
- `status` ∈ {`open`, `patched`}
- `severity` observed: `critical`, `high`, `medium` (no enum defined in spec)
- `affected_versions` is free-text range — not structured
- `cvss_score` is a decimal string

## 4. Frontend Conventions

Not applicable. Phase 2 (optional) is a CLI or minimal UI agent client; design open.

## 5. Testing

| Layer | Command | Runner | Notes |
|-------|---------|--------|-------|
| — | — | — | Not set up. Fill in once a runner is picked. |

## 6. Run Commands

No `package.json` yet. Commands will be added once the MCP server is scaffolded.

## 7. Linting & Formatting

Not configured. No ESLint, Prettier, or tsconfig committed.

## 8. Git Conventions

- Not a git repo yet (`Is a git repository: false`)
- Submission requires a public GitHub repo
- Conventional Commits suggested if adopted: `feat`, `fix`, `docs`, `chore`, `ci`, `refactor`, `test`, `style`

## 9. Deployment

| Environment | URL | How |
|-------------|-----|-----|
| Local | stdio transport | Launch via Claude Desktop MCP config or `npx`/`node` from client |

No remote deployment target. Spec is a local MCP server only.

## 10. CI/CD Reference

None. No `.github/workflows/`.

## 11. Tooling Gaps

- Platform is Windows + bash — use forward slashes and `/dev/null`, not `NUL`.
- Data files are named `*.db` but are plain ASCII text, not SQLite. Do not open with `sqlite3`.
