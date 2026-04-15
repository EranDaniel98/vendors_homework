# Vulnerability Registry — Building a Smart Access Layer

**Language:** TypeScript
**Estimated time:** 3–5 hours

---

## Background

One of Deloitte's clients maintains an internal database of security vulnerabilities — a legacy system built years ago by a team that no longer exists. The database tracks known vulnerabilities (CVEs) and maps each one to the relevant software vendor, and is used daily by security teams, risk managers, and analysts.

The problem? The data sits in plain text files stored on an internal server. There is no API, no search interface, and no convenient way to query the data without opening the files manually.

The team wants to connect this database to an internal AI agent that allows analysts to ask questions in natural language — "How many critical vulnerabilities are still open?", "Which CVEs were found in the Linux Kernel in the past year?", "What is the CVSS score of Log4Shell?" — and get immediate answers.

The chosen solution: build an **MCP Server** that wraps the existing files and exposes them as tools that any MCP-compatible LLM client can use.

---

## Existing Data Format

Two text files are waiting for you in the project folder. The format was developed internally and is not based on JSON, CSV, or any known standard — it is a custom pipe-delimited format born out of constraints from a legacy system.

Each file starts with a metadata block that describes the column layout, followed by the data rows themselves.

### vendors.db
This file contains the software vendors registered in the system. See the attached [`vendors.db`](./vendors.db) file.

### vulnerabilities.db
This file contains the registered vulnerabilities. Each vulnerability is linked to one vendor via the `vendor_id` field. See the attached [`vulnerabilities.db`](./vulnerabilities.db) file.

**A few things worth knowing about the format:**
- The `affected_versions` field describes a version range as free text
- The `vendor_id` field in the vulnerabilities file references the `id` field in the vendors file
- The `status` field can be either `open` or `patched`
- The `VERSION` field in the metadata exists for a reason — the format may change in the future
- The database is expected to grow — the solution should work with thousands of records

---

## What Needs to Be Built

### Phase 1 — MCP Server

Build an MCP Server in TypeScript using the official SDK (`@modelcontextprotocol/sdk`).

The server should load both files on startup, parse the metadata dynamically, and hold the data in memory for fast querying.

**As for the tools you expose — you have full freedom to design them.** Think about what a real security analyst would want to ask, and design the tools accordingly. The tools should allow an LLM to navigate the database naturally — searching, filtering by severity or status, and cross-referencing vendors with vulnerabilities.

The server must be connectable via Claude Desktop or any MCP-compatible client.

**Required output:**
- Complete, runnable code
- A `README.md` with setup instructions and a description of each tool you implemented
- A short note in the README about the design decisions you made and why

---

### Phase 2 — Agent Client *(optional)*

If you have access to an LLM API, build an agent layer on top of the MCP Server that allows users to ask natural language questions and receive answers.

The agent should accept a question from the user — via CLI or a simple UI — call the appropriate tools, and synthesize a final answer. Questions that require multiple tool calls should work as well.

**You are not required to provide your own API key.** Free options that work well with MCP:

- **Claude Desktop** — connects directly to MCP Servers, no API key needed at all
- **Ollama** — run models locally (Llama, Mistral, Qwen, etc.)
- **Groq** — free tier with full tool use support
- **Google Gemini API** — generous free tier with function calling

---

## Submission

Send a link to a public GitHub repository with the complete code.

In the README, in addition to the setup instructions and tool descriptions — add a short paragraph on what you would build differently or add with more time.
