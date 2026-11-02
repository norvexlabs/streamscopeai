---
key: field_profile_suggestion
label: Field Profile Suggestions
---


## Field Profile Suggestions Output

A **field profile** maps a wire tool + argument onto a canonical concept so tool-policy rules can target it uniformly. Without a profile, a rule can only match a tool by literal name glob and cannot reference a named argument; with a profile, the engine resolves the tool to a canonical `tool_id` (e.g. `shell_exec`, `read_file`, `web_fetch`) and the argument to a canonical `field` (e.g. `command`, `path`, `url`) — so one rule (`tool_id` `equals shell_exec`, `arg.command` matches …) covers every client of that tool, and a per-field **normaliser** canonicalises the value before matching (expands `bash -c`, percent-decodes URLs, strips SQL comments, normalises paths).

**When to propose.** Your tool-inventory context includes a "Field-Profile Coverage" section listing observed `(tool, field)` pairs and which are already covered. Propose a `field_profile_suggestion` for the **high-occurrence UNCOVERED** fields — especially ones you want to write a policy rule against but cannot, because no canonical `arg.<field>` exists for them yet. Do NOT propose profiles for already-covered fields, and don't propose for one-off low-occurrence noise.

Each `proposed_field_profiles` entry includes:
- `tool_id` (required): the canonical concept the tool maps to (`shell_exec`, `read_file`, `write_file`, `db_query`, `web_fetch`, `web_search`, …). Use `_` only — no `.` or `-`. Reuse an existing canonical id when one fits; pick a descriptive new one otherwise.
- `tool_pattern` (required): pipe-separated, case-insensitive glob over the wire tool name (`Bash`, `read_file|read|cat`, `*search*`). For an MCP tool `mcp__<server>__<tool>`, match the unprefixed local name and set `mcp_server`.
- `field` (required): the canonical argument name a rule will reference as `arg.<field>` (e.g. `command`, `path`, `url`, `query`). A plain identifier — never include the `arg.` prefix.
- `wire_field` (optional): the ACTUAL argument key on the wire when the client names it differently from the canonical `field` (e.g. canonical `path`, wire `target_file` for Cursor). Omit when they match.
- `normalizer` (required): one of —
  - `shell` — shell-tokenise to argv and unwrap `bash -c '…'` / `sh -c` / `python -c`. For command fields.
  - `url` — percent-decode, lowercase scheme + host, alias cloud-metadata hostnames to their link-local IPs. For URL fields.
  - `sql` — lowercase, strip comments, collapse whitespace. For SQL query fields.
  - `path` — lexical path normalisation (collapse `..`, normalise separators); never touches the filesystem. For file-path fields.
  - `patch` — the files a `*** Begin Patch` envelope adds, deletes, updates or moves to, each path-normalised. For a patch-text field whose files are named inside the patch, declared under the canonical `path` field so file-path rules read them.
  - `raw` — identity / no-op. Use only for genuinely low-risk fields where canonicalisation adds nothing (an explicit "considered, nothing to do").
- `app_filter` / `mcp_server` / `server_type` (optional, MUTUALLY EXCLUSIVE — at most one): scope the profile to a client family (`claude-code|cursor`), an MCP server, or a native server-tool tag (`web_search_20250305`, `google_search`). Leave all unset for a generic profile that matches by `tool_pattern` alone.
- `id` (optional): a stable id (`TFP-…` / `CUSTOM-…`); auto-generated if omitted.
- `description` (optional): a short human label.
- `priority` (optional): lower wins on overlapping `(tool_pattern, field)` matches (default 100). Set generic fallbacks higher (200) so specific profiles win.
- `rationale` (required): cite the uncovered `(tool, field)` pair from the coverage section and the traffic that exercises it.

Approved profiles are registered tenant-wide (they are not workspace-scoped). The same multi-cycle confirmation gate applies — propose freely on what you observe; only recurring proposals surface to operators.
