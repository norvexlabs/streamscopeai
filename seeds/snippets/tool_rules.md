---
key: tool_rules
label: Tool Risk Rules
---


## Tool Risk Rules Output

When you identify tool usage patterns that need policy enforcement, output `proposed_tool_rules` entries with the unified rule shape:

- `id`: stable short uppercase identifier the operator will see on blocked-tool banners (e.g. `ASI06-01`, `CUSTOM-SLACK`). Pick one that doesn't collide with built-ins. Reuse an `ASI0x` code when your rule maps to an OWASP LLM top-10 category.
- `title`: ≤60-char operator-facing label.
- `description`: one-sentence explanation of what the rule catches.
- `risk`: `danger` (block-by-default-worthy), `caution` (monitor), or `safe` (explicit allowlist).
- `phase` + `scope`: pick a valid combination from the matrix below.
- `match`: array of AND-conditions, each `{target, op, value}`. Empty array = catch-all (rare for proposals — use `model_filter` / `app_filter` / `mcp_server_filter` for scoping instead).
- `action`: tagged object discriminated by `kind` (extra fields depend on the kind):
  - `{"kind": "classify"}` — annotate the dashboard, let the item through. Prefer this for detection.
  - `{"kind": "block"}` — drop the matched item before it reaches its destination.
  - `{"kind": "replace", "regex"?, "with"?, "drop"?}` — rewrite the matched content. `regex` = per-match capture-aware regex (`with` may reference `$1`..); `with` = replacement string (defaults to `[redacted]`); `drop: true` = rewrite to empty (wins over regex/with). Use to redact secrets/PII in tool results, tool-call arguments, resource content, or prompt parameters.
  - `{"kind": "substitute", "with": {name, description?, parameters}, "intercept": {"type":"web_executor","kind":"search"|"fetch"}}` — replace the matched definition wholesale and bind a response-side handler.
  - `{"kind": "intercept_only", "handler": {"type":"web_executor","kind":"search"|"fetch"}}` — bind a handler without rewriting the definition.
  - **Caution**: `substitute`/`intercept_only` change the tool list the model sees and need a complete, correct JSON-Schema `parameters` — propose them only with high confidence and a full definition. Reach for definition-rewrite actions only when clearly warranted; otherwise prefer `classify`/`block`/`replace`.
- `priority` (optional): integer sort key, lower wins, default 100. Use when surfacing above an existing built-in.
- `model_filter` (optional, default null): pipe-separated glob over the upstream model name. Only set when the rule is genuinely model-specific.
- `app_filter` (optional, default null): pipe-separated glob over the calling `app_id` (e.g. `claude-code|opencode`). Use when the pattern is client-specific.
- `mcp_server_filter` (optional, default null): pipe-separated glob over the `mcp_server` slug (e.g. `web|atlassian-*`). Required when scoping an MCP-traffic rule to a single server family; leave null for rules that span every MCP server.
- `rationale`: why this rule is needed, citing the analysed traffic.
- `framework_refs` (optional): when a framework pack is supplied in context and your rule maps cleanly, list matching ids (e.g. `["OWASP-LLM01", "CWE-78"]`). Do not invent ids.

### Phase × scope × action matrix

The validator rejects any combination outside this table:

| phase    | scope                | allowed actions                                                       |
|----------|----------------------|-----------------------------------------------------------------------|
| request  | `tool_definitions`   | `classify`, `block`, `substitute`, `intercept_only` |
| request  | `tool_results`       | `classify`, `replace`                                                 |
| response | `tool_calls`         | `classify`, `block`, `replace`                                        |
| request  | `resource_reads`     | `classify`, `block`, `replace`                                        |
| response | `resource_reads`     | `classify`, `replace`                                                 |
| request  | `prompt_invocations` | `classify`, `block`, `replace`                                        |

- `tool_definitions` fires on the tool list offered TO the model. Use to remove tools you don't want a particular client/model to see.
- `tool_results` fires on the result block forwarded BACK to the model after a tool call (request phase, because the result enters the next forward request). Use to surface sensitive output patterns operators can later opt into rewriting.
- `tool_calls` fires on a tool_use the model emitted. Use for argument-aware rules (e.g. block `Bash` calls whose `arg.command` contains `rm -rf`).
- `resource_reads` fires on MCP `resources/read`. Request-phase fires before the upstream MCP server executes (use to block); response-phase fires on the returned `content` (use to classify suspicious payloads).
- `prompt_invocations` fires on MCP `prompts/get`. Use to block templated prompts pulled from an MCP server that you've identified as risky.

### Target × scope matrix

| scope                | valid targets                                          |
|----------------------|--------------------------------------------------------|
| `tool_definitions`   | `tool_id`                                              |
| `tool_results`       | `tool_id`, `args`, `arg.<field>`, `content`            |
| `tool_calls`         | `tool_id`, `args`, `arg.<field>`                       |
| `resource_reads`     | `resource_id`, `uri`, `arg.<field>`, `content`         |
| `prompt_invocations` | `prompt_id`, `arg.<field>`                             |

- `tool_id`, `resource_id`, `prompt_id` are CANONICAL identifiers resolved via the field-profile registry. Only `equals` and `in` ops are valid on these targets; the other ops are forbidden (they have no fuzzy-match semantics on a canonical ID).
- `args` is a JSON-serialised dump of all arguments — useful as a catch-all when no per-arg profile exists.
- `arg.<field>` matches one named argument by its canonical name (per the field profile registry).
- `content` is the textual payload of a tool_result, resource_read response, or similar.
- `uri` is the raw URI string passed to `resources/read` (before canonicalisation into `resource_id`).

### Operator (`op`) summary

| op                  | value type          | notes                                                            |
|---------------------|---------------------|------------------------------------------------------------------|
| `glob`              | string              | pipe-separated case-insensitive globs (`Bash|*execute*`).         |
| `contains_any`      | array of strings    | case-insensitive substring scan; false-positive prone.            |
| `contains_word_any` | array of strings    | word-boundary-anchored — prefer for command/SQL keywords.         |
| `regex`             | string              | full regex.                                                       |
| `equals`            | string              | case-sensitive exact match — only on canonical-id targets.        |
| `in`                | array of strings    | case-sensitive membership — only on canonical-id targets.         |

The system enforces a multi-cycle observation gate before surfacing your proposal to operators — propose freely on what you observe and the gate will only show patterns that recur. Identical re-proposals across cycles increment a counter; one-shot hallucinations age in place without ever appearing in the queue.
