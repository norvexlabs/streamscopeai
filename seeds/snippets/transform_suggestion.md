---
key: transform_suggestion
label: Transform Suggestions
---


## Transform Proposal Rules

- Proposed scripts apply to FUTURE requests only. Do not propose scripts that try to fix past data — only propose preventive transforms.
- **DO NOT propose transforms from a single session.** A finding is NOT grounds for a transform. Use your memory to track patterns. Only propose a transform when your memory shows the SAME pattern observed in 3+ sessions across multiple analysis cycles. When you see a new pattern, record it in memory and wait.
- **Only propose transforms for major, repeated issues.** Minor findings should result in alerts and memory updates only — NEVER transform proposals. Transforms are heavyweight interventions that modify live traffic; reserve them for serious, confirmed patterns that clearly warrant automated mitigation.

## Request vs Response Phase

Choose the correct phase for your proposed transform:
- **`phase: "request"`** — modifies the request BEFORE it reaches the upstream model. Use for: guardrail injection, PII redaction in user input, tool filtering, context compression, model routing.
- **`phase: "response"`** — modifies the response AFTER the model generates it, BEFORE the client sees it. Use for: PII redaction in model output, tool call argument sanitization, response content filtering, output disclaimers.

A PII pattern in **user messages** → request-phase `messages` scope.
A PII pattern in **model responses** → response-phase `text` scope.
A dangerous tool call argument pattern → response-phase `tool` scope (blocks the specific invocation, not the tool definition).

Always use the narrowest scope possible. A response text filter should use `scope: "text"`, not `scope: "global"`.

## Proposal Requirements

Each `proposed_programs` entry MUST include all of:
1. **name**: short `snake_case` identifier for the program.
2. **description**: what the script does in plain language (goal and mechanism).
3. **source**: valid Rhai script. In `full` mode (default) define `fn transform(ctx) { ... ctx }`; in `span` mode define `fn transform(m) { ... }` (see "Match mode" below). Must compile — invalid scripts are auto-rejected.
4. **phase**: `request` or `response` (see "Request vs Response Phase" above).
5. **scope**: for `phase: request` — `global` | `system_prompt` | `messages` | `tools`. For `phase: response` — `global` | `text` | `tool` | `thinking`. Use the narrowest scope that fits.
6. **rationale**: why this transform is safe and necessary, citing the cross-session pattern from memory that motivates it.

Optional fields:
- **model_filter**: comma-separated model aliases, or null for all.
- **app_filter**: comma-separated app_ids, or null for all.
- **match_mode**: `full` (default/omit) or `span` — see "Match mode" below.
- **trigger_regex**: a regex. In `full` mode it is an optional fast-find gate (the script runs only when in-scope content matches; omit ⇒ always run). In `span` mode it is REQUIRED and is the span finder.

Use `model_filter` and/or `app_filter` to restrict scope when the issue is specific to certain models or clients.

## Match mode: full vs span

- **`full` (default)** — your `source` defines `fn transform(ctx) { ... ctx }` and runs ONCE over the whole scope, taking and returning the `ctx` object documented below. Use it for structural edits (filter messages, inject a system prompt, drop a tool). An optional `trigger_regex` gates whether the script runs at all.
- **`span`** — your `source` defines `fn transform(m) { ... }` and runs ONCE PER MATCH of the required `trigger_regex`, on just the matched span. Use it for surgical per-occurrence rewrites (redact every match of a secret pattern, normalise each occurrence of a token) where a full-scope rewrite would be clumsy or error-prone. The function receives a map `m` and returns the replacement:
  - `m.matched` — the matched substring (String).
  - `m.groups` — array of capture groups (group 1 onward).
  - `m.before` / `m.after` — bounded context windows around the match.
  - `m.start` / `m.end` — byte offsets of the match.
  - **Return**: a `String` (the replacement for this match), `#{drop: true}` (delete the match), or `#{replace: "..."}` (explicit replacement). Returning anything else leaves the match unchanged.
  - Example: `fn transform(m) { redact_pii(m.matched) }` with `trigger_regex` finding the at-risk pattern.

  Span scripts do NOT see `ctx.messages` / `ctx.tools` — they operate on one matched text span at a time, so the `ctx`-shaped patterns below don't apply to them.

## Rhai Script Reference

This reference covers `full`-mode scripts, which define `fn transform(ctx)` and return the ctx object (`span` mode is described above).
Rhai is a sandboxed scripting language with JS-like syntax. Here is the essential syntax:

### Variables and types
```rhai
let x = 42;              // integer
let s = "hello";         // string
let b = true;            // boolean
let arr = [1, 2, 3];     // array
let map = #{"key": "value", "count": 10};  // map (object map)
let nothing = ();         // unit / null — check with `== ()`
```

### String operations
```rhai
s.contains("ell");        // true
s.replace("hello", "hi"); // "hi"
s.to_lower();             // lowercase
s.to_upper();             // uppercase
s.len();                  // 5 (length in characters)
s.starts_with("hel");     // true
s.ends_with("lo");        // true
s.trim();                 // strip whitespace
s.split(" ");             // array of substrings
let combined = "part1" + " " + "part2";  // concatenation with +
```

### Building multi-line strings

Use `[].join()` for readable multi-line string construction (preferred over `+=`):
```rhai
let rules = [
    "[Safety Policy]",
    "You must follow these rules.",
    "",
    "Content safety:",
    "- Never generate harmful content.",
    "- Refuse malware requests.",
].join("\n");
```

For dynamic strings where you need to splice variables between static blocks, use `+`:
```rhai
let header = [
    "## Session Analysis",
    "",
    "Model: " + ctx.model,
].join("\n");
let result = header + "\n\n" + dynamic_content;
```

### Array operations
```rhai
let arr = [1, 2, 3, 4, 5];
arr.len();                           // 5
arr.push(6);                         // append
arr.contains(3);                     // true
arr.filter(|x| x > 2);              // [3, 4, 5]
arr.map(|x| x * 2);                 // [2, 4, 6, 8, 10]
arr.remove(0);                       // remove at index
for item in arr { /* ... */ }        // iteration
```

### Map operations
```rhai
let m = #{};
m["key"] = "value";                  // set
let v = m["key"];                    // get (returns () if missing)
m.contains("key");                   // true
m.keys();                            // array of keys
m.remove("key");                     // remove
```

### Control flow
```rhai
if condition { ... } else { ... }
for i in range(0, 10) { ... }       // range loop
for item in array { ... }           // for-in loop
while condition { ... }
```

### ctx object (RequestContext)

| Field | Type | Writable | Example |
|-------|------|----------|---------|
| `ctx.system_prompt` | String or `()` | Yes | `ctx.system_prompt = "Be safe.\n" + ctx.system_prompt;` |
| `ctx.messages` | Array of maps | Yes | Each: `#{role: "user", content: "text", tool_call_id: (), tool_calls: []}` — the conversation only; the system prompt is `ctx.system_prompt` on every protocol |
| `msg.tool_calls` | Array of maps | Yes (assistant) | Each: `#{id: "call_1", name: "search", arguments_json: "{\"q\":\"...\"}"}`; filter it to drop a call, rewrite `arguments_json` (raw JSON string) to change one |
| `ctx.tools` | Array of maps | Yes | Each: `#{name: "Bash", description: "...", parameters_json: "..."}`; a provider-hosted tool (no function name) also carries `kind` (its type, e.g. `"web_search"`) and `config_json` (its configuration) |
| `ctx.model` | String | Yes | `ctx.model = "gpt-4o-mini";` |
| `ctx.user_id` | String | Read-only | |
| `ctx.app_id` | String or `()` | Read-only | |
| `ctx.api_version` | String | Read-only | `"chat_completions"` / `"anthropic_messages"` / `"responses"` / `"google_gemini"` |
| `ctx.metadata` | Map | Yes | `ctx.metadata["guardrail"] = "v1";` |
| `ctx.labels` | Array of strings | Yes | `ctx.labels.push("pii_redacted");` |

### Registered helper functions
- `contains_ci(string, pattern)` — case-insensitive contains
- `matches_glob(string, pattern)` — simple wildcard match (`*` and `?`)
- `redact_pii(string)` — mask all detected PII in place (`[REDACTED:US_SSN]`, etc.) using the in-process detector (email, card, SSN, IBAN, phone, IP, crypto, bank — checksum-validated)
- `redact_pattern(string, regex_str, replacement)` — regex-based redaction (compiled pattern is cached)
- `parse_int(string)` — parse string to integer
- `parse_json(string)` — parse a JSON string into a map / array / value (returns `()` on failure)
- `to_json(value)` — serialize a map / array / value to a compact JSON string

### Common patterns

**Filter messages:**
```rhai
ctx.messages = ctx.messages.filter(|msg| !msg.content.contains("secret"));
```

**Modify all message contents (use index-based loop — for-in creates copies):**
```rhai
for i in range(0, ctx.messages.len()) {
    ctx.messages[i].content = redact_pii(ctx.messages[i].content);
}
```

**Remove specific tools:**
```rhai
ctx.tools = ctx.tools.filter(|t| t.name != "Bash" && t.name != "Write");
```

**Inject system prompt guardrail:**
```rhai
if ctx.system_prompt == () {
    ctx.system_prompt = "Follow safety guidelines.";
} else {
    ctx.system_prompt = "Follow safety guidelines.\n\n" + ctx.system_prompt;
}
```

**Conditional on metadata:**
```rhai
if ctx.metadata["upstream_provider"] == "openai" {
    // OpenAI-specific logic
}
```

**Middle-out compression (keep first N + last N messages):**
```rhai
let max = 50;
if ctx.messages.len() > max {
    let keep_first = max / 2;
    let keep_last = max - keep_first;
    let total = ctx.messages.len();
    let result = [];
    for i in range(0, keep_first) { result.push(ctx.messages[i]); }
    for i in range(total - keep_last, total) { result.push(ctx.messages[i]); }
    ctx.messages = result;
}
```

### Scope enforcement

Scripts are assigned a `scope` that controls which fields they can see and modify:
- `global`: can read/write system_prompt, messages, tools, model, metadata, labels
- `system_prompt`: can read/write system_prompt, metadata, labels (cannot see messages or tools)
- `messages`: can read/write messages, metadata, labels (cannot see tools or system_prompt)
- `tools`: can read/write tools, metadata, labels (cannot see messages or system_prompt)

Choose the narrowest scope that fits your script. A PII redaction script that only modifies messages should use `scope: "messages"`. A tool filtering script should use `scope: "tools"`.

### Response-phase scripts (phase: "response")

Response scripts intercept content blocks AFTER the upstream responds, BEFORE the client sees them.
Use response phase when you need to:
- Redact PII from model output (not input)
- Modify or suppress tool call arguments in responses
- Filter thinking/reasoning content

Response scopes operate on individual content blocks, not the full request:

| Scope | Block type | Writable fields |
|-------|-----------|-----------------|
| `global` | All blocks | All writable fields for the block type |
| `text` | Text content | `ctx.content` (the response text) |
| `tool` | Tool use blocks | `ctx.tool_name`, `ctx.arguments` (JSON string) |
| `thinking` | Reasoning blocks | `ctx.content` (the thinking text) |

When the tenant's `healing_enabled` setting is on, the gateway repairs malformed
JSON *syntax* (trailing commas, unclosed brackets) in `ctx.arguments` before any
script runs — so a `tool`-scope script can `parse_json(ctx.arguments)` and expect
it to parse. Propose a *semantic* fix (coerce a stringified array to a real
array, fill a missing parameter), not a JSON-syntax repair.

Response ctx object (ResponseBlockContext):

| Field | Type | Writable | Notes |
|-------|------|----------|-------|
| `ctx.block_type` | String | Read-only | "text", "tool_use", "thinking" |
| `ctx.content` | String | Yes (text/thinking) | Text or thinking content |
| `ctx.tool_name` | String or `()` | Yes (tool scope) | Tool name |
| `ctx.tool_id` | String or `()` | Read-only | Tool call ID |
| `ctx.arguments` | String or `()` | Yes (tool scope) | Tool arguments JSON |
| `ctx.model` | String | Read-only | |
| `ctx.user_id` | String | Read-only | |
| `ctx.app_id` | String or `()` | Read-only | |
| `ctx.api_version` | String | Read-only | |
| `ctx.metadata` | Map | Yes | |
| `ctx.labels` | Array | Yes | Push labels for audit |

Choose request vs response phase:
- **Request phase**: modify what goes TO the model (system prompt, messages, tools, model routing)
- **Response phase**: modify what comes FROM the model (output text, tool calls, reasoning)

Your proposed `source` must compile as Rhai and define the `transform` function its `match_mode` requires — invalid scripts are automatically rejected.
