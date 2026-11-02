// name = "email_anonymizer_response"
// description = "Tutorial: anonymizes email addresses in LLM response text. Replaces any email (e.g. john@company.com) with anonymous@anonymous.org before the client receives it. Disabled by default — enable to activate."
// phase = "response"
// scope = "text"
// priority = 100
// enabled = false
// app_filter = "!streamscope-agent"
// trigger_regex = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
// match_mode = "span"

// ─────────────────────────────────────────────────────────────────────
// SPAN-MODE TRANSFORM TUTORIAL (response phase)
// ─────────────────────────────────────────────────────────────────────
//
// This is a SPAN-MODE transform (`match_mode = "span"`). The gateway finds
// every match of `trigger_regex` in each response text block and runs this
// script ONCE PER MATCH, rewriting only the matched span. The engine handles
// locating matches and splicing the replacements back.
//
// The script receives a per-match object `m` (NOT the full ResponseBlockContext):
//
//   m.matched  — the matched text (string), e.g. "john@company.com"
//   m.groups   — capture groups [$1, $2, ...] (empty when the pattern has none)
//   m.start    — byte offset of the match within the block (read-only)
//   m.end      — byte offset of the match end (read-only)
//   m.before   — a window of text immediately before the match (context)
//   m.after    — a window of text immediately after the match (context)
//
// RETURN VALUE:
//   - a string                 → replaces the matched span with that string
//   - #{ replace: "..." }      → same as returning the string
//   - #{ drop: true }          → removes the matched span entirely
//   - ()  (or the match itself) → leaves the span unchanged
//
// For streaming responses, each block is buffered until complete, then this
// script runs on the full block text before forwarding.
// ─────────────────────────────────────────────────────────────────────

fn transform(m) {
    "anonymous@anonymous.org"
}
