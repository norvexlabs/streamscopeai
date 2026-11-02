// name = "email_anonymizer_request"
// description = "Tutorial: anonymizes email addresses in request messages before sending upstream. Replaces any email (e.g. john@company.com) with anonymous@anonymous.org. Disabled by default — enable to activate."
// phase = "request"
// scope = "messages"
// priority = 100
// enabled = false
// app_filter = "!streamscope-agent"
// trigger_regex = "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
// match_mode = "span"

// ─────────────────────────────────────────────────────────────────────
// SPAN-MODE TRANSFORM TUTORIAL (request phase)
// ─────────────────────────────────────────────────────────────────────
//
// This is a SPAN-MODE transform (`match_mode = "span"`). Instead of receiving
// the whole conversation, the gateway finds every match of `trigger_regex` in
// the in-scope content (here: each request message) and runs this script ONCE
// PER MATCH. The script rewrites only the matched span — the engine handles
// locating matches and splicing replacements back, so there is no string
// surgery or index math to get right.
//
// The script receives a per-match object `m` (NOT the full RequestContext):
//
//   m.matched  — the matched text (string), e.g. "john@company.com"
//   m.groups   — capture groups [$1, $2, ...] (empty when the pattern has none)
//   m.start    — byte offset of the match within the field (read-only)
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
// `trigger_regex` is REQUIRED in span mode — it is the pattern the engine
// matches against. Here it matches standard email addresses; every match is
// replaced with a fixed anonymous address.
// ─────────────────────────────────────────────────────────────────────

fn transform(m) {
    "anonymous@anonymous.org"
}
