//! Output fingerprints: what lets the ingest tell that a new conversation
//! QUOTES an earlier turn — the agent's compaction re-sending an answer, a
//! subagent opening with its parent's tool-call argument.
//!
//! A text is cut into lines; each line, trimmed, that reads as prose — at
//! least [`MIN_BYTES`] bytes and [`MIN_WORDS`] words, at most [`MAX_BYTES`] —
//! is a segment, named by 8 bytes of its SHA-256. A quote survives any wrapper
//! a client puts around it on lines of its own (`<conversation-checkpoint>`,
//! `</system-reminder>`, a subagent preamble); a path, a URL, an identifier or
//! a base64 run is no segment, so a stray one cannot link two conversations.
//! An opening is read by its text parts only, without the context a client
//! injects into every conversation (its reminders, its instructions file):
//! shared by all of them, it is no quote of one. A tool result or a tool call
//! in it is no prose of the user's (a file's contents read back).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A segment's shortest line, in bytes.
pub const MIN_BYTES: usize = 24;
/// A segment's fewest whitespace-separated words.
pub const MIN_WORDS: usize = 3;
/// A segment's longest line, in bytes: past it a line is data, not prose.
pub const MAX_BYTES: usize = 16 * 1024;
/// The most segments kept of an opening: its quote may come last, after a
/// client's long preamble.
pub const OPENING_MAX: usize = 512;
/// The most segments kept of an answer.
pub const ANSWER_MAX: usize = 32;
/// The most segments kept of one string argument of a tool call — the same as
/// an answer's: the ingest ranks two quoted texts by how many of their lines
/// an opening carries, so neither kind may be cut shorter than the other.
pub const ARGUMENT_MAX: usize = ANSWER_MAX;
/// The most segments kept of all of one answer's tool-call arguments together.
pub const ARGUMENT_SEGMENTS_MAX: usize = 256;
/// How many messages from the conversation's start (its system run left out)
/// are tried for its opening: the first with text of the user's own.
pub const OPENING_CANDIDATES: usize = 4;

/// What one turn of a conversation can be quoted by, and what it quotes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnFingerprints {
    /// The segments of the message the conversation opens with — only on a
    /// turn that continues no earlier turn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opening: Vec<i64>,
    /// The segments of the answer's text (its reasoning left out).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<i64>,
    /// The segments of each string argument of the answer's tool calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<ArgumentFingerprints>,
}

impl TurnFingerprints {
    pub fn is_empty(&self) -> bool {
        self.opening.is_empty() && self.answer.is_empty() && self.arguments.is_empty()
    }
}

/// The segments of one string argument of one tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgumentFingerprints {
    /// The call's id, as the answer carries it.
    pub call_id: String,
    /// The argument's place among the call's string arguments (0-based).
    pub part: i16,
    pub segments: Vec<i64>,
}

/// The segments of `text`, in order, each once, at most `max`.
pub fn segments(text: &str, max: usize) -> Vec<i64> {
    let mut out = Vec::new();
    push_segments(text, max, &mut out);
    out
}

/// The segments of the user's own prose in the JSON document `json` (a
/// message as sent): its text — every string value outside a tool block
/// ([`for_each_text`]) — without the context a client injects
/// ([`own_prose`]), in document order, each once, at most `max`. A document
/// that does not parse is read as text.
///
/// [`own_prose`]: super::content::own_prose
pub fn json_segments(json: &str, max: usize) -> Vec<i64> {
    let mut out = Vec::new();
    let mut push = |s: &str| {
        if let Some(prose) = super::content::own_prose(s) {
            push_segments(&prose, max, &mut out);
        }
    };
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => for_each_text(&value, &mut |s| push(s)),
        Err(_) => push(json),
    }
    out
}

/// Where a conversation opens among `messages` (each as sent, in order),
/// trying `candidates` — the indices that may open it, in order (past its
/// system run, a volatile message left out): the first of the first
/// [`OPENING_CANDIDATES`] the user sent with any text of their own
/// ([`has_own_text`]), else the first. A client's injected context sent as a message of its own
/// (an instructions file, an environment block) is the same in every
/// conversation, so it never names one while a message after it can; nor
/// does an answer a client seeds (a greeting). Only these are passed over —
/// never a short message of the user's — so the choice is made by the
/// conversation's first messages and holds as its history grows.
pub fn opening_of(messages: &[String], candidates: impl IntoIterator<Item = usize>) -> Option<usize> {
    let mut candidates = candidates.into_iter().filter(|&i| i < messages.len()).peekable();
    let first = *candidates.peek()?;
    Some(candidates.take(OPENING_CANDIDATES).find(|&i| has_own_text(&messages[i])).unwrap_or(first))
}

/// Whether the message `json` (as sent) is the user's — not an answer (the
/// `assistant` / `model` role) — and carries any text that is not context a
/// client injects ([`own_prose`]), however short. A message past
/// [`OWN_TEXT_PARSE_MAX`] is the user's own without being read: a client's
/// injected context is a few kilobytes, and a large first message (a pasted
/// document, an image) is read on every turn of its conversation.
///
/// [`own_prose`]: super::content::own_prose
fn has_own_text(json: &str) -> bool {
    if json.len() > OWN_TEXT_PARSE_MAX {
        return true;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return super::content::own_prose(json).is_some_and(|p| !p.trim().is_empty());
    };
    if matches!(value.get("role").and_then(serde_json::Value::as_str), Some("assistant" | "model")) {
        return false;
    }
    let mut own = false;
    for_each_text(&value, &mut |s| {
        own = own || super::content::own_prose(s).is_some_and(|p| !p.trim().is_empty());
    });
    own
}

/// The largest message [`has_own_text`] reads, in bytes.
const OWN_TEXT_PARSE_MAX: usize = 64 * 1024;

/// The text values of a message: every string under `value`, in document
/// order (object keys are not values), except a block's metadata (its role,
/// type, ids — `METADATA_KEYS`) and anything inside a tool block — a tool
/// result, a tool call, a tool message — whose strings are a tool's, not the
/// user's. The block shapes are each protocol's own: a `type` naming a tool
/// call or result (Anthropic, Responses), a `functionCall` / `functionResponse`
/// part (Gemini), a `tool` role or a `tool_calls` list (Chat Completions).
fn for_each_text<'v>(value: &'v serde_json::Value, f: &mut impl FnMut(&'v str)) {
    const TOOL_TYPES: &[&str] = &["tool_result", "tool_use", "server_tool_use", "function_call", "function_call_output"];
    const TOOL_KEYS: &[&str] = &["tool_calls", "function_call", "functionCall", "functionResponse"];
    const METADATA_KEYS: &[&str] = &[
        "role", "type", "id", "name", "status", "call_id", "tool_call_id", "tool_use_id",
        "cache_control", "media_type", "mime_type", "mimeType", "signature",
    ];
    match value {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(items) => items.iter().for_each(|v| for_each_text(v, f)),
        serde_json::Value::Object(members) => {
            let kind = members.get("type").and_then(serde_json::Value::as_str);
            let role = members.get("role").and_then(serde_json::Value::as_str);
            if kind.is_some_and(|k| TOOL_TYPES.contains(&k) || k.ends_with("_tool_result")) || matches!(role, Some("tool" | "function")) {
                return;
            }
            members
                .iter()
                .filter(|(k, _)| !TOOL_KEYS.contains(&k.as_str()) && !METADATA_KEYS.contains(&k.as_str()))
                .for_each(|(_, v)| for_each_text(v, f));
        }
        _ => {}
    }
}

/// The fingerprinted string arguments of a tool call whose arguments are
/// `arguments` (a JSON document as the model sent it; read as one string when
/// it does not parse). An argument with no segment is left out, its place kept.
pub fn call_arguments(call_id: &str, arguments: &str) -> Vec<ArgumentFingerprints> {
    let mut strings: Vec<&str> = Vec::new();
    let parsed = serde_json::from_str::<serde_json::Value>(arguments);
    match &parsed {
        Ok(value) => for_each_string(value, &mut |s| strings.push(s)),
        Err(_) => strings.push(arguments),
    }
    strings
        .into_iter()
        .enumerate()
        .filter_map(|(part, s)| {
            let part = i16::try_from(part).ok()?;
            let segments = segments(s, ARGUMENT_MAX);
            (!segments.is_empty()).then(|| ArgumentFingerprints { call_id: call_id.to_string(), part, segments })
        })
        .collect()
}

/// Every string value under `value`, in document order (object keys are not
/// values).
fn for_each_string<'v>(value: &'v serde_json::Value, f: &mut impl FnMut(&'v str)) {
    match value {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(items) => items.iter().for_each(|v| for_each_string(v, f)),
        serde_json::Value::Object(members) => members.values().for_each(|v| for_each_string(v, f)),
        _ => {}
    }
}

fn push_segments(text: &str, max: usize, out: &mut Vec<i64>) {
    for line in text.lines() {
        if out.len() >= max {
            return;
        }
        let line = line.trim();
        if !(MIN_BYTES..=MAX_BYTES).contains(&line.len()) || line.split_whitespace().nth(MIN_WORDS - 1).is_none() {
            continue;
        }
        let fp = of_line(line);
        if !out.contains(&fp) {
            out.push(fp);
        }
    }
}

/// The fingerprint of one trimmed line.
fn of_line(line: &str) -> i64 {
    let mut digest = Sha256::new();
    digest.update(b"streamscope-fingerprint\0");
    digest.update(line.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[..8]);
    i64::from_be_bytes(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const PROMPT: &str = "What is 2+2? Reply with the number only.";

    #[test]
    fn a_segment_is_a_line_of_prose_trimmed() {
        assert_eq!(segments(&format!("  {PROMPT}\t"), 8), segments(PROMPT, 8));
        assert_eq!(segments(PROMPT, 8).len(), 1);
        // Too short, too few words, too long: no segment.
        assert!(segments("short line of text", 8).is_empty());
        assert!(segments("/work/project/src/some/deep/module/file.rs", 8).is_empty());
        assert!(segments("two words-that-are-long-enough-together", 8).is_empty());
        assert_eq!(segments("one two three-and-more-bytes", 8).len(), 1);
        let mut longest = "one two three ".to_string();
        longest.push_str(&"x".repeat(MAX_BYTES - longest.len()));
        assert_eq!(segments(&longest, 8).len(), 1);
        assert!(segments(&format!("{longest}x"), 8).is_empty());
        // Each once, at most `max`, in order.
        let text = "first line of the text here\nsecond line of the text here\nfirst line of the text here";
        assert_eq!(segments(text, 8).len(), 2);
        assert_eq!(segments(text, 1), segments("first line of the text here", 8));
    }

    #[test]
    fn a_json_message_is_read_by_its_string_values() {
        let message = serde_json::json!({
            "role": "user",
            "content": [
                {"type": "text", "text": "<system-reminder>\nThe reminder a client injects here\n</system-reminder>\n"},
                {"type": "text", "text": PROMPT},
            ]
        });
        // The reminder is the client's, in every conversation: only the prompt counts.
        let got = json_segments(&message.to_string(), 8);
        assert_eq!(got, segments(PROMPT, 8));
        assert_eq!(json_segments(PROMPT, 8), segments(PROMPT, 8));
        // Positive control: the same line outside a reminder block is prose.
        let plain = serde_json::json!({"role": "user", "content": format!("The reminder a client injects here\n{PROMPT}")});
        assert_eq!(json_segments(&plain.to_string(), 8), [segments("The reminder a client injects here", 8), segments(PROMPT, 8)].concat());
        // An instructions file a client sends as its own text is no prose of the user's.
        let agents = serde_json::json!({"role": "user", "content": "# AGENTS.md instructions\nAlways run the whole test suite first"});
        assert!(json_segments(&agents.to_string(), 8).is_empty());
    }

    #[test]
    fn a_calls_string_arguments_are_fingerprinted_each_in_its_place() {
        let args = serde_json::json!({"description": "add", "prompt": PROMPT, "n": 3}).to_string();
        let got = call_arguments("call_1", &args);
        // `description` is too short to fingerprint; `prompt` keeps its place.
        assert_eq!(got, vec![ArgumentFingerprints { call_id: "call_1".into(), part: 1, segments: segments(PROMPT, 8) }]);
        assert_eq!(call_arguments("c", PROMPT)[0].segments, segments(PROMPT, 8));
        assert!(call_arguments("c", "{}").is_empty());
    }

    #[test]
    fn a_tool_block_is_no_prose_of_the_users() {
        let file = "The configuration loader reads every file in order";
        // Anthropic: a tool result beside the user's text.
        let anthropic = serde_json::json!({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": file},
            {"type": "text", "text": PROMPT},
        ]});
        assert_eq!(json_segments(&anthropic.to_string(), 8), segments(PROMPT, 8));
        // Responses, Gemini and Chat Completions tool shapes.
        let output = serde_json::json!({"type": "function_call_output", "call_id": "c", "output": file});
        assert!(json_segments(&output.to_string(), 8).is_empty());
        let gemini = serde_json::json!({"role": "user", "parts": [{"functionResponse": {"name": "read", "response": {"text": file}}}, {"text": PROMPT}]});
        assert_eq!(json_segments(&gemini.to_string(), 8), segments(PROMPT, 8));
        let tool = serde_json::json!({"role": "tool", "tool_call_id": "c", "content": file});
        assert!(json_segments(&tool.to_string(), 8).is_empty());
        // Positive control: the same text as the user's own is prose.
        let own = serde_json::json!({"role": "user", "content": file});
        assert_eq!(json_segments(&own.to_string(), 8), segments(file, 8));
    }

    #[test]
    fn a_conversation_opens_with_its_first_message_of_the_users_own_prose() {
        let message = |text: &str| serde_json::json!({"role": "user", "content": text}).to_string();
        let agents = message("# AGENTS.md instructions\nAlways run the whole test suite first");
        let messages = [agents.clone(), message("ok"), message(PROMPT)];
        // The instructions file is passed; a short message of the user's own
        // is the opening, whatever comes after it.
        assert_eq!(opening_of(&messages, 0..3), Some(1));
        assert_eq!(opening_of(&messages[..2], 0..2), Some(1));
        assert_eq!(opening_of(&messages, [0, 2]), Some(2));
        // An answer a client seeds (a greeting) is passed over too.
        let greeting = serde_json::json!({"role": "assistant", "content": "Hi, I am the assistant, how can I help?"}).to_string();
        assert_eq!(opening_of(&[greeting, message(PROMPT)], 0..2), Some(1));
        // Only the candidates are tried, and past the first few none is.
        assert_eq!(opening_of(&messages, [0]), Some(0));
        let late: Vec<String> = std::iter::repeat_n(agents, OPENING_CANDIDATES).chain([message(PROMPT)]).collect();
        assert_eq!(opening_of(&late, 0..late.len()), Some(0));
        // Nothing to open with.
        assert_eq!(opening_of(&messages, [7]), None);
    }

    proptest! {
        /// A quoted line is found whatever a client wraps around it on lines of
        /// its own — the wrappers recorded from real clients included.
        #[test]
        fn a_quote_survives_the_wrappers_clients_put_around_it(
            words in proptest::collection::vec("[a-zA-Z0-9]{1,12}", 3..20),
            wrapper in prop_oneof![
                Just(("<conversation-checkpoint>\n<summary>\n", "\n</summary>\n</conversation-checkpoint>")),
                Just(("<system-reminder>\nRead the files first.\n</system-reminder>\n", "")),
                Just(("You are a subagent spawned by another session.\n", "")),
                Just(("Here is the first message of the conversation:\n\n<message>\n", "\n</message>\n\nReply with only the title.")),
            ],
        ) {
            let line = words.join(" ");
            let quoted = segments(&line, ANSWER_MAX);
            prop_assume!(!quoted.is_empty());
            let opening = segments(&format!("{}  {line}  {}", wrapper.0, wrapper.1), OPENING_MAX);
            prop_assert!(quoted.iter().all(|fp| opening.contains(fp)));
        }
    }
}
