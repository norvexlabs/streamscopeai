//! OpenAI Chat Completions wire types (`/v1/chat/completions`).
//!
//! Serde-driven request/response types that match the OpenAI wire format exactly.
//! Unknown fields are captured in `extra` via `#[serde(flatten)]` for forward
//! compatibility — the proxy preserves fields it doesn't understand.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::domain::{Message, Tool};

/// OpenAI Chat Completions request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logit_bias: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Forward-compat: capture unknown fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StopCondition {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<Value>,
}

/// Read the reasoning text out of a Chat Completions `message` object.
///
/// **Every reader of Chat Completions reasoning MUST go through here.**
/// Providers split on the spelling and none is universal — `reasoning`
/// (Ollama, OpenRouter), `reasoning_content` (DeepSeek, vLLM/SGLang
/// OpenAI-compat), and `thinking` chunks inside a chunk-array `content`
/// (Mistral) — and the recurring failure is one site learning a spelling its
/// siblings do not. Every such split has a visible consequence: reasoning that
/// is recorded in the audit trail but never redacted on the wire, or replayed
/// on one render path and silently dropped on another, or present when a
/// request streams and absent when the identical request does not.
///
/// Falls through an empty or non-string value on the first key, so a provider
/// that serializes both (one of them null or blank) is read correctly rather
/// than short-circuiting on mere presence. `thinking` chunks follow the key's
/// text — the order the streaming parser reads one delta in, so a body that
/// carries both reads the same streamed or not. Returns `None` when nothing
/// carries text — an absent reasoning channel, not an empty one. Writers go through
/// [`set_message_reasoning`] / [`reasoning_slots_mut`], which cover the same
/// set.
pub fn message_reasoning(message: &Value) -> Option<Cow<'_, str>> {
    let key = REASONING_KEYS
        .iter()
        .filter_map(|k| message.get(*k).and_then(|v| v.as_str()))
        .find(|s| !s.is_empty());
    match (key, content_thinking(message.get("content"))) {
        (Some(k), None) => Some(Cow::Borrowed(k)),
        (Some(k), Some(chunks)) => Some(Cow::Owned(format!("{k}{chunks}"))),
        (None, chunks) => chunks.map(Cow::Owned),
    }
}

/// Which channel one element of a Chat Completions chunk-array `content`
/// carries — the ONE predicate the streaming parser, the frame splitter, the
/// JSON readers and the writers share, so they can never disagree on which
/// chunk is which. Decided without building the chunk's text.
///
/// The array form is the Mistral spelling of `content` (`string | null |
/// ContentChunk[]`): text arrives as `{"type":"text","text":…}` and reasoning
/// as `{"type":"thinking","thinking":[{"type":"text","text":…}, …]}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkKind {
    /// A `text` chunk carrying text.
    Text,
    /// A `thinking` chunk with at least one `text` item carrying text.
    Thinking,
    /// Anything else: an empty or malformed chunk, a `reference`, an image, a
    /// `thinking` chunk holding only citations, a type this build does not
    /// know. Readers and writers leave it in place; it is never text.
    Other,
}

/// Classify one element of a chunk-array `content`. See [`ChunkKind`].
pub fn chunk_kind(chunk: &Value) -> ChunkKind {
    match chunk.get("type").and_then(Value::as_str) {
        Some("text") if chunk.get("text").and_then(Value::as_str).is_some_and(|t| !t.is_empty()) => {
            ChunkKind::Text
        }
        Some("thinking") if thinking_texts(chunk).any(|t| !t.is_empty()) => ChunkKind::Thinking,
        _ => ChunkKind::Other,
    }
}

/// The channel a chunk carries and its text there — a `text` chunk's text, or
/// a `thinking` chunk's prose items joined — from one classification. `None`
/// for [`ChunkKind::Other`].
pub fn chunk_text(chunk: &Value) -> Option<(ChunkKind, Cow<'_, str>)> {
    match chunk_kind(chunk) {
        ChunkKind::Text => chunk.get("text").and_then(Value::as_str).map(|t| (ChunkKind::Text, Cow::Borrowed(t))),
        ChunkKind::Thinking => Some((ChunkKind::Thinking, Cow::Owned(thinking_texts(chunk).collect()))),
        ChunkKind::Other => None,
    }
}

/// The type of each chunk in a chunk-array `content` that carries something
/// no reader takes as text or reasoning — a `reference` citation, an image, a
/// document, a type this build does not know — in order; a `thinking` chunk
/// holding only citations reads as `reference`. An empty `text` or `thinking`
/// chunk carries nothing and is not listed. A same-protocol client
/// is sent these chunks as they came; a translated client is not, so the
/// audit names them (`not_carried`).
pub fn unread_part_kinds(chunks: &[Value]) -> impl Iterator<Item = &str> {
    chunks.iter().filter(|c| chunk_kind(c) == ChunkKind::Other).filter_map(|c| {
        match c.get("type").and_then(Value::as_str) {
            Some("text") => None,
            // A `thinking` chunk with no prose: its items, if any, are citations.
            Some("thinking") => c
                .get("thinking")
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
                .then_some("reference"),
            Some(kind) => Some(kind),
            None => Some("untyped"),
        }
    })
}

/// The `not_carried` entries naming answer parts a translated client was not
/// sent, one per kind: `reference part in the answer`.
pub fn answer_parts_not_carried<'a>(kinds: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for kind in kinds {
        let entry = format!("{kind} part in the answer");
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

/// Whether an item inside a `thinking` chunk is reasoning prose. Its other
/// items (`reference`, `tool_reference`) are citations.
fn is_thinking_text_item(item: &Value) -> bool {
    item.get("type").and_then(Value::as_str) == Some("text") && item.get("text").is_some_and(Value::is_string)
}

/// The prose of a `thinking` chunk, item by item.
fn thinking_texts(chunk: &Value) -> impl Iterator<Item = &str> {
    chunk
        .get("thinking")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| is_thinking_text_item(item))
        .filter_map(|item| item.get("text").and_then(Value::as_str))
}

/// The text of every chunk of `kind` in a chunk-array `content`, joined in
/// order; `None` when none carries any.
fn joined(content: Option<&Value>, kind: ChunkKind) -> Option<String> {
    let text: String = content?
        .as_array()?
        .iter()
        .filter_map(chunk_text)
        .filter(|(k, _)| *k == kind)
        .map(|(_, t)| t)
        .collect();
    (!text.is_empty()).then_some(text)
}

/// The visible text of a Chat Completions `content` value: the string itself,
/// or every `text` chunk of a chunk array joined in order. `None` when there
/// is none — absent, null, empty, or an array without text.
///
/// **Every reader of Chat Completions response text MUST go through here**: a
/// reader that knows only the string form sees nothing in an array, so the
/// audit row, the PII scan and every translated client lose the answer while a
/// same-protocol client still receives it.
pub fn content_text(content: Option<&Value>) -> Option<Cow<'_, str>> {
    match content? {
        Value::String(s) if !s.is_empty() => Some(Cow::Borrowed(s)),
        array @ Value::Array(_) => joined(Some(array), ChunkKind::Text).map(Cow::Owned),
        _ => None,
    }
}

/// Reasoning carried as `thinking` chunks inside a chunk-array `content`,
/// joined in order. Read through [`message_reasoning`], never directly.
fn content_thinking(content: Option<&Value>) -> Option<String> {
    joined(content, ChunkKind::Thinking)
}

/// Every JSON string in `message` that carries reasoning: each
/// [`REASONING_KEYS`] spelling, and each prose item inside a `thinking` chunk.
/// The set [`message_reasoning`] reads from, so a writer masking every slot
/// leaves no unmasked copy on the wire.
pub fn reasoning_slots_mut(message: &mut Value) -> Vec<&mut Value> {
    let Some(obj) = message.as_object_mut() else { return Vec::new() };
    let mut slots = Vec::new();
    for (key, value) in obj.iter_mut() {
        if REASONING_KEYS.contains(&key.as_str()) && value.is_string() {
            slots.push(value);
        } else if key == "content"
            && let Value::Array(chunks) = value
        {
            for chunk in chunks.iter_mut().filter(|c| c.get("type").and_then(Value::as_str) == Some("thinking")) {
                for item in chunk
                    .get_mut("thinking")
                    .and_then(Value::as_array_mut)
                    .into_iter()
                    .flatten()
                    .filter(|item| is_thinking_text_item(item))
                {
                    if let Some(text) = item.get_mut("text") {
                        slots.push(text);
                    }
                }
            }
        }
    }
    slots
}

/// Every JSON string in `message` that carries visible text: the `content`
/// string, or each `text` chunk's `text` — the chunks [`content_text`] joins.
/// For an in-place rewrite that keeps every chunk where it is.
pub fn text_slots_mut(message: &mut Value) -> Vec<&mut Value> {
    match message.get_mut("content") {
        Some(s @ Value::String(_)) => vec![s],
        Some(Value::Array(chunks)) => chunks
            .iter_mut()
            .filter(|c| chunk_kind(c) == ChunkKind::Text)
            .filter_map(|c| c.get_mut("text"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Replace the visible text of `message` with `text`. A string (or absent)
/// `content` becomes the string; in a chunk array the first `text` chunk takes
/// the whole text and the other `text` chunks go — one channel, as
/// [`content_text`] reads it — while every other chunk keeps its order. A
/// `reference` that sat between two text chunks then follows the text rather
/// than splitting it: a rewritten text has no place inside it the citation
/// can be said to belong to.
pub fn set_content_text(message: &mut Value, text: String) {
    let Some(obj) = message.as_object_mut() else { return };
    match obj.get_mut("content") {
        Some(Value::Array(chunks)) => {
            let is_text = |c: &Value| chunk_kind(c) == ChunkKind::Text;
            match chunks.iter().position(is_text) {
                Some(first) => {
                    chunks[first]["text"] = Value::String(text);
                    let mut i = 0;
                    chunks.retain(|c| {
                        let keep = i == first || !is_text(c);
                        i += 1;
                        keep
                    });
                }
                None => chunks.push(serde_json::json!({"type": "text", "text": text})),
            }
        }
        _ => {
            obj.insert("content".to_string(), Value::String(text));
        }
    }
}

/// Append `text` after the visible text of `message`, on its own line when
/// there is text before it. A chunk array gains a `text` chunk at its end, so
/// nothing already there — reasoning included — is replaced.
pub fn append_content_text(message: &mut Value, text: &str) {
    let has_text = content_text(message.get("content")).is_some();
    let Some(obj) = message.as_object_mut() else { return };
    match obj.get_mut("content") {
        Some(Value::Array(chunks)) => {
            let piece = if has_text { format!("\n{text}") } else { text.to_string() };
            chunks.push(serde_json::json!({"type": "text", "text": piece}));
        }
        Some(Value::String(existing)) if !existing.is_empty() => {
            existing.push('\n');
            existing.push_str(text);
        }
        _ => {
            obj.insert("content".to_string(), Value::String(text.to_string()));
        }
    }
}

/// Replace the reasoning of `message` with `text` wherever it is carried, so
/// that [`message_reasoning`] reads back exactly `text`. They are one channel
/// under several names: rewriting only the one that was read would leave the
/// untransformed original on the wire beside it.
///
/// - A text equal to what is there changes nothing — a signature stays valid.
/// - Every [`REASONING_KEYS`] spelling that carries text takes `text`, and the
///   `thinking` chunks lose their prose (the key now carries the whole
///   channel the reader joined them into).
/// - Otherwise the first `thinking` chunk takes the whole text and the others
///   lose their prose.
///
/// A chunk that loses or changes its prose loses its `signature` — it signed
/// the reasoning the model wrote, which this no longer is, and a client
/// replaying it would present a signature over text it does not sign — but
/// keeps its citations; a chunk left with nothing at all goes.
pub fn set_message_reasoning(message: &mut Value, text: &str) {
    if message_reasoning(message).as_deref() == Some(text) {
        return;
    }
    let Some(obj) = message.as_object_mut() else { return };
    let mut keyed = false;
    for key in REASONING_KEYS {
        if obj.get(key).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            obj.insert(key.to_string(), Value::String(text.to_string()));
            keyed = true;
        }
    }
    let Some(Value::Array(chunks)) = obj.get_mut("content") else { return };
    let mut owner = (!keyed).then(|| chunks.iter().position(|c| chunk_kind(c) == ChunkKind::Thinking)).flatten();
    if owner.is_none() && !keyed {
        return;
    }
    let mut i = 0;
    chunks.retain_mut(|chunk| {
        let at = i;
        i += 1;
        if chunk_kind(chunk) != ChunkKind::Thinking {
            return true;
        }
        let Some(fields) = chunk.as_object_mut() else { return true };
        fields.remove("signature");
        let citations: Vec<Value> = fields
            .get("thinking")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| !is_thinking_text_item(item))
            .cloned()
            .collect();
        let mut items = Vec::with_capacity(citations.len() + 1);
        if owner == Some(at) {
            owner = None;
            items.push(serde_json::json!({"type": "text", "text": text}));
        }
        items.extend(citations);
        let keep = !items.is_empty();
        fields.insert("thinking".to_string(), Value::Array(items));
        keep
    });
}

/// The spellings of the Chat Completions reasoning channel, in read precedence.
///
/// These are two names for **one** channel, not two channels: readers take the
/// first carrying text, and a writer that rewrites reasoning must write every
/// one that carries text — leaving the other holding the untransformed original
/// would put unscreened reasoning on the wire beside the rewritten copy.
pub const REASONING_KEYS: [&str; 2] = ["reasoning", "reasoning_content"];

/// A Chat Completions `usage` object as the domain's [`super::domain::Usage`]
/// — the ONE reader for a stream's last chunk and a whole answer alike, so the
/// two are billed the same.
///
/// Two grammars share the object. OpenAI reports audio as prompt tokens
/// INSIDE `prompt_tokens` (`prompt_tokens_details.audio_tokens`), billed at
/// the audio rate by subtracting them from the text count. Mistral reports
/// audio in seconds (`prompt_audio_seconds`) and its `audio_tokens` OUTSIDE
/// `prompt_tokens` (live: a 3 s clip read `prompt_tokens` 9, `audio_tokens`
/// 375, `total_tokens` 389 = 9 + 375 + 5) — read as OpenAI's, the subtraction
/// would bill its text input at nothing. The seconds field is Mistral's
/// grammar, so where it is present the audio is billed in seconds and its
/// tokens are not a part of `prompt_tokens`. `cached_tokens` is a part of
/// `prompt_tokens` in both.
pub fn usage_of(usage: &Value) -> super::domain::Usage {
    let count = |v: Option<&Value>| v.and_then(Value::as_u64).map(|n| u32::try_from(n).unwrap_or(u32::MAX));
    let detail = |outer: &str, inner: &str| count(usage.get(outer).and_then(|d| d.get(inner)));
    let prompt = count(usage.get("prompt_tokens")).unwrap_or(0);
    let completion = count(usage.get("completion_tokens")).unwrap_or(0);
    // The key's presence is the grammar (Mistral sends it `null` for an answer
    // with no audio); a fraction of a second is billed as the whole second.
    let mistral_grammar = usage.get("prompt_audio_seconds").is_some();
    let audio_seconds = usage
        .get("prompt_audio_seconds")
        .and_then(Value::as_f64)
        .filter(|s| s.is_finite() && *s > 0.0)
        .map(|s| s.ceil().min(f64::from(u32::MAX)) as u32);
    super::domain::Usage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        reasoning_tokens: detail("completion_tokens_details", "reasoning_tokens"),
        cache_creation_tokens: None,
        cache_creation_1h_tokens: None,
        cache_read_tokens: detail("prompt_tokens_details", "cached_tokens"),
        audio_prompt_tokens: if mistral_grammar { None } else { detail("prompt_tokens_details", "audio_tokens") },
        audio_completion_tokens: detail("completion_tokens_details", "audio_tokens"),
        audio_prompt_seconds: audio_seconds,
        total_tokens: count(usage.get("total_tokens")).unwrap_or(prompt.saturating_add(completion)),
    }
}

#[cfg(test)]
mod reasoning_tests {
    use super::*;

    #[test]
    fn either_spelling_is_read_and_a_blank_one_never_wins() {
        let both_spellings = [
            serde_json::json!({"reasoning": "why"}),
            serde_json::json!({"reasoning_content": "why"}),
            serde_json::json!({"content": [
                {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]},
                {"type": "text", "text": "answer"}
            ]}),
        ];
        for m in &both_spellings {
            assert_eq!(message_reasoning(m).as_deref(), Some("why"), "{m}");
        }
        // A provider serializing both, one of them blank or null, must not
        // short-circuit onto the empty one — presence is not the signal, text is.
        assert_eq!(
            message_reasoning(&serde_json::json!({"reasoning": "", "reasoning_content": "why"})).as_deref(),
            Some("why")
        );
        assert_eq!(
            message_reasoning(&serde_json::json!({"reasoning": null, "reasoning_content": "why"})).as_deref(),
            Some("why")
        );
        assert_eq!(
            message_reasoning(&serde_json::json!({"reasoning": "", "content": [
                {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]}
            ]}))
            .as_deref(),
            Some("why")
        );
        assert_eq!(message_reasoning(&serde_json::json!({"content": "hi"})), None);
        assert_eq!(message_reasoning(&serde_json::json!({"reasoning": ""})), None);
        assert_eq!(
            message_reasoning(&serde_json::json!({"content": [
                {"type": "thinking", "thinking": [{"type": "reference", "reference_ids": [1]}]}
            ]})),
            None,
            "a thinking chunk holding only a citation carries no reasoning"
        );
    }

    #[test]
    fn content_text_reads_the_string_and_every_text_chunk_in_order() {
        use serde_json::json;
        assert_eq!(content_text(Some(&json!("hi"))).as_deref(), Some("hi"));
        assert_eq!(content_text(Some(&json!(""))), None);
        assert_eq!(content_text(Some(&Value::Null)), None);
        assert_eq!(content_text(None), None);
        let chunks = json!([
            {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]},
            {"type": "text", "text": "ans"},
            {"type": "reference", "reference_ids": [1]},
            {"type": "text", "text": "wer"}
        ]);
        assert_eq!(content_text(Some(&chunks)).as_deref(), Some("answer"));
        assert_eq!(content_text(Some(&json!([{"type": "reference", "reference_ids": [1]}]))), None);
    }

    #[test]
    fn writers_keep_every_chunk_that_is_not_the_channel_they_write() {
        use serde_json::json;
        let reference = json!({"type": "reference", "reference_ids": [1]});
        let mut m = json!({"content": [
            {"type": "thinking", "thinking": [{"type": "text", "text": "why"}], "signature": "s"},
            {"type": "text", "text": "a"},
            reference.clone(),
            {"type": "text", "text": "b"}
        ]});
        set_content_text(&mut m, "new".into());
        assert_eq!(content_text(m.get("content")).as_deref(), Some("new"));
        assert_eq!(message_reasoning(&m).as_deref(), Some("why"));
        assert!(m["content"].as_array().unwrap().contains(&reference), "{m}");

        set_message_reasoning(&mut m, "because");
        assert_eq!(message_reasoning(&m).as_deref(), Some("because"));
        assert_eq!(content_text(m.get("content")).as_deref(), Some("new"));

        append_content_text(&mut m, "notice");
        assert_eq!(content_text(m.get("content")).as_deref(), Some("new\nnotice"));
        assert_eq!(message_reasoning(&m).as_deref(), Some("because"));

        // A key and `thinking` chunks together read as one channel, key first
        // (the order the streaming parser reads a delta in); the rewrite lands
        // in the key and the chunks go, so it reads back once and nothing
        // untransformed stays beside it.
        let mut both = json!({"reasoning": "key", "content": [
            {"type": "thinking", "thinking": [{"type": "text", "text": "chunk"}]},
            {"type": "text", "text": "a"}
        ]});
        assert_eq!(message_reasoning(&both).as_deref(), Some("keychunk"));
        set_message_reasoning(&mut both, "R");
        assert_eq!(both["reasoning"], "R");
        assert_eq!(message_reasoning(&both).as_deref(), Some("R"));
        assert_eq!(content_text(both.get("content")).as_deref(), Some("a"));

        // A chunk that loses its prose keeps its citations.
        let mut cited = json!({"reasoning": "key", "content": [
            {"type": "thinking", "thinking": [
                {"type": "text", "text": "chunk"},
                {"type": "reference", "reference_ids": [3]}
            ], "signature": "s"}
        ]});
        set_message_reasoning(&mut cited, "R");
        assert_eq!(message_reasoning(&cited).as_deref(), Some("R"));
        assert_eq!(
            cited["content"],
            json!([{"type": "thinking", "thinking": [{"type": "reference", "reference_ids": [3]}]}])
        );

        // A rewrite drops the signature that signed the old reasoning; an
        // unchanged one keeps it.
        let signed = json!({"content": [
            {"type": "thinking", "thinking": [{"type": "text", "text": "why"}], "signature": "s"}
        ]});
        let mut same = signed.clone();
        set_message_reasoning(&mut same, "why");
        assert_eq!(same, signed);
        let mut changed = signed.clone();
        set_message_reasoning(&mut changed, "other");
        assert_eq!(changed["content"][0].get("signature"), None);

        // The string form stays a string.
        let mut s = json!({"content": "x"});
        append_content_text(&mut s, "n");
        assert_eq!(s["content"], "x\nn");
        let mut empty = json!({"content": null});
        append_content_text(&mut empty, "n");
        assert_eq!(empty["content"], "n");
    }

    fn chunk() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let text = "[a-z ]{0,6}";
        prop_oneof![
            text.prop_map(|t| serde_json::json!({"type": "text", "text": t})),
            (text, any::<bool>()).prop_map(|(t, cite)| {
                let mut items = vec![serde_json::json!({"type": "text", "text": t})];
                if cite {
                    items.push(serde_json::json!({"type": "reference", "reference_ids": [1]}));
                }
                serde_json::json!({"type": "thinking", "thinking": items})
            }),
            Just(serde_json::json!({"type": "reference", "reference_ids": [7]})),
            Just(serde_json::json!({"type": "image_url", "image_url": "data:x"})),
        ]
    }

    proptest::proptest! {
        /// The readers and the slot writers cover ONE set: masking every slot
        /// leaves no character of the original text or reasoning readable, and
        /// a rewrite through the setters is read back exactly while every chunk
        /// of the other kinds keeps its place.
        #[test]
        fn readers_and_writers_cover_the_same_chunks(
            chunks in proptest::collection::vec(chunk(), 0..6),
            new_text in "[A-Z]{1,4}",
        ) {
            let message = serde_json::json!({"content": chunks});
            let others = |m: &Value| -> Vec<Value> {
                m["content"].as_array().unwrap().iter()
                    .filter(|c| !matches!(c["type"].as_str(), Some("text" | "thinking")))
                    .cloned().collect()
            };

            let mut masked = message.clone();
            set_content_text(&mut masked, String::new());
            for slot in reasoning_slots_mut(&mut masked) { *slot = Value::String(String::new()); }
            proptest::prop_assert_eq!(content_text(masked.get("content")), None);
            proptest::prop_assert_eq!(message_reasoning(&masked), None);

            let text_of = |m: &Value| content_text(m.get("content")).map(Cow::into_owned);
            let reasoning_of = |m: &Value| message_reasoning(m).map(Cow::into_owned);

            let mut rewritten = message.clone();
            set_content_text(&mut rewritten, new_text.clone());
            proptest::prop_assert_eq!(text_of(&rewritten), Some(new_text.clone()));
            proptest::prop_assert_eq!(reasoning_of(&rewritten), reasoning_of(&message));
            proptest::prop_assert_eq!(others(&rewritten), others(&message));

            let had_reasoning = reasoning_of(&message).is_some();
            set_message_reasoning(&mut rewritten, &new_text);
            proptest::prop_assert_eq!(reasoning_of(&rewritten), had_reasoning.then(|| new_text.clone()));
            proptest::prop_assert_eq!(text_of(&rewritten), Some(new_text.clone()));
            proptest::prop_assert_eq!(others(&rewritten), others(&message));
        }
    }

    /// Every site that reads Chat Completions reasoning must go through
    /// [`message_reasoning`].
    ///
    /// This is a real, repeated defect, not a hypothetical: sites have disagreed
    /// on the spelling three separate times, and each split had a visible
    /// consequence — reasoning recorded in the audit trail but never redacted on
    /// the wire, replayed on one render path and dropped on another, present when
    /// a request streams and absent when the identical request does not. A grep
    /// gate is crude, but a new reader is exactly what it catches.
    #[test]
    fn reasoning_is_read_through_one_helper_only() {
        use std::path::PathBuf;

        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root resolves from CARGO_MANIFEST_DIR/../..")
            .to_path_buf();

        // Sites that legitimately name the raw keys in PRODUCTION code:
        // - `api/chat.rs` — the helper and `REASONING_KEYS` itself.
        // - `api/sse.rs` — the streaming delta is a typed struct, so its serde
        //   idents cannot come from the const; `chat_delta_covers_every_reasoning_spelling`
        //   ties the two together instead.
        //
        // Nothing else belongs here, and this list must not grow: a file whose
        // production code needs the set iterates `REASONING_KEYS`, which every
        // reader and both writers do. A file-level exemption would let a second
        // hand-rolled enumeration sit here unnoticed.
        let allowed_relative: &[&str] = &[
            "crates/streamscope-core/src/api/chat.rs",
            "crates/streamscope-core/src/api/sse.rs",
        ];
        // `reasoning_content` and the `/message/reasoning` pointer are specific to
        // a Chat Completions message body, so they carry no false positives. The
        // bare `"reasoning"` key is deliberately NOT a needle — it also names the
        // Responses request parameter, the Gemini thinking config and several
        // writers, and a gate that noisy would be rubber-stamped rather than read.
        // The consequence: this catches a new reader that knows BOTH spellings but
        // bypasses the helper, not one that knows only the `reasoning` spelling.
        // Which is the right trade — the helper's own doc is where a reader learns
        // there are two, and every current reader routes through it.
        let needles = ["\"reasoning_content\"", "/message/reasoning"];

        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![workspace_root.join("crates")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&workspace_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if allowed_relative.contains(&rel.as_str()) {
                    continue;
                }
                let Ok(src) = std::fs::read_to_string(&path) else {
                    continue;
                };
                scanned += 1;
                // Production code only — test fixtures legitimately spell out
                // wire JSON. Never widen this to a whole-FILE exemption: that
                // hides a production copy of the set behind the fixtures that
                // needed the exemption.
                //
                // Truncation is safe ONLY for a terminal test module. A file can
                // hold a mid-file `#[cfg(test)]` with production code below it
                // (several admin route files do), and truncating there would
                // blind the scan to that code. So truncate only when nothing
                // below the module opens another top-level item, and scan the
                // whole file otherwise — this must never scan less than the
                // production surface.
                let production = match src.split_once("#[cfg(test)]") {
                    Some((head, rest)) if src.matches("#[cfg(test)]").count() == 1 => {
                        let item_below = rest
                            .lines()
                            .filter(|l| !l.is_empty() && !l.starts_with(char::is_whitespace))
                            .skip(1) // the test module's own `mod … {`
                            .any(|l| !l.starts_with('}'));
                        if item_below { &src } else { head }
                    }
                    _ => &src,
                };
                for (i, line) in production.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or(line);
                    if needles.iter().any(|n| code.contains(n)) {
                        offenders.push(format!("{rel}:{}", i + 1));
                    }
                }
            }
        }
        // Structural, not environmental: a gate that silently scanned nothing
        // would pass forever.
        assert!(scanned > 100, "expected to scan the workspace, saw {scanned} files");
        assert!(
            offenders.is_empty(),
            "these sites name a Chat Completions reasoning key directly instead of reading \
             through `chat::message_reasoning` or iterating `chat::REASONING_KEYS`, which is \
             how the spellings drift apart: {offenders:?}"
        );
    }
}

#[cfg(test)]
mod usage_tests {
    use super::usage_of;
    use crate::pricing::{Currency, Rate, Rates, Unit};
    use serde_json::json;

    fn rates(pairs: &[(Unit, f64)]) -> Rates {
        Rates::from_units(pairs.iter().map(|(u, r)| (*u, Rate::Flat(*r))).collect(), Currency::USD)
    }

    /// Mistral's audio is outside `prompt_tokens` and priced per second: the
    /// text input is billed whole and the clip by its seconds — its 375 audio
    /// tokens are not a part of its 9 prompt tokens, so nothing is carved out.
    #[test]
    fn mistrals_audio_is_billed_in_seconds_beside_the_whole_text_input() {
        let u = usage_of(&json!({"prompt_tokens": 9, "completion_tokens": 5, "total_tokens": 389,
            "prompt_audio_seconds": 3,
            "prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 375}}));
        assert_eq!((u.prompt_tokens, u.audio_prompt_tokens, u.audio_prompt_seconds), (9, None, Some(3)));
        let cost = rates(&[(Unit::InputToken, 1.0), (Unit::OutputToken, 2.0), (Unit::AudioSecond, 0.5)])
            .cost(&u.billed_units());
        assert_eq!(cost.lines[&Unit::InputToken].count, 9);
        assert_eq!(cost.lines[&Unit::AudioSecond].count, 3);
        assert!(cost.unpriced.is_empty());
        // No per-second price published: the audio is named unpriced, the
        // text still billed — a floor, never a silent zero.
        let cost = rates(&[(Unit::InputToken, 1.0), (Unit::OutputToken, 2.0)]).cost(&u.billed_units());
        assert_eq!(cost.lines[&Unit::InputToken].count, 9);
        assert_eq!(cost.unpriced, [Unit::AudioSecond]);
        // The grammar is the key's presence, whatever its value: a fraction is
        // the whole second, a `null` no audio — never the OpenAI subtraction.
        for (seconds, billed) in [(json!(3.4), Some(4)), (json!(null), None)] {
            let u = usage_of(&json!({"prompt_tokens": 9, "completion_tokens": 5, "prompt_audio_seconds": seconds,
                "prompt_tokens_details": {"audio_tokens": 375}}));
            assert_eq!((u.audio_prompt_tokens, u.audio_prompt_seconds), (None, billed), "{seconds}");
        }
    }

    /// OpenAI's audio tokens are a part of `prompt_tokens`, cached tokens a
    /// part of it in both grammars.
    #[test]
    fn openais_audio_and_every_cache_read_are_parts_of_the_prompt() {
        let u = usage_of(&json!({"prompt_tokens": 100, "completion_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 20, "audio_tokens": 30},
            "completion_tokens_details": {"reasoning_tokens": 4, "audio_tokens": 6}}));
        assert_eq!(u.audio_prompt_tokens, Some(30));
        assert_eq!(u.audio_completion_tokens, Some(6));
        assert_eq!(u.cache_read_tokens, Some(20));
        assert_eq!(u.reasoning_tokens, Some(4));
        assert_eq!(u.audio_prompt_seconds, None);
        assert_eq!(u.total_tokens, 110);
        let cost = rates(&[(Unit::InputToken, 1.0), (Unit::CacheReadToken, 1.0), (Unit::AudioInputToken, 1.0), (Unit::OutputToken, 1.0)])
            .cost(&u.billed_units());
        assert_eq!(cost.lines[&Unit::InputToken].count, 50);
    }
}
