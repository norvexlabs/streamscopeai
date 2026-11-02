//! SSE (Server-Sent Events) codec for streaming LLM responses.
//!
//! Provides a tokio-codec [`SseDecoder`] that reassembles partial TCP chunks into
//! complete SSE events, and an [`SseEncoder`] that serializes [`DomainEvent`]s back
//! to wire format. Protocol-aware: handles differences between OpenAI (`data: [DONE]`),
//! Anthropic (`event: message_stop`), and Gemini (`data: {...}` with `finishReason`)
//! termination conventions.

use bytes::{Buf, BytesMut};
use serde::Deserialize;
use serde_json::Value;
use tokio_util::codec::{Decoder, Encoder};

use super::domain::{DomainEvent, FinishReason, Usage};

/// A raw SSE event as received from the wire.
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

impl SseEvent {
    /// Check if this is the terminal [DONE] event.
    pub fn is_done(&self) -> bool {
        self.data.trim() == "[DONE]"
    }
}

/// Streaming size cap for a single SSE frame.
///
/// A decoder consumes nothing until it finds the `\n\n` that ends a frame, so
/// without a ceiling a target that streams bytes and never emits that boundary
/// grows the reassembly buffer without limit — the same unbounded-read hazard
/// [`crate::http_body::read_body_capped`] closes for non-streaming bodies, in
/// the one shape that reader cannot see. Matched to the MCP payload cap, since
/// an MCP `tools/call` result can legitimately arrive as one frame; every other
/// consumer's real frames are orders of magnitude smaller.
pub const MAX_SSE_FRAME_BYTES: usize = 32 * 1024 * 1024;

/// Decodes an SSE byte stream into `SseEvent` items.
///
/// Handles partial chunks correctly by buffering until a complete
/// event (terminated by `\n\n`) is found.
pub struct SseDecoder {
    /// Refuse a frame that grows past this without ever ending.
    max_frame_bytes: usize,
    /// How far into the pending frame the boundary search has already looked,
    /// so a frame arriving in N chunks is scanned once rather than N times.
    /// Reset whenever a frame is consumed.
    scanned: usize,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::with_max_frame_bytes(MAX_SSE_FRAME_BYTES)
    }

    pub fn with_max_frame_bytes(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes, scanned: 0 }
    }
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SseCodecError {
    #[error("invalid UTF-8 in SSE stream")]
    InvalidUtf8,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A frame grew past the cap without ever ending. The stream is abandoned:
    /// nothing can be decoded from it, and continuing to buffer is the failure
    /// mode the cap exists to prevent.
    #[error("SSE frame exceeds the {limit_bytes}-byte cap")]
    FrameTooLarge { limit_bytes: usize },
}

impl Decoder for SseDecoder {
    type Item = SseEvent;
    type Error = SseCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<SseEvent>, SseCodecError> {
        // Look for double newline boundary (end of SSE event). The search
        // resumes where the last one stopped — rewound far enough to catch a
        // boundary straddling the join — so a frame delivered in N chunks costs
        // one pass over its bytes, not N.
        let boundary = find_event_boundary(src, self.scanned.saturating_sub(3));
        let boundary = match boundary {
            Some(pos) => pos,
            None => {
                if src.len() > self.max_frame_bytes {
                    return Err(SseCodecError::FrameTooLarge {
                        limit_bytes: self.max_frame_bytes,
                    });
                }
                self.scanned = src.len();
                return Ok(None); // need more data
            }
        };

        // Extract the event block.
        self.scanned = 0;
        let event_bytes = src.split_to(boundary);
        // Consume the double newline.
        while !src.is_empty() && (src[0] == b'\n' || src[0] == b'\r') {
            src.advance(1);
        }

        let event_str =
            std::str::from_utf8(&event_bytes).map_err(|_| SseCodecError::InvalidUtf8)?;

        let mut event_type = None;
        let mut data_lines = Vec::new();
        let mut id = None;

        for line in event_str.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event_type = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data_lines.push(value.trim_start_matches(' ').to_string());
            } else if let Some(value) = line.strip_prefix("id:") {
                id = Some(value.trim().to_string());
            }
            // Ignore comments (lines starting with ':') and unknown fields.
        }

        if data_lines.is_empty() && event_type.is_none() {
            // Empty event (e.g., keep-alive), skip and try next.
            return self.decode(src);
        }

        let data = data_lines.join("\n");

        Ok(Some(SseEvent {
            event_type,
            data,
            id,
        }))
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<SseEvent>, SseCodecError> {
        // First try normal decode (handles case where buffer has a complete event).
        if let Some(event) = self.decode(buf)? {
            return Ok(Some(event));
        }

        // If there are remaining bytes without a trailing \n\n, parse them as a final event.
        // This handles servers that close the connection without a final double-newline.
        if buf.is_empty() {
            return Ok(None);
        }

        self.scanned = 0;
        let event_bytes = buf.split_to(buf.len());
        let event_str =
            std::str::from_utf8(&event_bytes).map_err(|_| SseCodecError::InvalidUtf8)?;

        let trimmed = event_str.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let mut event_type = None;
        let mut data_lines = Vec::new();
        let mut id = None;

        for line in trimmed.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event_type = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data_lines.push(value.trim_start_matches(' ').to_string());
            } else if let Some(value) = line.strip_prefix("id:") {
                id = Some(value.trim().to_string());
            }
        }

        if data_lines.is_empty() && event_type.is_none() {
            return Ok(None);
        }

        let data = data_lines.join("\n");

        Ok(Some(SseEvent {
            event_type,
            data,
            id,
        }))
    }
}

/// Find the position of a double newline boundary in the buffer.
fn find_event_boundary(src: &BytesMut, from: usize) -> Option<usize> {
    let bytes = &src[..];
    for i in from..bytes.len().saturating_sub(1) {
        if bytes[i] == b'\n' && bytes[i + 1] == b'\n' {
            return Some(i);
        }
        if bytes[i] == b'\r' && i + 3 <= bytes.len() && bytes[i + 1] == b'\n'
            && bytes[i + 2] == b'\r' && i + 3 < bytes.len() && bytes[i + 3] == b'\n' {
                return Some(i);
            }
    }
    None
}

/// Encodes `SseEvent` items back into SSE wire format.
pub struct SseEncoder;

impl SseEncoder {
    pub fn new() -> Self {
        Self
    }

    /// Encode an `SseEvent` borrowed by reference. The hot path in
    /// `response_pipeline::stream` calls the encoder once per upstream frame;
    /// taking the event by reference lets callers avoid an `SseEvent::clone`
    /// per frame when they already hold a borrow (e.g. the decoded upstream
    /// event they parsed domain events from).
    pub fn encode_ref(
        &mut self,
        item: &SseEvent,
        dst: &mut BytesMut,
    ) -> Result<(), SseCodecError> {
        // Pre-reserve to minimize BytesMut reallocation. The framing overhead
        // is `event: ...\n` plus `data: \n` per data line plus a trailing `\n`.
        let event_type_len = item
            .event_type
            .as_ref()
            .map(|s| s.len() + 8) // "event: " + value + "\n"
            .unwrap_or(0);
        // Approximate: raw data length + `data: ` and `\n` per line is hard
        // to precompute without scanning; reserve the raw length plus a small
        // per-line margin covering the common single-line case.
        dst.reserve(event_type_len + item.data.len() + 8);

        if let Some(event_type) = &item.event_type {
            dst.extend_from_slice(b"event: ");
            dst.extend_from_slice(event_type.as_bytes());
            dst.extend_from_slice(b"\n");
        }
        for line in item.data.split('\n') {
            dst.extend_from_slice(b"data: ");
            dst.extend_from_slice(line.as_bytes());
            dst.extend_from_slice(b"\n");
        }
        dst.extend_from_slice(b"\n");
        Ok(())
    }
}

impl Default for SseEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder<SseEvent> for SseEncoder {
    type Error = SseCodecError;

    fn encode(&mut self, item: SseEvent, dst: &mut BytesMut) -> Result<(), SseCodecError> {
        self.encode_ref(&item, dst)
    }
}

/// API version detected from request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiVersion {
    ChatCompletions,
    Responses,
    AnthropicMessages,
    GoogleGemini,
}

use serde::Serialize;

// ── Private serde structs for ChatCompletions SSE chunks ──

#[derive(Deserialize)]
struct ChatChunk {
    #[serde(default)]
    choices: Vec<ChatChunkChoice>,
    usage: Option<serde_json::Value>,
    /// A mid-stream failure: the chunk is the HTTP error object, which the
    /// OpenAI SDKs raise on.
    #[serde(default, deserialize_with = "present_error")]
    error: Option<StreamError>,
}

/// An `error` member of a stream chunk: the protocol's error object, or — from
/// some OpenAI-compatible servers — a bare message string. Either is the error
/// it says; neither may leave the chunk unparseable and the error dropped.
#[derive(Deserialize)]
#[serde(untagged)]
enum StreamError {
    Object(StreamErrorObject),
    Message(String),
}

/// A chunk's `error` member, read only when it is an error as the
/// non-streaming path reads one (`envelope::is_error`): `null`, `{}`, `""` or
/// `false` is none, so one body is an error on both paths or on neither.
fn present_error<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<StreamError>, D::Error> {
    match Option::<serde_json::Value>::deserialize(d)? {
        Some(v) if crate::error::envelope::is_error(&v) => {
            StreamError::deserialize(v).map(Some).map_err(serde::de::Error::custom)
        }
        _ => Ok(None),
    }
}

impl StreamError {
    fn into_event(self, raw: &str) -> DomainEvent {
        match self {
            StreamError::Object(object) => object.into_event(raw),
            StreamError::Message(message) => DomainEvent::Error { message, code: None },
        }
    }
}

/// The `error` object a Chat Completions or Gemini upstream sends as a chunk
/// when it fails mid-stream: a `message`, plus that protocol's word for what
/// went wrong — Gemini's AIP-193 `status` (its `code` is the HTTP status),
/// OpenAI's `code`, or its `type` where `code` is null.
///
/// Every member but `message` is read as any value and kept only when it is a
/// string: a server sending a number there (`"status": 500`) still sent an
/// error, and a strict type would make the chunk unparseable and drop it.
#[derive(Deserialize)]
struct StreamErrorObject {
    message: Option<String>,
    code: Option<serde_json::Value>,
    #[serde(rename = "type")]
    kind: Option<serde_json::Value>,
    status: Option<serde_json::Value>,
}

impl StreamErrorObject {
    fn into_event(self, raw: &str) -> DomainEvent {
        let text = |v: &Option<serde_json::Value>| v.as_ref().and_then(|v| v.as_str()).map(str::to_string);
        let code = text(&self.status).or_else(|| text(&self.code)).or_else(|| text(&self.kind));
        DomainEvent::Error {
            message: self.message.unwrap_or_else(|| raw.to_string()),
            code,
        }
    }
}

#[derive(Deserialize)]
struct ChatChunkChoice {
    delta: Option<ChatDelta>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChatDelta {
    /// A string, or a chunk array (Mistral: `text` and `thinking` chunks) —
    /// held raw and read through [`crate::api::chat::chunk_kind`], so no
    /// shape of `content` can fail the chunk and take its tool calls, finish
    /// reason and usage down with it.
    #[serde(default)]
    content: Option<Value>,
    /// Thinking/reasoning content from reasoning models. Providers split on the
    /// spelling and neither is universal (`reasoning`: Ollama, OpenRouter;
    /// `reasoning_content`: DeepSeek, vLLM/SGLang OpenAI-compat). BOTH must be
    /// read: a stream whose reasoning is never accumulated is invisible to the
    /// audit row, to the response PII scan, and to the response cache, while the
    /// passthrough emitter still forwards it to the client.
    ///
    /// These are serde idents, so they cannot be generated from
    /// [`crate::api::chat::REASONING_KEYS`] the way every non-streaming site
    /// reads and writes them. `chat_delta_covers_every_reasoning_spelling` is
    /// the link instead: it fails if a spelling is added to that const without a
    /// matching field here. Held raw like `content` and read as text only, so
    /// a non-string value is no reasoning rather than a chunk that fails.
    #[serde(default)]
    reasoning: Option<Value>,
    #[serde(default)]
    reasoning_content: Option<Value>,
    tool_calls: Option<Vec<ChatDeltaToolCall>>,
}

#[derive(Deserialize)]
struct ChatDeltaToolCall {
    index: Option<usize>,
    id: Option<String>,
    /// `"function"` in the spec's chunk; `"custom"` names a custom call whose
    /// opening delta carries no `custom` object yet.
    r#type: Option<String>,
    function: Option<ChatDeltaFunction>,
    /// A custom (freeform) tool call. The spec's chunk has only the function
    /// form ("Currently, only `function` is supported"); a server streaming a
    /// custom call sends its message form — `custom: {name, input}` — with the
    /// input in pieces.
    custom: Option<ChatDeltaCustom>,
}

#[derive(Deserialize)]
struct ChatDeltaCustom {
    name: Option<String>,
    input: Option<String>,
}

#[derive(Deserialize)]
struct ChatDeltaFunction {
    name: Option<String>,
    arguments: Option<String>,
}

// ── Private serde structs for Responses API SSE events ──

#[derive(Deserialize)]
struct ResponsesDelta {
    delta: Option<String>,
    /// The item the delta is of, by id and by place.
    item_id: Option<String>,
    output_index: Option<usize>,
}

#[derive(Deserialize)]
struct ResponsesArgumentsDone {
    arguments: Option<String>,
    item_id: Option<String>,
    output_index: Option<usize>,
}

#[derive(Deserialize)]
struct ResponsesCustomInputDone {
    input: Option<serde_json::Value>,
    item_id: Option<String>,
    output_index: Option<usize>,
}

#[derive(Deserialize)]
struct ResponsesCompleted {
    response: Option<ResponsesCompletedInner>,
}

#[derive(Deserialize)]
struct ResponsesCompletedInner {
    status: Option<String>,
    usage: Option<ResponsesUsage>,
    error: Option<ResponsesErrorInner>,
    #[serde(default)]
    incomplete_details: Option<ResponsesIncompleteDetails>,
}

#[derive(Deserialize)]
struct ResponsesIncompleteDetails {
    reason: Option<String>,
}

impl ResponsesCompletedInner {
    /// The answer's finish when it states `status` ([`FinishReason::of_responses_status`]).
    fn finish_as(&self, status: &str) -> Option<FinishReason> {
        FinishReason::of_responses_status(status, self.incomplete_details.as_ref().and_then(|d| d.reason.as_deref()))
    }
}

#[derive(Deserialize)]
struct ResponsesUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    total_tokens: Option<u32>,
    #[serde(default)]
    output_tokens_details: Option<ResponsesOutputTokenDetails>,
    #[serde(default)]
    input_tokens_details: Option<ResponsesInputTokenDetails>,
}

#[derive(Deserialize)]
struct ResponsesOutputTokenDetails {
    reasoning_tokens: Option<u32>,
    /// Completion tokens that carried audio. Part of `output_tokens`.
    audio_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ResponsesInputTokenDetails {
    cached_tokens: Option<u32>,
    /// Prompt tokens that carried audio. Part of `input_tokens`.
    audio_tokens: Option<u32>,
}

/// The Responses `error` streaming event. Its spec shape is flat — `code`,
/// `message`, `param`, `sequence_number` beside `type`; a server nesting them
/// under an `error` key is read too.
#[derive(Deserialize)]
struct ResponsesError {
    message: Option<String>,
    code: Option<String>,
    error: Option<ResponsesErrorInner>,
}

#[derive(Deserialize)]
struct ResponsesErrorInner {
    message: Option<String>,
    code: Option<String>,
}

/// Output item from `response.output_item.added` event.
#[derive(Deserialize)]
struct ResponsesOutputItem {
    item: Option<ResponsesOutputItemInner>,
    output_index: Option<usize>,
}

#[derive(Deserialize)]
struct ResponsesOutputItemInner {
    r#type: Option<String>,
    /// Used by function_call items
    call_id: Option<String>,
    /// Used by mcp_call items (falls back from `id`)
    id: Option<String>,
    name: Option<String>,
    /// MCP server label — tool name may be prefixed with `{server_label}.`
    server_label: Option<String>,
    /// A function or MCP call's arguments, as far as the item states them.
    arguments: Option<String>,
    /// A custom (freeform) tool call's free text. Read loosely: another item
    /// kind may carry an `input` of another shape, which must not make the
    /// whole frame unreadable.
    input: Option<serde_json::Value>,
    /// Base64 image result from `image_generation_call` (on output_item.done)
    result: Option<String>,
}


/// What a frame says beyond its domain events, read in the same parse.
#[derive(Default)]
struct FrameFacts {
    /// A Responses upstream's word that a custom call's text is complete
    /// (`custom_tool_call_input.done`, or the custom item's
    /// `output_item.done`), with the whole text it states.
    custom_call_done: Option<Option<String>>,
    /// A Responses upstream's statement of a function or MCP call's whole
    /// arguments (`…arguments.done`, the item's `output_item.done`).
    call_stated: Option<String>,
    /// The output item a Responses call event is of.
    item: Option<ItemAddress>,
    /// The kind of each answer part the frame carries that no event reads
    /// (a Chat chunk-array `reference`, `image_url`, …), by
    /// [`crate::api::chat::unread_part_kinds`].
    unread_parts: Vec<String>,
}

/// The output item a Responses event names, by its place in the response's
/// `output` (`output_index`) and by its id (`item_id`; the item's own `id`
/// where the frame opens it). A client applies a delta to the item it names —
/// the OpenAI SDKs by `output_index`, others by id — never to the item opened
/// last, so the stream places it by the same address.
struct ItemAddress {
    output_index: Option<usize>,
    item_id: Option<String>,
    /// The frame opens the item (`output_item.added`).
    opens: bool,
}

/// A Responses response's call items: each one's id, by its `output_index`
/// (or by the key it was opened under without one, see `UNINDEXED`), and the
/// place later named for an item opened without one.
#[derive(Default)]
struct ResponsesItems {
    items: std::collections::BTreeMap<usize, Option<String>>,
    places: std::collections::BTreeMap<usize, usize>,
}

impl ResponsesItems {
    /// Where an item opened without an `output_index` is kept: past any index
    /// a response states, so it is addressed by its id alone.
    const UNINDEXED: usize = usize::MAX / 2;

    /// The upstream index an event naming `item` is placed at — the item's
    /// `output_index` — or `None` where it names no item: none at all, an id
    /// no call item carries, or an index and an id of two different items.
    /// An event only a client's own rule could place is placed nowhere, so no
    /// reader gives its bytes to a call the client does not.
    fn place(&mut self, item: &ItemAddress) -> Option<usize> {
        if item.opens {
            let index = item.output_index.unwrap_or(Self::UNINDEXED + self.items.len());
            self.items.insert(index, item.item_id.clone());
            return Some(index);
        }
        let by_id = item
            .item_id
            .as_deref()
            .and_then(|id| self.items.iter().find(|(_, known)| known.as_deref() == Some(id)).map(|(index, _)| *index));
        let named = item.output_index.map(|index| self.places.get(&index).copied().unwrap_or(index));
        match (named, by_id) {
            (Some(index), Some(of_id)) if index == of_id => Some(index),
            // An item opened without its place, named by its id and a place
            // no item holds: that place is its from now on.
            (Some(index), Some(of_id)) if of_id >= Self::UNINDEXED && !self.items.contains_key(&index) => {
                self.places.insert(index, of_id);
                Some(of_id)
            }
            (Some(_), Some(_)) => None,
            // An id that the item at the index does not carry names another.
            (Some(index), None) => match (&item.item_id, self.items.get(&index)) {
                (Some(_), Some(Some(_))) => None,
                _ => Some(index),
            },
            (None, of_id) => of_id,
        }
    }

    fn clear(&mut self) {
        self.items.clear();
        self.places.clear();
    }
}

/// A stream's parser: [`parse_domain_event`] for each frame, plus what only
/// the whole stream knows — where a custom (freeform) tool call's text starts
/// and ends. The per-frame parse gives each piece of that text escaped, marked
/// `CallArguments::FreeformPiece` — the wire's own word that the call is
/// custom, which every reader downstream acts on; this wraps them into the
/// domain's `{"input": <text>}`, per call:
/// - calls are told apart by
///   [`CallNumbering`](crate::pipeline::response_blocks::CallNumbering) — the
///   rule every reader shares — so a server repeating the name, or sending the
///   name first and the id later, is one call, and parallel calls whose
///   deltas interleave each get their own number and their own text;
/// - a call's arguments are opened once, on its first piece, and closed
///   exactly once with [`DomainEvent::FreeformCallEnd`]: where the upstream
///   says the text is complete (Responses `custom_tool_call_input.done`, or
///   the item's `output_item.done` when that comes first or alone), where a
///   new call starts at its index, before any content that is not a call
///   (text, reasoning, an error, the finish — a Chat call has no end event),
///   and at [`Self::finish`] when the stream ends with it open. A usage count
///   is not content: a server reporting it on every chunk (vLLM's continuous
///   usage) would otherwise close a call after its first piece;
/// - where the upstream's closing word carries the whole text (Responses
///   states it on both done events) and the pieces streamed fell short of it,
///   the rest is read from there before the close;
/// - a piece of a call whose arguments are closed (a lax server re-sending
///   after its own done event, a call continued after other content) is
///   marked `CallArguments::FreeformLate`: no reader appends it to arguments
///   already closed. A delta of no call at all (an Anthropic
///   `server_tool_use` block's input, a piece after every call retired) keeps
///   no upstream index, which could be another call's number: it is numbered
///   [`DomainEvent::NO_CALL`], and every reader sets it aside;
/// - one parser reads a client stream's every upstream response (each round
///   of an agent loop): [`Self::finish`] ends a response, retiring its calls,
///   so the next numbers its calls after them and the audit — which records
///   calls by number — never merges two rounds' calls.
///
/// Every consumer then reads each call's arguments as one whole JSON value,
/// with nothing after the close. The audit and the Chat, Responses and Gemini
/// clients keep interleaved parallel calls each whole; the block accumulator
/// (policy, when it holds calls) and the Anthropic builder hold one call at a
/// time — a call is read, or its block closed, when the next one starts, and
/// its later pieces are withheld: by the accumulator with an injection block
/// and a notice to the client, by the Anthropic builder with a warning.
/// Locked by
/// `a_custom_call_the_upstream_never_closes_is_read_whole`,
/// `a_chat_custom_call_restated_on_every_delta_is_one_call`,
/// `interleaved_parallel_calls_keep_each_custom_calls_text_whole`,
/// `a_custom_call_whose_text_comes_only_with_its_done_item_is_read`,
/// `a_chat_custom_tool_call_is_recorded_as_a_tool_call`,
/// `usage_on_every_chunk_does_not_end_a_custom_call`,
/// `a_piece_after_a_custom_calls_end_is_withheld_and_said_so`,
/// `a_round_cut_short_leaves_no_call_open_for_the_next` and
/// `a_stray_piece_belongs_to_no_call`.
pub struct StreamParser {
    version: ApiVersion,
    /// The stream's calls, numbered by the rule every reader shares.
    calls: crate::pipeline::response_blocks::CallNumbering,
    /// The freeform calls, by number: whether their arguments are open, and
    /// the escaped text their pieces gave so far.
    freeform: std::collections::BTreeMap<usize, (bool, String)>,
    /// The server tools' calls, by number: their input deltas are marked
    /// `CallArguments::ServerTool` like their opening.
    server_tools: std::collections::BTreeSet<usize>,
    /// The calls to a Responses built-in tool the client runs, by number:
    /// every delta placed on one is marked `CallArguments::ClientBuiltin` like
    /// its opening.
    builtins: std::collections::BTreeMap<usize, crate::api::domain::ClientBuiltin>,
    /// A Responses upstream's call items, by the address its events name.
    items: ResponsesItems,
    /// The arguments each function or MCP call's deltas gave so far, by
    /// number — what the upstream's statement of the whole arguments is read
    /// against.
    streamed: std::collections::BTreeMap<usize, String>,
    /// The frame being numbered is a call event naming no item: it belongs to
    /// no call.
    unaddressed: bool,
    /// Every kind of answer part the stream carried that no event reads — what
    /// a translated client is not sent.
    unread_parts: std::collections::BTreeSet<String>,
}

impl StreamParser {
    pub fn new(version: ApiVersion) -> Self {
        Self {
            version,
            calls: crate::pipeline::response_blocks::CallNumbering::for_upstream(version),
            freeform: std::collections::BTreeMap::new(),
            server_tools: std::collections::BTreeSet::new(),
            builtins: std::collections::BTreeMap::new(),
            items: ResponsesItems::default(),
            streamed: std::collections::BTreeMap::new(),
            unaddressed: false,
            unread_parts: std::collections::BTreeSet::new(),
        }
    }

    /// The kinds of answer part the stream carried so far that no event reads.
    pub fn unread_parts(&self) -> &std::collections::BTreeSet<String> {
        &self.unread_parts
    }

    /// The domain events `event` carries, with each freeform call's arguments
    /// opened and closed where the stream starts and ends the call.
    pub fn parse(&mut self, event: &SseEvent) -> Vec<DomainEvent> {
        let mut facts = FrameFacts::default();
        let mut parsed = parse_frame(event, self.version, &mut facts);
        self.unread_parts.extend(std::mem::take(&mut facts.unread_parts));
        // A Responses call event is placed at the item it names.
        let at = facts.item.as_ref().map(|item| self.items.place(item));
        if let Some(at) = at {
            for e in &mut parsed {
                if let DomainEvent::ToolCallDelta { index, .. } = e {
                    match at {
                        Some(k) => *index = k,
                        None => self.unaddressed = true,
                    }
                }
            }
        }
        let mut out = self.number(parsed);
        self.unaddressed = false;
        // The upstream's statement of a call's whole arguments: what its
        // deltas did not give is the call's rest — read, like every piece, by
        // the audit and policy. A statement that is no extension of what was
        // streamed adds nothing (a pass-through client is given what was
        // streamed, see `PassthroughPosition`).
        if let Some(stated) = facts.call_stated
            && let Some(Some(k)) = at
            && let Some(n) = self.calls.open_at(k)
        {
            let streamed = self.streamed.entry(n).or_default();
            if let Some(rest) = stated.strip_prefix(streamed.as_str()).filter(|r| !r.is_empty()) {
                let rest = rest.to_string();
                streamed.push_str(&rest);
                let form = match self.builtins.get(&n) {
                    Some(builtin) => crate::api::domain::CallArguments::ClientBuiltin(*builtin),
                    None if self.server_tools.contains(&n) => crate::api::domain::CallArguments::ServerTool,
                    None => crate::api::domain::CallArguments::Json,
                };
                out.push(DomainEvent::ToolCallDelta { index: n, id: None, function_name: None, arguments_delta: rest, form });
            }
        }
        if let Some(whole) = facts.custom_call_done
            && let Some(Some(k)) = at
            && let Some(n) = self.calls.open_at(k)
            && let Some((true, streamed)) = self.freeform.get(&n)
        {
            // The upstream's closing word states the whole text; what the
            // pieces did not give is read from it.
            if let Some(whole) = whole {
                let escaped = crate::api::domain_request::freeform_args_piece(&whole);
                if let Some(rest) = escaped.strip_prefix(streamed.as_str()).filter(|r| !r.is_empty()) {
                    out.push(DomainEvent::ToolCallDelta {
                        index: n,
                        id: None,
                        function_name: None,
                        arguments_delta: rest.to_string(),
                        form: crate::api::domain::CallArguments::FreeformPiece,
                    });
                }
            }
            out.extend(self.close(n));
        }
        out
    }

    /// The stream's reading of one frame's parsed events: each call delta
    /// given the stream's number for its call, each freeform call's
    /// arguments opened and closed where the stream starts and ends it.
    pub(crate) fn number(&mut self, parsed: Vec<DomainEvent>) -> Vec<DomainEvent> {
        use crate::pipeline::response_blocks::CallSlot;
        let mut out = Vec::with_capacity(parsed.len() + 1);
        for mut e in parsed {
            let DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, form } = &mut e else {
                // Content that is not a call ends every freeform call still
                // open; a usage count is not content. The finish ends the
                // response's calls.
                if !matches!(e, DomainEvent::Usage(_)) {
                    out.extend(self.close_all());
                }
                if matches!(e, DomainEvent::Done { .. }) {
                    self.calls.finish_response();
                    self.freeform.clear();
                    self.items.clear();
                    self.streamed.clear();
                }
                out.push(e);
                continue;
            };
            // A call event naming no item is no call's: its bytes are withheld.
            if self.unaddressed {
                tracing::warn!("a tool-call delta names no item the response opened; withheld");
                *index = DomainEvent::NO_CALL;
                out.push(e);
                continue;
            }
            let is_piece = *form == crate::api::domain::CallArguments::FreeformPiece;
            // A call starting at an index closes the one open there.
            let replaced = self.calls.open_at(*index);
            let slot = self.calls.place(*index, id.as_deref(), function_name.as_deref());
            // Every reader downstream addresses the call by the stream's own
            // number for it — 0, 1, 2 … in the order calls open — never the
            // upstream's index, which a Responses upstream sets to 0 for
            // every call. A delta of no call (an Anthropic `server_tool_use`
            // block's input, text after every call retired) keeps no upstream
            // index either: that could be another call's number.
            *index = match slot {
                CallSlot::Starts(n) | CallSlot::Continues(n) | CallSlot::Late(Some(n)) => n,
                CallSlot::Late(None) => DomainEvent::NO_CALL,
            };
            // A call is a server tool's only as it starts. Every delta placed
            // on one is its input, however it reads; a delta calling itself a
            // server tool's but placed on a client's call is that call's —
            // policy reads it.
            if let CallSlot::Starts(n) = slot {
                match *form {
                    crate::api::domain::CallArguments::ServerTool => {
                        self.server_tools.insert(n);
                    }
                    crate::api::domain::CallArguments::ClientBuiltin(builtin) => {
                        self.builtins.insert(n, builtin);
                    }
                    _ => {}
                }
            }
            if let CallSlot::Starts(n) | CallSlot::Continues(n) | CallSlot::Late(Some(n)) = slot {
                // A call is a built-in tool's, like a server tool's, only as it
                // starts: every delta placed on it is its own, and one calling
                // itself either but placed on another call is that call's.
                if let Some(builtin) = self.builtins.get(&n) {
                    *form = crate::api::domain::CallArguments::ClientBuiltin(*builtin);
                } else if self.server_tools.contains(&n) {
                    *form = crate::api::domain::CallArguments::ServerTool;
                } else if matches!(
                    *form,
                    crate::api::domain::CallArguments::ServerTool | crate::api::domain::CallArguments::ClientBuiltin(_)
                ) {
                    *form = crate::api::domain::CallArguments::Json;
                }
                // A Responses upstream states a call's whole arguments at its
                // end: kept to read that statement against.
                if self.version == ApiVersion::Responses
                    && matches!(
                        *form,
                        crate::api::domain::CallArguments::Json
                            | crate::api::domain::CallArguments::ServerTool
                            | crate::api::domain::CallArguments::ClientBuiltin(_)
                    )
                {
                    self.streamed.entry(n).or_default().push_str(arguments_delta);
                }
            }
            match slot {
                CallSlot::Starts(n) => {
                    if let Some(prev) = replaced {
                        out.extend(self.close(prev));
                    }
                    if is_piece {
                        self.freeform.insert(n, (true, arguments_delta.clone()));
                        arguments_delta.insert_str(0, crate::api::domain_request::FREEFORM_ARGS_OPEN);
                    }
                }
                CallSlot::Continues(n) if is_piece => match self.freeform.get_mut(&n) {
                    Some((true, escaped)) => escaped.push_str(arguments_delta),
                    // The call's first piece of text (its opening delta named
                    // the call alone): its arguments open here.
                    None => {
                        self.freeform.insert(n, (true, arguments_delta.clone()));
                        arguments_delta.insert_str(0, crate::api::domain_request::FREEFORM_ARGS_OPEN);
                    }
                    // Its arguments are closed: nothing may be appended to them.
                    Some((false, _)) => {
                        tracing::warn!(call = n, "custom tool call text arrived after the call's end");
                        *form = crate::api::domain::CallArguments::FreeformLate;
                    }
                },
                CallSlot::Late(n) if is_piece => {
                    tracing::warn!(call = ?n, "custom tool call text arrived after the call's end");
                    *form = crate::api::domain::CallArguments::FreeformLate;
                }
                CallSlot::Continues(_) | CallSlot::Late(_) => {}
            }
            out.push(e);
        }
        out
    }

    /// The upstream response is over: the end of every freeform call it left
    /// open, and its calls retired, so the next response (an agent-loop round
    /// read by the same parser) numbers its calls after them and never
    /// continues one of them.
    pub fn finish(&mut self) -> Vec<DomainEvent> {
        let ends = self.close_all();
        self.calls.finish_response();
        self.freeform.clear();
        self.items.clear();
        self.streamed.clear();
        ends
    }

    /// End freeform call `n`, if its arguments are open.
    fn close(&mut self, n: usize) -> Option<DomainEvent> {
        let (open, _) = self.freeform.get_mut(&n)?;
        std::mem::replace(open, false).then_some(DomainEvent::FreeformCallEnd { index: n })
    }

    fn close_all(&mut self) -> Vec<DomainEvent> {
        let open: Vec<usize> = self.freeform.iter().filter(|(_, (open, _))| *open).map(|(n, _)| *n).collect();
        open.into_iter().filter_map(|n| self.close(n)).collect()
    }
}

/// Parse an SSE event's JSON data into typed `DomainEvent`s.
///
/// Returns an empty vec for events that don't map to a domain event (e.g. keep-alives,
/// unrecognized event types, or malformed JSON).
/// May return multiple events (e.g. `response.completed` emits both Usage and Done).
pub fn parse_domain_event(event: &SseEvent, version: ApiVersion) -> Vec<DomainEvent> {
    parse_frame(event, version, &mut FrameFacts::default())
}

/// [`parse_domain_event`], also saying — in `facts`, from the same parse —
/// what the frame says beyond its events.
fn parse_frame(event: &SseEvent, version: ApiVersion, facts: &mut FrameFacts) -> Vec<DomainEvent> {
    if event.is_done() {
        return vec![]; // [DONE] sentinel is handled separately
    }

    match version {
        ApiVersion::ChatCompletions => parse_chat_completions_event(event, facts),
        ApiVersion::Responses => parse_responses_event(event, facts),
        ApiVersion::AnthropicMessages => parse_anthropic_sse_event(event),
        ApiVersion::GoogleGemini => parse_gemini_event(event),
    }
}

fn parse_chat_completions_event(event: &SseEvent, facts: &mut FrameFacts) -> Vec<DomainEvent> {
    let chunk: ChatChunk = match serde_json::from_str(&event.data) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("malformed ChatCompletions SSE chunk: {e}");
            return vec![];
        }
    };
    if let Some(error) = chunk.error {
        return vec![error.into_event(&event.data)];
    }

    let mut events = Vec::new();
    let choice = chunk.choices.first();

    // Content first, then what ends the stream. One chunk can carry both —
    // Ollama and vLLM put the last text beside `finish_reason`, and a delta can
    // hold reasoning and text, or several tool calls, at once — and every piece
    // is content the audit, the response policy and a translated client must
    // see, in the order the model wrote it.
    if let Some(delta) = choice.and_then(|c| c.delta.as_ref()) {
        // Reasoning/thinking delta — either spelling, whichever carries text.
        // Picking on presence alone would let a provider that sends both (one
        // of them blank) short-circuit onto the empty one and drop the delta.
        if let Some(reasoning) = [
            delta.reasoning.as_ref().and_then(Value::as_str),
            delta.reasoning_content.as_ref().and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        .find(|s| !s.is_empty())
        {
            events.push(DomainEvent::ReasoningDelta(reasoning.to_string()));
        }
        match &delta.content {
            Some(Value::String(content)) if !content.is_empty() => {
                events.push(DomainEvent::TextDelta(content.clone()));
            }
            // A chunk array: one event per chunk carrying text, in array
            // order. `split_chat_chunk` pairs the n-th content event with the
            // n-th such chunk through the same classifier.
            Some(Value::Array(chunks)) => {
                use crate::api::chat::{chunk_text, ChunkKind};
                facts.unread_parts.extend(crate::api::chat::unread_part_kinds(chunks).map(str::to_string));
                for (kind, text) in chunks.iter().filter_map(chunk_text) {
                    match kind {
                        ChunkKind::Text => events.push(DomainEvent::TextDelta(text.into_owned())),
                        ChunkKind::Thinking => events.push(DomainEvent::ReasoningDelta(text.into_owned())),
                        ChunkKind::Other => {}
                    }
                }
            }
            _ => {}
        }
        // An empty id or name names nothing: some servers send `"id": ""` on
        // every delta after the first, and reading it as an id would start a
        // new call in the middle of one.
        let named = |s: &Option<String>| s.clone().filter(|v| !v.is_empty());
        for (position, tc) in delta.tool_calls.iter().flatten().enumerate() {
            let index = tc.index.unwrap_or(position);
            let id = named(&tc.id);
            // A custom call's free text is the domain's `{"input": <text>}`:
            // each delta gives an escaped piece of it, and [`StreamParser`]
            // opens and closes the arguments where the stream starts and ends
            // the call.
            // A delta typed `custom` is one of a custom call however little
            // it carries — its opening may name the call's kind alone.
            if tc.custom.is_some() || tc.r#type.as_deref() == Some("custom") {
                let custom = tc.custom.as_ref();
                events.push(DomainEvent::ToolCallDelta {
                    index,
                    id,
                    function_name: custom.and_then(|c| named(&c.name)),
                    arguments_delta: crate::api::domain_request::freeform_args_piece(
                        custom.and_then(|c| c.input.as_deref()).unwrap_or_default(),
                    ),
                    form: crate::api::domain::CallArguments::FreeformPiece,
                });
                continue;
            }
            events.push(DomainEvent::ToolCallDelta {
                index,
                id,
                function_name: tc.function.as_ref().and_then(|f| named(&f.name)),
                arguments_delta: tc
                    .function
                    .as_ref()
                    .and_then(|f| f.arguments.clone())
                    .unwrap_or_default(),
                form: crate::api::domain::CallArguments::Json,
            });
        }
    }

    // A non-null finish_reason means the stream is finishing for this choice.
    // Some upstreams (e.g. Ollama, local mocks) send finish_reason + usage on
    // the same chunk, so both are collected.
    if let Some(reason) = choice.and_then(|c| c.finish_reason.as_ref()) {
        events.push(DomainEvent::Done {
            finish_reason: Some(FinishReason::normalize(reason)),
            native_finish_reason: Some(reason.clone()),
        });
    }

    // Usage rides the last chunk (with `stream_options.include_usage` on
    // OpenAI; unasked on Mistral). Read by the same reader as a whole answer's.
    if let Some(usage) = chunk.usage.as_ref().filter(|u| u.is_object()) {
        events.push(DomainEvent::Usage(super::chat::usage_of(usage)));
    }

    events
}

/// A Responses `mcp_call`'s tool name without its server's label: the item
/// may name the tool `{server_label}.{tool}` (`repo_browser.glob` → `glob`).
pub(crate) fn mcp_tool_name(name: &str, server_label: Option<&str>) -> String {
    server_label
        .and_then(|label| name.strip_prefix(label)?.strip_prefix('.'))
        .unwrap_or(name)
        .to_string()
}

/// The built-in tool whose call a Responses streaming event of type `kind`
/// streams a piece of: a shell call's commands (`shell_call_command.*`), a
/// patch's diff (`apply_patch_call_operation_diff.*`).
pub(crate) fn builtin_stream_frame(kind: &str) -> Option<crate::api::domain::ClientBuiltin> {
    if kind.starts_with("response.shell_call_command.") {
        Some(crate::api::domain::ClientBuiltin::Shell)
    } else if kind.starts_with("response.apply_patch_call_operation_diff.") {
        Some(crate::api::domain::ClientBuiltin::ApplyPatch)
    } else {
        None
    }
}

fn parse_responses_event(event: &SseEvent, facts: &mut FrameFacts) -> Vec<DomainEvent> {
    let Some(event_type) = event.event_type.as_deref() else {
        return vec![];
    };

    match event_type {
        "response.output_text.delta" | "response.content_part.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses delta: {e}");
                    return vec![];
                }
            };
            delta
                .delta
                .map(|d| vec![DomainEvent::TextDelta(d)])
                .unwrap_or_default()
        }
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses reasoning delta: {e}");
                    return vec![];
                }
            };
            delta
                .delta
                .filter(|d| !d.is_empty())
                .map(|d| vec![DomainEvent::ReasoningDelta(d)])
                .unwrap_or_default()
        }
        "response.refusal.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses refusal delta: {e}");
                    return vec![];
                }
            };
            delta
                .delta
                .map(|d| vec![DomainEvent::TextDelta(d)])
                .unwrap_or_default()
        }
        "response.output_item.added" => {
            let item: ResponsesOutputItem = match serde_json::from_str(&event.data) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!("malformed Responses output_item.added: {e}");
                    return vec![];
                }
            };
            let Some(inner) = item.item else {
                return vec![];
            };
            // A call item opens a call: the client's (`function_call`,
            // `custom_tool_call`, or a built-in tool's the client runs — a
            // shell command, a patch, a computer action), or one on a remote
            // MCP server the upstream runs itself (`mcp_call`). The other
            // items a server runs — a web, file or tool search, the code
            // interpreter, image generation — carry no arguments of a call. A
            // call item is addressed by its place and its id from here on.
            let builtin = inner.r#type.as_deref().and_then(crate::api::domain::ClientBuiltin::of_item_type);
            if builtin.is_some() || matches!(inner.r#type.as_deref(), Some("function_call" | "custom_tool_call" | "mcp_call")) {
                facts.item = Some(ItemAddress { output_index: item.output_index, item_id: inner.id.clone(), opens: true });
            }
            // A built-in tool's call opens named by its item type, with no
            // arguments: its payload is read whole from the item's done, the
            // upstream's statement of it — an opening payload may be one the
            // stream goes on to fill (a shell call's commands), which the done
            // would not extend.
            // A shell call in a hosted container is the server's to run, like
            // an MCP call: recorded as that server tool's call, never held.
            if let Some(builtin) = builtin {
                let hosted = builtin == crate::api::domain::ClientBuiltin::Shell
                    && serde_json::from_str::<serde_json::Value>(&event.data)
                        .ok()
                        .and_then(|v| v.get("item").map(crate::api::domain::ClientBuiltin::is_hosted_shell))
                        .unwrap_or(false);
                let form = if hosted {
                    crate::api::domain::CallArguments::ServerTool
                } else {
                    crate::api::domain::CallArguments::ClientBuiltin(builtin)
                };
                return vec![DomainEvent::ToolCallDelta {
                    index: 0,
                    id: inner.call_id.or(inner.id),
                    function_name: Some(builtin.tool_name().to_string()),
                    arguments_delta: String::new(),
                    form,
                }];
            }
            match inner.r#type.as_deref() {
                // Arguments the item states as it opens are its first piece.
                Some("function_call") => {
                    vec![DomainEvent::ToolCallDelta {
                        index: 0,
                        id: inner.call_id,
                        function_name: inner.name,
                        arguments_delta: inner.arguments.unwrap_or_default(),
                        form: crate::api::domain::CallArguments::Json,
                    }]
                }
                // A custom (freeform) tool call streams free text, which the
                // domain carries as `{"input": <text>}`: this and each
                // `custom_tool_call_input.delta` give an escaped piece of it,
                // and [`StreamParser`] opens and closes the arguments around
                // them.
                Some("custom_tool_call") => {
                    let text = inner.input.as_ref().and_then(serde_json::Value::as_str).unwrap_or_default();
                    vec![DomainEvent::ToolCallDelta {
                        index: 0,
                        id: inner.call_id,
                        function_name: inner.name,
                        arguments_delta: crate::api::domain_request::freeform_args_piece(text),
                        form: crate::api::domain::CallArguments::FreeformPiece,
                    }]
                }
                // Its input is that server tool's, never a client's call: the
                // audit records it, and no client is given it to run.
                Some("mcp_call") => {
                    let tool_name = inner.name.as_deref().map(|name| mcp_tool_name(name, inner.server_label.as_deref()));
                    vec![DomainEvent::ToolCallDelta {
                        index: 0,
                        id: inner.id,
                        function_name: tool_name,
                        arguments_delta: inner.arguments.unwrap_or_default(),
                        form: crate::api::domain::CallArguments::ServerTool,
                    }]
                }
                Some("image_generation_call") => {
                    vec![DomainEvent::ImageGeneration {
                        index: 0,
                        result_base64: None,
                    }]
                }
                _ => vec![],
            }
        }
        // Image generation done — extract final base64 result
        "response.output_item.done" => {
            let item: ResponsesOutputItem = match serde_json::from_str(&event.data) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!("malformed Responses output_item.done: {e}");
                    return vec![];
                }
            };
            let Some(inner) = item.item else {
                return vec![];
            };
            match inner.r#type.as_deref() {
                Some("image_generation_call") => vec![DomainEvent::ImageGeneration {
                    index: 0,
                    result_base64: inner.result,
                }],
                Some("custom_tool_call") => {
                    facts.custom_call_done = Some(inner.input.as_ref().and_then(serde_json::Value::as_str).map(str::to_string));
                    facts.item = Some(ItemAddress { output_index: item.output_index, item_id: inner.id, opens: false });
                    vec![]
                }
                // The item states the call's whole arguments: what the deltas
                // did not stream is read from there.
                Some("function_call" | "mcp_call") => {
                    facts.call_stated = inner.arguments;
                    facts.item = Some(ItemAddress { output_index: item.output_index, item_id: inner.id, opens: false });
                    vec![]
                }
                // A built-in tool's call: its payload, which the done states
                // whole, is the call's arguments.
                Some(kind) if let Some(builtin) = crate::api::domain::ClientBuiltin::of_item_type(kind) => {
                    facts.call_stated = serde_json::from_str::<serde_json::Value>(&event.data)
                        .ok()
                        .and_then(|v| v.get("item").map(|item| builtin.arguments(item)));
                    facts.item = Some(ItemAddress { output_index: item.output_index, item_id: inner.id, opens: false });
                    vec![]
                }
                _ => vec![],
            }
        }
        // A shell call's commands, or a patch's diff, as they stream: the
        // bytes ride the call they name, so a client is sent them only once
        // policy has read the call. Its arguments are what its done states.
        kind if let Some(builtin) = builtin_stream_frame(kind) => {
            let at = serde_json::from_str::<ResponsesDelta>(&event.data).ok();
            facts.item = Some(ItemAddress {
                output_index: at.as_ref().and_then(|d| d.output_index),
                item_id: at.and_then(|d| d.item_id),
                opens: false,
            });
            vec![DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: String::new(),
                form: crate::api::domain::CallArguments::ClientBuiltin(builtin),
            }]
        }
        "response.custom_tool_call_input.done" => {
            // The whole text rides `input`; read loosely, like an item's.
            let done = serde_json::from_str::<ResponsesCustomInputDone>(&event.data).ok();
            facts.item = done.as_ref().map(|d| ItemAddress { output_index: d.output_index, item_id: d.item_id.clone(), opens: false });
            facts.custom_call_done = Some(done.and_then(|d| d.input.as_ref().and_then(serde_json::Value::as_str).map(str::to_string)));
            vec![]
        }
        "response.custom_tool_call_input.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses custom tool input delta: {e}");
                    return vec![];
                }
            };
            facts.item = Some(ItemAddress { output_index: delta.output_index, item_id: delta.item_id, opens: false });
            vec![DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: crate::api::domain_request::freeform_args_piece(
                    delta.delta.as_deref().unwrap_or_default(),
                ),
                form: crate::api::domain::CallArguments::FreeformPiece,
            }]
        }
        "response.function_call_arguments.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses function delta: {e}");
                    return vec![];
                }
            };
            facts.item = Some(ItemAddress { output_index: delta.output_index, item_id: delta.item_id, opens: false });
            vec![DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: delta.delta.unwrap_or_default(),
                form: crate::api::domain::CallArguments::Json,
            }]
        }
        // An MCP call's input: [`StreamParser`] places it on the item it
        // names, and marks it that server tool's only where that item is one.
        "response.mcp_call_arguments.delta" => {
            let delta: ResponsesDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Responses MCP call delta: {e}");
                    return vec![];
                }
            };
            facts.item = Some(ItemAddress { output_index: delta.output_index, item_id: delta.item_id, opens: false });
            vec![DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: delta.delta.unwrap_or_default(),
                form: crate::api::domain::CallArguments::ServerTool,
            }]
        }
        // The call's whole arguments: what the deltas did not stream is read
        // from here, on the item it names.
        "response.mcp_call_arguments.done" |
        "response.function_call_arguments.done" => {
            if let Ok(done) = serde_json::from_str::<ResponsesArgumentsDone>(&event.data) {
                facts.call_stated = done.arguments;
                facts.item = Some(ItemAddress { output_index: done.output_index, item_id: done.item_id, opens: false });
            }
            vec![]
        }
        // Image generation streaming — pass through to client, no domain event needed.
        // The final image is captured via output_item.done above.
        "response.image_generation_call.partial_image" |
        "response.image_generation_call.generating" => {
            vec![]
        }
        "response.completed" => {
            let completed: ResponsesCompleted = match serde_json::from_str(&event.data) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("malformed Responses completed: {e}");
                    return vec![];
                }
            };
            let Some(inner) = completed.response else {
                tracing::warn!("response.completed event missing response field");
                return vec![DomainEvent::Done {
                    finish_reason: Some(FinishReason::Error),
                    native_finish_reason: Some("missing_response".to_string()),
                }];
            };
            // A response stating no status reads as completed, as a whole
            // body does (`translate::responses_answer_finish`).
            let finish_reason = inner.finish_as(inner.status.as_deref().unwrap_or("completed"));
            let mut events = Vec::with_capacity(2);
            // Emit Usage first if present
            if let Some(usage) = inner.usage {
                let input = usage.input_tokens.unwrap_or(0);
                let output = usage.output_tokens.unwrap_or(0);
                let total = usage.total_tokens.unwrap_or(input + output);
                let out_details = usage.output_tokens_details.as_ref();
                let in_details = usage.input_tokens_details.as_ref();
                events.push(DomainEvent::Usage(Usage {
                    prompt_tokens: input,
                    completion_tokens: output,
                    reasoning_tokens: out_details.and_then(|d| d.reasoning_tokens),
                    cache_creation_tokens: None,
                    cache_creation_1h_tokens: None,
                    cache_read_tokens: in_details.and_then(|d| d.cached_tokens),
                    total_tokens: total,
                    audio_prompt_tokens: in_details.and_then(|d| d.audio_tokens),
                    audio_completion_tokens: out_details.and_then(|d| d.audio_tokens),
                    audio_prompt_seconds: None,
                }));
            }
            // Always emit Done
            events.push(DomainEvent::Done {
                finish_reason,
                native_finish_reason: inner.status,
            });
            events
        }
        "response.incomplete" => {
            let completed: ResponsesCompleted = match serde_json::from_str(&event.data) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("malformed Responses incomplete: {e}");
                    return vec![];
                }
            };
            let mut events = Vec::with_capacity(2);
            if let Some(inner) = &completed.response
                && let Some(usage) = &inner.usage {
                    let input = usage.input_tokens.unwrap_or(0);
                    let output = usage.output_tokens.unwrap_or(0);
                    let total = usage.total_tokens.unwrap_or(input + output);
                    let out_details = usage.output_tokens_details.as_ref();
                    let in_details = usage.input_tokens_details.as_ref();
                    events.push(DomainEvent::Usage(Usage {
                        prompt_tokens: input,
                        completion_tokens: output,
                        reasoning_tokens: out_details.and_then(|d| d.reasoning_tokens),
                        cache_creation_tokens: None,
                        cache_creation_1h_tokens: None,
                        cache_read_tokens: in_details.and_then(|d| d.cached_tokens),
                        total_tokens: total,
                        audio_prompt_tokens: in_details.and_then(|d| d.audio_tokens),
                        audio_completion_tokens: out_details.and_then(|d| d.audio_tokens),
                        audio_prompt_seconds: None,
                    }));
                }
            let finish = completed
                .response
                .as_ref()
                .and_then(|inner| inner.finish_as("incomplete"))
                .unwrap_or(FinishReason::Length); // an `incomplete` status always states one
            events.push(DomainEvent::Done {
                finish_reason: Some(finish),
                native_finish_reason: Some("incomplete".to_string()),
            });
            events
        }
        "response.failed" => {
            let completed: ResponsesCompleted = match serde_json::from_str(&event.data) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("malformed Responses failed: {e}");
                    return vec![];
                }
            };
            let mut events = Vec::with_capacity(2);
            if let Some(inner) = &completed.response {
                // Extract error details if present
                if let Some(error) = &inner.error {
                    events.push(DomainEvent::Error {
                        message: error
                            .message
                            .clone()
                            .unwrap_or_else(|| "unknown error".to_string()),
                        code: error.code.clone(),
                    });
                }
            }
            events.push(DomainEvent::Done {
                finish_reason: Some(FinishReason::Error),
                native_finish_reason: Some("failed".to_string()),
            });
            events
        }
        "response.done" => {
            // Simpler done event without usage
            vec![DomainEvent::Done {
                finish_reason: Some(FinishReason::Stop),
                native_finish_reason: Some("completed".to_string()),
            }]
        }
        "error" => {
            let err: ResponsesError = match serde_json::from_str(&event.data) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("malformed Responses error: {e}");
                    return vec![DomainEvent::Error {
                        message: event.data.clone(),
                        code: None,
                    }];
                }
            };
            let (nested_message, nested_code) =
                err.error.map_or((None, None), |inner| (inner.message, inner.code));
            vec![DomainEvent::Error {
                message: err
                    .message
                    .or(nested_message)
                    .unwrap_or_else(|| event.data.clone()),
                code: err.code.or(nested_code),
            }]
        }
        other => {
            tracing::debug!(event_type = other, "unrecognized Responses SSE event type");
            vec![]
        }
    }
}

impl ApiVersion {
    /// Detect API version from request path.
    pub fn from_path(path: &str) -> Self {
        // Check Gemini paths first (most specific)
        if path.contains("/v1beta/models/") || path.contains("generateContent") {
            Self::GoogleGemini
        // Check /messages before /responses to avoid ambiguity
        } else if path.contains("/messages") {
            Self::AnthropicMessages
        } else if path.contains("/responses") {
            Self::Responses
        } else {
            Self::ChatCompletions
        }
    }

    /// Plain string representation for DB storage (no JSON quotes).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Responses => "responses",
            Self::AnthropicMessages => "anthropic_messages",
            Self::GoogleGemini => "google_gemini",
        }
    }
}

impl std::str::FromStr for ApiVersion {
    type Err = String;

    /// Parse the snake_case storage form written by `as_str` back into the enum.
    /// Unknown values are rejected — audit records are written by this codebase
    /// so an unrecognized string means data corruption.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chat_completions" => Ok(Self::ChatCompletions),
            "responses" => Ok(Self::Responses),
            "anthropic_messages" => Ok(Self::AnthropicMessages),
            "google_gemini" => Ok(Self::GoogleGemini),
            other => Err(format!("unknown api_version: {other}")),
        }
    }
}

// ── Private serde structs for Anthropic Messages SSE events ──

#[derive(Deserialize)]
struct AnthropicDelta {
    r#type: Option<String>,
    text: Option<String>,
    /// Anthropic `thinking_delta` events use a `thinking` field (not `text`).
    thinking: Option<String>,
    partial_json: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicContentBlockStart {
    index: Option<usize>,
    content_block: Option<AnthropicContentBlockDef>,
}

#[derive(Deserialize)]
struct AnthropicContentBlockDef {
    r#type: Option<String>,
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicContentBlockDelta {
    index: Option<usize>,
    delta: Option<AnthropicDelta>,
}

#[derive(Deserialize)]
struct AnthropicMessageDelta {
    delta: Option<AnthropicMessageDeltaInner>,
    usage: Option<AnthropicUsageBlock>,
}

#[derive(Deserialize)]
struct AnthropicMessageDeltaInner {
    stop_reason: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicUsageBlock {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    cache_creation_input_tokens: Option<u32>,
    cache_read_input_tokens: Option<u32>,
    /// The cache writes by lifetime; they sum to `cache_creation_input_tokens`.
    /// Read loosely: a shape this parser does not expect leaves the 1-hour
    /// count unknown, never the whole frame unread.
    cache_creation: Option<Value>,
}

impl AnthropicUsageBlock {
    /// The cache writes made with a 1-hour lifetime, when reported.
    fn cache_creation_1h_tokens(&self) -> Option<u32> {
        self.cache_creation
            .as_ref()?
            .get("ephemeral_1h_input_tokens")?
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
    }
}

#[derive(Deserialize)]
struct AnthropicMessageStart {
    message: Option<AnthropicMessageStartInner>,
}

#[derive(Deserialize)]
struct AnthropicMessageStartInner {
    usage: Option<AnthropicUsageBlock>,
}

// ── Gemini SSE parsing (stub — full implementation in Step 4) ──

/// Private serde structs for Gemini streaming chunks.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamChunk {
    candidates: Option<Vec<GeminiStreamCandidate>>,
    usage_metadata: Option<GeminiStreamUsage>,
    /// A mid-stream failure, sent as an AIP-193 error chunk.
    #[serde(default, deserialize_with = "present_error")]
    error: Option<StreamError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamCandidate {
    content: Option<GeminiStreamContent>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamContent {
    parts: Option<Vec<GeminiStreamPart>>,
}

/// A streaming part — uses untagged enum like the request type.
#[derive(Deserialize)]
#[serde(untagged)]
enum GeminiStreamPart {
    ThoughtText { thought: bool, text: String },
    FunctionCall { #[serde(rename = "functionCall")] function_call: GeminiStreamFunctionCall },
    Text { text: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamFunctionCall {
    id: Option<String>,
    name: Option<String>,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiStreamUsage {
    prompt_token_count: Option<u32>,
    candidates_token_count: Option<u32>,
    total_token_count: Option<u32>,
    thoughts_token_count: Option<u32>,
    cached_content_token_count: Option<u32>,
}

/// Parse Google Gemini SSE events into domain events.
///
/// Gemini SSE format: `data: {GenerateContentResponse JSON}\n\n` — no `event:` field.
/// Text is incremental, finishReason + usageMetadata in the final chunk only.
fn parse_gemini_event(event: &SseEvent) -> Vec<DomainEvent> {
    let chunk: GeminiStreamChunk = match serde_json::from_str(&event.data) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("malformed Gemini SSE chunk: {e}");
            return vec![];
        }
    };
    if let Some(error) = chunk.error {
        return vec![error.into_event(&event.data)];
    }

    let mut events = Vec::new();

    // Extract from first candidate
    if let Some(candidates) = &chunk.candidates
        && let Some(candidate) = candidates.first()
    {
        // Content parts first: the final chunk carries the last of the text
        // beside `finishReason`, and it precedes the end it arrives with.
        if let Some(content) = &candidate.content
            && let Some(parts) = &content.parts
        {
            let mut tool_index = 0usize;
            for part in parts {
                match part {
                    GeminiStreamPart::ThoughtText { thought: true, text } => {
                        if !text.is_empty() {
                            events.push(DomainEvent::ReasoningDelta(text.clone()));
                        }
                    }
                    GeminiStreamPart::Text { text } => {
                        if !text.is_empty() {
                            events.push(DomainEvent::TextDelta(text.clone()));
                        }
                    }
                    GeminiStreamPart::ThoughtText { thought: false, text } => {
                        if !text.is_empty() {
                            events.push(DomainEvent::TextDelta(text.clone()));
                        }
                    }
                    GeminiStreamPart::FunctionCall { function_call } => {
                        events.push(DomainEvent::ToolCallDelta {
                            index: tool_index,
                            id: function_call.id.clone(),
                            function_name: function_call.name.clone(),
                            arguments_delta: serde_json::to_string(&function_call.args)
                                .unwrap_or_default(),
                                form: crate::api::domain::CallArguments::Json,
                        });
                        tool_index += 1;
                    }
                }
            }
        }
        if let Some(reason) = &candidate.finish_reason {
            events.push(DomainEvent::Done {
                finish_reason: Some(FinishReason::normalize(reason)),
                native_finish_reason: Some(reason.clone()),
            });
        }
    }

    // Extract usage metadata (present in final chunk)
    if let Some(usage) = &chunk.usage_metadata {
        let prompt = usage.prompt_token_count.unwrap_or(0);
        // `completion_tokens` is the BILLABLE output count, and Gemini is the one
        // protocol whose wire does not already report it that way: thinking tokens
        // are billed at the output rate but live in their own
        // `thoughtsTokenCount`, OUTSIDE `candidatesTokenCount` (Gemini's own
        // `totalTokenCount` adds the two). Chat Completions, Responses and
        // Anthropic all fold reasoning into their output count already, so adding
        // it here is what makes the domain's meaning uniform across protocols —
        // without it a thinking model under-bills by its entire reasoning volume,
        // which on these models is routinely a third of the output.
        // `reasoning_tokens` keeps the informational sub-count for display.
        let thoughts = usage.thoughts_token_count.unwrap_or(0);
        let completion = usage.candidates_token_count.unwrap_or(0) + thoughts;
        let total = usage.total_token_count.unwrap_or(prompt + completion);
        events.push(DomainEvent::Usage(Usage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            reasoning_tokens: usage.thoughts_token_count,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: usage.cached_content_token_count,
            total_tokens: total,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
    }

    events
}

/// Parse Anthropic Messages API SSE events into domain events.
///
/// Used for Anthropic upstream passthrough — when the upstream IS Anthropic.
fn parse_anthropic_sse_event(event: &SseEvent) -> Vec<DomainEvent> {
    let Some(event_type) = event.event_type.as_deref() else {
        return vec![];
    };

    match event_type {
        "content_block_start" => {
            let block: AnthropicContentBlockStart = match serde_json::from_str(&event.data) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("malformed Anthropic content_block_start: {e}");
                    return vec![];
                }
            };
            let Some(cb) = block.content_block else {
                return vec![];
            };
            match cb.r#type.as_deref() {
                Some("tool_use") => {
                    vec![DomainEvent::ToolCallDelta {
                        index: block.index.unwrap_or(0),
                        id: cb.id,
                        function_name: cb.name,
                        arguments_delta: String::new(),
                        form: crate::api::domain::CallArguments::Json,
                    }]
                }
                // A server tool Anthropic runs itself: its input is the server
                // tool's call, which the audit records and no client is given.
                Some("server_tool_use" | "mcp_tool_use") => {
                    vec![DomainEvent::ToolCallDelta {
                        index: block.index.unwrap_or(0),
                        id: cb.id,
                        function_name: cb.name,
                        arguments_delta: String::new(),
                        form: crate::api::domain::CallArguments::ServerTool,
                    }]
                }
                _ => vec![], // text blocks start — no domain event needed
            }
        }
        "content_block_delta" => {
            let cbd: AnthropicContentBlockDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Anthropic content_block_delta: {e}");
                    return vec![];
                }
            };
            let Some(delta) = cbd.delta else {
                return vec![];
            };
            match delta.r#type.as_deref() {
                Some("text_delta") => {
                    delta
                        .text
                        .filter(|t| !t.is_empty())
                        .map(|t| vec![DomainEvent::TextDelta(t)])
                        .unwrap_or_default()
                }
                Some("thinking_delta") => {
                    delta
                        .thinking
                        .or(delta.text)
                        .filter(|t| !t.is_empty())
                        .map(|t| vec![DomainEvent::ReasoningDelta(t)])
                        .unwrap_or_default()
                }
                Some("input_json_delta") => {
                    let args = delta.partial_json.unwrap_or_default();
                    vec![DomainEvent::ToolCallDelta {
                        index: cbd.index.unwrap_or(0),
                        id: None,
                        function_name: None,
                        arguments_delta: args,
                        form: crate::api::domain::CallArguments::Json,
                    }]
                }
                _ => vec![],
            }
        }
        "message_delta" => {
            let md: AnthropicMessageDelta = match serde_json::from_str(&event.data) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("malformed Anthropic message_delta: {e}");
                    return vec![];
                }
            };
            let mut events = Vec::with_capacity(2);
            if let Some(usage) = md.usage {
                let output = usage.output_tokens.unwrap_or(0);
                // Anthropic reports input_tokens as the non-cached portion, disjoint from
                // cache_creation_input_tokens and cache_read_input_tokens. Domain Usage is
                // inclusive, so sum when input_tokens is present. Leave 0 otherwise so the
                // upstream usage-merge guard preserves the prompt_tokens set earlier in the stream.
                if usage.input_tokens.is_none()
                    && (usage.cache_creation_input_tokens.is_some()
                        || usage.cache_read_input_tokens.is_some())
                {
                    // Anomalous: cache stats arriving in message_delta without input_tokens.
                    // Real Anthropic streams put the full input breakdown in message_start;
                    // if this fires in prod the upstream protocol may have shifted and the
                    // inclusive sum from message_start may be missing this cache portion.
                    tracing::warn!(
                        cache_creation = ?usage.cache_creation_input_tokens,
                        cache_read = ?usage.cache_read_input_tokens,
                        "Anthropic message_delta carries cache stats without input_tokens — \
                         prompt_tokens will not be re-summed; possible under-bill"
                    );
                }
                let prompt = usage.input_tokens.map(|input| {
                    input
                        + usage.cache_creation_input_tokens.unwrap_or(0)
                        + usage.cache_read_input_tokens.unwrap_or(0)
                }).unwrap_or(0);
                events.push(DomainEvent::Usage(Usage {
                    prompt_tokens: prompt,
                    completion_tokens: output,
                    reasoning_tokens: None,
                    cache_creation_tokens: usage.cache_creation_input_tokens,
                    cache_creation_1h_tokens: usage.cache_creation_1h_tokens(),
                    cache_read_tokens: usage.cache_read_input_tokens,
                    total_tokens: prompt + output,
                    audio_prompt_tokens: None,
                    audio_completion_tokens: None,
                    audio_prompt_seconds: None,
                }));
            }
            // The audit's `native_finish_reason` is the upstream's own word
            // (`refusal`, `pause_turn`, `stop_sequence`, …), never a spelling
            // derived from the normalized reason.
            let raw = md.delta.and_then(|d| d.stop_reason);
            events.push(DomainEvent::Done {
                finish_reason: raw.as_deref().map(FinishReason::normalize),
                native_finish_reason: raw,
            });
            events
        }
        "message_start" => {
            // Extract input token usage from message_start if present
            let ms: AnthropicMessageStart = match serde_json::from_str(&event.data) {
                Ok(m) => m,
                Err(_) => return vec![],
            };
            if let Some(msg) = ms.message
                && let Some(usage) = msg.usage
                && let Some(input) = usage.input_tokens
                && input > 0
            {
                // Inclusive convention — see message_delta arm above.
                let prompt = input
                    + usage.cache_creation_input_tokens.unwrap_or(0)
                    + usage.cache_read_input_tokens.unwrap_or(0);
                return vec![DomainEvent::Usage(Usage {
                    prompt_tokens: prompt,
                    completion_tokens: 0,
                    reasoning_tokens: None,
                    cache_creation_tokens: usage.cache_creation_input_tokens,
                    cache_creation_1h_tokens: usage.cache_creation_1h_tokens(),
                    cache_read_tokens: usage.cache_read_input_tokens,
                    total_tokens: prompt,
                    audio_prompt_tokens: None,
                    audio_completion_tokens: None,
                    audio_prompt_seconds: None,
                })];
            }
            vec![]
        }
        "message_stop" | "content_block_stop" | "ping" => vec![],
        "error" => {
            // Try to parse error
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&event.data) {
                let message = val
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error")
                    .to_string();
                let code = val
                    .get("error")
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str())
                    .map(String::from);
                vec![DomainEvent::Error { message, code }]
            } else {
                vec![DomainEvent::Error {
                    message: event.data.clone(),
                    code: None,
                }]
            }
        }
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// A frame that never ends must be refused rather than buffered forever.
    ///
    /// This is the shape `read_body_capped` cannot see: the decoder consumes
    /// nothing until it finds `\n\n`, so an upstream that streams bytes without
    /// one grows the reassembly buffer without limit. Reached only through a
    /// streaming read, which is why the body-cap lint cannot flag it.
    #[test]
    fn refuses_a_frame_that_never_ends() {
        let mut decoder = SseDecoder::with_max_frame_bytes(64);
        let mut buf = BytesMut::new();

        // Under the cap: still waiting for more, not an error.
        buf.extend_from_slice(&b"data: ".repeat(5));
        assert_matches!(decoder.decode(&mut buf), Ok(None));

        // Past it: refused, and the buffer is not grown any further.
        buf.extend_from_slice(&b"x".repeat(64));
        assert_matches!(
            decoder.decode(&mut buf),
            Err(SseCodecError::FrameTooLarge { limit_bytes: 64 })
        );
    }

    /// A frame arriving in pieces is still decoded, and the resumed boundary
    /// search must not step over a `\n\n` that straddles a chunk join. An
    /// off-by-one here drops events silently rather than failing loudly.
    #[test]
    fn reassembles_a_frame_split_across_every_boundary_offset() {
        const FRAME: &[u8] = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n";

        for split in 1..FRAME.len() {
            let mut decoder = SseDecoder::new();
            let mut buf = BytesMut::new();
            let mut seen = Vec::new();

            for piece in [&FRAME[..split], &FRAME[split..]] {
                buf.extend_from_slice(piece);
                while let Ok(Some(ev)) = decoder.decode(&mut buf) {
                    seen.push(ev.data);
                }
            }

            assert_eq!(
                seen,
                vec![r#"{"a":1}"#.to_string(), r#"{"b":2}"#.to_string()],
                "split at {split} lost or mangled an event"
            );
        }
    }

    /// The cap is per frame, not per stream: a long stream of ordinary frames
    /// must never trip it, however many bytes it carries in total.
    #[test]
    fn the_cap_bounds_one_frame_not_the_whole_stream() {
        let mut decoder = SseDecoder::with_max_frame_bytes(64);
        let mut buf = BytesMut::new();
        for i in 0..200 {
            buf.extend_from_slice(format!("data: {i}\n\n").as_bytes());
            assert_matches!(decoder.decode(&mut buf), Ok(Some(_)));
        }
    }

    #[test]
    fn test_parse_chat_text_delta() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::TextDelta(text) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_chat_tool_call_delta() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"get_weather","arguments":"{\"loc"}}]},"finish_reason":null}]}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, .. } => {
                assert_eq!(*index, 0);
                assert_eq!(id.as_deref(), Some("call_1"));
                assert_eq!(function_name.as_deref(), Some("get_weather"));
                assert_eq!(arguments_delta, r#"{"loc"#);
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    fn chat(data: &str) -> Vec<DomainEvent> {
        let event = SseEvent { event_type: None, data: data.to_string(), id: None };
        parse_domain_event(&event, ApiVersion::ChatCompletions)
    }

    /// A chunk-array part no event reads (a `reference` citation, an image) is
    /// remembered by the stream parser, so a translated client's row can name
    /// it; text and reasoning chunks, read as events, are not.
    #[test]
    fn the_stream_remembers_the_answer_parts_no_event_reads() {
        let mut parser = StreamParser::new(ApiVersion::ChatCompletions);
        let frame = |content: &str| SseEvent {
            event_type: None,
            data: format!(r#"{{"choices":[{{"index":0,"delta":{{"content":{content}}},"finish_reason":null}}]}}"#),
            id: None,
        };
        parser.parse(&frame(r#"[{"type":"text","text":"a"},{"type":"thinking","thinking":[{"type":"text","text":"t"}]}]"#));
        assert!(parser.unread_parts().is_empty());
        parser.parse(&frame(r#"[{"type":"text","text":"b"},{"type":"reference","reference_ids":[1]},{"type":"text","text":""}]"#));
        parser.parse(&frame(r#"[{"type":"image_url","image_url":"https://x/y.png"},{"type":"thinking","thinking":[{"type":"reference","reference_ids":[2]}]}]"#));
        let kinds: Vec<&str> = parser.unread_parts().iter().map(String::as_str).collect();
        assert_eq!(kinds, ["image_url", "reference"]);
        assert_eq!(
            crate::api::chat::answer_parts_not_carried(parser.unread_parts().iter().map(String::as_str)),
            ["image_url part in the answer", "reference part in the answer"]
        );
    }

    /// A stream's last chunk and a whole answer go through one usage reader,
    /// so Mistral's audio seconds are billed the same streamed or not.
    #[test]
    fn a_streamed_usage_reads_as_the_whole_answers() {
        let usage = r#"{"prompt_tokens":9,"completion_tokens":5,"total_tokens":389,"prompt_audio_seconds":3,"prompt_tokens_details":{"cached_tokens":0,"audio_tokens":375}}"#;
        let events = chat(&format!(r#"{{"choices":[{{"index":0,"delta":{{"content":""}},"finish_reason":"stop"}}],"usage":{usage}}}"#));
        let streamed = events
            .iter()
            .find_map(|e| match e {
                DomainEvent::Usage(u) => Some(u.clone()),
                _ => None,
            })
            .unwrap();
        let whole = super::super::chat::usage_of(&serde_json::from_str(usage).unwrap());
        assert_eq!(streamed.billed_units(), whole.billed_units());
        assert_eq!(streamed.audio_prompt_seconds, Some(3));
    }

    #[test]
    fn text_in_the_finishing_chunk_is_read_before_the_finish() {
        // Ollama and vLLM send the last text beside `finish_reason` and usage.
        // It is content: the audit, the response policy and a translated
        // client all need it, and it precedes the end it arrives with.
        let events = chat(r#"{"choices":[{"index":0,"delta":{"content":"end."},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#);
        assert_matches!(
            events.as_slice(),
            [DomainEvent::TextDelta(t), DomainEvent::Done { .. }, DomainEvent::Usage(_)] if t == "end."
        );
    }

    #[test]
    fn reasoning_and_text_in_one_delta_are_both_read() {
        let events = chat(r#"{"choices":[{"index":0,"delta":{"reasoning_content":"hmm","content":"yes"},"finish_reason":null}]}"#);
        assert_matches!(
            events.as_slice(),
            [DomainEvent::ReasoningDelta(r), DomainEvent::TextDelta(t)] if r == "hmm" && t == "yes"
        );
    }

    #[test]
    fn every_tool_call_in_one_chunk_is_read() {
        // A parallel-call chunk names each call; the second is no less a call
        // for sharing the first one's chunk, and policy must see it.
        let events = chat(r#"{"choices":[{"index":0,"delta":{"tool_calls":[
            {"index":0,"id":"call_a","function":{"name":"Read","arguments":"{}"}},
            {"index":1,"id":"call_b","function":{"name":"Bash","arguments":"{}"}}
        ]},"finish_reason":null}]}"#);
        let calls: Vec<(usize, Option<&str>)> = events
            .iter()
            .map(|e| match e {
                DomainEvent::ToolCallDelta { index, function_name, .. } => (*index, function_name.as_deref()),
                other => panic!("expected only calls, got {other:?}"),
            })
            .collect();
        assert_eq!(calls, [(0, Some("Read")), (1, Some("Bash"))]);
    }

    #[test]
    fn a_gemini_chunks_content_comes_before_its_finish() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"last"}]},"finishReason":"STOP"}]}"#.to_string(),
            id: None,
        };
        let events = parse_domain_event(&event, ApiVersion::GoogleGemini);
        assert_matches!(
            events.as_slice(),
            [DomainEvent::TextDelta(t), DomainEvent::Done { .. }] if t == "last"
        );
    }

    #[test]
    fn test_parse_chat_finish_reason() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::Done { finish_reason, native_finish_reason } => {
                assert_eq!(*finish_reason, Some(FinishReason::Stop));
                assert_eq!(native_finish_reason.as_deref(), Some("stop"));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_chat_usage() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"id":"chatcmpl-1","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 10);
                assert_eq!(usage.completion_tokens, 20);
                assert_eq!(usage.total_tokens, 30);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_chat_usage_with_cached_and_reasoning() {
        // OpenAI Chat Completions: cached_tokens lives under prompt_tokens_details,
        // reasoning_tokens under completion_tokens_details. Separate buckets.
        let event = SseEvent {
            event_type: None,
            data: r#"{"id":"chatcmpl-1","choices":[],"usage":{
                "prompt_tokens":1000,
                "completion_tokens":200,
                "total_tokens":1200,
                "prompt_tokens_details":{"cached_tokens":600},
                "completion_tokens_details":{"reasoning_tokens":150}
            }}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 1000);
                assert_eq!(usage.completion_tokens, 200);
                assert_eq!(usage.cache_read_tokens, Some(600));
                assert_eq!(usage.reasoning_tokens, Some(150));
                assert_eq!(usage.cache_creation_tokens, None);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    /// Gemini is the one protocol that reports thinking tokens OUTSIDE its output
    /// count, so `completion_tokens` must add them back or a thinking model bills
    /// only its visible answer. The fixture's own `totalTokenCount` is the proof
    /// the two buckets are disjoint: 1000 + 200 + 150 = 1350.
    #[test]
    fn gemini_thinking_tokens_count_as_billable_output() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"candidates":[],"usageMetadata":{
                "promptTokenCount":1000,
                "candidatesTokenCount":200,
                "thoughtsTokenCount":150,
                "totalTokenCount":1350
            }}"#
            .to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::GoogleGemini);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 1000);
                // Billable output = visible candidates + billed-but-hidden thoughts.
                assert_eq!(usage.completion_tokens, 350);
                // The sub-count is still reported for display.
                assert_eq!(usage.reasoning_tokens, Some(150));
                assert_eq!(usage.total_tokens, 1350);
                assert_eq!(
                    usage.prompt_tokens + usage.completion_tokens,
                    usage.total_tokens,
                    "the domain's own totals must reconcile with Gemini's"
                );
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    /// A non-thinking Gemini response has no `thoughtsTokenCount` at all, and
    /// must bill exactly its candidate count — the fix must not inflate it.
    #[test]
    fn gemini_without_thinking_bills_only_candidates() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"candidates":[],"usageMetadata":{
                "promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15
            }}"#
            .to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::GoogleGemini);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.completion_tokens, 5);
                assert_eq!(usage.reasoning_tokens, None);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_done_sentinel_returns_empty() {
        let event = SseEvent {
            event_type: None,
            data: "[DONE]".to_string(),
            id: None,
        };
        assert!(parse_domain_event(&event, ApiVersion::ChatCompletions).is_empty());
    }

    #[test]
    fn test_parse_malformed_json_returns_empty() {
        let event = SseEvent {
            event_type: None,
            data: "not json at all".to_string(),
            id: None,
        };
        assert!(parse_domain_event(&event, ApiVersion::ChatCompletions).is_empty());
    }

    #[test]
    fn test_parse_chat_reasoning_delta() {
        let event = SseEvent {
            event_type: None,
            data: r#"{"id":"chatcmpl-1","choices":[{"index":0,"delta":{"reasoning":"Let me think..."},"finish_reason":null}]}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ReasoningDelta(text) => assert_eq!(text, "Let me think..."),
            other => panic!("expected ReasoningDelta, got {other:?}"),
        }
    }

    /// The streaming parser must accept every spelling in
    /// [`crate::api::chat::REASONING_KEYS`].
    ///
    /// `ChatDelta`'s fields are serde idents and cannot be generated from that
    /// const, so this is the only thing tying the two together. A spelling added
    /// to the const without a field here would leave that provider's reasoning
    /// unaccumulated on the streaming path — invisible to the audit row, the PII
    /// scan and the cache — while the passthrough emitter still forwards it to
    /// the client. Non-streaming would keep working, which is what makes the
    /// split so easy to miss.
    #[test]
    fn chat_delta_covers_every_reasoning_spelling() {
        for key in crate::api::chat::REASONING_KEYS {
            let event = SseEvent {
                event_type: None,
                data: format!(
                    r#"{{"id":"chatcmpl-1","choices":[{{"index":0,"delta":{{"{key}":"why"}},"finish_reason":null}}]}}"#
                ),
                id: None,
            };
            let result = parse_domain_event(&event, ApiVersion::ChatCompletions);
            assert_matches!(
                result.as_slice(),
                [DomainEvent::ReasoningDelta(text)] if text == "why",
                "`{key}` is in REASONING_KEYS but the streaming parser drops it"
            );
        }
    }

    /// A chunk-array `delta.content` (Mistral) is read chunk by chunk, in
    /// order: `thinking` as reasoning, `text` as text, anything else skipped —
    /// and the finish, usage and tool calls beside it are read as well.
    #[test]
    fn a_chunk_array_delta_is_read_chunk_by_chunk() {
        let events = chat(
            r#"{"choices":[{"index":0,"delta":{"content":[
                {"type":"thinking","thinking":[{"type":"text","text":"why"},{"type":"reference","reference_ids":[1]}]},
                {"type":"reference","reference_ids":[2]},
                {"type":"text","text":""},
                {"type":"text","text":"answer"}
            ]},"finish_reason":"model_length"}],
            "usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}"#,
        );
        assert_matches!(
            events.as_slice(),
            [
                DomainEvent::ReasoningDelta(r),
                DomainEvent::TextDelta(t),
                DomainEvent::Done { finish_reason: Some(FinishReason::Length), .. },
                DomainEvent::Usage(u),
            ] if r == "why" && t == "answer" && u.completion_tokens == 4,
            "{events:?}"
        );
    }

    /// Every shape a `delta.content` might hold: the spec's two and the
    /// malformed rest.
    fn any_delta_content() -> impl proptest::strategy::Strategy<Value = serde_json::Value> {
        use proptest::prelude::*;
        let chunk = prop_oneof![
            "[a-z]{0,4}".prop_map(|t| serde_json::json!({"type": "text", "text": t})),
            "[a-z]{0,4}".prop_map(|t| serde_json::json!({"type": "thinking", "thinking": [{"type": "text", "text": t}]})),
            Just(serde_json::json!({"type": "text", "text": 5})),
            Just(serde_json::json!(["nested"])),
            Just(serde_json::json!({"no_type": true})),
        ];
        prop_oneof![
            Just(serde_json::Value::Null),
            "[a-z]{0,4}".prop_map(serde_json::Value::from),
            any::<i64>().prop_map(serde_json::Value::from),
            any::<bool>().prop_map(serde_json::Value::from),
            proptest::collection::vec(chunk, 0..4).prop_map(serde_json::Value::from),
            Just(serde_json::json!({"type": "text", "text": "obj"})),
        ]
    }

    proptest::proptest! {
        /// Whatever `delta.content` or a reasoning key holds, the rest of the
        /// chunk is read: its tool call, finish reason and usage each produce
        /// their event.
        #[test]
        fn no_content_shape_takes_the_rest_of_the_chunk_down(content in any_delta_content()) {
            use proptest::prelude::*;
            let chunk = serde_json::json!({
                "choices": [{"index": 0, "delta": {
                    "content": content.clone(),
                    "reasoning": content,
                    "tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
                }, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
            });
            let events = chat(&chunk.to_string());
            prop_assert!(events.iter().any(|e| matches!(e, DomainEvent::ToolCallDelta { .. })), "{events:?}");
            prop_assert!(events.iter().any(|e| matches!(e, DomainEvent::Done { finish_reason: Some(FinishReason::ToolCalls), .. })), "{events:?}");
            prop_assert!(events.iter().any(|e| matches!(e, DomainEvent::Usage(_))), "{events:?}");
        }
    }

    #[test]
    fn test_parse_responses_text_delta() {
        let event = SseEvent {
            event_type: Some("response.output_text.delta".to_string()),
            data: r#"{"delta":"World"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::TextDelta(text) => assert_eq!(text, "World"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_function_delta() {
        let event = SseEvent {
            event_type: Some("response.function_call_arguments.delta".to_string()),
            data: r#"{"delta":"{\"q\":"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { arguments_delta, .. } => {
                assert_eq!(arguments_delta, r#"{"q":"#);
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_completed_emits_usage_and_done() {
        let event = SseEvent {
            event_type: Some("response.completed".to_string()),
            data: r#"{"response":{"status":"completed","usage":{"input_tokens":15,"output_tokens":25,"total_tokens":40}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 2, "response.completed should emit both Usage and Done");
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 15);
                assert_eq!(usage.completion_tokens, 25);
                assert_eq!(usage.total_tokens, 40);
            }
            other => panic!("expected Usage as first event, got {other:?}"),
        }
        match &result[1] {
            DomainEvent::Done { finish_reason, .. } => {
                assert_eq!(*finish_reason, Some(FinishReason::Stop));
            }
            other => panic!("expected Done as second event, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_completed_without_usage() {
        let event = SseEvent {
            event_type: Some("response.completed".to_string()),
            data: r#"{"response":{"status":"incomplete"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1, "response.completed without usage should emit only Done");
        match &result[0] {
            DomainEvent::Done { finish_reason, .. } => {
                assert_eq!(*finish_reason, Some(FinishReason::Length));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// A Chat Completions or Gemini upstream failing mid-stream sends its error
    /// object as a chunk; it is an error, not a chunk with nothing in it.
    #[test]
    fn a_mid_stream_error_chunk_from_chat_or_gemini_is_an_error_event() {
        let cases = [
            (
                ApiVersion::ChatCompletions,
                r#"{"error":{"message":"too long","type":"invalid_request_error","param":null,"code":"context_length_exceeded"}}"#,
                "too long",
                Some("context_length_exceeded"),
            ),
            (
                ApiVersion::ChatCompletions,
                r#"{"error":{"message":"busy","type":"server_error","code":null}}"#,
                "busy",
                Some("server_error"),
            ),
            (
                ApiVersion::GoogleGemini,
                r#"{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}"#,
                "quota",
                Some("RESOURCE_EXHAUSTED"),
            ),
            // Some OpenAI-compatible servers send the message alone, or a number
            // where a name belongs.
            (ApiVersion::ChatCompletions, r#"{"error":"Internal server error"}"#, "Internal server error", None),
            (ApiVersion::ChatCompletions, r#"{"error":{"message":"overloaded","status":500}}"#, "overloaded", None),
        ];
        for (protocol, data, want_message, want_code) in cases {
            let event = SseEvent { event_type: None, data: data.to_string(), id: None };
            match parse_domain_event(&event, protocol).as_slice() {
                [DomainEvent::Error { message, code }] => {
                    assert_eq!(message, want_message);
                    assert_eq!(code.as_deref(), want_code);
                }
                other => panic!("{protocol:?}: expected one Error, got {other:?}"),
            }
        }
    }

    /// An `error` member that says nothing is no error on a stream either — the
    /// same reading as a whole answer's (`envelope::is_error`): the chunk's
    /// content is read as if it were absent. Positive control: the cases above.
    #[test]
    fn an_empty_error_member_on_a_chunk_is_no_error() {
        for empty in [r#"null"#, r#"{}"#, r#""""#, r#""  ""#, r#"false"#] {
            for protocol in [ApiVersion::ChatCompletions, ApiVersion::GoogleGemini] {
                let data = match protocol {
                    ApiVersion::ChatCompletions => format!(
                        r#"{{"error":{empty},"choices":[{{"index":0,"delta":{{"content":"hi"}},"finish_reason":null}}]}}"#
                    ),
                    _ => format!(r#"{{"error":{empty},"candidates":[{{"content":{{"parts":[{{"text":"hi"}}]}}}}]}}"#),
                };
                let event = SseEvent { event_type: None, data, id: None };
                let events = parse_domain_event(&event, protocol);
                assert!(
                    !events.iter().any(|e| matches!(e, DomainEvent::Error { .. })),
                    "{protocol:?} {empty}: {events:?}"
                );
                assert!(
                    events.iter().any(|e| matches!(e, DomainEvent::TextDelta(t) if t == "hi")),
                    "{protocol:?} {empty}: the chunk's content is read: {events:?}"
                );
            }
        }
    }

    /// The Responses `error` event as its spec defines it: `code`, `message`,
    /// `param` and `sequence_number` beside `type`, nothing nested.
    #[test]
    fn a_responses_error_event_in_the_spec_shape_keeps_its_message_and_code() {
        let event = SseEvent {
            event_type: Some("error".to_string()),
            data: r#"{"type":"error","code":"rate_limit_exceeded","message":"slow down","param":null,"sequence_number":7}"#
                .to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        match result.as_slice() {
            [DomainEvent::Error { message, code }] => {
                assert_eq!(message, "slow down");
                assert_eq!(code.as_deref(), Some("rate_limit_exceeded"));
            }
            other => panic!("expected one Error, got {other:?}"),
        }
    }

    /// A server nesting the members under `error` is read too.
    #[test]
    fn test_parse_responses_error() {
        let event = SseEvent {
            event_type: Some("error".to_string()),
            data: r#"{"error":{"message":"rate limit","code":"rate_limit_exceeded"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::Error { message, code } => {
                assert_eq!(message, "rate limit");
                assert_eq!(code.as_deref(), Some("rate_limit_exceeded"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_unknown_event_returns_empty() {
        let event = SseEvent {
            event_type: Some("response.created".to_string()),
            data: r#"{"type":"response.created"}"#.to_string(),
            id: None,
        };
        assert!(parse_domain_event(&event, ApiVersion::Responses).is_empty());
    }

    #[test]
    fn test_parse_responses_reasoning_summary_delta() {
        let event = SseEvent {
            event_type: Some("response.reasoning_summary_text.delta".to_string()),
            data: r#"{"delta":"Let me think about this..."}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ReasoningDelta(text) => assert_eq!(text, "Let me think about this..."),
            other => panic!("expected ReasoningDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_reasoning_text_delta() {
        let event = SseEvent {
            event_type: Some("response.reasoning_text.delta".to_string()),
            data: r#"{"delta":"Step 1: analyze the problem"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ReasoningDelta(text) => assert_eq!(text, "Step 1: analyze the problem"),
            other => panic!("expected ReasoningDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_completed_with_token_details() {
        let event = SseEvent {
            event_type: Some("response.completed".to_string()),
            data: r#"{"response":{"status":"completed","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150,"output_tokens_details":{"reasoning_tokens":30},"input_tokens_details":{"cached_tokens":20}}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 2); // Usage + Done
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 100);
                assert_eq!(usage.completion_tokens, 50);
                assert_eq!(usage.reasoning_tokens, Some(30));
                assert_eq!(usage.cache_creation_tokens, None);
                assert_eq!(usage.cache_read_tokens, Some(20));
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_completed_without_token_details() {
        let event = SseEvent {
            event_type: Some("response.completed".to_string()),
            data: r#"{"response":{"status":"completed","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 2);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.reasoning_tokens, None);
                assert_eq!(usage.cache_creation_tokens, None);
                assert_eq!(usage.cache_read_tokens, None);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_output_item_added_function_call() {
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"item":{"type":"function_call","call_id":"call_abc123","name":"get_weather"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, .. } => {
                assert_eq!(*index, 0);
                assert_eq!(id.as_deref(), Some("call_abc123"));
                assert_eq!(function_name.as_deref(), Some("get_weather"));
                assert!(arguments_delta.is_empty());
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    /// A call as [`assembled_calls`] reads it: its first id and name, its
    /// arguments joined, and every form a delta of it carried.
    type AssembledCall = (Option<String>, Option<String>, String, Vec<crate::api::domain::CallArguments>);

    /// The calls a stream's events make, by number, as every reader downstream
    /// assembles them.
    fn assembled_calls(events: &[DomainEvent]) -> std::collections::BTreeMap<usize, AssembledCall> {
        let mut calls: std::collections::BTreeMap<usize, AssembledCall> = Default::default();
        for e in events {
            if let DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, form } = e {
                let call = calls.entry(*index).or_default();
                if call.0.is_none() {
                    call.0.clone_from(id);
                }
                if call.1.is_none() {
                    call.1.clone_from(function_name);
                }
                call.2.push_str(arguments_delta);
                call.3.push(*form);
            }
        }
        calls
    }

    #[test]
    fn a_built_in_tools_call_is_read_from_its_done_whole() {
        // A shell call opens with no commands, streams them, and states them
        // whole in its done: the stream reads ONE call, named by its item type,
        // its arguments the payload the done states — never the opening's,
        // which the stream went on to fill — and every delta of it carries the
        // built-in form, the streamed command frames included.
        use crate::api::domain::{CallArguments, ClientBuiltin};
        let item = |status: &str, commands: serde_json::Value| serde_json::json!({
            "id": "sh_1", "type": "shell_call", "call_id": "call_1", "status": status,
            "action": {"commands": commands, "timeout_ms": 5}
        });
        let frames = [
            ("response.output_item.added", serde_json::json!({"output_index": 0, "item": item("in_progress", serde_json::json!([]))})),
            ("response.shell_call_command.added", serde_json::json!({"output_index": 0, "command_index": 0, "command": ""})),
            ("response.shell_call_command.delta", serde_json::json!({"output_index": 0, "command_index": 0, "delta": "rm -rf /"})),
            ("response.shell_call_command.done", serde_json::json!({"output_index": 0, "command_index": 0, "command": "rm -rf /"})),
            ("response.output_item.done", serde_json::json!({"output_index": 0, "item": item("completed", serde_json::json!(["rm -rf /"]))})),
        ];
        let mut parser = StreamParser::new(ApiVersion::Responses);
        let mut events = Vec::new();
        for (name, data) in frames {
            events.extend(parser.parse(&SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None }));
        }
        let calls = assembled_calls(&events);
        assert_eq!(calls.len(), 1, "{events:?}");
        let (id, name, arguments, forms) = &calls[&0];
        assert_eq!(id.as_deref(), Some("call_1"));
        assert_eq!(name.as_deref(), Some("shell_call"));
        let arguments: serde_json::Value = serde_json::from_str(arguments).expect("the arguments are the payload's JSON");
        assert_eq!(arguments, serde_json::json!({"commands": ["rm -rf /"], "timeout_ms": 5}));
        assert!(forms.iter().all(|f| *f == CallArguments::ClientBuiltin(ClientBuiltin::Shell)), "{forms:?}");
        assert_eq!(forms.len(), 5, "every frame of the call rides it: {events:?}");
    }

    #[test]
    fn every_built_in_tools_call_is_read_as_a_call() {
        // Each kind a Responses client runs itself, stated at its opening and
        // at its done alike, read once — and an item a server runs is not one.
        use crate::api::domain::{CallArguments, ClientBuiltin};
        for (item, builtin, payload) in [
            (serde_json::json!({"type": "local_shell_call", "id": "i", "call_id": "c", "status": "completed",
                "action": {"type": "exec", "command": ["ls"], "env": {}}}),
             ClientBuiltin::LocalShell, serde_json::json!({"type": "exec", "command": ["ls"], "env": {}})),
            (serde_json::json!({"type": "apply_patch_call", "id": "i", "call_id": "c", "status": "completed",
                "operation": {"type": "delete_file", "path": "a.txt"}}),
             ClientBuiltin::ApplyPatch, serde_json::json!({"type": "delete_file", "path": "a.txt"})),
            (serde_json::json!({"type": "computer_call", "id": "i", "call_id": "c", "status": "completed",
                "pending_safety_checks": [], "action": {"type": "click", "x": 1, "y": 2, "button": "left"}}),
             ClientBuiltin::Computer, serde_json::json!({"type": "click", "x": 1, "y": 2, "button": "left"})),
            (serde_json::json!({"type": "computer_call", "id": "i", "call_id": "c", "status": "completed",
                "pending_safety_checks": [], "actions": [{"type": "wait"}]}),
             ClientBuiltin::Computer, serde_json::json!([{"type": "wait"}])),
        ] {
            let mut parser = StreamParser::new(ApiVersion::Responses);
            let mut events = Vec::new();
            for name in ["response.output_item.added", "response.output_item.done"] {
                let data = serde_json::json!({"output_index": 0, "item": item});
                events.extend(parser.parse(&SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None }));
            }
            let calls = assembled_calls(&events);
            assert_eq!(calls.len(), 1, "{item}");
            let (id, name, arguments, forms) = &calls[&0];
            assert_eq!(id.as_deref(), Some("c"));
            assert_eq!(name.as_deref(), Some(builtin.tool_name()));
            assert_eq!(serde_json::from_str::<serde_json::Value>(arguments).ok(), Some(payload), "{item}");
            assert!(forms.iter().all(|f| *f == CallArguments::ClientBuiltin(builtin)), "{forms:?}");
            // The non-streaming reader reads the same call.
            let call = crate::api::domain::tool_call_item(&item).expect("read as a call");
            assert_eq!((call.name, call.builtin), (builtin.tool_name(), Some(builtin)));
        }
        let mut parser = StreamParser::new(ApiVersion::Responses);
        let web = serde_json::json!({"output_index": 0, "item": {"type": "web_search_call", "id": "ws_1", "status": "completed"}});
        let events = parser.parse(&SseEvent { event_type: Some("response.output_item.added".into()), data: web.to_string(), id: None });
        assert!(assembled_calls(&events).is_empty(), "a call the server runs is no client's: {events:?}");
    }

    #[test]
    fn test_parse_responses_output_item_added_non_function_ignored() {
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"item":{"type":"message","role":"assistant"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "non-function_call output_item.added should be ignored");
    }

    #[test]
    fn test_parse_responses_function_call_arguments_done() {
        // done event is a no-op: id/name already set by output_item.added,
        // args accumulated from delta events. Emitting here would cause
        // AnthropicResponseBuilder to open a phantom second tool_use block.
        let event = SseEvent {
            event_type: Some("response.function_call_arguments.done".to_string()),
            data: r#"{"call_id":"call_abc123","name":"get_weather","arguments":"{\"location\":\"SF\"}"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "done event must be no-op to avoid phantom tool blocks");
    }

    #[test]
    fn test_parse_responses_refusal_delta() {
        let event = SseEvent {
            event_type: Some("response.refusal.delta".to_string()),
            data: r#"{"delta":"I cannot help with that request."}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::TextDelta(text) => assert_eq!(text, "I cannot help with that request."),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_incomplete() {
        let event = SseEvent {
            event_type: Some("response.incomplete".to_string()),
            data: r#"{"response":{"status":"incomplete","usage":{"input_tokens":100,"output_tokens":4096,"total_tokens":4196}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 2, "response.incomplete should emit Usage + Done");
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 100);
                assert_eq!(usage.completion_tokens, 4096);
                assert_eq!(usage.total_tokens, 4196);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        match &result[1] {
            DomainEvent::Done { finish_reason, native_finish_reason } => {
                assert_eq!(*finish_reason, Some(FinishReason::Length));
                assert_eq!(native_finish_reason.as_deref(), Some("incomplete"));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_failed() {
        let event = SseEvent {
            event_type: Some("response.failed".to_string()),
            data: r#"{"response":{"status":"failed","error":{"message":"server error","code":"server_error"}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 2, "response.failed should emit Error + Done");
        match &result[0] {
            DomainEvent::Error { message, code } => {
                assert_eq!(message, "server error");
                assert_eq!(code.as_deref(), Some("server_error"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
        match &result[1] {
            DomainEvent::Done { finish_reason, native_finish_reason } => {
                assert_eq!(*finish_reason, Some(FinishReason::Error));
                assert_eq!(native_finish_reason.as_deref(), Some("failed"));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    // ── Anthropic Messages API SSE tests ──

    #[test]
    fn test_parse_anthropic_text_delta() {
        let event = SseEvent {
            event_type: Some("content_block_delta".to_string()),
            data: r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::TextDelta(text) => assert_eq!(text, "Hello"),
            other => panic!("expected TextDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_tool_use_start() {
        let event = SseEvent {
            event_type: Some("content_block_start".to_string()),
            data: r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_123","name":"get_weather"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { id, function_name, arguments_delta, .. } => {
                assert_eq!(id.as_deref(), Some("toolu_123"));
                assert_eq!(function_name.as_deref(), Some("get_weather"));
                assert!(arguments_delta.is_empty());
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_input_json_delta() {
        let event = SseEvent {
            event_type: Some("content_block_delta".to_string()),
            data: r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"loc"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { arguments_delta, .. } => {
                assert_eq!(arguments_delta, r#"{"loc"#);
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_message_delta_with_usage() {
        let event = SseEvent {
            event_type: Some("message_delta".to_string()),
            data: r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 2);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.completion_tokens, 25);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        match &result[1] {
            DomainEvent::Done { finish_reason, .. } => {
                assert_eq!(*finish_reason, Some(FinishReason::Stop));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    /// The audit's `native_finish_reason` is Anthropic's own word; the
    /// normalized reason is the domain's reading of it.
    #[test]
    fn an_anthropic_stop_keeps_its_own_word_as_the_native_reason() {
        for (word, reading) in [
            ("refusal", FinishReason::ContentFilter),
            ("stop_sequence", FinishReason::Stop),
            ("pause_turn", FinishReason::Error),
        ] {
            let event = SseEvent {
                event_type: Some("message_delta".to_string()),
                data: format!(r#"{{"type":"message_delta","delta":{{"stop_reason":"{word}"}},"usage":{{"output_tokens":1}}}}"#),
                id: None,
            };
            let done = parse_domain_event(&event, ApiVersion::AnthropicMessages)
                .into_iter()
                .find_map(|e| match e {
                    DomainEvent::Done { finish_reason, native_finish_reason } => Some((finish_reason, native_finish_reason)),
                    _ => None,
                })
                .unwrap();
            assert_eq!(done, (Some(reading), Some(word.to_string())), "{word}");
        }
    }

    #[test]
    fn test_parse_anthropic_message_stop_returns_empty() {
        let event = SseEvent {
            event_type: Some("message_stop".to_string()),
            data: r#"{"type":"message_stop"}"#.to_string(),
            id: None,
        };
        assert!(parse_domain_event(&event, ApiVersion::AnthropicMessages).is_empty());
    }

    #[test]
    fn test_parse_anthropic_ping_returns_empty() {
        let event = SseEvent {
            event_type: Some("ping".to_string()),
            data: r#"{"type":"ping"}"#.to_string(),
            id: None,
        };
        assert!(parse_domain_event(&event, ApiVersion::AnthropicMessages).is_empty());
    }

    #[test]
    fn test_parse_anthropic_message_delta_with_cache_tokens() {
        let event = SseEvent {
            event_type: Some("message_delta".to_string()),
            data: r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":25,"cache_creation_input_tokens":100,"cache_read_input_tokens":50}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 2);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.completion_tokens, 25);
                assert_eq!(usage.cache_creation_tokens, Some(100));
                assert_eq!(usage.cache_read_tokens, Some(50));
                // No input_tokens in this fixture — prompt_tokens stays 0 so the upstream
                // usage-merge guard preserves the value set by message_start. (If cache stats
                // arrive only in message_delta without an accompanying input_tokens, the cache
                // portion will not be added to prompt_tokens — known edge case, doesn't occur
                // in real Anthropic streams.)
                assert_eq!(usage.prompt_tokens, 0);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_message_start_with_cache_tokens() {
        let event = SseEvent {
            event_type: Some("message_start".to_string()),
            data: r#"{"type":"message_start","message":{"usage":{"input_tokens":500,"cache_read_input_tokens":200}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                // Anthropic's input_tokens (500) is the non-cached portion; cache_read (200) is
                // disjoint. Domain Usage is inclusive, so prompt_tokens = 500 + 0 + 200 = 700.
                assert_eq!(usage.prompt_tokens, 700);
                assert_eq!(usage.total_tokens, 700);
                assert_eq!(usage.cache_creation_tokens, None);
                assert_eq!(usage.cache_read_tokens, Some(200));
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_message_start_inclusive_sum() {
        // Full breakdown: 500 fresh + 100 cache-creation + 50 cache-read = 650 total input.
        let event = SseEvent {
            event_type: Some("message_start".to_string()),
            data: r#"{"type":"message_start","message":{"usage":{"input_tokens":500,"cache_creation_input_tokens":100,"cache_read_input_tokens":50}}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.prompt_tokens, 650);
                assert_eq!(usage.cache_creation_tokens, Some(100));
                assert_eq!(usage.cache_read_tokens, Some(50));
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_anthropic_usage_carries_its_one_hour_cache_writes() {
        let event = SseEvent {
            event_type: Some("message_start".to_string()),
            data: r#"{"type":"message_start","message":{"usage":{"input_tokens":500,"cache_creation_input_tokens":100,"cache_read_input_tokens":50,"cache_creation":{"ephemeral_5m_input_tokens":60,"ephemeral_1h_input_tokens":40}}}}"#.to_string(),
            id: None,
        };
        match &parse_domain_event(&event, ApiVersion::AnthropicMessages)[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.cache_creation_tokens, Some(100));
                assert_eq!(usage.cache_creation_1h_tokens, Some(40));
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        // A split in a shape the parser does not expect costs only the split.
        let odd = SseEvent {
            event_type: Some("message_delta".to_string()),
            data: r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":5,"output_tokens":7,"cache_creation_input_tokens":3,"cache_creation":0}}"#.to_string(),
            id: None,
        };
        let events = parse_domain_event(&odd, ApiVersion::AnthropicMessages);
        assert_matches!(&events[0], DomainEvent::Usage(u) if u.completion_tokens == 7 && u.cache_creation_1h_tokens.is_none());
        assert_matches!(&events[1], DomainEvent::Done { .. });
    }

    #[test]
    fn test_parse_anthropic_message_delta_no_cache_tokens() {
        let event = SseEvent {
            event_type: Some("message_delta".to_string()),
            data: r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        match &result[0] {
            DomainEvent::Usage(usage) => {
                assert_eq!(usage.cache_creation_tokens, None);
                assert_eq!(usage.cache_read_tokens, None);
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_anthropic_thinking_delta() {
        let event = SseEvent {
            event_type: Some("content_block_delta".to_string()),
            data: r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","text":"Let me think..."}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::AnthropicMessages);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ReasoningDelta(text) => assert_eq!(text, "Let me think..."),
            other => panic!("expected ReasoningDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_api_version_from_path_messages() {
        assert_eq!(ApiVersion::from_path("/v1/messages"), ApiVersion::AnthropicMessages);
        assert_eq!(ApiVersion::from_path("/v1/messages/count_tokens"), ApiVersion::AnthropicMessages);
    }

    #[test]
    fn test_api_version_from_path_unchanged() {
        assert_eq!(ApiVersion::from_path("/v1/chat/completions"), ApiVersion::ChatCompletions);
        assert_eq!(ApiVersion::from_path("/v1/responses"), ApiVersion::Responses);
    }

    #[test]
    fn test_api_version_from_fwd_path() {
        // /fwd/{key}/v1/... paths use substring matching — should work with prefix.
        assert_eq!(ApiVersion::from_path("/fwd/vk-abc123/v1/messages"), ApiVersion::AnthropicMessages);
        assert_eq!(ApiVersion::from_path("/fwd/vk-abc123/v1/chat/completions"), ApiVersion::ChatCompletions);
        assert_eq!(ApiVersion::from_path("/fwd/vk-abc123/v1/responses"), ApiVersion::Responses);
        assert_eq!(ApiVersion::from_path("/fwd/vk-abc123/v1/messages/count_tokens"), ApiVersion::AnthropicMessages);
    }

    #[test]
    fn test_anthropic_api_version_as_str() {
        assert_eq!(ApiVersion::AnthropicMessages.as_str(), "anthropic_messages");
    }

    // ─── MCP call handling ───

    #[test]
    fn test_parse_responses_mcp_call_output_item_added() {
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"item":{"id":"mcp_abc123","arguments":"","name":"webfetch","server_label":"webfetch","type":"mcp_call","status":"in_progress"},"output_index":1}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, .. } => {
                assert_eq!(*index, 0);
                assert_eq!(id.as_deref(), Some("mcp_abc123"));
                assert_eq!(function_name.as_deref(), Some("webfetch"));
                assert!(arguments_delta.is_empty());
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_mcp_call_strips_server_label_prefix() {
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"item":{"id":"mcp_xyz","arguments":"","name":"repo_browser.glob","server_label":"repo_browser","type":"mcp_call","status":"in_progress"},"output_index":1}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { function_name, .. } => {
                // "repo_browser.glob" should be stripped to "glob"
                assert_eq!(function_name.as_deref(), Some("glob"));
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_mcp_call_no_strip_when_no_prefix() {
        // When name doesn't start with server_label prefix, keep as-is
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"item":{"id":"mcp_xyz","arguments":"","name":"custom_tool","server_label":"other_server","type":"mcp_call","status":"in_progress"},"output_index":1}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        match &result[0] {
            DomainEvent::ToolCallDelta { function_name, .. } => {
                assert_eq!(function_name.as_deref(), Some("custom_tool"));
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_mcp_call_arguments_delta() {
        let event = SseEvent {
            event_type: Some("response.mcp_call_arguments.delta".to_string()),
            data: r#"{"delta":"{\"url\":","item_id":"mcp_abc","output_index":1,"sequence_number":5,"type":"response.mcp_call_arguments.delta"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ToolCallDelta { arguments_delta, id, function_name, form, .. } => {
                assert_eq!(arguments_delta, r#"{"url":"#);
                // Placed by the item it names (see `StreamParser`).
                assert!(id.is_none());
                assert!(function_name.is_none());
                assert_eq!(*form, crate::api::domain::CallArguments::ServerTool);
            }
            other => panic!("expected ToolCallDelta, got {other:?}"),
        }
    }

    /// Every Responses call event is placed on the item it NAMES — by
    /// `output_index` and `item_id`, as a client applies it — never on the
    /// item opened last. An `mcp_call` is a tool the upstream runs on a remote
    /// MCP server: its input is that server tool's, never a client's call; a
    /// client call's delta sent after it opened is still the client call's,
    /// which policy reads; and a delta calling itself an MCP call's input but
    /// naming the client's item is the client's.
    #[test]
    fn a_responses_call_event_is_the_items_it_names() {
        use crate::api::domain::CallArguments;
        let ev = |name: &str, data: serde_json::Value| SseEvent { event_type: Some(name.into()), data: data.to_string(), id: None };
        let mut parser = StreamParser::new(ApiVersion::Responses);
        let mut events = Vec::new();
        for frame in [
            ev("response.output_item.added", serde_json::json!({"output_index": 0,
                "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "bash", "arguments": ""}})),
            ev("response.output_item.added", serde_json::json!({"output_index": 1,
                "item": {"id": "mcp_1", "type": "mcp_call", "name": "fetch", "server_label": "srv", "arguments": ""}})),
            // The client call's arguments, after the server tool's item opened.
            ev("response.function_call_arguments.delta", serde_json::json!({"item_id": "fc_1", "output_index": 0, "delta": "{\"cmd\":\"rm -rf /\"}"})),
            ev("response.mcp_call_arguments.delta", serde_json::json!({"item_id": "mcp_1", "output_index": 1, "delta": "{\"url\":1}"})),
            // Named by its place alone, or by its id alone.
            ev("response.function_call_arguments.delta", serde_json::json!({"output_index": 0, "delta": " "})),
            ev("response.function_call_arguments.delta", serde_json::json!({"item_id": "fc_1", "delta": " "})),
            // Calling itself an MCP call's input, naming the client's item.
            ev("response.mcp_call_arguments.delta", serde_json::json!({"item_id": "fc_1", "output_index": 0, "delta": " "})),
        ] {
            events.extend(parser.parse(&frame));
        }
        let calls: Vec<(usize, &str, CallArguments)> = events
            .iter()
            .filter_map(|e| match e {
                DomainEvent::ToolCallDelta { index, arguments_delta, form, .. } => Some((*index, arguments_delta.as_str(), *form)),
                _ => None,
            })
            .collect();
        assert_eq!(
            calls,
            vec![
                (0, "", CallArguments::Json),
                (1, "", CallArguments::ServerTool),
                (0, "{\"cmd\":\"rm -rf /\"}", CallArguments::Json),
                (1, "{\"url\":1}", CallArguments::ServerTool),
                (0, " ", CallArguments::Json),
                (0, " ", CallArguments::Json),
                (0, " ", CallArguments::Json),
            ]
        );
        assert!(!events[0].not_a_client_call() && events[1].not_a_client_call());
    }

    /// An item opened without its `output_index` is its own once a later
    /// event names it by its id and a place no other item holds: every event
    /// naming that place, or that id, is placed on it — never withheld as no
    /// call's — and a place another item holds still names that one.
    #[test]
    fn an_item_opened_without_its_place_takes_the_one_it_is_later_named_by() {
        let ev = |name: &str, data: serde_json::Value| SseEvent { event_type: Some(name.into()), data: data.to_string(), id: None };
        let mut parser = StreamParser::new(ApiVersion::Responses);
        let mut events = Vec::new();
        for frame in [
            ev("response.output_item.added", serde_json::json!({
                "item": {"id": "fc_0", "type": "function_call", "call_id": "call_0", "name": "bash", "arguments": ""}})),
            ev("response.output_item.added", serde_json::json!({"output_index": 1,
                "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "read", "arguments": ""}})),
            ev("response.function_call_arguments.delta", serde_json::json!({"output_index": 0, "item_id": "fc_0", "delta": "a"})),
            ev("response.function_call_arguments.delta", serde_json::json!({"output_index": 0, "delta": "b"})),
            ev("response.function_call_arguments.delta", serde_json::json!({"item_id": "fc_0", "delta": "c"})),
            ev("response.function_call_arguments.delta", serde_json::json!({"output_index": 1, "delta": "d"})),
            ev("response.function_call_arguments.delta", serde_json::json!({"output_index": 1, "item_id": "fc_0", "delta": "e"})),
        ] {
            events.extend(parser.parse(&frame));
        }
        let placed: Vec<(usize, &str)> = events
            .iter()
            .filter_map(|e| match e {
                DomainEvent::ToolCallDelta { index, arguments_delta, .. } if !arguments_delta.is_empty() => Some((*index, arguments_delta.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(placed, [(0, "a"), (0, "b"), (0, "c"), (1, "d"), (DomainEvent::NO_CALL, "e")]);
    }

    /// A Responses call event naming no item this response opened — no
    /// address, an unknown id, or an index and an id of two different items —
    /// is no call's: its bytes are withheld, never given to the item opened
    /// last.
    #[test]
    fn a_responses_delta_naming_no_item_is_no_calls() {
        let ev = |name: &str, data: serde_json::Value| SseEvent { event_type: Some(name.into()), data: data.to_string(), id: None };
        let mut parser = StreamParser::new(ApiVersion::Responses);
        for (index, id) in [(0, "fc_0"), (1, "fc_1")] {
            parser.parse(&ev("response.output_item.added", serde_json::json!({"output_index": index,
                "item": {"id": id, "type": "function_call", "call_id": format!("call_{index}"), "name": "bash", "arguments": ""}})));
        }
        for delta in [
            serde_json::json!({"delta": "a"}),
            serde_json::json!({"item_id": "fc_9", "delta": "b"}),
            serde_json::json!({"item_id": "fc_0", "output_index": 1, "delta": "c"}),
            serde_json::json!({"item_id": "fc_9", "output_index": 1, "delta": "d"}),
        ] {
            let events = parser.parse(&ev("response.function_call_arguments.delta", delta.clone()));
            assert!(
                matches!(events.as_slice(), [DomainEvent::ToolCallDelta { index: DomainEvent::NO_CALL, .. }]),
                "{delta} → {events:?}"
            );
        }
    }

    #[test]
    fn test_parse_responses_mcp_call_arguments_done_no_doubling() {
        // done event is a no-op to avoid phantom tool blocks
        let event = SseEvent {
            event_type: Some("response.mcp_call_arguments.done".to_string()),
            data: r#"{"item_id":"mcp_abc","name":"webfetch","arguments":"{\"url\":\"https://example.com\"}"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "done event must be no-op to avoid phantom tool blocks");
    }

    #[test]
    fn test_parse_responses_function_call_arguments_done_no_doubling() {
        // done event is a no-op to avoid phantom tool blocks
        let event = SseEvent {
            event_type: Some("response.function_call_arguments.done".to_string()),
            data: r#"{"call_id":"fc_123","name":"bash","arguments":"{\"command\":\"ls\"}"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "done event must be no-op to avoid phantom tool blocks");
    }

    #[test]
    fn test_parse_responses_mcp_call_done_uses_item_id() {
        // MCP done events are now no-ops (same as function_call done)
        let event = SseEvent {
            event_type: Some("response.mcp_call_arguments.done".to_string()),
            data: r#"{"item_id":"mcp_999","arguments":"{}"}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "done event must be no-op to avoid phantom tool blocks");
    }

    #[test]
    fn test_parse_responses_image_generation_output_item_added() {
        let event = SseEvent {
            event_type: Some("response.output_item.added".to_string()),
            data: r#"{"type":"response.output_item.added","output_index":1,"item":{"type":"image_generation_call","id":"ig_abc","status":"in_progress"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ImageGeneration { index, result_base64 } => {
                assert_eq!(*index, 0);
                assert!(result_base64.is_none());
            }
            other => panic!("expected ImageGeneration, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_image_generation_done() {
        let event = SseEvent {
            event_type: Some("response.output_item.done".to_string()),
            data: r#"{"type":"response.output_item.done","output_index":1,"item":{"type":"image_generation_call","id":"ig_abc","result":"iVBORw0KGgo=","status":"completed"}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert_eq!(result.len(), 1);
        match &result[0] {
            DomainEvent::ImageGeneration { index, result_base64 } => {
                assert_eq!(*index, 0);
                assert_eq!(result_base64.as_deref(), Some("iVBORw0KGgo="));
            }
            other => panic!("expected ImageGeneration, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_responses_image_generation_partial_image_noop() {
        let event = SseEvent {
            event_type: Some("response.image_generation_call.partial_image".to_string()),
            data: r#"{"type":"response.image_generation_call.partial_image","partial_image":"chunk..."}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "partial_image should produce no domain events");
    }

    #[test]
    fn test_parse_responses_output_item_done_non_image_ignored() {
        let event = SseEvent {
            event_type: Some("response.output_item.done".to_string()),
            data: r#"{"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_1","status":"completed","role":"assistant","content":[]}}"#.to_string(),
            id: None,
        };
        let result = parse_domain_event(&event, ApiVersion::Responses);
        assert!(result.is_empty(), "non-image_generation output_item.done should be no-op");
    }
}
