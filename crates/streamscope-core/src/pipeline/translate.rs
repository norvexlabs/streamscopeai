//! Protocol translation between Anthropic Messages API / OpenAI Responses API
//! and OpenAI Chat Completions.

use chrono::Utc;
use serde_json::Value;

use crate::api::domain::{CallArguments, DomainEvent, FinishReason};

// Request translation lives on `DomainRequest` in `api/domain_request.rs`;
// this module owns response translation (DomainEvent → wire SSE).

/// Prompt-cache token counts, normalized across upstream protocols so the
/// client-facing `usage` carries cache visibility regardless of the
/// inbound×upstream protocol pair.
///
/// `read` = cache *hits* (discounted ~0.1× input). `creation` = cache *writes*
/// (premium ~1.25× input) — only Anthropic reports a write metric; OpenAI
/// (Chat/Responses) and Gemini expose hits only.
///
/// **Invariant:** the single-field client protocols (Chat Completions,
/// Responses, Gemini) express only cache *hits*, so emitting into them surfaces
/// `read` ONLY. A creation is a miss that was written — a premium-billed token,
/// not a discounted hit — and must never be reported as a cached token.
#[derive(Default, Clone, Copy)]
struct CacheUsage {
    read: u64,
    creation: u64,
}

impl CacheUsage {
    /// OpenAI Chat Completions (`prompt_tokens_details`) / Responses
    /// (`input_tokens_details`) usage object: `<details_key>.cached_tokens`.
    fn from_openai(usage: Option<&Value>, details_key: &str) -> Self {
        let read = usage
            .and_then(|u| u.get(details_key))
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Self { read, creation: 0 }
    }

    /// Anthropic usage object: split `cache_read_input_tokens` /
    /// `cache_creation_input_tokens`.
    fn from_anthropic(usage: Option<&Value>) -> Self {
        let g = |k: &str| usage.and_then(|u| u.get(k)).and_then(|v| v.as_u64()).unwrap_or(0);
        Self {
            read: g("cache_read_input_tokens"),
            creation: g("cache_creation_input_tokens"),
        }
    }

    /// Gemini response: `usageMetadata.cachedContentTokenCount` (hits only).
    fn from_gemini(response_json: &Value) -> Self {
        let read = response_json
            .get("usageMetadata")
            .and_then(|u| u.get("cachedContentTokenCount"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Self { read, creation: 0 }
    }

    /// Domain `Usage` (streaming builders operate on the normalized domain type).
    fn from_parts(read: Option<u32>, creation: Option<u32>) -> Self {
        Self {
            read: read.unwrap_or(0) as u64,
            creation: creation.unwrap_or(0) as u64,
        }
    }

    /// Scale cache counts the same way prompt tokens are scaled for a
    /// context-window mismatch (the read count is part of the prompt).
    fn scaled(self, scale: impl Fn(u64) -> u64) -> Self {
        Self {
            read: scale(self.read),
            creation: scale(self.creation),
        }
    }

    /// Total cached tokens (read + creation), part of the prompt.
    fn total(self) -> u64 {
        self.read + self.creation
    }

    /// OpenAI/Gemini report a prompt total that *includes* cached tokens; the
    /// Anthropic wire reports `input_tokens` *disjoint* from the cache fields.
    /// Convert an inclusive prompt count to the Anthropic-exclusive form.
    fn exclusive_prompt(self, inclusive: u64) -> u64 {
        inclusive.saturating_sub(self.total())
    }

    /// Inverse of `exclusive_prompt`: Anthropic reports an exclusive
    /// `input_tokens`; OpenAI/Gemini/Responses expect a prompt total that
    /// includes the cached subset.
    fn inclusive_prompt(self, exclusive: u64) -> u64 {
        exclusive + self.total()
    }

    /// Anthropic client target: both read and creation.
    fn apply_anthropic(self, usage_json: &mut Value) {
        usage_json["cache_read_input_tokens"] = serde_json::json!(self.read);
        usage_json["cache_creation_input_tokens"] = serde_json::json!(self.creation);
    }

    /// Chat Completions client target: `prompt_tokens_details.cached_tokens` (read only).
    fn apply_chat(self, usage_json: &mut Value) {
        if self.read > 0 {
            usage_json["prompt_tokens_details"] = serde_json::json!({"cached_tokens": self.read});
        }
    }

    /// Responses client target: `input_tokens_details.cached_tokens` (read only).
    fn apply_responses(self, usage_json: &mut Value) {
        if self.read > 0 {
            usage_json["input_tokens_details"] = serde_json::json!({"cached_tokens": self.read});
        }
    }

    /// Gemini client target: `usageMetadata.cachedContentTokenCount` (read only).
    fn apply_gemini(self, usage_metadata: &mut Value) {
        if self.read > 0 {
            usage_metadata["cachedContentTokenCount"] = serde_json::json!(self.read);
        }
    }
}

// ─── Part B: Streaming Response Translation (OpenAI → Anthropic SSE) ───

/// State machine that converts DomainEvents into Anthropic SSE events.
/// State machine for detecting `<think>...</think>` tags streamed across
/// multiple TextDelta events.
#[derive(Debug, Clone, PartialEq)]
enum ThinkTagState {
    /// Haven't seen any think tag yet. Buffer initial text in case it starts with `<think>`.
    Init,
    /// Inside a `<think>` block — content goes to thinking block.
    InsideThink,
    /// Saw `</think>` — all subsequent content is normal text.
    AfterThink,
    /// No think tags detected (first content was not `<think>`).
    NoThinkTags,
}

/// The call an Anthropic `tool_use` block carries.
struct ToolBlock {
    /// The call's number on the stream.
    call: usize,
    input: ToolInput,
    /// Whether the block has started on the client. Anthropic states a
    /// call's id and name on its block's start, and a later delta cannot add
    /// either, so the block of a call not yet both identified and named waits:
    /// its id, name and input are held here, and it starts once the call has
    /// both — or, when it must close first, with an id minted for it and the
    /// name it has, so nothing is dropped.
    started: bool,
    id: Option<String>,
    name: Option<String>,
    held: String,
}

/// Where the input of the call an Anthropic `tool_use` block carries stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolInput {
    /// Arguments the stream closes itself — a function call's JSON, or a
    /// custom call written whole.
    Whole,
    /// A streamed custom call's text, open until the call's end.
    FreeformOpen,
    /// A streamed custom call whose end closed its input: nothing is written
    /// into it after.
    FreeformEnded,
}

pub struct AnthropicResponseBuilder {
    model: String,
    request_id: String,
    /// Set once `message_stop` is written — see [`Self::terminal_sent`].
    terminal_sent: bool,
    content_index: usize,
    has_thinking_block: bool,
    has_text_block: bool,
    has_tool_block: bool,
    /// The call the open `tool_use` block carries.
    tool_block_call: Option<ToolBlock>,
    /// The calls whose block was written and closed — or, never named, told
    /// in its place: Anthropic's blocks are sequential, so a later piece of
    /// one cannot reach it.
    closed_tool_calls: std::collections::HashSet<usize>,
    /// Whether a `tool_use` block was written — what the stop claims.
    gave_calls: bool,
    /// The calls whose bytes were withheld — later arguments after the call's
    /// block closed or after its end, told once per call in a text block after
    /// the calls (`write_withheld_notices`); or a call never named, told in its
    /// place — the audit reads them through [`Self::take_withheld_calls`].
    withheld: crate::pipeline::response::WithheldCalls,
    /// The ids minted for calls written before the upstream identified them.
    minted: crate::pipeline::response::MintedIds,
    message_started: bool,
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: Option<u32>,
    cache_read_input_tokens: Option<u32>,
    /// Upstream model's context window size (tokens).
    context_window: Option<i32>,
    /// Scaling factor for reported tokens: client_context_window / upstream_context_window.
    /// When >1.0, inflates reported tokens so clients (e.g. Claude Code) trigger compaction
    /// at the correct time relative to the upstream's actual context limit.
    token_scale: f64,
    /// The finish from the Done event — the message's end is deferred until
    /// Usage arrives (OpenAI sends Usage AFTER finish_reason in streaming),
    /// and its stop word is settled then, over every call written by then.
    pending_stop_reason: Option<Option<FinishReason>>,
    /// Buffer for detecting `<think>` tags embedded in TextDelta content stream.
    /// Some models (e.g. DeepSeek via vLLM) send thinking inside the content
    /// field with `<think>...</think>` tags rather than a dedicated `reasoning` field.
    think_tag_state: ThinkTagState,
}

impl AnthropicResponseBuilder {
    pub fn new(
        model: String,
        request_id: String,
        context_window: Option<i32>,
        client_context_window: Option<i32>,
        estimated_input_tokens: u32,
        max_output_tokens: u32,
    ) -> Self {
        // Compute scaling factor: if the client's expected context window is larger
        // than the upstream, inflate reported tokens proportionally so the client
        // triggers compaction at the right time.
        // Scale against the *effective* upstream input limit (context_window - max_output_tokens)
        // so clients auto-compact before hitting the real limit.
        let token_scale = match (client_context_window, context_window) {
            (Some(client_cw), Some(upstream_cw)) if upstream_cw > 0 && client_cw > upstream_cw => {
                let effective_upstream = (upstream_cw - max_output_tokens as i32).max(1);
                let scale = client_cw as f64 / effective_upstream as f64;
                tracing::debug!(
                    client_cw,
                    upstream_cw,
                    max_output_tokens,
                    effective_upstream,
                    token_scale = format!("{scale:.2}"),
                    "token scaling active"
                );
                scale
            }
            _ => 1.0,
        };
        Self {
            model,
            request_id,
            terminal_sent: false,
            content_index: 0,
            has_thinking_block: false,
            has_text_block: false,
            has_tool_block: false,
            tool_block_call: None,
            closed_tool_calls: std::collections::HashSet::new(),
            gave_calls: false,
            withheld: crate::pipeline::response::WithheldCalls::default(),
            minted: crate::pipeline::response::MintedIds::default(),
            message_started: false,
            input_tokens: estimated_input_tokens,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            context_window: client_context_window.or(context_window),
            token_scale,
            pending_stop_reason: None,
            think_tag_state: ThinkTagState::Init,
        }
    }

    /// Process a domain event and produce zero or more Anthropic SSE event strings.
    pub fn process_event(&mut self, event: &DomainEvent) -> Vec<String> {
        let mut sse_events = Vec::new();
        // Nothing follows the stream's end — the message's, or an error's (a
        // Responses `response.failed` parses to the error and then a finish).
        if self.terminal_sent {
            return sse_events;
        }

        // Emit message_start on first meaningful event
        if !self.message_started {
            self.message_started = true;
            let mut message = serde_json::json!({
                "id": format!("msg_{}", crate::ids::client_id(&self.request_id)),
                "type": "message",
                "role": "assistant",
                "model": self.model,
                "content": [],
                "stop_reason": null,
                "stop_sequence": null,
                "usage": {
                    "input_tokens": self.scale_tokens(self.input_tokens),
                    "output_tokens": 0,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0
                }
            });
            if let Some(cw) = self.context_window {
                message["model_info"] = serde_json::json!({"context_window": cw});
            }
            sse_events.push(self.format_sse_event(
                "message_start",
                &serde_json::json!({
                    "type": "message_start",
                    "message": message
                }),
            ));
        }

        match event {
            // A freeform call's end is the closing piece of its input, written
            // to the call's block while it is open. A block closed before the
            // end came (another call started first) had its input closed then.
            DomainEvent::FreeformCallEnd { index } => {
                if let Some(block) = &mut self.tool_block_call
                    && block.call == *index
                    && block.input == ToolInput::FreeformOpen
                {
                    block.input = ToolInput::FreeformEnded;
                    block.held.push_str(crate::api::domain_request::FREEFORM_ARGS_CLOSE);
                    self.write_held_input(&mut sse_events);
                }
            }
            DomainEvent::TextDelta(text) => {
                self.process_text_delta(text, &mut sse_events);
            }
            DomainEvent::ReasoningDelta(text) => {
                // Dedicated reasoning field from upstream (e.g. OpenAI reasoning models).
                // Emit as Anthropic thinking content block.
                self.emit_thinking_delta(text, &mut sse_events);
            }
            DomainEvent::ToolCallDelta {
                index,
                id,
                function_name,
                arguments_delta,
                form,
            } => {
                // One block per call: a call is its number on the stream, so a
                // server restating the name or the id on every delta writes one
                // block. A later piece of a call whose block is closed cannot
                // reach it — Anthropic's blocks are sequential.
                // A server tool's input is no client's call.
                if *form == CallArguments::ServerTool && *index != DomainEvent::NO_CALL {
                    return sse_events;
                }
                // A built-in tool's call is a Responses client's to run: this
                // one is told, after the calls, that it was not carried.
                if let CallArguments::ClientBuiltin(builtin) = form
                    && *index != DomainEvent::NO_CALL
                {
                    if self.withheld.not_carried(*index, *builtin) {
                        tracing::warn!(index, tool = builtin.tool_name(), "a built-in tool call cannot reach this client; not carried");
                    }
                    return sse_events;
                }
                // Nothing is written into a call after its block closed, after
                // a custom call's end, or for no call at all: its bytes are
                // withheld.
                let ended = self
                    .tool_block_call
                    .as_ref()
                    .is_some_and(|b| b.call == *index && b.input == ToolInput::FreeformEnded);
                if self.closed_tool_calls.contains(index) || ended || event.is_withheld_piece() {
                    if self.withheld.withhold(*index, arguments_delta) {
                        tracing::warn!(index, "tool-call arguments arrived after the call ended; withheld");
                    }
                    return sse_events;
                }
                if self.tool_block_call.as_ref().is_none_or(|b| b.call != *index) {
                    // Close text/thinking block if open
                    self.close_current_block(&mut sse_events);
                    self.tool_block_call = Some(ToolBlock {
                        call: *index,
                        input: ToolInput::Whole,
                        started: false,
                        id: None,
                        name: None,
                        held: String::new(),
                    });
                }
                if let Some(block) = &mut self.tool_block_call {
                    // A streamed custom call's input is open until its end —
                    // whatever its opening delta, which may name the call alone.
                    if block.input == ToolInput::Whole && *form == CallArguments::FreeformPiece {
                        block.input = ToolInput::FreeformOpen;
                    }
                    if block.id.is_none() {
                        block.id.clone_from(id);
                    }
                    // An empty name names nothing — on every source, a script's
                    // rebuild of a nameless call included.
                    if block.name.is_none() {
                        block.name = function_name.clone().filter(|n| !n.is_empty());
                    }
                    block.held.push_str(arguments_delta);
                }
                self.start_tool_block(false, &mut sse_events);
                self.write_held_input(&mut sse_events);
            }
            DomainEvent::Usage(usage) => {
                if usage.prompt_tokens > 0 {
                    self.input_tokens = usage.prompt_tokens;
                }
                if usage.completion_tokens > 0 {
                    self.output_tokens = usage.completion_tokens;
                }
                self.cache_creation_input_tokens = usage.cache_creation_tokens.or(self.cache_creation_input_tokens);
                self.cache_read_input_tokens = usage.cache_read_tokens.or(self.cache_read_input_tokens);
                // If Done was already received and deferred, emit message_delta now
                // (OpenAI sends Usage AFTER finish_reason in streaming).
                if let Some(finish) = self.pending_stop_reason.take() {
                    self.emit_message_end(finish, &mut sse_events);
                }
            }
            DomainEvent::Done {
                finish_reason,
                ..
            } => {
                // Close any open content block
                self.close_current_block(&mut sse_events);
                self.write_withheld_notices(&mut sse_events);

                // Defer message_delta/message_stop — Usage may arrive next.
                self.pending_stop_reason = Some(finish_reason.clone());
            }
            // An error ends the client's stream: nothing is written after it
            // (no close of a message the upstream failed).
            DomainEvent::Error { message, code } => {
                tracing::warn!(error_message = %message, error_code = ?code, "upstream error during stream");
                self.terminal_sent = true;
                sse_events.push(format!(
                    "event: error\ndata: {}\n\n",
                    serde_json::json!({
                        "type": "error",
                        "error": {
                            "type": crate::error::envelope::anthropic_stream_error_type(code.as_deref()),
                            "message": message
                        }
                    })
                ));
            }
            // ImageGeneration is Responses-API-only; no Anthropic equivalent.
            DomainEvent::ImageGeneration { .. } => {}
            DomainEvent::ServerToolCallDelta {
                tool_use_id,
                name,
                input_delta,
                ..
            } => {
                self.emit_server_tool_use(tool_use_id, name, input_delta, &mut sse_events);
            }
            DomainEvent::ServerToolResult {
                tool_use_id,
                content,
                ..
            } => {
                self.emit_web_search_tool_result(tool_use_id, content, &mut sse_events);
            }
            DomainEvent::ServerToolError {
                tool_use_id,
                error_kind,
                ..
            } => {
                self.emit_web_search_tool_result_error(
                    tool_use_id,
                    error_kind,
                    &mut sse_events,
                );
            }
        }

        sse_events
    }

    /// Synthesise an Anthropic `server_tool_use` content block from a
    /// `DomainEvent::ServerToolCallDelta`. The substitution agent loop emits
    /// these events between rounds when an enabled `WS-SUB-*` server-tool
    /// rule fired; this method re-renders them as the wire shape the client
    /// originally asked for so server-tool emulation is byte-faithful.
    ///
    /// One-shot: start + arg-delta + stop in a single call (the agent loop
    /// has the full args at dispatch time, so streaming the deltas serves
    /// no purpose). `close_current_block` increments `content_index` so the
    /// follow-up `web_search_tool_result` block lands at the next index.
    /// `tool_use_id` is the agent loop's stable identifier — projected to
    /// `server_tool_use.id` here and to `web_search_tool_result.tool_use_id`
    /// on the result block, so conformant clients can pair them.
    fn emit_server_tool_use(
        &mut self,
        tool_use_id: &str,
        name: &str,
        input_delta: &str,
        sse_events: &mut Vec<String>,
    ) {
        self.close_current_block(sse_events);
        sse_events.push(self.format_sse_event(
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": self.content_index,
                "content_block": {
                    "type": "server_tool_use",
                    "id": tool_use_id,
                    "name": name,
                    "input": {}
                }
            }),
        ));
        if !input_delta.is_empty() {
            sse_events.push(self.format_sse_event(
                "content_block_delta",
                &serde_json::json!({
                    "type": "content_block_delta",
                    "index": self.content_index,
                    "delta": {
                        "type": "input_json_delta",
                        "partial_json": input_delta
                    }
                }),
            ));
        }
        // Mark as a tool block so close_current_block emits content_block_stop
        // and bumps content_index for the result block.
        self.has_tool_block = true;
        self.close_current_block(sse_events);
    }

    /// Synthesise an Anthropic `web_search_tool_result` content block.
    /// Detects the dispatched payload shape and projects to the protocol
    /// native form: `SearchResult` (with `hits`) maps to a `web_search_result`
    /// array; `FetchResult` (with `extracted_text`) is folded into a single
    /// document; opaque payloads pass through as a stringified text result
    /// so nothing is silently dropped.
    fn emit_web_search_tool_result(
        &mut self,
        tool_use_id: &str,
        content: &Value,
        sse_events: &mut Vec<String>,
    ) {
        self.close_current_block(sse_events);
        let result_content = anthropic_search_result_content(content);
        sse_events.push(self.format_sse_event(
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": self.content_index,
                "content_block": {
                    "type": "web_search_tool_result",
                    "tool_use_id": tool_use_id,
                    "content": result_content
                }
            }),
        ));
        self.has_tool_block = true;
        self.close_current_block(sse_events);
    }

    /// Synthesise the error variant of `web_search_tool_result` — Anthropic
    /// nests the failure inline rather than emitting a separate error event.
    fn emit_web_search_tool_result_error(
        &mut self,
        tool_use_id: &str,
        error_kind: &str,
        sse_events: &mut Vec<String>,
    ) {
        self.close_current_block(sse_events);
        sse_events.push(self.format_sse_event(
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": self.content_index,
                "content_block": {
                    "type": "web_search_tool_result",
                    "tool_use_id": tool_use_id,
                    "content": {
                        "type": "web_search_tool_result_error",
                        "error_code": anthropic_web_search_error_code(error_kind)
                    }
                }
            }),
        ));
        self.has_tool_block = true;
        self.close_current_block(sse_events);
    }

    /// Scale a token count by the client/upstream context window ratio.
    fn scale_tokens(&self, tokens: u32) -> u32 {
        if self.token_scale > 1.0 {
            (tokens as f64 * self.token_scale).round() as u32
        } else {
            tokens
        }
    }

    /// Whether the client has been handed the stream's end (`message_stop`).
    pub fn terminal_sent(&self) -> bool {
        self.terminal_sent
    }

    /// Emit the final message_delta + message_stop events, the stop word
    /// settled from `finish` over every call the client was given.
    fn emit_message_end(&mut self, finish: Option<FinishReason>, sse_events: &mut Vec<String>) {
        // Content after the finish (a lax server's, while the message's end
        // waited for its usage) opened a block: it stops before the message
        // does. Arguments withheld meanwhile are said too.
        self.close_current_block(sse_events);
        self.write_withheld_notices(sse_events);
        self.terminal_sent = true;
        // Every call is retired now: the stop claims what the client holds.
        let stop_reason = finish
            .map(|r| settle_withheld(&r, self.gave_calls, &self.withheld))
            .map(|r| anthropic_stop_for(Some(&r), self.gave_calls));
        // Domain Usage stores prompt_tokens as inclusive of cache. Anthropic wire format
        // reports input_tokens as the non-cached portion (disjoint from cache_*_input_tokens),
        // so subtract the cache fields back out.
        let cache_creation = self.cache_creation_input_tokens.unwrap_or(0);
        let cache_read = self.cache_read_input_tokens.unwrap_or(0);
        let exclusive_input = self.input_tokens.saturating_sub(cache_creation + cache_read);
        let scaled_input = self.scale_tokens(exclusive_input);
        let scaled_output = self.scale_tokens(self.output_tokens);
        if self.token_scale > 1.0 {
            tracing::info!(
                raw_input = exclusive_input,
                raw_output = self.output_tokens,
                scaled_input,
                scaled_output,
                token_scale = format!("{:.2}", self.token_scale),
                "token scaling applied — client sees scaled values"
            );
        }
        sse_events.push(self.format_sse_event(
            "message_delta",
            &serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": stop_reason},
                "usage": {
                    "input_tokens": scaled_input,
                    "output_tokens": scaled_output,
                    "cache_creation_input_tokens": self.cache_creation_input_tokens.map(|t| self.scale_tokens(t)).unwrap_or(0),
                    "cache_read_input_tokens": self.cache_read_input_tokens.map(|t| self.scale_tokens(t)).unwrap_or(0)
                }
            }),
        ));
        sse_events.push(self.format_sse_event(
            "message_stop",
            &serde_json::json!({"type": "message_stop"}),
        ));
    }

    /// Flush any deferred Done event (call at stream end in case no Usage followed Done).
    pub fn flush_pending(&mut self) -> Vec<String> {
        let mut sse_events = Vec::new();
        if self.terminal_sent {
            return sse_events;
        }
        if let Some(finish) = self.pending_stop_reason.take() {
            self.emit_message_end(finish, &mut sse_events);
        }
        sse_events
    }

    /// Force a clean Anthropic close when the upstream stream was truncated
    /// mid-generation (e.g. vLLM hit `max_model_len` / `max_tokens` and closed
    /// the HTTP connection without emitting the final usage chunk + `[DONE]`).
    ///
    /// The emitter has already forwarded `message_start` and possibly many
    /// content_block deltas to the client. Without this synthesized close the
    /// client sees an unterminated stream (or our zero-token guard's
    /// `overloaded_error`, which triggers a pointless retry of a doomed
    /// request). Here we emit, in order:
    ///   1. `content_block_stop` for any currently-open block (so the client's
    ///      block state machine resolves).
    ///   2. `message_delta` with `stop_reason: "max_tokens"` and whatever usage
    ///      we did observe.
    ///   3. `message_stop`.
    ///
    /// A message that already ended is not ended twice: this writes nothing.
    ///
    /// `max_tokens` — the truncation, in Anthropic's words through
    /// [`anthropic_stop_reason`] — is the Messages API's signal to callers to
    /// treat the response as incomplete; Claude Code and the Anthropic SDKs
    /// honor it by refusing to act on truncated `tool_use.input` JSON.
    pub fn force_close_truncated(&mut self) -> Vec<String> {
        let mut sse_events = Vec::new();
        // If we never emitted message_start, the client never saw any events.
        // A clean close in that case would be malformed (message_delta with no
        // message_start). Let the zero-token guard handle that case separately.
        if !self.message_started || self.terminal_sent {
            return sse_events;
        }
        // Any pending finish from a Done event that arrived without Usage
        // is still authoritative — prefer it over the synthetic truncation.
        let finish = self.pending_stop_reason.take().flatten().unwrap_or(FinishReason::Length);
        self.close_current_block(&mut sse_events);
        self.write_withheld_notices(&mut sse_events);
        self.emit_message_end(Some(finish), &mut sse_events);
        sse_events
    }

    /// The calls whose bytes were withheld, not yet taken — for the audit
    /// row, which says why: arguments cut short, a built-in tool not carried,
    /// or a call never named.
    pub fn take_withheld_calls(&mut self) -> Vec<(usize, crate::pipeline::response::Withheld)> {
        self.withheld.take_unreported()
    }

    /// Whether the client has been sent the message's start.
    pub fn message_started(&self) -> bool {
        self.message_started
    }

    /// The ids minted for calls written before the upstream identified them,
    /// not yet taken — for the audit row, which says which id the client got.
    pub fn take_minted_ids(&mut self) -> Vec<(usize, String)> {
        self.minted.take()
    }

    /// Tell the client, once per call, that arguments of a call arrived after
    /// its block closed and were withheld — a text block after the calls.
    fn write_withheld_notices(&mut self, sse_events: &mut Vec<String>) {
        let untold = self.withheld.untold();
        if untold.is_empty() {
            return;
        }
        for notice in untold {
            self.emit_text_delta(notice, sse_events);
        }
        self.close_current_block(sse_events);
    }

    /// Start the held `tool_use` block under `name`, if it has not started.
    fn start_tool_block(&mut self, force: bool, sse_events: &mut Vec<String>) {
        let Some(block) = self
            .tool_block_call
            .as_mut()
            .filter(|b| !b.started && (force || (b.id.is_some() && b.name.is_some())))
        else {
            return;
        };
        // A block starts only under its call's name (see `close_current_block`).
        let Some(name) = block.name.clone() else {
            return;
        };
        block.started = true;
        let (call, id) = (block.call, block.id.clone());
        // An id the upstream has not sent is minted, and the audit row says so.
        let id = id.unwrap_or_else(|| self.minted.mint(call, format!("toolu_{}_{call}", self.request_id)));
        self.has_tool_block = true;
        self.gave_calls = true;
        let start = self.format_sse_event(
            "content_block_start",
            &serde_json::json!({
                "type": "content_block_start",
                "index": self.content_index,
                "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
            }),
        );
        sse_events.push(start);
    }

    /// Write the input held for the started `tool_use` block.
    fn write_held_input(&mut self, sse_events: &mut Vec<String>) {
        let Some(block) = self.tool_block_call.as_mut().filter(|b| b.started && !b.held.is_empty()) else {
            return;
        };
        let held = std::mem::take(&mut block.held);
        let delta = self.input_json_delta(&held);
        sse_events.push(delta);
    }

    /// Emit a thinking delta — opens a thinking content block if needed.
    fn emit_thinking_delta(&mut self, text: &str, sse_events: &mut Vec<String>) {
        // Blocks are sequential: a call's or a text's block closes before a
        // thinking block starts at the next index.
        if self.has_text_block || self.has_tool_block || self.tool_block_call.is_some() {
            self.close_current_block(sse_events);
        }
        if !self.has_thinking_block {
            self.has_thinking_block = true;
            sse_events.push(self.format_sse_event(
                "content_block_start",
                &serde_json::json!({
                    "type": "content_block_start",
                    "index": self.content_index,
                    "content_block": {"type": "thinking", "thinking": ""}
                }),
            ));
        }
        sse_events.push(self.format_sse_event(
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": self.content_index,
                "delta": {"type": "thinking_delta", "thinking": text}
            }),
        ));
    }

    /// Emit a text delta — opens a text content block if needed.
    fn emit_text_delta(&mut self, text: &str, sse_events: &mut Vec<String>) {
        // Blocks are sequential: a call's block closes before a text block
        // starts at the next index.
        if self.has_tool_block || self.tool_block_call.is_some() {
            self.close_current_block(sse_events);
        }
        if !self.has_text_block {
            // Close thinking block first if transitioning
            if self.has_thinking_block {
                // Synthesize a signature_delta — Claude Code expects a signature
                // to close thinking blocks. Use a timestamp-based placeholder since
                // non-Anthropic upstreams don't provide real signatures.
                let sig = synthetic_thinking_signature();
                sse_events.push(self.format_sse_event(
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": self.content_index,
                        "delta": {"type": "signature_delta", "signature": sig}
                    }),
                ));
                sse_events.push(self.format_sse_event(
                    "content_block_stop",
                    &serde_json::json!({
                        "type": "content_block_stop",
                        "index": self.content_index
                    }),
                ));
                self.content_index += 1;
                self.has_thinking_block = false;
            }
            self.has_text_block = true;
            sse_events.push(self.format_sse_event(
                "content_block_start",
                &serde_json::json!({
                    "type": "content_block_start",
                    "index": self.content_index,
                    "content_block": {"type": "text", "text": ""}
                }),
            ));
        }
        if !text.is_empty() {
            sse_events.push(self.format_sse_event(
                "content_block_delta",
                &serde_json::json!({
                    "type": "content_block_delta",
                    "index": self.content_index,
                    "delta": {"type": "text_delta", "text": text}
                }),
            ));
        }
    }

    /// Process a TextDelta — handles `<think>...</think>` tags embedded in content.
    ///
    /// Some models (DeepSeek via vLLM, Ollama) embed thinking inside the content
    /// stream with `<think>...</think>` tags. This method detects those tags and
    /// routes content to thinking vs text blocks accordingly.
    fn process_text_delta(&mut self, text: &str, sse_events: &mut Vec<String>) {
        match self.think_tag_state {
            ThinkTagState::Init => {
                // Check if the content starts with <think>
                // Models often send "<think>" as one of the first deltas
                if let Some(rest) = text.strip_prefix("<think>") {
                    self.think_tag_state = ThinkTagState::InsideThink;
                    if !rest.is_empty() {
                        // Recurse to process the rest (might contain </think>)
                        self.process_text_delta(rest, sse_events);
                    }
                } else if text.trim().is_empty() {
                    // Whitespace-only deltas before content — stay in Init
                } else {
                    // Not a think tag — treat as normal text
                    self.think_tag_state = ThinkTagState::NoThinkTags;
                    self.emit_text_delta(text, sse_events);
                }
            }
            ThinkTagState::InsideThink => {
                // Look for </think> in this delta
                if let Some(pos) = text.find("</think>") {
                    let thinking_part = &text[..pos];
                    let after_part = &text[pos + "</think>".len()..];
                    if !thinking_part.is_empty() {
                        self.emit_thinking_delta(thinking_part, sse_events);
                    }
                    self.think_tag_state = ThinkTagState::AfterThink;
                    if !after_part.is_empty() {
                        let trimmed = after_part.trim_start_matches('\n');
                        if !trimmed.is_empty() {
                            self.emit_text_delta(trimmed, sse_events);
                        }
                    }
                } else {
                    // Still inside think block
                    self.emit_thinking_delta(text, sse_events);
                }
            }
            ThinkTagState::AfterThink => {
                // All content after </think> is normal text
                self.emit_text_delta(text, sse_events);
            }
            ThinkTagState::NoThinkTags => {
                // No think tags detected — pass through as text
                self.emit_text_delta(text, sse_events);
            }
        }
    }

    /// Close the currently open content block (thinking, text, or tool_use).
    fn close_current_block(&mut self, sse_events: &mut Vec<String>) {
        // A freeform call closed before its end (another call started first)
        // is closed as the text it had: its input must be whole JSON. Only a
        // call its deltas name freeform is — a function call cut off inside
        // a string stays cut off.
        if let Some(block) = &mut self.tool_block_call
            && block.input == ToolInput::FreeformOpen
        {
            block.input = ToolInput::FreeformEnded;
            block.held.push_str(crate::api::domain_request::FREEFORM_ARGS_CLOSE);
        }
        // A call its deltas never named cannot reach the client: it is told
        // in the call's place, in a text block of its own.
        // (A block starts only under a name: `start_tool_block`.)
        let nameless = self.tool_block_call.as_ref().filter(|b| b.name.is_none()).map(|b| b.call);
        if nameless.is_none() && self.tool_block_call.is_some() {
            // A call its deltas never identified still reaches the client.
            self.start_tool_block(true, sse_events);
            self.write_held_input(sse_events);
        }
        if let Some(block) = self.tool_block_call.take() {
            self.closed_tool_calls.insert(block.call);
        }
        if let Some(call) = nameless
            && self.withheld.nameless(call)
        {
            tracing::warn!(index = call, "a tool call the stream never named cannot reach an Anthropic client; not carried");
            self.emit_text_delta(crate::pipeline::response::NAMELESS_CALL_NOTICE, sse_events);
        }
        if self.has_thinking_block || self.has_text_block || self.has_tool_block {
            // Synthesize signature_delta when closing a thinking block directly
            if self.has_thinking_block {
                let sig = synthetic_thinking_signature();
                sse_events.push(self.format_sse_event(
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": self.content_index,
                        "delta": {"type": "signature_delta", "signature": sig}
                    }),
                ));
            }
            sse_events.push(self.format_sse_event(
                "content_block_stop",
                &serde_json::json!({
                    "type": "content_block_stop",
                    "index": self.content_index
                }),
            ));
            self.content_index += 1;
            self.has_thinking_block = false;
            self.has_text_block = false;
            self.has_tool_block = false;
        }
    }

    fn format_sse_event(&self, event_type: &str, data: &Value) -> String {
        format!(
            "event: {event_type}\ndata: {}\n\n",
            serde_json::to_string(data).unwrap_or_default()
        )
    }

    /// A piece of the open `tool_use` block's input.
    fn input_json_delta(&self, partial_json: &str) -> String {
        self.format_sse_event(
            "content_block_delta",
            &serde_json::json!({
                "type": "content_block_delta",
                "index": self.content_index,
                "delta": {"type": "input_json_delta", "partial_json": partial_json}
            }),
        )
    }
}

// ─── Substitution result mappers (shared by streaming + non-streaming) ───
//
// `WebService::dispatch_intercept` returns a JSON-stringified
// `SearchResult` (`{hits, total_filtered, backend}`) or `FetchResult`
// (`{url, final_url, content_type, status, extracted_text, ...}`). The
// substitution agent loop wraps that into `DomainEvent::ServerToolResult`
// with `content: serde_json::Value`. These mappers project the typed
// payload to the wire shape each protocol's native server-tool emits.
//
// Pure functions, no per-builder state — reused by both the streaming
// renderers (`process_event` arms) and the non-streaming JSON splice in
// `pipeline::response_blocks`.

/// Map dispatched search/fetch result content to Anthropic's
/// `web_search_tool_result.content`. Search results become a typed array
/// of `web_search_result` blocks; fetch results fold into a single
/// document; opaque payloads pass through as `web_search_result` carrying
/// the raw text under `title` so the model still sees something — nothing
/// is silently discarded.
pub(crate) fn anthropic_search_result_content(content: &Value) -> Value {
    if let Some(hits) = content.get("hits").and_then(Value::as_array) {
        let mapped: Vec<Value> = hits
            .iter()
            .map(|h| {
                let mut block = serde_json::json!({
                    "type": "web_search_result",
                    "url": h.get("url").and_then(Value::as_str).unwrap_or(""),
                    "title": h.get("title").and_then(Value::as_str).unwrap_or(""),
                });
                if let Some(published) = h.get("published").and_then(Value::as_str) {
                    block["page_age"] = serde_json::json!(published);
                }
                block
            })
            .collect();
        return Value::Array(mapped);
    }
    if let Some(text) = content.get("extracted_text").and_then(Value::as_str) {
        let url = content
            .get("final_url")
            .and_then(Value::as_str)
            .or_else(|| content.get("url").and_then(Value::as_str))
            .unwrap_or("");
        return serde_json::json!([{
            "type": "web_search_result",
            "url": url,
            "title": url,
            "encrypted_content": text
        }]);
    }
    // Opaque — wrap so the block isn't structurally empty (nothing is
    // silently discarded). Stash the raw payload under
    // `encrypted_content` (Anthropic's slot for prefetched body) rather
    // than `title`, so UIs that render `web_search_result.title` don't
    // surface a JSON blob.
    serde_json::json!([{
        "type": "web_search_result",
        "url": "",
        "title": "opaque executor result",
        "encrypted_content": serde_json::to_string(content).unwrap_or_default(),
    }])
}

// ─── Part C: Non-streaming Response Translation (OpenAI → Anthropic) ───

/// Translate an OpenAI Chat Completions non-streaming response to Anthropic Messages format.
pub fn openai_response_to_anthropic(
    response_json: &Value,
    model: &str,
    request_id: &str,
    input_tokens: u32,
    context_window: Option<i32>,
    client_context_window: Option<i32>,
    max_output_tokens: u32,
) -> Value {
    let choice = response_json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|choices| choices.first());

    let mut content_blocks = Vec::new();

    if let Some(choice) = choice {
        let message = choice.get("message");

        // Extract reasoning/thinking content (dedicated field from reasoning models)
        if let Some(reasoning) = message.and_then(crate::api::chat::message_reasoning)
            && !reasoning.is_empty() {
                content_blocks.push(anthropic_thinking_block(&reasoning));
            }

        // Extract text content — the string, or every `text` chunk of a
        // chunk array.
        if let Some(text) = message.and_then(|m| crate::api::chat::content_text(m.get("content")))
            && !text.is_empty() {
                // Check for inline <think>...</think> tags
                if let Some(open) = text.find("<think>") {
                    if let Some(close) = text.rfind("</think>") {
                        let think_start = open + "<think>".len();
                        if close > think_start {
                            let thinking = text[think_start..close].trim();
                            if !thinking.is_empty() {
                                content_blocks.push(anthropic_thinking_block(thinking));
                            }
                            let before = text[..open].trim();
                            let after = text[close + "</think>".len()..].trim();
                            let clean = if before.is_empty() {
                                after.to_string()
                            } else {
                                format!("{before}\n{after}")
                            };
                            let clean = clean.trim().to_string();
                            if !clean.is_empty() {
                                content_blocks.push(serde_json::json!({
                                    "type": "text",
                                    "text": clean
                                }));
                            }
                        } else {
                            content_blocks.push(serde_json::json!({
                                "type": "text",
                                "text": text
                            }));
                        }
                    } else {
                        content_blocks.push(serde_json::json!({
                            "type": "text",
                            "text": text
                        }));
                    }
                } else {
                    content_blocks.push(serde_json::json!({
                        "type": "text",
                        "text": text
                    }));
                }
            }

        // Extract tool calls
        if let Some(tool_calls) = message
            .and_then(|m| m.get("tool_calls"))
            .and_then(|tc| tc.as_array())
        {
            // A custom (freeform) call arrives as a call carrying its text
            // as `{"input": …}` (`tool_call_item`).
            for call in tool_calls.iter().filter_map(crate::api::domain::tool_call_item) {
                let input: Value = serde_json::from_str(&call.arguments)
                    .unwrap_or(Value::Object(Default::default()));
                content_blocks.push(serde_json::json!({
                    "type": "tool_use",
                    "id": call.call_id.unwrap_or_default(),
                    "name": call.name,
                    "input": input
                }));
            }
        }
    }

    // Map finish_reason
    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(|r| r.as_str());
    let wrote_calls = content_blocks.iter().any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"));
    let stop_reason = anthropic_stop_for(finish_reason.map(FinishReason::normalize).as_ref(), wrote_calls);

    // Extract usage and apply token scaling (using effective upstream limit)
    let token_scale = match (client_context_window, context_window) {
        (Some(client_cw), Some(upstream_cw)) if upstream_cw > 0 && client_cw > upstream_cw => {
            let effective_upstream = (upstream_cw - max_output_tokens as i32).max(1);
            client_cw as f64 / effective_upstream as f64
        }
        _ => 1.0,
    };
    let scale = |tokens: u64| -> u64 {
        if token_scale > 1.0 {
            (tokens as f64 * token_scale).round() as u64
        } else {
            tokens
        }
    };

    let usage = response_json.get("usage");
    let raw_prompt = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(input_tokens as u64);
    let raw_completion = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    // OpenAI prompt_tokens INCLUDES cached; Anthropic input_tokens is disjoint
    // from cache_* — subtract the cache before scaling so the reported total
    // (input_tokens + cache_read + cache_creation) stays correct.
    let cache = CacheUsage::from_openai(usage, "prompt_tokens_details");
    let prompt_tokens = scale(cache.exclusive_prompt(raw_prompt));
    let completion_tokens = scale(raw_completion);
    if token_scale > 1.0 {
        tracing::info!(
            raw_input = raw_prompt,
            raw_output = raw_completion,
            scaled_input = prompt_tokens,
            scaled_output = completion_tokens,
            token_scale = format!("{token_scale:.2}"),
            "token scaling applied — client sees scaled values"
        );
    }

    let mut response = serde_json::json!({
        "id": format!("msg_{}", crate::ids::client_id(request_id)),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens
        }
    });
    cache.scaled(scale).apply_anthropic(&mut response["usage"]);
    stamp_model_info(&mut response, context_window, client_context_window);
    response
}

/// Stamp `model_info.context_window` — the window THIS response's usage figures
/// are measured against.
///
/// Every caller is a path that BUILDS an Anthropic response from another
/// protocol, which is exactly where token scaling applies: where
/// `client_context_window` exceeds the upstream's, the counts in the same body
/// have already been inflated by `client_cw / upstream_cw`. The window stated
/// here must therefore be the client one too, or the client compares inflated
/// usage against the smaller real window and compacts far too early, discarding
/// context it still had.
///
/// One helper because the three non-streaming builders and the streaming
/// builder must agree: while each stamped its own, the streaming and
/// non-streaming halves of one route advertised DIFFERENT windows, and the
/// Gemini path advertised none while still scaling its counts. Nothing reports
/// that — the client simply compacts at the wrong moment.
fn stamp_model_info(
    response: &mut serde_json::Value,
    context_window: Option<i32>,
    client_context_window: Option<i32>,
) {
    if let Some(cw) = client_context_window.or(context_window) {
        response["model_info"] = serde_json::json!({ "context_window": cw });
    }
}

// ─── Part E: Streaming Response Translation (any upstream → Responses SSE) ───

/// State machine that converts DomainEvents into OpenAI Responses API SSE events.
///
/// Every output item streams the way the spec frames it: `output_item.added`,
/// its deltas, then closing events that restate the WHOLE content —
/// `output_text.done` and `content_part.done` for a message,
/// `reasoning_summary_text.done` and `reasoning_summary_part.done` for
/// reasoning, `function_call_arguments.done` for a call — and an
/// `output_item.done` carrying the complete item. `response.completed` carries
/// every item as its `output`. A client that assembles its answer from the done
/// events rather than the deltas (Codex does) must read exactly what the deltas
/// streamed, so every closing event is built from the text the deltas carried.
///
/// Each `output_index` names one item and indexes only grow. A reasoning or
/// message item closes before any other item opens. Function calls are kept
/// open side by side, one per upstream call index, so arguments an upstream
/// interleaves across parallel calls each reach their own call; they close
/// together when text resumes or the response completes. Call boundaries
/// follow the response-phase accumulator's reading, so policy and the client
/// see the same calls: on an upstream that streams every call whole (Gemini)
/// each call event is a call; elsewhere a delta at an open call's index
/// continues it unless it names ANOTHER id or name (compared only where both
/// sides name one — servers repeat the id or the name on every delta, or send
/// the name first and the id later). A Chat upstream may number a call's later
/// deltas by position (a lax server sends no index after the first), so there a
/// delta naming nothing, at an index no call has claimed, continues the call
/// opened last.
pub struct ResponsesResponseBuilder {
    response_id: String,
    model: String,
    /// The response id as item ids embed it (`msg_<base>_<output_index>`).
    id_base: String,
    response_created: bool,
    /// Every item opened so far, in `output_index` order.
    items: Vec<ResponsesItem>,
    /// The open reasoning or message item, as a position in `items`.
    open: Option<usize>,
    /// The open function calls, as positions in `items`, in the order opened.
    open_calls: Vec<usize>,
    /// The calls whose later arguments were withheld — bytes after the call's
    /// item closed, or after a custom call's end: the client is told once per
    /// call, in a message after the calls (`write_withheld_notices`); the audit
    /// reads them through [`Self::take_withheld_calls`].
    withheld: crate::pipeline::response::WithheldCalls,
    /// The ids minted for calls announced before the upstream identified them.
    minted: crate::pipeline::response::MintedIds,
    input_tokens: u32,
    output_tokens: u32,
    reasoning_tokens: Option<u32>,
    cache_creation_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    /// Currently-open `web_search_call` output_item awaiting the matching
    /// `ServerToolResult` / `ServerToolError` to emit `.completed` then
    /// `output_item.done`. Carries the output_index, item_id, and action JSON
    /// so the close events match the open events byte-for-byte.
    pending_web_search_call: Option<PendingResponsesWebSearchCall>,
    /// While true, `TextDelta` events are dropped at the wire (matching the
    /// non-streaming Responses visible-mode walker, which discards round-0
    /// preamble text — preserves spec ordering of `web_search_call` BEFORE
    /// the assistant message item). Set by `enter_visible_mode_round()`,
    /// cleared once a `ServerToolResult|Error` closes the matching
    /// `web_search_call` (next round's TextDeltas land normally).
    drop_round_text: bool,
    /// URL+title pairs harvested from `ServerToolResult.content` events
    /// the substitution loop emitted earlier in this stream — deduped
    /// by URL on push so each unique hit emits exactly one citation.
    /// Empty when no visible-mode rounds dispatched (or only failed
    /// dispatches, which carry no URLs to cite).
    visible_mode_url_sources: Vec<crate::pipeline::response_blocks::UrlCitationSource>,
    /// The next event's `sequence_number` — see [`Self::responses_sse`].
    sequence_number: u64,
    /// Set by the first `Done`; a repeated one changes nothing.
    finished: bool,
    /// Set once `response.completed` (or `.incomplete`) is sent: the response
    /// the client holds is final, so nothing streamed after it can be added.
    completed: bool,
    /// The status of a `response.completed` held back at `Done`: a Chat
    /// upstream sends its usage in a chunk AFTER the one carrying
    /// `finish_reason` (`stream_options.include_usage`), and
    /// `response.completed` is where a Responses client reads it — sent at
    /// `Done`, it would state zero tokens. Sent on the next `Usage`, or at the
    /// stream-end flush if none comes.
    pending_completed: Option<Option<Incomplete>>,
}

/// Why a translated Responses turn stopped short: a reason the upstream's
/// finish stated (`incomplete_details.reason`), or a stream that ended with
/// no finish at all, whose cause the gateway cannot know — the spec's reason
/// is optional, and is left unstated.
#[derive(Debug, Clone, Copy)]
enum Incomplete {
    Reason(&'static str),
    CutShort,
}

/// One output item of the streamed response.
struct ResponsesItem {
    id: String,
    kind: ResponsesItemKind,
    /// What the deltas carried: the reasoning summary, the message text, or
    /// the call's arguments.
    text: String,
    /// The complete item as `output_item.done` sent it — what
    /// `response.completed` lists. `None` while the item is open.
    closed: Option<Value>,
    /// Its `output_item.added` was sent. A function call is announced once it
    /// is identified — see [`ResponsesResponseBuilder::announce`].
    announced: bool,
}

enum ResponsesItemKind {
    Reasoning,
    Message,
    /// `call_id` is the upstream's own id (empty until it names one) and
    /// `index` its call index — what a continuing delta is compared with.
    /// `wire_call_id` is the id the client is given, fixed when the call is
    /// announced (empty until then): the upstream's, or one minted here when
    /// it has named none by then (Gemini's ids are optional) — the spec
    /// requires every call to carry a unique one, and the client answers each
    /// call by it.
    FunctionCall { call_id: String, name: String, index: usize, wire_call_id: String },
    WebSearchCall,
}

/// In-flight `web_search_call` output_item state, kept between
/// `ServerToolCallDelta` (open) and `ServerToolResult|Error` (close).
struct PendingResponsesWebSearchCall {
    output_index: usize,
    item_id: String,
    action: serde_json::Value,
}

impl ResponsesResponseBuilder {
    pub fn new(response_id: String, model: String) -> Self {
        let id_base = response_id
            .strip_prefix("resp_")
            .unwrap_or(&response_id)
            .replace('-', "");
        Self {
            response_id,
            model,
            id_base,
            response_created: false,
            items: Vec::new(),
            open: None,
            open_calls: Vec::new(),
            withheld: crate::pipeline::response::WithheldCalls::default(),
            minted: crate::pipeline::response::MintedIds::default(),
            input_tokens: 0,
            output_tokens: 0,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_read_tokens: None,
            pending_web_search_call: None,
            drop_round_text: false,
            visible_mode_url_sources: Vec::new(),
            sequence_number: 0,
            finished: false,
            completed: false,
            pending_completed: None,
        }
    }

    /// One Responses streaming event. Every event the spec defines carries a
    /// `sequence_number` — its position in the stream, from 0 — so it is
    /// stamped here, the one place each event this builder sends passes.
    fn responses_sse(&mut self, event_type: &str, mut data: Value) -> String {
        data["sequence_number"] = self.sequence_number.into();
        self.sequence_number += 1;
        format_responses_sse(event_type, &data)
    }

    /// Signal from the substitution agent loop: the events about to be
    /// replayed are from a round whose intercepted server-tool will be
    /// emulated visibly, so `web_search_call` output_items must precede
    /// the assistant message. Drop round-0 `TextDelta` events to keep the
    /// message item from opening at a low `output_index` — once a
    /// `web_search_call` has been emitted, subsequent `TextDelta`s land
    /// normally at the next index. No-op if a message item is already open
    /// from a prior non-visible round (the agent loop decides visible-mode at
    /// request time, not mid-stream).
    pub fn enter_visible_mode_round(&mut self) {
        if !self.message_open() {
            self.drop_round_text = true;
        }
    }

    /// Whether the client has been handed the stream's end
    /// (`response.completed` / `.incomplete`).
    pub fn terminal_sent(&self) -> bool {
        self.completed
    }

    /// The calls whose arguments were withheld, not yet taken — for the
    /// audit row, which says the client's copy of them stops short.
    pub fn take_withheld_calls(&mut self) -> Vec<(usize, crate::pipeline::response::Withheld)> {
        self.withheld.take_unreported()
    }

    /// The ids minted for calls announced before the upstream identified
    /// them, not yet taken — for the audit row.
    pub fn take_minted_ids(&mut self) -> Vec<(usize, String)> {
        self.minted.take()
    }

    /// Tell the client, once per call, that arguments of a call arrived after
    /// it ended and were withheld — a message after the calls, as the turn
    /// ends (a message opened sooner would close calls still streaming).
    fn write_withheld_notices(&mut self, out: &mut Vec<String>) {
        for text in self.withheld.untold() {
            let i = self.text_item(true, out);
            self.items[i].text.push_str(text);
            let id = self.items[i].id.clone();
            out.push(self.responses_sse("response.output_text.delta", serde_json::json!({
                "type": "response.output_text.delta",
                "item_id": id,
                "output_index": i,
                "content_index": 0,
                "delta": text,
                "logprobs": []
            })));
        }
    }

    fn message_open(&self) -> bool {
        self.open
            .is_some_and(|i| matches!(self.items[i].kind, ResponsesItemKind::Message))
    }

    /// Append an item at the next `output_index`, announcing it when
    /// `announce` — every item but a function call not yet identified.
    fn open_item(&mut self, kind: ResponsesItemKind, announce: bool, out: &mut Vec<String>) -> usize {
        let output_index = self.items.len();
        let prefix = match kind {
            ResponsesItemKind::Reasoning => "rs",
            ResponsesItemKind::Message => "msg",
            ResponsesItemKind::FunctionCall { .. } => "fc",
            ResponsesItemKind::WebSearchCall => "ws",
        };
        let id = format!("{prefix}_{}_{output_index}", self.id_base);
        self.items.push(ResponsesItem { id, kind, text: String::new(), closed: None, announced: false });
        if announce {
            self.announce(output_index, out);
        }
        output_index
    }

    /// Send item `i`'s `output_item.added`, once — after every earlier item's,
    /// so the client meets them in `output_index` order.
    ///
    /// A function call waits — its arguments held with it, sent here as one
    /// delta — until it is identified (named, with the upstream's id), it
    /// closes, or a later item opens: a server may send a call's name first
    /// and its id on a later delta, and the id the client is handed at
    /// `output_item.added` is the one it answers by — fixed here, the
    /// upstream's when it has sent one by now, else minted (the spec requires
    /// every call to carry a unique id).
    fn announce(&mut self, i: usize, out: &mut Vec<String>) {
        for j in 0..=i {
            if self.items[j].announced {
                continue;
            }
            self.items[j].announced = true;
            let id = self.items[j].id.clone();
            let minted = format!("call_{}_{j}", self.id_base);
            if let ResponsesItemKind::FunctionCall { call_id, index, .. } = &self.items[j].kind
                && call_id.is_empty()
            {
                self.minted.mint(*index, minted.clone());
            }
            let item = match &mut self.items[j].kind {
                ResponsesItemKind::Reasoning => {
                    serde_json::json!({"id": id, "type": "reasoning", "summary": []})
                }
                ResponsesItemKind::Message => serde_json::json!({
                    "id": id, "type": "message", "status": "in_progress",
                    "role": "assistant", "content": []
                }),
                ResponsesItemKind::FunctionCall { call_id, name, wire_call_id, .. } => {
                    *wire_call_id = if call_id.is_empty() { minted } else { call_id.clone() };
                    serde_json::json!({
                        "id": id, "type": "function_call", "status": "in_progress",
                        "call_id": wire_call_id, "name": name, "arguments": ""
                    })
                }
                // Announced by its own opener, which carries the action.
                ResponsesItemKind::WebSearchCall => continue,
            };
            out.push(self.responses_sse("response.output_item.added", serde_json::json!({
                "type": "response.output_item.added",
                "output_index": j,
                "item": item
            })));
            // Arguments that arrived before the call was announced, sent now.
            if matches!(self.items[j].kind, ResponsesItemKind::FunctionCall { .. }) && !self.items[j].text.is_empty() {
                let delta = self.items[j].text.clone();
                out.push(self.responses_sse("response.function_call_arguments.delta", serde_json::json!({
                    "type": "response.function_call_arguments.delta",
                    "item_id": id,
                    "output_index": j,
                    "delta": delta
                })));
            }
        }
    }

    /// The open reasoning or message item of the kind asked for, opening one
    /// (and closing whatever else is open first) when there is none.
    fn text_item(&mut self, want_message: bool, out: &mut Vec<String>) -> usize {
        if let Some(i) = self.open {
            match self.items[i].kind {
                ResponsesItemKind::Message if want_message => return i,
                ResponsesItemKind::Reasoning if !want_message => return i,
                _ => {}
            }
        }
        self.close_open(None, out);
        let i = if want_message {
            let i = self.open_item(ResponsesItemKind::Message, true, out);
            let id = self.items[i].id.clone();
            out.push(self.responses_sse("response.content_part.added", serde_json::json!({
                "type": "response.content_part.added",
                "item_id": id,
                "output_index": i,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}
            })));
            i
        } else {
            let i = self.open_item(ResponsesItemKind::Reasoning, true, out);
            let id = self.items[i].id.clone();
            out.push(self.responses_sse("response.reasoning_summary_part.added", serde_json::json!({
                "type": "response.reasoning_summary_part.added",
                "item_id": id,
                "output_index": i,
                "summary_index": 0,
                "part": {"type": "summary_text", "text": ""}
            })));
            i
        };
        self.open = Some(i);
        i
    }

    /// Open function call `index` (the stream's number for it), named by
    /// `call_id` / `name` (either may be empty), announced at once only when
    /// both are known — see [`Self::announce`].
    fn open_call(&mut self, call_id: String, name: String, index: usize, out: &mut Vec<String>) -> usize {
        // Text closes before a call opens.
        if let Some(t) = self.open.take() {
            self.close_text(t, None, out);
        }
        let identified = !call_id.is_empty() && !name.is_empty();
        let kind = ResponsesItemKind::FunctionCall { call_id, name, index, wire_call_id: String::new() };
        let i = self.open_item(kind, identified, out);
        self.open_calls.push(i);
        i
    }

    /// The item of call `n` (the stream's number for it), if one opened.
    fn call_item(&self, n: usize) -> Option<usize> {
        self.items.iter().position(|item| matches!(item.kind, ResponsesItemKind::FunctionCall { index, .. } if index == n))
    }

    /// Close every open item, in `output_index` order, restating each one's
    /// whole content. `turn_end` is the turn's incomplete reason when the turn
    /// is ending (`Some(None)` = completed): only then are citations attached
    /// to a message and one stopped short marked `incomplete`.
    fn close_open(&mut self, turn_end: Option<Option<Incomplete>>, out: &mut Vec<String>) {
        let mut open: Vec<usize> = std::mem::take(&mut self.open_calls);
        open.extend(self.open.take());
        open.sort_unstable();
        for i in open {
            match self.items[i].kind {
                ResponsesItemKind::FunctionCall { .. } => self.close_call(i, turn_end, out),
                _ => self.close_text(i, turn_end, out),
            }
        }
    }

    /// Close reasoning or message item `i` — see [`Self::close_open`].
    fn close_text(&mut self, i: usize, turn_end: Option<Option<Incomplete>>, out: &mut Vec<String>) {
        let id = self.items[i].id.clone();
        let text = std::mem::take(&mut self.items[i].text);
        let closed = if matches!(self.items[i].kind, ResponsesItemKind::Reasoning) {
            out.push(self.responses_sse("response.reasoning_summary_text.done", serde_json::json!({
                "type": "response.reasoning_summary_text.done",
                "item_id": id,
                "output_index": i,
                "summary_index": 0,
                "text": text
            })));
            let part = serde_json::json!({"type": "summary_text", "text": text});
            out.push(self.responses_sse("response.reasoning_summary_part.done", serde_json::json!({
                "type": "response.reasoning_summary_part.done",
                "item_id": id,
                "output_index": i,
                "summary_index": 0,
                "part": part
            })));
            serde_json::json!({"id": id, "type": "reasoning", "summary": [part]})
        } else {
            // `url_citation` annotations for the visible-mode URLs harvested
            // this turn, attached to the message the turn ends on — between
            // its last `output_text.delta` and its `output_text.done`, so an
            // SDK that stream-renders citation chips sees them in place.
            let mut annotations = Vec::new();
            if turn_end.is_some() && !self.visible_mode_url_sources.is_empty() {
                let citations = crate::pipeline::response_blocks::compute_url_citations(
                    &text,
                    &self.visible_mode_url_sources,
                );
                for (annotation_index, citation) in citations.iter().enumerate() {
                    let annotation = crate::pipeline::response_blocks::url_citation_to_json(citation);
                    out.push(self.responses_sse(
                        "response.output_text.annotation.added",
                        serde_json::json!({
                            "type": "response.output_text.annotation.added",
                            "item_id": id,
                            "output_index": i,
                            "content_index": 0,
                            "annotation_index": annotation_index,
                            "annotation": annotation,
                        }),
                    ));
                    annotations.push(annotation);
                }
            }
            out.push(self.responses_sse("response.output_text.done", serde_json::json!({
                "type": "response.output_text.done",
                "item_id": id,
                "output_index": i,
                "content_index": 0,
                "text": text,
                "logprobs": []
            })));
            let part = serde_json::json!({
                "type": "output_text", "text": text, "annotations": annotations, "logprobs": []
            });
            out.push(self.responses_sse("response.content_part.done", serde_json::json!({
                "type": "response.content_part.done",
                "item_id": id,
                "output_index": i,
                "content_index": 0,
                "part": part
            })));
            let status = match turn_end {
                Some(Some(_)) => "incomplete",
                _ => "completed",
            };
            serde_json::json!({
                "id": id, "type": "message", "status": status, "role": "assistant",
                "content": [part]
            })
        };
        self.finish_item(i, closed, out);
    }

    /// Close function call `i`, restating its whole arguments — `incomplete`
    /// when the turn ends stopped short (the arguments may be cut), as a
    /// message is.
    fn close_call(&mut self, i: usize, turn_end: Option<Option<Incomplete>>, out: &mut Vec<String>) {
        self.announce(i, out);
        let id = self.items[i].id.clone();
        // The closed item holds the arguments from here on.
        let arguments = std::mem::take(&mut self.items[i].text);
        let ResponsesItemKind::FunctionCall { name, wire_call_id, .. } = &self.items[i].kind else {
            return;
        };
        let status = match turn_end {
            Some(Some(_)) => "incomplete",
            _ => "completed",
        };
        let closed = serde_json::json!({
            "id": id, "type": "function_call", "status": status,
            "call_id": wire_call_id, "name": name, "arguments": arguments
        });
        out.push(self.responses_sse("response.function_call_arguments.done", serde_json::json!({
            "type": "response.function_call_arguments.done",
            "item_id": id,
            "output_index": i,
            "arguments": arguments
        })));
        self.finish_item(i, closed, out);
    }

    /// Send an item's `output_item.done` and keep it for `response.completed`.
    fn finish_item(&mut self, i: usize, closed: Value, out: &mut Vec<String>) {
        out.push(self.responses_sse("response.output_item.done", serde_json::json!({
            "type": "response.output_item.done",
            "output_index": i,
            "item": closed
        })));
        self.items[i].closed = Some(closed);
    }

    /// Process a domain event and produce zero or more Responses SSE event strings.
    pub fn process_event(&mut self, event: &DomainEvent) -> Vec<String> {
        let mut out = Vec::new();
        // Nothing follows the response's end — its completion, or an error
        // (a `response.failed` parses to the error and then a finish). The
        // final response was sent: an item opened now could never be closed
        // or listed in it. The audit state records the content.
        if self.completed {
            if matches!(event, DomainEvent::ReasoningDelta(_) | DomainEvent::TextDelta(_) | DomainEvent::ToolCallDelta { .. }) {
                tracing::warn!("content streamed after the response ended; not sent to the client");
            }
            return out;
        }

        // Emit response.created on first meaningful event
        if !self.response_created {
            self.response_created = true;
            out.push(self.responses_sse("response.created", serde_json::json!({
                "type": "response.created",
                "response": {
                    "id": self.response_id,
                    "object": "response",
                    "status": "in_progress",
                    "model": self.model,
                    "output": []
                }
            })));
        }

        // A freeform call's end is the closing piece of its arguments.
        let event = event.as_tool_call_delta();
        match event.as_ref() {
            DomainEvent::FreeformCallEnd { .. } => {}
            DomainEvent::ReasoningDelta(text) => {
                let i = self.text_item(false, &mut out);
                self.items[i].text.push_str(text);
                let id = self.items[i].id.clone();
                out.push(self.responses_sse("response.reasoning_summary_text.delta", serde_json::json!({
                    "type": "response.reasoning_summary_text.delta",
                    "item_id": id,
                    "output_index": i,
                    "summary_index": 0,
                    "delta": text
                })));
            }
            DomainEvent::TextDelta(text) => {
                if self.drop_round_text && !self.message_open() {
                    return out;
                }
                let i = self.text_item(true, &mut out);
                self.items[i].text.push_str(text);
                let id = self.items[i].id.clone();
                out.push(self.responses_sse("response.output_text.delta", serde_json::json!({
                    "type": "response.output_text.delta",
                    "item_id": id,
                    "output_index": i,
                    "content_index": 0,
                    "delta": text,
                    "logprobs": []
                })));
            }
            // Bytes no call may take — of no call, or a custom call's text
            // after its end — are withheld.
            DomainEvent::ToolCallDelta { index, arguments_delta, .. } if event.is_withheld_piece() => {
                if self.withheld.withhold(*index, arguments_delta) {
                    tracing::warn!(index, "tool-call arguments arrived for no open call; withheld");
                }
            }
            // A built-in tool's call reaches a Responses client as the
            // upstream's own item, on a pass-through; a call this builder
            // would write is told, as the turn ends, not to have been carried.
            DomainEvent::ToolCallDelta { index, form: CallArguments::ClientBuiltin(builtin), .. } => {
                if self.withheld.not_carried(*index, *builtin) {
                    tracing::warn!(index, tool = builtin.tool_name(), "a built-in tool call cannot reach this client; not carried");
                }
            }
            // A server tool's input is no client's call.
            e if e.not_a_client_call() => {}
            DomainEvent::ToolCallDelta {
                index,
                id,
                function_name,
                arguments_delta,
                ..
            } => {
                // A call is its number on the stream: the delta goes to that
                // call's item, or opens it. Nothing is written into a closed
                // item — a second item under a closed call's id would have the
                // client run it twice — and the bytes are withheld.
                let item = self.call_item(*index);
                let closed = item.is_some_and(|i| self.items[i].closed.is_some());
                if closed {
                    if self.withheld.withhold(*index, arguments_delta) {
                        tracing::warn!(index, "tool-call arguments arrived after the call ended; withheld");
                    }
                    return out;
                }
                let i = match item {
                    Some(i) => i,
                    None => self.open_call(
                        id.clone().unwrap_or_default(),
                        function_name.clone().unwrap_or_default(),
                        *index,
                        &mut out,
                    ),
                };
                // A continuing delta fills in what the call lacked.
                if let ResponsesItemKind::FunctionCall { call_id, name, .. } = &mut self.items[i].kind {
                    if call_id.is_empty() && let Some(id) = id {
                        call_id.clone_from(id);
                    }
                    if name.is_empty() && let Some(n) = function_name {
                        name.clone_from(n);
                    }
                }
                let identified = matches!(
                    &self.items[i].kind,
                    ResponsesItemKind::FunctionCall { call_id, name, .. } if !call_id.is_empty() && !name.is_empty()
                );
                if identified {
                    self.announce(i, &mut out);
                }
                if !self.items[i].announced {
                    self.items[i].text.push_str(arguments_delta);
                } else if !arguments_delta.is_empty() {
                    self.items[i].text.push_str(arguments_delta);
                    let item_id = self.items[i].id.clone();
                    out.push(self.responses_sse("response.function_call_arguments.delta", serde_json::json!({
                        "type": "response.function_call_arguments.delta",
                        "item_id": item_id,
                        "output_index": i,
                        "delta": arguments_delta
                    })));
                }
            }
            DomainEvent::Usage(usage) => {
                if usage.prompt_tokens > 0 { self.input_tokens = usage.prompt_tokens; }
                if usage.completion_tokens > 0 { self.output_tokens = usage.completion_tokens; }
                if usage.reasoning_tokens.is_some() { self.reasoning_tokens = usage.reasoning_tokens; }
                if usage.cache_creation_tokens.is_some() { self.cache_creation_tokens = usage.cache_creation_tokens; }
                if usage.cache_read_tokens.is_some() { self.cache_read_tokens = usage.cache_read_tokens; }
                if let Some(incomplete) = self.pending_completed.take() {
                    self.complete(incomplete, &mut out);
                }
            }
            DomainEvent::Done { finish_reason, .. } => {
                if self.finished {
                    return out;
                }
                self.finished = true;
                // Usage may still follow — see `pending_completed`. The open
                // item closes with the response, so a delta an upstream sends
                // after its finish still lands in it.
                self.pending_completed = Some(responses_incomplete_reason(finish_reason.as_ref()).map(Incomplete::Reason));
            }
            // An error ends the client's stream: nothing is written after it.
            DomainEvent::Error { message, code } => {
                tracing::warn!(error_message = %message, error_code = ?code, "upstream error during stream");
                self.completed = true;
                out.push(self.responses_sse(
                    "error",
                    crate::error::envelope::openai_stream_error(
                        crate::api::sse::ApiVersion::Responses,
                        message,
                        code.as_deref(),
                    ),
                ));
            }
            // ImageGeneration events are native Responses API — raw SSE already forwarded.
            DomainEvent::ImageGeneration { .. } => {}
            // Substitution-emulated server-tool events: the agent loop
            // synthesises these between substitution rounds when the
            // intercepted tool was a native server-tool
            // (`InterceptBinding.original_server_type.is_some()`). Renders
            // as native `web_search_call` output_items — `output_item.added
            // (in_progress)` → `web_search_call.in_progress` →
            // `web_search_call.completed` (success only) → `output_item.done`
            // — at the next `output_index`, BEFORE the assistant message:
            // `enter_visible_mode_round()` drops the round's preamble
            // `TextDelta`s so the message opens after every web_search_call
            // (matches native OpenAI ordering and the non-streaming Responses
            // visible-mode walker in `pipeline::response_blocks`).
            // URL+title pairs harvested from each `ServerToolResult.content`
            // feed the `response.output_text.annotation.added` events sent
            // when the turn's message closes — substring-matched into the
            // assistant text where possible, span-less fallback otherwise.
            DomainEvent::ServerToolCallDelta {
                tool_use_id,
                input_delta,
                ..
            } => {
                self.emit_web_search_call_open(tool_use_id, input_delta, &mut out);
            }
            DomainEvent::ServerToolResult { content, .. } => {
                let sources = crate::pipeline::response_blocks::extract_url_citation_sources_from_search_content(content);
                for src in sources {
                    if !self
                        .visible_mode_url_sources
                        .iter()
                        .any(|s| s.url == src.url)
                    {
                        self.visible_mode_url_sources.push(src);
                    }
                }
                self.emit_web_search_call_close(false, &mut out);
            }
            DomainEvent::ServerToolError { .. } => {
                self.emit_web_search_call_close(true, &mut out);
            }
        }

        out
    }

    /// Open a synthesised `web_search_call` output_item at the next free
    /// `output_index` (BEFORE any assistant message — `drop_round_text`
    /// keeps the message from opening prematurely). Stores the in-flight
    /// `(output_index, item_id, action)` so the matching close events can
    /// reference the same identifiers.
    fn emit_web_search_call_open(
        &mut self,
        tool_use_id: &str,
        input_delta: &str,
        out: &mut Vec<String>,
    ) {
        self.close_open(None, out);
        let oi = self.open_item(ResponsesItemKind::WebSearchCall, true, out);
        let item_id = format!("ws_{tool_use_id}");
        self.items[oi].id.clone_from(&item_id);
        let action = responses_web_search_action(input_delta);
        out.push(self.responses_sse(
            "response.output_item.added",
            serde_json::json!({
                "type": "response.output_item.added",
                "output_index": oi,
                "item": {
                    "id": item_id,
                    "type": "web_search_call",
                    "status": "in_progress",
                    "action": action,
                }
            }),
        ));
        out.push(self.responses_sse(
            "response.web_search_call.in_progress",
            serde_json::json!({
                "type": "response.web_search_call.in_progress",
                "output_index": oi,
                "item_id": item_id,
            }),
        ));
        self.pending_web_search_call = Some(PendingResponsesWebSearchCall {
            output_index: oi,
            item_id,
            action,
        });
    }

    /// Stream-end flush: the response held for its usage is sent, and one
    /// whose stream ended with no finish ends `incomplete` — plus a
    /// defense-in-depth close for any in-flight
    /// `web_search_call` output_item. No current loop-exit path leaves
    /// `pending_web_search_call` non-empty (open + close fire in the same
    /// synchronous for-loop with no `.await` between them, and the
    /// cancel-mid-dispatch branch bails BEFORE the open), but a future
    /// bail point that splits open from close would dangle the wire
    /// `output_item.added (in_progress)` without a matching
    /// `output_item.done`. This guarantees the client's state machine
    /// always resolves.
    pub fn flush_pending(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        if self.completed {
            return out;
        }
        if self.pending_web_search_call.is_some() {
            self.emit_web_search_call_close(true, &mut out);
        }
        if let Some(incomplete) = self.pending_completed.take() {
            self.complete(incomplete, &mut out);
        } else if self.response_created {
            // The stream ended with no finish (cut short): the response ends
            // `incomplete`, its open items closed and every call announced,
            // so the client holds every call the audit records.
            self.complete(Some(Incomplete::CutShort), &mut out);
        }
        out
    }

    /// End the response: close the open item, then send `response.completed`
    /// (or `.incomplete`) carrying the usage received so far and every closed
    /// item as `output` — the response a client that reads only the terminal
    /// event (the OpenAI SDK's final response) is handed.
    fn complete(&mut self, incomplete: Option<Incomplete>, out: &mut Vec<String>) {
        self.write_withheld_notices(out);
        self.close_open(Some(incomplete), out);
        self.completed = true;
        out.push(self.response_completed(incomplete));
    }

    fn response_completed(&mut self, incomplete: Option<Incomplete>) -> String {
        let mut usage_json = serde_json::json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens
        });
        if let Some(rt) = self.reasoning_tokens {
            usage_json["output_tokens_details"] = serde_json::json!({"reasoning_tokens": rt});
        }
        CacheUsage::from_parts(self.cache_read_tokens, self.cache_creation_tokens)
            .apply_responses(&mut usage_json);
        // Sent once, at the end: the closed items move into it.
        let output: Vec<Value> = self.items.iter_mut().filter_map(|item| item.closed.take()).collect();
        let mut response = serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "model": self.model,
            "output": output,
            "usage": usage_json
        });
        match incomplete {
            Some(Incomplete::Reason(reason)) => stamp_responses_status(&mut response, Some(reason)),
            Some(Incomplete::CutShort) => {
                response["status"] = Value::from("incomplete");
                response["incomplete_details"] = Value::Null;
            }
            None => stamp_responses_status(&mut response, None),
        }
        // The spec closes a response that stopped short with its own event,
        // `response.incomplete`; a client dispatches on the event type.
        let event = if incomplete.is_some() { "response.incomplete" } else { "response.completed" };
        self.responses_sse(event, serde_json::json!({
            "type": event,
            "response": response
        }))
    }

    /// Close the in-flight `web_search_call` output_item with `completed`
    /// (success) or `failed` (executor error) status. Clears
    /// `drop_round_text` so the next round's `TextDelta`s open the message
    /// normally.
    fn emit_web_search_call_close(&mut self, error: bool, out: &mut Vec<String>) {
        let Some(pending) = self.pending_web_search_call.take() else {
            return;
        };
        let status = if error { "failed" } else { "completed" };
        // The spec streams no event for a failed search; the item's own
        // `status` is where a failure is stated.
        if !error {
            out.push(self.responses_sse(
                "response.web_search_call.completed",
                serde_json::json!({
                    "type": "response.web_search_call.completed",
                    "output_index": pending.output_index,
                    "item_id": pending.item_id,
                }),
            ));
        }
        let closed = serde_json::json!({
            "id": pending.item_id,
            "type": "web_search_call",
            "status": status,
            "action": pending.action,
        });
        self.finish_item(pending.output_index, closed, out);
        self.drop_round_text = false;
    }
}

/// The `web_search_tool_result_error.error_code` for a search the gateway ran
/// and could not complete, from the dispatch's error category. Anthropic's
/// schema is a closed set, so every category lands on one of its values —
/// `unavailable` ("an internal error occurred") for anything the client did
/// not cause and could not fix by asking differently.
pub(crate) fn anthropic_web_search_error_code(category: &str) -> &'static str {
    match category {
        "rate_limited" => "too_many_requests",
        "invalid_url" | "scheme_refused" | "ssrf_refused" | "url_filter_denied" => {
            "invalid_tool_input"
        }
        "oversized" => "request_too_large",
        _ => "unavailable",
    }
}

/// The `action` of a `web_search_call` item for a search the gateway ran: the
/// query the model asked for, when its arguments name one.
pub(crate) fn responses_web_search_action(input_delta: &str) -> Value {
    let mut action = serde_json::json!({"type": "search"});
    if let Some(q) = serde_json::from_str::<Value>(input_delta)
        .ok()
        .as_ref()
        .and_then(|v| v.get("query"))
        .and_then(|v| v.as_str())
    {
        action["query"] = Value::String(q.to_string());
    }
    action
}

fn format_responses_sse(event_type: &str, data: &Value) -> String {
    format!(
        "event: {event_type}\ndata: {}\n\n",
        serde_json::to_string(data).unwrap_or_default()
    )
}

// ─── Part F: Non-streaming Response Translation (OpenAI ChatCompletions → Responses) ───

/// Translate an OpenAI Chat Completions non-streaming response to Responses API format.
pub fn chat_completions_to_responses_response(
    response_json: &Value,
    model: &str,
    response_id: &str,
) -> Value {
    let choice = response_json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|choices| choices.first());

    let message = choice.and_then(|c| c.get("message"));
    let mut output = Vec::new();

    // Reasoning content → reasoning output item (before message)
    let reasoning_text = message
        .and_then(crate::api::chat::message_reasoning)
        .unwrap_or_default();

    if !reasoning_text.is_empty() {
        output.push(serde_json::json!({
            "id": format!("rs_{}", crate::ids::client_id(response_id)),
            "type": "reasoning",
            "summary": [{
                "type": "summary_text",
                "text": reasoning_text
            }]
        }));
    }

    // Text content → output message item
    let content_text = message
        .and_then(|m| crate::api::chat::content_text(m.get("content")))
        .unwrap_or_default();

    if !content_text.is_empty() {
        output.push(serde_json::json!({
            "id": format!("msg_{}", crate::ids::client_id(response_id)),
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": content_text,
                "annotations": []
            }]
        }));
    }

    // Tool calls → function_call output items
    if let Some(tool_calls) = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
    {
        // A custom (freeform) call arrives as a function call carrying its
        // text as `{"input": …}` (`tool_call_item`): the Responses client
        // declared no custom tool to this upstream.
        for call in tool_calls.iter().filter_map(crate::api::domain::tool_call_item) {
            let arguments = if call.arguments.is_empty() { "{}".to_string() } else { call.arguments };
            output.push(serde_json::json!({
                "type": "function_call",
                "call_id": call.call_id.unwrap_or_default(),
                "name": call.name,
                "arguments": arguments
            }));
        }
    }

    // Usage
    let usage = response_json.get("usage");
    let input_tokens = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let reasoning_tokens = usage
        .and_then(|u| u.get("completion_tokens_details"))
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(|t| t.as_u64());
    let cached_tokens = usage
        .and_then(|u| u.get("prompt_tokens_details"))
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|t| t.as_u64());

    // Status from finish_reason
    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(|r| r.as_str());
    let mut usage_json = serde_json::json!({
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens
    });
    if let Some(rt) = reasoning_tokens {
        usage_json["output_tokens_details"] = serde_json::json!({"reasoning_tokens": rt});
    }
    if let Some(ct) = cached_tokens {
        usage_json["input_tokens_details"] = serde_json::json!({"cached_tokens": ct});
    }

    let mut response = serde_json::json!({
        "id": response_id,
        "object": "response",
        "model": model,
        "output": output,
        "usage": usage_json
    });
    let finish = finish_reason.map(FinishReason::normalize);
    stamp_responses_status(&mut response, responses_incomplete_reason(finish.as_ref()));
    response
}

/// Stamp a Responses body's `status`: `incomplete` with the
/// `incomplete_details: {reason}` the spec pairs with it when the upstream
/// stopped short — `max_output_tokens` at the output cap, `content_filter`
/// when a filter cut it — else `completed`.
fn stamp_responses_status(response: &mut Value, incomplete: Option<&str>) {
    match incomplete {
        Some(reason) => {
            response["status"] = Value::from("incomplete");
            response["incomplete_details"] = serde_json::json!({"reason": reason});
        }
        None => response["status"] = Value::from("completed"),
    }
}

/// A stop in Chat Completions' `finish_reason` words, over the stop
/// `FinishReason::normalize` settled from the vendor's own spelling — so a
/// non-streaming Chat client reads the same reason a streaming one does. A
/// normal stop that carries tool calls is `tool_calls`; an unrecognised stop
/// reads `stop` (Chat has no word for it).
fn chat_finish(finish: Option<FinishReason>, has_tool_calls: bool) -> &'static str {
    match finish {
        Some(FinishReason::Length) => "length",
        Some(FinishReason::ToolCalls) => "tool_calls",
        Some(FinishReason::ContentFilter) => "content_filter",
        _ if has_tool_calls => "tool_calls",
        _ => "stop",
    }
}

/// A stop in Anthropic's `stop_reason` words, over the settled
/// [`FinishReason`] — the one mapping every translation onto Anthropic that
/// holds a stop word reads (streaming, non-streaming, the pass-through
/// rewrite). A Responses body states a `status` rather than a stop word, read
/// as a finish first ([`responses_answer_finish`]).
/// `end_turn` is the honest reading of a filtered or failed stop: Anthropic has
/// no value naming a filter or an error, and `refusal` names the model
/// declining, which is a claim about a different actor.
pub(crate) fn anthropic_stop_reason(finish: &FinishReason) -> &'static str {
    match finish {
        FinishReason::Stop | FinishReason::ContentFilter | FinishReason::Error => "end_turn",
        FinishReason::Length => "max_tokens",
        FinishReason::ToolCalls => "tool_use",
    }
}

/// A stop that claims tool calls when every call the turn made was withheld
/// whole — never named, or a built-in tool the client cannot run — and told
/// in its place: a plain stop, the reason riding the notice; a client handed
/// `tool_use` / `tool_calls` with no call to run cannot act on the turn. An
/// upstream that claimed calls and made none is its own defect, and any other
/// stop stands.
fn settle_withheld(finish: &FinishReason, gave_calls: bool, withheld: &crate::pipeline::response::WithheldCalls) -> FinishReason {
    match finish {
        FinishReason::ToolCalls if !gave_calls && withheld.any_whole() => FinishReason::Stop,
        other => other.clone(),
    }
}

/// [`anthropic_stop_reason`] for a turn that did or did not hand the client a
/// call: a truncation is said as such (`max_tokens` — the call may be cut
/// short) and a filtered or failed stop as a plain end even with calls (where
/// Chat, [`chat_finish`], keeps `tool_calls` for a failed turn's calls), while
/// any other stop with a call written is
/// `tool_use`, the word an Anthropic client runs calls on (a Responses or
/// Gemini upstream reports a plain stop for a turn ending in calls). Every
/// translation onto Anthropic reads it, streaming or not.
pub(crate) fn anthropic_stop_for(finish: Option<&FinishReason>, wrote_calls: bool) -> &'static str {
    match finish {
        Some(FinishReason::Length) => "max_tokens",
        // A filtered or failed turn (Gemini `MALFORMED_FUNCTION_CALL`, an
        // aborted generation) is no call to run, whatever it wrote.
        Some(FinishReason::ContentFilter | FinishReason::Error) => "end_turn",
        _ if wrote_calls => "tool_use",
        Some(f) => anthropic_stop_reason(f),
        None => "end_turn",
    }
}

/// The upstream's own stop word, when it is already Gemini's: Gemini's
/// `finishReason` values are SCREAMING_SNAKE_CASE (`STOP`, `RECITATION`,
/// `SPII`, …), and no other protocol spells a stop that way (`length`,
/// `model_length`, `end_turn`, `refusal`, `incomplete`). Read by shape rather
/// than against a copied list, so a value Gemini adds later still passes.
fn gemini_own_word(native: Option<&str>) -> Option<&str> {
    native.filter(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
}

/// A stop in Gemini's `finishReason` words — the one mapping every translation
/// onto Gemini reads, streaming or not (a Responses `status` read as a finish
/// first, [`responses_answer_finish`]). The upstream's own word is
/// kept only when it IS Gemini's ([`gemini_own_word`]: a Gemini answer
/// replayed from the response cache keeps its `RECITATION` or `SPII`); any
/// other protocol's word is stated through the settled [`FinishReason`].
pub(crate) fn gemini_finish_reason(finish: &FinishReason, native: Option<&str>) -> String {
    // Kept only where it says what the settled reason says: a finish the
    // gateway settled after a content edit (a removed call) owns the claim.
    if let Some(word) = gemini_own_word(native).filter(|w| FinishReason::normalize(w) == *finish) {
        return word.to_string();
    }
    match finish {
        FinishReason::Stop | FinishReason::ToolCalls => "STOP",
        FinishReason::Length => "MAX_TOKENS",
        FinishReason::ContentFilter => "SAFETY",
        FinishReason::Error => "OTHER",
    }
    .to_string()
}

/// Why a turn stopped short, in the Responses spec's words — the one mapping
/// every translation onto Responses reads, streaming or not, over the stop
/// `FinishReason::normalize` settled from the vendor's own spelling.
fn responses_incomplete_reason(finish: Option<&FinishReason>) -> Option<&'static str> {
    match finish {
        Some(FinishReason::Length) => Some("max_output_tokens"),
        Some(FinishReason::ContentFilter) => Some("content_filter"),
        _ => None,
    }
}

/// A whole Responses answer's `status`; a body stating none is a completed one.
pub(crate) fn responses_answer_status(response_json: &Value) -> &str {
    response_json.get("status").and_then(|s| s.as_str()).unwrap_or("completed")
}

/// A whole Responses answer's finish, read from its status as the stream
/// reads it ([`FinishReason::of_responses_status`]).
pub(crate) fn responses_answer_finish(response_json: &Value) -> Option<FinishReason> {
    FinishReason::of_responses_status(
        responses_answer_status(response_json),
        response_json.pointer("/incomplete_details/reason").and_then(|r| r.as_str()),
    )
}

// ─── Part H: Non-streaming Response Translation (Responses → Anthropic / ChatCompletions) ───

/// Translate an OpenAI Responses API non-streaming response to Anthropic Messages format.
pub fn responses_response_to_anthropic(
    response_json: &Value,
    model: &str,
    request_id: &str,
    context_window: Option<i32>,
    client_context_window: Option<i32>,
    max_output_tokens: u32,
) -> Value {
    let mut content_blocks = Vec::new();

    if let Some(output) = response_json.get("output").and_then(|o| o.as_array()) {
        for item in output {
            let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match item_type {
                "message" => {
                    if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                        for part in content {
                            let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            if matches!(part_type, "output_text" | "refusal")
                                && let Some(text) = part.get("text").and_then(|t| t.as_str())
                                    && !text.is_empty() {
                                        content_blocks.push(serde_json::json!({
                                            "type": "text",
                                            "text": text
                                        }));
                                    }
                        }
                    }
                }
                "reasoning" => {
                    // Reasoning blocks → Anthropic thinking blocks
                    if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                        for part in content {
                            if let Some(text) = part.get("text").and_then(|t| t.as_str())
                                && !text.is_empty() {
                                    content_blocks.push(anthropic_thinking_block(text));
                                }
                        }
                    }
                }
                // A custom (freeform) tool call reaches the client as a call
                // carrying its text as `{"input": …}` (`tool_call_item`).
                "function_call" | "custom_tool_call" => {
                    let Some(call) = crate::api::domain::tool_call_item(item) else { continue };
                    let input: Value = serde_json::from_str(&call.arguments)
                        .unwrap_or(Value::Object(Default::default()));
                    content_blocks.push(serde_json::json!({
                        "type": "tool_use",
                        "id": call.call_id.unwrap_or_default(),
                        "name": call.name,
                        "input": input
                    }));
                }
                // A built-in tool's call is a Responses client's to run: this
                // client is told it was not carried.
                _ if let Some(builtin) = crate::api::domain::ClientBuiltin::of_item(item) => {
                    content_blocks.push(serde_json::json!({"type": "text", "text": builtin.not_carried_notice()}));
                }
                _ => {}
            }
        }
    }

    // A Responses answer says `completed` whether or not it called a tool, so
    // the stop is read from its status and the calls it carries
    // (`anthropic_stop_for`).
    let calls = content_blocks.iter().any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"));
    let stop_reason = anthropic_stop_for(responses_answer_finish(response_json).as_ref(), calls);

    // Apply token scaling (using effective upstream limit)
    let token_scale = match (client_context_window, context_window) {
        (Some(client_cw), Some(upstream_cw)) if upstream_cw > 0 && client_cw > upstream_cw => {
            let effective_upstream = (upstream_cw - max_output_tokens as i32).max(1);
            client_cw as f64 / effective_upstream as f64
        }
        _ => 1.0,
    };
    let scale = |tokens: u64| -> u64 {
        if token_scale > 1.0 {
            (tokens as f64 * token_scale).round() as u64
        } else {
            tokens
        }
    };

    let usage = response_json.get("usage");
    let raw_input = usage.and_then(|u| u.get("input_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let raw_output = usage.and_then(|u| u.get("output_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    // Responses input_tokens INCLUDES cached; Anthropic input_tokens is disjoint
    // from cache_* — subtract before scaling to keep the total correct.
    let cache = CacheUsage::from_openai(usage, "input_tokens_details");
    let input_tokens = scale(cache.exclusive_prompt(raw_input));
    let output_tokens = scale(raw_output);
    if token_scale > 1.0 {
        tracing::info!(
            raw_input,
            raw_output,
            scaled_input = input_tokens,
            scaled_output = output_tokens,
            token_scale = format!("{token_scale:.2}"),
            "token scaling applied — client sees scaled values"
        );
    }

    let mut response = serde_json::json!({
        "id": format!("msg_{}", crate::ids::client_id(request_id)),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens
        }
    });
    cache.scaled(scale).apply_anthropic(&mut response["usage"]);
    stamp_model_info(&mut response, context_window, client_context_window);
    response
}

/// Translate an OpenAI Responses API non-streaming response to ChatCompletions format.
pub fn responses_response_to_chat_completions(
    response_json: &Value,
    model: &str,
) -> Value {
    let mut content_text = String::new();
    let mut reasoning_text = String::new();
    let mut tool_calls = Vec::new();

    if let Some(output) = response_json.get("output").and_then(|o| o.as_array()) {
        for item in output {
            let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match item_type {
                "message" => {
                    if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                        for part in content {
                            let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");
                            // Handle both output_text and refusal content types
                            if matches!(part_type, "output_text" | "refusal")
                                && let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                    content_text.push_str(text);
                                }
                        }
                    }
                }
                "reasoning" => {
                    // Extract reasoning text from summary or content array
                    let parts = item.get("summary").and_then(|s| s.as_array())
                        .or_else(|| item.get("content").and_then(|c| c.as_array()));
                    if let Some(parts) = parts {
                        for part in parts {
                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                reasoning_text.push_str(text);
                            }
                        }
                    }
                }
                // A custom (freeform) tool call reaches the client as the Chat
                // custom call it is — Chat has one, `{type: "custom", custom:
                // {name, input}}` — and a function call as a function call.
                "function_call" | "custom_tool_call" => {
                    let Some(call) = crate::api::domain::tool_call_item(item) else { continue };
                    let id = call.call_id.unwrap_or_default();
                    if call.custom {
                        let input = item.get("input").and_then(|i| i.as_str()).unwrap_or_default();
                        tool_calls.push(serde_json::json!({
                            "id": id,
                            "type": "custom",
                            "custom": {"name": call.name, "input": input}
                        }));
                        continue;
                    }
                    let arguments = if call.arguments.is_empty() { "{}".to_string() } else { call.arguments };
                    tool_calls.push(serde_json::json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": arguments
                        }
                    }));
                }
                // A built-in tool's call is a Responses client's to run: this
                // client is told it was not carried.
                _ if let Some(builtin) = crate::api::domain::ClientBuiltin::of_item(item) => {
                    content_text.push_str(builtin.not_carried_notice());
                }
                _ => {}
            }
        }
    }

    let finish_reason = chat_finish(responses_answer_finish(response_json), !tool_calls.is_empty());

    let usage = response_json.get("usage");
    let prompt_tokens = usage.and_then(|u| u.get("input_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let completion_tokens = usage.and_then(|u| u.get("output_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let reasoning_tokens = usage
        .and_then(|u| u.get("output_tokens_details"))
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(|t| t.as_u64());
    let cached_tokens = usage
        .and_then(|u| u.get("input_tokens_details"))
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|t| t.as_u64());

    let mut message = serde_json::json!({
        "role": "assistant",
        "content": if content_text.is_empty() { Value::Null } else { Value::String(content_text) },
        "tool_calls": if tool_calls.is_empty() { Value::Null } else { Value::Array(tool_calls) },
    });
    if !reasoning_text.is_empty() {
        message["reasoning"] = Value::String(reasoning_text);
    }

    let mut usage_json = serde_json::json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens
    });
    if let Some(rt) = reasoning_tokens {
        usage_json["completion_tokens_details"] = serde_json::json!({"reasoning_tokens": rt});
    }
    if let Some(ct) = cached_tokens {
        usage_json["prompt_tokens_details"] = serde_json::json!({"cached_tokens": ct});
    }

    serde_json::json!({
        "id": response_json.get("id").and_then(|i| i.as_str()).unwrap_or(""),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason
        }],
        "usage": usage_json
    })
}

// ─── Part I: Streaming Response Translation (Any → ChatCompletions SSE) ───

/// State machine that converts DomainEvents into ChatCompletions SSE chunks.
pub struct ChatCompletionsResponseBuilder {
    model: String,
    response_id: String,
    /// Whether a call was written — what the finish claims.
    has_tool_calls: bool,
    /// Set once `data: [DONE]` is written — see [`Self::terminal_sent`].
    terminal_sent: bool,
    /// The client's custom (freeform) tools: a call to one is written as the
    /// Chat custom call it declared (see [`Self::with_freeform_tools`]).
    freeform_tools: std::collections::HashSet<String>,
    /// The calls written in the custom form, until their end.
    custom_calls: std::collections::HashSet<usize>,
    /// The calls written in the function form.
    function_calls: std::collections::HashSet<usize>,
    /// Calls not yet both identified and named, by number. Whether a call is
    /// written in the custom form depends on its name, and its first chunk is
    /// where a client reads its id, so a call's first deltas wait here until
    /// it has both; one the stream never completes is written when the
    /// stream ends — its id minted — and one it never named is told in its
    /// place.
    held_calls: std::collections::BTreeMap<usize, HeldChatCall>,
    /// The client's index for each call — see [`ChatWireIndexes`].
    wire_indexes: ChatWireIndexes,
    /// The calls whose bytes were withheld — later arguments (a custom call's
    /// text after its end), a built-in tool's call the client cannot run, or
    /// a call never named — each told once, in place; what the finish settles
    /// from ([`settle_withheld`]).
    withheld: crate::pipeline::response::WithheldCalls,
    /// The ids minted for calls written before the upstream identified them.
    minted: crate::pipeline::response::MintedIds,
    /// The finish is written and `data: [DONE]` is not yet: the usage a
    /// stream reports after its finish (`stream_options.include_usage`) goes
    /// before it, and the stream's end writes it where none comes.
    done_pending: bool,
    /// The upstream's finish, written as the stream ends — after every call
    /// it carries, so its reason is a claim about all of them (a call first
    /// seen after the finish included).
    pending_finish: Option<Option<crate::api::domain::FinishReason>>,
}

/// A Chat client's index for each call, by the call's number on the stream:
/// 0, 1, 2 … in the order the calls are first written — so the calls a client
/// is given run from 0 however the stream numbered them (the calls of earlier
/// agent-loop rounds, and a call policy removed, never reach it). The Chat
/// builder and a held Chat pass-through read calls in this one index space.
#[derive(Debug, Default)]
pub(crate) struct ChatWireIndexes(std::collections::HashMap<usize, usize>);

impl ChatWireIndexes {
    /// The client's index for call `n`.
    pub(crate) fn of(&mut self, n: usize) -> usize {
        let next = self.0.len();
        *self.0.entry(n).or_insert(next)
    }
}

/// What a Chat client has not been sent yet of a call not yet both
/// identified and named.
#[derive(Default)]
struct HeldChatCall {
    id: Option<String>,
    name: Option<String>,
    /// A streamed custom call's text — its arguments, with the opening
    /// `FREEFORM_ARGS_OPEN` — or a function call's arguments.
    arguments: String,
    freeform: bool,
    /// A custom call written whole (`CallArguments::FreeformWhole`).
    whole: bool,
    /// A streamed custom call whose end came.
    ended: bool,
}

impl ChatCompletionsResponseBuilder {
    /// Whether the client has been handed the stream's end (`data: [DONE]`).
    pub fn terminal_sent(&self) -> bool {
        self.terminal_sent
    }

    pub fn new(model: String, response_id: String) -> Self {
        Self {
            model,
            response_id,
            has_tool_calls: false,
            terminal_sent: false,
            freeform_tools: std::collections::HashSet::new(),
            custom_calls: std::collections::HashSet::new(),
            function_calls: std::collections::HashSet::new(),
            held_calls: std::collections::BTreeMap::new(),
            wire_indexes: ChatWireIndexes::default(),
            withheld: crate::pipeline::response::WithheldCalls::default(),
            minted: crate::pipeline::response::MintedIds::default(),
            done_pending: false,
            pending_finish: None,
        }
    }

    /// The client's index for call `n` (see [`ChatWireIndexes`]).
    fn wire_index(&mut self, n: usize) -> usize {
        self.wire_indexes.of(n)
    }

    /// The calls whose arguments were withheld, not yet taken — for the
    /// audit row.
    pub fn take_withheld_calls(&mut self) -> Vec<(usize, crate::pipeline::response::Withheld)> {
        self.withheld.take_unreported()
    }

    /// The ids minted for calls written before the upstream identified them,
    /// not yet taken — for the audit row.
    pub fn take_minted_ids(&mut self) -> Vec<(usize, String)> {
        self.minted.take()
    }

    /// A chunk of assistant text.
    fn text_chunk(&self, text: &str) -> String {
        let chunk = serde_json::json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "model": self.model,
            "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}]
        });
        format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default())
    }

    /// The finish chunk, once: its reason read with every call the stream
    /// carried.
    fn write_finish(&mut self, out: &mut Vec<String>) {
        let Some(finish_reason) = self.pending_finish.take() else {
            return;
        };
        // The one Chat mapping the non-streaming translation reads too.
        // A Responses upstream reports "completed" even for tool calls,
        // so any other stop with calls streamed is `tool_calls`; a
        // truncation or a filter is said as such even then.
        let finish_reason = finish_reason.map(|f| settle_withheld(&f, self.has_tool_calls, &self.withheld));
        let reason = (finish_reason.is_some() || self.has_tool_calls)
            .then(|| chat_finish(finish_reason, self.has_tool_calls));
        let chunk = serde_json::json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": reason
            }]
        });
        out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
    }

    /// The stream's end: the finish, then `[DONE]`.
    fn write_done(&mut self, out: &mut Vec<String>) {
        self.write_finish(out);
        if std::mem::replace(&mut self.done_pending, false) {
            out.push("data: [DONE]\n\n".to_string());
            self.terminal_sent = true;
        }
    }

    /// Write every call still held — the stream is ending.
    fn write_held_calls(&mut self, out: &mut Vec<String>) {
        for (index, held) in std::mem::take(&mut self.held_calls) {
            self.write_held_call(index, held, out);
        }
    }

    /// The calls still held when the stream ends without its finish (cut
    /// short), written — or, never named, told — so the client has every call
    /// the audit records.
    pub fn flush_pending(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        if self.terminal_sent {
            return out;
        }
        self.write_held_calls(&mut out);
        self.write_done(&mut out);
        out
    }

    /// The client's custom (freeform) tools, by name. A call to one reaches
    /// the client as the Chat custom call it declared.
    pub fn with_freeform_tools(mut self, names: std::collections::HashSet<String>) -> Self {
        self.freeform_tools = names;
        self
    }

    /// A delta of a call written in the Chat custom form, carrying `text` —
    /// a piece of the call's free text. The spec's chunk has only the
    /// function form; this is the message form — `custom: {name, input}` —
    /// with the input in pieces, the shape a Chat stream carrying a custom
    /// call is read in.
    fn custom_call_delta(&self, index: usize, id: Option<&String>, name: Option<&String>, text: &str) -> String {
        let mut custom = serde_json::json!({"input": text});
        if let Some(name) = name {
            custom["name"] = Value::String(name.clone());
        }
        let mut tc = serde_json::json!({"index": index, "type": "custom", "custom": custom});
        if let Some(id) = id {
            tc["id"] = Value::String(id.clone());
        }
        let chunk = serde_json::json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "model": self.model,
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]
        });
        format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default())
    }

    /// A delta of a call written in the function form.
    fn function_call_delta(&self, index: usize, id: Option<&String>, name: Option<&String>, arguments: &str) -> String {
        let mut tc = serde_json::json!({"index": index, "type": "function", "function": {}});
        if let Some(id) = id {
            tc["id"] = Value::String(id.clone());
        }
        if let Some(name) = name {
            tc["function"]["name"] = Value::String(name.clone());
        }
        if !arguments.is_empty() {
            tc["function"]["arguments"] = Value::String(arguments.to_string());
        }
        let chunk = serde_json::json!({
            "id": self.response_id,
            "object": "chat.completion.chunk",
            "model": self.model,
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]
        });
        format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default())
    }

    /// The free text of an escaped piece of a custom call's text. Each piece
    /// is escaped whole, so it reads back alone; one that does not is passed
    /// on as it came rather than lost.
    fn freeform_text(piece: &str) -> String {
        serde_json::from_str::<String>(&format!("\"{piece}\"")).unwrap_or_else(|_| piece.to_string())
    }

    /// Write a held call — identified and named, or, at the stream's end,
    /// named, with an id minted for it (one never named is told in its place):
    /// in the custom form when
    /// it is a custom call to one of the client's custom tools, else in the
    /// function form — a custom call's arguments then being
    /// `{"input": <text>}`.
    fn write_held_call(&mut self, index: usize, held: HeldChatCall, out: &mut Vec<String>) {
        // A call the stream never named cannot reach the client: it is told
        // in the call's place.
        if held.name.is_none() {
            if self.withheld.nameless(index) {
                tracing::warn!(index, "a tool call the stream never named cannot reach a Chat client; not carried");
                out.push(self.text_chunk(crate::pipeline::response::NAMELESS_CALL_NOTICE));
            }
            return;
        }
        self.has_tool_calls = true;
        // An id the upstream has not sent is minted, and the audit row says so.
        let id = Some(held.id.clone().unwrap_or_else(|| self.minted.mint(index, format!("call_{}_{index}", self.response_id))));
        let name = held.name.as_ref();
        let wire = self.wire_index(index);
        let custom = held.freeform && name.is_some_and(|n| self.freeform_tools.contains(n));
        if !custom {
            self.function_calls.insert(index);
            let mut arguments = held.arguments;
            if held.ended {
                arguments.push_str(crate::api::domain_request::FREEFORM_ARGS_CLOSE);
            }
            out.push(self.function_call_delta(wire, id.as_ref(), name, &arguments));
            return;
        }
        let text = if held.whole {
            crate::api::domain_request::freeform_whole_text(&held.arguments)
        } else {
            let open = crate::api::domain_request::FREEFORM_ARGS_OPEN;
            Self::freeform_text(held.arguments.strip_prefix(open).unwrap_or(&held.arguments))
        };
        // A streamed call is custom until its end; one written whole, or
        // already ended, has none to come.
        if !held.whole && !held.ended {
            self.custom_calls.insert(index);
        }
        out.push(self.custom_call_delta(wire, id.as_ref(), name, &text));
    }

    /// Process a domain event and produce zero or more ChatCompletions SSE event strings.
    pub fn process_event(&mut self, event: &DomainEvent) -> Vec<String> {
        let mut out = Vec::new();
        // Nothing follows the stream's end — `[DONE]`, or an error's (a
        // Responses `response.failed` parses to the error and then a finish).
        if self.terminal_sent {
            return out;
        }

        // A call is written once it is both identified and named: whether a
        // custom call is written in the Chat custom form (its text piece by
        // piece, nothing for its end) depends on its name — a tool the client
        // declared custom — and a custom call to anything else is a function
        // call whose arguments are `{"input": <text>}`. Whether a call is
        // custom is its deltas' `form`.
        match event {
            // Bytes no call may take — of no call, or a custom call's text
            // after its end — are withheld, and the client told once.
            DomainEvent::ToolCallDelta { index, arguments_delta, .. } if event.is_withheld_piece() => {
                if self.withheld.withhold(*index, arguments_delta) {
                    tracing::warn!(index, "tool-call arguments arrived for no open call; withheld");
                    out.push(self.text_chunk(crate::pipeline::response::WITHHELD_NOTICE));
                }
                return out;
            }
            // A built-in tool's call is a Responses client's to run: this
            // one is told, once, that it was not carried.
            DomainEvent::ToolCallDelta { index, form: CallArguments::ClientBuiltin(builtin), .. } => {
                if self.withheld.not_carried(*index, *builtin) {
                    tracing::warn!(index, tool = builtin.tool_name(), "a built-in tool call cannot reach this client; not carried");
                    out.push(self.text_chunk(builtin.not_carried_notice()));
                }
                return out;
            }
            // A server tool's input is no client's call.
            e if e.not_a_client_call() => return out,
            DomainEvent::FreeformCallEnd { index } => {
                if self.custom_calls.remove(index) {
                    return out;
                }
                if let Some(held) = self.held_calls.get_mut(index) {
                    held.ended = true;
                    return out;
                }
                // A function-form call's end is the closing piece of its
                // arguments; a call never written has none to close.
                if self.function_calls.contains(index) {
                    let wire = self.wire_index(*index);
                    out.push(self.function_call_delta(wire, None, None, crate::api::domain_request::FREEFORM_ARGS_CLOSE));
                }
                return out;
            }
            DomainEvent::ToolCallDelta { index, id, function_name, arguments_delta, form } => {
                // An empty name names nothing (a script's rebuild may write one).
                let function_name = function_name.as_ref().filter(|n| !n.is_empty());
                if self.custom_calls.contains(index) {
                    let wire = self.wire_index(*index);
                    let text = Self::freeform_text(arguments_delta);
                    if id.is_some() || function_name.is_some() || !text.is_empty() {
                        out.push(self.custom_call_delta(wire, id.as_ref(), function_name, &text));
                    }
                    return out;
                }
                if self.function_calls.contains(index) {
                    let wire = self.wire_index(*index);
                    out.push(self.function_call_delta(wire, id.as_ref(), function_name, arguments_delta));
                    return out;
                }
                // A call told as nameless is closed: a later piece of it goes
                // nowhere (the notice and the audit's record of it stand).
                if self.withheld.is_nameless(*index) {
                    return out;
                }
                let held = self.held_calls.entry(*index).or_default();
                if held.id.is_none() {
                    held.id.clone_from(id);
                }
                if held.name.is_none() {
                    held.name = function_name.cloned();
                }
                held.freeform |= form.is_freeform();
                held.whole |= *form == CallArguments::FreeformWhole;
                held.arguments.push_str(arguments_delta);
                if held.id.is_some()
                    && held.name.is_some()
                    && let Some(held) = self.held_calls.remove(index)
                {
                    self.write_held_call(*index, held, &mut out);
                }
                return out;
            }
            DomainEvent::Done { .. } | DomainEvent::Error { .. } => self.write_held_calls(&mut out),
            // A call first seen after the finish is held like any other; the
            // usage that ends the stream writes it, then the finish.
            DomainEvent::Usage(_) if self.done_pending => {
                self.write_held_calls(&mut out);
                self.write_finish(&mut out);
            }
            _ => {}
        }

        match event {
            DomainEvent::FreeformCallEnd { .. } => {}
            DomainEvent::TextDelta(text) => {
                let chunk = serde_json::json!({
                    "id": self.response_id,
                    "object": "chat.completion.chunk",
                    "model": self.model,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": text},
                        "finish_reason": null
                    }]
                });
                out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
            }
            DomainEvent::ReasoningDelta(text) => {
                let chunk = serde_json::json!({
                    "id": self.response_id,
                    "object": "chat.completion.chunk",
                    "model": self.model,
                    "choices": [{
                        "index": 0,
                        "delta": {"reasoning": text},
                        "finish_reason": null
                    }]
                });
                out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
            }
            // Every call delta was written above.
            DomainEvent::ToolCallDelta { .. } => {}
            DomainEvent::Usage(usage) => {
                let mut usage_json = serde_json::json!({
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens
                });
                if let Some(rt) = usage.reasoning_tokens {
                    usage_json["completion_tokens_details"] =
                        serde_json::json!({"reasoning_tokens": rt});
                }
                // cached_tokens is a prompt-side cache HIT — it belongs in
                // prompt_tokens_details (not completion_*), and excludes cache
                // creations (premium writes, not hits).
                CacheUsage::from_parts(usage.cache_read_tokens, usage.cache_creation_tokens)
                    .apply_chat(&mut usage_json);
                let chunk = serde_json::json!({
                    "id": self.response_id,
                    "object": "chat.completion.chunk",
                    "model": self.model,
                    "choices": [],
                    "usage": usage_json
                });
                out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
                self.write_done(&mut out);
            }
            // Held for the stream's end (`write_finish`): a call may still
            // follow it.
            DomainEvent::Done { finish_reason, .. } => {
                if !self.done_pending {
                    self.pending_finish = Some(finish_reason.clone());
                }
                self.done_pending = true;
            }
            DomainEvent::Error { message, code } => {
                tracing::warn!(error_message = %message, error_code = ?code, "upstream error during stream");
                self.write_finish(&mut out);
                let error_data = crate::error::envelope::openai_stream_error(
                    crate::api::sse::ApiVersion::ChatCompletions,
                    message,
                    code.as_deref(),
                );
                out.push(format!("data: {}\n\n", serde_json::to_string(&error_data).unwrap_or_default()));
                out.push("data: [DONE]\n\n".to_string());
                self.done_pending = false;
                self.terminal_sent = true;
            }
            // ImageGeneration is Responses-API-only; no ChatCompletions equivalent.
            DomainEvent::ImageGeneration { .. } => {}
            // Chat Completions has no native server-tool wire shape, so
            // visible-mode events have nowhere to land — drop and rely on
            // audit + URL filter / SSRF guarantees from the substitution
            // dispatch.
            DomainEvent::ServerToolCallDelta { .. }
            | DomainEvent::ServerToolResult { .. }
            | DomainEvent::ServerToolError { .. } => {}
        }

        out
    }
}

// ─── Gemini Response Builder ────────────────────────────────────────────────

/// State machine that converts DomainEvents into Gemini SSE chunks.
///
/// Gemini SSE format: `data: {GenerateContentResponse JSON}\n\n`
/// Defers Done until Usage arrives (same pattern as Anthropic — OpenAI sends
/// finish_reason before usage in streaming).
///
/// Tool-call deltas are also deferred: Gemini's wire format requires one
/// complete `functionCall: {name, id?, args}` part per tool, but upstream
/// protocols (OpenAI, Anthropic) stream tool args incrementally. We
/// accumulate per-index then emit one chunk per tool right before the final
/// chunk so Gemini SDK clients see complete arguments.
pub struct GeminiResponseBuilder {
    model: String,
    /// Set once the final candidate is written — see [`Self::terminal_sent`].
    terminal_sent: bool,
    pending_stop_reason: Option<Option<String>>,
    input_tokens: u32,
    output_tokens: u32,
    reasoning_tokens: Option<u32>,
    cache_read_tokens: Option<u32>,
    pending_tool_calls: Vec<PendingGeminiToolCall>,
    /// Substitution-mode grounding, emitted single-shot on the final
    /// candidate (see [`GeminiGrounding`]).
    grounding: GeminiGrounding,
    /// The calls whose later arguments were withheld (a custom call's text
    /// after its end): the client is told once per call, at once.
    withheld: crate::pipeline::response::WithheldCalls,
}

/// The `groundingMetadata` a Gemini client is owed for searches the gateway
/// ran in the model's place (visible-mode web-search substitution). Each
/// `ServerToolCallDelta` contributes its query and each `ServerToolResult` its
/// hits as `groundingChunks`. Emitted once, on the final candidate, so the
/// client sees one consolidated block however many substitution rounds ran.
/// Shared by the translated builder and the pass-through emitter.
#[derive(Debug, Default)]
pub(crate) struct GeminiGrounding {
    chunks: Vec<Value>,
    queries: Vec<String>,
}

impl GeminiGrounding {
    /// Take in one substitution event; anything else is ignored.
    pub(crate) fn absorb(&mut self, event: &DomainEvent) {
        match event {
            // Gemini's `groundingMetadata` doesn't carry per-call IDs —
            // chunks correlate via `groundingSupports.groundingChunkIndices`
            // back into `groundingChunks`. Drop `tool_use_id` here.
            DomainEvent::ServerToolCallDelta { input_delta, .. } => {
                if let Ok(args) = serde_json::from_str::<Value>(input_delta)
                    && let Some(q) = args.get("query").and_then(Value::as_str)
                    && !self.queries.iter().any(|x| x == q)
                {
                    self.queries.push(q.to_string());
                }
            }
            DomainEvent::ServerToolResult { content, .. } => self.absorb_chunks(content),
            // Errors don't add chunks but the query is already queued from
            // the call-delta — `groundingMetadata.webSearchQueries` still
            // surfaces what the model tried to search for.
            _ => {}
        }
    }

    /// Push every `SearchHit` from a dispatched `SearchResult` payload as a
    /// Gemini `groundingChunk`. Skips dups by URI so the single-shot final
    /// emission doesn't double up across substitution rounds. Fetch payloads
    /// (`extracted_text`) land as a single chunk pointing at the fetched URL —
    /// the model can still cite it via `webSearchQueries` even when the
    /// executor was a fetch, not a search.
    fn absorb_chunks(&mut self, content: &Value) {
        let mut push_chunk = |uri: String, title: String| {
            if !self
                .chunks
                .iter()
                .any(|c| c.get("web").and_then(|w| w.get("uri")) == Some(&Value::String(uri.clone())))
            {
                self.chunks.push(serde_json::json!({"web": {"uri": uri, "title": title}}));
            }
        };
        if let Some(hits) = content.get("hits").and_then(Value::as_array) {
            for h in hits {
                let url = h.get("url").and_then(Value::as_str).unwrap_or("").to_string();
                let title = h.get("title").and_then(Value::as_str).unwrap_or("").to_string();
                if !url.is_empty() {
                    push_chunk(url, title);
                }
            }
        } else if let Some(url) = content
            .get("final_url")
            .and_then(Value::as_str)
            .or_else(|| content.get("url").and_then(Value::as_str))
        {
            let title = content
                .get("content_type")
                .and_then(Value::as_str)
                .unwrap_or(url)
                .to_string();
            push_chunk(url.to_string(), title);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty() && self.queries.is_empty()
    }

    /// The consolidated `groundingMetadata` object.
    pub(crate) fn metadata(&self) -> Value {
        serde_json::json!({
            "groundingChunks": self.chunks,
            "webSearchQueries": self.queries,
        })
    }
}

#[derive(Debug, Default)]
struct PendingGeminiToolCall {
    index: usize,
    id: Option<String>,
    name: Option<String>,
    args_buf: String,
}

impl GeminiResponseBuilder {
    /// Whether the client has been handed the stream's end (the candidate
    /// carrying `finishReason`).
    pub fn terminal_sent(&self) -> bool {
        self.terminal_sent
    }

    pub fn new(model: String) -> Self {
        Self {
            model,
            terminal_sent: false,
            pending_stop_reason: None,
            input_tokens: 0,
            output_tokens: 0,
            reasoning_tokens: None,
            cache_read_tokens: None,
            pending_tool_calls: Vec::new(),
            withheld: crate::pipeline::response::WithheldCalls::default(),
            grounding: GeminiGrounding::default(),
        }
    }

    /// Render any accumulated tool calls as one Gemini SSE chunk per tool.
    /// Called right before the final chunk (containing `finishReason` +
    /// `usageMetadata`). Args that fail to parse fall back to `{}` so the
    /// client always sees a structurally valid `functionCall` part — never
    /// a tool with a name but no arguments. A `functionCall` needs a name, so
    /// a call the stream never named goes as a notice in its place, recorded
    /// on the audit row.
    fn drain_pending_tool_calls(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let calls: Vec<PendingGeminiToolCall> = std::mem::take(&mut self.pending_tool_calls);
        for tc in calls {
            let Some(name) = tc.name else {
                if self.withheld.nameless(tc.index) {
                    tracing::warn!(index = tc.index, "a tool call the stream never named cannot reach a Gemini client; not carried");
                    let chunk = serde_json::json!({
                        "candidates": [{"content": {"role": "model", "parts": [{"text": crate::pipeline::response::NAMELESS_CALL_NOTICE}]}}]
                    });
                    out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
                }
                continue;
            };
            let mut fc = serde_json::json!({"name": name});
            if let Some(id) = tc.id {
                fc["id"] = Value::String(id);
            }
            let args = if tc.args_buf.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str::<Value>(&tc.args_buf).unwrap_or_else(|_| serde_json::json!({}))
            };
            fc["args"] = args;
            let chunk = serde_json::json!({
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{"functionCall": fc}]
                    }
                }]
            });
            out.push(format!(
                "data: {}\n\n",
                serde_json::to_string(&chunk).unwrap_or_default()
            ));
        }
        out
    }

    pub fn process_event(&mut self, event: &DomainEvent) -> Vec<String> {
        let mut out = Vec::new();
        // Nothing follows the stream's end — the final candidate, or an
        // error's (a Responses `response.failed` parses to the error and then
        // a finish).
        if self.terminal_sent {
            return out;
        }

        // A freeform call's end is the closing piece of its arguments.
        let event = event.as_tool_call_delta();
        match event.as_ref() {
            DomainEvent::FreeformCallEnd { .. } => {}
            DomainEvent::TextDelta(text) => {
                let chunk = serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"text": text}]
                        }
                    }]
                });
                out.push(format!(
                    "data: {}\n\n",
                    serde_json::to_string(&chunk).unwrap_or_default()
                ));
            }
            DomainEvent::ReasoningDelta(text) => {
                let chunk = serde_json::json!({
                    "candidates": [{
                        "content": {
                            "role": "model",
                            "parts": [{"thought": true, "text": text}]
                        }
                    }]
                });
                out.push(format!(
                    "data: {}\n\n",
                    serde_json::to_string(&chunk).unwrap_or_default()
                ));
            }
            // Bytes no call may take — of no call, or a custom call's text
            // after its end — are withheld, and the client told once.
            DomainEvent::ToolCallDelta { index, arguments_delta, .. } if event.is_withheld_piece() => {
                if self.withheld.withhold(*index, arguments_delta) {
                    tracing::warn!(index, "tool-call arguments arrived for no open call; withheld");
                    let chunk = serde_json::json!({
                        "candidates": [{"content": {"role": "model", "parts": [{"text": crate::pipeline::response::WITHHELD_NOTICE}]}}]
                    });
                    out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
                }
            }
            // A built-in tool's call is a Responses client's to run: this
            // one is told, once, that it was not carried.
            DomainEvent::ToolCallDelta { index, form: CallArguments::ClientBuiltin(builtin), .. } => {
                if self.withheld.not_carried(*index, *builtin) {
                    tracing::warn!(index, tool = builtin.tool_name(), "a built-in tool call cannot reach this client; not carried");
                    let chunk = serde_json::json!({
                        "candidates": [{"content": {"role": "model", "parts": [{"text": builtin.not_carried_notice()}]}}]
                    });
                    out.push(format!("data: {}\n\n", serde_json::to_string(&chunk).unwrap_or_default()));
                }
            }
            // A server tool's input is no client's call.
            e if e.not_a_client_call() => {}
            DomainEvent::ToolCallDelta {
                index,
                id,
                function_name,
                arguments_delta,
                ..
            } => {
                // Accumulate per-index. Gemini's wire format wants one
                // complete `functionCall` part per tool, so we hold off
                // emission until the stream finalizes (drained right before
                // the final chunk in `emit_final_chunk` callers).
                let entry = match self
                    .pending_tool_calls
                    .iter_mut()
                    .position(|t| t.index == *index)
                {
                    Some(pos) => &mut self.pending_tool_calls[pos],
                    None => self.pending_tool_calls.push_mut(PendingGeminiToolCall {
                        index: *index,
                        ..Default::default()
                    }),
                };
                if let Some(tc_id) = id {
                    entry.id = Some(tc_id.clone());
                }
                // An empty name names nothing (a script's rebuild may write one).
                if let Some(name) = function_name.as_ref().filter(|n| !n.is_empty()) {
                    entry.name = Some(name.clone());
                }
                entry.args_buf.push_str(arguments_delta);
            }
            DomainEvent::Usage(usage) => {
                self.input_tokens = usage.prompt_tokens;
                self.output_tokens = usage.completion_tokens;
                self.reasoning_tokens = usage.reasoning_tokens;
                self.cache_read_tokens = usage.cache_read_tokens;

                // If Done arrived before Usage (common in OpenAI upstream), emit now
                if let Some(stop_reason) = self.pending_stop_reason.take() {
                    out.extend(self.drain_pending_tool_calls());
                    out.extend(self.emit_final_chunk(stop_reason.as_deref()));
                }
            }
            DomainEvent::Done { finish_reason, native_finish_reason } => {
                // A finish stated only in the upstream's own word keeps it
                // when that word is Gemini's.
                let reason = match finish_reason {
                    Some(r) => Some(gemini_finish_reason(r, native_finish_reason.as_deref())),
                    None => gemini_own_word(native_finish_reason.as_deref()).map(str::to_string),
                };
                // If Usage already arrived, emit immediately. Otherwise defer.
                if self.input_tokens > 0 || self.output_tokens > 0 {
                    out.extend(self.drain_pending_tool_calls());
                    out.extend(self.emit_final_chunk(reason.as_deref()));
                } else {
                    self.pending_stop_reason = Some(reason);
                }
            }
            // An error ends the client's stream: the calls it held go first,
            // and nothing follows it.
            DomainEvent::Error { message, .. } => {
                out.extend(self.drain_pending_tool_calls());
                self.terminal_sent = true;
                let chunk = crate::error::envelope::ClientError::stream_failure(message)
                    .body(crate::api::sse::ApiVersion::GoogleGemini);
                out.push(format!(
                    "data: {}\n\n",
                    serde_json::to_string(&chunk).unwrap_or_default()
                ));
            }
            DomainEvent::ImageGeneration { .. } => {}
            DomainEvent::ServerToolCallDelta { .. }
            | DomainEvent::ServerToolResult { .. }
            | DomainEvent::ServerToolError { .. } => self.grounding.absorb(event.as_ref()),
        }

        out
    }

    /// The calls whose arguments were withheld, not yet taken — for the
    /// audit row.
    pub fn take_withheld_calls(&mut self) -> Vec<(usize, crate::pipeline::response::Withheld)> {
        self.withheld.take_unreported()
    }

    /// Flush any deferred events (call at stream end).
    pub fn flush_pending(&mut self) -> Vec<String> {
        if self.terminal_sent {
            return Vec::new();
        }
        let mut out = self.drain_pending_tool_calls();
        if let Some(reason) = self.pending_stop_reason.take() {
            out.extend(self.emit_final_chunk(reason.as_deref()));
        }
        out
    }

    fn emit_final_chunk(&mut self, finish_reason: Option<&str>) -> Vec<String> {
        self.terminal_sent = true;
        let mut chunk = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": finish_reason.unwrap_or("STOP")
            }],
            "usageMetadata": {
                "promptTokenCount": self.input_tokens,
                "candidatesTokenCount": self.output_tokens,
                "totalTokenCount": self.input_tokens + self.output_tokens
            },
            "modelVersion": self.model
        });
        if let Some(rt) = self.reasoning_tokens {
            chunk["usageMetadata"]["thoughtsTokenCount"] = serde_json::json!(rt);
        }
        if let Some(cr) = self.cache_read_tokens {
            chunk["usageMetadata"]["cachedContentTokenCount"] = serde_json::json!(cr);
        }
        // Single-shot grounding emission (Decision #2). Lands on the final
        // candidate so substitution rounds collapse into one client-visible
        // `groundingMetadata`.
        if !self.grounding.is_empty() {
            chunk["candidates"][0]["groundingMetadata"] = self.grounding.metadata();
        }
        vec![format!(
            "data: {}\n\n",
            serde_json::to_string(&chunk).unwrap_or_default()
        )]
    }
}

// ─── Non-streaming Gemini response translation ──────────────────────────────

/// Parsed view of a non-streaming Gemini response. Thinking parts
/// (`thought: true`) are collected into `reasoning` so translators can surface
/// them to CC (`message.reasoning`), Anthropic (`thinking` block), and
/// Responses (`reasoning` output item).
struct ParsedGemini<'a> {
    text: Option<String>,
    reasoning: Option<String>,
    tool_calls: Option<Vec<Value>>,
    finish_reason: Option<&'a str>,
}

fn parse_gemini_response(response_json: &Value) -> ParsedGemini<'_> {
    let candidate = response_json
        .get("candidates")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first());

    let finish_reason = candidate
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str());

    let parts = candidate
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array());

    let Some(parts) = parts else {
        return ParsedGemini {
            text: None,
            reasoning: None,
            tool_calls: None,
            finish_reason,
        };
    };

    let mut texts = Vec::new();
    let mut reasonings = Vec::new();
    let mut tool_calls = Vec::new();

    for part in parts {
        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
            if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
                reasonings.push(text.to_string());
            } else {
                texts.push(text.to_string());
            }
        }
        if let Some(fc) = part.get("functionCall") {
            tool_calls.push(fc.clone());
        }
    }

    ParsedGemini {
        text: if texts.is_empty() {
            None
        } else {
            Some(texts.join(""))
        },
        reasoning: if reasonings.is_empty() {
            None
        } else {
            Some(reasonings.join(""))
        },
        tool_calls: if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        },
        finish_reason,
    }
}

/// Extract `(prompt, completion)` usage from Gemini response JSON, where
/// `completion` is the BILLABLE output count.
///
/// Gemini reports thinking tokens in their own `thoughtsTokenCount`, OUTSIDE
/// `candidatesTokenCount` (its `totalTokenCount` adds the two), yet bills them at
/// the output rate. Every other protocol we translate to defines its output count
/// as already inclusive of reasoning, so the two are summed here — both to bill
/// correctly and so the translated response reports the same output count the
/// client would have seen natively.
fn gemini_usage(response_json: &Value) -> (u32, u32) {
    let um = response_json.get("usageMetadata");
    let count = |key: &str| {
        um.and_then(|u| u.get(key))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32
    };
    (
        count("promptTokenCount"),
        count("candidatesTokenCount") + count("thoughtsTokenCount"),
    )
}

/// Gemini upstream → ChatCompletions client (non-streaming).
pub fn gemini_response_to_chat_completions(
    response_json: &Value,
    model: &str,
) -> Value {
    let ParsedGemini { text, reasoning, tool_calls, finish_reason } = parse_gemini_response(response_json);
    let (prompt, completion) = gemini_usage(response_json);

    let cc_reason = chat_finish(
        finish_reason.map(FinishReason::normalize),
        tool_calls.as_ref().is_some_and(|t| !t.is_empty()),
    );

    let mut message = serde_json::json!({"role": "assistant"});
    if let Some(t) = &text {
        message["content"] = Value::String(t.clone());
    }
    if let Some(tcs) = &tool_calls {
        let cc_tcs: Vec<Value> = tcs
            .iter()
            .enumerate()
            .map(|(i, fc)| {
                serde_json::json!({
                    "id": fc.get("id").and_then(|v| v.as_str()).unwrap_or(&format!("call_{i}")),
                    "type": "function",
                    "function": {
                        "name": fc.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        "arguments": fc.get("args").map(|a| serde_json::to_string(a).unwrap_or_default()).unwrap_or_default()
                    }
                })
            })
            .collect();
        message["tool_calls"] = Value::Array(cc_tcs);
    }
    if let Some(r) = reasoning {
        message["reasoning"] = Value::String(r);
    }

    let mut result = serde_json::json!({
        "id": format!("chatcmpl-{:08x}", rand::random::<u32>()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": cc_reason
        }],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion
        }
    });
    CacheUsage::from_gemini(response_json).apply_chat(&mut result["usage"]);
    result
}

/// Gemini upstream → Anthropic client (non-streaming).
pub fn gemini_response_to_anthropic(
    response_json: &Value,
    model: &str,
    request_id: &str,
    context_window: Option<i32>,
    client_context_window: Option<i32>,
    max_output_tokens: u32,
) -> Value {
    let ParsedGemini { text, reasoning, tool_calls, finish_reason } = parse_gemini_response(response_json);
    let (prompt, completion) = gemini_usage(response_json);

    let stop_reason = anthropic_stop_for(
        finish_reason.map(FinishReason::normalize).as_ref(),
        tool_calls.as_ref().is_some_and(|t| !t.is_empty()),
    );

    let mut content = Vec::new();
    if let Some(r) = &reasoning {
        content.push(anthropic_thinking_block(r));
    }
    if let Some(t) = &text {
        content.push(serde_json::json!({"type": "text", "text": t}));
    }
    if let Some(tcs) = &tool_calls {
        for fc in tcs {
            content.push(serde_json::json!({
                "type": "tool_use",
                "id": fc.get("id").and_then(|v| v.as_str()).unwrap_or("call_0"),
                "name": fc.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                "input": fc.get("args").unwrap_or(&Value::Object(Default::default()))
            }));
        }
    }
    if content.is_empty() {
        content.push(serde_json::json!({"type": "text", "text": ""}));
    }

    // Token scaling for context window mismatch (same as AnthropicResponseBuilder).
    // Cache-read tokens are part of the prompt, so scale them the same way.
    let scale = |tokens: u64| -> u64 {
        match (client_context_window, context_window) {
            (Some(client_cw), Some(upstream_cw)) if upstream_cw > 0 && client_cw > upstream_cw => {
                let effective = (upstream_cw - max_output_tokens as i32).max(1);
                ((tokens as f64) * (client_cw as f64 / effective as f64)).round() as u64
            }
            _ => tokens,
        }
    };
    // Gemini promptTokenCount INCLUDES cached; Anthropic input_tokens is disjoint
    // from cache_* — subtract before scaling to keep the total correct.
    let cache = CacheUsage::from_gemini(response_json);
    let scaled_prompt = scale(cache.exclusive_prompt(prompt as u64)) as u32;

    let mut response = serde_json::json!({
        "id": format!("msg_{}", crate::ids::client_id(request_id)),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": scaled_prompt,
            "output_tokens": completion
        }
    });
    cache.scaled(scale).apply_anthropic(&mut response["usage"]);
    stamp_model_info(&mut response, context_window, client_context_window);
    response
}

/// Gemini upstream → Responses API client (non-streaming).
pub fn gemini_response_to_responses(
    response_json: &Value,
    model: &str,
    request_id: &str,
) -> Value {
    let ParsedGemini { text, reasoning, tool_calls, .. } = parse_gemini_response(response_json);
    let (prompt, completion) = gemini_usage(response_json);

    let mut output = Vec::new();
    if let Some(r) = &reasoning {
        output.push(serde_json::json!({
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": r}]
        }));
    }
    if let Some(tcs) = &tool_calls {
        let base = crate::ids::client_id(request_id);
        for (n, fc) in tcs.iter().enumerate() {
            // The spec requires every call to carry a unique `call_id`, and the
            // client answers each call by it; Gemini's own id is optional, so
            // one is minted where it names none.
            let call_id = fc
                .get("id")
                .and_then(|v| v.as_str())
                .filter(|id| !id.is_empty())
                .map_or_else(|| format!("call_{base}_{n}"), str::to_string);
            output.push(serde_json::json!({
                "type": "function_call",
                "id": format!("fc_{base}_{n}"),
                "call_id": call_id,
                "name": fc.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                "arguments": fc.get("args").map(|a| serde_json::to_string(a).unwrap_or_default()).unwrap_or_default()
            }));
        }
    }
    if let Some(t) = &text {
        output.insert(0, serde_json::json!({
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": t}]
        }));
    }

    let mut response = serde_json::json!({
        "id": format!("resp_{}", crate::ids::client_id(request_id)),
        "object": "response",
        "model": model,
        "output": output,
        "usage": {
            "input_tokens": prompt,
            "output_tokens": completion,
            "total_tokens": prompt + completion
        }
    });
    let finish = response_json
        .pointer("/candidates/0/finishReason")
        .and_then(Value::as_str)
        .map(FinishReason::normalize);
    stamp_responses_status(&mut response, responses_incomplete_reason(finish.as_ref()));
    CacheUsage::from_gemini(response_json).apply_responses(&mut response["usage"]);
    response
}

/// ChatCompletions upstream → Gemini client (non-streaming).
pub fn chat_completions_to_gemini_response(response_json: &Value) -> Value {
    let choice = response_json
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first());

    let mut parts = Vec::new();
    // Reasoning first, on Gemini's own thought channel — the streaming emitter
    // already produces `thought: true` parts, so omitting it here would deliver
    // the model's reasoning to a streaming Gemini client and silently drop it
    // for the identical non-streaming request (and for a non-streaming cache
    // hit off the same stored answer).
    if let Some(reasoning) = choice
        .and_then(|c| c.get("message"))
        .and_then(crate::api::chat::message_reasoning)
    {
        parts.push(serde_json::json!({"text": reasoning, "thought": true}));
    }
    if let Some(content) = choice
        .and_then(|c| c.get("message"))
        .and_then(|m| crate::api::chat::content_text(m.get("content")))
    {
        parts.push(serde_json::json!({"text": content}));
    }
    if let Some(tool_calls) = choice
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
    {
        // A custom (freeform) call arrives as a call carrying its text as
        // `{"input": …}` (`tool_call_item`).
        for call in tool_calls.iter().filter_map(crate::api::domain::tool_call_item) {
            let args = serde_json::from_str::<Value>(&call.arguments).unwrap_or(Value::Object(Default::default()));
            parts.push(serde_json::json!({
                "functionCall": {
                    "id": call.call_id.unwrap_or_default(),
                    "name": call.name,
                    "args": args
                }
            }));
        }
    }

    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(|r| r.as_str())
        .map_or_else(|| "STOP".to_string(), |r| gemini_finish_reason(&FinishReason::normalize(r), Some(r)));

    let usage = response_json.get("usage");
    let prompt = usage.and_then(|u| u.get("prompt_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
    let completion = usage.and_then(|u| u.get("completion_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);

    let mut result = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": parts},
            "finishReason": finish_reason
        }],
        "usageMetadata": {
            "promptTokenCount": prompt,
            "candidatesTokenCount": completion,
            "totalTokenCount": prompt + completion
        }
    });
    CacheUsage::from_openai(usage, "prompt_tokens_details")
        .apply_gemini(&mut result["usageMetadata"]);
    result
}

/// Anthropic upstream → Gemini client (non-streaming).
pub fn anthropic_to_gemini_response(response_json: &Value) -> Value {
    let mut parts = Vec::new();

    if let Some(content) = response_json.get("content").and_then(|c| c.as_array()) {
        for block in content {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        parts.push(serde_json::json!({"text": t}));
                    }
                }
                Some("thinking") => {
                    if let Some(t) = block.get("thinking").and_then(|t| t.as_str()) {
                        parts.push(serde_json::json!({"thought": true, "text": t}));
                    }
                }
                Some("tool_use") => {
                    parts.push(serde_json::json!({
                        "functionCall": {
                            "id": block.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            "name": block.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                            "args": block.get("input").unwrap_or(&Value::Object(Default::default()))
                        }
                    }));
                }
                _ => {}
            }
        }
    }

    let stop_reason = response_json
        .get("stop_reason")
        .and_then(|r| r.as_str())
        .map_or_else(|| "STOP".to_string(), |r| gemini_finish_reason(&FinishReason::normalize(r), Some(r)));

    let usage = response_json.get("usage");
    let input_excl = usage.and_then(|u| u.get("input_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
    let completion = usage.and_then(|u| u.get("output_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
    // Anthropic input_tokens excludes cached; Gemini promptTokenCount includes it.
    let cache = CacheUsage::from_anthropic(usage);
    let prompt = cache.inclusive_prompt(input_excl);

    let mut result = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": parts},
            "finishReason": stop_reason
        }],
        "usageMetadata": {
            "promptTokenCount": prompt,
            "candidatesTokenCount": completion,
            "totalTokenCount": prompt + completion
        }
    });
    cache.apply_gemini(&mut result["usageMetadata"]);
    result
}

/// Responses API upstream → Gemini client (non-streaming).
pub fn responses_to_gemini_response(response_json: &Value) -> Value {
    let mut parts = Vec::new();

    if let Some(output) = response_json.get("output").and_then(|o| o.as_array()) {
        for item in output {
            match item.get("type").and_then(|t| t.as_str()) {
                Some("message") => {
                    if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
                        for part in content {
                            if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                                parts.push(serde_json::json!({"text": t}));
                            }
                        }
                    }
                }
                // A custom (freeform) tool call reaches the client as a call
                // carrying its text as `{"input": …}` (`tool_call_item`).
                Some("function_call" | "custom_tool_call") => {
                    let Some(call) = crate::api::domain::tool_call_item(item) else { continue };
                    let args = serde_json::from_str::<Value>(&call.arguments)
                        .unwrap_or(Value::Object(Default::default()));
                    parts.push(serde_json::json!({
                        "functionCall": {
                            "id": call.call_id.unwrap_or_default(),
                            "name": call.name,
                            "args": args
                        }
                    }));
                }
                // A built-in tool's call is a Responses client's to run: this
                // client is told it was not carried.
                _ if let Some(builtin) = crate::api::domain::ClientBuiltin::of_item(item) => {
                    parts.push(serde_json::json!({"text": builtin.not_carried_notice()}));
                }
                _ => {}
            }
        }
    }

    let finish_reason = gemini_finish_reason(&responses_answer_finish(response_json).unwrap_or(FinishReason::Stop), None);

    let usage = response_json.get("usage");
    let prompt = usage.and_then(|u| u.get("input_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);
    let completion = usage.and_then(|u| u.get("output_tokens")).and_then(|v| v.as_u64()).unwrap_or(0);

    let mut result = serde_json::json!({
        "candidates": [{
            "content": {"role": "model", "parts": parts},
            "finishReason": finish_reason
        }],
        "usageMetadata": {
            "promptTokenCount": prompt,
            "candidatesTokenCount": completion,
            "totalTokenCount": prompt + completion
        }
    });
    CacheUsage::from_openai(usage, "input_tokens_details")
        .apply_gemini(&mut result["usageMetadata"]);
    result
}

/// Anthropic upstream → ChatCompletions client (non-streaming).
pub fn anthropic_to_chat_completions(response_json: &Value, model: &str) -> Value {
    let mut content_text = String::new();
    let mut reasoning_text = String::new();
    let mut tool_calls = Vec::new();

    if let Some(content) = response_json.get("content").and_then(|c| c.as_array()) {
        for block in content {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        content_text.push_str(t);
                    }
                }
                Some("thinking") => {
                    if let Some(t) = block.get("thinking").and_then(|t| t.as_str()) {
                        reasoning_text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let arguments = block
                        .get("input")
                        .map(|a| serde_json::to_string(a).unwrap_or_default())
                        .unwrap_or_default();
                    tool_calls.push(serde_json::json!({
                        "id": id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": arguments
                        }
                    }));
                }
                _ => {}
            }
        }
    }

    let stop_reason = response_json.get("stop_reason").and_then(|r| r.as_str());
    let finish_reason = chat_finish(stop_reason.map(FinishReason::normalize), !tool_calls.is_empty());

    let usage = response_json.get("usage");
    let input_excl = usage.and_then(|u| u.get("input_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let completion_tokens = usage.and_then(|u| u.get("output_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    // Anthropic input_tokens excludes cached; ChatCompletions prompt_tokens
    // includes it — fold the cache back into the prompt total.
    let cache = CacheUsage::from_anthropic(usage);
    let prompt_tokens = cache.inclusive_prompt(input_excl);

    let mut message = serde_json::json!({"role": "assistant"});
    if !content_text.is_empty() {
        message["content"] = Value::String(content_text);
    } else {
        message["content"] = Value::Null;
    }
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }
    if !reasoning_text.is_empty() {
        message["reasoning"] = Value::String(reasoning_text);
    }

    let mut usage_json = serde_json::json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens
    });
    cache.apply_chat(&mut usage_json);

    serde_json::json!({
        "id": format!("chatcmpl-{:08x}", rand::random::<u32>()),
        "object": "chat.completion",
        "created": Utc::now().timestamp(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason
        }],
        "usage": usage_json
    })
}

/// Anthropic upstream → Responses API client (non-streaming).
pub fn anthropic_to_responses_response(
    response_json: &Value,
    model: &str,
    request_id: &str,
) -> Value {
    let mut output = Vec::new();
    let mut has_text = false;
    let mut text_parts = Vec::new();

    if let Some(content) = response_json.get("content").and_then(|c| c.as_array()) {
        for block in content {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        text_parts.push(serde_json::json!({"type": "output_text", "text": t}));
                        has_text = true;
                    }
                }
                Some("thinking") => {
                    if let Some(t) = block.get("thinking").and_then(|t| t.as_str()) {
                        output.push(serde_json::json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": t}]
                        }));
                    }
                }
                Some("tool_use") => {
                    let id = block.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let arguments = block
                        .get("input")
                        .map(|a| serde_json::to_string(a).unwrap_or_default())
                        .unwrap_or_default();
                    output.push(serde_json::json!({
                        "type": "function_call",
                        "id": format!("fc_{id}"),
                        "call_id": id,
                        "name": name,
                        "arguments": arguments
                    }));
                }
                _ => {}
            }
        }
    }

    // Group text parts into a single message output item
    if has_text {
        output.insert(0, serde_json::json!({
            "type": "message",
            "role": "assistant",
            "content": text_parts
        }));
    }

    let stop_reason = response_json.get("stop_reason").and_then(|r| r.as_str());

    let usage = response_json.get("usage");
    let input_excl = usage.and_then(|u| u.get("input_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    let output_tokens = usage.and_then(|u| u.get("output_tokens")).and_then(|t| t.as_u64()).unwrap_or(0);
    // Anthropic input_tokens excludes cached; Responses input_tokens includes it.
    let cache = CacheUsage::from_anthropic(usage);
    let input_tokens = cache.inclusive_prompt(input_excl);

    let mut response = serde_json::json!({
        "id": format!("resp_{}", crate::ids::client_id(request_id)),
        "object": "response",
        "model": model,
        "output": output,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    });
    let finish = stop_reason.map(FinishReason::normalize);
    stamp_responses_status(&mut response, responses_incomplete_reason(finish.as_ref()));
    cache.apply_responses(&mut response["usage"]);
    response
}

/// The signature a thinking block the gateway BUILT for an Anthropic client
/// carries. The Messages API's thinking block requires one, and Claude Code
/// closes a streamed thinking block on its `signature_delta`; reasoning from
/// another upstream has none, so it is a placeholder (`synth_` + the clock)
/// that Anthropic would not verify. Streamed and whole answers carry the same
/// kind, so the two read alike.
fn synthetic_thinking_signature() -> String {
    format!(
        "{}{:x}",
        crate::api::domain_request::SYNTHETIC_SIGNATURE_PREFIX,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()
    )
}

/// A whole answer's thinking block for an Anthropic client, signed with
/// [`synthetic_thinking_signature`].
fn anthropic_thinking_block(thinking: &str) -> Value {
    serde_json::json!({"type": "thinking", "thinking": thinking, "signature": synthetic_thinking_signature()})
}

#[cfg(test)]
mod tests {

    /// The Messages API's thinking block requires `signature`. A whole answer
    /// built for an Anthropic client from any other upstream carries one, as
    /// a streamed one does (`signature_delta`) — from a Chat reasoning key, a
    /// Mistral `thinking` chunk, inline `<think>` tags, a Responses reasoning
    /// item and a Gemini thought alike.
    #[test]
    fn every_built_anthropic_thinking_block_is_signed() {
        let signed = |r: &Value| {
            let blocks: Vec<&Value> = r["content"].as_array().unwrap().iter().filter(|b| b["type"] == "thinking").collect();
            assert!(!blocks.is_empty(), "no thinking block: {r}");
            for b in blocks {
                assert!(b["signature"].as_str().is_some_and(|s| !s.is_empty()), "unsigned: {b}");
            }
        };
        for message in [
            serde_json::json!({"role": "assistant", "content": "hi", "reasoning_content": "why"}),
            serde_json::json!({"role": "assistant", "content": [
                {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]}, {"type": "text", "text": "hi"}]}),
            serde_json::json!({"role": "assistant", "content": "<think>why</think>hi"}),
        ] {
            let oai = serde_json::json!({"choices": [{"index": 0, "message": message, "finish_reason": "stop"}]});
            signed(&openai_response_to_anthropic(&oai, "m", "abc12345", 1, None, None, 0));
        }
        let responses = serde_json::json!({"status": "completed", "output": [
            {"type": "reasoning", "content": [{"type": "reasoning_text", "text": "why"}]},
            {"type": "message", "content": [{"type": "output_text", "text": "hi"}]}]});
        signed(&responses_response_to_anthropic(&responses, "m", "abc12345", None, None, 0));
        let gemini = serde_json::json!({"candidates": [{"content": {"parts": [
            {"text": "why", "thought": true}, {"text": "hi"}]}, "finishReason": "STOP"}]});
        signed(&gemini_response_to_anthropic(&gemini, "m", "abc12345", None, None, 0));
    }
    use super::*;
    use crate::api::domain::Usage;

    /// A custom call's input is closed at its end, and nothing is written
    /// into it after: a piece of the call arriving later is not written, so
    /// the client's input stays the whole JSON it was closed as.
    #[test]
    fn nothing_is_written_into_a_custom_calls_input_after_its_end() {
        let piece = |id: Option<&str>, name: Option<&str>, text: &str, form| DomainEvent::ToolCallDelta {
            index: 0,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: text.to_string(),
            form,
        };
        for late in [CallArguments::FreeformPiece, CallArguments::FreeformLate] {
            let mut builder = AnthropicResponseBuilder::new("m".into(), "req1".into(), None, None, 0, 0);
            let mut frames = builder.process_event(&piece(Some("call_1"), Some("apply_patch"), "{\"input\":\"a", CallArguments::FreeformPiece));
            frames.extend(builder.process_event(&DomainEvent::FreeformCallEnd { index: 0 }));
            frames.extend(builder.process_event(&piece(None, None, "b", late)));
            frames.extend(builder.process_event(&DomainEvent::Done {
                finish_reason: Some(FinishReason::ToolCalls),
                native_finish_reason: None,
            }));
            frames.extend(builder.flush_pending());
            let input: String = frames
                .iter()
                .flat_map(|f| f.lines())
                .filter_map(|l| l.strip_prefix("data: "))
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter_map(|v| v["delta"]["partial_json"].as_str().map(String::from))
                .collect();
            assert_eq!(input, "{\"input\":\"a\"}", "{late:?}: {frames:?}");
        }
    }

    /// A Responses client's call item holds the custom call's arguments as
    /// they were closed: a piece the stream marks late is not written into it.
    #[test]
    fn a_responses_call_item_is_not_written_a_custom_calls_text_after_its_end() {
        let piece = |id: Option<&str>, name: Option<&str>, text: &str, form| DomainEvent::ToolCallDelta {
            index: 0,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: text.to_string(),
            form,
        };
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        let mut frames = builder.process_event(&piece(Some("call_1"), Some("apply_patch"), "{\"input\":\"a", CallArguments::FreeformPiece));
        frames.extend(builder.process_event(&DomainEvent::FreeformCallEnd { index: 0 }));
        frames.extend(builder.process_event(&piece(None, None, "b", CallArguments::FreeformLate)));
        frames.extend(builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::ToolCalls),
            native_finish_reason: None,
        }));
        frames.extend(builder.flush_pending());
        let events = sse_data(&frames);
        let done: Vec<&Value> = events
            .iter()
            .filter(|e| e["type"] == "response.output_item.done" && e["item"]["type"] == "function_call")
            .map(|e| &e["item"]["arguments"])
            .collect();
        assert_eq!(done, [&serde_json::json!("{\"input\":\"a\"}")], "{events:?}");
        // The piece withheld is said, once, as the turn ends.
        let told = events.iter().filter(|e| e["type"] == "response.output_text.delta").count();
        assert_eq!(told, 1, "{events:?}");
    }

    /// A Chat client is sent a call once a delta names it: whether a custom
    /// call is written in the custom form depends on its name (a tool the
    /// client declared custom), so a call whose opening delta says only its
    /// kind — or only its id — waits for its name, then goes out in one form
    /// from its first chunk. Named by nothing, the client is told at the end.
    #[test]
    fn a_chat_client_is_sent_a_custom_call_once_it_is_named() {
        let delta = |id: Option<&str>, name: Option<&str>, text: &str, form| DomainEvent::ToolCallDelta {
            index: 0,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: text.to_string(),
            form,
        };
        let open = crate::api::domain_request::FREEFORM_ARGS_OPEN;
        let done = DomainEvent::Done { finish_reason: Some(FinishReason::ToolCalls), native_finish_reason: None };
        let openings = [
            delta(Some("call_1"), None, open, CallArguments::FreeformPiece),
            delta(Some("call_1"), None, "", CallArguments::Json),
        ];
        for opening in openings {
            let mut builder = ChatCompletionsResponseBuilder::new("m".into(), "c".into())
                .with_freeform_tools(["apply_patch".to_string()].into());
            let second = if matches!(opening, DomainEvent::ToolCallDelta { form: CallArguments::Json, .. }) {
                format!("{open}*** Begin ")
            } else {
                "*** Begin ".to_string()
            };
            let mut frames = builder.process_event(&opening);
            frames.extend(builder.process_event(&delta(None, Some("apply_patch"), &second, CallArguments::FreeformPiece)));
            frames.extend(builder.process_event(&delta(None, None, "Patch", CallArguments::FreeformPiece)));
            frames.extend(builder.process_event(&DomainEvent::FreeformCallEnd { index: 0 }));
            frames.extend(builder.process_event(&done));
            let calls: Vec<Value> = sse_data(&frames)
                .iter()
                .flat_map(|v| v["choices"][0]["delta"]["tool_calls"].as_array().cloned().unwrap_or_default())
                .collect();
            assert!(calls.iter().all(|c| c["type"] == "custom"), "{calls:?}");
            assert_eq!(calls[0]["id"], "call_1", "{calls:?}");
            assert_eq!(calls[0]["custom"]["name"], "apply_patch", "{calls:?}");
            let text: String = calls.iter().filter_map(|c| c["custom"]["input"].as_str()).collect();
            assert_eq!(text, "*** Begin Patch");
        }
        // Named by nothing: held to the end, then told in the call's place —
        // no client can run a call without a name.
        let mut builder = ChatCompletionsResponseBuilder::new("m".into(), "c".into());
        let mut frames = builder.process_event(&delta(Some("call_9"), None, "{}", CallArguments::Json));
        assert!(frames.is_empty(), "{frames:?}");
        frames.extend(builder.process_event(&done));
        let data = sse_data(&frames);
        assert!(data.iter().all(|v| v["choices"][0]["delta"]["tool_calls"].is_null()), "{frames:?}");
        let text: String = data.iter().filter_map(|v| v["choices"][0]["delta"]["content"].as_str()).collect();
        assert_eq!(text, crate::pipeline::response::NAMELESS_CALL_NOTICE);
    }

    /// Text after a tool call is a block of its own: the call's block is
    /// closed before the text's starts, each at its own index.
    #[test]
    fn text_after_a_call_opens_a_block_of_its_own() {
        let mut builder = AnthropicResponseBuilder::new("m".into(), "req1".into(), None, None, 0, 0);
        let mut frames = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".into()),
            function_name: Some("Read".into()),
            arguments_delta: "{}".into(),
            form: CallArguments::Json,
        });
        frames.extend(builder.process_event(&DomainEvent::TextDelta("ok".into())));
        frames.extend(builder.process_event(&DomainEvent::Done { finish_reason: Some(FinishReason::ToolCalls), native_finish_reason: None }));
        frames.extend(builder.flush_pending());
        let events: Vec<(String, u64)> = frames
            .iter()
            .flat_map(|f| f.lines())
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["type"] == "content_block_start" || v["type"] == "content_block_stop")
            .map(|v| (v["type"].as_str().unwrap_or_default().to_string(), v["index"].as_u64().unwrap_or(99)))
            .collect();
        let expected = [("content_block_start", 0), ("content_block_stop", 0), ("content_block_start", 1), ("content_block_stop", 1)]
            .map(|(t, i)| (t.to_string(), i));
        assert_eq!(events, expected, "{frames:?}");
    }

    #[test]
    fn force_close_truncated_emits_a_max_tokens_stop_when_stream_cut() {
        // Simulate: message_start + some text_deltas, then upstream EOF without
        // Done/Usage (vLLM hitting max_tokens and closing the socket).
        let mut builder = AnthropicResponseBuilder::new(
            "devstral".into(),
            "req1".into(),
            None,
            None,
            0,
            0,
        );
        // Client sees: message_start + content_block_start + content_block_delta
        let _ = builder.process_event(&DomainEvent::TextDelta("partial output".into()));
        assert!(builder.message_started);
        assert!(builder.has_text_block);

        // Upstream dies. Synthesize the clean close.
        let events = builder.force_close_truncated();
        // Expect: content_block_stop, message_delta (max_tokens), message_stop
        assert_eq!(events.len(), 3, "unexpected sequence: {events:?}");
        assert!(events[0].contains("content_block_stop"), "got: {}", events[0]);
        // A truncation in Anthropic's own word: `length` is no Messages API
        // `stop_reason`.
        assert!(events[1].contains("\"stop_reason\":\"max_tokens\""),
            "message_delta must carry stop_reason=max_tokens, got: {}", events[1]);
        assert!(events[2].contains("message_stop"), "got: {}", events[2]);
    }

    #[test]
    fn force_close_truncated_is_noop_if_message_never_started() {
        // Zero events, emitter hasn't sent message_start yet — the caller's
        // zero-token guard uses the `overloaded_error` path instead; this
        // synthesizer must refuse to emit a malformed close.
        let mut builder = AnthropicResponseBuilder::new(
            "devstral".into(),
            "req1".into(),
            None,
            None,
            0,
            0,
        );
        let events = builder.force_close_truncated();
        assert!(events.is_empty());
    }

    #[test]
    fn force_close_truncated_prefers_pending_stop_reason_over_the_synthetic_truncation() {
        // If a Done event arrived but the Usage chunk was lost, the authoritative
        // stop_reason from upstream must be preserved — don't overwrite with
        // synthetic truncation.
        let mut builder = AnthropicResponseBuilder::new(
            "devstral".into(),
            "req1".into(),
            None,
            None,
            0,
            0,
        );
        let _ = builder.process_event(&DomainEvent::TextDelta("output".into()));
        // Done defers until Usage — here Usage never arrives.
        let _ = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".into()),
        });
        let events = builder.force_close_truncated();
        assert!(events.iter().any(|e| e.contains("\"stop_reason\":\"end_turn\"")),
            "Done's stop_reason must win over the synthetic truncation: {events:?}");
    }

    #[test]
    fn response_builder_text_streaming() {
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        // Should have: message_start, content_block_start, content_block_delta
        assert_eq!(events.len(), 3);
        assert!(events[0].contains("message_start"));
        assert!(events[1].contains("content_block_start"));
        assert!(events[2].contains("text_delta"));

        let events = builder.process_event(&DomainEvent::TextDelta(" world".to_string()));
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("text_delta"));

        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });
        // Done defers message_delta/message_stop — flush to emit them
        events.extend(builder.flush_pending());
        // content_block_stop, message_delta, message_stop
        assert_eq!(events.len(), 3);
        assert!(events[0].contains("content_block_stop"));
        assert!(events[1].contains("end_turn"));
        assert!(events[2].contains("message_stop"));
    }

    #[test]
    fn response_builder_tool_call_streaming() {
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        // Text first
        builder.process_event(&DomainEvent::TextDelta("Let me check.".to_string()));

        // Tool call start
        let events = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("get_weather".to_string()),
            arguments_delta: String::new(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Should close text block, start tool block
        assert!(events.iter().any(|e| e.contains("content_block_stop")));
        assert!(events.iter().any(|e| e.contains("tool_use")));

        // Tool call arguments
        let events = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: r#"{"loc"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(events[0].contains("input_json_delta"));

        // Done with tool_use finish reason
        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::ToolCalls),
            native_finish_reason: Some("tool_calls".to_string()),
        });
        events.extend(builder.flush_pending());
        assert!(events.iter().any(|e| e.contains("tool_use")));
    }

    #[test]
    fn anthropic_renders_substitution_server_tool_use_and_result() {
        // Visible-mode emulation. The substitution agent loop emits a
        // synthesised `ServerToolCallDelta` + `ServerToolResult` pair when
        // an enabled `WS-SUB-AC-WEB-SEARCH` rule fires; the renderer must
        // translate them into Anthropic's native `server_tool_use` +
        // `web_search_tool_result` content_block pair so the client sees
        // the same wire shape it asked for.
        let mut builder = AnthropicResponseBuilder::new(
            "claude-3-5-sonnet".to_string(),
            "abcdef0123".to_string(),
            None,
            None,
            0,
            0,
        );

        // Preamble text first — the model usually prefixes a reasoning
        // sentence before invoking the search.
        builder.process_event(&DomainEvent::TextDelta("Let me search.".to_string()));

        // Synthesised server-tool call. The agent loop's `tool_use_id`
        // must round-trip onto both `server_tool_use.id` and
        // `web_search_tool_result.tool_use_id` so conformant clients can
        // pair the call with its result.
        let call_id = "tu_sub_abc_0";
        let events = builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: call_id.to_string(),
            server_type: "web_search_20250305".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"rust async streams"}"#.to_string(),
        });
        // Closes the text block, opens server_tool_use, emits arg-delta,
        // closes server_tool_use. The text-block close + tool-block close
        // increment content_index twice so the next block lands at index 2.
        let joined = events.join("\n");
        assert!(joined.contains("\"type\":\"server_tool_use\""));
        assert!(joined.contains(&format!("\"id\":\"{call_id}\"")));
        assert!(joined.contains("\"name\":\"web_search\""));
        assert!(joined.contains("\"partial_json\":\"{\\\"query\\\":\\\"rust async streams\\\"}\""));
        assert!(joined.contains("\"index\":1"), "server_tool_use should land at index 1 after text-block at 0: {joined}");

        // Synthesised result block — Anthropic shape with structured hits.
        // Same `tool_use_id` as the call (correlation invariant).
        let result_events = builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: call_id.to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/a", "title": "Hit A"}],
                "total_filtered": 0,
                "backend": "searxng"
            }),
        });
        let joined = result_events.join("\n");
        assert!(joined.contains("\"type\":\"web_search_tool_result\""));
        assert!(joined.contains(&format!("\"tool_use_id\":\"{call_id}\"")));
        assert!(joined.contains("\"type\":\"web_search_result\""));
        assert!(joined.contains("\"url\":\"https://example.com/a\""));
        assert!(joined.contains("\"index\":2"), "result should land at index 2: {joined}");

        // Error variant nests inline in `web_search_tool_result.content`.
        let err_events = builder.process_event(&DomainEvent::ServerToolError {
            index: 1,
            tool_use_id: "tu_sub_abc_1".to_string(),
            error_kind: "rate_limited".to_string(),
        });
        let joined = err_events.join("\n");
        assert!(joined.contains("\"type\":\"web_search_tool_result_error\""));
        assert!(joined.contains("\"error_code\":\"too_many_requests\""));
    }

    #[test]
    fn anthropic_search_result_content_maps_typed_payloads() {
        // SearchResult → array of web_search_result blocks with page_age
        // when published is set.
        let search = serde_json::json!({
            "hits": [
                {"url": "https://a", "title": "A", "published": "2026-01-02"},
                {"url": "https://b", "title": "B"},
            ],
            "total_filtered": 0,
            "backend": "searxng"
        });
        let v = anthropic_search_result_content(&search);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["page_age"], "2026-01-02");
        assert!(arr[1].get("page_age").is_none());

        // FetchResult → single document with extracted_text under
        // encrypted_content (Anthropic's slot for prefetched body).
        let fetch = serde_json::json!({
            "url": "https://x",
            "final_url": "https://x/y",
            "content_type": "text/html",
            "status": 200,
            "extracted_text": "Body",
            "redirect_chain": [],
            "extracted_size": 4,
            "raw_size": 100
        });
        let v = anthropic_search_result_content(&fetch);
        let arr = v.as_array().unwrap();
        assert_eq!(arr[0]["url"], "https://x/y");
        assert_eq!(arr[0]["encrypted_content"], "Body");

        // Opaque payload — wrapped, not silently dropped. Raw JSON lands
        // in `encrypted_content` so UIs that surface `title` don't render
        // a JSON blob.
        let opaque = serde_json::json!({"weird": "shape"});
        let v = anthropic_search_result_content(&opaque);
        let block = &v.as_array().unwrap()[0];
        assert_eq!(block["title"], "opaque executor result");
        assert!(
            block["encrypted_content"]
                .as_str()
                .unwrap()
                .contains("weird"),
            "raw payload must round-trip into encrypted_content: {block:?}"
        );
    }

    #[test]
    fn openai_response_to_anthropic_text() {
        let oai_response = serde_json::json!({
            "id": "chatcmpl-123",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });

        let result = openai_response_to_anthropic(&oai_response, "gpt-4o", "abc12345", 10, None, None, 0);

        assert_eq!(result["type"], "message");
        assert_eq!(result["role"], "assistant");
        assert_eq!(result["stop_reason"], "end_turn");
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "Hello!");
        assert_eq!(result["usage"]["input_tokens"], 10);
        assert_eq!(result["usage"]["output_tokens"], 5);
    }

    #[test]
    fn openai_response_to_anthropic_tool_calls() {
        let oai_response = serde_json::json!({
            "id": "chatcmpl-123",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"location\":\"SF\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 15, "total_tokens": 25}
        });

        let result = openai_response_to_anthropic(&oai_response, "gpt-4o", "abc12345", 10, None, None, 0);

        assert_eq!(result["stop_reason"], "tool_use");
        assert_eq!(result["content"][0]["type"], "tool_use");
        assert_eq!(result["content"][0]["name"], "get_weather");
        assert_eq!(result["content"][0]["input"]["location"], "SF");
    }

    // ─── Cross-protocol cache-usage surfacing (client-visibility) ───

    #[test]
    fn openai_to_anthropic_surfaces_cache_read() {
        let oai = serde_json::json!({
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105,
                      "prompt_tokens_details": {"cached_tokens": 80}}
        });
        let r = openai_response_to_anthropic(&oai, "gpt-4o", "abc12345", 100, None, None, 0);
        assert_eq!(r["usage"]["cache_read_input_tokens"], 80);
        assert_eq!(r["usage"]["cache_creation_input_tokens"], 0);
        // input_tokens must be disjoint from cache (Anthropic wire): 100 incl − 80 = 20.
        assert_eq!(r["usage"]["input_tokens"], 20);
    }

    #[test]
    fn gemini_to_anthropic_surfaces_cache_read() {
        let g = serde_json::json!({
            "candidates": [{"content": {"parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 5, "cachedContentTokenCount": 60}
        });
        let r = gemini_response_to_anthropic(&g, "gemini-2.5-flash", "abcdef012345", None, None, 0);
        assert_eq!(r["usage"]["cache_read_input_tokens"], 60);
        assert_eq!(r["usage"]["cache_creation_input_tokens"], 0);
        // 100 incl − 60 = 40, disjoint from cache_read.
        assert_eq!(r["usage"]["input_tokens"], 40);
    }

    #[test]
    fn anthropic_to_gemini_surfaces_cache_read_only() {
        // cache_read → cachedContentTokenCount; cache_creation (a premium write,
        // not a hit) must NOT be folded into the cached count.
        let a = serde_json::json!({
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 5,
                      "cache_read_input_tokens": 40, "cache_creation_input_tokens": 25}
        });
        let r = anthropic_to_gemini_response(&a);
        assert_eq!(r["usageMetadata"]["cachedContentTokenCount"], 40);
        // Gemini promptTokenCount INCLUDES cached: 100 excl + 40 read + 25 creation = 165.
        assert_eq!(r["usageMetadata"]["promptTokenCount"], 165);
    }

    #[test]
    fn anthropic_to_responses_surfaces_cache_read_only() {
        let a = serde_json::json!({
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 5,
                      "cache_read_input_tokens": 40, "cache_creation_input_tokens": 25}
        });
        let r = anthropic_to_responses_response(&a, "claude", "abcdef012345");
        assert_eq!(r["usage"]["input_tokens_details"]["cached_tokens"], 40);
        // Responses input_tokens INCLUDES cached: 100 excl + 40 + 25 = 165.
        assert_eq!(r["usage"]["input_tokens"], 165);
    }

    #[test]
    fn anthropic_to_chat_includes_cache_in_prompt() {
        let a = serde_json::json!({
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 5,
                      "cache_read_input_tokens": 40, "cache_creation_input_tokens": 25}
        });
        let r = anthropic_to_chat_completions(&a, "claude");
        assert_eq!(r["usage"]["prompt_tokens_details"]["cached_tokens"], 40);
        // ChatCompletions prompt_tokens INCLUDES cached: 100 excl + 40 + 25 = 165.
        assert_eq!(r["usage"]["prompt_tokens"], 165);
        assert_eq!(r["usage"]["total_tokens"], 170);
    }

    #[test]
    fn response_builder_tracks_output_tokens() {
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        // Emit text
        builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));

        // Emit usage with output tokens
        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 10,
            completion_tokens: 25,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 35,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        // Done
        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });
        events.extend(builder.flush_pending());

        // message_delta should contain output_tokens: 25
        let message_delta = events.iter().find(|e| e.contains("message_delta")).unwrap();
        assert!(message_delta.contains("\"output_tokens\":25"), "expected output_tokens: 25, got: {message_delta}");
    }

    #[test]
    fn chat_completions_to_responses_text() {
        let oai_response = serde_json::json!({
            "id": "chatcmpl-123",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });

        let result = chat_completions_to_responses_response(&oai_response, "gpt-4o", "resp_123");
        assert_eq!(result["object"], "response");
        assert_eq!(result["status"], "completed");
        assert_eq!(result["output"][0]["type"], "message");
        assert_eq!(result["output"][0]["content"][0]["type"], "output_text");
        assert_eq!(result["output"][0]["content"][0]["text"], "Hello!");
        assert_eq!(result["usage"]["input_tokens"], 10);
        assert_eq!(result["usage"]["output_tokens"], 5);
    }

    #[test]
    fn responses_builder_text_streaming() {
        let mut builder = ResponsesResponseBuilder::new(
            "resp_123".to_string(),
            "gpt-4o".to_string(),
        );

        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        // response.created, output_item.added, content_part.added, output_text.delta
        assert_eq!(events.len(), 4);
        assert!(events[0].contains("response.created"));
        assert!(events[1].contains("response.output_item.added"));
        assert!(events[2].contains("response.content_part.added"));
        assert!(events[3].contains("response.output_text.delta"));

        let events = builder.process_event(&DomainEvent::TextDelta(" world".to_string()));
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("response.output_text.delta"));

        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });
        // No usage followed: the stream-end flush sends the held completion.
        events.extend(builder.flush_pending());
        assert!(events.iter().any(|e| e.contains("response.completed")));
        assert!(events.iter().any(|e| e.contains("\"completed\"")));
    }

    /// A Chat upstream sends usage in the chunk AFTER `finish_reason`. The
    /// completion waits for it, so the client reads real token counts — and a
    /// capped answer says why it is incomplete.
    #[test]
    fn responses_completed_carries_usage_that_follows_the_finish() {
        let mut builder = ResponsesResponseBuilder::new("resp_1234".to_string(), "m".to_string());
        builder.process_event(&DomainEvent::TextDelta("Hi".to_string()));
        let at_done = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Length),
            native_finish_reason: Some("length".to_string()),
        });
        assert!(!at_done.iter().any(|e| e.contains("response.incomplete")), "held for the usage");
        let after = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 12,
            completion_tokens: 8,
            total_tokens: 20,
            ..Default::default()
        }));
        let completed = sse_data(&after).into_iter().last().unwrap();
        assert_eq!(completed["type"], "response.incomplete", "a capped answer closes with its own event");
        assert_eq!(completed["response"]["usage"]["output_tokens"], 8);
        assert_eq!(completed["response"]["status"], "incomplete");
        assert_eq!(completed["response"]["incomplete_details"]["reason"], "max_output_tokens");
        assert!(builder.flush_pending().is_empty(), "sent once");

        // A filtered stream says so, even when no usage follows.
        let mut filtered = ResponsesResponseBuilder::new("resp_5678".to_string(), "m".to_string());
        filtered.process_event(&DomainEvent::TextDelta("Hi".to_string()));
        filtered.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::ContentFilter),
            native_finish_reason: Some("content_filter".to_string()),
        });
        let flushed = filtered.flush_pending();
        let completed = sse_data(&flushed).into_iter().last().unwrap();
        assert_eq!(completed["response"]["incomplete_details"]["reason"], "content_filter");
    }

    /// The data of every `data:` line a builder emitted, parsed.
    fn sse_data(frames: &[String]) -> Vec<serde_json::Value> {
        frames
            .iter()
            .flat_map(|f| f.lines())
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|d| *d != "[DONE]")
            .map(|d| serde_json::from_str(d).unwrap())
            .collect()
    }

    /// A mid-stream error from each upstream's vocabulary reaches an OpenAI
    /// client in OpenAI's: a foreign code translated, an OpenAI one as sent.
    #[test]
    fn an_upstream_stream_error_reaches_openai_clients_in_their_own_grammar() {
        for (code, want) in [
            (Some("context_length_exceeded"), "context_length_exceeded"),
            (Some("rate_limit_error"), "rate_limit_exceeded"),
            (Some("RESOURCE_EXHAUSTED"), "rate_limit_exceeded"),
        ] {
            let error = DomainEvent::Error { message: "boom".into(), code: code.map(String::from) };

            let mut chat = ChatCompletionsResponseBuilder::new("m".into(), "chatcmpl-1".into());
            let frames = chat.process_event(&error);
            assert_eq!(frames.last().map(String::as_str), Some("data: [DONE]\n\n"));
            let [chunk] = sse_data(&frames).try_into().unwrap();
            assert_eq!(chunk["error"]["code"], want, "{code:?}: {chunk}");
            assert_eq!(chunk["error"]["type"], "upstream_error");
            assert_eq!(chunk["error"]["message"], "boom");

            let mut responses = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
            // A first event opens the response (`response.created`) before it.
            let frames: Vec<String> = responses
                .process_event(&error)
                .into_iter()
                .filter(|f| f.starts_with("event: error\n"))
                .collect();
            let [event] = sse_data(&frames).try_into().unwrap();
            assert_eq!(event["type"], "error");
            assert_eq!(event["code"], want, "{code:?}: {event}");
            assert_eq!(event["message"], "boom");
            assert!(event.get("error").is_none(), "{event}");
        }
    }

    /// Every event of a translated Responses stream carries the
    /// `sequence_number` the spec requires: its position, from 0, with no gap
    /// across `process_event` calls.
    #[test]
    fn every_responses_stream_event_is_numbered_in_order() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        let mut frames = Vec::new();
        for event in [
            DomainEvent::ReasoningDelta("think".into()),
            DomainEvent::TextDelta("Hello".into()),
            DomainEvent::TextDelta(" world".into()),
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("bash".into()),
                arguments_delta: "{}".into(),
                form: crate::api::domain::CallArguments::Json,
            },
            DomainEvent::Error { message: "boom".into(), code: None },
            DomainEvent::Done { finish_reason: Some(FinishReason::Stop), native_finish_reason: None },
        ] {
            frames.extend(builder.process_event(&event));
        }
        frames.extend(builder.flush_pending());
        let events = sse_data(&frames);
        assert!(events.len() > 6, "{frames:?}");
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event["sequence_number"], i as u64, "event {i}: {event}");
        }
    }

    /// A translated Responses stream closes every item the way the spec
    /// frames it: each item closes before the next opens, every closing event
    /// restates the whole content the deltas carried, every event names its
    /// item by the id `output_item.added` announced, and `response.completed`
    /// carries the closed items as its `output`. A client that assembles its
    /// answer from the done events (Codex) reads what the deltas streamed.
    #[test]
    fn a_translated_responses_stream_closes_every_item_with_its_content() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        let call = |id: Option<&str>, name: Option<&str>, args: &str| DomainEvent::ToolCallDelta {
            index: 0,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: args.into(),
            form: crate::api::domain::CallArguments::Json,
        };
        let mut frames = Vec::new();
        // A Responses upstream numbers every call 0; the stream parser gives
        // each its own number.
        let mut parser = crate::api::sse::StreamParser::new(crate::api::sse::ApiVersion::Responses);
        for event in parser.number(vec![
            DomainEvent::ReasoningDelta("Let me ".into()),
            DomainEvent::ReasoningDelta("think.".into()),
            DomainEvent::TextDelta("Hello".into()),
            DomainEvent::TextDelta(" world".into()),
            call(Some("call_1"), Some("bash"), ""),
            call(None, None, "{\"cmd\":"),
            call(None, None, "\"ls\"}"),
            // A second call at the same upstream index is a new call.
            call(Some("call_2"), Some("read"), "{}"),
            DomainEvent::Done { finish_reason: Some(FinishReason::ToolCalls), native_finish_reason: None },
            DomainEvent::Usage(Usage { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7, ..Default::default() }),
        ]) {
            frames.extend(builder.process_event(&event));
        }
        frames.extend(builder.flush_pending());
        let events = sse_data(&frames);

        let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
        assert_eq!(types, [
            "response.created",
            "response.output_item.added",
            "response.reasoning_summary_part.added",
            "response.reasoning_summary_text.delta",
            "response.reasoning_summary_text.delta",
            "response.reasoning_summary_text.done",
            "response.reasoning_summary_part.done",
            "response.output_item.done",
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            // Each call its own item, open until the response ends (a
            // call's end is the response's: calls may interleave).
            "response.output_item.added",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.delta",
            "response.output_item.added",
            "response.function_call_arguments.delta",
            "response.function_call_arguments.done",
            "response.output_item.done",
            "response.function_call_arguments.done",
            "response.output_item.done",
            "response.completed",
        ]);

        // Every event names its item by the id announced for that index.
        let mut ids = std::collections::HashMap::new();
        for e in &events {
            if e["type"] == "response.output_item.added" {
                ids.insert(e["output_index"].as_u64().unwrap(), e["item"]["id"].clone());
            } else if let Some(item_id) = e.get("item_id") {
                assert_eq!(Some(item_id), ids.get(&e["output_index"].as_u64().unwrap()), "{e}");
            }
        }
        assert_eq!(ids.len(), 4, "four items, four distinct indexes: {ids:?}");
        let distinct: std::collections::HashSet<String> = ids.values().map(|v| v.to_string()).collect();
        assert_eq!(distinct.len(), 4, "item ids are unique: {ids:?}");

        let done = |t: &str| events.iter().filter(move |e| e["type"] == t).collect::<Vec<_>>();
        assert_eq!(done("response.reasoning_summary_text.done")[0]["text"], "Let me think.");
        assert_eq!(done("response.reasoning_summary_part.done")[0]["part"]["text"], "Let me think.");
        assert_eq!(done("response.output_text.done")[0]["text"], "Hello world");
        assert_eq!(done("response.content_part.done")[0]["part"]["text"], "Hello world");
        let args: Vec<&Value> = done("response.function_call_arguments.done").iter().map(|e| &e["arguments"]).collect();
        assert_eq!(args, [&Value::from("{\"cmd\":\"ls\"}"), &Value::from("{}")]);

        let items: Vec<Value> = done("response.output_item.done").iter().map(|e| e["item"].clone()).collect();
        assert_eq!(items[0]["type"], "reasoning");
        assert_eq!(items[0]["summary"], serde_json::json!([{"type": "summary_text", "text": "Let me think."}]));
        assert_eq!(items[1]["type"], "message");
        assert_eq!(items[1]["status"], "completed");
        assert_eq!(items[1]["content"][0]["type"], "output_text");
        assert_eq!(items[1]["content"][0]["text"], "Hello world");
        assert_eq!(items[1]["content"][0]["annotations"], serde_json::json!([]));
        for (item, (call_id, name, arguments)) in items[2..].iter().zip([
            ("call_1", "bash", "{\"cmd\":\"ls\"}"),
            ("call_2", "read", "{}"),
        ]) {
            assert_eq!(item["type"], "function_call");
            assert_eq!(item["status"], "completed");
            assert_eq!((item["call_id"].as_str(), item["name"].as_str()), (Some(call_id), Some(name)));
            assert_eq!(item["arguments"], arguments);
        }
        for (item, index) in items.iter().zip(0u64..) {
            assert_eq!(&item["id"], &ids[&index], "{item}");
        }

        let completed = &events.last().unwrap()["response"];
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["output"], Value::Array(items), "the final response lists every closed item");
        assert_eq!(completed["usage"]["output_tokens"], 4);
    }

    /// How upstreams frame tool calls, and the calls a Responses client must
    /// get: a server restating the id or the name on every delta (a trailing
    /// empty one included), and Gemini sending each call whole at index 0.
    #[test]
    fn restated_and_whole_tool_calls_become_the_calls_the_upstream_meant() {
        use crate::api::sse::ApiVersion;
        let call = |index: usize, id: Option<&str>, name: Option<&str>, args: &str| DomainEvent::ToolCallDelta {
            index,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: args.into(),
            form: crate::api::domain::CallArguments::Json,
        };
        // The stream parser numbers the upstream's calls; the builder writes
        // the calls it numbered.
        let calls_from = |upstream: ApiVersion, events: Vec<DomainEvent>| -> Vec<(String, String, String)> {
            let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
            let mut parser = crate::api::sse::StreamParser::new(upstream);
            let mut frames = Vec::new();
            for e in &parser.number(events) {
                frames.extend(builder.process_event(e));
            }
            frames.extend(builder.process_event(&DomainEvent::Done {
                finish_reason: Some(FinishReason::ToolCalls),
                native_finish_reason: None,
            }));
            frames.extend(builder.flush_pending());
            sse_data(&frames)
                .into_iter()
                .filter(|e| e["type"] == "response.output_item.done" && e["item"]["type"] == "function_call")
                .map(|e| {
                    let item = &e["item"];
                    (item["call_id"].as_str().unwrap().to_string(),
                     item["name"].as_str().unwrap().to_string(),
                     item["arguments"].as_str().unwrap().to_string())
                })
                .collect()
        };
        let calls = |events| calls_from(ApiVersion::ChatCompletions, events);
        let one = vec![("c1".to_string(), "bash".to_string(), "{\"cmd\":\"ls\"}".to_string())];
        // The id restated on every delta.
        assert_eq!(calls(vec![
            call(0, Some("c1"), Some("bash"), "{\"cmd\":"),
            call(0, Some("c1"), None, "\"ls\"}"),
        ]), one);
        // The name restated on every delta, a trailing empty one included.
        assert_eq!(calls(vec![
            call(0, Some("c1"), Some("bash"), "{\"cmd\":"),
            call(0, None, Some("bash"), "\"ls\"}"),
            call(0, None, Some("bash"), ""),
        ]), one);
        // The name first, the id later: one call, announced under the
        // upstream's id — the one the audit and a policy rewrite carry.
        assert_eq!(calls(vec![
            call(0, None, Some("bash"), "{\"cmd\":"),
            call(0, Some("c1"), None, "\"ls\"}"),
        ]), one);
        // Arguments naming nothing continue the open call whatever index they
        // carry (a lax server sends none after the first).
        assert_eq!(calls(vec![
            call(1, Some("c1"), Some("bash"), "{\"cmd\":"),
            call(0, None, None, "\"ls\"}"),
        ]), one);
        // Gemini: each call whole, each at index 0 of its own chunk, an id or not.
        assert_eq!(calls_from(ApiVersion::GoogleGemini, vec![
            call(0, None, Some("read"), "{\"path\":\"a\"}"),
            call(0, None, Some("read"), "{\"path\":\"b\"}"),
        ]), vec![
            // Each id-less call is given its own id to be answered by.
            ("call_1_0".to_string(), "read".to_string(), "{\"path\":\"a\"}".to_string()),
            ("call_1_1".to_string(), "read".to_string(), "{\"path\":\"b\"}".to_string()),
        ]);
        // A second call at the next index.
        assert_eq!(calls(vec![call(0, Some("c1"), Some("a"), "{}"), call(1, Some("c2"), Some("b"), "{}")]).len(), 2);
        // Parallel calls whose arguments arrive interleaved: each reaches its own.
        assert_eq!(calls(vec![
            call(0, Some("c1"), Some("bash"), ""),
            call(1, Some("c2"), Some("read"), ""),
            call(0, None, None, "{\"cmd\":\"ls\"}"),
            call(1, None, None, "{}"),
        ]), vec![
            ("c1".to_string(), "bash".to_string(), "{\"cmd\":\"ls\"}".to_string()),
            ("c2".to_string(), "read".to_string(), "{}".to_string()),
        ]);
        // A call closed by text, then restated by its id: its late bytes are
        // withheld, never a second item under the same call id.
        assert_eq!(calls(vec![
            call(0, Some("c1"), Some("bash"), "{\"cmd\":\"ls\"}"),
            DomainEvent::TextDelta("Running it.".into()),
            call(0, Some("c1"), None, ""),
        ]), one);
        // An Anthropic upstream numbers every block, so arguments at an index
        // no call carries (a server tool's input) never join an open call.
        assert_eq!(calls_from(ApiVersion::AnthropicMessages, vec![
            call(1, Some("c1"), Some("bash"), "{\"cmd\":\"ls\"}"),
            call(2, None, None, "{\"query\":\"x\"}"),
        ]), one);
    }

    /// A delta the upstream sends after its finish still lands in the message
    /// the response closes; once the response has completed, nothing opens.
    #[test]
    fn content_after_the_finish_lands_in_the_message_until_the_response_completes() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        let mut frames = builder.process_event(&DomainEvent::TextDelta("Hel".into()));
        frames.extend(builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: None,
        }));
        frames.extend(builder.process_event(&DomainEvent::TextDelta("lo".into())));
        assert!(!builder.terminal_sent(), "the finish alone hands the client no end");
        frames.extend(builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 1,
            completion_tokens: 2,
            total_tokens: 3,
            ..Default::default()
        })));
        assert!(builder.terminal_sent());
        let events = sse_data(&frames);
        let text_done: Vec<&Value> =
            events.iter().filter(|e| e["type"] == "response.output_text.done").collect();
        assert_eq!(text_done.len(), 1);
        assert_eq!(text_done[0]["text"], "Hello");
        assert_eq!(events.last().unwrap()["response"]["output"][0]["content"][0]["text"], "Hello");

        let after = builder.process_event(&DomainEvent::TextDelta("!".into()));
        assert!(after.is_empty(), "{after:?}");
        assert!(builder.flush_pending().is_empty());
    }

    /// A call the output cap cut off closes `incomplete`: its arguments may be
    /// partial, and a client must not run it as a finished call.
    #[test]
    fn a_call_cut_off_by_the_cap_closes_incomplete() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        let mut frames = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("c1".into()),
            function_name: Some("bash".into()),
            arguments_delta: "{\"cmd\":".into(),
            form: crate::api::domain::CallArguments::Json,
        });
        frames.extend(builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Length),
            native_finish_reason: None,
        }));
        frames.extend(builder.flush_pending());
        let events = sse_data(&frames);
        let done: Vec<&Value> = events.iter().filter(|e| e["type"] == "response.output_item.done").collect();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0]["item"]["status"], "incomplete");
        assert_eq!(events.last().unwrap()["response"]["output"][0]["status"], "incomplete");
    }

    /// A message stopped at the output cap is closed `incomplete`, and a
    /// repeated `Done` closes nothing twice.
    #[test]
    fn a_capped_message_closes_incomplete_once() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".into(), "m".into());
        builder.process_event(&DomainEvent::TextDelta("Hel".into()));
        let done = DomainEvent::Done { finish_reason: Some(FinishReason::Length), native_finish_reason: None };
        let mut frames = builder.process_event(&done);
        frames.extend(builder.process_event(&done));
        frames.extend(builder.flush_pending());
        let events = sse_data(&frames);
        let item_done: Vec<&Value> =
            events.iter().filter(|e| e["type"] == "response.output_item.done").collect();
        assert_eq!(item_done.len(), 1, "{events:?}");
        assert_eq!(item_done[0]["item"]["status"], "incomplete");
        assert_eq!(item_done[0]["item"]["content"][0]["text"], "Hel");
        let last = events.last().unwrap();
        assert_eq!(last["type"], "response.incomplete");
        assert_eq!(last["response"]["output"][0]["content"][0]["text"], "Hel");
    }

    // ─── ChatCompletionsResponseBuilder: finish_reason override ───

    #[test]
    fn chat_completions_builder_overrides_stop_to_tool_calls() {
        let mut builder =
            ChatCompletionsResponseBuilder::new("gpt-4o".to_string(), "chatcmpl-123".to_string());

        // Stream a tool call
        let events = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("bash".to_string()),
            arguments_delta: String::new(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(!events.is_empty());
        assert!(events[0].contains("tool_calls"));

        let events = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: r#"{"cmd":"ls"}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(events[0].contains("tool_calls"));

        // Responses API sends "completed" → mapped to FinishReason::Stop
        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("completed".to_string()),
        });
        events.extend(builder.flush_pending());
        // Should be overridden to "tool_calls" in the output
        let combined = events.join("");
        assert!(
            combined.contains("\"tool_calls\""),
            "finish_reason should be tool_calls, got: {combined}"
        );
        assert!(!combined.contains("\"finish_reason\":\"stop\""));
    }

    // ─── Response translation: reasoning + refusal ───

    #[test]
    fn responses_to_anthropic_handles_reasoning_items() {
        let response_json = serde_json::json!({
            "id": "resp_123",
            "status": "completed",
            "output": [
                {
                    "type": "reasoning",
                    "content": [{"type": "text", "text": "Let me think about this..."}]
                },
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "The answer is 42."}]
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
        });

        let result = responses_response_to_anthropic(
            &response_json, "gpt-4o", "msg_123", None, None, 0,
        );
        let content = result["content"].as_array().unwrap();
        // Should have thinking block + text block
        let types: Vec<&str> = content.iter()
            .map(|b| b["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"thinking"), "missing thinking block: {types:?}");
        assert!(types.contains(&"text"), "missing text block: {types:?}");
    }

    #[test]
    fn responses_to_anthropic_handles_refusal() {
        let response_json = serde_json::json!({
            "id": "resp_123",
            "status": "completed",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "refusal", "text": "I cannot help with that."}]
            }],
            "usage": {"input_tokens": 5, "output_tokens": 8, "total_tokens": 13}
        });

        let result = responses_response_to_anthropic(
            &response_json, "gpt-4o", "msg_123", None, None, 0,
        );
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty(), "refusal should produce content blocks");
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "I cannot help with that.");
    }

    #[test]
    fn responses_to_chat_completions_handles_refusal() {
        let response_json = serde_json::json!({
            "id": "resp_123",
            "status": "completed",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{"type": "refusal", "text": "I cannot do that."}]
            }],
            "usage": {"input_tokens": 5, "output_tokens": 8, "total_tokens": 13}
        });

        let result = responses_response_to_chat_completions(
            &response_json, "gpt-4o",
        );
        let message = &result["choices"][0]["message"];
        assert!(
            message["content"].as_str().unwrap().contains("I cannot do that."),
            "refusal text should appear in content"
        );
    }

    #[test]
    fn a_built_in_call_reaches_a_non_streaming_client_on_another_protocol_as_a_notice() {
        // Only a Responses client has the item to run: every other client gets
        // a notice in its place, never a call of another kind.
        let response_json = serde_json::json!({
            "id": "resp_123",
            "status": "completed",
            "output": [
                {"type": "local_shell_call", "id": "lsh_1", "call_id": "call_1", "status": "completed",
                 "action": {"type": "exec", "command": ["ls", "-la"], "env": {}}},
                {"type": "apply_patch_call", "id": "ap_1", "call_id": "call_2", "status": "completed",
                 "operation": {"type": "delete_file", "path": "a.txt"}}
            ],
            "usage": {"input_tokens": 5, "output_tokens": 8, "total_tokens": 13}
        });
        let chat = responses_response_to_chat_completions(&response_json, "gpt-4o");
        let message = &chat["choices"][0]["message"];
        assert!(message.get("tool_calls").is_none_or(Value::is_null), "{chat}");
        let text = message["content"].as_str().unwrap_or_default();
        assert!(text.contains("`local_shell`") && text.contains("`apply_patch`"), "{chat}");

        let anthropic = responses_response_to_anthropic(&response_json, "gpt-4o", "msg_123", None, None, 0);
        let blocks = anthropic["content"].as_array().unwrap();
        assert!(blocks.iter().all(|b| b["type"] == "text"), "{anthropic}");
        assert_eq!(blocks.len(), 2, "{anthropic}");

        let gemini = responses_to_gemini_response(&response_json);
        let parts = gemini["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert!(parts.iter().all(|p| p.get("functionCall").is_none() && p["text"].is_string()), "{gemini}");
        assert_eq!(parts.len(), 2, "{gemini}");

        // A shell call the server ran in its hosted container is no call the
        // client was owed: no notice stands in for it.
        let hosted = serde_json::json!({"status": "completed", "output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "c", "status": "completed",
             "action": {"commands": ["ls"]}, "environment": {"type": "container_auto"}}
        ]});
        let chat = responses_response_to_chat_completions(&hosted, "gpt-4o");
        assert!(!chat.to_string().contains("not carried"), "{chat}");
        assert!(!responses_to_gemini_response(&hosted).to_string().contains("not carried"));
        assert!(!responses_response_to_anthropic(&hosted, "m", "msg", None, None, 0).to_string().contains("not carried"));
    }

    #[test]
    fn chat_completions_builder_keeps_stop_without_tool_calls() {
        let mut builder =
            ChatCompletionsResponseBuilder::new("gpt-4o".to_string(), "chatcmpl-123".to_string());

        // Only text, no tool calls
        builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));

        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("completed".to_string()),
        });
        events.extend(builder.flush_pending());
        let combined = events.join("");
        assert!(combined.contains("\"stop\""));
    }

    // ─── Token reporting fix tests ───

    #[test]
    fn message_start_has_estimated_input_tokens() {
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 500, 0);

        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        let message_start = &events[0];
        assert!(
            message_start.contains("\"input_tokens\":500"),
            "message_start should contain estimated input_tokens: {message_start}"
        );
    }

    #[test]
    fn message_start_scales_estimated_tokens() {
        // client_context_window = 200K, upstream = 32K, max_output = 0 → scale = 6.25x
        let mut builder = AnthropicResponseBuilder::new(
            "gpt-4o".to_string(),
            "abc12345".to_string(),
            Some(32_000),
            Some(200_000),
            100,
            0,
        );

        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        let message_start = &events[0];
        // 100 * (200000/32000) = 625
        assert!(
            message_start.contains("\"input_tokens\":625"),
            "message_start should contain scaled input_tokens (625): {message_start}"
        );
    }

    #[test]
    fn message_delta_has_correct_tokens_chatcompletions_flow() {
        // ChatCompletions: Done arrives before Usage
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));

        // Done first (deferred)
        builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });

        // Usage triggers the deferred message_delta
        let events = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 1000,
            completion_tokens: 50,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 1050,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        let message_delta = events.iter().find(|e| e.contains("message_delta")).unwrap();
        assert!(
            message_delta.contains("\"input_tokens\":1000"),
            "expected input_tokens: 1000, got: {message_delta}"
        );
        assert!(
            message_delta.contains("\"output_tokens\":50"),
            "expected output_tokens: 50, got: {message_delta}"
        );
    }

    #[test]
    fn message_delta_has_correct_tokens_responses_flow() {
        // Responses API: Usage and Done arrive, then flush
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));

        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 800,
            completion_tokens: 30,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 830,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });

        let events = builder.flush_pending();
        let message_delta = events.iter().find(|e| e.contains("message_delta")).unwrap();
        assert!(
            message_delta.contains("\"input_tokens\":800"),
            "expected input_tokens: 800, got: {message_delta}"
        );
        assert!(
            message_delta.contains("\"output_tokens\":30"),
            "expected output_tokens: 30, got: {message_delta}"
        );
    }

    #[test]
    fn usage_merge_preserves_prompt_tokens() {
        // Simulates Anthropic protocol: two Usage events (prompt first, then completion)
        let mut builder =
            AnthropicResponseBuilder::new("gpt-4o".to_string(), "abc12345".to_string(), None, None, 0, 0);

        builder.process_event(&DomainEvent::TextDelta("Hi".to_string()));

        // First usage: prompt only
        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 500,
            completion_tokens: 0,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 500,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        // Second usage: completion only (prompt=0 should NOT overwrite)
        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 0,
            completion_tokens: 100,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 100,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        assert_eq!(builder.input_tokens, 500, "prompt_tokens should be preserved");
        assert_eq!(builder.output_tokens, 100, "completion_tokens should be updated");
    }

    #[test]
    fn message_delta_scales_both_tokens() {
        // client_context_window = 200K, upstream = 32K, max_output = 0 → scale = 6.25x
        let mut builder = AnthropicResponseBuilder::new(
            "gpt-4o".to_string(),
            "abc12345".to_string(),
            Some(32_000),
            Some(200_000),
            0,
            0,
        );

        builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));

        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 150,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });

        let events = builder.flush_pending();
        let message_delta = events.iter().find(|e| e.contains("message_delta")).unwrap();
        // 100 * 6.25 = 625, 50 * 6.25 = 313
        assert!(
            message_delta.contains("\"input_tokens\":625"),
            "expected scaled input_tokens (625): {message_delta}"
        );
        assert!(
            message_delta.contains("\"output_tokens\":313"),
            "expected scaled output_tokens (313): {message_delta}"
        );
    }

    #[test]
    fn scaling_accounts_for_max_output_tokens() {
        // client_context_window = 200K, upstream = 150K, max_output = 32K
        // effective = 150K - 32K = 118K, scale = 200K / 118K ≈ 1.694x
        let mut builder = AnthropicResponseBuilder::new(
            "gpt-4o".to_string(),
            "abc12345".to_string(),
            Some(150_000),
            Some(200_000),
            100_000, // estimated input tokens
            32_000,  // max_output_tokens
        );

        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        let message_start = &events[0];
        // 100_000 * (200_000 / 118_000) ≈ 169_492
        assert!(
            message_start.contains("\"input_tokens\":169492"),
            "expected scaled input_tokens (~169492): {message_start}"
        );
    }

    // ─── ResponsesResponseBuilder reasoning tests ───

    #[test]
    fn responses_builder_reasoning_then_text_streaming() {
        let mut builder = ResponsesResponseBuilder::new(
            "resp_1234".to_string(),
            "o3-mini".to_string(),
        );

        // First reasoning delta — response.created + output_item.added (reasoning) + reasoning_summary_part.added + delta
        let events = builder.process_event(&DomainEvent::ReasoningDelta("Let me think...".to_string()));
        let combined = events.join("");
        assert!(combined.contains("response.created"), "missing response.created");
        assert!(combined.contains("\"type\":\"reasoning\""), "missing reasoning output item");
        assert!(combined.contains("response.reasoning_summary_text.delta"), "missing reasoning delta event");
        assert!(combined.contains("Let me think..."), "missing reasoning text");

        // Second reasoning delta — only delta event
        let events = builder.process_event(&DomainEvent::ReasoningDelta(" more".to_string()));
        assert_eq!(events.len(), 1);
        assert!(events[0].contains("response.reasoning_summary_text.delta"));

        // Text delta — closes the reasoning item, then opens the message at output_index 1
        let events = builder.process_event(&DomainEvent::TextDelta("The answer is 42.".to_string()));
        let combined = events.join("");
        let reasoning_done = combined.find("response.reasoning_summary_text.done").expect("reasoning closes first");
        let message_added = combined.find("\"type\":\"message\"").expect("missing message output item");
        assert!(reasoning_done < message_added, "the reasoning item closes before the message opens");
        assert!(combined.contains("\"text\":\"Let me think... more\""), "the close restates the reasoning");
        assert!(combined.contains("\"output_index\":1"), "text should be at output_index 1");
        assert!(combined.contains("response.output_text.delta"), "missing text delta");
        assert!(combined.contains("The answer is 42."), "missing text content");

        // Usage with reasoning + cached tokens
        builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            reasoning_tokens: Some(30),
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: Some(20),
            total_tokens: 150,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        // Done
        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });
        events.extend(builder.flush_pending());
        let combined = events.join("");
        assert!(combined.contains("response.output_text.done"), "missing message done");
        assert!(combined.contains("response.completed"), "missing response.completed");
        assert!(combined.contains("\"reasoning_tokens\":30"), "missing reasoning_tokens in usage");
        assert!(combined.contains("\"cached_tokens\":20"), "missing cached_tokens in usage");
    }

    #[test]
    fn responses_builder_reasoning_only_streaming() {
        let mut builder = ResponsesResponseBuilder::new(
            "resp_5678".to_string(),
            "o1-preview".to_string(),
        );

        builder.process_event(&DomainEvent::ReasoningDelta("thinking...".to_string()));
        let mut events = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
        });
        events.extend(builder.flush_pending());
        let combined = events.join("");
        // Should close reasoning but NOT have message close events
        assert!(combined.contains("response.reasoning_summary_text.done"), "missing reasoning done");
        assert!(combined.contains("response.completed"), "missing completed");
        assert!(!combined.contains("\"type\":\"message\""), "should not have message item close");
    }

    #[test]
    fn responses_builder_text_only_no_reasoning_offset() {
        let mut builder = ResponsesResponseBuilder::new(
            "resp_9999".to_string(),
            "gpt-4o".to_string(),
        );

        // Text without reasoning — output_index should be 0
        let events = builder.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        let combined = events.join("");
        assert!(combined.contains("\"output_index\":0"), "text should be at output_index 0 when no reasoning");
    }

    #[test]
    fn responses_renders_substitution_web_search_call_before_message() {
        // Visible-mode emulation. Substitution agent loop signals the
        // builder via `enter_visible_mode_round()` BEFORE replaying a
        // round's events; the builder drops the round-0 preamble
        // `TextDelta` so the synthesised `web_search_call` output_item
        // lands at `output_index = 0`. The next round's `TextDelta`
        // opens the assistant message at `output_index = 1`, matching
        // native OpenAI Responses ordering.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_abcdef00".to_string(),
            "gpt-4o-search".to_string(),
        );

        // Round-0 replay: agent loop calls enter_visible_mode_round.
        builder.enter_visible_mode_round();

        // Preamble `TextDelta` from the model is dropped at the wire to
        // preserve spec ordering. Internally captured into history by
        // the agent loop's separate `capture_preamble`.
        let events = builder.process_event(&DomainEvent::TextDelta(
            "Let me search.".to_string(),
        ));
        let combined = events.join("");
        // Allow `response.created` to fire (first meaningful event always
        // emits it) but assert no `output_text.delta` was emitted.
        assert!(
            !combined.contains("response.output_text.delta"),
            "round-0 preamble must not reach the wire in visible-mode: {combined}"
        );
        assert!(
            !combined.contains("\"type\":\"message\""),
            "message item must not open in round-0 visible-mode: {combined}"
        );

        // Synthesised `web_search_call` open. Action is parsed from the
        // delta JSON so the wire shape mirrors native OpenAI.
        let call_id = "tu_sub_abc_0";
        let events = builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: call_id.to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"openai responses spec"}"#.to_string(),
        });
        let joined = events.join("");
        assert!(
            joined.contains("\"type\":\"web_search_call\""),
            "expected web_search_call open: {joined}"
        );
        assert!(
            joined.contains("\"output_index\":0"),
            "web_search_call should land at output_index 0: {joined}"
        );
        assert!(
            joined.contains(&format!("\"id\":\"ws_{call_id}\"")),
            "web_search_call.id derived from tool_use_id: {joined}"
        );
        assert!(
            joined.contains("\"status\":\"in_progress\""),
            "open emits in_progress: {joined}"
        );
        assert!(
            joined.contains("\"query\":\"openai responses spec\""),
            "action carries parsed query: {joined}"
        );
        assert!(
            joined.contains("response.web_search_call.in_progress"),
            "in_progress event: {joined}"
        );

        // Synthesised result. Must close the web_search_call output_item
        // with `completed` status and bump the next message index.
        let events = builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: call_id.to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/spec", "title": "Spec"}],
                "total_filtered": 0,
                "backend": "searxng"
            }),
        });
        let joined = events.join("");
        assert!(
            joined.contains("response.web_search_call.completed"),
            "completed event: {joined}"
        );
        assert!(
            joined.contains("response.output_item.done"),
            "output_item.done event: {joined}"
        );
        assert!(
            joined.contains("\"status\":\"completed\""),
            "done event carries completed status: {joined}"
        );

        // Round-1 text opens the assistant message at the bumped index.
        let events = builder.process_event(&DomainEvent::TextDelta(
            "Here is the answer.".to_string(),
        ));
        let joined = events.join("");
        assert!(
            joined.contains("\"type\":\"message\""),
            "message opens after web_search_call: {joined}"
        );
        assert!(
            joined.contains("\"output_index\":1"),
            "message lands at output_index 1 (after web_search_call at 0): {joined}"
        );
        assert!(
            joined.contains("response.output_text.delta"),
            "text delta emits normally in round-1: {joined}"
        );
    }

    #[test]
    fn responses_renders_substitution_web_search_call_failed_on_error() {
        let mut builder = ResponsesResponseBuilder::new(
            "resp_failtest0".to_string(),
            "gpt-4o-search".to_string(),
        );
        builder.enter_visible_mode_round();
        // Drop round-0 preamble.
        builder.process_event(&DomainEvent::TextDelta("trying...".to_string()));

        let call_id = "tu_sub_xyz_0";
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: call_id.to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q"}"#.to_string(),
        });
        // Executor error → close with failed status.
        let events = builder.process_event(&DomainEvent::ServerToolError {
            index: 0,
            tool_use_id: call_id.to_string(),
            error_kind: "no_backend".to_string(),
        });
        let joined = events.join("");
        // The spec has no failed-search event: the failure is the item's status.
        assert!(
            !joined.contains("response.web_search_call.failed")
                && !joined.contains("response.web_search_call.completed"),
            "a failed search streams no call event of its own: {joined}"
        );
        assert!(
            joined.contains("\"status\":\"failed\""),
            "output_item.done carries failed status: {joined}"
        );
    }

    #[test]
    fn responses_renders_two_substitution_rounds_monotonic_indexes() {
        // Multi-round visible-mode: two substitution rounds each emit
        // their own web_search_call at consecutive output_indexes BEFORE
        // the final message. The builder must keep `web_search_calls_emitted`
        // monotonic and clear `drop_round_text` between rounds so each
        // round's preamble drop reactivates correctly.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_multi00000".to_string(),
            "gpt-4o-search".to_string(),
        );

        // Round 1.
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::TextDelta("first preamble".to_string()));
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_a".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q1"}"#.to_string(),
        });
        let events = builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_a".to_string(),
            content: serde_json::json!({"hits": []}),
        });
        let joined = events.join("");
        assert!(joined.contains("\"output_index\":0"), "round-1 close at oi=0: {joined}");

        // Round 2 — second visible-mode round before any message opens.
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::TextDelta("second preamble".to_string()));
        let events = builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_b".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q2"}"#.to_string(),
        });
        let joined = events.join("");
        assert!(joined.contains("\"output_index\":1"), "round-2 open at oi=1: {joined}");
        builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_b".to_string(),
            content: serde_json::json!({"hits": []}),
        });

        // Final message opens at oi=2 (after both web_search_calls).
        let events = builder.process_event(&DomainEvent::TextDelta("final".to_string()));
        let joined = events.join("");
        assert!(joined.contains("\"output_index\":2"), "message at oi=2: {joined}");
    }

    #[test]
    fn responses_visible_mode_no_op_when_message_already_open() {
        // Defensive: if the message item was already opened by an earlier
        // round (non-visible-mode), `enter_visible_mode_round` is a no-op
        // (drop_round_text stays false). Subsequent `TextDelta`s land
        // normally; web_search_call still emits AFTER the message at the
        // bumped output_index (non-spec ordering, documented limitation).
        let mut builder = ResponsesResponseBuilder::new(
            "resp_late0000".to_string(),
            "gpt-4o-search".to_string(),
        );
        // Open the message via a TextDelta before any visible-mode signal.
        builder.process_event(&DomainEvent::TextDelta("hello".to_string()));
        // Now signal visible-mode. Should be a no-op since message is open.
        builder.enter_visible_mode_round();
        // Text continues to land normally.
        let events = builder.process_event(&DomainEvent::TextDelta(" world".to_string()));
        let joined = events.join("");
        assert!(
            joined.contains("response.output_text.delta"),
            "TextDelta still emits when enter_visible_mode_round() arrived too late: {joined}"
        );
    }

    #[test]
    fn responses_flush_pending_closes_dangling_web_search_call() {
        // Defensive: if the agent loop bails between
        // ServerToolCallDelta and ServerToolResult (e.g. cancel during
        // dispatch), `flush_pending` must close the in-flight
        // web_search_call so the client's state machine doesn't hang.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_dangle000".to_string(),
            "gpt-4o-search".to_string(),
        );
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::TextDelta("preamble".to_string()));
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_dangle".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q"}"#.to_string(),
        });
        // No ServerToolResult — simulate cancel.
        let events = builder.flush_pending();
        let joined = events.join("");
        assert!(
            joined.contains("\"status\":\"failed\""),
            "flush closes dangling web_search_call as failed: {joined}"
        );
        assert!(
            !joined.contains("response.web_search_call.failed"),
            "no event the spec does not define: {joined}"
        );
        assert!(
            joined.contains("response.output_item.done"),
            "flush emits output_item.done: {joined}"
        );
    }

    #[test]
    fn responses_emits_url_citation_annotations_with_substring_match() {
        // After a visible-mode round dispatches a search whose hit URL
        // appears verbatim in the assistant text, the Done arm should
        // emit a `response.output_text.annotation.added` carrying the
        // `url_citation` with byte spans pointing at the URL.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_cite00000".to_string(),
            "gpt-4o-search".to_string(),
        );
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::TextDelta("looking up...".to_string()));
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_cite".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q"}"#.to_string(),
        });
        builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_cite".to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/doc", "title": "Example Doc"}],
            }),
        });
        // Assistant text quotes the URL verbatim.
        builder.process_event(&DomainEvent::TextDelta(
            "See https://example.com/doc for more.".to_string(),
        ));
        let mut done = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: None,
        });
        done.extend(builder.flush_pending());
        let joined = done.join("");
        assert!(
            joined.contains("response.output_text.annotation.added"),
            "annotation event present: {joined}"
        );
        assert!(
            joined.contains("\"type\":\"url_citation\""),
            "url_citation type: {joined}"
        );
        assert!(
            joined.contains("\"url\":\"https://example.com/doc\""),
            "annotation carries URL: {joined}"
        );
        assert!(
            joined.contains("\"start_index\":4"),
            "spans match URL position in text (offset 4 after 'See '): {joined}"
        );
        // Annotation event must come BEFORE content_part.done in the output stream.
        let ann_pos = joined.find("response.output_text.annotation.added").unwrap();
        let close_pos = joined.find("response.content_part.done").unwrap();
        assert!(ann_pos < close_pos, "annotation precedes content_part.done");
    }

    #[test]
    fn responses_emits_url_citation_without_spans_when_no_substring_match() {
        // When the model paraphrases instead of quoting the URL or title,
        // the Option-4 fallback emits a span-less `url_citation` so the
        // SDK can still render the citation chip.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_paraph000".to_string(),
            "gpt-4o-search".to_string(),
        );
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::TextDelta("looking up...".to_string()));
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_p".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q"}"#.to_string(),
        });
        builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_p".to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/blog", "title": "Some Blog"}],
            }),
        });
        // Text mentions neither the URL nor the title.
        builder.process_event(&DomainEvent::TextDelta(
            "Based on the search, the answer is yes.".to_string(),
        ));
        let mut done = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: None,
        });
        done.extend(builder.flush_pending());
        let joined = done.join("");
        assert!(
            joined.contains("response.output_text.annotation.added"),
            "annotation event still present without substring match: {joined}"
        );
        assert!(
            joined.contains("\"url\":\"https://example.com/blog\""),
            "url present: {joined}"
        );
        assert!(
            !joined.contains("\"start_index\""),
            "no spans when no substring matched: {joined}"
        );
    }

    #[test]
    fn responses_dedups_url_citations_across_rounds() {
        // If the same URL surfaces in multiple ServerToolResult events
        // (e.g. two rounds searching the same site), the annotation
        // emitter must only emit one annotation per URL.
        let mut builder = ResponsesResponseBuilder::new(
            "resp_dedup0000".to_string(),
            "gpt-4o-search".to_string(),
        );
        // Round 1.
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_d1".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q1"}"#.to_string(),
        });
        builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_d1".to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/x", "title": "X"}],
            }),
        });
        // Round 2 returns the same hit.
        builder.enter_visible_mode_round();
        builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_d2".to_string(),
            server_type: "web_search_preview".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"q2"}"#.to_string(),
        });
        builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_d2".to_string(),
            content: serde_json::json!({
                "hits": [{"url": "https://example.com/x", "title": "X"}],
            }),
        });
        builder.process_event(&DomainEvent::TextDelta("the answer".to_string()));
        let mut done = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: None,
        });
        done.extend(builder.flush_pending());
        let annotations: Vec<Value> = sse_data(&done)
            .into_iter()
            .filter(|e| e["type"] == "response.output_text.annotation.added")
            .collect();
        assert_eq!(annotations.len(), 1, "single annotation per URL across rounds: {annotations:?}");
        assert_eq!(annotations[0]["annotation"]["url"], "https://example.com/x");
    }

    // ─── Non-streaming reasoning translation tests ───

    #[test]
    fn chat_completions_to_responses_with_reasoning() {
        let oai_response = serde_json::json!({
            "id": "chatcmpl-123",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "The answer is 42.",
                    "reasoning": "Let me think about the meaning of life..."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 50,
                "total_tokens": 60,
                "completion_tokens_details": {
                    "reasoning_tokens": 30
                },
                "prompt_tokens_details": {
                    "cached_tokens": 5
                }
            }
        });

        let result = chat_completions_to_responses_response(&oai_response, "o1-preview", "resp_123");
        let output = result["output"].as_array().unwrap();

        // First item should be reasoning
        assert_eq!(output[0]["type"], "reasoning");
        assert_eq!(output[0]["summary"][0]["text"], "Let me think about the meaning of life...");

        // Second item should be message
        assert_eq!(output[1]["type"], "message");

        // Usage should include token details
        assert_eq!(result["usage"]["output_tokens_details"]["reasoning_tokens"], 30);
        assert_eq!(result["usage"]["input_tokens_details"]["cached_tokens"], 5);
    }

    #[test]
    fn responses_to_chat_completions_with_reasoning() {
        let responses_json = serde_json::json!({
            "id": "resp_456",
            "object": "response",
            "status": "completed",
            "model": "o3-mini",
            "output": [
                {
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "Thinking step by step..."}]
                },
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "The answer."}]
                }
            ],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "total_tokens": 150,
                "output_tokens_details": {"reasoning_tokens": 30},
                "input_tokens_details": {"cached_tokens": 10}
            }
        });

        let result = responses_response_to_chat_completions(&responses_json, "o3-mini");

        // Should have reasoning field on message
        assert_eq!(
            result["choices"][0]["message"]["reasoning"],
            "Thinking step by step..."
        );
        assert_eq!(result["choices"][0]["message"]["content"], "The answer.");

        // Usage should include token details
        assert_eq!(result["usage"]["completion_tokens_details"]["reasoning_tokens"], 30);
        assert_eq!(result["usage"]["prompt_tokens_details"]["cached_tokens"], 10);
    }

    // ─── ChatCompletionsResponseBuilder token details test ───

    #[test]
    fn cc_builder_usage_includes_token_details() {
        let mut builder = ChatCompletionsResponseBuilder::new(
            "gpt-4o".to_string(),
            "chatcmpl-123".to_string(),
        );

        let events = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            reasoning_tokens: Some(30),
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: Some(20),
            total_tokens: 150,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        assert_eq!(events.len(), 1);
        // Parse the SSE chunk's usage block to assert correct field placement:
        // cached_tokens is prompt-side (prompt_tokens_details), reasoning is
        // completion-side (completion_tokens_details) — not swapped.
        let json_str = events[0].trim_start_matches("data: ").trim();
        let chunk: Value = serde_json::from_str(json_str).expect("valid SSE JSON");
        let usage = &chunk["usage"];
        assert_eq!(usage["completion_tokens_details"]["reasoning_tokens"], 30);
        assert_eq!(usage["prompt_tokens_details"]["cached_tokens"], 20);
        assert!(
            usage["completion_tokens_details"].get("cached_tokens").is_none(),
            "cached_tokens must not land in completion_tokens_details: {usage}"
        );
    }

    #[test]
    fn cc_builder_usage_no_details_when_absent() {
        let mut builder = ChatCompletionsResponseBuilder::new(
            "gpt-4o".to_string(),
            "chatcmpl-456".to_string(),
        );

        let events = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 150,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));

        assert_eq!(events.len(), 1);
        assert!(!events[0].contains("completion_tokens_details"), "should not include details when absent");
    }

    // ─── Anthropic → ChatCompletions translation ───

    #[test]
    fn anthropic_to_cc_text_only() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello world"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let result = anthropic_to_chat_completions(&anthropic_resp, "claude-3");
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["model"], "claude-3");
        assert_eq!(result["choices"][0]["message"]["content"], "Hello world");
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
        assert_eq!(result["usage"]["prompt_tokens"], 10);
        assert_eq!(result["usage"]["completion_tokens"], 5);
    }

    #[test]
    fn anthropic_to_cc_tool_use() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_02",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "SF"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 15}
        });
        let result = anthropic_to_chat_completions(&anthropic_resp, "claude-3");
        assert_eq!(result["choices"][0]["finish_reason"], "tool_calls");
        let tool_calls = result["choices"][0]["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["function"]["name"], "get_weather");
        assert_eq!(tool_calls[0]["id"], "call_1");
    }

    #[test]
    fn anthropic_to_cc_thinking() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_03",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "Let me think about this..."},
                {"type": "text", "text": "The answer is 42."}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 20}
        });
        let result = anthropic_to_chat_completions(&anthropic_resp, "claude-3");
        assert_eq!(result["choices"][0]["message"]["content"], "The answer is 42.");
        assert_eq!(result["choices"][0]["message"]["reasoning"], "Let me think about this...");
    }

    // ─── Anthropic → Responses API translation ───

    #[test]
    fn anthropic_to_responses_text_only() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello world"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let result = anthropic_to_responses_response(&anthropic_resp, "claude-3", "req_abc123456789");
        assert_eq!(result["object"], "response");
        assert_eq!(result["model"], "claude-3");
        assert_eq!(result["status"], "completed");
        let output = result["output"].as_array().unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["content"][0]["type"], "output_text");
        assert_eq!(output[0]["content"][0]["text"], "Hello world");
    }

    #[test]
    fn anthropic_to_responses_tool_use() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_02",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "call_1", "name": "search", "input": {"q": "test"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 15}
        });
        let result = anthropic_to_responses_response(&anthropic_resp, "claude-3", "req_abc123456789");
        let output = result["output"].as_array().unwrap();
        assert_eq!(output.len(), 2); // message + function_call
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["name"], "search");
        assert_eq!(output[1]["call_id"], "call_1");
    }

    #[test]
    fn anthropic_to_responses_thinking() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_03",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "Reasoning here..."},
                {"type": "text", "text": "The answer."}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 20}
        });
        let result = anthropic_to_responses_response(&anthropic_resp, "claude-3", "req_abc123456789");
        let output = result["output"].as_array().unwrap();
        // reasoning comes first, then message with text (message inserted at position 0)
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[1]["type"], "reasoning");
    }

    #[test]
    fn anthropic_to_responses_max_tokens() {
        let anthropic_resp = serde_json::json!({
            "id": "msg_04",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Partial..."}],
            "stop_reason": "max_tokens",
            "usage": {"input_tokens": 10, "output_tokens": 50}
        });
        let result = anthropic_to_responses_response(&anthropic_resp, "claude-3", "req_abc123456789");
        assert_eq!(result["status"], "incomplete");
        assert_eq!(result["incomplete_details"]["reason"], "max_output_tokens");
    }

    /// A non-streaming Chat client reads the same finish reason a streaming
    /// one does: filtered stops are `content_filter`, never a vendor's raw word.
    #[test]
    fn a_non_streaming_chat_finish_reason_is_chats_own_word() {
        let from_gemini = |finish: &str| {
            gemini_response_to_chat_completions(
                &serde_json::json!({
                    "candidates": [{"content": {"role": "model", "parts": [{"text": "x"}]}, "finishReason": finish}],
                    "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
                }),
                "m",
            )["choices"][0]["finish_reason"]
                .clone()
        };
        let from_anthropic = |stop: &str| {
            anthropic_to_chat_completions(
                &serde_json::json!({"id": "m", "type": "message", "role": "assistant",
                    "content": [{"type": "text", "text": "x"}], "stop_reason": stop,
                    "usage": {"input_tokens": 1, "output_tokens": 1}}),
                "m",
            )["choices"][0]["finish_reason"]
                .clone()
        };
        assert_eq!(from_gemini("PROHIBITED_CONTENT"), "content_filter");
        assert_eq!(from_gemini("MAX_TOKENS"), "length");
        assert_eq!(from_gemini("STOP"), "stop");
        assert_eq!(from_anthropic("refusal"), "content_filter");
        assert_eq!(from_anthropic("stop_sequence"), "stop");
        assert_eq!(from_anthropic("max_tokens"), "length");
    }

    /// The Responses spec pairs `status: "incomplete"` with the reason in
    /// `incomplete_details`; every translation onto Responses states it, and a
    /// finished answer carries neither.
    #[test]
    fn every_translation_to_responses_says_why_it_is_incomplete() {
        let chat = |finish: &str| {
            chat_completions_to_responses_response(
                &serde_json::json!({
                    "id": "c", "choices": [{"message": {"role": "assistant", "content": "x"}, "finish_reason": finish}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }),
                "m",
                "req_abc123456789",
            )
        };
        let gemini = |finish: &str| {
            gemini_response_to_responses(
                &serde_json::json!({
                    "candidates": [{"content": {"role": "model", "parts": [{"text": "x"}]}, "finishReason": finish}],
                    "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
                }),
                "m",
                "req_abc123456789",
            )
        };
        for capped in [chat("length"), gemini("MAX_TOKENS")] {
            assert_eq!(capped["status"], "incomplete", "{capped}");
            assert_eq!(capped["incomplete_details"]["reason"], "max_output_tokens", "{capped}");
        }
        let anthropic = |stop: &str| {
            anthropic_to_responses_response(
                &serde_json::json!({"id": "m", "type": "message", "role": "assistant",
                    "content": [{"type": "text", "text": "x"}], "stop_reason": stop,
                    "usage": {"input_tokens": 1, "output_tokens": 1}}),
                "m",
                "req_abc123456789",
            )
        };
        for filtered in [chat("content_filter"), gemini("SAFETY"), gemini("PROHIBITED_CONTENT"), anthropic("refusal")] {
            assert_eq!(filtered["status"], "incomplete", "{filtered}");
            assert_eq!(filtered["incomplete_details"]["reason"], "content_filter", "{filtered}");
        }
        for done in [chat("stop"), gemini("STOP")] {
            assert_eq!(done["status"], "completed", "{done}");
            assert!(done.get("incomplete_details").is_none(), "{done}");
        }
    }

    fn gemini_thinking_fixture() -> Value {
        serde_json::json!({
            "candidates": [{
                "content": {"parts": [
                    {"thought": true, "text": "Analyzing..."},
                    {"text": "The answer is 42."}
                ]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 7}
        })
    }

    #[test]
    fn gemini_to_chat_completions_thinking() {
        let resp = gemini_thinking_fixture();
        let result = gemini_response_to_chat_completions(&resp, "gemini-2.5-pro");
        let msg = &result["choices"][0]["message"];
        assert_eq!(msg["content"], "The answer is 42.");
        assert_eq!(msg["reasoning"], "Analyzing...");
        assert!(result["created"].as_i64().unwrap_or(0) > 0);
    }

    /// Non-streaming twin of the streaming rule: thinking tokens are billed at
    /// the output rate but sit outside `candidatesTokenCount`, so the translated
    /// response's output count must include them — otherwise a Gemini thinking
    /// model is billed for its visible answer alone, and the client sees an
    /// output count smaller than what it paid for.
    #[test]
    fn gemini_usage_counts_thinking_as_output() {
        let mut resp = gemini_thinking_fixture();
        resp["usageMetadata"] = serde_json::json!({
            "promptTokenCount": 5,
            "candidatesTokenCount": 7,
            "thoughtsTokenCount": 40,
            "totalTokenCount": 52,
        });
        let result = gemini_response_to_chat_completions(&resp, "gemini-2.5-pro");
        assert_eq!(result["usage"]["prompt_tokens"], 5);
        assert_eq!(result["usage"]["completion_tokens"], 47);
        assert_eq!(result["usage"]["total_tokens"], 52);

        // A response with no thinking is unchanged.
        let plain = gemini_thinking_fixture();
        let plain_result = gemini_response_to_chat_completions(&plain, "gemini-2.5-pro");
        assert_eq!(plain_result["usage"]["completion_tokens"], 7);
    }

    #[test]
    fn gemini_to_anthropic_thinking() {
        let resp = gemini_thinking_fixture();
        let result = gemini_response_to_anthropic(&resp, "gemini-2.5-pro", "req_abcdef123456", None, None, 1024);
        let content = result["content"].as_array().unwrap();
        // thinking block first, then text
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "Analyzing...");
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "The answer is 42.");
    }

    #[test]
    fn gemini_builder_accumulates_streaming_tool_call_args() {
        // Regression: pre-fix, args-only deltas were silently dropped because
        // the emitter only emitted when `function_name.is_some()`. Gemini
        // clients then saw `{functionCall:{name}}` with no `args`, breaking
        // tool execution from a Gemini SDK against an OpenAI/Anthropic
        // upstream behind the proxy.
        let mut builder = GeminiResponseBuilder::new("gemini-2.5-pro".to_string());

        // Chunk 1: name + id, no args yet (typical OpenAI ChatCompletions
        // first tool-call chunk).
        let out = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_abc".to_string()),
            function_name: Some("get_weather".to_string()),
            arguments_delta: String::new(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(out.is_empty(), "tool-call deltas must be deferred until stream end");

        // Chunk 2 + 3: incremental args. Pre-fix these would have been dropped
        // entirely because function_name is None.
        let out = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: r#"{"city":"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(out.is_empty());
        let out = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: r#""Paris"}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        assert!(out.is_empty());

        // Done arrives before Usage (OpenAI ChatCompletions ordering).
        let out = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::ToolCalls),
            native_finish_reason: Some("tool_calls".to_string()),
        });
        assert!(out.is_empty(), "Done is deferred until Usage");

        // Usage triggers the flush — first the accumulated tool call, then
        // the final chunk with finishReason + usageMetadata.
        let out = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 10,
            completion_tokens: 5,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 15,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        assert_eq!(out.len(), 2, "expected one tool-call chunk + one final chunk");
        let tc_chunk = &out[0];
        assert!(tc_chunk.contains("functionCall"), "tool-call chunk: {tc_chunk}");
        assert!(tc_chunk.contains("\"name\":\"get_weather\""), "tool-call chunk: {tc_chunk}");
        assert!(tc_chunk.contains("\"id\":\"call_abc\""), "tool-call chunk: {tc_chunk}");
        // Args fully accumulated and parsed as a JSON object — not lost.
        assert!(tc_chunk.contains("\"args\":{\"city\":\"Paris\"}"), "tool-call chunk: {tc_chunk}");
        let final_chunk = &out[1];
        assert!(final_chunk.contains("finishReason"), "final chunk: {final_chunk}");
        assert!(final_chunk.contains("usageMetadata"), "final chunk: {final_chunk}");
    }

    /// A stop in another protocol's words reaches an Anthropic or Gemini
    /// client in THAT client's words, streaming or not. Mistral's
    /// `model_length` is the sharpest case: a truncation that, read raw, would
    /// reach a Gemini client verbatim and an Anthropic one as a clean
    /// `end_turn`.
    #[test]
    fn a_translated_stop_is_stated_in_the_clients_words() {
        let chat = |finish: &str| {
            serde_json::json!({
                "id": "x",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": finish}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })
        };
        for (finish, anthropic, gemini) in [
            ("stop", "end_turn", "STOP"),
            ("length", "max_tokens", "MAX_TOKENS"),
            ("model_length", "max_tokens", "MAX_TOKENS"),
            ("tool_calls", "tool_use", "STOP"),
            ("content_filter", "end_turn", "SAFETY"),
            ("error", "end_turn", "OTHER"),
        ] {
            let a = openai_response_to_anthropic(&chat(finish), "m", "abc12345", 1, None, None, 0);
            assert_eq!(a["stop_reason"], anthropic, "{finish}");
            let g = chat_completions_to_gemini_response(&chat(finish));
            assert_eq!(g["candidates"][0]["finishReason"], gemini, "{finish}");

            let mut builder = GeminiResponseBuilder::new("m".to_string());
            builder.process_event(&DomainEvent::Done {
                finish_reason: Some(FinishReason::normalize(finish)),
                native_finish_reason: Some(finish.to_string()),
            });
            let out = builder.process_event(&DomainEvent::Usage(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                reasoning_tokens: None,
                cache_creation_tokens: None,
                cache_creation_1h_tokens: None,
                cache_read_tokens: None,
                total_tokens: 2,
                audio_prompt_tokens: None,
                audio_completion_tokens: None,
                audio_prompt_seconds: None,
            }));
            let last = out.last().expect("a final chunk");
            assert!(last.contains(&format!("\"finishReason\":\"{gemini}\"")), "{finish}: {last}");
        }

        // Anthropic's own words, onto a non-streaming Gemini client.
        for (stop, gemini) in [
            ("end_turn", "STOP"),
            ("stop_sequence", "STOP"),
            ("max_tokens", "MAX_TOKENS"),
            ("tool_use", "STOP"),
            ("refusal", "SAFETY"),
            ("pause_turn", "OTHER"),
        ] {
            let body = serde_json::json!({
                "content": [{"type": "text", "text": "hi"}], "stop_reason": stop,
                "usage": {"input_tokens": 1, "output_tokens": 1}
            });
            assert_eq!(anthropic_to_gemini_response(&body)["candidates"][0]["finishReason"], gemini, "{stop}");
        }

        // A word already in Gemini's enum — a Gemini answer replayed from the
        // response cache — is kept, streaming or not, never flattened.
        let cached = chat("RECITATION");
        assert_eq!(chat_completions_to_gemini_response(&cached)["candidates"][0]["finishReason"], "RECITATION");
        let mut builder = GeminiResponseBuilder::new("m".to_string());
        builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::normalize("RECITATION")),
            native_finish_reason: Some("RECITATION".to_string()),
        });
        let out = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 1,
            completion_tokens: 1,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 2,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        assert!(out.last().unwrap().contains("\"finishReason\":\"RECITATION\""), "{out:?}");
        // …but a word the settled reason no longer agrees with is not: a
        // finish settled to a clean stop after a removed call says STOP.
        assert_eq!(gemini_finish_reason(&FinishReason::Stop, Some("UNEXPECTED_TOOL_CALL")), "STOP");

        // An Anthropic client, streaming or not, is told `tool_use` for a turn
        // that handed it a call — whatever plain stop the upstream reported —
        // and `max_tokens` for one cut short, calls or not.
        for (finish, anthropic) in [
            (FinishReason::Stop, "tool_use"),
            (FinishReason::Length, "max_tokens"),
            // A failed turn is no call to run.
            (FinishReason::Error, "end_turn"),
        ] {
            let mut builder = AnthropicResponseBuilder::new("m".into(), "req1".into(), None, None, 0, 0);
            let mut out = builder.process_event(&DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_string()),
                function_name: Some("f".to_string()),
                arguments_delta: "{}".to_string(),
                form: crate::api::domain::CallArguments::Json,
            });
            out.extend(builder.process_event(&DomainEvent::Done { finish_reason: Some(finish.clone()), native_finish_reason: None }));
            out.extend(builder.process_event(&DomainEvent::Usage(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                reasoning_tokens: None,
                cache_creation_tokens: None,
                cache_creation_1h_tokens: None,
                cache_read_tokens: None,
                total_tokens: 2,
                audio_prompt_tokens: None,
                audio_completion_tokens: None,
                audio_prompt_seconds: None,
            })));
            let joined = out.join("");
            assert!(joined.contains(&format!("\"stop_reason\":\"{anthropic}\"")), "{finish:?}: {joined}");
        }
        for (word, anthropic, chat_word) in [
            ("STOP", "tool_use", Some("tool_calls")),
            ("MAX_TOKENS", "max_tokens", Some("length")),
            // A failed turn's Chat word follows the calls the message still
            // carries, not the stop, and is not this table's claim.
            ("MALFORMED_FUNCTION_CALL", "end_turn", None),
        ] {
            let body = serde_json::json!({"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "f", "args": {}}}
            ]}, "finishReason": word}]});
            assert_eq!(gemini_response_to_anthropic(&body, "m", "abc12345", None, None, 0)["stop_reason"], anthropic, "{word}");
            if let Some(chat_word) = chat_word {
                assert_eq!(gemini_response_to_chat_completions(&body, "m")["choices"][0]["finish_reason"], chat_word, "{word}");
            }
        }

        // A streaming Chat client is told what a non-streaming one is: a turn
        // cut short while a call streamed is `length`, a clean one `tool_calls`.
        for (finish, chat_word) in [(FinishReason::Length, "length"), (FinishReason::Stop, "tool_calls")] {
            let mut builder = ChatCompletionsResponseBuilder::new("m".to_string(), "chatcmpl-1".to_string());
            let mut out = builder.process_event(&DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_string()),
                function_name: Some("f".to_string()),
                arguments_delta: "{}".to_string(),
                form: crate::api::domain::CallArguments::Json,
            });
            out.extend(builder.process_event(&DomainEvent::Done { finish_reason: Some(finish.clone()), native_finish_reason: None }));
            out.extend(builder.flush_pending());
            let joined = out.join("");
            assert!(joined.contains(&format!("\"finish_reason\":\"{chat_word}\"")), "{finish:?}: {joined}");
            assert_eq!(chat_finish(Some(finish), true), chat_word);
        }

        // A finish stated only in a word — no settled reason — keeps it when
        // the word is Gemini's, and states none rather than another protocol's.
        for (native, expect) in [("MAX_TOKENS", Some("MAX_TOKENS")), ("end_turn", None)] {
            let mut builder = GeminiResponseBuilder::new("m".to_string());
            builder.process_event(&DomainEvent::Done { finish_reason: None, native_finish_reason: Some(native.to_string()) });
            let out = builder.process_event(&DomainEvent::Usage(Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                reasoning_tokens: None,
                cache_creation_tokens: None,
                cache_creation_1h_tokens: None,
                cache_read_tokens: None,
                total_tokens: 2,
                audio_prompt_tokens: None,
                audio_completion_tokens: None,
                audio_prompt_seconds: None,
            }));
            let last = out.last().unwrap();
            match expect {
                Some(word) => assert!(last.contains(&format!("\"finishReason\":\"{word}\"")), "{native}: {last}"),
                None => assert!(!last.contains(native), "{native}: {last}"),
            }
        }

        // Gemini's own words onto a non-streaming Anthropic client.
        for (word, anthropic) in [("STOP", "end_turn"), ("MAX_TOKENS", "max_tokens"), ("SAFETY", "end_turn")] {
            let body = serde_json::json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": word}]});
            let a = gemini_response_to_anthropic(&body, "m", "abc12345", None, None, 0);
            assert_eq!(a["stop_reason"], anthropic, "{word}");
        }
    }

    #[test]
    fn gemini_builder_emits_grounding_metadata_on_substitution() {
        // Visible-mode emulation. Substitution agent loop streams
        // `ServerToolCallDelta` (with the model's query) followed by
        // `ServerToolResult` carrying the dispatched `SearchResult`. The
        // builder must accumulate both into single-shot
        // `groundingMetadata` on the final candidate (Decision #2) — never
        // emitted twice across substitution rounds.
        let mut builder = GeminiResponseBuilder::new("gemini-2.5-flash".to_string());
        // Round 1 — call delta + result. Neither emits a chunk on its own
        // (single-shot, Decision #2).
        let out = builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 0,
            tool_use_id: "tu_a".to_string(),
            server_type: "google_search".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"rust 2024 edition"}"#.to_string(),
        });
        assert!(out.is_empty(), "call delta must not emit a chunk: {out:?}");
        let out = builder.process_event(&DomainEvent::ServerToolResult {
            index: 0,
            tool_use_id: "tu_a".to_string(),
            content: serde_json::json!({
                "hits": [
                    {"url": "https://blog.rust-lang.org", "title": "Rust 2024 release"},
                    {"url": "https://blog.rust-lang.org", "title": "Dup — should be deduped"},
                    {"url": "https://doc.rust-lang.org/edition-guide", "title": "Edition Guide"}
                ],
                "total_filtered": 0,
                "backend": "searxng"
            }),
        });
        assert!(out.is_empty(), "result must not emit a chunk: {out:?}");
        // Round 2 — second substitution round, partial URI overlap. Dedup
        // must hold across rounds, not just within one. Adds two new URIs
        // and re-asserts a previously-seen one.
        let _ = builder.process_event(&DomainEvent::ServerToolCallDelta {
            index: 1,
            tool_use_id: "tu_b".to_string(),
            server_type: "google_search".to_string(),
            name: "web_search".to_string(),
            input_delta: r#"{"query":"async streams"}"#.to_string(),
        });
        let _ = builder.process_event(&DomainEvent::ServerToolResult {
            index: 1,
            tool_use_id: "tu_b".to_string(),
            content: serde_json::json!({
                "hits": [
                    {"url": "https://blog.rust-lang.org", "title": "Already seen in round 1"},
                    {"url": "https://crates.io/crates/futures", "title": "Futures crate"}
                ],
                "total_filtered": 0,
                "backend": "searxng"
            }),
        });
        // Done+Usage triggers final chunk with grounding folded in.
        builder.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("STOP".to_string()),
        });
        let out = builder.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 1,
            completion_tokens: 1,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 2,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        let final_chunk = out
            .iter()
            .find(|c| c.contains("groundingMetadata"))
            .expect("expected groundingMetadata on the final chunk");
        // Both rounds' queries land in webSearchQueries.
        assert!(
            final_chunk.contains("\"rust 2024 edition\""),
            "final chunk: {final_chunk}"
        );
        assert!(
            final_chunk.contains("\"async streams\""),
            "final chunk: {final_chunk}"
        );
        // Round 2's new URI shows up.
        assert!(
            final_chunk.contains("\"uri\":\"https://crates.io/crates/futures\""),
            "final chunk: {final_chunk}"
        );
        assert!(
            final_chunk.contains("\"uri\":\"https://blog.rust-lang.org\""),
            "final chunk: {final_chunk}"
        );
        assert!(
            final_chunk.contains("\"uri\":\"https://doc.rust-lang.org/edition-guide\""),
            "final chunk: {final_chunk}"
        );
        // Cross-round dedup: blog.rust-lang.org appeared in round 1 (twice in
        // hits) and again in round 2. The final groundingMetadata must carry
        // exactly one entry. Counting the hostname covers both `uri` and any
        // future `domain` fields.
        let chunks_count = final_chunk.matches("blog.rust-lang.org").count();
        assert_eq!(chunks_count, 1, "expected dedup on URI: {final_chunk}");
    }

    #[test]
    fn gemini_builder_flush_pending_emits_tool_calls() {
        // If the upstream ends without a Done+Usage pair (truncation), the
        // accumulator must still flush so the client doesn't see a
        // tool-less stream.
        let mut builder = GeminiResponseBuilder::new("gemini-2.5-pro".to_string());
        builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_x".to_string()),
            function_name: Some("noop".to_string()),
            arguments_delta: r#"{"k":1}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        let out = builder.flush_pending();
        assert!(!out.is_empty(), "flush_pending must emit deferred tool calls");
        assert!(out[0].contains("\"name\":\"noop\""), "{out:?}");
        assert!(out[0].contains("\"args\":{\"k\":1}"), "{out:?}");
    }

    /// A translated stream that ends with no finish is a response that
    /// stopped short: the Responses client is closed with
    /// `response.incomplete` (no reason — the gateway cannot know one), the
    /// call still open closed `incomplete`, and announced under a minted id
    /// since the client had not yet been handed it. A builder that sent nothing
    /// sends nothing.
    #[test]
    fn a_responses_stream_cut_short_ends_incomplete() {
        let mut builder = ResponsesResponseBuilder::new("resp_1".to_string(), "m".to_string());
        let mut out = builder.process_event(&DomainEvent::TextDelta("partial".to_string()));
        out.extend(builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: Some("read".to_string()),
            arguments_delta: r#"{"p":"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        }));
        out.extend(builder.flush_pending());
        let events: Vec<Value> = out
            .iter()
            .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")).and_then(|d| serde_json::from_str(d).ok()))
            .collect();
        let added: Vec<&Value> = events.iter().filter(|e| e["type"] == "response.output_item.added").map(|e| &e["item"]).collect();
        assert_eq!(added.iter().map(|i| i["type"].as_str().unwrap()).collect::<Vec<_>>(), ["message", "function_call"]);
        assert!(added[1]["call_id"].as_str().is_some_and(|id| !id.is_empty()), "{added:?}");
        let last = events.last().unwrap();
        assert_eq!(last["type"], "response.incomplete", "{events:?}");
        assert_eq!(last["response"]["status"], "incomplete");
        assert_eq!(last["response"]["incomplete_details"], Value::Null);
        let statuses: Vec<&str> = last["response"]["output"].as_array().unwrap().iter().map(|i| i["status"].as_str().unwrap()).collect();
        // The message ended when the call opened; the call is what was cut.
        assert_eq!(statuses, ["completed", "incomplete"]);
        assert!(builder.flush_pending().is_empty(), "the response ends once");
        assert!(ResponsesResponseBuilder::new("resp_2".to_string(), "m".to_string()).flush_pending().is_empty());
    }

    /// A call first seen after the finish, still unidentified when the usage
    /// ends the stream, reaches the Chat client before the finish, which then
    /// says `tool_calls` — the client holds every call the audit records, and
    /// is told to run it.
    #[test]
    fn a_call_after_the_finish_reaches_the_chat_client_before_the_end() {
        let mut builder = ChatCompletionsResponseBuilder::new("m".to_string(), "req_1".to_string());
        let mut out = builder.process_event(&DomainEvent::Done {
            finish_reason: Some(crate::api::domain::FinishReason::Stop),
            native_finish_reason: None,
        });
        out.extend(builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: Some("late".to_string()),
            arguments_delta: r#"{"k":1}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        }));
        out.extend(builder.process_event(&DomainEvent::Usage(crate::api::domain::Usage {
            prompt_tokens: 1,
            completion_tokens: 1,
            total_tokens: 2,
            ..Default::default()
        })));
        let call = out.iter().position(|l| l.contains("\"name\":\"late\"")).expect("the late call was written");
        let finish = out.iter().position(|l| l.contains("\"finish_reason\":\"")).expect("the finish was written");
        let done = out.iter().position(|l| l.contains("[DONE]")).expect("the stream ended");
        assert!(call < finish && finish < done, "{out:?}");
        // The finish is a claim about every call the client got.
        assert!(out[finish].contains("\"finish_reason\":\"tool_calls\""), "{out:?}");
        assert_eq!(out.iter().filter(|l| l.contains("\"finish_reason\":\"")).count(), 1, "{out:?}");
    }

    /// A Gemini `functionCall` needs a name, so a call the stream never named
    /// reaches the client as a notice in its place, recorded once for the
    /// audit row; a named call beside it goes as a call.
    #[test]
    fn a_gemini_client_is_told_of_a_call_the_stream_never_named() {
        let mut builder = GeminiResponseBuilder::new("m".to_string());
        let delta = |index: usize, name: Option<&str>| DomainEvent::ToolCallDelta {
            index,
            id: Some(format!("call_{index}")),
            function_name: name.map(str::to_string),
            arguments_delta: r#"{"k":1}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        };
        let mut out = builder.process_event(&delta(0, None));
        out.extend(builder.process_event(&delta(1, Some("noop"))));
        out.extend(builder.process_event(&DomainEvent::Done {
            finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
            native_finish_reason: None,
        }));
        out.extend(builder.flush_pending());
        let parts: Vec<Value> = out
            .iter()
            .filter_map(|l| serde_json::from_str::<Value>(l.trim().strip_prefix("data: ")?).ok())
            .flat_map(|c| c["candidates"][0]["content"]["parts"].as_array().cloned().unwrap_or_default())
            .collect();
        assert_eq!(
            parts,
            [
                serde_json::json!({"text": crate::pipeline::response::NAMELESS_CALL_NOTICE}),
                serde_json::json!({"functionCall": {"id": "call_1", "name": "noop", "args": {"k": 1}}}),
            ]
        );
        assert_eq!(builder.take_withheld_calls(), [(0, crate::pipeline::response::Withheld::Nameless)]);
    }

    /// Call `index` with id `call_<index>`, named `name` (or not).
    fn call_delta(index: usize, name: Option<&str>) -> DomainEvent {
        DomainEvent::ToolCallDelta {
            index,
            id: Some(format!("call_{index}")),
            function_name: name.map(str::to_string),
            arguments_delta: r#"{"k":1}"#.to_string(),
            form: CallArguments::Json,
        }
    }

    fn data_frames(frames: &[String]) -> Vec<Value> {
        frames
            .iter()
            .flat_map(|f| f.lines())
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .collect()
    }

    const TOOL_CALLS_DONE: DomainEvent = DomainEvent::Done { finish_reason: Some(FinishReason::ToolCalls), native_finish_reason: None };

    /// An Anthropic `tool_use` block needs a name: a call the stream never
    /// named reaches the client as a text block telling it so, in the call's
    /// place, recorded once; a named call beside it goes as a call, and a
    /// later piece of the nameless call goes nowhere.
    #[test]
    fn an_anthropic_client_is_told_of_a_call_the_stream_never_named() {
        let mut builder = AnthropicResponseBuilder::new("m".into(), "req1".into(), None, None, 0, 0);
        let mut frames = builder.process_event(&call_delta(0, None));
        frames.extend(builder.process_event(&call_delta(1, Some("noop"))));
        frames.extend(builder.process_event(&call_delta(0, Some("late"))));
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        let starts: Vec<&Value> =
            events.iter().filter(|e| e["type"] == "content_block_start").map(|e| &e["content_block"]).collect();
        assert_eq!(starts.iter().map(|b| b["type"].as_str().unwrap()).collect::<Vec<_>>(), ["text", "tool_use"], "{events:?}");
        assert_eq!(starts[1]["name"], "noop");
        let text: String = events
            .iter()
            .filter(|e| e["delta"]["type"] == "text_delta")
            .map(|e| e["delta"]["text"].as_str().unwrap())
            .collect();
        assert_eq!(text, crate::pipeline::response::NAMELESS_CALL_NOTICE, "told once, in the call's place");
        let stop = events.iter().find(|e| e["type"] == "message_delta").unwrap();
        assert_eq!(stop["delta"]["stop_reason"], "tool_use", "a named call reached the client");
        assert_eq!(builder.take_withheld_calls(), [(0, crate::pipeline::response::Withheld::Nameless)]);

        // A turn whose only call was nameless claims no call — an empty name
        // (a script's rebuild of the call) names nothing either.
        let mut builder = AnthropicResponseBuilder::new("m".into(), "req2".into(), None, None, 0, 0);
        let mut frames = builder.process_event(&call_delta(0, Some("")));
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        assert!(events.iter().all(|e| e["content_block"]["type"] != "tool_use"), "{events:?}");
        let stop = events.iter().find(|e| e["type"] == "message_delta").unwrap();
        assert_eq!(stop["delta"]["stop_reason"], "end_turn");

        // A lax server's call after the finish, while the end waits for the
        // usage: the stop is settled at the end, over what the client holds.
        let mut builder = AnthropicResponseBuilder::new("m".into(), "req3".into(), None, None, 0, 0);
        let mut frames = builder.process_event(&DomainEvent::TextDelta("ok".into()));
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.process_event(&call_delta(0, None)));
        frames.extend(builder.process_event(&DomainEvent::Usage(crate::api::domain::Usage {
            prompt_tokens: 3,
            completion_tokens: 2,
            ..Default::default()
        })));
        let events = data_frames(&frames);
        let stop = events.iter().find(|e| e["type"] == "message_delta").unwrap();
        assert_eq!(stop["delta"]["stop_reason"], "end_turn", "{events:?}");
        assert_eq!(builder.take_withheld_calls(), [(0, crate::pipeline::response::Withheld::Nameless)]);

        // Any call withheld whole settles the same: a built-in tool the
        // client cannot run, told in its place.
        let builtin = crate::api::domain::ClientBuiltin::Shell;
        let mut builder = AnthropicResponseBuilder::new("m".into(), "req4".into(), None, None, 0, 0);
        let mut frames = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_0".into()),
            function_name: Some(builtin.tool_name().into()),
            arguments_delta: "{}".into(),
            form: CallArguments::ClientBuiltin(builtin),
        });
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        let stop = events.iter().find(|e| e["type"] == "message_delta").unwrap();
        assert_eq!(stop["delta"]["stop_reason"], "end_turn", "{events:?}");
    }

    /// Parsed off the wire: an upstream call item opening with no id and an
    /// empty name is still a call — the client is told of it as nameless,
    /// never handed `""` or stray bytes.
    #[test]
    fn a_wire_call_with_an_empty_name_and_no_id_is_told_as_nameless() {
        let event = crate::api::sse::SseEvent {
            event_type: Some("response.output_item.added".into()),
            data: r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"","arguments":"{}"}}"#.into(),
            id: None,
        };
        let parsed = crate::api::sse::StreamParser::new(crate::api::sse::ApiVersion::Responses).parse(&event);
        let mut anthropic = AnthropicResponseBuilder::new("m".into(), "req1".into(), None, None, 0, 0);
        let mut chat = ChatCompletionsResponseBuilder::new("m".into(), "c".into());
        let (mut to_anthropic, mut to_chat) = (Vec::new(), Vec::new());
        for e in parsed.iter().chain([&TOOL_CALLS_DONE]) {
            to_anthropic.extend(anthropic.process_event(e));
            to_chat.extend(chat.process_event(e));
        }
        to_anthropic.extend(anthropic.flush_pending());
        to_chat.extend(chat.flush_pending());
        let (to_anthropic, to_chat) = (data_frames(&to_anthropic), data_frames(&to_chat));
        assert!(to_anthropic.iter().all(|e| e["content_block"]["type"] != "tool_use"), "{to_anthropic:?}");
        let text: String = to_anthropic.iter().filter_map(|e| e["delta"]["text"].as_str()).collect();
        assert_eq!(text, crate::pipeline::response::NAMELESS_CALL_NOTICE);
        assert!(to_chat.iter().all(|e| e["choices"][0]["delta"]["tool_calls"].is_null()), "{to_chat:?}");
        let text: String = to_chat.iter().filter_map(|e| e["choices"][0]["delta"]["content"].as_str()).collect();
        assert_eq!(text, crate::pipeline::response::NAMELESS_CALL_NOTICE);
        assert_eq!(anthropic.take_withheld_calls().iter().map(|(_, w)| *w).collect::<Vec<_>>(), [crate::pipeline::response::Withheld::Nameless]);
        assert_eq!(chat.take_withheld_calls().iter().map(|(_, w)| *w).collect::<Vec<_>>(), [crate::pipeline::response::Withheld::Nameless]);
    }

    /// A Chat call is written with a name: a call the stream never named
    /// reaches the client as content telling it so, recorded once; the named
    /// call is the only call, and a turn with no other call finishes `stop`.
    #[test]
    fn a_chat_client_is_told_of_a_call_the_stream_never_named() {
        let mut builder = ChatCompletionsResponseBuilder::new("m".into(), "c".into());
        let mut frames = builder.process_event(&call_delta(0, None));
        frames.extend(builder.process_event(&call_delta(1, Some("noop"))));
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.process_event(&call_delta(0, Some("late"))));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        let calls: Vec<&Value> =
            events.iter().flat_map(|e| e["choices"][0]["delta"]["tool_calls"].as_array().into_iter().flatten()).collect();
        assert!(!calls.is_empty() && calls.iter().all(|c| c["id"] == "call_1"), "{events:?}");
        assert!(calls.iter().any(|c| c["function"]["name"] == "noop"));
        let text: String =
            events.iter().filter_map(|e| e["choices"][0]["delta"]["content"].as_str()).collect();
        assert_eq!(text, crate::pipeline::response::NAMELESS_CALL_NOTICE);
        let finishes: Vec<&Value> =
            events.iter().map(|e| &e["choices"][0]["finish_reason"]).filter(|f| !f.is_null()).collect();
        assert_eq!(finishes, [&serde_json::json!("tool_calls")]);
        assert_eq!(builder.take_withheld_calls(), [(0, crate::pipeline::response::Withheld::Nameless)]);

        // An empty name (a script's rebuild of the call) names nothing.
        let mut builder = ChatCompletionsResponseBuilder::new("m".into(), "c2".into());
        let mut frames = builder.process_event(&call_delta(0, Some("")));
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        assert!(events.iter().all(|e| e["choices"][0]["delta"]["tool_calls"].is_null()), "{events:?}");
        let finishes: Vec<&Value> =
            events.iter().map(|e| &e["choices"][0]["finish_reason"]).filter(|f| !f.is_null()).collect();
        assert_eq!(finishes, [&serde_json::json!("stop")]);

        // Any call withheld whole settles the same: a built-in tool the
        // client cannot run, told in its place.
        let builtin = crate::api::domain::ClientBuiltin::ApplyPatch;
        let mut builder = ChatCompletionsResponseBuilder::new("m".into(), "c3".into());
        let mut frames = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_0".into()),
            function_name: Some(builtin.tool_name().into()),
            arguments_delta: "{}".into(),
            form: CallArguments::ClientBuiltin(builtin),
        });
        frames.extend(builder.process_event(&TOOL_CALLS_DONE));
        frames.extend(builder.flush_pending());
        let events = data_frames(&frames);
        let finishes: Vec<&Value> =
            events.iter().map(|e| &e["choices"][0]["finish_reason"]).filter(|f| !f.is_null()).collect();
        assert_eq!(finishes, [&serde_json::json!("stop")], "{events:?}");
    }

    #[test]
    fn gemini_to_responses_thinking() {
        let resp = gemini_thinking_fixture();
        let result = gemini_response_to_responses(&resp, "gemini-2.5-pro", "req_abcdef123456");
        let output = result["output"].as_array().unwrap();
        // message first, reasoning second (same convention as anthropic_to_responses)
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["content"][0]["text"], "The answer is 42.");
        assert_eq!(output[1]["type"], "reasoning");
        assert_eq!(output[1]["summary"][0]["text"], "Analyzing...");
    }

    /// Every Responses `function_call` carries a `call_id` the client answers
    /// it by — unique even where Gemini named none, and Gemini's own when it did.
    #[test]
    fn a_gemini_call_reaches_a_responses_client_with_its_own_call_id() {
        let resp = serde_json::json!({
            "candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "read", "args": {"path": "a"}}},
                {"functionCall": {"name": "read", "args": {"path": "b"}}},
                {"functionCall": {"id": "g-1", "name": "grep", "args": {}}}
            ]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}
        });
        let result = gemini_response_to_responses(&resp, "gemini-2.5-pro", "req_abcdef123456");
        let calls: Vec<&Value> = result["output"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["type"] == "function_call")
            .collect();
        let ids: Vec<&str> = calls.iter().map(|c| c["call_id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1], "{ids:?}");
        assert!(!ids[0].is_empty() && !ids[1].is_empty(), "{ids:?}");
        assert_eq!(ids[2], "g-1");
    }

    /// A whole Responses answer's stop is read from its status once, and the
    /// calls it carries, on every target and on the stream: a completed turn
    /// that called a tool stopped for it, a failed or cancelled one is an
    /// error (a call it carries keeps `tool_calls` on Chat, which says what
    /// the message holds), an incomplete one is a cut or a filter.
    #[test]
    fn a_responses_status_reads_as_one_finish_on_every_target() {
        let answer = |status: &str, call: bool| {
            let mut output = vec![serde_json::json!({"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "ok", "annotations": []}]})];
            if call {
                output.push(serde_json::json!({"type": "function_call", "id": "fc_1", "call_id": "call_1",
                    "name": "lookup", "arguments": "{}", "status": "completed"}));
            }
            serde_json::json!({"id": "resp_1", "object": "response", "status": status, "output": output,
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
        };
        // One row per class of `status` (and of `incomplete_details.reason`),
        // each target's word written from its own spec.
        for (status, reason, call, anthropic, chat, gemini) in [
            ("completed", None, true, "tool_use", Some("tool_calls"), "STOP"),
            ("completed", None, false, "end_turn", Some("stop"), "STOP"),
            ("incomplete", None, true, "max_tokens", Some("length"), "MAX_TOKENS"),
            ("incomplete", Some("max_output_tokens"), true, "max_tokens", Some("length"), "MAX_TOKENS"),
            ("incomplete", Some("content_filter"), true, "end_turn", Some("content_filter"), "SAFETY"),
            ("failed", None, true, "end_turn", None, "OTHER"),
            ("cancelled", None, true, "end_turn", None, "OTHER"),
            // Not finished: no finish is stated, so the calls decide.
            ("in_progress", None, true, "tool_use", Some("tool_calls"), "STOP"),
            ("queued", None, false, "end_turn", Some("stop"), "STOP"),
        ] {
            let mut body = answer(status, call);
            if let Some(reason) = reason {
                body["incomplete_details"] = serde_json::json!({"reason": reason});
            }
            let case = format!("{status} {reason:?}, call: {call}");
            let got = responses_response_to_anthropic(&body, "m", "abc12345", None, None, 0);
            assert_eq!(got["stop_reason"], anthropic, "{case}: {got}");
            // A failed turn's Chat word follows the calls the message still
            // carries, not the status, and is not this table's claim.
            if let Some(chat) = chat {
                let got = responses_response_to_chat_completions(&body, "m");
                assert_eq!(got["choices"][0]["finish_reason"], chat, "{case}: {got}");
            }
            let got = responses_to_gemini_response(&body);
            assert_eq!(got["candidates"][0]["finishReason"], gemini, "{case}: {got}");

            // The stream's final event reads the same status the same way.
            let event = crate::api::sse::SseEvent {
                event_type: Some("response.completed".to_string()),
                data: serde_json::json!({"response": body}).to_string(),
                id: None,
            };
            let events = crate::api::sse::parse_domain_event(&event, crate::api::sse::ApiVersion::Responses);
            let Some(DomainEvent::Done { finish_reason, .. }) = events.last() else {
                panic!("{case}: no Done in {events:?}");
            };
            assert_eq!(*finish_reason, responses_answer_finish(&body), "{case}");
        }
    }

    #[test]
    fn anthropic_to_chat_completions_has_created() {
        let resp = serde_json::json!({
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let result = anthropic_to_chat_completions(&resp, "claude-3");
        assert!(result["created"].as_i64().unwrap_or(0) > 0);
    }

    #[test]
    fn responses_to_chat_completions_has_created() {
        let resp = serde_json::json!({
            "id": "resp_1",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "ok"}]
            }],
            "status": "completed",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let result = responses_response_to_chat_completions(&resp, "gpt-4o");
        assert!(result["created"].as_i64().unwrap_or(0) > 0);
    }

    /// A Responses upstream's custom (freeform) tool call reaches a client of
    /// a protocol with no freeform call as the call it is — that protocol's
    /// function call, carrying the free text as `{"input": …}` — never nothing.
    /// (A Chat client gets its own custom call:
    /// `a_responses_custom_tool_call_reaches_a_chat_client_as_a_chat_custom_call`.)
    #[test]
    fn a_responses_custom_tool_call_reaches_every_other_client_as_a_call() {
        let resp = serde_json::json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": "*** Begin Patch"}
        ]});
        let input = serde_json::json!({"input": "*** Begin Patch"});
        let anthropic = responses_response_to_anthropic(&resp, "m", "req-1", None, None, 4096);
        let block = anthropic["content"].as_array().unwrap().iter().find(|b| b["type"] == "tool_use").expect("{anthropic}");
        assert_eq!((block["name"].as_str(), &block["input"]), (Some("apply_patch"), &input));
        let gemini = responses_to_gemini_response(&resp);
        let part = &gemini["candidates"][0]["content"]["parts"][0]["functionCall"];
        assert_eq!((part["name"].as_str(), &part["args"]), (Some("apply_patch"), &input), "{gemini}");
    }

    /// A Chat Completions upstream's custom (freeform) tool call reaches a
    /// client of another protocol as that protocol's call, carrying the free
    /// text as `{"input": …}` — never nothing.
    #[test]
    fn a_chat_custom_tool_call_reaches_every_other_client_as_a_call() {
        let resp = serde_json::json!({"id": "c", "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": null, "tool_calls": [
                {"id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Begin Patch"}}]}}]});
        let input = serde_json::json!({"input": "*** Begin Patch"});
        let anthropic = openai_response_to_anthropic(&resp, "m", "req-1", 0, None, None, 4096);
        let block = anthropic["content"].as_array().unwrap().iter().find(|b| b["type"] == "tool_use").cloned()
            .unwrap_or_default();
        assert_eq!((block["name"].as_str(), &block["input"]), (Some("apply_patch"), &input), "{anthropic}");
        let responses = chat_completions_to_responses_response(&resp, "m", "resp-1");
        let call = responses["output"].as_array().unwrap().iter().find(|i| i["type"] == "function_call").cloned()
            .unwrap_or_default();
        assert_eq!(call["name"], "apply_patch", "{responses}");
        assert_eq!(serde_json::from_str::<Value>(call["arguments"].as_str().unwrap_or("")).ok(), Some(input.clone()));
        let gemini = chat_completions_to_gemini_response(&resp);
        let part = &gemini["candidates"][0]["content"]["parts"][0]["functionCall"];
        assert_eq!((part["name"].as_str(), &part["args"]), (Some("apply_patch"), &input), "{gemini}");
    }

    /// A Responses upstream's custom tool call reaches a Chat client as the
    /// Chat custom call it is — `{type: "custom", custom: {name, input}}` —
    /// the form a Chat client that declared a custom tool reads.
    #[test]
    fn a_responses_custom_tool_call_reaches_a_chat_client_as_a_chat_custom_call() {
        let resp = serde_json::json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": "*** Begin Patch"}
        ]});
        let chat = responses_response_to_chat_completions(&resp, "m");
        assert_eq!(chat["choices"][0]["message"]["tool_calls"][0], serde_json::json!({
            "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Begin Patch"}}), "{chat}");
        assert_eq!(chat["choices"][0]["finish_reason"], "tool_calls");
    }
}
