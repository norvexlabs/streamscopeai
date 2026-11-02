//! Response-phase state accumulation across the SSE stream.
//!
//! [`TransformState`] collects usage counters, finish reason, timing metrics,
//! accumulated text/reasoning/tool calls, and response-side transform artifacts
//! as streaming events arrive. This state feeds the [`AuditRecord`](crate::audit::AuditRecord)
//! after the stream completes. Text accumulation is capped at 256 KB to bound memory.

use serde::{Deserialize, Serialize};

use crate::api::domain::{DomainEvent, FinishReason, Usage};
use crate::api::sse::ApiVersion;

/// Maximum accumulated text size (256 KB) to prevent unbounded memory growth.
const MAX_ACCUMULATED_TEXT_BYTES: usize = 256 * 1024;

/// Surface marker appended once when the streaming accumulator crosses
/// [`MAX_ACCUMULATED_TEXT_BYTES`]. Lets operators tell a capped stream apart from
/// a complete-but-large one. The ellipsis (`…`) matches the convention used by
/// [`crate::proxy::truncate_with_marker`] at other display-text cap sites.
const ACCUMULATOR_TRUNCATED_MARKER: &str = "\n…[truncated: exceeded 256 KB accumulator cap]";

/// A tool call reassembled from streaming ToolCallDelta events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccumulatedToolCall {
    pub index: usize,
    pub id: String,
    pub function_name: String,
    pub arguments: String,
    /// A call the upstream ran itself — an Anthropic `server_tool_use` /
    /// `mcp_tool_use` block, a Responses `mcp_call` — recorded like any call,
    /// but never one a client runs. Additive on the stored row: absent reads
    /// as `false`, and `false` is not written, so rows stay readable by
    /// builds on either side of it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server_tool: bool,
}

/// The notice a client is given — once per call — for arguments of a tool call
/// it will never get: bytes that arrived after the call ended (policy read it,
/// the client's block for it closed, or its own end came).
pub const WITHHELD_NOTICE: &str = "\n[Part of a tool call's arguments arrived after the call ended, and was withheld.]\n";

/// The notice a client is given in place of a tool call the stream never
/// named: no protocol's call can go without a name.
pub const NAMELESS_CALL_NOTICE: &str = "\n[A tool call arrived without a name, and was not delivered.]\n";

/// Why a client's emitter did not give it a call's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withheld {
    /// Arguments of a call that arrived after its end, or of no call.
    Late,
    /// A call to a Responses built-in tool, which only a Responses client can
    /// run (see [`crate::api::domain::ClientBuiltin`]).
    NotCarried(crate::api::domain::ClientBuiltin),
    /// A call the stream never named: the client is told in its place.
    Nameless,
}

impl Withheld {
    /// What the client is told in the bytes' place — through
    /// [`WithheldCalls::untold`], or, for a nameless call, written by its
    /// builder in the call's place.
    pub fn notice(self) -> &'static str {
        match self {
            Self::Late => WITHHELD_NOTICE,
            Self::NotCarried(builtin) => builtin.not_carried_notice(),
            Self::Nameless => NAMELESS_CALL_NOTICE,
        }
    }
}

/// The calls a client's emitter withheld bytes of, in order, and why — each
/// told to the client once ([`Self::untold`], or in the call's place for a
/// nameless one) and reported to the audit once ([`Self::take_unreported`]).
#[derive(Debug, Default)]
pub struct WithheldCalls {
    calls: Vec<(usize, Withheld)>,
    told: usize,
    reported: usize,
}

impl WithheldCalls {
    /// Withhold `bytes` of call `call`: whether this is the call's first
    /// withholding (the client is told once per call). Only bytes are
    /// withheld: a delta carrying none withholds nothing.
    pub fn withhold(&mut self, call: usize, bytes: &str) -> bool {
        !bytes.is_empty() && self.record(call, Withheld::Late)
    }

    /// Withhold call `call` to built-in tool `builtin` whole: whether this is
    /// the call's first word (the client is told once per call).
    pub fn not_carried(&mut self, call: usize, builtin: crate::api::domain::ClientBuiltin) -> bool {
        self.record(call, Withheld::NotCarried(builtin))
    }

    /// Withhold call `call`, which the stream never named, whole: whether
    /// this is the first time — the caller then writes [`NAMELESS_CALL_NOTICE`]
    /// in the call's place, so [`Self::untold`] never says it. A call whose
    /// late arguments were withheld already is still told this — the call
    /// itself goes missing here.
    pub fn nameless(&mut self, call: usize) -> bool {
        if self.is_nameless(call) {
            return false;
        }
        self.calls.push((call, Withheld::Nameless));
        true
    }

    /// Whether call `call` went to the client as a nameless call's notice.
    pub fn is_nameless(&self, call: usize) -> bool {
        self.calls.contains(&(call, Withheld::Nameless))
    }

    /// Whether any call was withheld whole — never named, or a built-in tool
    /// the client cannot run — rather than in part.
    pub fn any_whole(&self) -> bool {
        self.calls.iter().any(|&(_, why)| matches!(why, Withheld::Nameless | Withheld::NotCarried(_)))
    }

    fn record(&mut self, call: usize, why: Withheld) -> bool {
        if self.calls.iter().any(|(known, _)| *known == call) {
            return false;
        }
        self.calls.push((call, why));
        true
    }

    /// What the client has not been told yet — told now. A nameless call was
    /// told in its place.
    pub fn untold(&mut self) -> Vec<&'static str> {
        let untold = self.calls[self.told..]
            .iter()
            .filter(|(_, why)| *why != Withheld::Nameless)
            .map(|(_, why)| why.notice())
            .collect();
        self.told = self.calls.len();
        untold
    }

    /// The calls not yet reported to the audit — reported now.
    pub fn take_unreported(&mut self) -> Vec<(usize, Withheld)> {
        let taken = self.calls[self.reported..].to_vec();
        self.reported = self.calls.len();
        taken
    }
}

/// Ids a client's builder minted for calls the upstream had not identified
/// when they had to be written, in order — each reported to the audit once
/// ([`TransformState::client_id`]).
#[derive(Debug, Default)]
pub struct MintedIds(Vec<(usize, String)>);

impl MintedIds {
    /// Mint the id call `call` is written under.
    pub fn mint(&mut self, call: usize, id: String) -> String {
        self.0.push((call, id.clone()));
        id
    }

    /// The ids minted since the last take.
    pub fn take(&mut self) -> Vec<(usize, String)> {
        std::mem::take(&mut self.0)
    }
}

/// Accumulates state across the SSE stream for audit record generation.
#[derive(Debug)]
pub struct TransformState {
    pub api_version: ApiVersion,
    pub usage: Usage,
    pub finish_reason: Option<FinishReason>,
    pub native_finish_reason: Option<String>,
    pub started_at: std::time::Instant,
    pub first_token_at: Option<std::time::Instant>,
    pub event_count: u64,
    /// Accumulated response text from streaming TextDelta events.
    pub accumulated_text: String,
    /// A whole answer's other choices or candidates, each named by where it
    /// sits ([`crate::proxy::content::other_answers_text`]) — read by the
    /// response PII scan beside the first, which `accumulated_text` holds.
    pub other_answers: Vec<(String, String)>,
    /// Accumulated reasoning/thinking content from streaming ReasoningDelta events.
    pub accumulated_reasoning: String,
    /// Accumulated tool calls reassembled from streaming ToolCallDelta events.
    pub accumulated_tool_calls: Vec<AccumulatedToolCall>,
    /// Error message from upstream (if any).
    pub error_message: Option<String>,
    /// Error code from upstream (if any).
    pub error_code: Option<String>,
    /// Audit badges accumulated by the response pipeline (block accumulator,
    /// non-streaming policy/script paths, healing). Drained into
    /// `AuditRecord::badges` at finalize time.
    pub badges: crate::audit::BadgeBuilder,
    /// Per-program outcomes for the response phase (drained into
    /// `transform_diff.response_transform_programs`).
    pub response_program_outcomes: Vec<crate::proxy::content::TransformProgramRef>,
    /// Internal pipeline-path tag (`fastpath` | `buffered`). Analytics column,
    /// never user-facing.
    pub pipeline_path: Option<&'static str>,
    /// Per-step diffs from response-phase scripts.
    pub response_step_diffs: Vec<crate::proxy::content::TransformStepDiff>,
    /// Blocked response-side tool calls (argument-based policy).
    pub response_blocked_tools: Vec<crate::proxy::content::BlockedToolInfo>,
    /// Per-field rewrites of tool_call arguments captured by response-phase
    /// `replace` rules (and, in the future, by Rhai scripts that mutate
    /// `ctx.arguments`). Surfaced in `transform_diff.tool_arg_modifications`.
    pub tool_arg_modifications: Vec<crate::proxy::content::ToolArgModification>,
    /// Structured injection blocks from response-side transforms.
    pub response_injection_blocks: Vec<crate::proxy::content::InjectionBlock>,
    /// Inline-guardrail findings on web tool-results folded back this turn —
    /// one per flagged scan, drained into `transform_diff.guardrail_steps`.
    pub response_guardrail_steps: Vec<crate::proxy::content::GuardrailStepDiff>,
    /// Model tool calls the substitution agent loop intercepted and ran
    /// server-side this turn — drained into `transform_diff.intercepted_tool_calls`
    /// so the session view can replay each as a visible, interception-banner'd
    /// `ToolCall` (the call is absorbed by the loop, never in `response_tool_calls`).
    pub response_intercepted_tool_calls: Vec<crate::proxy::content::InterceptedToolCall>,
    /// Original response text before response-phase transforms modified it.
    pub original_response_content: Option<String>,
    /// Original response tool calls before response-phase blocking.
    pub original_response_tool_calls: Option<serde_json::Value>,

    /// Number of images generated via Responses API `image_generation` tool.
    pub image_generation_count: u32,
    /// Base64 image results from `image_generation` (for audit blob capture).
    pub image_generation_results: Vec<String>,

    // Error tracking for audit
    /// True when the client disconnected before the stream completed.
    pub client_disconnected: bool,
    /// True once the upstream finished the answer being streamed (its `Done`
    /// in the final round). A client that hangs up after this point — Codex
    /// closes on `response.completed`, before the upstream's trailing framing
    /// arrives — received the whole answer, so the exchange is not abandoned.
    pub answer_ended: bool,
    /// True when the stream timed out due to idle timeout.
    pub stream_timed_out: bool,
    /// HTTP status code from upstream (for non-streaming error paths).
    pub upstream_status_code: Option<u16>,
}

impl TransformState {
    pub fn new(api_version: ApiVersion) -> Self {
        Self {
            api_version,
            usage: Usage::default(),
            finish_reason: None,
            native_finish_reason: None,
            started_at: std::time::Instant::now(),
            first_token_at: None,
            event_count: 0,
            accumulated_text: String::new(),
            accumulated_reasoning: String::new(),
            accumulated_tool_calls: Vec::new(),
            error_message: None,
            error_code: None,
            badges: crate::audit::BadgeBuilder::new(),
            response_program_outcomes: Vec::new(),
            pipeline_path: None,
            response_step_diffs: Vec::new(),
            response_blocked_tools: Vec::new(),
            tool_arg_modifications: Vec::new(),
            response_injection_blocks: Vec::new(),
            response_guardrail_steps: Vec::new(),
            response_intercepted_tool_calls: Vec::new(),
            other_answers: Vec::new(),
            original_response_content: None,
            original_response_tool_calls: None,
            image_generation_count: 0,
            image_generation_results: Vec::new(),
            client_disconnected: false,
            answer_ended: false,
            stream_timed_out: false,
            upstream_status_code: None,
        }
    }

    /// Create with an explicit start time (for accurate latency when the upstream
    /// request was initiated before this state object is constructed).
    pub fn new_with_start(api_version: ApiVersion, started_at: std::time::Instant) -> Self {
        Self {
            started_at,
            ..Self::new(api_version)
        }
    }

    /// The `transform` of the record that arguments of a tool call arriving
    /// after the call ended were withheld ([`Self::arguments_withheld`]).
    pub const ARGUMENTS_WITHHELD: &'static str = "tool_call_end";

    /// The `transform` of the record of the id a client was given for a call
    /// the upstream had not identified when the client's builder wrote it
    /// ([`Self::client_id`]).
    pub const CLIENT_ID: &'static str = "tool_call_id";

    /// The `transform` of the record that a call to a Responses built-in tool
    /// was not carried to a client that cannot run it ([`Self::not_carried`]).
    pub const NOT_CARRIED: &'static str = "tool_call_not_carried";

    /// The record that the client was given call `call` (a stream's call
    /// number) under `id`, an id the gateway minted: the upstream had sent
    /// none by the time the call had to be written. The call's own record
    /// keeps the upstream's id, where one came later.
    pub fn client_id(call: usize, id: &str) -> crate::proxy::content::InjectionBlock {
        crate::proxy::content::InjectionBlock {
            transform: Self::CLIENT_ID.to_string(),
            scope: "tool_use".to_string(),
            field: "id".to_string(),
            action: "replace".to_string(),
            content: format!("tool call {call}: the client was given the id {id}"),
        }
    }

    /// The record that arguments of tool call `call` (a stream's call number,
    /// or [`DomainEvent::NO_CALL`]) that arrived after the call ended were
    /// withheld — one wording, whichever reader withheld them: the stream
    /// parser (a piece after a custom call's end), response tool policy (bytes
    /// after it read the call), or a client's emitter (bytes after the call's
    /// block closed).
    pub fn arguments_withheld(call: usize) -> crate::proxy::content::InjectionBlock {
        let content = if call == DomainEvent::NO_CALL {
            "tool-call arguments that arrived for no open call were withheld".to_string()
        } else {
            format!("tool call {call}: arguments that arrived after the call ended were withheld")
        };
        crate::proxy::content::InjectionBlock {
            transform: Self::ARGUMENTS_WITHHELD.to_string(),
            scope: "tool_use".to_string(),
            field: "arguments".to_string(),
            action: "remove".to_string(),
            content,
        }
    }

    /// The record that call `call` (a stream's call number), which the stream
    /// never named, was not carried to a client whose protocol needs a name.
    pub fn nameless_not_carried(call: usize) -> crate::proxy::content::InjectionBlock {
        crate::proxy::content::InjectionBlock {
            transform: Self::NOT_CARRIED.to_string(),
            scope: "tool_use".to_string(),
            field: "tool_call".to_string(),
            action: "remove".to_string(),
            content: format!("tool call {call}: a call the stream never named was not carried to this client"),
        }
    }

    /// The record that call `call` (a stream's call number), to Responses
    /// built-in tool `builtin`, was not carried to a client that cannot run it.
    pub fn not_carried(call: usize, builtin: crate::api::domain::ClientBuiltin) -> crate::proxy::content::InjectionBlock {
        crate::proxy::content::InjectionBlock {
            transform: Self::NOT_CARRIED.to_string(),
            scope: "tool_use".to_string(),
            field: "tool_call".to_string(),
            action: "remove".to_string(),
            content: if call == DomainEvent::NO_CALL {
                format!("a call to the Responses built-in tool `{}` was not carried to this client", builtin.tool_name())
            } else {
                format!(
                    "tool call {call}: a call to the Responses built-in tool `{}` was not carried to this client",
                    builtin.tool_name()
                )
            },
        }
    }

    /// The record that call `call` (a stream's call number) to Responses
    /// built-in tool `builtin` was read before its payload was stated, and so
    /// withheld from the client whole.
    pub fn unread_withheld(call: usize, builtin: crate::api::domain::ClientBuiltin) -> crate::proxy::content::InjectionBlock {
        crate::proxy::content::InjectionBlock {
            transform: Self::ARGUMENTS_WITHHELD.to_string(),
            scope: "tool_use".to_string(),
            field: "tool_call".to_string(),
            action: "remove".to_string(),
            content: format!(
                "tool call {call}: a call to the Responses built-in tool `{}` was read before its payload was stated, and withheld",
                builtin.tool_name()
            ),
        }
    }

    /// Record what a client's emitter withheld of call `call`, and why.
    pub fn record_withheld(&mut self, call: usize, why: Withheld) {
        match why {
            Withheld::Late => self.record_arguments_withheld(call),
            Withheld::NotCarried(builtin) => self.record_injection_block(Self::not_carried(call, builtin)),
            Withheld::Nameless => self.record_injection_block(Self::nameless_not_carried(call)),
        }
    }

    /// Record `block` on the row — a withheld-arguments record once per call,
    /// however many readers withheld them.
    pub fn record_injection_block(&mut self, block: crate::proxy::content::InjectionBlock) {
        let recorded = block.transform == Self::ARGUMENTS_WITHHELD
            && self
                .response_injection_blocks
                .iter()
                .any(|b| b.transform == block.transform && b.content == block.content);
        if !recorded {
            self.response_injection_blocks.push(block);
        }
    }

    /// Record that arguments of tool call `call` were withheld (once).
    pub fn record_arguments_withheld(&mut self, call: usize) {
        self.record_injection_block(Self::arguments_withheld(call));
    }

    /// Process a domain event — accumulate usage and timing info.
    pub fn process_event(&mut self, event: &DomainEvent) {
        self.event_count += 1;

        // A freeform call's end is the closing piece of its arguments.
        let event = event.as_tool_call_delta();
        match event.as_ref() {
            DomainEvent::FreeformCallEnd { .. } => {}
            DomainEvent::TextDelta(text) => {
                if self.first_token_at.is_none() {
                    self.first_token_at = Some(std::time::Instant::now());
                }
                if self.accumulated_text.len() < MAX_ACCUMULATED_TEXT_BYTES {
                    self.accumulated_text.push_str(text);
                    if self.accumulated_text.len() >= MAX_ACCUMULATED_TEXT_BYTES {
                        self.accumulated_text.push_str(ACCUMULATOR_TRUNCATED_MARKER);
                    }
                }
            }
            DomainEvent::ReasoningDelta(text) => {
                if self.first_token_at.is_none() {
                    self.first_token_at = Some(std::time::Instant::now());
                }
                if self.accumulated_reasoning.len() < MAX_ACCUMULATED_TEXT_BYTES {
                    self.accumulated_reasoning.push_str(text);
                    if self.accumulated_reasoning.len() >= MAX_ACCUMULATED_TEXT_BYTES {
                        self.accumulated_reasoning.push_str(ACCUMULATOR_TRUNCATED_MARKER);
                    }
                }
            }
            // A custom call's text after the call's end is not glued onto its
            // closed arguments, and bytes of no call belong to none: the call
            // is recorded as it was closed, and the row says what was left out
            // (only bytes are: an empty piece leaves nothing out). A server
            // tool's input is recorded as that server tool's call, below.
            DomainEvent::ToolCallDelta { index, arguments_delta, form, .. }
                if *form == crate::api::domain::CallArguments::FreeformLate || *index == DomainEvent::NO_CALL =>
            {
                if !arguments_delta.is_empty() {
                    self.record_arguments_withheld(*index);
                }
            }
            DomainEvent::ToolCallDelta {
                index,
                id,
                function_name,
                arguments_delta,
                form,
            } => {
                if self.first_token_at.is_none() {
                    self.first_token_at = Some(std::time::Instant::now());
                }
                // Find existing entry by index or create a new one
                let entry = if let Some(existing) = self
                    .accumulated_tool_calls
                    .iter_mut()
                    .find(|tc| tc.index == *index)
                {
                    existing
                } else {
                    self.accumulated_tool_calls.push_mut(AccumulatedToolCall {
                        index: *index,
                        id: String::new(),
                        function_name: String::new(),
                        arguments: String::new(),
                        server_tool: false,
                    })
                };
                if *form == crate::api::domain::CallArguments::ServerTool {
                    entry.server_tool = true;
                }
                if let Some(tc_id) = id {
                    entry.id.clone_from(tc_id);
                }
                if let Some(name) = function_name {
                    entry.function_name.clone_from(name);
                }
                entry.arguments.push_str(arguments_delta);
            }
            DomainEvent::Usage(usage) => {
                if usage.prompt_tokens > 0 {
                    self.usage.prompt_tokens = usage.prompt_tokens;
                }
                if usage.completion_tokens > 0 {
                    self.usage.completion_tokens = usage.completion_tokens;
                }
                if usage.reasoning_tokens.is_some() {
                    self.usage.reasoning_tokens = usage.reasoning_tokens;
                }
                if usage.cache_creation_tokens.is_some() {
                    self.usage.cache_creation_tokens = usage.cache_creation_tokens;
                }
                if usage.cache_creation_1h_tokens.is_some() {
                    self.usage.cache_creation_1h_tokens = usage.cache_creation_1h_tokens;
                }
                if usage.cache_read_tokens.is_some() {
                    self.usage.cache_read_tokens = usage.cache_read_tokens;
                }
                if usage.audio_prompt_tokens.is_some() {
                    self.usage.audio_prompt_tokens = usage.audio_prompt_tokens;
                }
                if usage.audio_completion_tokens.is_some() {
                    self.usage.audio_completion_tokens = usage.audio_completion_tokens;
                }
                if usage.audio_prompt_seconds.is_some() {
                    self.usage.audio_prompt_seconds = usage.audio_prompt_seconds;
                }
                self.usage.total_tokens = self.usage.prompt_tokens + self.usage.completion_tokens;
            }
            DomainEvent::Done {
                finish_reason,
                native_finish_reason,
            } => {
                // Responses API reports "completed" even for tool calls.
                // Override to ToolCalls when the turn holds a call the client
                // runs — a server tool's is the upstream's, already run.
                if self.accumulated_tool_calls.iter().any(|c| !c.server_tool) {
                    self.finish_reason = Some(FinishReason::ToolCalls);
                } else {
                    self.finish_reason = finish_reason.clone();
                }
                self.native_finish_reason = native_finish_reason.clone();
            }
            DomainEvent::Error { message, code } => {
                self.finish_reason = Some(FinishReason::Error);
                self.error_message = Some(message.clone());
                self.error_code = code.clone();
            }
            DomainEvent::ImageGeneration { result_base64, .. } => {
                if self.first_token_at.is_none() {
                    self.first_token_at = Some(std::time::Instant::now());
                }
                self.image_generation_count += 1;
                if let Some(b64) = result_base64 {
                    // Cap stored images at 10 MB base64 to avoid memory bloat
                    if b64.len() <= 10 * 1024 * 1024 {
                        self.image_generation_results.push(b64.clone());
                    }
                }
            }
            // Substitution-emulated server-tool events. Counted under
            // their own per-iteration aggregation in a follow-up PR;
            // foundation PR no-ops to keep the match exhaustive.
            DomainEvent::ServerToolCallDelta { .. }
            | DomainEvent::ServerToolResult { .. }
            | DomainEvent::ServerToolError { .. } => {}
        }
    }

    /// What the response PII scan reads: the answer, then a whole answer's
    /// other choices, each named by where it sits; none that is blank. The
    /// one list both the row's scan (`finalize_audit`) and `/v1/analyze`'s
    /// verdict read.
    pub fn response_pii_inputs(&self) -> Vec<crate::guardrail::GuardrailInput> {
        std::iter::once((String::new(), self.full_response_content()))
            .chain(self.other_answers.iter().cloned())
            .filter(|(_, text)| !text.trim().is_empty())
            .map(|(target, classifiable)| crate::guardrail::GuardrailInput {
                id: "response".to_string(),
                classifiable,
                target,
            })
            .collect()
    }

    /// Build the full response content, wrapping reasoning in `<thinking>` tags.
    ///
    /// If the upstream provider sends reasoning via a dedicated `reasoning` field
    /// (e.g. OpenAI), `accumulated_reasoning` is populated and gets wrapped in
    /// `<thinking>` tags.
    ///
    /// If the model embeds `<think>...</think>` tags inside the content stream
    /// (e.g. Ollama LFM 2.5), `accumulated_reasoning` is empty and the tags live
    /// in `accumulated_text`. In that case we extract them here so that the stored
    /// `response_content` always uses the canonical `<thinking>` format and the
    /// content portion is clean.
    pub fn full_response_content(&self) -> String {
        let has_reasoning = !self.accumulated_reasoning.is_empty();
        let has_text = !self.accumulated_text.is_empty();
        match (has_reasoning, has_text) {
            (true, true) => format!(
                "<thinking>\n{}\n</thinking>\n\n{}",
                self.accumulated_reasoning, self.accumulated_text
            ),
            (true, false) => format!(
                "<thinking>\n{}\n</thinking>",
                self.accumulated_reasoning
            ),
            (false, true) => {
                // No dedicated reasoning field — check if the text stream contains
                // model-native <think>...</think> tags and normalize them.
                Self::normalize_inline_think_tags(&self.accumulated_text)
            }
            (false, false) => String::new(),
        }
    }

    /// Extract `<think>...</think>` (or `</think>` without opening, or an
    /// opening never closed) from model output that embeds thinking inline in
    /// the content stream, and rewrite to
    /// the canonical `<thinking>...</thinking>` format with clean content.
    fn normalize_inline_think_tags(text: &str) -> String {
        // Case 1: <think>REASONING</think>CONTENT (possibly with extra </think> later)
        if let Some(open) = text.find("<think>") {
            // Find the LAST </think> to handle models that leak reasoning
            // between multiple </think> tags
            if let Some(last_close) = text.rfind("</think>") {
                let think_start = open + "<think>".len();
                if last_close > think_start {
                    let reasoning = text[think_start..last_close].trim();
                    let before = text[..open].trim();
                    let after = text[last_close + "</think>".len()..].trim();
                    let clean = if before.is_empty() {
                        after.to_string()
                    } else {
                        format!("{before}\n{after}")
                    };
                    let clean = clean.trim().to_string();
                    if reasoning.is_empty() {
                        return clean;
                    }
                    if clean.is_empty() {
                        return format!("<thinking>\n{reasoning}\n</thinking>");
                    }
                    return format!("<thinking>\n{reasoning}\n</thinking>\n\n{clean}");
                }
            }
        }

        // Case 2: <think>REASONING, never closed — an answer cut off while the
        // model was still reasoning (a client gone mid-stream, an output cap
        // reached inside the thought). Only a thought that OPENS the answer:
        // a `<think>` later in prose is the model writing about the tag.
        if let Some(rest) = text.trim_start().strip_prefix("<think>")
            && !rest.contains("</think>")
        {
            let reasoning = rest.trim();
            return if reasoning.is_empty() {
                String::new()
            } else {
                format!("<thinking>\n{reasoning}\n</thinking>")
            };
        }

        // Case 3: REASONING</think>CONTENT (no opening tag — LFM 2.5 edge case)
        if let Some(close) = text.rfind("</think>") {
            let reasoning = text[..close].trim();
            let after = text[close + "</think>".len()..].trim();
            if !after.is_empty() && !reasoning.is_empty() {
                return format!(
                    "<thinking>\n{reasoning}\n</thinking>\n\n{after}"
                );
            }
        }

        // No think tags found — return as-is
        text.to_string()
    }

    /// Time to first token in milliseconds.
    pub fn ttft_ms(&self) -> u64 {
        self.first_token_at
            .map(|t| t.duration_since(self.started_at).as_millis() as u64)
            .unwrap_or(0)
    }

    /// Total latency in milliseconds.
    pub fn total_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call whose late arguments were withheld and which then goes missing
    /// for having no name is told both — once each, the second in the call's
    /// place — and both are reported.
    #[test]
    fn a_nameless_call_is_told_even_after_its_late_arguments_were() {
        let mut withheld = WithheldCalls::default();
        assert!(withheld.withhold(2, "x"));
        assert!(withheld.nameless(2));
        assert!(!withheld.nameless(2), "told once");
        assert!(withheld.any_whole());
        assert_eq!(withheld.untold(), [WITHHELD_NOTICE], "the nameless call's notice is written in its place");
        assert!(withheld.untold().is_empty());
        assert_eq!(withheld.take_unreported(), [(2, Withheld::Late), (2, Withheld::Nameless)]);
    }

    #[test]
    fn an_answer_cut_off_inside_its_thought_is_still_canonical() {
        let cut = TransformState::normalize_inline_think_tags("<think>Let me weigh the");
        assert_eq!(cut, "<thinking>\nLet me weigh the\n</thinking>");
        assert_eq!(TransformState::normalize_inline_think_tags("\n<think>  a\n"), "<thinking>\na\n</thinking>");
        // An opening with nothing after it yet is no reasoning at all.
        assert_eq!(TransformState::normalize_inline_think_tags("<think>"), "");
        // A tag the prose merely names is the answer, left as written.
        let prose = "Qwen wraps its reasoning in a <think> tag, followed by the reply";
        assert_eq!(TransformState::normalize_inline_think_tags(prose), prose);
        // Positive control: a closed thought still takes the closed-tag branch.
        assert_eq!(
            TransformState::normalize_inline_think_tags("<think>a</think>b"),
            "<thinking>\na\n</thinking>\n\nb"
        );
    }

    proptest::proptest! {
        /// Normalising never touches an answer that carries no think tag, and
        /// a thought cut off at any point keeps every reasoning character it
        /// had (trimmed), wrapped once. Not claimed: idempotence over text
        /// that already holds a canonical `<thinking>` block.
        #[test]
        fn a_cut_off_thought_keeps_its_reasoning_and_plain_text_is_untouched(
            s in "[^<>]{0,64}",
        ) {
            proptest::prop_assert_eq!(TransformState::normalize_inline_think_tags(&s), s.clone());
            let cut = TransformState::normalize_inline_think_tags(&format!("<think>{s}"));
            let expected = if s.trim().is_empty() {
                String::new()
            } else {
                format!("<thinking>\n{}\n</thinking>", s.trim())
            };
            proptest::prop_assert_eq!(cut, expected);
        }

        /// A `<think>` the prose names after some text, with no closing tag
        /// after it, is the answer, left as written.
        #[test]
        fn a_tag_named_mid_answer_is_left_as_written(
            before in "[^<>]{0,32}[^<>\\s][^<>]{0,32}",
            after in "[^<>]{0,64}",
        ) {
            let text = format!("{before}<think>{after}");
            proptest::prop_assert_eq!(TransformState::normalize_inline_think_tags(&text), text);
        }
    }

    #[test]
    fn normalize_inline_think_tags_basic() {
        let input = "<think>reasoning here</think>\n\nParis";
        let result = TransformState::normalize_inline_think_tags(input);
        assert!(result.starts_with("<thinking>"));
        assert!(result.contains("reasoning here"));
        assert!(result.ends_with("Paris"));
        // Content should NOT contain <think> tags
        assert!(!result.contains("<think>"));
        assert!(!result.contains("</think>"));
    }

    #[test]
    fn normalize_inline_think_tags_leaked_reasoning() {
        // Model leaks reasoning between </think> tags
        let input = "<think>deep reasoning</think>\nWait but also...\n</think>\n\nActual answer";
        let result = TransformState::normalize_inline_think_tags(input);
        assert!(result.starts_with("<thinking>"));
        assert!(result.contains("deep reasoning"));
        assert!(result.contains("Wait but also"));
        assert!(result.ends_with("Actual answer"));
        // Clean content should NOT have leaked reasoning
        let after_closing = result.split("</thinking>").last().unwrap().trim();
        assert_eq!(after_closing, "Actual answer");
    }

    #[test]
    fn normalize_inline_think_tags_no_opening() {
        // LFM 2.5 edge case: no opening tag
        let input = "some reasoning\n</think>\n\nthe answer";
        let result = TransformState::normalize_inline_think_tags(input);
        assert!(result.starts_with("<thinking>"));
        assert!(result.contains("some reasoning"));
        assert!(result.ends_with("the answer"));
    }

    #[test]
    fn normalize_no_tags() {
        let input = "just a plain answer";
        let result = TransformState::normalize_inline_think_tags(input);
        assert_eq!(result, "just a plain answer");
    }

    #[test]
    fn full_response_content_with_inline_think_tags() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        state.process_event(&DomainEvent::TextDelta(
            "<think>model reasoning</think>\nParis".to_string(),
        ));
        let result = state.full_response_content();
        assert!(result.starts_with("<thinking>"));
        assert!(result.contains("model reasoning"));
        assert!(result.ends_with("Paris"));
    }

    #[test]
    fn accumulates_text_from_multiple_deltas() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        state.process_event(&DomainEvent::TextDelta("Hello ".to_string()));
        state.process_event(&DomainEvent::TextDelta("world".to_string()));
        state.process_event(&DomainEvent::TextDelta("!".to_string()));
        assert_eq!(state.accumulated_text, "Hello world!");
        assert_eq!(state.event_count, 3);
        assert!(state.first_token_at.is_some());
    }

    #[test]
    fn text_accumulation_respects_size_limit() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        // Push a chunk that fills past the limit
        let big_chunk = "x".repeat(MAX_ACCUMULATED_TEXT_BYTES + 100);
        state.process_event(&DomainEvent::TextDelta(big_chunk));
        // First chunk accepted (even if oversized — it's a single event)
        assert!(state.accumulated_text.len() >= MAX_ACCUMULATED_TEXT_BYTES);
        // Truncation marker appended exactly once at the tail
        assert!(state.accumulated_text.ends_with(ACCUMULATOR_TRUNCATED_MARKER));
        // Subsequent chunks should be dropped (marker stays last, not duplicated)
        state.process_event(&DomainEvent::TextDelta("more".to_string()));
        assert!(!state.accumulated_text.ends_with("more"));
        assert!(state.accumulated_text.ends_with(ACCUMULATOR_TRUNCATED_MARKER));
        assert_eq!(
            state.accumulated_text.matches(ACCUMULATOR_TRUNCATED_MARKER).count(),
            1
        );
    }

    #[test]
    fn reassembles_fragmented_tool_call() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        // First delta: id + function name
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_123".to_string()),
            function_name: Some("get_weather".to_string()),
            arguments_delta: "{\"loc".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Second delta: more arguments
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: "ation\":\"NYC\"}".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });

        assert_eq!(state.accumulated_tool_calls.len(), 1);
        let tc = &state.accumulated_tool_calls[0];
        assert_eq!(tc.id, "call_123");
        assert_eq!(tc.function_name, "get_weather");
        assert_eq!(tc.arguments, "{\"location\":\"NYC\"}");
    }

    #[test]
    fn reassembles_multiple_parallel_tool_calls() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        // Tool call 0 start
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_a".to_string()),
            function_name: Some("func_a".to_string()),
            arguments_delta: "{\"a\":".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Tool call 1 start
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 1,
            id: Some("call_b".to_string()),
            function_name: Some("func_b".to_string()),
            arguments_delta: "{\"b\":".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Tool call 0 continue
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: "1}".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Tool call 1 continue
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 1,
            id: None,
            function_name: None,
            arguments_delta: "2}".to_string(),
            form: crate::api::domain::CallArguments::Json,
        });

        assert_eq!(state.accumulated_tool_calls.len(), 2);
        assert_eq!(state.accumulated_tool_calls[0].function_name, "func_a");
        assert_eq!(state.accumulated_tool_calls[0].arguments, "{\"a\":1}");
        assert_eq!(state.accumulated_tool_calls[1].function_name, "func_b");
        assert_eq!(state.accumulated_tool_calls[1].arguments, "{\"b\":2}");
    }

    #[test]
    fn finish_reason_overridden_to_tool_calls_when_tool_calls_present() {
        let mut state = TransformState::new(ApiVersion::Responses);
        // Accumulate a tool call
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("bash".to_string()),
            arguments_delta: r#"{"cmd":"ls"}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Responses API sends "completed" status → maps to FinishReason::Stop
        state.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("completed".to_string()),
        });
        // Should be overridden to ToolCalls because we have accumulated tool calls
        assert_eq!(state.finish_reason, Some(FinishReason::ToolCalls));
        assert_eq!(state.native_finish_reason, Some("completed".to_string()));
    }

    /// A turn whose only calls are server tools the upstream ran itself is
    /// no turn of tool calls: the client is told it stopped, and the audit
    /// row says the same — while recording the server tool's call. A client
    /// call beside them makes it one.
    #[test]
    fn a_turn_of_server_tools_alone_does_not_finish_in_tool_calls() {
        let frame = |name: &str, data: serde_json::Value| crate::api::sse::SseEvent { event_type: Some(name.into()), data: data.to_string(), id: None };
        for (client_call, want) in [(false, FinishReason::Stop), (true, FinishReason::ToolCalls)] {
            let mut frames = vec![
                frame("response.output_item.added", serde_json::json!({"output_index": 0,
                    "item": {"id": "mcp_1", "type": "mcp_call", "name": "fetch", "server_label": "srv", "arguments": ""}})),
                frame("response.mcp_call_arguments.delta", serde_json::json!({"item_id": "mcp_1", "output_index": 0, "delta": "{}"})),
            ];
            if client_call {
                frames.push(frame("response.output_item.added", serde_json::json!({"output_index": 1,
                    "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "bash", "arguments": "{}"}})));
            }
            frames.push(frame("response.completed", serde_json::json!({"response": {"id": "r", "status": "completed", "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})));
            let mut state = TransformState::new(ApiVersion::Responses);
            let mut parser = crate::api::sse::StreamParser::new(ApiVersion::Responses);
            for f in &frames {
                for e in parser.parse(f) {
                    state.process_event(&e);
                }
            }
            assert_eq!(state.finish_reason, Some(want), "client call: {client_call}");
            assert_eq!(state.accumulated_tool_calls[0].id, "mcp_1");
        }
    }

    #[test]
    fn finish_reason_not_overridden_when_no_tool_calls() {
        let mut state = TransformState::new(ApiVersion::Responses);
        // Only text, no tool calls
        state.process_event(&DomainEvent::TextDelta("Hello".to_string()));
        state.process_event(&DomainEvent::Done {
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("completed".to_string()),
        });
        // Should remain Stop
        assert_eq!(state.finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn done_event_empty_arguments_does_not_corrupt_accumulated() {
        let mut state = TransformState::new(ApiVersion::Responses);
        // Simulate delta accumulation
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("webfetch".to_string()),
            arguments_delta: r#"{"url":"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: None,
            arguments_delta: r#""https://example.com"}"#.to_string(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Simulate "done" event with empty arguments (our fix)
        state.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("webfetch".to_string()),
            arguments_delta: String::new(),
            form: crate::api::domain::CallArguments::Json,
        });
        // Arguments should be the accumulated deltas only, not doubled
        assert_eq!(state.accumulated_tool_calls.len(), 1);
        assert_eq!(
            state.accumulated_tool_calls[0].arguments,
            r#"{"url":"https://example.com"}"#
        );
    }

    // ─── Usage merge tests ───

    #[test]
    fn usage_merge_preserves_earlier_values() {
        let mut state = TransformState::new(ApiVersion::AnthropicMessages);
        // Anthropic message_start: prompt only
        state.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 500,
            completion_tokens: 0,
            reasoning_tokens: None,
            cache_creation_tokens: Some(50),
            cache_creation_1h_tokens: None,
            cache_read_tokens: Some(100),
            total_tokens: 500,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        // Anthropic message_delta: completion only
        state.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 0,
            completion_tokens: 200,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 200,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        assert_eq!(state.usage.prompt_tokens, 500);    // preserved, not overwritten to 0
        assert_eq!(state.usage.completion_tokens, 200); // updated
        assert_eq!(state.usage.total_tokens, 700);      // recalculated
        assert_eq!(state.usage.cache_creation_tokens, Some(50)); // preserved (second was None)
        assert_eq!(state.usage.cache_read_tokens, Some(100)); // preserved (second was None)
    }

    #[test]
    fn usage_single_complete_event() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        state.process_event(&DomainEvent::Usage(Usage {
            prompt_tokens: 1000,
            completion_tokens: 50,
            reasoning_tokens: Some(10),
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 1050,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        }));
        assert_eq!(state.usage.prompt_tokens, 1000);
        assert_eq!(state.usage.completion_tokens, 50);
        assert_eq!(state.usage.total_tokens, 1050);
        assert_eq!(state.usage.reasoning_tokens, Some(10));
    }
}
