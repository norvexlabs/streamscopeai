//! Response-side block buffering and policy enforcement.
//!
//! Accumulates complete content blocks (text, tool_use, thinking) from the SSE
//! stream, processes them through tool policy checks and response-phase Rhai
//! scripts, then emits the (possibly modified or suppressed) blocks to the client.

use std::sync::Arc;

use crate::api::domain::{CallArguments, DomainEvent};
use crate::api::sse::SseEvent;
use crate::proxy::content::TransformStepDiff;
use crate::scripting::response_context::ResponseBlockContext;
use crate::scripting::{ScriptEngine, ScriptFailMode, TransformProgram};

// ─── Types ───────────────────────────────────────────────────────────────────

/// Which block types to buffer (derived from active response transforms + tool risk rules).
#[derive(Debug, Default)]
pub struct BlockInterests {
    pub buffer_tool_blocks: bool,
    pub buffer_text_blocks: bool,
    pub buffer_thinking_blocks: bool,
}

impl BlockInterests {
    /// Returns true if ANY buffering is needed.
    pub fn is_active(&self) -> bool {
        self.buffer_tool_blocks || self.buffer_text_blocks || self.buffer_thinking_blocks
    }
}

/// Block type being accumulated.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockType {
    Text,
    Thinking,
    ToolUse,
}

/// A buffered event: domain event paired with its raw SSE event (for passthrough replay).
pub struct BufferedEvent {
    /// `None` for an upstream frame that carries no domain meaning — an
    /// Anthropic `content_block_stop`, a Responses `response.created`. It is
    /// nothing to the audit or the state, and everything to a pass-through
    /// client, which needs it in the position the upstream sent it in.
    pub domain_event: Option<DomainEvent>,
    pub raw_sse: Option<SseEvent>,
}

impl BufferedEvent {
    /// A frame the gateway forwards but does not understand.
    pub fn passthrough(raw: SseEvent) -> Self {
        Self { domain_event: None, raw_sse: Some(raw) }
    }
}

/// Maximum buffered events per block — prevents memory exhaustion from adversarial model output.
/// Set very high (64K events ≈ megabytes of tool arguments) so real-world tool calls are never
/// truncated. Only triggers on pathological upstream output.
/// If exceeded AND blocking rules exist: the block is **dropped** (fail-closed, not fail-open).
/// This is the secure default — incomplete analysis with active block rules = block.
const MAX_BUFFERED_EVENTS: usize = 65_536;

/// A block being accumulated from the SSE stream.
pub struct PendingBlock {
    pub block_type: BlockType,
    /// All buffered events for this block (for replay on allow).
    pub buffered: Vec<BufferedEvent>,
    // ── Accumulated content (built as events arrive) ──
    pub tool_call_id: Option<String>,
    pub tool_call_index: usize,
    pub tool_name: Option<String>,
    pub tool_arguments: String,
    pub text_content: String,
    pub thinking_content: String,
    /// Frames the upstream sent while this block was buffering that carry no
    /// domain event — the block's own `content_block_stop`, a Responses
    /// `output_text.done`. They belong after the block's content, so they wait
    /// with it and are emitted when it is.
    pub trailing: Vec<SseEvent>,
    /// Set on tool-use blocks whose `function_name` matched a request-phase
    /// substitution binding. When `Some`, the block is suppressed from the
    /// client renderer at flush time and pushed onto
    /// `BlockAccumulator.pending_intercepted` so the substitution agent
    /// loop can execute it through the bound handler.
    pub intercept_binding: Option<crate::proxy::content::InterceptBinding>,
    /// A thinking block whose own frames carried the upstream's signature over
    /// it (Anthropic `signature_delta`). Read off `trailing` when the block
    /// completes; see [`BlockRequestMeta::signed_thinking_reaches_client`].
    pub signed: bool,
    /// A custom (freeform) call — as its deltas' `form` says, never as its
    /// arguments look — and whether its arguments are closed: by its end, or
    /// by arriving whole.
    pub freeform: bool,
    pub freeform_closed: bool,
    /// A call to a Responses built-in tool the client runs — as its deltas'
    /// `form` says.
    pub builtin: Option<crate::api::domain::ClientBuiltin>,
}

/// A tool call captured for substitution dispatch. Built from a `PendingBlock`
/// whose `intercept_binding` matched. The substitution agent loop drains
/// these from `BlockAccumulator.pending_intercepted` after the upstream
/// stream completes, executes each via the bound `InterceptKind`, and feeds
/// the synthesised `ToolResult` back into the next upstream round.
#[derive(Debug, Clone)]
pub struct PendingInterceptedCall {
    pub binding: crate::proxy::content::InterceptBinding,
    /// Upstream-supplied id for the call. `None` for protocols that match
    /// tool calls positionally rather than by id (Gemini); the agent loop
    /// must fall back to `tool_call_index` for correlation in that case.
    pub tool_use_id: Option<String>,
    /// Wire tool name as emitted by the upstream (== `binding.replaced_name`
    /// for `Substitute`, or the original name for `InterceptOnly`).
    pub tool_name: String,
    /// Index assigned by the upstream for this tool call (per-protocol; the
    /// renderer uses it on the corresponding `ToolResult` if and when one is
    /// emitted).
    pub tool_call_index: usize,
    /// Concatenated `arguments_delta` payload as a JSON string. Caller
    /// parses this against the substituted tool's input schema.
    pub arguments_json: String,
    /// The `thoughtSignature` on the call's part (Gemini), which the
    /// continuation must send back with the call.
    pub thought_signature: Option<String>,
    /// Set by [`Self::police`] when a response-phase tool-call rule blocked
    /// the call: the rule's description. A blocked call is never run; the
    /// model's call is answered as refused (`WebError::PolicyBlocked`).
    pub blocked: Option<String>,
}

/// What the response-phase tool-call rules did to one intercepted call, for
/// the request's audit row (see [`PendingInterceptedCall::police`]).
#[derive(Debug, Default)]
pub struct InterceptPolicyRecord {
    /// The client's tool the call stands for.
    pub name: String,
    pub blocked: Option<crate::proxy::content::BlockedToolInfo>,
    pub modifications: Vec<crate::proxy::content::ToolArgModification>,
}

/// The tool the request withheld that a call by `name` is to, if any — the
/// one lookup every reader of a call makes before its own rules (see
/// [`BlockAccumulator::withheld_tools`]).
fn withheld_tool<'a>(
    withheld_tools: &'a [crate::proxy::content::BlockedToolInfo],
    name: &str,
) -> Option<&'a crate::proxy::content::BlockedToolInfo> {
    withheld_tools.iter().find(|w| w.name == name)
}

impl PendingInterceptedCall {
    /// Decide this call by the response-phase tool-call rules before the
    /// gateway runs it, as every call the client receives is decided: under
    /// the name the model called, the substitute's (`binding.replaced_name`)
    /// and the client's tool it stands for (`binding.original_name`), each
    /// reading the arguments as the one before left them — and, once one
    /// rewrote them, reading only the block rules, so a rule two names resolve
    /// to never rewrites twice and a rewrite never hides a block. A rewrite
    /// replaces `arguments_json`, which is what is run; a block sets
    /// `blocked`. Read on the arguments as healed, so a malformed call cannot
    /// slip past a rule on its arguments. A call under a name the request
    /// withheld (`withheld_tools`) is blocked first.
    pub fn police(
        &mut self,
        tool_rules: &[crate::config::tool_rules::Rule],
        field_profiles: &crate::config::tool_rules::FieldProfileSet,
        model: Option<&str>,
        app_id: Option<&str>,
        withheld_tools: &[crate::proxy::content::BlockedToolInfo],
    ) -> InterceptPolicyRecord {
        let mut record = InterceptPolicyRecord { name: self.binding.original_name.clone(), ..Default::default() };
        let sent = self.arguments_json.clone();
        let mut names: Vec<String> = Vec::new();
        for name in [&self.tool_name, &self.binding.replaced_name, &self.binding.original_name] {
            if !name.is_empty() && !names.contains(name) {
                names.push(name.clone());
            }
        }
        // Once a reading has rewritten the call, the later ones read only the
        // block rules: a rewrite they would take first must not hide a block.
        let block_rules = std::cell::OnceCell::new();
        for name in names {
            let rules: &[crate::config::tool_rules::Rule] = if record.modifications.is_empty() {
                tool_rules
            } else {
                block_rules.get_or_init(|| {
                    tool_rules
                        .iter()
                        .filter(|r| r.action.kind() == crate::config::tool_rules::ActionKind::Block)
                        .cloned()
                        .collect::<Vec<_>>()
                })
            };
            let args: Option<serde_json::Value> = serde_json::from_str(&self.arguments_json).ok();
            match evaluate_response_tool_call_policy(
                rules,
                withheld_tools,
                field_profiles,
                model,
                app_id,
                &name,
                &self.arguments_json,
                args.as_ref(),
            ) {
                ToolCallPolicy::Allow => {}
                ToolCallPolicy::Replace { new_args_str, modifications, .. } => {
                    self.arguments_json = new_args_str;
                    record.modifications.extend(modifications);
                }
                ToolCallPolicy::Block { rule_id, title, description } => {
                    // A rule without a title is named for the client's tool,
                    // never the reading's (an internal substitute's name).
                    let title = if title == format!("Response tool blocked: {name}") {
                        format!("Response tool blocked: {}", record.name)
                    } else {
                        title
                    };
                    // A blocked call runs nothing: it is kept, and recorded,
                    // as the model sent it — no rewrite applies to it.
                    self.arguments_json = sent;
                    record.modifications.clear();
                    self.blocked = Some(description.clone());
                    record.blocked = Some(crate::proxy::content::BlockedToolInfo {
                        not_applied: false,
                        name: record.name.clone(),
                        title,
                        description,
                        rule_id,
                        tool_use_id: self.tool_use_id.clone(),
                        call_index: None,
                        arguments: Some(
                            serde_json::from_str(&self.arguments_json)
                                .unwrap_or_else(|_| serde_json::Value::String(self.arguments_json.clone())),
                        ),
                    });
                    break;
                }
            }
        }
        record
    }
}

impl InterceptPolicyRecord {
    /// Record this outcome as a call the client receives is recorded: a
    /// block as a blocked response tool call, a rewrite as modified arguments.
    pub fn record_into(
        self,
        badges: &mut crate::audit::badge::BadgeBuilder,
        injection_blocks: &mut Vec<crate::proxy::content::InjectionBlock>,
        blocked_tools: &mut Vec<crate::proxy::content::BlockedToolInfo>,
        arg_modifications: &mut Vec<crate::proxy::content::ToolArgModification>,
    ) {
        if !self.modifications.is_empty() {
            badges.add_modified();
            injection_blocks.push(crate::proxy::content::InjectionBlock {
                transform: "tool_policy".to_string(),
                scope: "tool_use".to_string(),
                field: "arguments".to_string(),
                action: "replace".to_string(),
                content: format!("{}: {} field(s) rewritten", self.name, self.modifications.len()),
            });
            arg_modifications.extend(self.modifications);
        }
        if let Some(info) = self.blocked {
            badges.add_tool_blocked(crate::audit::Phase::Response, self.name.clone());
            injection_blocks.push(crate::proxy::content::InjectionBlock {
                transform: "tool_policy".to_string(),
                scope: "tool_use".to_string(),
                field: "tool_call".to_string(),
                action: "remove".to_string(),
                content: self.name,
            });
            blocked_tools.push(info);
        }
    }
}

impl PendingBlock {
    fn new(block_type: BlockType, event: &DomainEvent, raw_sse: Option<SseEvent>) -> Self {
        let mut block = Self {
            block_type,
            buffered: Vec::new(),
            trailing: Vec::new(),
            tool_call_id: None,
            tool_call_index: 0,
            tool_name: None,
            tool_arguments: String::new(),
            text_content: String::new(),
            thinking_content: String::new(),
            intercept_binding: None,
            signed: false,
            freeform: false,
            freeform_closed: false,
            builtin: None,
        };
        block.accumulate(event, raw_sse);
        block
    }

    fn accumulate(&mut self, event: &DomainEvent, raw_sse: Option<SseEvent>) {
        match event {
            DomainEvent::ToolCallDelta {
                index,
                id,
                function_name,
                arguments_delta,
                form,
            } => {
                // `process` never hands a call whose freeform arguments are
                // closed more of them (`BlockAccumulator::after_the_end`):
                // appended, they would follow the closing `"}`.
                if form.is_freeform() {
                    self.freeform = true;
                }
                if *form == CallArguments::FreeformWhole {
                    self.freeform_closed = true;
                }
                if let CallArguments::ClientBuiltin(builtin) = form {
                    self.builtin = Some(*builtin);
                }
                // A call's index is the one its first delta names; a later
                // delta that names none (a lax server) does not move it.
                if self.buffered.is_empty() {
                    self.tool_call_index = *index;
                }
                // A repeated id or name is the same call's; one that differed
                // would have started a call of its own.
                if self.tool_call_id.is_none() {
                    self.tool_call_id.clone_from(id);
                }
                if self.tool_name.is_none() {
                    self.tool_name.clone_from(function_name);
                }
                self.tool_arguments.push_str(arguments_delta);
            }
            // A freeform call's end is the closing piece of its arguments; the
            // buffered event stays the end, which has no bytes on the wire.
            DomainEvent::FreeformCallEnd { .. } => {
                self.tool_arguments.push_str(crate::api::domain_request::FREEFORM_ARGS_CLOSE);
                self.freeform_closed = true;
            }
            DomainEvent::TextDelta(text) => {
                self.text_content.push_str(text);
            }
            DomainEvent::ReasoningDelta(text) => {
                self.thinking_content.push_str(text);
            }
            _ => {}
        }
        self.buffered.push(BufferedEvent {
            domain_event: Some(event.clone()),
            raw_sse,
        });
    }
}

/// A call the gateway wrote whole (a policy rewrite, a script), as the one
/// delta that replaces `block`'s: its arguments and their form. A freeform
/// call stays one — its arguments the domain's `{"input": <text>}` — so every
/// reader after this one reads it as the call it is — a built-in tool's call
/// too, under its item type.
fn whole_call(block: &PendingBlock, name: String, arguments: String) -> DomainEvent {
    let (name, arguments_delta, form) = if let Some(builtin) = block.builtin {
        (builtin.tool_name().to_string(), arguments, CallArguments::ClientBuiltin(builtin))
    } else if block.freeform {
        let text = crate::api::domain_request::freeform_whole_text(&arguments);
        (name, crate::api::domain_request::freeform_call_input(&text).to_string(), CallArguments::FreeformWhole)
    } else {
        (name, arguments, CallArguments::Json)
    };
    DomainEvent::ToolCallDelta {
        index: block.tool_call_index,
        id: block.tool_call_id.clone(),
        function_name: Some(name),
        arguments_delta,
        form,
    }
}

/// A call to a Responses built-in tool the gateway rewrote, as the frame a
/// pass-through Responses client is sent in its place: the upstream's own item
/// — as its done states it, else as it opened — with `arguments` as its
/// payload, stated done (the pass-through opens it for the client from this).
/// Every other field of the item is kept (a computer call's pending safety
/// checks, a shell call's environment), so the client runs the call it was owed
/// with only the payload changed. Nothing where `arguments` do not fit the
/// payload or the block holds no item: the caller then removes the call,
/// saying so.
fn builtin_call_frames(
    block: &PendingBlock,
    builtin: crate::api::domain::ClientBuiltin,
    arguments: &str,
) -> Option<SseEvent> {
    let item_frame = |kind: &str| {
        block
            .buffered
            .iter()
            .rev()
            .filter_map(|b| b.raw_sse.as_ref())
            .find(|raw| raw.event_type.as_deref() == Some(kind))
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw.data).ok())
    };
    let frame = item_frame("response.output_item.done").or_else(|| item_frame("response.output_item.added"))?;
    let mut item = frame.get("item").filter(|item| item.is_object()).cloned()?;
    let field = builtin.payload_field(&item);
    item[field] = crate::api::domain::ClientBuiltin::payload_for(field, arguments)?;
    builtin.keep_read_payload_only(&mut item);
    if item.get("status").and_then(serde_json::Value::as_str).is_none_or(|status| status == "in_progress") {
        item["status"] = serde_json::Value::from("completed");
    }
    let kind = "response.output_item.done";
    let mut data = serde_json::json!({"type": kind, "item": item});
    if let Some(output_index) = frame.get("output_index") {
        data["output_index"] = output_index.clone();
    }
    Some(SseEvent { event_type: Some(kind.to_string()), data: data.to_string(), id: None })
}

/// Tool policy decision for a completed block.
enum PolicyDecision {
    Allow,
    /// A response/tool_calls `replace` rule fired — the regex actually
    /// matched the args JSON and produced a rewrite. The block continues
    /// downstream (Rhai scripts, emitter) with the new args.
    Replace {
        tool_name: String,
        rule_id: String,
        rule_title: Option<String>,
        rule_description: Option<String>,
        new_args_string: String,
        modifications: Vec<crate::proxy::content::ToolArgModification>,
    },
    Block {
        tool_name: String,
        reason: Option<String>,
        rule_id: String,
        rule_title: Option<String>,
    },
}

/// Processing statistics for the accumulator (exposed for dashboard / audit).
#[derive(Debug, Default, Clone)]
pub struct BlockStats {
    /// Number of blocks that were buffered.
    pub blocks_buffered: u32,
    /// Number of tool blocks checked against policy.
    pub tool_blocks_checked: u32,
    /// Number of tool blocks blocked by policy.
    pub tool_blocks_blocked: u32,
    /// Number of text blocks processed.
    pub text_blocks_processed: u32,
    /// Number of thinking blocks processed.
    pub thinking_blocks_processed: u32,
    /// Number of response scripts applied.
    pub scripts_applied: u32,
}

/// Lightweight metadata from the request, needed to populate ResponseBlockContext.
#[derive(Debug, Clone)]
pub struct BlockRequestMeta {
    pub model: String,
    pub user_id: String,
    pub app_id: Option<String>,
    pub api_version: String,
    pub model_alias: Option<String>,
    /// See [`signed_thinking_reaches_client`].
    pub signed_thinking_reaches_client: bool,
}

impl BlockRequestMeta {
    /// The script context of `meta`'s answer from `upstream_model` on
    /// `upstream`: every response-phase script pass builds it here.
    pub fn for_answer(
        meta: &crate::proxy::RequestMeta,
        upstream_model: String,
        upstream: crate::api::sse::ApiVersion,
    ) -> Self {
        Self {
            model: upstream_model,
            user_id: meta.user_id.to_string(),
            app_id: meta.app_id.clone(),
            api_version: meta.api_version.as_str().to_string(),
            model_alias: Some(meta.model_requested.clone()),
            signed_thinking_reaches_client: signed_thinking_reaches_client(meta.api_version, upstream),
        }
    }
}

/// Whether the client receives the upstream's thinking signatures as sent: an
/// Anthropic client on an Anthropic upstream. A thinking block that carries one
/// must go back to the API unmodified or the next turn is refused, so a response
/// script's rewrite of it is recorded (`modified_not_applied`) and not applied.
/// The two settings that promise nothing unscreened reaches the client still
/// apply to it — a `closed`-mode script failure suppresses it, and the PII
/// guardrail in enforce mode masks it — at the cost of that next turn. On any
/// other leg the signature never reaches the client and a rewrite applies.
pub fn signed_thinking_reaches_client(
    client: crate::api::sse::ApiVersion,
    upstream: crate::api::sse::ApiVersion,
) -> bool {
    client == crate::api::sse::ApiVersion::AnthropicMessages
        && upstream == crate::api::sse::ApiVersion::AnthropicMessages
}

/// A call policy has already read, by the stream's number for it.
struct CheckedCall {
    index: usize,
    /// It reached the client (it was not removed or intercepted).
    delivered: bool,
    /// Some of its late arguments were withheld already.
    withheld: bool,
}

// ─── Tool-call boundaries ────────────────────────────────────────────────────

/// A streamed tool call as a reader knows it: the id and name it was given so
/// far (a lax server may send the name first and the id later, or neither).
#[derive(Clone, Copy)]
pub(crate) struct KnownCall<'a> {
    pub id: Option<&'a str>,
    pub name: Option<&'a str>,
}

/// Whether `raw` states a call's whole arguments — a Responses done event, of
/// the arguments or of the whole item. Only a Responses stream states them
/// again, and its pass-through restates every such statement to what the
/// client was given.
fn is_call_statement(raw: &SseEvent) -> bool {
    matches!(
        raw.event_type.as_deref(),
        Some(
            "response.function_call_arguments.done"
                | "response.custom_tool_call_input.done"
                | "response.mcp_call_arguments.done"
                | "response.output_item.done"
        )
    )
}

/// Whether `raw` is a Responses item's `output_item.done`.
fn is_item_done(raw: Option<&SseEvent>) -> bool {
    raw.is_some_and(|raw| raw.event_type.as_deref() == Some("response.output_item.done"))
}

/// The block or item an upstream frame addresses, as a client applies it: an
/// Anthropic content block by `index`, a Responses output item by
/// `output_index` and by id (`item_id`, or the item's own `id` where the frame
/// opens it).
#[derive(Clone, Debug, PartialEq)]
struct WireAddress {
    index: Option<u64>,
    item_id: Option<String>,
}

impl WireAddress {
    fn of(raw: &SseEvent) -> Self {
        let v: serde_json::Value = serde_json::from_str(&raw.data).unwrap_or_default();
        Self {
            index: v.get("index").or_else(|| v.get("output_index")).and_then(serde_json::Value::as_u64),
            item_id: v
                .get("item_id")
                .or_else(|| v.get("item").and_then(|item| item.get("id")))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        }
    }

    /// Whether `at` addresses the block or item this address names: every
    /// part of it that `at` states agrees, and it states one.
    fn names(&self, at: &Self) -> bool {
        fn agrees<T: PartialEq>(mine: &Option<T>, theirs: &Option<T>) -> bool {
            theirs.is_none() || mine == theirs
        }
        (at.index.is_some() || at.item_id.is_some()) && agrees(&self.index, &at.index) && agrees(&self.item_id, &at.item_id)
    }
}

/// Where a streamed tool-call delta belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallDelta {
    /// It opens a new call.
    Starts,
    /// It continues the call open at its index.
    ContinuesAtIndex,
    /// It names no call, at an index no call has claimed, from an upstream
    /// that may number a call's later deltas by position (Chat): the call
    /// opened last continues. One that sends a new call's arguments before its
    /// name (out of spec) has them read as the previous call's — the one
    /// reading of those bytes every reader shares.
    ContinuesLast,
    /// The late bytes of a call already closed (read by policy, or closed by
    /// the content after it) — or of a call that never started.
    Late,
}

/// What a reader of a tool-call stream knows when a delta arrives.
pub(crate) struct CallsSeen<'a> {
    /// The upstream sends each call in one event (Gemini), so every call
    /// event is a new call, id or not, at any index.
    pub calls_arrive_whole: bool,
    /// The upstream may number a call's later deltas by position rather than
    /// by the call's index (Chat). Any other upstream numbers every block, so
    /// arguments at an index no call carries (an Anthropic server tool's
    /// input) never join an open call.
    pub lax_indexes: bool,
    /// The reader's open call at the delta's index.
    pub open_at_index: Option<KnownCall<'a>>,
    /// The latest call the reader closed at that index.
    pub closed_at_index: Option<KnownCall<'a>>,
    /// A closed call carries the delta's id.
    pub closed_carries_id: bool,
    /// The reader has a call open (at any index).
    pub any_open: bool,
}

/// The ONE rule deciding where a streamed tool call ends and the next begins,
/// asked by ONE reader: the stream parser's [`CallNumbering`], which gives
/// every call its own number. Every other reader — the audit, response policy
/// (the accumulator), every client's builder — keys calls by that number and
/// decides nothing about boundaries, so the calls policy approved are the
/// calls the client receives. A reader re-deriving any part of this is the
/// drift it exists to prevent.
///
/// `delta` is what the delta names. A delta names ANOTHER call only where
/// both sides name one and they differ: a server may repeat the id or the name
/// on every delta, or send the name first and the id later.
pub(crate) fn call_delta(delta: KnownCall<'_>, seen: CallsSeen<'_>) -> CallDelta {
    let KnownCall { id, name } = delta;
    let CallsSeen { calls_arrive_whole, lax_indexes, open_at_index, closed_at_index, closed_carries_id, any_open } =
        seen;
    if calls_arrive_whole {
        return CallDelta::Starts;
    }
    // A call restated by the id of one already closed is that call's late
    // bytes: a second call under the same id would have the client run it
    // twice.
    if id.is_some() && closed_carries_id {
        return CallDelta::Late;
    }
    let names_another = |call: KnownCall<'_>| {
        let differs = |delta: Option<&str>, known: Option<&str>| {
            matches!((delta, known), (Some(d), Some(k)) if d != k)
        };
        differs(id, call.id) || differs(name, call.name)
    };
    if let Some(open) = open_at_index {
        return if names_another(open) { CallDelta::Starts } else { CallDelta::ContinuesAtIndex };
    }
    // An index a closed call claimed: a new call only under a new id or name
    // (Responses numbers every call 0, and so does a lax server sending neither
    // index nor id); otherwise it is that call's late bytes.
    if let Some(closed) = closed_at_index {
        return if names_another(closed) { CallDelta::Starts } else { CallDelta::Late };
    }
    if id.is_some() || name.is_some() {
        CallDelta::Starts
    } else if any_open && lax_indexes {
        CallDelta::ContinuesLast
    } else {
        CallDelta::Late
    }
}

/// The calls of one upstream response, numbered the reader's own way — 0, 1,
/// 2 … in the order they open — with where each delta belongs decided by
/// [`call_delta`]. An upstream's index is not a call's identity: a Responses
/// upstream numbers every call 0, a Gemini chunk numbers its own parts from
/// 0, and a lax Chat server numbers a call's later deltas by position. Every
/// reader that keeps calls apart (a translated client's builder, the audit)
/// numbers them through this, so they number them alike.
pub(crate) struct CallNumbering {
    calls_arrive_whole: bool,
    lax_indexes: bool,
    calls: Vec<NumberedCall>,
}

struct NumberedCall {
    upstream_index: usize,
    id: Option<String>,
    name: Option<String>,
    open: bool,
    /// A call of an earlier upstream response: it keeps its number, and no
    /// delta is placed against it.
    retired: bool,
}

/// Where a streamed tool-call delta belongs, by the reader's own number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallSlot {
    /// It opens call `n`.
    Starts(usize),
    /// It continues call `n`.
    Continues(usize),
    /// Late bytes of call `n`, already closed — or of no call at all.
    Late(Option<usize>),
}

impl CallNumbering {
    /// Numbering for a stream from `upstream`.
    pub(crate) fn for_upstream(upstream: crate::api::sse::ApiVersion) -> Self {
        use crate::api::sse::ApiVersion;
        Self {
            calls_arrive_whole: upstream == ApiVersion::GoogleGemini,
            lax_indexes: upstream == ApiVersion::ChatCompletions,
            calls: Vec::new(),
        }
    }

    /// Place a delta naming `id` / `name` at the upstream's `index`.
    pub(crate) fn place(&mut self, index: usize, id: Option<&str>, name: Option<&str>) -> CallSlot {
        fn known(c: &NumberedCall) -> KnownCall<'_> {
            KnownCall { id: c.id.as_deref(), name: c.name.as_deref() }
        }
        // A delta restating the id of a call this response already has is that
        // call's, whatever index it carries — never a second call under it.
        if let Some(id) = id
            && let Some(n) = self.calls.iter().rposition(|c| !c.retired && c.id.as_deref() == Some(id))
            && self.calls[n].upstream_index != index
        {
            return if self.calls[n].open { CallSlot::Continues(n) } else { CallSlot::Late(Some(n)) };
        }
        let open_at = self.open_at(index);
        let closed_at = self.calls.iter().rposition(|c| !c.retired && !c.open && c.upstream_index == index);
        let closed_with_id = id.and_then(|id| {
            self.calls.iter().rposition(|c| !c.retired && !c.open && c.id.as_deref() == Some(id))
        });
        let role = call_delta(
            KnownCall { id, name },
            CallsSeen {
                calls_arrive_whole: self.calls_arrive_whole,
                lax_indexes: self.lax_indexes,
                open_at_index: open_at.map(|i| known(&self.calls[i])),
                closed_at_index: closed_at.map(|i| known(&self.calls[i])),
                closed_carries_id: closed_with_id.is_some(),
                any_open: self.calls.iter().any(|c| !c.retired && c.open),
            },
        );
        let continues = |calls: &mut Vec<NumberedCall>, n: usize| {
            let call = &mut calls[n];
            if call.id.is_none() {
                call.id = id.map(str::to_string);
            }
            if call.name.is_none() {
                call.name = name.map(str::to_string);
            }
            CallSlot::Continues(n)
        };
        match role {
            CallDelta::Starts => {
                if let Some(i) = open_at {
                    self.calls[i].open = false;
                }
                self.calls.push(NumberedCall {
                    upstream_index: index,
                    id: id.map(str::to_string),
                    name: name.map(str::to_string),
                    open: true,
                    retired: false,
                });
                CallSlot::Starts(self.calls.len() - 1)
            }
            CallDelta::ContinuesAtIndex => match open_at {
                Some(n) => continues(&mut self.calls, n),
                None => CallSlot::Late(None),
            },
            CallDelta::ContinuesLast => match self.calls.iter().rposition(|c| !c.retired && c.open) {
                Some(n) => continues(&mut self.calls, n),
                None => CallSlot::Late(None),
            },
            CallDelta::Late => CallSlot::Late(closed_with_id.or(closed_at)),
        }
    }

    /// The call open at the upstream's `index` — where a freeform call's end
    /// belongs.
    pub(crate) fn open_at(&self, index: usize) -> Option<usize> {
        self.calls.iter().rposition(|c| !c.retired && c.open && c.upstream_index == index)
    }

    /// The upstream response is over: its calls keep their numbers, and the
    /// next response's calls are placed afresh (an agent-loop round numbers
    /// its calls from 0 again).
    pub(crate) fn finish_response(&mut self) {
        for call in &mut self.calls {
            call.open = false;
            call.retired = true;
        }
    }

}

// ─── BlockAccumulator ────────────────────────────────────────────────────────

/// Accumulates DomainEvents into complete blocks at content boundaries.
/// Sits between SSE parsing and EventEmitter in the streaming pipeline.
pub struct BlockAccumulator {
    /// Active block being buffered (None = no active block).
    active: Option<PendingBlock>,
    /// The upstream streams every tool call whole, in one frame (Gemini: a
    /// `functionCall` part is the complete call; its arguments stream in
    /// pieces only when the request opts in with `streamFunctionCallArguments`,
    /// which the gateway's request type does not carry — locked by
    /// `a_gemini_request_never_asks_for_streamed_call_arguments`). A call
    /// policy rewrites is then written back into that frame
    /// (`rewritten_call_frame`), keeping what the frame carries beside it.
    calls_arrive_whole: bool,
    /// The calls of the current upstream response that policy has already
    /// read (or gave up on), by the stream's number for them. Cleared at each
    /// response's finish, which retires its calls.
    checked_calls: Vec<CheckedCall>,
    /// Each server tool's call, by number: the wire address of the frame that
    /// opened it (see [`WireAddress`]).
    server_tools: std::collections::HashMap<usize, WireAddress>,
    /// Usage reports that arrived while a block was held, released right
    /// behind it.
    held_usage: Vec<BufferedEvent>,
    /// Which block types to buffer.
    interests: BlockInterests,
    /// Tool risk rules for argument-based policy checks.
    tool_rules: Vec<crate::config::tool_rules::Rule>,
    /// Per-(tool, field) normaliser registry. Resolved snapshot from
    /// `TenantConfig.tool_field_profiles`. Drives `arg.<field>` canonicalisation
    /// before rule matching so spacing / encoding tricks don't bypass rules.
    tool_field_profiles: Arc<crate::config::tool_rules::FieldProfileSet>,
    /// Response-phase transform programs.
    response_programs: Vec<TransformProgram>,
    /// Script engine for executing response-phase Rhai scripts.
    script_engine: Option<Arc<ScriptEngine>>,
    /// Request metadata for building ResponseBlockContext.
    request_meta: Option<BlockRequestMeta>,
    /// Whether to capture before/after diffs for response scripts.
    capture_diffs: bool,
    /// How to react when a response-phase script errors.
    fail_mode: ScriptFailMode,
    /// Processing statistics.
    pub stats: BlockStats,
    /// Audit badges accumulated by policy enforcement and script errors.
    pub badges: crate::audit::BadgeBuilder,
    /// Per-program outcomes for the response chain (drained into
    /// `transform_diff.response_transform_programs`).
    pub program_outcomes: Vec<crate::proxy::content::TransformProgramRef>,
    /// Per-script diffs (when capture_diffs is enabled).
    pub step_diffs: Vec<TransformStepDiff>,
    /// Original content of blocks that were modified by response scripts.
    pub original_text_blocks: Vec<String>,
    /// Original tool calls blocked by response-side policy.
    pub blocked_tool_infos: Vec<crate::proxy::content::BlockedToolInfo>,
    /// Per-field rewrites of tool_call arguments captured by response-phase
    /// `replace` rules (and, in the future, by Rhai scripts that mutate
    /// `ctx.arguments`). Each entry surfaces in the session UI on the
    /// matching tool call.
    pub tool_arg_modifications: Vec<crate::proxy::content::ToolArgModification>,
    /// Structured injection blocks for response-side transforms.
    pub injection_blocks: Vec<crate::proxy::content::InjectionBlock>,
    /// Tool-name → intercept handler map produced by request-phase
    /// `Substitute` / `InterceptOnly` rules. When the upstream emits a
    /// `ToolCallDelta` with a `function_name` that matches an entry, the
    /// substitution agent loop (when wired) routes the call through the
    /// bound handler instead of forwarding to the client. Empty when no
    /// substitution rules fired for this request.
    pub intercept_bindings: Vec<crate::proxy::content::InterceptBinding>,
    /// The tools the request withheld, each with its rule (see
    /// [`Self::withheld_tools`]).
    withheld_tools: Vec<crate::proxy::content::BlockedToolInfo>,
    /// Captured tool-use blocks whose `function_name` matched a binding in
    /// `intercept_bindings`. Populated as the upstream stream is decoded;
    /// the substitution agent loop drains the list at end-of-round to
    /// execute each call via the bound handler. Suppressed blocks are
    /// never emitted to the client renderer.
    pub pending_intercepted: Vec<PendingInterceptedCall>,
    /// Heal malformed JSON syntax in finalized structured-output text blocks
    /// (set only when the request asked for `json_schema`).
    heal_structured_text: bool,
    /// Heal malformed JSON syntax in finalized tool-call argument strings.
    heal_tool_args: bool,
    /// Tool calls this response actually delivered to the client. Counted from
    /// what leaves `process_completed_block`, not from what arrived, so every
    /// suppression path — policy block, argument-overflow, a `closed`-mode
    /// script failure — is reflected without each having to remember to
    /// decrement. Read by `settle_finish_reason`.
    tool_calls_delivered: u32,
}

impl BlockAccumulator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        interests: BlockInterests,
        tool_rules: Vec<crate::config::tool_rules::Rule>,
        tool_field_profiles: Arc<crate::config::tool_rules::FieldProfileSet>,
        response_programs: Vec<TransformProgram>,
        script_engine: Option<Arc<ScriptEngine>>,
        request_meta: Option<BlockRequestMeta>,
        capture_diffs: bool,
        fail_mode: ScriptFailMode,
        intercept_bindings: Vec<crate::proxy::content::InterceptBinding>,
        heal_structured_text: bool,
        heal_tool_args: bool,
        upstream: crate::api::sse::ApiVersion,
    ) -> Self {
        Self {
            active: None,
            calls_arrive_whole: upstream == crate::api::sse::ApiVersion::GoogleGemini,
            checked_calls: Vec::new(),
            server_tools: std::collections::HashMap::new(),
            held_usage: Vec::new(),
            interests,
            tool_rules,
            tool_field_profiles,
            response_programs,
            script_engine,
            request_meta,
            capture_diffs,
            fail_mode,
            stats: BlockStats::default(),
            badges: crate::audit::BadgeBuilder::new(),
            program_outcomes: Vec::new(),
            step_diffs: Vec::new(),
            original_text_blocks: Vec::new(),
            blocked_tool_infos: Vec::new(),
            tool_arg_modifications: Vec::new(),
            injection_blocks: Vec::new(),
            intercept_bindings,
            withheld_tools: Vec::new(),
            pending_intercepted: Vec::new(),
            heal_structured_text,
            heal_tool_args,
            tool_calls_delivered: 0,
        }
    }

    /// Refuse a call to a tool the request withheld — a declaration tool
    /// policy removed, or a tool the client only lists as deferred — under
    /// that tool's rule: the client may still run a tool it does not declare.
    /// Matched by the call's name. The caller buffers tool blocks whenever it
    /// passes any.
    pub fn withheld_tools(mut self, tools: Vec<crate::proxy::content::BlockedToolInfo>) -> Self {
        self.withheld_tools = tools;
        self
    }

    /// True when at least one request-phase substitution rule produced an
    /// intercept binding for this request. The substitution agent loop
    /// reads this to decide whether to engage; the `BlockAccumulator`
    /// itself only stores the bindings.
    pub fn has_intercept_bindings(&self) -> bool {
        !self.intercept_bindings.is_empty()
    }

    /// Look up an intercept binding by the wire tool name the upstream
    /// emitted. Matches `replaced_name` first (the post-substitution wire
    /// name the upstream is expected to echo) and falls back to
    /// `original_name` (the pre-substitution name the client declared) so
    /// that a downstream protocol translation that happens to revert the
    /// substituted name on the wire still routes the call through the
    /// bound handler instead of leaking it to the client.
    pub fn intercept_binding_for(
        &self,
        tool_name: &str,
    ) -> Option<&crate::proxy::content::InterceptBinding> {
        self.intercept_bindings
            .iter()
            .find(|b| b.replaced_name == tool_name || b.original_name == tool_name)
    }

    /// Whether this accumulator may intercept a call (it holds substitution
    /// bindings).
    pub fn intercepts_calls(&self) -> bool {
        !self.intercept_bindings.is_empty()
    }

    /// True when at least one upstream `tool_use` matched an intercept
    /// binding and is queued for the substitution agent loop.
    pub fn has_pending_intercepted(&self) -> bool {
        !self.pending_intercepted.is_empty()
    }

    /// Drain the queued intercepted calls. The substitution agent loop
    /// calls this at end-of-round and dispatches each entry through the
    /// bound `InterceptKind` handler.
    pub fn take_pending_intercepted(&mut self) -> Vec<PendingInterceptedCall> {
        std::mem::take(&mut self.pending_intercepted)
    }

    /// Process a single DomainEvent. Returns events to forward to the emitter.
    ///
    /// When buffering, returns empty. On block complete, returns processed events.
    /// Take an upstream frame that parsed into no domain event — an Anthropic
    /// `content_block_stop`, a Responses `response.created`. It means nothing
    /// to the audit and everything to a pass-through client, which needs it
    /// where the upstream put it.
    ///
    /// While a block is buffering, "where the upstream put it" is after that
    /// block's content, so the frame waits with the block and shares its fate:
    /// a block policy removes takes its own closing frames with it, and the
    /// emitter drops any that would close a container the client never saw.
    pub fn process_raw(&mut self, raw: SseEvent, opens_container: bool) -> Vec<BufferedEvent> {
        // A frame that OPENS something — an Anthropic `content_block_start`, a
        // Responses `output_item.added` or `content_part.added` — ends whatever
        // was open before it. The accumulator groups by block kind, not by the
        // upstream's containers, so a second text block would otherwise keep
        // merging into the first and its content would leave before the frames
        // that address it. Close the held block, then let the opener through.
        if opens_container {
            let mut out = self.flush_active();
            out.push(BufferedEvent::passthrough(raw));
            return out;
        }
        match &mut self.active {
            // A frame after a held usage report goes out behind it, in the
            // order they came — a Chat stream's `[DONE]` after the usage a lax
            // server sent once text followed its finish.
            Some(_) if !self.held_usage.is_empty() && self.held_usage.len() < MAX_BUFFERED_EVENTS => {
                self.held_usage.push(BufferedEvent::passthrough(raw));
                Vec::new()
            }
            // The same cap the block's own events have, for the same reason: an
            // upstream can send these without end (`ping`), and holding them is
            // holding memory. Past it they go out where they are rather than
            // being kept or dropped — an out-of-order keepalive costs a client
            // nothing, and a frame it never receives can cost it the stream.
            Some(block) if block.trailing.len() < MAX_BUFFERED_EVENTS => {
                block.trailing.push(raw);
                Vec::new()
            }
            _ => vec![BufferedEvent::passthrough(raw)],
        }
    }

    pub fn process(
        &mut self,
        event: DomainEvent,
        raw_sse: Option<SseEvent>,
    ) -> Vec<BufferedEvent> {
        // A freeform call's end closes the arguments of the call it names
        // when that call is held. A call already read had its arguments
        // closed when it was read (`process_completed_block`), and a call
        // given up on keeps its late bytes: either way the end is dropped.
        // With no call held or read (tool calls not buffered) it passes.
        if let DomainEvent::FreeformCallEnd { index } = event {
            if let Some(block) = &mut self.active
                && block.block_type == BlockType::ToolUse
                && block.tool_call_index == index
            {
                block.accumulate(&event, raw_sse);
                return Vec::new();
            }
            // A call already read had its arguments closed then; the end is
            // the gateway's bookkeeping. Its frame (a Responses
            // `custom_tool_call_input.done`) is the item's own, which a client
            // holding the item is owed — stating what that client was given
            // (the pass-through restates it) — and one that never got the
            // call is not.
            if let Some(call) = self.checked_calls.iter().find(|c| c.index == index) {
                return match raw_sse.filter(|_| call.delivered) {
                    Some(raw) => vec![BufferedEvent::passthrough(raw)],
                    None => Vec::new(),
                };
            }
            return vec![BufferedEvent { domain_event: Some(event), raw_sse }];
        }
        match &event {
            DomainEvent::ToolCallDelta { .. } => self.route_call_delta(event, raw_sse),
            // ── Text delta ──
            DomainEvent::TextDelta(_) => {
                if self.interests.buffer_text_blocks {
                    if self
                        .active
                        .as_ref()
                        .is_some_and(|b| b.block_type == BlockType::Text)
                    {
                        let block = self.active.as_mut().unwrap();
                        block.accumulate(&event, raw_sse);
                        if block.buffered.len() >= MAX_BUFFERED_EVENTS {
                            tracing::error!(
                                events = block.buffered.len(),
                                "block accumulator: text block exceeded {MAX_BUFFERED_EVENTS} events — dropping (fail-closed)"
                            );
                            self.stats.blocks_buffered += 1;
                            self.stats.text_blocks_processed += 1;
                            self.badges.add_block_overflow(crate::audit::BlockKind::Text);
                            self.active = None;
                            // Not silently: the client is told, and on a
                            // Responses pass-through the notice is what tells
                            // the final response the client's copy diverged.
                            let mut out = vec![overflow_notice()];
                            out.append(&mut self.held_usage);
                            return out;
                        }
                        vec![]
                    } else {
                        let out = self.flush_active();
                        self.active = Some(PendingBlock::new(BlockType::Text, &event, raw_sse));
                        out
                    }
                } else {
                    let out = self.flush_active();
                    let mut result = out;
                    result.push(BufferedEvent {
                        domain_event: Some(event),
                        raw_sse,
                    });
                    result
                }
            }
            // ── Reasoning delta ──
            DomainEvent::ReasoningDelta(_) => {
                if self.interests.buffer_thinking_blocks {
                    if self
                        .active
                        .as_ref()
                        .is_some_and(|b| b.block_type == BlockType::Thinking)
                    {
                        let block = self.active.as_mut().unwrap();
                        block.accumulate(&event, raw_sse);
                        if block.buffered.len() >= MAX_BUFFERED_EVENTS {
                            tracing::error!(
                                events = block.buffered.len(),
                                "block accumulator: thinking block exceeded {MAX_BUFFERED_EVENTS} events — dropping (fail-closed)"
                            );
                            self.stats.blocks_buffered += 1;
                            self.stats.thinking_blocks_processed += 1;
                            self.badges.add_block_overflow(crate::audit::BlockKind::Thinking);
                            self.active = None;
                            // Not silently: the client is told, and on a
                            // Responses pass-through the notice is what tells
                            // the final response the client's copy diverged.
                            let mut out = vec![overflow_notice()];
                            out.append(&mut self.held_usage);
                            return out;
                        }
                        vec![]
                    } else {
                        let out = self.flush_active();
                        self.active =
                            Some(PendingBlock::new(BlockType::Thinking, &event, raw_sse));
                        out
                    }
                } else {
                    let out = self.flush_active();
                    let mut result = out;
                    result.push(BufferedEvent {
                        domain_event: Some(event),
                        raw_sse,
                    });
                    result
                }
            }
            // Taken before this match (see the top of `process`).
            DomainEvent::FreeformCallEnd { .. } => vec![BufferedEvent { domain_event: Some(event), raw_sse }],
            // ── Image generation — pass through (no buffering needed, tool policy
            //    is enforced at request time by blocking the tool from the tools array) ──
            DomainEvent::ImageGeneration { .. } => {
                let mut out = self.flush_active();
                out.push(BufferedEvent {
                    domain_event: Some(event),
                    raw_sse,
                });
                out
            }
            // ── Terminal events — flush active block and pass through ──
            //
            // `Done` is the one that cannot be a blind pass-through: the flush
            // above may have removed the only tool call in the response, and a
            // finish reason that still claims one contradicts the content this
            // response actually carries. See `settle_finish_reason`.
            DomainEvent::Done { .. } => {
                let mut out = self.flush_active();
                self.checked_calls.clear();
                let (domain_event, raw_sse) = self.settle_finish_reason(event, raw_sse);
                out.push(BufferedEvent {
                    domain_event: Some(domain_event),
                    raw_sse,
                });
                out
            }
            // A usage count is not a content boundary: servers that report it
            // on every chunk (Gemini, vLLM's continuous usage) would otherwise
            // cut every held block into one block per chunk — a call checked
            // on its first fragment, a script never seeing a match that spans
            // two chunks.
            //
            // It still belongs after the content it counts, and a translated
            // client reads it as the stream's last word — so while a block is
            // held, so is the usage (and the frame carrying it), going out
            // right behind the block.
            DomainEvent::Usage(_) => {
                let usage = BufferedEvent { domain_event: Some(event), raw_sse };
                if self.active.is_some() || !self.held_usage.is_empty() {
                    self.held_usage.push(usage);
                    Vec::new()
                } else {
                    vec![usage]
                }
            }
            DomainEvent::Error { .. } => {
                let mut out = self.flush_active();
                out.push(BufferedEvent {
                    domain_event: Some(event),
                    raw_sse,
                });
                out
            }
            // Substitution-emulated server-tool events. Defensive
            // pass-through; the substitution agent loop emits these
            // *after* execution and routes them straight to the
            // per-protocol renderer.
            DomainEvent::ServerToolCallDelta { .. }
            | DomainEvent::ServerToolResult { .. }
            | DomainEvent::ServerToolError { .. } => {
                let mut out = self.flush_active();
                out.push(BufferedEvent {
                    domain_event: Some(event),
                    raw_sse,
                });
                out
            }
        }
    }

    /// Flush any remaining active block at stream end.
    pub fn flush(&mut self) -> Vec<BufferedEvent> {
        self.flush_active()
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// Flush the active block, processing it through policy and scripts.
    /// Arguments for a call policy has already read (parallel calls whose
    /// deltas interleave, a call continued after other content, a custom
    /// call's text after its end). These bytes were never part of what it
    /// read, so they do not reach the client: the call arrives as it was
    /// read, and the client is told once why — unless the call itself was
    /// removed, which the client has already been told.
    fn withhold_late_bytes(&mut self, at: usize, index: usize, bytes: &str) -> Vec<BufferedEvent> {
        // Only bytes are withheld: a delta carrying none (an id restated, a
        // trailing empty piece) withholds nothing.
        if bytes.is_empty() {
            return vec![];
        }
        tracing::warn!(
            index,
            "block accumulator: tool-call arguments arrived for a call already checked; withheld"
        );
        let call = &mut self.checked_calls[at];
        if call.withheld {
            return vec![];
        }
        call.withheld = true;
        let delivered = call.delivered;
        // The audit row records the call as the upstream sent it; this says
        // the client's copy stops short of that.
        self.injection_blocks.push(crate::pipeline::response::TransformState::arguments_withheld(index));
        if !delivered {
            return vec![];
        }
        vec![BufferedEvent {
            domain_event: Some(DomainEvent::TextDelta(crate::pipeline::response::WITHHELD_NOTICE.to_string())),
            raw_sse: None,
        }]
    }

    /// Bytes for the held call after its custom (freeform) arguments closed —
    /// a lax server re-sending after its own done event. Nothing is appended
    /// to closed arguments: the held call is whole, so it is read now, and the
    /// bytes are withheld as late bytes of a call policy read.
    fn after_the_end(&mut self, bytes: &str) -> Vec<BufferedEvent> {
        let mut out = self.flush_active();
        // Reading the call recorded it last.
        if let Some(at) = self.checked_calls.len().checked_sub(1) {
            let index = self.checked_calls[at].index;
            out.extend(self.withhold_late_bytes(at, index, bytes));
        }
        out
    }

    /// Where a call delta goes is its number's to say: the stream parser gives
    /// every call its own, so the held call is the one of its number, a call
    /// policy already read is one of a number it checked, and any other
    /// number opens a call. Nothing here re-decides where a call
    /// begins or ends — that is the parser's (`CallNumbering`), and a delta it
    /// could place in no call arrives numbered `NO_CALL`.
    fn route_call_delta(&mut self, event: DomainEvent, raw_sse: Option<SseEvent>) -> Vec<BufferedEvent> {
        let pass = |event, raw_sse| vec![BufferedEvent { domain_event: Some(event), raw_sse }];
        let DomainEvent::ToolCallDelta { index: n, form, arguments_delta, .. } = &event else {
            return pass(event, raw_sse);
        };
        let (n, form) = (*n, *form);
        // A delta of no call is no call's to hold or read: it passes, and no
        // emitter writes it.
        if n == DomainEvent::NO_CALL {
            return pass(event, raw_sse);
        }
        // A server tool's input is a call the upstream runs itself: policy
        // does not hold it. Its block ends whatever is held, as it does on
        // the wire. Its frame passes unscreened only where it addresses that
        // server tool's own block or item: one addressing any other — a
        // client's call, which the client would apply it to — is withheld as
        // bytes of no call.
        if form == CallArguments::ServerTool {
            let mut out = self.flush_active();
            if let Some(raw) = &raw_sse {
                let at = WireAddress::of(raw);
                let opened = self.server_tools.entry(n).or_insert_with(|| at.clone());
                if !opened.names(&at) {
                    tracing::warn!(call = n, "a server tool's input frame addresses another item; withheld");
                    let bytes = arguments_delta.clone();
                    let stray = DomainEvent::ToolCallDelta {
                        index: DomainEvent::NO_CALL,
                        id: None,
                        function_name: None,
                        arguments_delta: bytes,
                        form: CallArguments::Json,
                    };
                    out.extend(pass(stray, None));
                    return out;
                }
            }
            out.extend(pass(event, raw_sse));
            return out;
        }
        let late = form == CallArguments::FreeformLate;
        let bytes = arguments_delta.clone();
        if let Some(block) = self.active.as_mut().filter(|b| b.block_type == BlockType::ToolUse && b.tool_call_index == n) {
            // Nothing is appended to a custom call's closed arguments.
            if block.freeform_closed || late {
                return if bytes.is_empty() { vec![] } else { self.after_the_end(&bytes) };
            }
            block.accumulate(&event, raw_sse);
            return self.check_overflow();
        }
        // Bytes of a call policy already read. The frame carrying them may be
        // the item's own statement of its whole arguments (a Responses done
        // event, whose rest the stream parser read as this piece): a client
        // holding the item is owed it, stating what that client was given —
        // the pass-through restates it — and the bytes it adds stay withheld.
        if let Some(at) = self.checked_calls.iter().rposition(|c| c.index == n) {
            if !self.interests.buffer_tool_blocks {
                return pass(event, raw_sse);
            }
            let mut out = self.withhold_late_bytes(at, n, &bytes);
            if self.checked_calls[at].delivered
                && let Some(raw) = raw_sse.filter(is_call_statement)
            {
                out.push(BufferedEvent::passthrough(raw));
            }
            return out;
        }
        // Any other number is a call opening — the parser numbers calls in
        // the order they open, and every call opened while calls are held is
        // held, then read — unless calls are not held, or the delta is a late
        // piece (no emitter writes one into a call): then it passes, behind
        // whatever it follows.
        let mut out = self.flush_active();
        if self.interests.buffer_tool_blocks && !late {
            self.active = Some(PendingBlock::new(BlockType::ToolUse, &event, raw_sse));
        } else {
            out.extend(pass(event, raw_sse));
        }
        out
    }

    /// Safety: drop an oversized held call to prevent memory exhaustion.
    /// Fail-closed: if blocking rules exist and it cannot be fully analysed,
    /// the call is suppressed rather than let through.
    fn check_overflow(&mut self) -> Vec<BufferedEvent> {
        let Some(block) = self.active.as_mut().filter(|b| b.buffered.len() >= MAX_BUFFERED_EVENTS) else {
            return vec![];
        };
        let tool_name = block.tool_name.clone().unwrap_or_default();
        let index_of_call = block.tool_call_index;
        // Substitution-intercepted blocks are invisible to the client by
        // contract: queue the (truncated) call onto `pending_intercepted` so
        // the agent loop can surface the failure as a typed `tool_result`
        // error to the model, and skip the operator-visible text notice that
        // the regular overflow path emits.
        let binding_match = self
            .intercept_bindings
            .iter()
            .find(|b| b.replaced_name == tool_name || b.original_name == tool_name)
            .cloned();
        if let Some(binding) = binding_match {
            tracing::error!(
                tool_name = %tool_name,
                events = block.buffered.len(),
                rule_id = ?binding.rule_id,
                "block accumulator: substituted tool block exceeded {MAX_BUFFERED_EVENTS} events — \
                 queuing truncated args for agent-loop error path"
            );
            let mut pending = PendingInterceptedCall {
                binding,
                tool_use_id: block.tool_call_id.clone(),
                thought_signature: Self::call_signature(self.calls_arrive_whole, block),
                tool_name,
                tool_call_index: block.tool_call_index,
                arguments_json: std::mem::take(&mut block.tool_arguments),
                blocked: None,
            };
            self.active = None;
            self.stats.blocks_buffered += 1;
            self.stats.tool_blocks_checked += 1;
            // What arrived so far may still parse (a whole object padded with
            // whitespace): it is decided like any intercepted call.
            self.police_intercepted(&mut pending);
            self.pending_intercepted.push(pending);
            // Its later bytes stay with it, whatever call is held by then.
            self.checked_calls.push(CheckedCall { index: index_of_call, delivered: false, withheld: true });
            return std::mem::take(&mut self.held_usage);
        }
        tracing::error!(
            tool_name = %tool_name,
            events = block.buffered.len(),
            "block accumulator: tool block exceeded {MAX_BUFFERED_EVENTS} events — \
             dropping block (fail-closed, incomplete analysis with active block rules)"
        );
        self.stats.blocks_buffered += 1;
        self.stats.tool_blocks_checked += 1;
        self.stats.tool_blocks_blocked += 1;
        self.badges.add_tool_blocked_overflow(crate::audit::Phase::Response, tool_name.clone());
        self.active = None;
        // Its later bytes stay with it, whatever call is held by then.
        self.checked_calls.push(CheckedCall { index: index_of_call, delivered: false, withheld: true });
        // Nothing is silently discarded: surface a text notice
        // so the client sees that something was suppressed (mirrors the
        // explicit policy-block branch).
        let mut out = vec![BufferedEvent {
            domain_event: Some(DomainEvent::TextDelta(format!(
                "[Tool call to `{tool_name}` was dropped: response exceeded \
                 the safety analysis buffer; cannot evaluate against active \
                 risk rules. Try a smaller invocation.]"
            ))),
            raw_sse: None,
        }];
        out.append(&mut self.held_usage);
        out
    }

    fn flush_active(&mut self) -> Vec<BufferedEvent> {
        let mut out = match self.active.take() {
            Some(block) => self.process_completed_block(block),
            None => Vec::new(),
        };
        out.append(&mut self.held_usage);
        out
    }

    /// Repair malformed JSON syntax in a finalized block before tool policy,
    /// substitution, and response scripts evaluate it. When healing changes
    /// content, the buffered events are rebuilt from the healed value so the
    /// client receives the repaired form (same single-synthetic-event shape a
    /// modifying response script produces). Gated by the per-route healing
    /// flag — `heal_structured_text` covers `json_schema` text blocks,
    /// `heal_tool_args` covers tool-call argument strings.
    fn heal_block(&mut self, block: &mut PendingBlock) {
        match block.block_type {
            BlockType::Text if self.heal_structured_text && !block.text_content.is_empty() => {
                let healed = crate::pipeline::healing::heal_json(&block.text_content);
                if healed != block.text_content {
                    block.text_content = healed.clone();
                    block.buffered = vec![BufferedEvent {
                        domain_event: Some(DomainEvent::TextDelta(healed)),
                        raw_sse: None,
                    }];
                    self.badges.add_json_healed();
                }
            }
            // A freeform call's arguments are the gateway's own JSON around
            // the model's text, and a built-in tool's call's are its payload
            // as the parser re-serialised it: there is no syntax of the
            // model's to repair.
            BlockType::ToolUse
                if self.heal_tool_args && !block.freeform && block.builtin.is_none() && !block.tool_arguments.is_empty() =>
            {
                let healed = crate::pipeline::healing::heal_json(&block.tool_arguments);
                if healed != block.tool_arguments {
                    block.tool_arguments = healed.clone();
                    block.buffered = vec![BufferedEvent {
                        domain_event: Some(DomainEvent::ToolCallDelta {
                            index: block.tool_call_index,
                            id: block.tool_call_id.clone(),
                            function_name: block.tool_name.clone(),
                            arguments_delta: healed,
                            form: crate::api::domain::CallArguments::Json,
                        }),
                        raw_sse: None,
                    }];
                    self.badges.add_json_healed();
                }
            }
            _ => {}
        }
    }

    /// Reconcile the stream's finish reason with the content that survived
    /// this response's policy and script passes.
    ///
    /// A finish reason is a claim about what the response contains, and every
    /// wire we speak reads it that way. Anthropic documents `stop_reason:
    /// "tool_use"` as "one or more `tool_use` blocks" that the caller executes
    /// and answers with a `tool_result`; OpenAI's `finish_reason: "tool_calls"`
    /// is the same promise. So when policy removes the last tool call, leaving
    /// the claim standing hands the client a response that says "run the tool I
    /// called" with no tool to run — Claude Code discards the whole message,
    /// including the operator's block notice, and spends a turn retrying.
    ///
    /// The settled value is `Stop`, the one every target has: Anthropic's other
    /// candidates name a different actor (`refusal` is the *model* declining)
    /// and OpenAI's `content_filter` has no equivalent on the Anthropic or
    /// Gemini wires, so routing through either would make two of the four
    /// clients report something that did not happen. The reason the call is
    /// gone rides the channel every wire does have — the injected text notice.
    ///
    /// Invariants to preserve. Settle only when a tool call was there to begin
    /// with (`tool_blocks_checked`, raised on every removal path including the
    /// argument-overflow drop, which returns before `process_completed_block`)
    /// and NONE of them was delivered. A surviving call keeps the claim true; an
    /// upstream that sent this finish reason with no tool call at all is its own
    /// defect and not one to paper over; and a call queued for the substitution
    /// agent loop is executed rather than removed — that round ends with its own
    /// `Done`.
    fn settle_finish_reason(
        &self,
        event: DomainEvent,
        raw_sse: Option<SseEvent>,
    ) -> (DomainEvent, Option<SseEvent>) {
        let DomainEvent::Done {
            finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
            native_finish_reason,
        } = &event
        else {
            return (event, raw_sse);
        };
        if self.tool_calls_delivered > 0
            || self.stats.tool_blocks_checked == 0
            || !self.pending_intercepted.is_empty()
        {
            return (event, raw_sse);
        }
        tracing::info!(
            seen = self.stats.tool_blocks_checked,
            "every tool call was removed — settling finish reason to stop"
        );
        // `native_finish_reason` is provenance, not a wire field: it records
        // what the upstream said and is read only by the audit row, which also
        // carries the block badge explaining the divergence. Settling it too
        // would erase the evidence that a tool call was ever attempted.
        //
        // `raw_sse` is KEPT, and that is load-bearing. A same-protocol pair
        // emits through `EventEmitter::Passthrough`, which rewrites the raw
        // frame's finish field from THIS domain value
        // (`normalize_finish_reason_in_sse_event`) — so forwarding it settles
        // the claim and preserves everything else the frame carries, which for
        // Anthropic's `message_delta` includes the output-token `usage`.
        // Dropping it instead sends the emitter down its synthesise path, and
        // no per-protocol synthesiser renders a `Done` — the client would get
        // no finish frame at all, trading one broken claim for a missing one.
        (
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::Stop),
                native_finish_reason: native_finish_reason.clone(),
            },
            raw_sse,
        )
    }

    /// Settle the finish of a round the substitution loop gave up on. Its
    /// intercepted calls kept the claim while the loop meant to answer them
    /// (`settle_finish_reason` leaves it while any are pending); now none of
    /// them will reach the client, so the claim stands only if a call did.
    pub fn settle_given_up(&self, event: &mut BufferedEvent) {
        if let Some(DomainEvent::Done { finish_reason, .. }) = &mut event.domain_event
            && *finish_reason == Some(crate::api::domain::FinishReason::ToolCalls)
            && self.tool_calls_delivered == 0
        {
            *finish_reason = Some(crate::api::domain::FinishReason::Stop);
        }
    }

    /// Process a completed block, then record whether a tool call survived it.
    ///
    /// The tally is taken from the events that leave, so a call removed by any
    /// path — policy block, argument overflow, a `closed`-mode script failure —
    /// is counted as not delivered without that path having to say so.
    fn process_completed_block(&mut self, mut block: PendingBlock) -> Vec<BufferedEvent> {
        let was_tool_use = block.block_type == BlockType::ToolUse;
        // A freeform call read before its end — another call started first —
        // is read, and delivered, as the text it had: its arguments are closed
        // here, and the end the stream sends later is dropped (see `process`).
        if was_tool_use && block.freeform && !block.freeform_closed {
            let end = DomainEvent::FreeformCallEnd { index: block.tool_call_index };
            block.accumulate(&end, None);
        }
        let call_index = block.tool_call_index;
        // A built-in tool's call is read from its done, the one statement of
        // its payload; read before it (another item opened first, the stream
        // cut short), what it carries was never read and the client is not
        // given the call (the pass-through gives one only as policy read it).
        let unread_builtin = block
            .builtin
            .filter(|_| was_tool_use && !block.buffered.iter().any(|b| is_item_done(b.raw_sse.as_ref())));
        block.signed = block.block_type == BlockType::Thinking
            && block.trailing.iter().any(|f| thinking_signature(f).is_some());
        let trailing = std::mem::take(&mut block.trailing);
        let mut out = self.process_completed_block_inner(block);
        // Withheld whole: no client is given any part of it — the audit, which
        // reads the stream's own events, still records the call — and it is
        // said once, here; its done, if it comes, adds no second word.
        if let Some(builtin) = unread_builtin {
            out.retain(|e| !matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { index, .. }) if *index == call_index));
            self.injection_blocks.push(crate::pipeline::response::TransformState::unread_withheld(call_index, builtin));
            out.push(BufferedEvent {
                domain_event: Some(DomainEvent::TextDelta(format!(
                    "\n[A `{}` call was withheld: it was read before its payload was stated.]\n",
                    builtin.tool_name()
                ))),
                raw_sse: None,
            });
        }
        out.extend(trailing.into_iter().map(BufferedEvent::passthrough));
        if was_tool_use {
            let delivered = out.iter().any(|e| {
                matches!(e.domain_event, Some(DomainEvent::ToolCallDelta { .. }))
            });
            if delivered {
                self.tool_calls_delivered += 1;
            }
            self.checked_calls.retain(|c| c.index != call_index);
            self.checked_calls.push(CheckedCall { index: call_index, delivered, withheld: unread_builtin.is_some() });
        }
        out
    }

    /// Decide an intercepted call by the response-phase tool-call rules and
    /// record the outcome (`PendingInterceptedCall::police`).
    fn police_intercepted(&mut self, call: &mut PendingInterceptedCall) {
        let model = self.request_meta.as_ref().map(|m| m.model.as_str());
        let app_id = self.request_meta.as_ref().and_then(|m| m.app_id.as_deref());
        let record = call.police(&self.tool_rules, &self.tool_field_profiles, model, app_id, &self.withheld_tools);
        if record.blocked.is_some() {
            self.stats.tool_blocks_blocked += 1;
        }
        record.record_into(
            &mut self.badges,
            &mut self.injection_blocks,
            &mut self.blocked_tool_infos,
            &mut self.tool_arg_modifications,
        );
    }

    /// Process a completed block through tool policy and response scripts.
    fn process_completed_block_inner(&mut self, mut block: PendingBlock) -> Vec<BufferedEvent> {
        self.stats.blocks_buffered += 1;

        // Heal malformed JSON syntax before any consumer (substitution agent
        // loop, tool policy, response scripts, client renderer) sees the block.
        self.heal_block(&mut block);

        // Substitution intercept resolution: any tool-use block whose
        // `function_name` matches an active binding is suppressed from
        // the renderer and queued for the agent loop. The lookup runs at
        // flush time rather than opener time so it handles protocols
        // that send the function_name on a continuation delta.
        // A built-in tool's call is the client's to run, whatever its name:
        // no substitution binding takes it.
        if block.block_type == BlockType::ToolUse && block.intercept_binding.is_none() && block.builtin.is_none()
            && let Some(name) = block.tool_name.as_deref()
            && let Some(binding) = self.intercept_binding_for(name)
        {
            block.intercept_binding = Some(binding.clone());
        }

        if let Some(binding) = block.intercept_binding.take()
            && block.block_type == BlockType::ToolUse
        {
            self.stats.tool_blocks_checked += 1;
            let thought_signature = Self::call_signature(self.calls_arrive_whole, &block);
            let tool_use_id = block.tool_call_id;
            let tool_name = block
                .tool_name
                .unwrap_or_else(|| binding.replaced_name.clone());
            tracing::debug!(
                tool_name = %tool_name,
                tool_use_id = ?tool_use_id,
                rule_id = ?binding.rule_id,
                action = %binding.action,
                "block_accumulator: queued substitution-intercepted tool call",
            );
            let mut call = PendingInterceptedCall {
                binding,
                tool_use_id,
                tool_name,
                tool_call_index: block.tool_call_index,
                arguments_json: block.tool_arguments,
                thought_signature,
                blocked: None,
            };
            self.police_intercepted(&mut call);
            self.pending_intercepted.push(call);
            return vec![];
        }

        match block.block_type {
            BlockType::ToolUse => {
                self.stats.tool_blocks_checked += 1;

                // A built-in tool's payload cannot take a rewrite that is not
                // JSON: the call is removed as blocked by that rule, as on a
                // non-streaming answer — never sent as if rewritten.
                let decision = match self.check_tool_policy(&block) {
                    PolicyDecision::Replace { tool_name, rule_id, rule_title, new_args_string, .. }
                        if block.builtin.is_some_and(|b| builtin_call_frames(&block, b, &new_args_string).is_none()) =>
                    {
                        PolicyDecision::Block {
                            tool_name,
                            reason: Some("the rewritten arguments could not be written into the call".to_string()),
                            rule_id,
                            rule_title,
                        }
                    }
                    decision => decision,
                };
                match decision {
                    PolicyDecision::Allow => self.run_response_scripts(block),
                    PolicyDecision::Replace {
                        tool_name,
                        rule_id,
                        rule_title,
                        rule_description,
                        new_args_string,
                        modifications,
                    } => {
                        // Mutate args + replace buffered events with a synthetic
                        // ToolCallDelta carrying the new args. Subsequent script
                        // chain (if any) sees the rewritten args.
                        let mut block = block;
                        let call = whole_call(&block, tool_name.clone(), new_args_string);
                        if let DomainEvent::ToolCallDelta { arguments_delta, .. } = &call {
                            block.tool_arguments.clone_from(arguments_delta);
                        }
                        block.buffered = self.rewritten_call_events(&block, call);
                        let title = rule_title
                            .clone()
                            .unwrap_or_else(|| format!("Tool args rewritten: {tool_name}"));
                        let desc = rule_description
                            .clone()
                            .unwrap_or_else(|| "tool_call args rewritten by policy".to_string());
                        self.tool_arg_modifications.extend(modifications.clone());
                        self.badges.add_modified();
                        self.injection_blocks
                            .push(crate::proxy::content::InjectionBlock {
                                transform: "tool_policy".to_string(),
                                scope: "tool_use".to_string(),
                                field: "arguments".to_string(),
                                action: "replace".to_string(),
                                content: format!(
                                    "{tool_name}: {} field(s) rewritten",
                                    modifications.len()
                                ),
                            });
                        tracing::info!(
                            tool_name = %tool_name,
                            fields = modifications.len(),
                            rule_id = ?rule_id,
                            rule = %title,
                            reason = %desc,
                            "response tool call args rewritten by policy"
                        );
                        self.run_response_scripts(block)
                    }
                    PolicyDecision::Block { tool_name, reason, rule_id, rule_title } => {
                        self.stats.tool_blocks_blocked += 1;
                        let desc = reason.clone().unwrap_or_else(|| "Blocked by policy".to_string());
                        self.badges
                            .add_tool_blocked(crate::audit::Phase::Response, tool_name.clone());
                        // Capture blocked tool info for dual-view — arguments
                        // round-trip as parsed JSON when possible, falling back
                        // to the raw accumulated string so the audit UI can
                        // always show what the model attempted.
                        let captured_args = if block.tool_arguments.is_empty() {
                            None
                        } else {
                            Some(
                                serde_json::from_str::<serde_json::Value>(&block.tool_arguments)
                                    .unwrap_or_else(|_| {
                                        serde_json::Value::String(block.tool_arguments.clone())
                                    }),
                            )
                        };
                        let title = rule_title
                            .clone()
                            .unwrap_or_else(|| format!("Response tool blocked: {tool_name}"));
                        self.blocked_tool_infos.push(crate::proxy::content::BlockedToolInfo {
                            not_applied: false,
                            name: tool_name.clone(),
                            title,
                            description: desc.clone(),
                            rule_id: rule_id.clone(),
                            tool_use_id: block.tool_call_id.clone(),
                            call_index: None,
                            arguments: captured_args,
                        });
                        self.injection_blocks.push(crate::proxy::content::InjectionBlock {
                            transform: "tool_policy".to_string(),
                            scope: "tool_use".to_string(),
                            field: "tool_call".to_string(),
                            action: "remove".to_string(),
                            content: tool_name.clone(),
                        });
                        tracing::info!(
                            tool_name = %tool_name,
                            reason = %desc,
                            "response tool call blocked by argument-based policy"
                        );
                        // Emit a text notice instead of silently suppressing
                        vec![BufferedEvent {
                            domain_event: Some(DomainEvent::TextDelta(format!(
                                "\n[Tool call to `{tool_name}` was blocked by policy: {desc}]\n"
                            ))),
                            raw_sse: None,
                        }]
                    }
                }
            }
            BlockType::Text => {
                self.stats.text_blocks_processed += 1;
                self.run_response_scripts(block)
            }
            BlockType::Thinking => {
                self.stats.thinking_blocks_processed += 1;
                self.run_response_scripts(block)
            }
        }
    }

    /// Run response-phase Rhai scripts on a completed block.
    ///
    /// If no scripts or no engine → returns original buffered events (zero overhead).
    /// If scripts modify the block → re-emits as synthetic DomainEvents.
    fn run_response_scripts(&mut self, block: PendingBlock) -> Vec<BufferedEvent> {
        // Fast path: no response programs or no engine → replay original events
        if self.response_programs.is_empty() {
            return block.buffered;
        }
        let (Some(engine), Some(meta)) = (&self.script_engine, &self.request_meta) else {
            return block.buffered;
        };

        // Build ResponseBlockContext from PendingBlock
        let block_type_str = match block.block_type {
            BlockType::Text => "text",
            BlockType::ToolUse => "tool_use",
            BlockType::Thinking => "thinking",
        };
        let ctx = ResponseBlockContext {
            block_type: block_type_str.to_string(),
            content: match block.block_type {
                BlockType::Text => block.text_content.clone(),
                BlockType::Thinking => block.thinking_content.clone(),
                _ => String::new(),
            },
            tool_name: block.tool_name.clone(),
            tool_id: block.tool_call_id.clone(),
            arguments: if block.tool_arguments.is_empty() {
                None
            } else {
                Some(block.tool_arguments.clone())
            },
            model: meta.model.clone(),
            user_id: meta.user_id.clone(),
            app_id: meta.app_id.clone(),
            api_version: meta.api_version.clone(),
            metadata: std::collections::HashMap::new(),
            labels: vec![],
        };

        let original = ctx.clone();
        let model_alias = meta.model_alias.as_deref();
        // The client is handed this block's signature as the upstream sent it,
        // and the API refuses a signed block that comes back changed — so
        // nothing below may change it. What policy decided is recorded instead.
        let keep_signed = block.signed && meta.signed_thinking_reaches_client;

        match engine.execute_response_chain(
            &self.response_programs,
            ctx,
            model_alias,
            self.capture_diffs,
            self.fail_mode,
        ) {
            Ok((result_ctx, script_outcomes, script_diffs)) => {
                if !script_outcomes.is_empty() {
                    self.stats.scripts_applied += script_outcomes.len() as u32;
                }
                // Promote per-program errors into ScriptError badges; the
                // outcomes themselves flow into the trace for the per-program
                // summary in the response transform_diff section.
                for outcome in &script_outcomes {
                    if matches!(
                        outcome.outcome,
                        crate::proxy::content::TransformProgramOutcome::Errored
                    ) {
                        self.badges
                            .add_script_error(crate::audit::Phase::Response, outcome.name.clone());
                    }
                }
                let modifying_program_name = script_outcomes
                    .iter()
                    .find(|o| matches!(
                        o.outcome,
                        crate::proxy::content::TransformProgramOutcome::Modified
                    ))
                    .map(|o| o.name.clone());
                self.program_outcomes.extend(script_outcomes);
                self.step_diffs.extend(script_diffs);

                if result_ctx.was_modified(&original) && keep_signed {
                    tracing::info!(
                        program = ?modifying_program_name,
                        "response script rewrote a signed thinking block; kept the original \
                         so the client can send it back"
                    );
                    self.badges.add(crate::audit::AuditBadge::ModifiedNotApplied);
                    block.buffered
                } else if result_ctx.was_modified(&original) {
                    // Save original content for dual-view diff
                    let block_scope = match block.block_type {
                        BlockType::Text => "text",
                        BlockType::Thinking => "thinking",
                        BlockType::ToolUse => "tool_use",
                    };
                    match block.block_type {
                        BlockType::Text | BlockType::Thinking => {
                            self.original_text_blocks.push(original.content.clone());
                            self.injection_blocks.push(crate::proxy::content::InjectionBlock {
                                transform: modifying_program_name.unwrap_or_else(|| "response_script".to_string()),
                                scope: block_scope.to_string(),
                                field: "content".to_string(),
                                action: "replace".to_string(),
                                content: original.content.clone(),
                            });
                        }
                        BlockType::ToolUse => {
                            // A built-in tool's call keeps its item type: a
                            // rename is recorded, not applied.
                            if block.builtin.is_some()
                                && result_ctx.tool_name.as_ref().is_some_and(|n| Some(n) != block.tool_name.as_ref())
                            {
                                self.badges.add(crate::audit::AuditBadge::ModifiedNotApplied);
                            }
                        }
                    }
                    // Re-emit as synthetic DomainEvents
                    self.rebuild_block_events(&block, &result_ctx)
                } else {
                    // Unmodified — replay original events (preserves raw SSE fidelity)
                    block.buffered
                }
            }
            Err(e) => {
                match self.fail_mode {
                    ScriptFailMode::Open => {
                        tracing::warn!(
                            error = %e,
                            "response script chain failed, replaying original block (fail-open)"
                        );
                        block.buffered
                    }
                    ScriptFailMode::Closed => {
                        tracing::error!(
                            error = %e,
                            "response script chain failed, suppressing block (fail-closed)"
                        );
                        let program_name = self.first_response_program();
                        self.badges
                            .add_script_error(crate::audit::Phase::Response, program_name);
                        self.injection_blocks
                            .push(crate::proxy::content::InjectionBlock {
                                transform: "fail_closed".to_string(),
                                scope: match block.block_type {
                                    BlockType::Text => "text",
                                    BlockType::Thinking => "thinking",
                                    BlockType::ToolUse => "tool_use",
                                }
                                .to_string(),
                                field: "content".to_string(),
                                action: "remove".to_string(),
                                content: format!("script error: {e}"),
                            });
                        // Drop the buffered events; emit a synthetic notice so the client
                        // receives a visible signal rather than a silently truncated stream.
                        vec![BufferedEvent {
                            domain_event: Some(DomainEvent::TextDelta(format!(
                                "\n[Response block suppressed: transform script failed in fail-closed mode: {e}]\n"
                            ))),
                            raw_sse: None,
                        }]
                    }
                }
            }
        }
    }

    /// The events that replace `block`'s where the gateway writes its call
    /// whole (`call`, from [`whole_call`]): the call, with the frames a
    /// pass-through client is sent in its place where the upstream's own can
    /// be restated (see [`Self::rewritten_call_frame`],
    /// [`builtin_call_frames`]). Where none can, the pass-through writes the
    /// call from the event.
    fn rewritten_call_events(&mut self, block: &PendingBlock, call: DomainEvent) -> Vec<BufferedEvent> {
        let DomainEvent::ToolCallDelta { function_name, arguments_delta, .. } = &call else {
            return vec![BufferedEvent { domain_event: Some(call), raw_sse: None }];
        };
        // A built-in tool's call goes out as its done carried WITH the call:
        // the pass-through gives a client a built-in call only from a done
        // carried with the call's read.
        if let Some(builtin) = block.builtin {
            let done = builtin_call_frames(block, builtin, arguments_delta);
            // A rewrite the call's payload cannot take is not sent as if
            // written: the call is removed and the client told.
            if done.is_none() {
                tracing::warn!(tool = builtin.tool_name(), "a rewrite of a built-in tool call could not be written into it; removed");
                self.injection_blocks.push(crate::proxy::content::InjectionBlock {
                    transform: "response_script".to_string(),
                    scope: "tool_use".to_string(),
                    field: "tool_call".to_string(),
                    action: "remove".to_string(),
                    content: format!("{}: the rewrite could not be written into the call; removed", builtin.tool_name()),
                });
                return vec![BufferedEvent {
                    domain_event: Some(DomainEvent::TextDelta(format!(
                        "\n[A rewrite of the `{}` call could not be written into it; the call was removed.]\n",
                        builtin.tool_name()
                    ))),
                    raw_sse: None,
                }];
            }
            return vec![BufferedEvent { raw_sse: done, domain_event: Some(call) }];
        }
        let raw_sse = self.rewritten_call_frame(block, function_name.as_deref().unwrap_or_default(), arguments_delta);
        vec![BufferedEvent { domain_event: Some(call), raw_sse }]
    }

    /// The upstream's own frame for a whole call, with its name and arguments
    /// replaced — for a protocol that sends each call whole (Gemini). The part
    /// carries more than the call: a `thoughtSignature` Gemini refuses the next
    /// turn without, and the chunk's candidate fields. A frame built from the
    /// domain event alone would drop them. `None` elsewhere, or where the
    /// held frame is not one call part.
    fn rewritten_call_frame(&self, block: &PendingBlock, name: &str, arguments: &str) -> Option<SseEvent> {
        if !self.calls_arrive_whole {
            return None;
        }
        let raw = block.buffered.first()?.raw_sse.as_ref()?;
        let mut v = serde_json::from_str::<serde_json::Value>(&raw.data).ok()?;
        let args = serde_json::from_str::<serde_json::Value>(arguments).ok()?;
        let parts = v.pointer_mut("/candidates/0/content/parts")?.as_array_mut()?;
        let mut calls = parts.iter_mut().filter_map(|p| p.get_mut("functionCall"));
        let call = calls.next()?;
        call["name"] = serde_json::Value::String(name.to_string());
        call["args"] = args;
        if calls.next().is_some() {
            return None;
        }
        Some(SseEvent { event_type: raw.event_type.clone(), data: serde_json::to_string(&v).ok()?, id: raw.id.clone() })
    }

    /// The `thoughtSignature` on the part of a call that arrived whole
    /// (Gemini): the held frame's call part, when the frame holds that call
    /// alone — a chunk is cut one call per frame wherever a call may be
    /// intercepted (`frame_is_cut`). A frame holding several states no
    /// signature for any one of them: guessing could hand a call another's.
    /// `None` elsewhere.
    fn call_signature(calls_arrive_whole: bool, block: &PendingBlock) -> Option<String> {
        if !calls_arrive_whole {
            return None;
        }
        let raw = block.buffered.first()?.raw_sse.as_ref()?;
        let v = serde_json::from_str::<serde_json::Value>(&raw.data).ok()?;
        let mut calls = v
            .pointer("/candidates/0/content/parts")?
            .as_array()?
            .iter()
            .filter(|p| p.get("functionCall").is_some());
        let part = calls.next()?;
        if calls.next().is_some() {
            return None;
        }
        part.get("thoughtSignature")?.as_str().map(str::to_string)
    }

    /// The program a failed response chain is attributed to: the first (or
    /// only) one, since `execute_response_chain` returns Err on the first
    /// failure.
    fn first_response_program(&self) -> String {
        self.response_programs
            .first()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "response_script".to_string())
    }

    /// Rebuild a block's events from a modified ResponseBlockContext.
    ///
    /// Creates synthetic DomainEvents with `raw_sse: None` (they'll go through
    /// the EventEmitter for protocol-correct encoding).
    fn rebuild_block_events(
        &mut self,
        block: &PendingBlock,
        ctx: &ResponseBlockContext,
    ) -> Vec<BufferedEvent> {
        match block.block_type {
            BlockType::Text => {
                vec![BufferedEvent {
                    domain_event: Some(DomainEvent::TextDelta(ctx.content.clone())),
                    raw_sse: None,
                }]
            }
            BlockType::ToolUse => {
                let name = ctx.tool_name.clone().or_else(|| block.tool_name.clone()).unwrap_or_default();
                // A built-in tool's call a script left the arguments of keeps
                // its own: an empty rewrite would remove it.
                let arguments = match &ctx.arguments {
                    Some(arguments) => arguments.clone(),
                    None if block.builtin.is_some() => block.tool_arguments.clone(),
                    None => String::new(),
                };
                self.rewritten_call_events(block, whole_call(block, name, arguments))
            }
            BlockType::Thinking => {
                vec![BufferedEvent {
                    domain_event: Some(DomainEvent::ReasoningDelta(ctx.content.clone())),
                    raw_sse: None,
                }]
            }
        }
    }

    /// Walk response/tool_calls rules in priority order; return the first
    /// matching rule whose action is `block` or whose `replace` regex
    /// actually rewrites the args — unless the call, a shell call that only
    /// applies a patch, meets a `block` rule as the patch tool
    /// (`tool_rules::patch_block`): that block is returned in place of a
    /// rewrite or an allow. `classify` rules surface their metadata
    /// elsewhere (via `classify_tool_call`) and don't gate the call.
    fn check_tool_policy(&self, block: &PendingBlock) -> PolicyDecision {
        use crate::config::tool_rules::{self, ActionKind, Phase, RuleAction, Scope, ToolCallResolver};

        let raw_tool_name = block.tool_name.as_deref().unwrap_or("");
        if raw_tool_name.is_empty() {
            return PolicyDecision::Allow;
        }
        // A call to a tool the request withheld is refused before the
        // answer's own rules are read (`Self::withheld_tools`).
        if let Some(withheld) = withheld_tool(&self.withheld_tools, raw_tool_name) {
            return PolicyDecision::Block {
                tool_name: raw_tool_name.to_string(),
                reason: Some(withheld.description.clone()),
                rule_id: withheld.rule_id.clone(),
                rule_title: Some(withheld.title.clone()),
            };
        }
        let (tool_name, mcp_server) = match tool_rules::parse_mcp_namespace(raw_tool_name) {
            Some((srv, local)) => (local, Some(srv)),
            None => (raw_tool_name, None),
        };

        let args: Option<serde_json::Value> = if !block.tool_arguments.is_empty() {
            serde_json::from_str(&block.tool_arguments).ok()
        } else {
            None
        };

        let model = self.request_meta.as_ref().map(|m| m.model.as_str());
        let app_id = self.request_meta.as_ref().and_then(|m| m.app_id.as_deref());
        let tool_id = self
            .tool_field_profiles
            .resolve_tool_id(tool_name, app_id, mcp_server)
            .map(|s| s.to_string());
        // LLM-proxy path: `mcp_server` derived from the wire-name namespace
        // prefix is a heuristic, not authoritative. `mcp_server_filter` rules
        // only fire on the MCP gateway (where the upstream comes from the
        // route mapping), so pass `None` here for parity with the pre-check
        // in `prepare_block_interests`. The wire-derived `mcp_server` still
        // flows into `ToolCallResolver` for field-profile lookup, which IS
        // legitimately scoped per-server.
        let scoped = tool_rules::extract_for(
            &self.tool_rules,
            Phase::Response,
            Scope::ToolCalls,
            tool_rules::RuleAxes {
                model,
                app_id,
                ..Default::default()
            },
        );
        let resolver = ToolCallResolver {
            name: tool_name,
            arguments: args.as_ref(),
            field_profiles: Some(&self.tool_field_profiles),
            app_id,
            mcp_server,
            tool_id: tool_id.as_deref(),
        };

        // Preserve the wire name for UI surfacing — operators want to see
        // the original (incl. mcp__ namespace), not the stripped local name
        // used for resolution.
        let blocked_by = |rule: &tool_rules::Rule| PolicyDecision::Block {
            tool_name: raw_tool_name.to_string(),
            reason: rule.description.clone(),
            rule_id: rule.id.clone(),
            rule_title: rule.title.clone(),
        };
        // A shell call that only applies a patch is also read as the patch
        // tool, and that reading can only add a block to this call's own
        // decision (`patch_block`) — read only once its own rules have not
        // blocked it.
        let patch_block = std::cell::OnceCell::new();
        let patch_block = || *patch_block.get_or_init(|| tool_rules::patch_block(&scoped, &resolver));
        for rule in &scoped {
            let rule = *rule;
            if !tool_rules::evaluate(rule, &resolver) {
                continue;
            }
            match rule.action.kind() {
                ActionKind::Classify => continue,
                ActionKind::Block => return blocked_by(rule),
                ActionKind::Replace if patch_block().is_some() => break,
                ActionKind::Replace => {
                    let original_args_str = if block.tool_arguments.is_empty() {
                        "{}".to_string()
                    } else {
                        block.tool_arguments.clone()
                    };
                    let Some(new_args_str) =
                        tool_rules::apply_replacement(&rule.action, &original_args_str)
                    else {
                        // Regex didn't match (or invalid) — try the next rule.
                        continue;
                    };
                    if new_args_str == original_args_str {
                        continue;
                    }
                    let modifications = diff_tool_args(
                        &original_args_str,
                        &new_args_str,
                        &rule.id,
                    );
                    if modifications.is_empty() {
                        continue;
                    }
                    // `with: drop` collapses to "" — keep semantics consistent
                    // by storing an empty JSON object on the wire so downstream
                    // protocol encoders don't choke on a non-JSON args string.
                    let new_args_string = match &rule.action {
                        RuleAction::Replace { drop: true, .. } if block.freeform => {
                            crate::api::domain_request::freeform_call_input("").to_string()
                        }
                        RuleAction::Replace { drop: true, .. } => "{}".to_string(),
                        _ => new_args_str,
                    };
                    return PolicyDecision::Replace {
                        tool_name: raw_tool_name.to_string(),
                        rule_id: rule.id.clone(),
                        rule_title: rule.title.clone(),
                        rule_description: rule.description.clone(),
                        new_args_string,
                        modifications,
                    };
                }
                // Tool-definition rewrite actions don't apply at the
                // tool-call evaluation phase.
                ActionKind::Substitute | ActionKind::InterceptOnly => continue,
            }
        }
        match patch_block() {
            Some(rule) => blocked_by(rule),
            None => PolicyDecision::Allow,
        }
    }
}

/// Compute per-field rewrites between two JSON-encoded args strings. When the
/// strings parse to objects, returns one `ToolArgModification` per top-level
/// key whose value changed. When they don't (non-object payload, parse error),
/// returns a single entry with field `<args>` carrying the before/after pair.
fn diff_tool_args(
    before_str: &str,
    after_str: &str,
    rule_id: &str,
) -> Vec<crate::proxy::content::ToolArgModification> {
    use serde_json::Value;
    let before: Value = serde_json::from_str(before_str).unwrap_or(Value::Null);
    let after: Value = serde_json::from_str(after_str).unwrap_or(Value::Null);
    if before == after {
        return Vec::new();
    }
    if let (Value::Object(b), Value::Object(a)) = (&before, &after) {
        let mut keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for k in b.keys() {
            keys.insert(k.as_str());
        }
        for k in a.keys() {
            keys.insert(k.as_str());
        }
        let mut out = Vec::new();
        for k in keys {
            let bv = b.get(k).cloned().unwrap_or(Value::Null);
            let av = a.get(k).cloned().unwrap_or(Value::Null);
            if bv != av {
                out.push(crate::proxy::content::ToolArgModification {
                    field: k.to_string(),
                    original: bv,
                    effective: av,
                    rule_id: rule_id.to_string(),
                });
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    vec![crate::proxy::content::ToolArgModification {
        field: "<args>".to_string(),
        original: before,
        effective: after,
        rule_id: rule_id.to_string(),
    }]
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// What stands in for a held text or thinking block dropped because it outran
/// the analysis buffer.
fn overflow_notice() -> BufferedEvent {
    BufferedEvent {
        domain_event: Some(DomainEvent::TextDelta(
            "\n[Part of the response was withheld: it exceeded the safety analysis buffer and \
             could not be checked against active policy.]\n"
                .to_string(),
        )),
        raw_sse: None,
    }
}

/// The signature an Anthropic `signature_delta` frame carries, if it is one
/// and the signature is not empty. Read on every frame of a round, so a frame
/// that does not name the delta type is passed over unparsed.
pub(crate) fn thinking_signature(frame: &SseEvent) -> Option<String> {
    if frame.event_type.as_deref() != Some("content_block_delta") || !frame.data.contains("signature_delta") {
        return None;
    }
    let v = serde_json::from_str::<serde_json::Value>(&frame.data).ok()?;
    let delta = v.get("delta")?;
    if delta.get("type").and_then(|t| t.as_str()) != Some("signature_delta") {
        return None;
    }
    delta
        .get("signature")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Compute block interests from active programs and tool risk rules.
///
/// Buffering is required when EITHER a Rhai response-phase program is active
/// for a given block kind, OR a `phase=response, scope=tool_calls,
/// action=block` rule has any non-name conditions (i.e. it inspects args).
/// Pure-name response-phase blocks could be enforced inline, but we always
/// buffer tool blocks anyway when a response/tool_calls block rule exists so
/// the BlockAccumulator can attach the rule id and arguments to the audit
/// record consistently with the args-aware path.
pub fn compute_interests(
    active_programs: &[TransformProgram],
    tool_rules: &[crate::config::tool_rules::Rule],
    model_alias: Option<&str>,
    app_id: Option<&str>,
) -> BlockInterests {
    let response_programs: Vec<&TransformProgram> = active_programs
        .iter()
        .filter(|p| p.enabled && p.phase == "response")
        .filter(|p| p.applies_to_model(model_alias))
        .filter(|p| p.applies_to_app(app_id))
        .collect();

    let has_text_scripts = response_programs
        .iter()
        .any(|p| matches!(p.scope.as_str(), "global" | "text"));
    let has_tool_scripts = response_programs
        .iter()
        .any(|p| matches!(p.scope.as_str(), "global" | "tool"));
    let has_thinking_scripts = response_programs
        .iter()
        .any(|p| matches!(p.scope.as_str(), "global" | "thinking"));

    // Any response-phase tool_calls rule with action=block OR action=replace
    // forces tool-block buffering: the BlockAccumulator needs the complete
    // tool_use to evaluate args, attach rule id + arguments to the audit
    // record, or mutate args.
    let has_response_tool_rules = crate::config::tool_rules::extract_for(
        tool_rules,
        crate::config::tool_rules::Phase::Response,
        crate::config::tool_rules::Scope::ToolCalls,
        crate::config::tool_rules::RuleAxes {
            model: model_alias,
            app_id,
            ..Default::default()
        },
    )
    .iter()
    .any(|r| {
        matches!(
            r.action.kind(),
            crate::config::tool_rules::ActionKind::Block | crate::config::tool_rules::ActionKind::Replace
        )
    });

    BlockInterests {
        buffer_tool_blocks: has_tool_scripts || has_response_tool_rules,
        buffer_text_blocks: has_text_scripts,
        buffer_thinking_blocks: has_thinking_scripts,
    }
}

/// Extract response-phase programs applicable to the given model/app.
pub fn extract_response_programs(
    active_programs: &[TransformProgram],
    model_alias: Option<&str>,
    app_id: Option<&str>,
) -> Vec<TransformProgram> {
    active_programs
        .iter()
        .filter(|p| p.enabled && p.phase == "response")
        .filter(|p| p.applies_to_model(model_alias))
        .filter(|p| p.applies_to_app(app_id))
        .cloned()
        .collect()
}

/// Settle a non-streaming response's finish reason once policy has removed the
/// last tool call from it — the JSON counterpart of
/// `BlockAccumulator::settle_finish_reason`, and held to the same invariant:
/// a finish reason must not claim a tool call the response does not carry.
///
/// `field` / `claims` / `settled` are the per-wire spelling of that one rule
/// (`finish_reason` `tool_calls`→`stop` on Chat Completions, `stop_reason`
/// `tool_use`→`end_turn` on Anthropic Messages). Only rewrites when the value
/// is exactly the claim being retracted, so an upstream that stopped for some
/// other reason — `length`, `max_tokens` — keeps it.
fn settle_finish_reason_json(
    target: &mut serde_json::Value,
    field: &'static str,
    claims: &'static str,
    settled: &'static str,
) {
    if target.get(field).and_then(|v| v.as_str()) == Some(claims)
        && let Some(obj) = target.as_object_mut()
    {
        obj.insert(field.to_string(), serde_json::Value::String(settled.to_string()));
    }
}

/// Apply response-side tool policy to a non-streaming JSON response.
///
/// Removes blocked tool calls from the response JSON in place — a call the
/// answer-phase rules block, or one to a tool the request withheld
/// (`withheld_tools`, see [`BlockAccumulator::withheld_tools`]). The captured
/// `BlockedToolInfo` entries are the non-streaming counterpart of what the
/// `BlockAccumulator` stashes on the streaming path — they surface the tool
/// name, policy description, and the arguments the model actually attempted
/// so the admin-UI audit trail can show *what* was blocked (and not just
/// that *something* was blocked).
/// Returns the captured `BlockedToolInfo` list and a list of tool names that
/// were blocked. Callers feed the names into `BadgeBuilder::add_tool_blocked`
/// so the audit chip rolls up name + count.
pub fn apply_response_policy_json(
    response_json: &mut serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    tool_rules: &[crate::config::tool_rules::Rule],
    field_profiles: &crate::config::tool_rules::FieldProfileSet,
    model: Option<&str>,
    app_id: Option<&str>,
    withheld_tools: &[crate::proxy::content::BlockedToolInfo],
) -> (
    Vec<String>,
    Vec<crate::proxy::content::BlockedToolInfo>,
    Vec<crate::proxy::content::ToolArgModification>,
) {
    use crate::api::sse::ApiVersion;

    let mut blocked_names: Vec<String> = Vec::new();
    let mut blocked_notices: Vec<String> = Vec::new();
    let mut blocked_infos: Vec<crate::proxy::content::BlockedToolInfo> = Vec::new();
    let mut arg_mods: Vec<crate::proxy::content::ToolArgModification> = Vec::new();

    match upstream_version {
        ApiVersion::ChatCompletions => {
            // choices[].message.tool_calls[]
            if let Some(choices) = response_json
                .get_mut("choices")
                .and_then(|c| c.as_array_mut())
            {
                for (choice_at, choice) in choices.iter_mut().enumerate() {
                    if let Some(tool_calls) = choice
                        .get_mut("message")
                        .and_then(|m| m.get_mut("tool_calls"))
                        .and_then(|tc| tc.as_array_mut())
                    {
                        // A call's place among the calls the row records: the
                        // first choice's, before policy runs.
                        let mut position: u32 = 0;
                        tool_calls.retain_mut(|tc| {
                            // A function call or a custom (freeform) one
                            // (`tool_call_item`).
                            let Some(call) = crate::api::domain::tool_call_item(tc) else {
                                return true;
                            };
                            let call_index = (choice_at == 0).then_some(position);
                            position += 1;
                            let name = call.name.to_string();
                            let tool_use_id = call.call_id.map(str::to_string);
                            let args_str = call.arguments;
                            let args: Option<serde_json::Value> =
                                serde_json::from_str(&args_str).ok();
                            match evaluate_response_tool_call_policy(
                                tool_rules,
                                withheld_tools,
                                field_profiles,
                                model,
                                app_id,
                                &name,
                                &args_str,
                                args.as_ref(),
                            ) {
                                ToolCallPolicy::Allow => true,
                                ToolCallPolicy::Replace { new_args_str, modifications, .. } => {
                                    // A Chat call is never a built-in tool's: it is always written.
                                    let _ = crate::api::domain::set_tool_call_arguments(tc, &new_args_str);
                                    arg_mods.extend(modifications);
                                    tracing::info!(
                                        tool_name = %name,
                                        "non-streaming: response tool args rewritten by policy"
                                    );
                                    true
                                }
                                ToolCallPolicy::Block { rule_id, title, description } => {
                                    blocked_names.push(name.clone());
                                    blocked_notices.push(format!("[Tool call to `{name}` was blocked by policy: {description}]"));
                                    blocked_infos.push(crate::proxy::content::BlockedToolInfo {
                                        not_applied: false,
                                        name: name.clone(),
                                        title,
                                        description,
                                        rule_id,
                                        tool_use_id,
                                        call_index,
                                        arguments: args.clone().or_else(|| {
                                            if args_str.is_empty() {
                                                None
                                            } else {
                                                Some(serde_json::Value::String(args_str.clone()))
                                            }
                                        }),
                                    });
                                    tracing::info!(
                                        tool_name = %name,
                                        "non-streaming: response tool call blocked by policy"
                                    );
                                    false
                                }
                            }
                        });
                    }
                    // If all tool calls were blocked, inject a text notice so the client sees something.
                    let mut settle_finish = false;
                    if !blocked_notices.is_empty() {
                        let msg = choice.get_mut("message");
                        if let Some(msg) = msg {
                            // Appended: a chunk-array `content` holds the
                            // model's text and reasoning, which the notice
                            // must not replace.
                            crate::api::chat::append_content_text(msg, &blocked_notices.join("\n"));
                            // An emptied `tool_calls` must not survive as `[]`:
                            // a client testing the key's presence reads an empty
                            // array as "there are calls to run".
                            if msg
                                .get("tool_calls")
                                .and_then(|tc| tc.as_array())
                                .is_some_and(|a| a.is_empty())
                                && let Some(obj) = msg.as_object_mut()
                            {
                                obj.remove("tool_calls");
                                settle_finish = true;
                            }
                        }
                    }
                    // Settled after the `message` borrow ends — see
                    // `settle_finish_reason_json`.
                    if settle_finish {
                        settle_finish_reason_json(choice, "finish_reason", "tool_calls", "stop");
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            // Settled after the `content` borrow ends — see `settle_finish_reason_json`.
            let mut settle_stop_reason = false;
            // content[] where type=tool_use
            if let Some(content) = response_json
                .get_mut("content")
                .and_then(|c| c.as_array_mut())
            {
                // A call's place among the answer's `tool_use` blocks.
                let mut position: u32 = 0;
                content.retain_mut(|block| {
                    let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if block_type != "tool_use" {
                        return true;
                    }
                    let call_index = Some(position);
                    position += 1;
                    let name = block
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let tool_use_id = block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let args = block.get("input").cloned();
                    let args_str = args
                        .as_ref()
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .unwrap_or_default();
                    match evaluate_response_tool_call_policy(
                        tool_rules,
                        withheld_tools,
                        field_profiles,
                        model,
                        app_id,
                        &name,
                        &args_str,
                        args.as_ref(),
                    ) {
                        ToolCallPolicy::Allow => true,
                        ToolCallPolicy::Replace { new_args_str, modifications, .. } => {
                            // Anthropic `input` is an object — parse the
                            // rewritten args back to JSON. If parse fails
                            // (operator's regex produced invalid JSON), skip
                            // the rewrite and let it pass through.
                            if let Ok(new_input) =
                                serde_json::from_str::<serde_json::Value>(&new_args_str)
                                && let Some(obj) = block.as_object_mut()
                            {
                                obj.insert("input".to_string(), new_input);
                                arg_mods.extend(modifications);
                            } else {
                                tracing::warn!(
                                    tool_name = %name,
                                    "non-streaming Anthropic: replace produced invalid JSON args, skipped"
                                );
                            }
                            true
                        }
                        ToolCallPolicy::Block { rule_id, title, description } => {
                            blocked_names.push(name.clone());
                            blocked_notices.push(format!("[Tool call to `{name}` was blocked by policy: {description}]"));
                            blocked_infos.push(crate::proxy::content::BlockedToolInfo {
                                not_applied: false,
                                name: name.clone(),
                                title,
                                description,
                                rule_id,
                                tool_use_id,
                                call_index,
                                arguments: args,
                            });
                            false
                        }
                    }
                });
                // Inject text notice for blocked tool calls.
                if !blocked_notices.is_empty() {
                    settle_stop_reason = !content
                        .iter()
                        .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"));
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": blocked_notices.join("\n"),
                    }));
                }
            }
            if settle_stop_reason {
                settle_finish_reason_json(response_json, "stop_reason", "tool_use", "end_turn");
            }
        }
        ApiVersion::GoogleGemini => {
            // candidates[0].content.parts[] where part has functionCall
            if let Some(parts) = response_json
                .get_mut("candidates")
                .and_then(|c| c.as_array_mut())
                .and_then(|a| a.first_mut())
                .and_then(|c| c.get_mut("content"))
                .and_then(|c| c.get_mut("parts"))
                .and_then(|p| p.as_array_mut())
            {
                // A call's place among the candidate's `functionCall` parts.
                let mut position: u32 = 0;
                parts.retain_mut(|part| {
                    let Some(fc) = part.get("functionCall") else {
                        return true; // keep non-functionCall parts
                    };
                    let call_index = Some(position);
                    position += 1;
                    let name = fc
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    // A Gemini call's `id` is optional; without one its place
                    // (`call_index`) is what tells it from a sibling.
                    let tool_use_id = fc.get("id").and_then(|v| v.as_str()).map(str::to_string);
                    let gemini_args = fc.get("args").cloned();
                    let args_str = gemini_args
                        .as_ref()
                        .map(|a| serde_json::to_string(a).unwrap_or_default())
                        .unwrap_or_default();
                    let args: Option<serde_json::Value> = serde_json::from_str(&args_str).ok();
                    match evaluate_response_tool_call_policy(
                        tool_rules,
                        withheld_tools,
                        field_profiles,
                        model,
                        app_id,
                        &name,
                        &args_str,
                        args.as_ref(),
                    ) {
                        ToolCallPolicy::Allow => true,
                        ToolCallPolicy::Replace { new_args_str, modifications, .. } => {
                            if let Ok(new_args_v) =
                                serde_json::from_str::<serde_json::Value>(&new_args_str)
                                && let Some(fc_mut) = part
                                    .get_mut("functionCall")
                                    .and_then(|f| f.as_object_mut())
                            {
                                fc_mut.insert("args".to_string(), new_args_v);
                                arg_mods.extend(modifications);
                            } else {
                                tracing::warn!(
                                    tool_name = %name,
                                    "non-streaming Gemini: replace produced invalid JSON args, skipped"
                                );
                            }
                            true
                        }
                        ToolCallPolicy::Block { rule_id, title, description } => {
                            blocked_names.push(name.clone());
                            blocked_notices.push(format!("[Tool call to `{name}` was blocked by policy: {description}]"));
                            blocked_infos.push(crate::proxy::content::BlockedToolInfo {
                                not_applied: false,
                                name: name.clone(),
                                title,
                                description,
                                rule_id,
                                tool_use_id,
                                call_index,
                                arguments: gemini_args,
                            });
                            false
                        }
                    }
                });
                // Same notice the other three wires get. Gemini needs no finish
                // reason settled: its `FinishReason` has no value meaning "the
                // model called a function" (a function call is read from the
                // parts), so removing the part is the whole edit.
                if !blocked_notices.is_empty() {
                    parts.push(serde_json::json!({ "text": blocked_notices.join("\n") }));
                }
            }
        }
        ApiVersion::Responses => {
            // output[] items calling a tool: function calls and custom
            // (freeform) tool calls alike (`tool_call_item`).
            if let Some(output) = response_json
                .get_mut("output")
                .and_then(|o| o.as_array_mut())
            {
                // A call's place among the client calls the row records: a
                // call the server ran is none.
                let mut position: u32 = 0;
                output.retain_mut(|item| {
                    // A built-in call goes on carrying only the payload read.
                    if let Some(builtin) = crate::api::domain::ClientBuiltin::of_item(item) {
                        builtin.keep_read_payload_only(item);
                    }
                    let Some(call) = crate::api::domain::tool_call_item(item) else {
                        return true;
                    };
                    // As the row records a client call (`extract_upstream_response`).
                    let recorded = item
                        .get("type")
                        .and_then(|t| t.as_str())
                        .is_some_and(crate::api::domain::is_client_call_item);
                    let call_index = recorded.then_some(position);
                    position += u32::from(recorded);
                    let name = call.name.to_string();
                    let tool_use_id = call.call_id.map(str::to_string);
                    let args_str = call.arguments;
                    let args: Option<serde_json::Value> = serde_json::from_str(&args_str).ok();
                    match evaluate_response_tool_call_policy(
                        tool_rules,
                        withheld_tools,
                        field_profiles,
                        model,
                        app_id,
                        &name,
                        &args_str,
                        args.as_ref(),
                    ) {
                        ToolCallPolicy::Allow => true,
                        ToolCallPolicy::Replace { rule_id: replace_rule_id, new_args_str, modifications } => {
                            if crate::api::domain::set_tool_call_arguments(item, &new_args_str) {
                                arg_mods.extend(modifications);
                                return true;
                            }
                            // A built-in tool's payload cannot take arguments
                            // that are not JSON: the call is not left standing
                            // as if rewritten, it is removed.
                            let description = "the rewritten arguments could not be written into the call".to_string();
                            blocked_names.push(name.clone());
                            blocked_notices.push(format!("[Tool call to `{name}` was blocked by policy: {description}]"));
                            blocked_infos.push(crate::proxy::content::BlockedToolInfo {
                                not_applied: false,
                                name: name.clone(),
                                title: format!("Response tool blocked: {name}"),
                                description,
                                rule_id: replace_rule_id,
                                tool_use_id,
                                call_index,
                                arguments: args.clone(),
                            });
                            false
                        }
                        ToolCallPolicy::Block { rule_id, title, description } => {
                            blocked_names.push(name.clone());
                            blocked_notices.push(format!("[Tool call to `{name}` was blocked by policy: {description}]"));
                            blocked_infos.push(crate::proxy::content::BlockedToolInfo {
                                not_applied: false,
                                name: name.clone(),
                                title,
                                description,
                                rule_id,
                                tool_use_id,
                                call_index,
                                arguments: args.clone().or_else(|| {
                                    if args_str.is_empty() {
                                        None
                                    } else {
                                        Some(serde_json::Value::String(args_str.clone()))
                                    }
                                }),
                            });
                            false
                        }
                    }
                });
                // Inject text notice for blocked tool calls.
                if !blocked_notices.is_empty() {
                    output.push(serde_json::json!({
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": blocked_notices.join("\n")}],
                    }));
                }
            }
        }
    }

    (blocked_names, blocked_infos, arg_mods)
}

/// Walk a non-streaming upstream JSON response and collect every `tool_use`
/// block whose name matches an `InterceptBinding` (by `replaced_name OR
/// original_name`, mirroring `BlockAccumulator::intercept_binding_for`).
///
/// Returns:
///   - `Vec<PendingInterceptedCall>` — entries the agent loop will dispatch.
///   - `real_tool_use_present` — true when at least one tool_use *not* matched
///     by a binding was present (mixed-pending detection).
///
/// Read-only — does not mutate the JSON. Pair with
/// `splice_intercepted_from_response_json` to actually remove the matched
/// blocks before returning to the client.
pub fn extract_pending_intercepts_from_response_json(
    response_json: &serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    bindings: &[crate::proxy::content::InterceptBinding],
) -> (Vec<PendingInterceptedCall>, bool) {
    let (pending, real) = extract_round_calls(response_json, upstream_version, bindings);
    (pending, !real.is_empty())
}

/// A call of a whole answer's round that no substitution binding takes — the
/// client's to run.
#[derive(Debug, Clone)]
pub struct RoundRealCall {
    /// A Gemini call part's `thoughtSignature`.
    pub thought_signature: Option<String>,
    /// A Responses built-in tool's call (`tool_call_item`'s `builtin`).
    pub builtin: bool,
}

/// [`extract_pending_intercepts_from_response_json`], with the round's real
/// calls themselves rather than whether there is one.
pub fn extract_round_calls(
    response_json: &serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    bindings: &[crate::proxy::content::InterceptBinding],
) -> (Vec<PendingInterceptedCall>, Vec<RoundRealCall>) {
    use crate::api::sse::ApiVersion;

    let find_binding = |tool_name: &str| -> Option<&crate::proxy::content::InterceptBinding> {
        bindings
            .iter()
            .find(|b| b.replaced_name == tool_name || b.original_name == tool_name)
    };

    let mut pending: Vec<PendingInterceptedCall> = Vec::new();
    let mut real: Vec<RoundRealCall> = Vec::new();

    match upstream_version {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response_json.get("choices").and_then(|c| c.as_array()) {
                for choice in choices.iter() {
                    if let Some(tool_calls) = choice
                        .get("message")
                        .and_then(|m| m.get("tool_calls"))
                        .and_then(|tc| tc.as_array())
                    {
                        for (idx, tc) in tool_calls.iter().enumerate() {
                            let Some(call) = crate::api::domain::tool_call_item(tc) else {
                                continue;
                            };
                            let name = call.name;
                            let Some(binding) = find_binding(name) else {
                                if !name.is_empty() {
                                    real.push(RoundRealCall {
                                        thought_signature: None,
                                        builtin: false,
                                    });
                                }
                                continue;
                            };
                            pending.push(PendingInterceptedCall {
                                binding: binding.clone(),
                                tool_use_id: call.call_id.map(str::to_string),
                                tool_name: name.to_string(),
                                tool_call_index: idx,
                                arguments_json: call.arguments,
                                thought_signature: None,
                                blocked: None,
                            });
                        }
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(content) = response_json.get("content").and_then(|c| c.as_array()) {
                for (idx, block) in content.iter().enumerate() {
                    let block_type = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if block_type != "tool_use" {
                        continue;
                    }
                    let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let Some(binding) = find_binding(name) else {
                        if !name.is_empty() {
                            real.push(RoundRealCall {
                                thought_signature: None,
                                builtin: false,
                            });
                        }
                        continue;
                    };
                    let tool_use_id = block
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let arguments_json = block
                        .get("input")
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .unwrap_or_default();
                    pending.push(PendingInterceptedCall {
                        binding: binding.clone(),
                        tool_use_id,
                        tool_name: name.to_string(),
                        tool_call_index: idx,
                        arguments_json,
                        thought_signature: None,
                        blocked: None,
                    });
                }
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response_json.get("output").and_then(|o| o.as_array()) {
                for (idx, item) in output.iter().enumerate() {
                    let Some(call) = crate::api::domain::tool_call_item(item) else {
                        continue;
                    };
                    let name = call.name;
                    // A built-in tool's call is the client's to run, whatever
                    // its name: no substitution binding takes it.
                    let binding = if call.builtin.is_some() { None } else { find_binding(name) };
                    let Some(binding) = binding else {
                        if !name.is_empty() {
                            real.push(RoundRealCall {
                                thought_signature: None,
                                builtin: call.builtin.is_some(),
                            });
                        }
                        continue;
                    };
                    pending.push(PendingInterceptedCall {
                        binding: binding.clone(),
                        tool_use_id: call.call_id.map(str::to_string),
                        tool_name: name.to_string(),
                        tool_call_index: idx,
                        arguments_json: call.arguments,
                        thought_signature: None,
                        blocked: None,
                    });
                }
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(parts) = response_json
                .get("candidates")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .and_then(|c| c.get("content"))
                .and_then(|c| c.get("parts"))
                .and_then(|p| p.as_array())
            {
                for (idx, part) in parts.iter().enumerate() {
                    let Some(fc) = part.get("functionCall") else {
                        continue;
                    };
                    let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    // A Gemini call's id is optional; the gateway gives one to
                    // a call with none before this reads it (`call_ids`).
                    let tool_use_id = fc.get("id").and_then(|v| v.as_str()).filter(|id| !id.is_empty()).map(str::to_string);
                    let arguments_json = fc
                        .get("args")
                        .map(|v| serde_json::to_string(v).unwrap_or_default())
                        .unwrap_or_default();
                    let thought_signature = part.get("thoughtSignature").and_then(|s| s.as_str()).map(str::to_string);
                    let Some(binding) = find_binding(name) else {
                        if !name.is_empty() {
                            real.push(RoundRealCall {
                                thought_signature,
                                builtin: false,
                            });
                        }
                        continue;
                    };
                    pending.push(PendingInterceptedCall {
                        binding: binding.clone(),
                        tool_use_id,
                        tool_name: name.to_string(),
                        tool_call_index: idx,
                        arguments_json,
                        thought_signature,
                        blocked: None,
                    });
                }
            }
        }
    }

    (pending, real)
}

/// Whether the answer's tool policy can act on a call at all: a
/// `response × tool_calls` rule that blocks or rewrites applies to this model
/// and app, or the request withheld a tool. Every whole-answer pass is gated
/// on it, so none walks or copies an answer the policy cannot change.
pub fn response_tool_policy_acts(
    tool_rules: &[crate::config::tool_rules::Rule],
    model: Option<&str>,
    app_id: Option<&str>,
    withheld_tools: &[crate::proxy::content::BlockedToolInfo],
) -> bool {
    use crate::config::tool_rules::{self, ActionKind};
    !withheld_tools.is_empty()
        || tool_rules::extract_for(
            tool_rules,
            tool_rules::Phase::Response,
            tool_rules::Scope::ToolCalls,
            tool_rules::RuleAxes { model, app_id, ..Default::default() },
        )
        .iter()
        .any(|r| matches!(r.action.kind(), ActionKind::Block | ActionKind::Replace))
}

/// The calls the answer's tool policy removes from a whole answer's round when
/// it removes every real call of it.
pub struct RealCallsRemoved {
    pub blocked_names: Vec<String>,
    pub blocked_infos: Vec<crate::proxy::content::BlockedToolInfo>,
    /// Some call's arguments were healed before the policy read them.
    pub healed: bool,
}

/// Decide a substitution round's real calls by the answer's tool policy: the
/// pass that removes calls from a whole answer ([`apply_response_policy_json`],
/// over the arguments as healed when `heal`), run on a copy of the round
/// without its intercepted calls. `Some` when the round has a real call and
/// the pass removes every one — the round is then continued without them, as
/// a stream's accumulator leaves them out, rather than handed to the client
/// with nothing to answer. `None` when a real call survives, when there is
/// none, when the policy cannot act ([`response_tool_policy_acts`]), when one
/// is a Responses built-in tool's, and when one carries a Gemini thought
/// signature (a continuation without the signed call may be refused).
#[allow(clippy::too_many_arguments)]
pub fn real_calls_the_policy_removes(
    response_json: &serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    bindings: &[crate::proxy::content::InterceptBinding],
    tool_rules: &[crate::config::tool_rules::Rule],
    field_profiles: &crate::config::tool_rules::FieldProfileSet,
    model: Option<&str>,
    app_id: Option<&str>,
    withheld_tools: &[crate::proxy::content::BlockedToolInfo],
    heal: bool,
) -> Option<RealCallsRemoved> {
    if !response_tool_policy_acts(tool_rules, model, app_id, withheld_tools) {
        return None;
    }
    let (_, real) = extract_round_calls(response_json, upstream_version, bindings);
    if real.is_empty() || real.iter().any(|c| c.builtin || c.thought_signature.is_some()) {
        return None;
    }
    let mut real_only = response_json.clone();
    splice_intercepted_from_response_json(&mut real_only, upstream_version, bindings);
    let healed = heal && crate::pipeline::healing::heal_tool_call_arguments_json(&mut real_only, upstream_version);
    let (blocked_names, blocked_infos, _) = apply_response_policy_json(
        &mut real_only,
        upstream_version,
        tool_rules,
        field_profiles,
        model,
        app_id,
        withheld_tools,
    );
    if !extract_round_calls(&real_only, upstream_version, bindings).1.is_empty() {
        return None;
    }
    // This round is not the answer the row keeps: a place in it names no call there.
    let blocked_infos = blocked_infos
        .into_iter()
        .map(|info| crate::proxy::content::BlockedToolInfo { call_index: None, ..info })
        .collect();
    Some(RealCallsRemoved { blocked_names, blocked_infos, healed })
}

/// Remove every `tool_use` block whose name matches an `InterceptBinding`
/// from the upstream JSON response. Mirrors the streaming path's
/// buffered-discard for substituted blocks (Decision #1: invisibility).
///
/// Used at cap-hit, executor-error, forward-error, and similar bail paths
/// where the round's upstream response is about to be returned to the
/// client. On the success path we don't splice — we re-issue and use the
/// next round's upstream response, which the model has already moved past
/// the intercepted tool_use in.
pub fn splice_intercepted_from_response_json(
    response_json: &mut serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    bindings: &[crate::proxy::content::InterceptBinding],
) {
    use crate::api::sse::ApiVersion;

    if bindings.is_empty() {
        return;
    }
    let matches = |tool_name: &str| -> bool {
        bindings
            .iter()
            .any(|b| b.replaced_name == tool_name || b.original_name == tool_name)
    };

    match upstream_version {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response_json
                .get_mut("choices")
                .and_then(|c| c.as_array_mut())
            {
                for choice in choices.iter_mut() {
                    if let Some(tool_calls) = choice
                        .get_mut("message")
                        .and_then(|m| m.get_mut("tool_calls"))
                        .and_then(|tc| tc.as_array_mut())
                    {
                        tool_calls.retain(|tc| {
                            crate::api::domain::tool_call_item(tc).is_none_or(|call| !matches(call.name))
                        });
                        // If we emptied the array, Chat Completions still
                        // expects either an absent field or an empty list.
                        // Drop the field so a downstream parser doesn't
                        // see [] when the model wasn't trying to call any
                        // tool.
                        if tool_calls.is_empty()
                            && let Some(msg) = choice.get_mut("message").and_then(|m| m.as_object_mut())
                        {
                            msg.remove("tool_calls");
                        }
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(content) = response_json
                .get_mut("content")
                .and_then(|c| c.as_array_mut())
            {
                content.retain(|block| {
                    if block.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
                        return true;
                    }
                    let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    !matches(name)
                });
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response_json
                .get_mut("output")
                .and_then(|o| o.as_array_mut())
            {
                output.retain(|item| {
                    crate::api::domain::tool_call_item(item)
                        .is_none_or(|call| call.builtin.is_some() || !matches(call.name))
                });
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(parts) = response_json
                .get_mut("candidates")
                .and_then(|c| c.as_array_mut())
                .and_then(|a| a.first_mut())
                .and_then(|c| c.get_mut("content"))
                .and_then(|c| c.get_mut("parts"))
                .and_then(|p| p.as_array_mut())
            {
                parts.retain(|part| {
                    let Some(fc) = part.get("functionCall") else {
                        return true;
                    };
                    let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    !matches(name)
                });
            }
        }
    }
}

/// Inject a synthetic text block at the tail of the upstream JSON response.
/// Used at cap-hit / error bail paths so the client doesn't see an empty or
/// tool-only response after the agent loop scrubbed the intercepted
/// `tool_use` blocks.
pub fn inject_substitution_marker_text(
    response_json: &mut serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    marker: &str,
) {
    use crate::api::sse::ApiVersion;
    match upstream_version {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response_json
                .get_mut("choices")
                .and_then(|c| c.as_array_mut())
                && let Some(choice) = choices.first_mut()
                && let Some(msg) = choice.get_mut("message")
            {
                crate::api::chat::append_content_text(msg, marker);
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(content) = response_json
                .get_mut("content")
                .and_then(|c| c.as_array_mut())
            {
                content.push(serde_json::json!({
                    "type": "text",
                    "text": marker,
                }));
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response_json
                .get_mut("output")
                .and_then(|o| o.as_array_mut())
            {
                output.push(serde_json::json!({
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": marker}],
                }));
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(parts) = response_json
                .get_mut("candidates")
                .and_then(|c| c.as_array_mut())
                .and_then(|a| a.first_mut())
                .and_then(|c| c.get_mut("content"))
                .and_then(|c| c.get_mut("parts"))
                .and_then(|p| p.as_array_mut())
            {
                parts.push(serde_json::json!({"text": marker}));
            }
        }
    }
}

/// A non-streaming upstream response's assistant turn as its model produced
/// it, for the next substitution round's splice
/// (`DomainRequest::append_assistant_round`): each signed `thinking` block and
/// each `redacted_thinking` block unchanged, each text block as written, and
/// where each `tool_use` stands, in order. Mirrors the streaming loop's
/// `RoundCapture`: a replayed thinking block is bound to the turn as it was
/// produced, so the splice carries it only where the turn it rebuilds — from
/// the text before the first `tool_use` ([`extract_preamble_from_response_json`])
/// and the calls — is that turn. Only Anthropic seals its thinking, so every
/// other protocol's response yields no parts, and the splice takes its default
/// layout.
pub fn extract_round_parts_from_response_json(
    response_json: &serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
) -> Vec<crate::api::domain_request::RoundPart> {
    use crate::api::domain_request::{DomainContentBlock, RoundPart};
    if upstream_version != crate::api::sse::ApiVersion::AnthropicMessages {
        return Vec::new();
    }
    let Some(content) = response_json.get("content").and_then(|c| c.as_array()) else {
        return Vec::new();
    };
    let mut parts = Vec::new();
    for block in content {
        match block.get("type").and_then(|t| t.as_str()) {
            Some("thinking") => {
                if let Some(signature) = block.get("signature").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                    parts.push(RoundPart::Thinking(DomainContentBlock::Thinking {
                        thinking: block.get("thinking").and_then(|t| t.as_str()).unwrap_or_default().to_string(),
                        signature: Some(signature.to_string()),
                        signed_by: Some(crate::api::sse::ApiVersion::AnthropicMessages),
                    }));
                }
            }
            Some("redacted_thinking") => parts.push(RoundPart::Thinking(DomainContentBlock::Unknown { value: block.clone() })),
            Some("text") => parts.push(RoundPart::Text(
                block.get("text").and_then(|t| t.as_str()).unwrap_or_default().to_string(),
            )),
            Some("tool_use") => {
                parts.push(RoundPart::Call(block.get("id").and_then(|i| i.as_str()).map(str::to_string)));
            }
            _ => {}
        }
    }
    parts
}

/// Extract the assistant's text content that precedes the *first* tool_use
/// block in a non-streaming upstream JSON response. Mirrors
/// `capture_preamble` on the streaming side: the model's pre-tool reasoning
/// must reach the upstream's view of the conversation in the next
/// substitution round so the model can reference its own statement, but
/// post-tool text is dropped (folding it into the leading preamble would
/// falsify the original `Text → ToolUse → Text` ordering).
///
/// Anthropic / Responses / Gemini interleave text and tool blocks in their
/// content/output arrays — preamble is everything before the first tool
/// block. Chat Completions has a separate `content` string and
/// `tool_calls` array, so the entire `content` field is preamble.
pub fn extract_preamble_from_response_json(
    response_json: &serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
) -> String {
    use crate::api::sse::ApiVersion;
    match upstream_version {
        ApiVersion::ChatCompletions => {
            response_json
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .and_then(|c| c.get("message"))
                .and_then(|m| crate::api::chat::content_text(m.get("content")))
                .unwrap_or_default()
                .into_owned()
        }
        ApiVersion::AnthropicMessages => {
            let mut preamble = String::new();
            if let Some(content) = response_json.get("content").and_then(|c| c.as_array()) {
                for block in content.iter() {
                    let bt = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if bt == "tool_use" {
                        break;
                    }
                    if bt == "text"
                        && let Some(t) = block.get("text").and_then(|t| t.as_str())
                    {
                        preamble.push_str(t);
                    }
                }
            }
            preamble
        }
        ApiVersion::Responses => {
            let mut preamble = String::new();
            if let Some(output) = response_json.get("output").and_then(|o| o.as_array()) {
                for item in output.iter() {
                    let it = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if crate::api::domain::tool_call_item(item).is_some() {
                        break;
                    }
                    if it == "message"
                        && let Some(parts) = item.get("content").and_then(|c| c.as_array())
                    {
                        for part in parts.iter() {
                            if part.get("type").and_then(|t| t.as_str()) == Some("output_text")
                                && let Some(t) = part.get("text").and_then(|t| t.as_str())
                            {
                                preamble.push_str(t);
                            }
                        }
                    }
                }
            }
            preamble
        }
        ApiVersion::GoogleGemini => {
            let mut preamble = String::new();
            if let Some(parts) = response_json
                .get("candidates")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
                .and_then(|c| c.get("content"))
                .and_then(|c| c.get("parts"))
                .and_then(|p| p.as_array())
            {
                for part in parts.iter() {
                    if part.get("functionCall").is_some() {
                        break;
                    }
                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                        preamble.push_str(t);
                    }
                }
            }
            preamble
        }
    }
}

/// One substitution round's visible-mode artifact for the non-streaming
/// agent loop. Captured *before* re-issuing each round so the final-body
/// splice can reconstruct the full conversation flow as the client would
/// have seen it had the upstream natively executed the server-tool.
///
/// Mirrors the streaming visible-mode path in `response_pipeline.rs`, where
/// `ServerToolCallDelta` + `ServerToolResult|Error` events are emitted
/// per-round. Non-streaming has no event channel, so we accumulate the same
/// information per-round and inject native wire blocks once at the end via
/// `inject_visible_mode_blocks_into_response_json`.
#[derive(Debug, Clone)]
pub struct VisibleModeRound {
    /// Model text emitted *before* the first tool_use in this round
    /// (already byte-capped + UTF-8-safe by the caller). Empty string when
    /// the model went straight to a tool call with no preamble.
    pub preamble: String,
    /// Visible-mode calls dispatched this round, in order. Each entry is
    /// the upstream's intercepted `tool_use` plus the dispatched outcome.
    pub calls: Vec<VisibleModeCall>,
}

#[derive(Debug, Clone)]
pub struct VisibleModeCall {
    /// Stable id matching the streaming path: prefers the upstream's own
    /// `tool_use.id` when carried, falling back to
    /// `tu_sub_<request_id>_<index>`. Pairs the synthesised call
    /// block with its result block.
    pub tool_use_id: String,
    /// Original `server_type` the client requested
    /// (`web_search_20250305`, `web_search_preview`, `google_search`).
    pub server_type: String,
    /// Canonical executor name (`web_search` / `web_fetch`).
    pub name: String,
    /// Parsed call arguments. `Null` if the upstream emitted no args.
    pub input: serde_json::Value,
    /// Dispatch outcome — projected to native wire shape per protocol.
    pub outcome: VisibleModeOutcome,
}

#[derive(Debug, Clone)]
pub enum VisibleModeOutcome {
    /// Dispatch succeeded; carries the JSON content
    /// (`SearchResult`/`FetchResult`/opaque) returned by
    /// `WebService::dispatch_intercept`.
    Success(serde_json::Value),
    /// Dispatch failed; carries the typed `WebError::category()`
    /// string. Renderers project to protocol-native error blocks
    /// (Anthropic `web_search_tool_result_error`, Responses
    /// `web_search_call.status = "failed"`).
    Error(String),
}

/// Source for a `url_citation` annotation: a single URL+title pair pulled
/// from a dispatched visible-mode result. Used by both streaming
/// (`ResponsesResponseBuilder`) and non-streaming
/// (`inject_visible_mode_blocks_into_response_json`) paths to decorate the
/// subsequent assistant message text with `url_citation` annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlCitationSource {
    pub url: String,
    pub title: Option<String>,
}

/// Computed `url_citation` annotation: the source URL+title plus optional
/// byte spans into the assistant message text where the citation applies.
/// Spans are present when the URL or title appears as a substring of the
/// text (Option 1); absent when no substring match was found and the
/// annotation falls back to a span-less citation (Option 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlCitation {
    pub url: String,
    pub title: Option<String>,
    pub start_index: Option<usize>,
    pub end_index: Option<usize>,
}

/// Pull URL+title pairs from a single dispatched search/fetch result
/// payload (the `Value` carried in `ServerToolResult.content` /
/// `VisibleModeOutcome::Success`). Recognises the same shapes as
/// `anthropic_search_result_content`:
/// - `SearchResult` → each entry of `hits[]` becomes one source
/// - `FetchResult` → `final_url` (or `url`) becomes one source, with the
///   `content_type` mapped to `title`
/// - opaque payloads contribute nothing
pub fn extract_url_citation_sources_from_search_content(
    content: &serde_json::Value,
) -> Vec<UrlCitationSource> {
    let mut out = Vec::new();
    if let Some(hits) = content.get("hits").and_then(|h| h.as_array()) {
        for h in hits {
            let url = h
                .get("url")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if url.is_empty() {
                continue;
            }
            let title = h
                .get("title")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            out.push(UrlCitationSource { url, title });
        }
        return out;
    }
    if let Some(url) = content
        .get("final_url")
        .and_then(|u| u.as_str())
        .or_else(|| content.get("url").and_then(|u| u.as_str()))
        .filter(|s| !s.is_empty())
    {
        let title = content
            .get("content_type")
            .and_then(|t| t.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        out.push(UrlCitationSource {
            url: url.to_string(),
            title,
        });
    }
    out
}

/// Walk every visible-mode round in order, returning unique URL+title
/// citation sources from the dispatched success outcomes. Dedup is by URL
/// only — first occurrence wins (so the title from the first hit takes
/// precedence over later duplicates).
pub fn collect_visible_mode_url_sources(rounds: &[VisibleModeRound]) -> Vec<UrlCitationSource> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<UrlCitationSource> = Vec::new();
    for round in rounds {
        for call in round.calls.iter() {
            if let VisibleModeOutcome::Success(content) = &call.outcome {
                for src in extract_url_citation_sources_from_search_content(content) {
                    if seen.insert(src.url.clone()) {
                        out.push(src);
                    }
                }
            }
        }
    }
    out
}

/// Minimum byte length a title needs before it's eligible for the
/// title-substring fallback. Below this floor, generic 1-3 character
/// titles ("AI", "X", "GPU") would match unrelated text and produce
/// wildly wrong byte spans.
const TITLE_MATCH_MIN_BYTES: usize = 4;

/// Compute `url_citation` annotations against an assistant message text.
/// First-match semantics: for each source, prefer a URL substring match
/// (byte-indexed), fall back to a title substring match if the URL isn't
/// quoted literally. URLs that appear nowhere — verbatim or by title —
/// still emit a span-less annotation so the SDK can render the citation
/// chip even when the model paraphrased the source.
///
/// When the same URL appears multiple times in the text, only the first
/// occurrence gets a span — native OpenAI sometimes emits per-occurrence
/// citations, but that's deferred. Output ordering matches `sources`
/// order; duplicate sources emit duplicate annotations, so de-dup the
/// source list before calling (e.g. via `collect_visible_mode_url_sources`).
pub fn compute_url_citations(text: &str, sources: &[UrlCitationSource]) -> Vec<UrlCitation> {
    let mut out: Vec<UrlCitation> = Vec::with_capacity(sources.len());
    for src in sources {
        if let Some(start) = text.find(src.url.as_str()) {
            let end = start + src.url.len();
            out.push(UrlCitation {
                url: src.url.clone(),
                title: src.title.clone(),
                start_index: Some(start),
                end_index: Some(end),
            });
            continue;
        }
        if let Some(title) = src.title.as_deref()
            && title.len() >= TITLE_MATCH_MIN_BYTES
            && let Some(start) = text.find(title)
        {
            let end = start + title.len();
            out.push(UrlCitation {
                url: src.url.clone(),
                title: src.title.clone(),
                start_index: Some(start),
                end_index: Some(end),
            });
            continue;
        }
        out.push(UrlCitation {
            url: src.url.clone(),
            title: src.title.clone(),
            start_index: None,
            end_index: None,
        });
    }
    out
}

/// Render a [`UrlCitation`] as its native Responses annotation JSON. Spans
/// are emitted only when matched; span-less citations omit
/// `start_index`/`end_index` entirely (Option 4 fallback).
pub(crate) fn url_citation_to_json(citation: &UrlCitation) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "type".to_string(),
        serde_json::Value::String("url_citation".to_string()),
    );
    obj.insert(
        "url".to_string(),
        serde_json::Value::String(citation.url.clone()),
    );
    if let Some(t) = &citation.title {
        obj.insert("title".to_string(), serde_json::Value::String(t.clone()));
    }
    if let Some(s) = citation.start_index {
        obj.insert("start_index".to_string(), serde_json::Value::Number(s.into()));
    }
    if let Some(e) = citation.end_index {
        obj.insert("end_index".to_string(), serde_json::Value::Number(e.into()));
    }
    serde_json::Value::Object(obj)
}

/// Inject visible-mode native server-tool wire blocks into the final
/// non-streaming response JSON, mirroring the streaming visible-mode path
/// (which emits `ServerToolCallDelta` + `ServerToolResult` events through
/// the per-protocol renderer in `translate.rs`).
///
/// Per protocol:
/// - **Anthropic** (`AnthropicMessages`): for each round in order, prepend
///   `[text(preamble?), server_tool_use, web_search_tool_result | _error]`
///   into `content[]`. Existing final-round blocks follow at the tail.
/// - **Gemini** (`GoogleGemini`): single-shot per Decision #2 — accumulate
///   every call's `query` into `webSearchQueries` and every successful
///   result's hits into `groundingChunks`, attach to
///   `candidates[0].groundingMetadata` only when non-empty.
/// - **Responses** (`Responses`): prepend `web_search_call` output_items
///   ahead of every existing item in `output[]` (one per call, in round
///   order). Each item: `{type, id, status, action: {type: "search",
///   query?}}`. The first assistant `message` item in `output[]` is then
///   walked: every `output_text` content part gains `url_citation`
///   annotations on `annotations[]` (one per dispatched URL, byte-spans
///   when the URL or title appears verbatim, span-less otherwise — see
///   [`compute_url_citations`]).
/// - **ChatCompletions**: no native server-tool wire shape; this is a
///   no-op (mirrors the streaming path which drops the events).
///
/// The walker is idempotent on `rounds.is_empty()` — caller can invoke it
/// unconditionally without guarding.
pub fn inject_visible_mode_blocks_into_response_json(
    response_json: &mut serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    rounds: &[VisibleModeRound],
) {
    use crate::api::sse::ApiVersion;
    if rounds.is_empty() {
        return;
    }

    match upstream_version {
        ApiVersion::AnthropicMessages => {
            let Some(content) = response_json
                .get_mut("content")
                .and_then(|c| c.as_array_mut())
            else {
                return;
            };
            let mut prepend: Vec<serde_json::Value> = Vec::new();
            for round in rounds {
                if !round.preamble.is_empty() {
                    prepend.push(serde_json::json!({
                        "type": "text",
                        "text": round.preamble,
                    }));
                }
                for call in round.calls.iter() {
                    prepend.push(serde_json::json!({
                        "type": "server_tool_use",
                        "id": call.tool_use_id,
                        "name": call.name,
                        "input": call.input,
                    }));
                    let result_block = match &call.outcome {
                        VisibleModeOutcome::Success(content) => {
                            let result_content =
                                crate::pipeline::translate::anthropic_search_result_content(
                                    content,
                                );
                            serde_json::json!({
                                "type": "web_search_tool_result",
                                "tool_use_id": call.tool_use_id,
                                "content": result_content,
                            })
                        }
                        VisibleModeOutcome::Error(error_kind) => serde_json::json!({
                            "type": "web_search_tool_result",
                            "tool_use_id": call.tool_use_id,
                            "content": {
                                "type": "web_search_tool_result_error",
                                "error_code": error_kind,
                            },
                        }),
                    };
                    prepend.push(result_block);
                }
            }
            // Splice prepend at the head: drain into a new vec so existing
            // blocks stay in place after.
            let mut new_content = prepend;
            new_content.append(content);
            *content = new_content;
        }
        ApiVersion::GoogleGemini => {
            let mut chunks: Vec<serde_json::Value> = Vec::new();
            let mut queries: Vec<String> = Vec::new();
            let mut push_chunk = |uri: &str, title: &str| {
                if uri.is_empty() {
                    return;
                }
                let already = chunks.iter().any(|c| {
                    c.get("web")
                        .and_then(|w| w.get("uri"))
                        .and_then(|u| u.as_str())
                        == Some(uri)
                });
                if !already {
                    chunks.push(serde_json::json!({
                        "web": {"uri": uri, "title": title}
                    }));
                }
            };
            for round in rounds {
                for call in round.calls.iter() {
                    if let Some(q) = call.input.get("query").and_then(|v| v.as_str())
                        && !queries.iter().any(|x| x == q)
                    {
                        queries.push(q.to_string());
                    }
                    if let VisibleModeOutcome::Success(content) = &call.outcome {
                        if let Some(hits) = content.get("hits").and_then(|h| h.as_array()) {
                            for h in hits {
                                let url = h.get("url").and_then(|u| u.as_str()).unwrap_or("");
                                let title = h.get("title").and_then(|t| t.as_str()).unwrap_or("");
                                push_chunk(url, title);
                            }
                        } else if let Some(url) = content
                            .get("final_url")
                            .and_then(|u| u.as_str())
                            .or_else(|| content.get("url").and_then(|u| u.as_str()))
                        {
                            let title = content
                                .get("content_type")
                                .and_then(|c| c.as_str())
                                .unwrap_or(url);
                            push_chunk(url, title);
                        }
                    }
                }
            }
            if chunks.is_empty() && queries.is_empty() {
                return;
            }
            let candidates = response_json
                .get_mut("candidates")
                .and_then(|c| c.as_array_mut());
            let Some(candidates) = candidates else {
                return;
            };
            let Some(first) = candidates.first_mut() else {
                return;
            };
            let Some(obj) = first.as_object_mut() else {
                return;
            };
            // Emit both keys even when one side is empty — matches the
            // streaming `GeminiResponseBuilder::emit_final_chunk` shape so
            // SDK clients see a stable contract regardless of path.
            let grounding = serde_json::json!({
                "groundingChunks": chunks,
                "webSearchQueries": queries,
            });
            obj.insert("groundingMetadata".to_string(), grounding);
        }
        ApiVersion::Responses => {
            let Some(output) = response_json
                .get_mut("output")
                .and_then(|o| o.as_array_mut())
            else {
                return;
            };
            let mut prepend: Vec<serde_json::Value> = Vec::new();
            for round in rounds {
                for call in round.calls.iter() {
                    let status = match &call.outcome {
                        VisibleModeOutcome::Success(_) => "completed",
                        VisibleModeOutcome::Error(_) => "failed",
                    };
                    let mut action = serde_json::json!({"type": "search"});
                    if let Some(q) = call.input.get("query").and_then(|v| v.as_str()) {
                        action["query"] = serde_json::Value::String(q.to_string());
                    }
                    prepend.push(serde_json::json!({
                        "type": "web_search_call",
                        "id": call.tool_use_id,
                        "status": status,
                        "action": action,
                    }));
                }
            }
            let mut new_output = prepend;
            new_output.append(output);
            // Decorate the first assistant message in `output[]` with
            // `url_citation` annotations on each `output_text` content
            // part. Mirrors the streaming path's annotation emission so
            // SDKs see the same citations regardless of `stream=true`.
            let sources = collect_visible_mode_url_sources(rounds);
            if !sources.is_empty() {
                for item in new_output.iter_mut() {
                    if item.get("type").and_then(|t| t.as_str()) != Some("message") {
                        continue;
                    }
                    let Some(content_arr) =
                        item.get_mut("content").and_then(|c| c.as_array_mut())
                    else {
                        break;
                    };
                    for part in content_arr.iter_mut() {
                        if part.get("type").and_then(|t| t.as_str()) != Some("output_text") {
                            continue;
                        }
                        let text = part
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        let citations = compute_url_citations(&text, &sources);
                        if citations.is_empty() {
                            continue;
                        }
                        let new_annotations: Vec<serde_json::Value> =
                            citations.iter().map(url_citation_to_json).collect();
                        let part_obj = match part.as_object_mut() {
                            Some(o) => o,
                            None => continue,
                        };
                        match part_obj.get_mut("annotations") {
                            Some(serde_json::Value::Array(arr)) => arr.extend(new_annotations),
                            _ => {
                                part_obj.insert(
                                    "annotations".to_string(),
                                    serde_json::Value::Array(new_annotations),
                                );
                            }
                        }
                    }
                    break;
                }
            }
            *output = new_output;
        }
        ApiVersion::ChatCompletions => {
            // Chat Completions has no native server-tool wire shape — the
            // streaming renderer drops `ServerTool*` events for the same
            // reason. Visible-mode rendering is therefore not applicable;
            // the badge surface (`WebSubstitutedServer`) still fires
            // so audit reflects the dispatch.
        }
    }
}

/// Outcome of evaluating response/tool_calls rules against one tool call.
enum ToolCallPolicy {
    Allow,
    Replace {
        /// Id of the `replace` rule that rewrote the call.
        rule_id: String,
        new_args_str: String,
        modifications: Vec<crate::proxy::content::ToolArgModification>,
    },
    Block {
        rule_id: String,
        title: String,
        description: String,
    },
}

/// Walk response/tool_calls rules; first matching block-or-effective-replace wins.
/// Mirrors `BlockAccumulator::check_tool_policy` for the non-streaming path.
#[allow(clippy::too_many_arguments)]
fn evaluate_response_tool_call_policy(
    rules: &[crate::config::tool_rules::Rule],
    withheld_tools: &[crate::proxy::content::BlockedToolInfo],
    field_profiles: &crate::config::tool_rules::FieldProfileSet,
    model: Option<&str>,
    app_id: Option<&str>,
    name: &str,
    args_str: &str,
    args: Option<&serde_json::Value>,
) -> ToolCallPolicy {
    use crate::config::tool_rules::{self, ActionKind, Phase, RuleAction, Scope, ToolCallResolver};

    // A call to a tool the request withheld is refused before the answer's
    // own rules are read (`BlockAccumulator::withheld_tools`).
    if let Some(withheld) = withheld_tool(withheld_tools, name) {
        return ToolCallPolicy::Block {
            rule_id: withheld.rule_id.clone(),
            title: withheld.title.clone(),
            description: withheld.description.clone(),
        };
    }
    let (effective_name, mcp_server) = match tool_rules::parse_mcp_namespace(name) {
        Some((srv, local)) => (local, Some(srv)),
        None => (name, None),
    };
    let tool_id = field_profiles
        .resolve_tool_id(effective_name, app_id, mcp_server)
        .map(|s| s.to_string());
    // LLM-proxy enforcement: pass `None` for `mcp_server` so server-filtered
    // rules only fire on the MCP gateway path (where the upstream is
    // authoritative). Wire-derived `mcp_server` from the namespace prefix is
    // a heuristic — keep it for field-profile lookup but not rule filtering.
    let scoped = tool_rules::extract_for(
        rules,
        Phase::Response,
        Scope::ToolCalls,
        tool_rules::RuleAxes {
            model,
            app_id,
            ..Default::default()
        },
    );
    let resolver = ToolCallResolver {
        name: effective_name,
        arguments: args,
        field_profiles: Some(field_profiles),
        app_id,
        mcp_server,
        tool_id: tool_id.as_deref(),
    };
    let blocked_by = |rule: &tool_rules::Rule| ToolCallPolicy::Block {
        rule_id: rule.id.clone(),
        title: rule.title.clone().unwrap_or_else(|| format!("Response tool blocked: {name}")),
        description: rule.description.clone().unwrap_or_else(|| "blocked by policy".to_string()),
    };
    // A shell call that only applies a patch is also read as the patch tool,
    // and that reading can only add a block — read once the call's own rules
    // have not blocked it (`patch_block`).
    let patch_block = std::cell::OnceCell::new();
    let patch_block = || *patch_block.get_or_init(|| tool_rules::patch_block(&scoped, &resolver));
    for rule in &scoped {
        let rule = *rule;
        if !tool_rules::evaluate(rule, &resolver) {
            continue;
        }
        match rule.action.kind() {
            ActionKind::Classify => continue,
            ActionKind::Block => return blocked_by(rule),
            ActionKind::Replace if patch_block().is_some() => break,
            ActionKind::Replace => {
                let original = if args_str.is_empty() {
                    "{}".to_string()
                } else {
                    args_str.to_string()
                };
                let Some(new_args_str) = tool_rules::apply_replacement(&rule.action, &original) else {
                    continue;
                };
                if new_args_str == original {
                    continue;
                }
                let mods = diff_tool_args(&original, &new_args_str, &rule.id);
                if mods.is_empty() {
                    continue;
                }
                let new_args_str = match &rule.action {
                    RuleAction::Replace { drop: true, .. } => "{}".to_string(),
                    _ => new_args_str,
                };
                return ToolCallPolicy::Replace {
                    rule_id: rule.id.clone(),
                    new_args_str,
                    modifications: mods,
                };
            }
            // Tool-definition rewrite actions don't apply at the
            // tool-call evaluation phase.
            ActionKind::Substitute | ActionKind::InterceptOnly => continue,
        }
    }
    match patch_block() {
        Some(rule) => blocked_by(rule),
        None => ToolCallPolicy::Allow,
    }
}

/// Mask detected PII in place in a **non-streaming** client response body (P3
/// leakage enforce). Walks the protocol-specific text blocks of `response_json`
/// (rendered in `client_version`) and replaces each finding with the configured
/// placeholder. A no-op when nothing is found. Streaming responses cannot use
/// this — their bytes are already flushed — so streaming enforce is audit-only.
pub fn redact_pii_in_response_json(
    response_json: &mut serde_json::Value,
    client_version: crate::api::sse::ApiVersion,
    pii: &crate::guardrail::PiiSettings,
) {
    use crate::api::sse::ApiVersion;

    fn masked(text: &str, pii: &crate::guardrail::PiiSettings) -> Option<String> {
        let findings = crate::guardrail::detect_pii(text, pii);
        (!findings.is_empty()).then(|| crate::guardrail::redact(text, &findings, &pii.redaction_placeholder))
    }

    fn redact_in(value: &mut serde_json::Value, pii: &crate::guardrail::PiiSettings) {
        if let Some(m) = value.as_str().and_then(|text| masked(text, pii)) {
            *value = serde_json::Value::String(m);
        }
    }

    // Both visible output AND reasoning/thinking text are masked: the audit scan
    // runs over `full_response_content()` (which concatenates reasoning + prose),
    // so the wire must cover the same surface or an enforce "block" would be a
    // lie for PII the model put in its reasoning. Mirrors the block set of
    // `apply_response_scripts_json` below.
    match client_version {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response_json.get_mut("choices").and_then(|c| c.as_array_mut()) {
                for choice in choices {
                    // Every text slot and every reasoning spelling, always — a
                    // chunk-array `content` included. Masking only what one
                    // reader happens to return leaves PII on the wire for
                    // bodies using another, while the audit — which scans the
                    // extracted channel — still records the finding as masked.
                    // The slots come from the same helpers the readers use, so
                    // they cannot drift.
                    if let Some(message) = choice.get_mut("message") {
                        // Each slot in place first, so a chunk array keeps its
                        // shape and each reasoning key its own text. Then the
                        // channel as the audit reads it — text chunks joined,
                        // reasoning joined key-then-chunks — so a value split
                        // across two slots, which no slot alone holds, is
                        // masked as one.
                        // The joined pass runs only where there are several
                        // slots: one slot alone is its whole channel.
                        let carries = |v: &serde_json::Value| v.as_str().is_some_and(|t| !t.is_empty());
                        let mut text_slots = 0;
                        for slot in crate::api::chat::text_slots_mut(message) {
                            text_slots += usize::from(carries(slot));
                            redact_in(slot, pii);
                        }
                        if text_slots > 1
                            && let Some(m) = crate::api::chat::content_text(message.get("content"))
                                .and_then(|t| masked(&t, pii))
                        {
                            crate::api::chat::set_content_text(message, m);
                        }
                        // Reasoning joins across `thinking` chunk prose only
                        // where no key carries text: each key is a whole slot
                        // masked above, and a joined write-back would hand a
                        // second key the first one's text.
                        let mut reasoning_slots = 0;
                        for slot in crate::api::chat::reasoning_slots_mut(message) {
                            reasoning_slots += usize::from(carries(slot));
                            redact_in(slot, pii);
                        }
                        let keyed = crate::api::chat::REASONING_KEYS
                            .iter()
                            .any(|k| message.get(*k).is_some_and(carries));
                        if reasoning_slots > 1
                            && !keyed
                            && let Some(m) = crate::api::chat::message_reasoning(message).and_then(|r| masked(&r, pii))
                        {
                            crate::api::chat::set_message_reasoning(message, &m);
                        }
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(blocks) = response_json.get_mut("content").and_then(|c| c.as_array_mut()) {
                for block in blocks {
                    match block.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            if let Some(text) = block.get_mut("text") {
                                redact_in(text, pii);
                            }
                        }
                        // A signed block is masked too, though the API then
                        // refuses it back: enforce is the operator's "never let
                        // this through", and it outranks the next turn.
                        Some("thinking") => {
                            if let Some(text) = block.get_mut("thinking") {
                                redact_in(text, pii);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response_json.get_mut("output").and_then(|o| o.as_array_mut()) {
                for item in output {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some("message") => {
                            if let Some(parts) =
                                item.get_mut("content").and_then(|c| c.as_array_mut())
                            {
                                for part in parts {
                                    if part.get("type").and_then(|t| t.as_str())
                                        == Some("output_text")
                                        && let Some(text) = part.get_mut("text")
                                    {
                                        redact_in(text, pii);
                                    }
                                }
                            }
                        }
                        // Its `summary` and its `content` (`reasoning_text`): the
                        // surface the audit scans (`content::whole_answer_text`).
                        Some("reasoning") => {
                            for key in ["summary", "content"] {
                                for s in item.get_mut(key).and_then(|s| s.as_array_mut()).into_iter().flatten() {
                                    if let Some(text) = s.get_mut("text") {
                                        redact_in(text, pii);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(candidates) =
                response_json.get_mut("candidates").and_then(|c| c.as_array_mut())
            {
                for candidate in candidates {
                    if let Some(parts) = candidate
                        .pointer_mut("/content/parts")
                        .and_then(|p| p.as_array_mut())
                    {
                        for part in parts {
                            if let Some(text) = part.get_mut("text") {
                                redact_in(text, pii);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Apply response-phase Rhai scripts to a non-streaming JSON response in place.
///
/// Walks the response JSON per `upstream_version`, builds a `ResponseBlockContext`
/// for each content block (text, thinking, tool_use), runs the response script
/// chain, and writes any mutations back into the JSON. This is the non-streaming
/// counterpart of `BlockAccumulator::run_response_scripts` and mirrors the shape
/// of `apply_response_policy_json` immediately above.
///
/// Returns the badge builder, per-program outcomes, step diffs, and a list of
/// original text/thinking content recorded before mutation (used to populate
/// `original_response_content` for the dual-view diff).
///
/// Fail mode:
/// - `Open`: script errors are logged and the affected block is left unchanged.
/// - `Closed`: script errors replace the affected block's content with an
///   operator notice and emit a `script_error` audit badge, mirroring the
///   streaming-path semantics in `BlockAccumulator::run_response_scripts`.
#[allow(clippy::type_complexity)]
pub fn apply_response_scripts_json(
    response_json: &mut serde_json::Value,
    upstream_version: crate::api::sse::ApiVersion,
    response_programs: &[TransformProgram],
    script_engine: &ScriptEngine,
    request_meta: &BlockRequestMeta,
    capture_diffs: bool,
    fail_mode: ScriptFailMode,
) -> (
    crate::audit::BadgeBuilder,
    Vec<crate::proxy::content::TransformProgramRef>,
    Vec<TransformStepDiff>,
    Vec<crate::proxy::content::InjectionBlock>,
    Vec<String>,
) {
    use crate::api::sse::ApiVersion;

    let mut badges = crate::audit::BadgeBuilder::new();
    let mut program_outcomes: Vec<crate::proxy::content::TransformProgramRef> = Vec::new();
    let mut step_diffs: Vec<TransformStepDiff> = Vec::new();
    let mut injection_blocks: Vec<crate::proxy::content::InjectionBlock> = Vec::new();
    let mut originals: Vec<String> = Vec::new();

    if response_programs.is_empty() {
        return (badges, program_outcomes, step_diffs, injection_blocks, originals);
    }

    // Helper: run chain on one block, handle fail_mode, append stats.
    // Returns Some(mutated_ctx) when the caller should write mutations back.
    let run_block = |bt: &str,
                     text_content: &str,
                     tool_name: Option<&str>,
                     tool_id: Option<&str>,
                     arguments: Option<&str>,
                     keep: bool,
                     badges: &mut crate::audit::BadgeBuilder,
                     program_outcomes: &mut Vec<crate::proxy::content::TransformProgramRef>,
                     step_diffs: &mut Vec<TransformStepDiff>,
                     injection_blocks: &mut Vec<crate::proxy::content::InjectionBlock>,
                     originals: &mut Vec<String>|
     -> Option<ResponseBlockContext> {
        let ctx = ResponseBlockContext {
            block_type: bt.to_string(),
            content: text_content.to_string(),
            tool_name: tool_name.map(|s| s.to_string()),
            tool_id: tool_id.map(|s| s.to_string()),
            arguments: arguments.map(|s| s.to_string()),
            model: request_meta.model.clone(),
            user_id: request_meta.user_id.clone(),
            app_id: request_meta.app_id.clone(),
            api_version: request_meta.api_version.clone(),
            metadata: std::collections::HashMap::new(),
            labels: vec![],
        };
        let before = ctx.clone();
        match script_engine.execute_response_chain(
            response_programs,
            ctx,
            request_meta.model_alias.as_deref(),
            capture_diffs,
            fail_mode,
        ) {
            Ok((result_ctx, outcomes, sd)) => {
                for o in &outcomes {
                    if matches!(
                        o.outcome,
                        crate::proxy::content::TransformProgramOutcome::Errored
                    ) {
                        badges.add_script_error(crate::audit::Phase::Response, o.name.clone());
                    }
                }
                let modifying_program_name = outcomes
                    .iter()
                    .find(|o| matches!(
                        o.outcome,
                        crate::proxy::content::TransformProgramOutcome::Modified
                    ))
                    .map(|o| o.name.clone());
                program_outcomes.extend(outcomes);
                step_diffs.extend(sd);
                if keep && result_ctx.was_modified(&before) {
                    // A signed thinking block goes back to the API as it was
                    // sent or not at all — see
                    // `BlockRequestMeta::signed_thinking_reaches_client`.
                    badges.add(crate::audit::AuditBadge::ModifiedNotApplied);
                    None
                } else if result_ctx.was_modified(&before) {
                    if matches!(bt, "text" | "thinking") {
                        originals.push(before.content.clone());
                        injection_blocks.push(crate::proxy::content::InjectionBlock {
                            transform: modifying_program_name
                                .clone()
                                .unwrap_or_else(|| "response_script".to_string()),
                            scope: bt.to_string(),
                            field: "content".to_string(),
                            action: "replace".to_string(),
                            content: before.content.clone(),
                        });
                    }
                    Some(result_ctx)
                } else {
                    None
                }
            }
            Err(e) => {
                match fail_mode {
                    ScriptFailMode::Open => {
                        tracing::warn!(
                            error = %e,
                            block_type = %bt,
                            "non-streaming response script chain failed, leaving block unchanged (fail-open)"
                        );
                        None
                    }
                    ScriptFailMode::Closed => {
                        tracing::error!(
                            error = %e,
                            block_type = %bt,
                            "non-streaming response script chain failed, replacing block with notice (fail-closed)"
                        );
                        let program_name = response_programs
                            .first()
                            .map(|p| p.name.clone())
                            .unwrap_or_else(|| "response_script".to_string());
                        badges.add_script_error(crate::audit::Phase::Response, program_name);
                        injection_blocks.push(crate::proxy::content::InjectionBlock {
                            transform: "fail_closed".to_string(),
                            scope: bt.to_string(),
                            field: "content".to_string(),
                            action: "remove".to_string(),
                            content: format!("script error: {e}"),
                        });
                        // Build a synthetic result ctx with the notice replacing the content.
                        let mut notice = before.clone();
                        let message = format!(
                            "[Response block suppressed: transform script failed in fail-closed mode: {e}]"
                        );
                        match bt {
                            "text" | "thinking" => {
                                originals.push(before.content.clone());
                                notice.content = message;
                            }
                            "tool_use" => {
                                // Neutralize the tool call: clear name + arguments.
                                notice.tool_name = Some("__blocked_by_fail_closed__".to_string());
                                notice.arguments = Some("{}".to_string());
                            }
                            _ => {}
                        }
                        Some(notice)
                    }
                }
            }
        }
    };

    match upstream_version {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response_json
                .get_mut("choices")
                .and_then(|c| c.as_array_mut())
            {
                for choice in choices.iter_mut() {
                    let Some(message) = choice.get_mut("message") else { continue };

                    // Text content — the string, or every `text` chunk of a
                    // chunk array; written back without disturbing the array's
                    // other chunks.
                    let cur_text = crate::api::chat::content_text(message.get("content"))
                        .map(std::borrow::Cow::into_owned);
                    if let Some(cur_text) = cur_text
                        && let Some(new_ctx) = run_block(
                            "text", &cur_text, None, None, None, false,
                            &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                        )
                    {
                        crate::api::chat::set_content_text(message, new_ctx.content);
                    }

                    // Reasoning. Read through the one helper (providers split on
                    // the spelling), copying the text out before taking
                    // `&mut message`. The result is written back to EVERY
                    // spelling carrying text, because they are one channel under
                    // several names: rewriting only the one that was read would
                    // leave the untransformed original on the wire beside it —
                    // the leak `redact_pii_in_response_json` refuses for the same
                    // reason.
                    if let Some(cur) = crate::api::chat::message_reasoning(message)
                        .map(std::borrow::Cow::into_owned)
                        && let Some(new_ctx) = run_block(
                            "thinking", &cur, None, None, None, false,
                            &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                        )
                    {
                        crate::api::chat::set_message_reasoning(message, &new_ctx.content);
                    }

                    // Tool calls
                    if let Some(tool_calls) = message
                        .get_mut("tool_calls")
                        .and_then(|tc| tc.as_array_mut())
                    {
                        for tc in tool_calls.iter_mut() {
                            // A function call or a custom (freeform) one.
                            let Some(call) = crate::api::domain::tool_call_item(tc) else {
                                continue;
                            };
                            let (id, name, args) =
                                (call.call_id.map(String::from), call.name.to_string(), call.arguments);
                            if let Some(new_ctx) = run_block(
                                "tool_use", "", Some(&name), id.as_deref(), Some(&args), false,
                                &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                            ) {
                                if let Some(n) = new_ctx.tool_name
                                    && let Some(serde_json::Value::Object(def)) = if tc.get("function").is_some() {
                                        tc.get_mut("function")
                                    } else {
                                        tc.get_mut("custom")
                                    }
                                {
                                    def.insert("name".to_string(), serde_json::Value::String(n));
                                }
                                if let Some(a) = new_ctx.arguments {
                                    // A Chat call is never a built-in tool's: it is always written.
                                    let _ = crate::api::domain::set_tool_call_arguments(tc, &a);
                                }
                            }
                        }
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(content) = response_json
                .get_mut("content")
                .and_then(|c| c.as_array_mut())
            {
                for block in content.iter_mut() {
                    let bt = block.get("type").and_then(|t| t.as_str()).unwrap_or("").to_string();
                    match bt.as_str() {
                        "text" => {
                            let cur = block.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
                            if let Some(new_ctx) = run_block(
                                "text", &cur, None, None, None, false,
                                &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                            ) {
                                block["text"] = serde_json::Value::String(new_ctx.content);
                            }
                        }
                        "thinking" => {
                            let cur = block.get("thinking").and_then(|t| t.as_str()).unwrap_or("").to_string();
                            let signed = block
                                .get("signature")
                                .and_then(|v| v.as_str())
                                .is_some_and(|v| !v.is_empty());
                            if let Some(new_ctx) = run_block(
                                "thinking", &cur, None, None, None,
                                signed && request_meta.signed_thinking_reaches_client,
                                &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                            ) {
                                block["thinking"] = serde_json::Value::String(new_ctx.content);
                            }
                        }
                        "tool_use" => {
                            let name = block.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                            let id = block.get("id").and_then(|v| v.as_str()).map(String::from);
                            let args_str = block
                                .get("input")
                                .map(|v| serde_json::to_string(v).unwrap_or_default())
                                .unwrap_or_default();
                            if let Some(new_ctx) = run_block(
                                "tool_use", "", Some(&name), id.as_deref(), Some(&args_str), false,
                                &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                            ) {
                                if let Some(n) = new_ctx.tool_name {
                                    block["name"] = serde_json::Value::String(n);
                                }
                                if let Some(a) = new_ctx.arguments
                                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(&a)
                                {
                                    block["input"] = v;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(parts) = response_json
                .get_mut("candidates")
                .and_then(|c| c.as_array_mut())
                .and_then(|a| a.first_mut())
                .and_then(|c| c.get_mut("content"))
                .and_then(|c| c.get_mut("parts"))
                .and_then(|p| p.as_array_mut())
            {
                for part in parts.iter_mut() {
                    let is_thought = part.get("thought").and_then(|t| t.as_bool()).unwrap_or(false);
                    if let Some(fc) = part.get("functionCall") {
                        let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                        let args_str = fc
                            .get("args")
                            .map(|v| serde_json::to_string(v).unwrap_or_default())
                            .unwrap_or_default();
                        if let Some(new_ctx) = run_block(
                            "tool_use", "", Some(&name), None, Some(&args_str), false,
                            &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                        ) && let Some(fc_mut) = part.get_mut("functionCall")
                        {
                            if let Some(n) = new_ctx.tool_name {
                                fc_mut["name"] = serde_json::Value::String(n);
                            }
                            if let Some(a) = new_ctx.arguments
                                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&a)
                            {
                                fc_mut["args"] = v;
                            }
                        }
                    } else if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                        let cur = text.to_string();
                        let bt = if is_thought { "thinking" } else { "text" };
                        if let Some(new_ctx) = run_block(
                            bt, &cur, None, None, None, false,
                            &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                        ) {
                            part["text"] = serde_json::Value::String(new_ctx.content);
                        }
                    }
                }
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response_json
                .get_mut("output")
                .and_then(|o| o.as_array_mut())
            {
                for item in output.iter_mut() {
                    let item_type = item
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("")
                        .to_string();
                    match item_type.as_str() {
                        "message" => {
                            if let Some(content) = item
                                .get_mut("content")
                                .and_then(|c| c.as_array_mut())
                            {
                                for part in content.iter_mut() {
                                    let pt = part.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                    if pt == "output_text" {
                                        let cur = part.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
                                        if let Some(new_ctx) = run_block(
                                            "text", &cur, None, None, None, false,
                                            &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                                        ) {
                                            part["text"] = serde_json::Value::String(new_ctx.content);
                                        }
                                    }
                                }
                            }
                        }
                        "reasoning" => {
                            if let Some(summaries) = item
                                .get_mut("summary")
                                .and_then(|s| s.as_array_mut())
                            {
                                for s in summaries.iter_mut() {
                                    let cur = s.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
                                    if let Some(new_ctx) = run_block(
                                        "thinking", &cur, None, None, None, false,
                                        &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                                    ) {
                                        s["text"] = serde_json::Value::String(new_ctx.content);
                                    }
                                }
                            }
                        }
                        // A built-in tool's call is read like a function
                        // call's; it is named by its type, so it keeps it.
                        kind if crate::api::domain::is_client_call_item(kind) =>
                        {
                            let Some(call) = crate::api::domain::tool_call_item(item) else {
                                continue;
                            };
                            let builtin = call.builtin.is_some();
                            let (name, id, args) =
                                (call.name.to_string(), call.call_id.map(String::from), call.arguments);
                            if let Some(new_ctx) = run_block(
                                "tool_use", "", Some(&name), id.as_deref(), Some(&args), false,
                                &mut badges, &mut program_outcomes, &mut step_diffs, &mut injection_blocks, &mut originals,
                            ) {
                                // A built-in tool's call keeps its item type: a
                                // rename is recorded, not applied.
                                match new_ctx.tool_name.filter(|n| *n != name) {
                                    Some(_) if builtin => badges.add(crate::audit::AuditBadge::ModifiedNotApplied),
                                    Some(n) => item["name"] = serde_json::Value::String(n),
                                    None => {}
                                }
                                // A built-in tool's call whose payload cannot
                                // take the script's arguments is not left
                                // standing as if rewritten: a notice stands in.
                                if let Some(a) = new_ctx.arguments
                                    && !crate::api::domain::set_tool_call_arguments(item, &a)
                                {
                                    injection_blocks.push(crate::proxy::content::InjectionBlock {
                                        transform: "response_script".to_string(),
                                        scope: "tool_use".to_string(),
                                        field: "tool_call".to_string(),
                                        action: "remove".to_string(),
                                        content: format!("{name}: the script's rewrite could not be written into the call; removed"),
                                    });
                                    *item = serde_json::json!({
                                        "id": format!("msg_{}", uuid::Uuid::new_v4().simple()),
                                        "type": "message",
                                        "role": "assistant",
                                        "status": "completed",
                                        "content": [{"type": "output_text", "annotations": [], "text": format!(
                                            "[A response script's rewrite of the `{name}` call could not be written into it; the call was removed.]"
                                        )}],
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    (badges, program_outcomes, step_diffs, injection_blocks, originals)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use serde_json::{Value, json};

    // ── redact_pii_in_response_json ──

    fn enabled_pii() -> crate::guardrail::PiiSettings {
        crate::guardrail::PiiSettings {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn redact_pii_response_anthropic() {
        let mut resp = json!({
            "content": [
                {"type": "text", "text": "your ssn is 123-45-6789 ok"},
                {"type": "tool_use", "id": "t1", "name": "x", "input": {}}
            ]
        });
        redact_pii_in_response_json(
            &mut resp,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &enabled_pii(),
        );
        let text = resp["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "your ssn is [REDACTED:US_SSN] ok");
        // The non-text block is untouched.
        assert_eq!(resp["content"][1]["type"], "tool_use");
    }

    #[test]
    fn redact_pii_response_chat_completions() {
        let mut resp = json!({
            "choices": [{"message": {"role": "assistant", "content": "email a@b.com now"}}]
        });
        redact_pii_in_response_json(
            &mut resp,
            crate::api::sse::ApiVersion::ChatCompletions,
            &enabled_pii(),
        );
        assert_eq!(
            resp["choices"][0]["message"]["content"],
            "email [REDACTED:EMAIL_ADDRESS] now"
        );
    }

    /// A chunk-array `content` (Mistral) is masked in every text and thinking
    /// chunk, and keeps its shape — the same slots the audit scans.
    #[test]
    fn redact_pii_response_chat_completions_chunk_content() {
        let mut resp = json!({
            "choices": [{"message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": [{"type": "text", "text": "mail a@b.com"}]},
                {"type": "text", "text": "email a@b.com now"},
                {"type": "reference", "reference_ids": [1]}
            ]}}]
        });
        redact_pii_in_response_json(
            &mut resp,
            crate::api::sse::ApiVersion::ChatCompletions,
            &enabled_pii(),
        );
        let content = &resp["choices"][0]["message"]["content"];
        assert_eq!(content[0]["thinking"][0]["text"], "mail [REDACTED:EMAIL_ADDRESS]");
        assert_eq!(content[1]["text"], "email [REDACTED:EMAIL_ADDRESS] now");
        assert_eq!(content[2], json!({"type": "reference", "reference_ids": [1]}));

        // A value split across two `text` chunks is found as the audit finds
        // it, in the joined text, and masked as one.
        let mut split = json!({
            "choices": [{"message": {"role": "assistant", "content": [
                {"type": "text", "text": "mail a@"},
                {"type": "reference", "reference_ids": [1]},
                {"type": "text", "text": "b.com now"}
            ]}}]
        });
        redact_pii_in_response_json(&mut split, crate::api::sse::ApiVersion::ChatCompletions, &enabled_pii());
        let message = &split["choices"][0]["message"];
        assert_eq!(
            crate::api::chat::content_text(message.get("content")).as_deref(),
            Some("mail [REDACTED:EMAIL_ADDRESS] now")
        );
        assert!(message["content"].as_array().unwrap().contains(&json!({"type": "reference", "reference_ids": [1]})));

        // Reasoning split across two prose items of a `thinking` chunk is
        // found in the joined channel, as the audit reads it, and masked.
        let mut split = json!({
            "choices": [{"message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": [
                    {"type": "text", "text": "mail a@"},
                    {"type": "text", "text": "b.com"}
                ]},
                {"type": "text", "text": "ok"}
            ]}}]
        });
        redact_pii_in_response_json(&mut split, crate::api::sse::ApiVersion::ChatCompletions, &enabled_pii());
        let message = &split["choices"][0]["message"];
        assert_eq!(
            crate::api::chat::message_reasoning(message).as_deref(),
            Some("mail [REDACTED:EMAIL_ADDRESS]")
        );

        // A value inside one chunk is masked in place: the citation keeps its
        // place between the chunks, and each reasoning key keeps its own text.
        let mut inside = json!({
            "choices": [{"message": {"role": "assistant",
                "reasoning": "mail a@b.com", "reasoning_content": "other notes",
                "content": [
                    {"type": "text", "text": "A"},
                    {"type": "reference", "reference_ids": [1]},
                    {"type": "text", "text": "B a@b.com"}
                ]}}]
        });
        redact_pii_in_response_json(&mut inside, crate::api::sse::ApiVersion::ChatCompletions, &enabled_pii());
        let message = &inside["choices"][0]["message"];
        assert_eq!(message["content"], json!([
            {"type": "text", "text": "A"},
            {"type": "reference", "reference_ids": [1]},
            {"type": "text", "text": "B [REDACTED:EMAIL_ADDRESS]"}
        ]));
        assert_eq!(message["reasoning"], "mail [REDACTED:EMAIL_ADDRESS]");
        assert_eq!(message["reasoning_content"], "other notes");
    }

    #[test]
    fn redact_pii_response_gemini_and_responses() {
        let mut gem = json!({
            "candidates": [{"content": {"parts": [{"text": "ssn 123-45-6789"}]}}]
        });
        redact_pii_in_response_json(
            &mut gem,
            crate::api::sse::ApiVersion::GoogleGemini,
            &enabled_pii(),
        );
        assert_eq!(gem["candidates"][0]["content"]["parts"][0]["text"], "ssn [REDACTED:US_SSN]");

        let mut resp = json!({
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "ssn 123-45-6789"}]}]
        });
        redact_pii_in_response_json(
            &mut resp,
            crate::api::sse::ApiVersion::Responses,
            &enabled_pii(),
        );
        assert_eq!(resp["output"][0]["content"][0]["text"], "ssn [REDACTED:US_SSN]");
    }

    #[test]
    fn redact_pii_response_masks_reasoning() {
        // PII in a reasoning/thinking block must be masked too — the audit scans
        // reasoning + prose, so the wire must cover both or an enforce block lies.
        let mut anthropic = json!({
            "content": [
                {"type": "thinking", "thinking": "the user's ssn is 123-45-6789"},
                {"type": "text", "text": "done"}
            ]
        });
        redact_pii_in_response_json(
            &mut anthropic,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &enabled_pii(),
        );
        assert_eq!(
            anthropic["content"][0]["thinking"],
            "the user's ssn is [REDACTED:US_SSN]"
        );

        let mut responses = json!({
            "output": [
                {"type": "reasoning", "summary": [{"type": "summary_text", "text": "ssn 123-45-6789"}],
                 "content": [{"type": "reasoning_text", "text": "and 123-45-6788"}]},
                {"type": "message", "content": [{"type": "output_text", "text": "ok"}]}
            ]
        });
        redact_pii_in_response_json(
            &mut responses,
            crate::api::sse::ApiVersion::Responses,
            &enabled_pii(),
        );
        assert_eq!(responses["output"][0]["summary"][0]["text"], "ssn [REDACTED:US_SSN]");
        // Its `content` is reasoning the audit scans, so it is masked too.
        assert_eq!(responses["output"][0]["content"][0]["text"], "and [REDACTED:US_SSN]");

        let mut chat = json!({
            "choices": [{"message": {"role": "assistant", "content": "ok", "reasoning_content": "ssn 123-45-6789"}}]
        });
        redact_pii_in_response_json(
            &mut chat,
            crate::api::sse::ApiVersion::ChatCompletions,
            &enabled_pii(),
        );
        assert_eq!(chat["choices"][0]["message"]["reasoning_content"], "ssn [REDACTED:US_SSN]");
    }

    // ── apply_response_scripts_json — thinking scope ──

    /// A thinking-scope response transform must reach the reasoning channel on
    /// **every** protocol.
    ///
    /// This is a parity test rather than four separate ones because the failure
    /// mode is per-arm: each protocol carries reasoning in its own shape, so an
    /// arm can be written that handles prose and tool calls and silently skips
    /// reasoning. A tenant then sees the program applied when a request streams
    /// (the streaming path runs thinking scripts on each reasoning delta) and
    /// skipped when it does not.
    #[test]
    fn thinking_scope_reaches_every_protocols_reasoning_channel() {
        let program = crate::scripting::TransformProgram {
            id: "t".into(),
            name: "mark_thinking".into(),
            source: r#"fn transform(ctx) { ctx.content = "[T] " + ctx.content; ctx }"#.into(),
            phase: "response".into(),
            scope: "thinking".into(),
            priority: 10,
            enabled: true,
            version_hash: "v1".into(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        };
        let meta = BlockRequestMeta {
            model: "m".into(),
            user_id: "u".into(),
            app_id: None,
            api_version: "chat_completions".into(),
            model_alias: None,
            signed_thinking_reaches_client: false,
        };
        let engine = crate::scripting::ScriptEngine::new();

        // (protocol, response body, JSON pointer to the reasoning text, pointer to the prose)
        let cases: Vec<(crate::api::sse::ApiVersion, Value, &str, &str)> = vec![
            (
                crate::api::sse::ApiVersion::ChatCompletions,
                json!({"choices": [{"message": {"role": "assistant", "content": "answer", "reasoning": "why"}}]}),
                "/choices/0/message/reasoning",
                "/choices/0/message/content",
            ),
            // The other spelling must be written back to the key the provider
            // used, not to the one this code happens to prefer.
            (
                crate::api::sse::ApiVersion::ChatCompletions,
                json!({"choices": [{"message": {"role": "assistant", "content": "answer", "reasoning_content": "why"}}]}),
                "/choices/0/message/reasoning_content",
                "/choices/0/message/content",
            ),
            // Mistral's chunk-array `content`: reasoning in a `thinking`
            // chunk, prose in a `text` chunk beside it.
            (
                crate::api::sse::ApiVersion::ChatCompletions,
                json!({"choices": [{"message": {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]},
                    {"type": "text", "text": "answer"}
                ]}}]}),
                "/choices/0/message/content/0/thinking/0/text",
                "/choices/0/message/content/1/text",
            ),
            (
                crate::api::sse::ApiVersion::AnthropicMessages,
                json!({"content": [
                    {"type": "thinking", "thinking": "why"},
                    {"type": "text", "text": "answer"}
                ]}),
                "/content/0/thinking",
                "/content/1/text",
            ),
            (
                crate::api::sse::ApiVersion::GoogleGemini,
                json!({"candidates": [{"content": {"parts": [
                    {"text": "why", "thought": true},
                    {"text": "answer"}
                ]}}]}),
                "/candidates/0/content/parts/0/text",
                "/candidates/0/content/parts/1/text",
            ),
            (
                crate::api::sse::ApiVersion::Responses,
                json!({"output": [
                    {"type": "reasoning", "summary": [{"type": "summary_text", "text": "why"}]},
                    {"type": "message", "content": [{"type": "output_text", "text": "answer"}]}
                ]}),
                "/output/0/summary/0/text",
                "/output/1/content/0/text",
            ),
        ];

        for (version, body, reasoning_ptr, prose_ptr) in cases {
            let mut resp = body;
            apply_response_scripts_json(
                &mut resp,
                version,
                std::slice::from_ref(&program),
                &engine,
                &meta,
                false,
                ScriptFailMode::Open,
            );
            assert_eq!(
                resp.pointer(reasoning_ptr).and_then(|v| v.as_str()),
                Some("[T] why"),
                "{version:?}: a thinking-scope program never reached the reasoning channel"
            );
            // Scope discipline: a thinking program must not touch prose.
            assert_eq!(
                resp.pointer(prose_ptr).and_then(|v| v.as_str()),
                Some("answer"),
                "{version:?}: a thinking-scope program leaked into the text block"
            );
        }
    }

    /// A body carrying BOTH Chat Completions reasoning spellings must have both
    /// rewritten.
    ///
    /// They are one channel under two names, and readers take the first with
    /// text — so rewriting only that one leaves the untransformed original on
    /// the wire in the other. For a redacting transform that is a straight leak,
    /// and an invisible one: the audit records the rewritten channel it read.
    /// `redact_pii_in_response_json` masks both keys for exactly this reason.
    #[test]
    fn thinking_scope_rewrites_both_chat_completions_reasoning_spellings() {
        let program = crate::scripting::TransformProgram {
            id: "t".into(),
            name: "redact_thinking".into(),
            source: r#"fn transform(ctx) { ctx.content = "[SCRUBBED]"; ctx }"#.into(),
            phase: "response".into(),
            scope: "thinking".into(),
            priority: 10,
            enabled: true,
            version_hash: "v1".into(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        };
        let meta = BlockRequestMeta {
            model: "m".into(),
            user_id: "u".into(),
            app_id: None,
            api_version: "chat_completions".into(),
            model_alias: None,
            signed_thinking_reaches_client: false,
        };
        let mut resp = json!({"choices": [{"message": {
            "role": "assistant",
            "content": "answer",
            "reasoning": "the secret is hunter2",
            "reasoning_content": "the secret is hunter2",
        }}]});
        apply_response_scripts_json(
            &mut resp,
            crate::api::sse::ApiVersion::ChatCompletions,
            std::slice::from_ref(&program),
            &crate::scripting::ScriptEngine::new(),
            &meta,
            false,
            ScriptFailMode::Open,
        );
        for key in crate::api::chat::REASONING_KEYS {
            assert_eq!(
                resp["choices"][0]["message"][key], "[SCRUBBED]",
                "`{key}` kept the untransformed original beside the rewritten copy"
            );
        }

        // A blank sibling holds no original to leak, so it stays blank rather
        // than being materialised into reasoning the model never emitted.
        let mut blank_sibling = json!({"choices": [{"message": {
            "role": "assistant",
            "content": "answer",
            "reasoning": "the secret is hunter2",
            "reasoning_content": "",
        }}]});
        apply_response_scripts_json(
            &mut blank_sibling,
            crate::api::sse::ApiVersion::ChatCompletions,
            std::slice::from_ref(&program),
            &crate::scripting::ScriptEngine::new(),
            &meta,
            false,
            ScriptFailMode::Open,
        );
        assert_eq!(blank_sibling["choices"][0]["message"]["reasoning"], "[SCRUBBED]");
        assert_eq!(blank_sibling["choices"][0]["message"]["reasoning_content"], "");
    }

    /// An absent reasoning channel must not be invented, and a blank one must
    /// not be rewritten into a non-empty string — either would put reasoning on
    /// the wire that the model never emitted.
    #[test]
    fn thinking_scope_leaves_an_absent_or_blank_reasoning_channel_alone() {
        let program = crate::scripting::TransformProgram {
            id: "t".into(),
            name: "mark_thinking".into(),
            source: r#"fn transform(ctx) { ctx.content = "[T] " + ctx.content; ctx }"#.into(),
            phase: "response".into(),
            scope: "thinking".into(),
            priority: 10,
            enabled: true,
            version_hash: "v1".into(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        };
        let meta = BlockRequestMeta {
            model: "m".into(),
            user_id: "u".into(),
            app_id: None,
            api_version: "chat_completions".into(),
            model_alias: None,
            signed_thinking_reaches_client: false,
        };
        let engine = crate::scripting::ScriptEngine::new();

        for body in [
            json!({"choices": [{"message": {"role": "assistant", "content": "answer"}}]}),
            json!({"choices": [{"message": {"role": "assistant", "content": "answer", "reasoning": ""}}]}),
        ] {
            let mut resp = body.clone();
            apply_response_scripts_json(
                &mut resp,
                crate::api::sse::ApiVersion::ChatCompletions,
                std::slice::from_ref(&program),
                &engine,
                &meta,
                false,
                ScriptFailMode::Open,
            );
            assert_eq!(resp, body, "an absent/blank reasoning channel was materialised");
        }
    }

    #[test]
    fn redact_pii_response_noop_when_clean() {
        let mut resp = json!({"content": [{"type": "text", "text": "nothing to see"}]});
        let before = resp.clone();
        redact_pii_in_response_json(
            &mut resp,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &enabled_pii(),
        );
        assert_eq!(resp, before);
    }

    // ── compute_interests ──

    #[test]
    fn interests_inactive_when_no_rules_no_programs() {
        let interests = compute_interests(&[], &[], None, None);
        assert!(!interests.is_active());
    }

    #[test]
    fn response_phase_block_rule_enables_tool_buffering() {
        // Any response/tool_calls block rule (with or without arg conditions)
        // forces tool buffering — the BlockAccumulator needs the complete
        // tool_use to attach rule id + arguments to the audit record.
        let rules = rules_from_json(vec![json!({
            "id": "T-5107",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let interests = compute_interests(&[], &rules, None, None);
        assert!(interests.buffer_tool_blocks);
        assert!(!interests.buffer_text_blocks);
        assert!(!interests.buffer_thinking_blocks);
    }

    #[test]
    fn request_phase_block_rule_does_not_enable_response_buffering() {
        // Request-phase rules act on tool definitions before forwarding.
        // The response-phase BlockAccumulator must not buffer tool calls
        // for them — they don't apply on the response side.
        let rules = rules_from_json(vec![json!({
            "id": "T-5128",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{ "target": "name", "op": "glob", "value": "web_search" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let interests = compute_interests(&[], &rules, None, None);
        assert!(!interests.buffer_tool_blocks);
    }

    #[test]
    fn response_text_program_enables_text_buffering() {
        let programs = vec![make_response_program("pii_redact", "text")];
        let interests = compute_interests(&programs, &[], None, None);
        assert!(interests.buffer_text_blocks);
        assert!(!interests.buffer_tool_blocks);
        assert!(!interests.buffer_thinking_blocks);
    }

    #[test]
    fn response_global_program_enables_all_buffering() {
        let programs = vec![make_response_program("global_filter", "global")];
        let interests = compute_interests(&programs, &[], None, None);
        assert!(interests.buffer_text_blocks);
        assert!(interests.buffer_tool_blocks);
        assert!(interests.buffer_thinking_blocks);
    }

    #[test]
    fn request_phase_program_ignored_for_interests() {
        let programs = vec![TransformProgram {
            phase: "request".to_string(),
            ..make_response_program("request_only", "global")
        }];
        let interests = compute_interests(&programs, &[], None, None);
        assert!(!interests.is_active());
    }

    // ── BlockAccumulator — tool policy ──

    #[test]
    fn tool_allowed_when_args_dont_match_rule() {
        let rules = rules_from_json(vec![json!({
            "id": "T-5171",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = make_tool_accumulator(rules);

        let mut output = vec![];
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Read".into()),
                arguments_delta: r#"{"file_path": "/home/user/file.txt"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        assert!(output
            .iter()
            .any(|e| matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { .. }))));
        assert_eq!(acc.stats.tool_blocks_blocked, 0);
    }

    #[test]
    fn tool_blocked_when_args_match_rule() {
        let rules = rules_from_json(vec![json!({
            "id": "T-5210",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger",
            "description": "Blocked: reading sensitive files"
        })]);
        let mut acc = make_tool_accumulator(rules);

        let mut output = vec![];
        // Fragmented tool call
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Read".into()),
                arguments_delta: r#"{"file_path""#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: r#": "/etc/shadow"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // Tool call suppressed (replaced with text notice), Done event present
        assert!(!output
            .iter()
            .any(|e| matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { .. }))));
        assert!(output
            .iter()
            .any(|e| matches!(&e.domain_event, Some(DomainEvent::Done { .. }))));
        // Explanatory text notice should be present
        assert!(output.iter().any(|e| matches!(
            &e.domain_event,
            Some(DomainEvent::TextDelta(t)) if t.contains("blocked by policy")
        )));
        assert_eq!(acc.stats.tool_blocks_blocked, 1);
        let badges = acc.badges.clone().finish();
        assert!(badges.iter().any(|b| matches!(
            b,
            crate::audit::AuditBadge::ToolBlocked { phase, names, .. }
                if *phase == crate::audit::Phase::Response && names.iter().any(|n| n == "Read")
        )));
    }

    /// A record's place (`call_index`) names its call among the calls a whole
    /// answer's row records — read back the way the console reads them — on
    /// every protocol: the row records every call before policy runs, and
    /// neither the server's own calls nor an item it does not record as a call
    /// count. A Gemini call's optional `id` is
    /// read; a Chat choice past the first, which the row does not keep, gets
    /// no place.
    #[test]
    fn a_removed_calls_place_names_it_in_the_stored_answer() {
        use crate::api::sse::ApiVersion;
        let withheld = [crate::proxy::content::BlockedToolInfo {
            not_applied: false,
            name: "search".into(),
            title: "t".into(),
            description: "search is withheld".into(),
            rule_id: "R-S".into(),
            tool_use_id: None,
            call_index: None,
            arguments: None,
        }];
        let chat_call = |id: &str, name: &str| json!({"type": "function", "id": id, "function": {"name": name, "arguments": "{}"}});
        let cases = [
            (ApiVersion::ChatCompletions, json!({"choices": [
                {"index": 0, "message": {"role": "assistant", "tool_calls": [
                    chat_call("s1", "search"), chat_call("r1", "read"), chat_call("s2", "search"),
                ]}},
                {"index": 1, "message": {"role": "assistant", "tool_calls": [chat_call("s3", "search")]}},
            ]})),
            (ApiVersion::AnthropicMessages, json!({"content": [
                {"type": "text", "text": "looking"},
                {"type": "server_tool_use", "id": "srv", "name": "web_search", "input": {}},
                {"type": "tool_use", "id": "s1", "name": "search", "input": {}},
                {"type": "tool_use", "id": "r1", "name": "read", "input": {}},
                {"type": "tool_use", "id": "s2", "name": "search", "input": {}},
            ]})),
            (ApiVersion::GoogleGemini, json!({"candidates": [{"content": {"role": "model", "parts": [
                {"text": "looking"},
                {"functionCall": {"name": "search", "args": {}}},
                {"functionCall": {"name": "read", "args": {}}},
                {"functionCall": {"id": "s2", "name": "search", "args": {}}},
            ]}}]})),
            (ApiVersion::Responses, json!({"output": [
                {"type": "mcp_call", "id": "m1", "name": "lookup", "arguments": "{}", "server_label": "x"},
                {"type": "shell_call", "id": "h1", "call_id": "h1", "action": {"commands": ["ls"]}, "environment": {"type": "container_auto"}},
                // Read as a call, but no item the row records as one.
                {"type": "function", "name": "lookup", "arguments": "{}"},
                {"type": "function_call", "id": "f1", "call_id": "s1", "name": "search", "arguments": "{}"},
                {"type": "function_call", "id": "f2", "call_id": "r1", "name": "read", "arguments": "{}"},
                {"type": "function_call", "id": "f3", "call_id": "s2", "name": "search", "arguments": "{}"},
            ]})),
        ];
        for (wire, answer) in cases {
            let mut policed = answer.clone();
            let (_, infos, _) = apply_response_policy_json(
                &mut policed, wire, &[], &default_test_profiles(), None, None, &withheld,
            );
            let places: Vec<_> = infos.iter().map(|i| i.call_index).collect();
            let mut row = crate::pipeline::response::TransformState::new(wire);
            crate::pipeline::response_pipeline::read_whole_answer(&answer, wire, &mut row);
            let stored = serde_json::to_value(&row.accumulated_tool_calls).unwrap();
            let calls: Vec<(String, String)> =
                crate::api::domain_request::domain_assistant_content_from_stored(wire, None, Some(&stored), None)
                    .into_iter()
                    .filter_map(|b| match b {
                        crate::api::domain_request::DomainContentBlock::ToolUse { id, name, .. } => Some((id, name)),
                        _ => None,
                    })
                    .collect();
            let expected: &[Option<u32>] =
                if wire == ApiVersion::ChatCompletions { &[Some(0), Some(2), None] } else { &[Some(0), Some(2)] };
            assert_eq!(places, expected, "{wire:?}");
            for info in &infos {
                let Some(place) = info.call_index else { continue };
                let (id, name) = &calls[place as usize];
                assert_eq!(name, &info.name, "{wire:?}: {calls:?}");
                if let Some(call) = &info.tool_use_id {
                    assert_eq!(id, call, "{wire:?}");
                }
            }
            let ids: Vec<_> = infos.iter().map(|i| i.tool_use_id.as_deref()).collect();
            let expected_ids: &[Option<&str>] = match wire {
                ApiVersion::GoogleGemini => &[None, Some("s2")],
                ApiVersion::ChatCompletions => &[Some("s1"), Some("s2"), Some("s3")],
                _ => &[Some("s1"), Some("s2")],
            };
            assert_eq!(ids, expected_ids, "{wire:?}");
        }
    }

    /// WebFetch as a request withholds it, under rule `R-FETCH`.
    fn withheld_web_fetch() -> crate::proxy::content::BlockedToolInfo {
        crate::proxy::content::BlockedToolInfo {
            not_applied: false,
            name: "WebFetch".into(),
            title: "Web fetch".into(),
            description: "WebFetch is withheld".into(),
            rule_id: "R-FETCH".into(),
            tool_use_id: None,
            call_index: None,
            arguments: None,
        }
    }

    /// A call to a tool the request withheld (tool policy removed its
    /// declaration, or the client only lists it as deferred) is refused under
    /// that tool's rule, streamed or whole on every protocol, though no
    /// answer-phase rule names it: a client can run a tool it never declared.
    /// A call to another tool, and the same call with nothing withheld, go
    /// through.
    #[test]
    fn a_call_to_a_withheld_tool_is_blocked() {
        use crate::api::sse::ApiVersion;
        let withheld = vec![withheld_web_fetch()];
        let calls = |output: &[BufferedEvent]| {
            output.iter().filter(|e| matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { .. }))).count()
        };
        let stream = |name: &str, withheld: Vec<crate::proxy::content::BlockedToolInfo>| {
            let mut acc = make_tool_accumulator(vec![]).withheld_tools(withheld);
            let mut output = acc.process(
                DomainEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_1".into()),
                    function_name: Some(name.into()),
                    arguments_delta: r#"{"url":"https://example.com"}"#.into(),
                    form: crate::api::domain::CallArguments::Json,
                },
                None,
            );
            output.extend(acc.process(DomainEvent::Done { finish_reason: None, native_finish_reason: None }, None));
            (calls(&output), acc.blocked_tool_infos)
        };
        let (delivered, blocked) = stream("WebFetch", withheld.clone());
        assert_eq!(delivered, 0);
        assert_eq!(
            blocked.iter().map(|b| (b.name.as_str(), b.rule_id.as_str())).collect::<Vec<_>>(),
            [("WebFetch", "R-FETCH")]
        );
        assert!(stream("WebFetch", vec![]).0 > 0);
        let (delivered, blocked) = stream("Read", withheld.clone());
        assert!(delivered > 0 && blocked.is_empty());

        let args = r#"{"url":"https://example.com"}"#;
        let answer = |wire: ApiVersion, name: &str| match wire {
            ApiVersion::ChatCompletions => json!({"choices": [{"message": {"content": null, "tool_calls": [{
                "id": "call_1", "type": "function", "function": {"name": name, "arguments": args}}]}}]}),
            ApiVersion::AnthropicMessages => json!({"content": [
                {"type": "tool_use", "id": "toolu_1", "name": name, "input": {"url": "https://example.com"}}]}),
            ApiVersion::Responses => json!({"output": [
                {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": name, "arguments": args}]}),
            ApiVersion::GoogleGemini => json!({"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": name, "args": {"url": "https://example.com"}}}]}}]}),
        };
        for wire in [ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages, ApiVersion::Responses, ApiVersion::GoogleGemini] {
            let policy = |name: &str, withheld: &[crate::proxy::content::BlockedToolInfo]| {
                let mut response = answer(wire, name);
                let (names, infos, _) =
                    apply_response_policy_json(&mut response, wire, &[], &default_test_profiles(), None, None, withheld);
                (response, names, infos)
            };
            let (response, names, infos) = policy("WebFetch", &withheld);
            assert_eq!(names, ["WebFetch"], "{wire:?}");
            assert_eq!(infos[0].rule_id, "R-FETCH", "{wire:?}");
            assert!(!response.to_string().contains(r#""name":"WebFetch""#), "{wire:?}: {response}");
            for (name, withheld) in [("WebFetch", &[][..]), ("Read", &withheld[..])] {
                let (response, names, _) = policy(name, withheld);
                assert!(names.is_empty(), "{wire:?} {name}");
                assert_eq!(response, answer(wire, name), "{wire:?} {name}");
            }
        }
    }

    #[test]
    fn non_tool_events_pass_through_when_only_tool_buffering() {
        let mut acc = make_tool_accumulator(vec![]);

        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta("hello ".into()), None));
        output.extend(acc.process(DomainEvent::TextDelta("world".into()), None));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        assert_eq!(output.len(), 3);
        assert_matches!(
            &output[0].domain_event,
            Some(DomainEvent::TextDelta(t)) if t == "hello "
        );
    }

    #[test]
    fn multiple_tool_calls_each_checked_independently() {
        let rules = rules_from_json(vec![json!({
            "id": "T-5378",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "shell_exec" },
                { "target": "any_arg", "op": "contains_any", "value": ["rm -rf"] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = make_tool_accumulator(rules);

        let mut output = vec![];
        // First tool call — safe
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Bash".into()),
                arguments_delta: r#"{"command": "ls -la"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        // Second tool call — dangerous (flushes first)
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 1,
                id: Some("call_2".into()),
                function_name: Some("Bash".into()),
                arguments_delta: r#"{"command": "rm -rf /"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        // Done flushes the second tool call
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        let tool_events: Vec<_> = output
            .iter()
            .filter(|e| matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { .. })))
            .collect();
        assert_eq!(tool_events.len(), 1); // Only the safe one
        assert_eq!(acc.stats.tool_blocks_checked, 2);
        assert_eq!(acc.stats.tool_blocks_blocked, 1);
    }

    #[test]
    fn text_buffering_replays_original_events() {
        let interests = BlockInterests {
            buffer_tool_blocks: false,
            buffer_text_blocks: true,
            buffer_thinking_blocks: false,
        };
        let mut acc = BlockAccumulator::new(interests, vec![], Default::default(), vec![], None, None, false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions);

        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta("Hello ".into()), None));
        output.extend(acc.process(DomainEvent::TextDelta("world".into()), None));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // 2 text deltas replayed + done
        assert_eq!(output.len(), 3);
        assert_matches!(
            &output[0].domain_event,
            Some(DomainEvent::TextDelta(t)) if t == "Hello "
        );
        assert_matches!(
            &output[1].domain_event,
            Some(DomainEvent::TextDelta(t)) if t == "world"
        );
    }

    // ── Streaming JSON healing ──

    fn make_healing_accumulator(
        heal_structured_text: bool,
        heal_tool_args: bool,
    ) -> BlockAccumulator {
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: true,
            buffer_thinking_blocks: false,
        };
        BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            vec![],
            heal_structured_text,
            heal_tool_args,
            crate::api::sse::ApiVersion::ChatCompletions,
        )
    }

    fn done_event() -> DomainEvent {
        DomainEvent::Done {
            finish_reason: None,
            native_finish_reason: None,
        }
    }

    fn healed(acc: &BlockAccumulator) -> bool {
        acc.badges
            .clone()
            .finish()
            .iter()
            .any(|b| matches!(b, crate::audit::AuditBadge::JsonHealed))
    }

    #[test]
    fn streaming_heals_structured_output_text() {
        let mut acc = make_healing_accumulator(true, false);
        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta(r#"{"a": 1,"#.into()), None));
        output.extend(acc.process(DomainEvent::TextDelta("}".into()), None));
        output.extend(acc.process(done_event(), None));

        let text: Vec<&str> = output
            .iter()
            .filter_map(|e| match &e.domain_event {
                Some(DomainEvent::TextDelta(t)) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        // Healed text re-emitted as a single delta.
        assert_eq!(text.len(), 1);
        assert!(serde_json::from_str::<serde_json::Value>(text[0]).is_ok());
        assert!(healed(&acc));
    }

    #[test]
    fn streaming_skips_text_healing_when_disabled() {
        let mut acc = make_healing_accumulator(false, false);
        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta(r#"{"a": 1,"#.into()), None));
        output.extend(acc.process(DomainEvent::TextDelta("}".into()), None));
        output.extend(acc.process(done_event(), None));

        let text: Vec<&str> = output
            .iter()
            .filter_map(|e| match &e.domain_event {
                Some(DomainEvent::TextDelta(t)) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        // Original deltas replayed verbatim — malformed JSON untouched.
        assert_eq!(text, vec![r#"{"a": 1,"#, "}"]);
        assert!(!healed(&acc));
    }

    #[test]
    fn streaming_heals_tool_call_arguments() {
        let mut acc = make_healing_accumulator(false, true);
        let mut output = vec![];
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Bash".into()),
                arguments_delta: r#"{"command": "ls","#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(done_event(), None));

        let args: Vec<&str> = output
            .iter()
            .filter_map(|e| match &e.domain_event {
                Some(DomainEvent::ToolCallDelta { arguments_delta, .. }) => {
                    Some(arguments_delta.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(args.len(), 1);
        assert!(serde_json::from_str::<serde_json::Value>(args[0]).is_ok());
        assert!(healed(&acc));
    }

    #[test]
    fn streaming_skips_tool_healing_when_disabled() {
        let mut acc = make_healing_accumulator(false, false);
        let mut output = vec![];
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Bash".into()),
                arguments_delta: r#"{"command": "ls","#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(done_event(), None));

        let args: Vec<&str> = output
            .iter()
            .filter_map(|e| match &e.domain_event {
                Some(DomainEvent::ToolCallDelta { arguments_delta, .. }) => {
                    Some(arguments_delta.as_str())
                }
                _ => None,
            })
            .collect();
        // Malformed args replayed unchanged.
        assert_eq!(args, vec![r#"{"command": "ls","#]);
        assert!(!healed(&acc));
    }

    #[test]
    fn flush_at_stream_end() {
        let mut acc = make_tool_accumulator(vec![]);

        // Start a tool block without any terminal event
        acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Read".into()),
                arguments_delta: r#"{"path":"/"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        );

        // Manual flush at stream end
        let flushed = acc.flush();
        assert_eq!(flushed.len(), 1);
        assert_matches!(
            &flushed[0].domain_event,
            Some(DomainEvent::ToolCallDelta { .. })
        );
    }

    // ── Non-streaming policy ──

    /// A non-streaming answer meets the same patch reading as a stream: a
    /// shell call that only applies a patch is blocked by a path rule on the
    /// patch tool; the same command applying no patch is not.
    #[test]
    fn a_non_streaming_shell_patch_meets_the_patch_tools_block() {
        use crate::config::tool_rules::{FieldProfile, FieldProfileSet};
        use crate::config::tool_rules_normalize::Normalizer;
        let profile = |tool_id: &str, pattern: &str, field: &str, wire: Option<&str>, normalizer| FieldProfile {
            id: None,
            description: None,
            source: None,
            tool_id: tool_id.into(),
            tool_pattern: pattern.into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: field.into(),
            wire_field: wire.map(str::to_string),
            normalizer,
            priority: 100,
            is_builtin: false,
        };
        let set = FieldProfileSet::new(vec![
            profile("shell_exec", "shell", "command", None, Normalizer::Shell),
            profile("edit_file", "apply_patch", "path", Some("input"), Normalizer::Patch),
        ]);
        let rules = rules_from_json(vec![json!({
            "id": "block-workflows", "phase": "response", "scope": "tool_calls", "risk": "danger",
            "match": [{"target": "tool_id", "op": "equals", "value": "edit_file"},
                      {"target": "arg.path", "op": "glob", "value": ".github/workflows/*"}],
            "action": {"kind": "block"}
        })]);
        let decide = |command: serde_json::Value| {
            let args = json!({ "command": command });
            evaluate_response_tool_call_policy(&rules, &[], &set, None, None, "shell", &args.to_string(), Some(&args))
        };
        let patch = "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+x\n*** End Patch";
        assert!(matches!(
            decide(json!(["apply_patch", patch])),
            ToolCallPolicy::Block { rule_id: id, .. } if id == "block-workflows"
        ));
        assert!(matches!(decide(json!(["cat", ".github/workflows/ci.yml"])), ToolCallPolicy::Allow));
    }

    #[test]
    fn non_streaming_chat_completions_blocks_tool_calls() {
        use crate::api::sse::ApiVersion;
        let rules = rules_from_json(vec![json!({
            "id": "T-5680",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);

        let mut response = json!({
            "choices": [{
                "message": {
                    "content": "Let me read that file.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "Read",
                                "arguments": "{\"file_path\":\"/etc/shadow\"}"
                            }
                        },
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "Read",
                                "arguments": "{\"file_path\":\"/home/user/readme.md\"}"
                            }
                        }
                    ]
                }
            }]
        });

        let (blocked_names, _blocked_infos, _arg_mods) =
            apply_response_policy_json(&mut response, ApiVersion::ChatCompletions, &rules, &default_test_profiles(), None, None, &[]);

        let tool_calls = response["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap();
        assert_eq!(tool_calls.len(), 1); // Only safe call remains
        assert_eq!(
            tool_calls[0]["function"]["name"].as_str().unwrap(),
            "Read"
        );
        assert!(tool_calls[0]["function"]["arguments"]
            .as_str()
            .unwrap()
            .contains("readme.md"));
        assert_eq!(blocked_names.len(), 1);
        assert_eq!(blocked_names[0], "Read");
    }

    /// The blocked-call notice is appended to a chunk-array `content`, so the
    /// model's text and reasoning chunks stay beside it.
    #[test]
    fn a_blocked_call_notice_keeps_the_chunks_it_joins() {
        use crate::api::sse::ApiVersion;
        let rules = rules_from_json(vec![json!({
            "id": "T-5741",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut response = json!({
            "choices": [{
                "message": {
                    "content": [
                        {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]},
                        {"type": "text", "text": "Let me read that file."}
                    ],
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/shadow\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let (blocked_names, _, _) =
            apply_response_policy_json(&mut response, ApiVersion::ChatCompletions, &rules, &default_test_profiles(), None, None, &[]);
        assert_eq!(blocked_names.len(), 1);
        let message = &response["choices"][0]["message"];
        assert_eq!(crate::api::chat::message_reasoning(message).as_deref(), Some("why"));
        let text = crate::api::chat::content_text(message.get("content")).unwrap();
        assert!(text.starts_with("Let me read that file.\n"), "{text}");
        assert!(text.len() > "Let me read that file.\n".len(), "the notice was appended: {text}");
    }

    // ── Response script execution ──

    #[test]
    fn text_script_modifies_content() {
        let engine = Arc::new(ScriptEngine::new());
        let programs = vec![make_response_program_with_source(
            "redact",
            "text",
            r#"fn transform(ctx) { ctx.content = "[FILTERED] " + ctx.content; ctx }"#,
        )];
        let meta = make_block_meta();
        let interests = BlockInterests {
            buffer_tool_blocks: false,
            buffer_text_blocks: true,
            buffer_thinking_blocks: false,
        };
        let mut acc =
            BlockAccumulator::new(interests, vec![], Default::default(), programs, Some(engine), Some(meta), false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions);

        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta("this is secret data".into()), None));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // Should have rebuilt events: 1 TextDelta + 1 Done
        assert_eq!(output.len(), 2);
        if let Some(DomainEvent::TextDelta(text)) = &output[0].domain_event {
            assert!(text.starts_with("[FILTERED] "));
            assert!(text.contains("secret data"));
        } else {
            panic!("expected TextDelta, got {:?}", output[0].domain_event);
        }
        assert!(acc.stats.scripts_applied > 0);
    }

    #[test]
    fn text_scope_script_does_not_run_on_tool_blocks() {
        let engine = Arc::new(ScriptEngine::new());
        let programs = vec![make_response_program_with_source(
            "text_only",
            "text",
            r#"fn transform(ctx) { ctx.labels.push("text_ran"); ctx }"#,
        )];
        let meta = make_block_meta();
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: true,
            buffer_thinking_blocks: false,
        };
        let mut acc =
            BlockAccumulator::new(interests, vec![], Default::default(), programs, Some(engine), Some(meta), false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions);

        let mut output = vec![];
        // Emit a tool block
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Bash".into()),
                arguments_delta: r#"{"cmd":"ls"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // Text-scope script should not have run on the tool block — no
        // program outcomes recorded for that scope.
        assert!(
            acc.program_outcomes.iter().all(|o| o.name != "text_only"),
            "text-scope script should not run on tool blocks"
        );
    }

    #[test]
    fn tool_scope_script_modifies_arguments() {
        let engine = Arc::new(ScriptEngine::new());
        let programs = vec![make_response_program_with_source(
            "sanitize_args",
            "tool",
            r#"fn transform(ctx) { ctx.arguments = "{\"path\":\"/safe/file\"}"; ctx }"#,
        )];
        let meta = make_block_meta();
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        let mut acc =
            BlockAccumulator::new(interests, vec![], Default::default(), programs, Some(engine), Some(meta), false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions);

        let mut output = vec![];
        output.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".into()),
                function_name: Some("Read".into()),
                arguments_delta: r#"{"path":"/etc/passwd"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // Tool call should have been rebuilt with sanitized arguments
        let tool_events: Vec<_> = output
            .iter()
            .filter(|e| matches!(&e.domain_event, Some(DomainEvent::ToolCallDelta { .. })))
            .collect();
        assert_eq!(tool_events.len(), 1);
        if let Some(DomainEvent::ToolCallDelta {
            arguments_delta, ..
        }) = &tool_events[0].domain_event
        {
            assert!(arguments_delta.contains("/safe/"));
            assert!(!arguments_delta.contains("/etc/"));
        }
    }

    #[test]
    fn global_scope_script_runs_on_all_block_types() {
        let engine = Arc::new(ScriptEngine::new());
        let programs = vec![make_response_program_with_source(
            "global_tag",
            "global",
            r#"fn transform(ctx) { ctx.labels.push("global_ran"); ctx }"#,
        )];
        let meta = make_block_meta();
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: true,
            buffer_thinking_blocks: true,
        };
        let mut acc = BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            programs,
            Some(engine),
            Some(meta),
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        );

        // Text block
        acc.process(DomainEvent::TextDelta("hello".into()), None);
        // New tool block (flushes text)
        acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("c1".into()),
                function_name: Some("X".into()),
                arguments_delta: "{}".into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        );
        // Thinking block (flushes tool)
        acc.process(DomainEvent::ReasoningDelta("think".into()), None);
        // Flush all
        acc.flush();

        let global_runs = acc
            .program_outcomes
            .iter()
            .filter(|o| o.name == "global_tag")
            .count();
        assert_eq!(
            global_runs,
            3,
            "global scope should run on all 3 block types"
        );
    }

    #[test]
    fn no_scripts_returns_original_events() {
        let engine = Arc::new(ScriptEngine::new());
        let meta = make_block_meta();
        let interests = BlockInterests {
            buffer_tool_blocks: false,
            buffer_text_blocks: true,
            buffer_thinking_blocks: false,
        };
        // No programs
        let mut acc =
            BlockAccumulator::new(interests, vec![], Default::default(), vec![], Some(engine), Some(meta), false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions);

        let mut output = vec![];
        output.extend(acc.process(DomainEvent::TextDelta("Hello ".into()), None));
        output.extend(acc.process(DomainEvent::TextDelta("world".into()), None));
        output.extend(acc.process(
            DomainEvent::Done {
                finish_reason: None,
                native_finish_reason: None,
            },
            None,
        ));

        // Original events replayed
        assert_eq!(output.len(), 3);
        assert_eq!(acc.stats.scripts_applied, 0);
    }

    // ── Helpers ──

    fn make_response_program_with_source(
        name: &str,
        scope: &str,
        source: &str,
    ) -> TransformProgram {
        TransformProgram {
            id: name.to_string(),
            name: name.to_string(),
            source: source.to_string(),
            phase: "response".to_string(),
            scope: scope.to_string(),
            priority: 100,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    fn make_block_meta() -> BlockRequestMeta {
        BlockRequestMeta {
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            model_alias: Some("gpt-4o".to_string()),
            signed_thinking_reaches_client: false,
        }
    }

    fn make_response_program(name: &str, scope: &str) -> TransformProgram {
        TransformProgram {
            id: name.to_string(),
            name: name.to_string(),
            source: "fn transform(ctx) { ctx }".to_string(),
            phase: "response".to_string(),
            scope: scope.to_string(),
            priority: 100,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    fn rule_from_json(v: serde_json::Value) -> crate::config::tool_rules::Rule {
        serde_json::from_value(v).expect("rule JSON must deserialize")
    }

    fn rules_from_json(items: Vec<serde_json::Value>) -> Vec<crate::config::tool_rules::Rule> {
        items.into_iter().map(rule_from_json).collect()
    }

    fn make_tool_accumulator(rules: Vec<crate::config::tool_rules::Rule>) -> BlockAccumulator {
        make_tool_accumulator_with_profiles(rules, default_test_profiles())
    }

    fn make_tool_accumulator_with_profiles(
        rules: Vec<crate::config::tool_rules::Rule>,
        profiles: crate::config::tool_rules::FieldProfileSet,
    ) -> BlockAccumulator {
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        BlockAccumulator::new(interests, rules, Arc::new(profiles), vec![], None, None, false, ScriptFailMode::Open, vec![], false, false, crate::api::sse::ApiVersion::ChatCompletions)
    }

    /// Test fixture: profiles that map the tools used by `response_blocks`
    /// tests to canonical Stage C `tool_id`s. Avoids each test having to
    /// hand-roll the same registry.
    fn default_test_profiles() -> crate::config::tool_rules::FieldProfileSet {
        use crate::config::tool_rules::FieldProfile;
        use crate::config::tool_rules_normalize::Normalizer;
        crate::config::tool_rules::FieldProfileSet::new(vec![
            FieldProfile {
                id: Some("test-Read".into()),
                description: None,
                source: None,
                tool_id: "read_file".into(),
                tool_pattern: "Read".into(),
                app_filter: None,
                mcp_server: None,
                server_type: None,
                field: "file_path".into(),
                wire_field: None,
                normalizer: Normalizer::Raw,
                priority: 100,
                is_builtin: false,
            },
            FieldProfile {
                id: Some("test-Bash".into()),
                description: None,
                source: None,
                tool_id: "shell_exec".into(),
                tool_pattern: "Bash".into(),
                app_filter: None,
                mcp_server: None,
                server_type: None,
                field: "command".into(),
                wire_field: None,
                normalizer: Normalizer::Raw,
                priority: 100,
                is_builtin: false,
            },
            // A custom (freeform) tool: its free text is its one field.
            FieldProfile {
                id: Some("test-apply_patch".into()),
                description: None,
                source: None,
                tool_id: "apply_patch".into(),
                tool_pattern: "apply_patch".into(),
                app_filter: None,
                mcp_server: None,
                server_type: None,
                field: "input".into(),
                wire_field: None,
                normalizer: Normalizer::Raw,
                priority: 100,
                is_builtin: false,
            },
        ])
    }

    /// Block any `apply_patch` call deleting a file.
    fn block_patch_deletes() -> Vec<crate::config::tool_rules::Rule> {
        rules_from_json(vec![json!({
            "id": "T-6133",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "apply_patch" },
                { "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })])
    }

    /// A Responses upstream's custom (freeform) tool call is a tool call: the
    /// same block and rewrite rules reach it, reading its free text as the
    /// field `input`, and an allowed one is left as it came.
    #[test]
    fn a_responses_custom_tool_call_meets_the_same_policy_as_a_function_call() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "id": "resp_1",
            "status": "completed",
            "output": [
                {"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_1", "name": "apply_patch", "input": "*** Delete File: a.txt"},
                {"type": "custom_tool_call", "id": "ctc_2", "call_id": "call_2", "name": "apply_patch", "input": "*** Update File: b.txt"}
            ]
        });
        let (blocked, infos, _) = apply_response_policy_json(
            &mut response, ApiVersion::Responses, &block_patch_deletes(), &default_test_profiles(), None, None,
            &[],
        );
        assert_eq!(blocked, ["apply_patch"]);
        assert_eq!(infos[0].tool_use_id.as_deref(), Some("call_1"));
        let output = response["output"].as_array().unwrap();
        assert_eq!(output[0]["call_id"], "call_2", "the allowed call is left as it came: {output:?}");
        assert_eq!(output[0]["input"], "*** Update File: b.txt");
        assert!(output[1]["content"][0]["text"].as_str().unwrap().contains("blocked by policy"));

        let rewrite = rules_from_json(vec![json!({
            "id": "T-6170",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "with": "*** Begin Patch" },
            "risk": "danger"
        })]);
        let mut response = json!({"output": [
            {"type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": "*** Delete File: a.txt"}
        ]});
        apply_response_policy_json(&mut response, ApiVersion::Responses, &rewrite, &default_test_profiles(), None, None, &[]);
        let call = &response["output"][0];
        assert_eq!(call["type"], "custom_tool_call");
        assert_eq!(call["input"], "*** Begin Patch", "{call}");
        assert!(call.get("arguments").is_none());
    }

    /// A Responses stream carrying one custom (freeform) tool call.
    fn responses_custom_call_upstream(input: &str) -> Vec<(&'static str, serde_json::Value)> {
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        let (head, tail) = input.split_at(input.len() / 2);
        let item = |status: &str, input: &str| json!({
            "id": "ctc_1", "type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": input, "status": status
        });
        vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": item("in_progress", "")}))),
            ("response.custom_tool_call_input.delta", next(json!({"type": "response.custom_tool_call_input.delta", "item_id": "ctc_1", "output_index": 0, "delta": head}))),
            ("response.custom_tool_call_input.delta", next(json!({"type": "response.custom_tool_call_input.delta", "item_id": "ctc_1", "output_index": 0, "delta": tail}))),
            ("response.custom_tool_call_input.done", next(json!({"type": "response.custom_tool_call_input.done", "item_id": "ctc_1", "output_index": 0, "input": input}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": item("completed", input)}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed",
                "output": [item("completed", input)], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}}))),
        ]
    }

    #[test]
    fn a_streamed_custom_tool_call_is_blocked_like_a_function_call() {
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let frames = client_frames(
            crate::api::sse::ApiVersion::Responses,
            &responses_custom_call_upstream("*** Delete File: a.txt"),
            &mut acc,
        );
        assert!(
            !frames.iter().any(|(_, d)| d["item"]["type"] == "custom_tool_call"
                || d["type"] == "response.custom_tool_call_input.delta"
                || d["type"] == "response.custom_tool_call_input.done"),
            "a blocked call reached the client: {frames:?}"
        );
        assert!(frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("blocked by policy"))));
        let completed = &frames.last().unwrap().1;
        assert!(
            completed["response"]["output"].as_array().unwrap().iter().all(|i| i["type"] != "custom_tool_call"),
            "{completed}"
        );
    }

    #[test]
    fn an_allowed_streamed_custom_tool_call_reaches_the_client_as_sent() {
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let upstream = responses_custom_call_upstream("*** Update File: b.txt");
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let sent: Vec<_> = upstream.iter().map(|(_, d)| d.clone()).collect();
        let got: Vec<_> = frames.iter().map(|(_, d)| d.clone()).collect();
        assert_eq!(got, sent);
    }

    /// A Chat Completions stream carrying one custom (freeform) tool call. The
    /// spec's chunk has only the function form; a server streaming a custom
    /// call sends its message form — `type: "custom"`, `custom: {name, input}` —
    /// with the input in pieces.
    fn chat_custom_call_upstream(input: &str) -> Vec<(&'static str, serde_json::Value)> {
        let chunk = |delta: serde_json::Value, finish: serde_json::Value| json!({
            "id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        });
        let (head, tail) = input.split_at(input.len() / 2);
        vec![
            ("", chunk(json!({"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "custom",
                "custom": {"name": "apply_patch", "input": ""}}]}), serde_json::Value::Null)),
            ("", chunk(json!({"tool_calls": [{"index": 0, "custom": {"input": head}}]}), serde_json::Value::Null)),
            ("", chunk(json!({"tool_calls": [{"index": 0, "custom": {"input": tail}}]}), serde_json::Value::Null)),
            ("", chunk(json!({}), json!("tool_calls"))),
        ]
    }

    /// A Chat Completions upstream's custom tool call — declared to it when a
    /// Chat client declares one — is a tool call: a block rule reaches it,
    /// streamed and not, reading its free text as the field `input`.
    #[test]
    fn a_chat_custom_tool_call_meets_the_same_policy_as_a_function_call() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": null, "tool_calls": [
                {"id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Delete File: a.txt"}},
                {"id": "call_2", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Update File: b.txt"}}
            ]}}]});
        let (blocked, infos, _) = apply_response_policy_json(
            &mut response, ApiVersion::ChatCompletions, &block_patch_deletes(), &default_test_profiles(), None, None,
            &[],
        );
        assert_eq!(blocked, ["apply_patch"]);
        assert_eq!(infos[0].tool_use_id.as_deref(), Some("call_1"));
        let calls = response["choices"][0]["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["custom"]["input"], "*** Update File: b.txt");

        let rewrite = rules_from_json(vec![json!({
            "id": "T-6283",
            "phase": "response", "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "with": "*** Begin Patch" }, "risk": "danger"
        })]);
        let mut response = json!({"choices": [{"index": 0, "message": {"role": "assistant", "tool_calls": [
            {"id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Delete File: a.txt"}}
        ]}}]});
        apply_response_policy_json(&mut response, ApiVersion::ChatCompletions, &rewrite, &default_test_profiles(), None, None, &[]);
        let call = &response["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["custom"]["input"], "*** Begin Patch", "{call}");
        assert!(call.get("function").is_none());
    }

    #[test]
    fn a_streamed_chat_custom_tool_call_is_blocked_like_a_function_call() {
        let mut acc = text_accumulator(block_patch_deletes());
        let frames = client_frames(
            crate::api::sse::ApiVersion::ChatCompletions,
            &chat_custom_call_upstream("*** Delete File: a.txt"),
            &mut acc,
        );
        assert!(
            !frames.iter().any(|(_, d)| d["choices"][0]["delta"]["tool_calls"].is_array()),
            "a blocked call reached the client: {frames:?}"
        );
        assert!(frames.iter().any(|(_, d)| d["choices"][0]["delta"]["content"]
            .as_str()
            .is_some_and(|t| t.contains("blocked by policy"))));
    }

    #[test]
    fn an_allowed_streamed_chat_custom_tool_call_reaches_the_client_as_sent() {
        let mut acc = text_accumulator(block_patch_deletes());
        let upstream = chat_custom_call_upstream("*** Update File: b.txt");
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let sent: Vec<_> = upstream.iter().map(|(_, d)| d.clone()).collect();
        let got: Vec<_> = frames.iter().map(|(_, d)| d.clone()).collect();
        assert_eq!(got, sent);
    }

    #[test]
    fn a_rewritten_streamed_chat_custom_tool_call_stays_a_custom_call() {
        let rewrite = rules_from_json(vec![json!({
            "id": "T-6326",
            "phase": "response", "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "with": "*** Begin Patch" }, "risk": "danger"
        })]);
        let mut acc = text_accumulator(rewrite);
        let frames = client_frames(
            crate::api::sse::ApiVersion::ChatCompletions,
            &chat_custom_call_upstream("*** Delete File: a.txt"),
            &mut acc,
        );
        let calls: Vec<_> = frames
            .iter()
            .flat_map(|(_, d)| d["choices"][0]["delta"]["tool_calls"].as_array().cloned().unwrap_or_default())
            .collect();
        assert!(calls.iter().all(|c| c.get("function").is_none()), "{calls:?}");
        let input: String = calls.iter().filter_map(|c| c["custom"]["input"].as_str()).collect();
        assert_eq!(input, "*** Begin Patch", "{calls:?}");
        assert!(calls.iter().any(|c| c["custom"]["name"] == "apply_patch" && c["id"] == "call_1"), "{calls:?}");
    }

    /// A server may repeat a Chat call's name on every delta, or send the name
    /// first and the id later. Either is one call: its text is read whole, not
    /// reopened at every delta that names it.
    #[test]
    fn a_chat_custom_call_restated_on_every_delta_is_one_call() {
        let chunk = |tc: serde_json::Value, finish: serde_json::Value| ("", json!({
            "id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": finish}]
        }));
        let finish = ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64,
            "model": "gpt-x", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}));
        let restated = vec![
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Del"}}), serde_json::Value::Null),
            chunk(json!({"index": 0, "type": "custom", "custom": {"name": "apply_patch", "input": "ete File: a"}}), serde_json::Value::Null),
            finish.clone(),
        ];
        let name_then_id = vec![
            chunk(json!({"index": 0, "type": "custom", "custom": {"name": "apply_patch", "input": "*** Del"}}), serde_json::Value::Null),
            chunk(json!({"index": 0, "id": "call_1", "custom": {"input": "ete File: a"}}), serde_json::Value::Null),
            finish,
        ];
        for upstream in [restated, name_then_id] {
            let mut acc = text_accumulator(block_patch_deletes());
            let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
            assert!(
                !frames.iter().any(|(_, d)| d["choices"][0]["delta"]["tool_calls"].is_array()),
                "a blocked call reached the client: {frames:?}"
            );
        }
    }

    /// A Responses server may stream no input deltas and state the call's text
    /// only on `output_item.done` — its final word on the item. That text is
    /// the call's, and policy reads it.
    #[test]
    fn a_custom_call_whose_text_comes_only_with_its_done_item_is_read() {
        let upstream: Vec<_> = responses_custom_call_upstream("*** Delete File: a.txt")
            .into_iter()
            .filter(|(n, _)| !n.starts_with("response.custom_tool_call_input"))
            .collect();
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "custom_tool_call"), "{frames:?}");
        // Deltas that stopped short are completed from the done item.
        let short: Vec<_> = responses_custom_call_upstream("*** Delete File: a.txt")
            .into_iter()
            .enumerate()
            .filter(|(i, (n, _))| !(*n == "response.custom_tool_call_input.delta" && *i == 3)
                && *n != "response.custom_tool_call_input.done")
            .map(|(_, f)| f)
            .collect();
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &short, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "custom_tool_call"), "{frames:?}");
    }

    /// A Responses stream's custom call closes its input with
    /// `custom_tool_call_input.done`, but an upstream that ends the item with
    /// `output_item.done` alone — or whose stream is cut before either — has
    /// still said all there is: its text is read whole, once.
    #[test]
    fn a_custom_call_the_upstream_never_closes_is_read_whole() {
        let without = |kind: &str| {
            responses_custom_call_upstream("*** Delete File: a.txt")
                .into_iter()
                .filter(|(n, _)| *n != kind)
                .collect::<Vec<_>>()
        };
        // Ended by `output_item.done` alone.
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses,
            &without("response.custom_tool_call_input.done"), &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "custom_tool_call"), "{frames:?}");
        // Cut before either done event, and before the response completed.
        let cut: Vec<_> = responses_custom_call_upstream("*** Delete File: a.txt")
            .into_iter()
            .take_while(|(n, _)| *n != "response.custom_tool_call_input.done")
            .collect();
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, block_patch_deletes());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &cut, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "custom_tool_call"
            || d["type"] == "response.custom_tool_call_input.delta"), "{frames:?}");
        // Closed by both: the arguments are closed once, and the rewrite reads them.
        let rewrite = rules_from_json(vec![json!({
            "id": "T-6430",
            "phase": "response", "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "with": "*** Begin Patch" }, "risk": "danger"
        })]);
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, rewrite);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses,
            &responses_custom_call_upstream("*** Delete File: a.txt"), &mut acc);
        let done = frames.iter().find(|(_, d)| d["type"] == "response.output_item.done").expect("{frames:?}");
        assert_eq!(done.1["item"]["input"], "*** Begin Patch");
    }

    /// A Chat client that declared a custom tool is handed a Responses
    /// upstream's streamed call to it in the Chat custom form it reads —
    /// `custom: {name, input}` deltas, the input in pieces — never as a
    /// function call it did not declare.
    #[test]
    fn a_streamed_custom_tool_call_reaches_a_chat_client_as_its_custom_call() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::Responses;
        let facts = crate::api::domain_request::ClientToolFacts {
            freeform: ["apply_patch".to_string()].into(),
            ..Default::default()
        };
        let mut emitter = EventEmitter::new(crate::api::sse::ApiVersion::ChatCompletions, upstream, "m", "req-1", None, None, 0, 0)
            .with_client_tools(&facts);
        let mut body = String::new();
        let input = "*** Begin \"Patch\"\n+ line";
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        for (name, data) in responses_custom_call_upstream(input) {
            let event = SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                for chunk in emitter.process_streaming_event(&de, Some(&event)) {
                    body.push_str(std::str::from_utf8(&chunk).unwrap());
                }
            }
        }
        for chunk in emitter.flush() {
            body.push_str(std::str::from_utf8(&chunk).unwrap());
        }
        let (mut name, mut text, mut finish, mut functions) = (String::new(), String::new(), None, 0);
        for line in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let choice = &v["choices"][0];
            if let Some(f) = choice["finish_reason"].as_str() {
                finish = Some(f.to_string());
            }
            for tc in choice["delta"]["tool_calls"].as_array().into_iter().flatten() {
                functions += usize::from(tc.get("function").is_some());
                name.push_str(tc["custom"]["name"].as_str().unwrap_or_default());
                text.push_str(tc["custom"]["input"].as_str().unwrap_or_default());
            }
        }
        assert_eq!(functions, 0, "{body}");
        assert_eq!((name.as_str(), text.as_str()), ("apply_patch", input), "{body}");
        assert_eq!(finish.as_deref(), Some("tool_calls"));
    }

    /// A Responses upstream numbers every call 0. Translated to a client that
    /// addresses calls by index, each call gets its own — 0, 1, … in the order
    /// they open — or the client's SDK merges them into one.
    #[test]
    fn calls_a_responses_upstream_numbers_alike_reach_other_clients_apart() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::Responses;
        let item = |id: &str, kind: &str, name: &str| json!({"id": id, "type": kind, "call_id": format!("call_{id}"), "name": name, "status": "in_progress"});
        let frames = vec![
            ("response.created", json!({"type": "response.created", "response": {"id": "r", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "output_index": 0, "item": item("a", "function_call", "read")})),
            ("response.function_call_arguments.delta", json!({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "a", "delta": "{\"p\":1}"})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "output_index": 1, "item": item("b", "function_call", "grep")})),
            ("response.function_call_arguments.delta", json!({"type": "response.function_call_arguments.delta", "output_index": 1, "item_id": "b", "delta": "{\"q\":2}"})),
            ("response.completed", json!({"type": "response.completed", "response": {"id": "r", "status": "completed", "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}})),
        ];
        let run = |client: crate::api::sse::ApiVersion| {
            let mut emitter = EventEmitter::new(client, upstream, "m", "req-1", None, None, 0, 0);
            let mut state = crate::pipeline::response::TransformState::new(client);
            let mut parser = crate::api::sse::StreamParser::new(upstream);
            let mut body = String::new();
            for (name, data) in &frames {
                let event = SseEvent { event_type: Some((*name).to_string()), data: data.to_string(), id: None };
                for de in parser.parse(&event) {
                    state.process_event(&de);
                    for chunk in emitter.process_streaming_event(&de, Some(&event)) {
                        body.push_str(std::str::from_utf8(&chunk).unwrap());
                    }
                }
            }
            for chunk in emitter.flush() {
                body.push_str(std::str::from_utf8(&chunk).unwrap());
            }
            (body, state)
        };
        // Chat: two calls at two indexes, each whole.
        let (body, state) = run(crate::api::sse::ApiVersion::ChatCompletions);
        let mut calls: std::collections::BTreeMap<u64, (String, String)> = Default::default();
        for line in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            for tc in v["choices"][0]["delta"]["tool_calls"].as_array().into_iter().flatten() {
                let call = calls.entry(tc["index"].as_u64().unwrap()).or_default();
                call.0.push_str(tc["function"]["name"].as_str().unwrap_or_default());
                call.1.push_str(tc["function"]["arguments"].as_str().unwrap_or_default());
            }
        }
        assert_eq!(calls.len(), 2, "{body}");
        assert_eq!(calls[&0], ("read".to_string(), "{\"p\":1}".to_string()));
        assert_eq!(calls[&1], ("grep".to_string(), "{\"q\":2}".to_string()));
        // The audit records two calls, not one merged.
        let recorded: Vec<_> = state.accumulated_tool_calls.iter().map(|c| (c.function_name.as_str(), c.arguments.as_str())).collect();
        assert_eq!(recorded, [("read", "{\"p\":1}"), ("grep", "{\"q\":2}")]);
        // Gemini: one whole `functionCall` part per call.
        let (body, _) = run(crate::api::sse::ApiVersion::GoogleGemini);
        let names: Vec<String> = body.lines().filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .flat_map(|v| v["candidates"][0]["content"]["parts"].as_array().cloned().unwrap_or_default())
            .filter_map(|p| p["functionCall"]["name"].as_str().map(String::from))
            .collect();
        assert_eq!(names, ["read", "grep"], "{body}");
    }

    /// Anthropic addresses its content blocks by its own index, and a call is
    /// one block however the upstream restates it: a Chat server repeating the
    /// name on every delta does not open a block per delta.
    #[test]
    fn a_restated_call_reaches_an_anthropic_client_as_one_block() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value, finish: serde_json::Value| json!({
            "id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": finish}]
        });
        let frames = [
            chunk(json!({"index": 0, "id": "call_1", "type": "function", "function": {"name": "read", "arguments": "{\"p\":"}}), serde_json::Value::Null),
            chunk(json!({"index": 0, "type": "function", "function": {"name": "read", "arguments": "1}"}}), serde_json::Value::Null),
            json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
        ];
        let mut emitter = EventEmitter::new(crate::api::sse::ApiVersion::AnthropicMessages, upstream, "m", "req-1", None, None, 0, 0);
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut body = String::new();
        for data in frames {
            let event = SseEvent { event_type: None, data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                for c in emitter.process_streaming_event(&de, Some(&event)) {
                    body.push_str(std::str::from_utf8(&c).unwrap());
                }
            }
        }
        let starts = body.matches("\"type\":\"tool_use\"").count();
        assert_eq!(starts, 1, "{body}");
        let input: String = body.lines().filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["delta"]["partial_json"].as_str().map(String::from)).collect();
        assert_eq!(input, "{\"p\":1}");
    }

    /// Parallel Chat calls may interleave: a custom call at index 0, a
    /// function at index 1, then more of call 0. Call 0's text is one text —
    /// never reopened — and a call read before its end (another started first)
    /// is read as the text it had.
    #[test]
    fn interleaved_parallel_calls_keep_each_custom_calls_text_whole() {
        let chunk = |tc: serde_json::Value| ("", json!({
            "id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]
        }));
        let finish = ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64,
            "model": "gpt-x", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}));
        let interleaved = vec![
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Delete "}})),
            chunk(json!({"index": 1, "id": "call_2", "type": "function", "function": {"name": "Read", "arguments": "{}"}})),
            chunk(json!({"index": 0, "custom": {"input": "File: a"}})),
            finish.clone(),
        ];
        // The stream parser gives call 0 one text, opened once.
        let mut parser = crate::api::sse::StreamParser::new(crate::api::sse::ApiVersion::ChatCompletions);
        let mut state = crate::pipeline::response::TransformState::new(crate::api::sse::ApiVersion::ChatCompletions);
        for (_, data) in &interleaved {
            let event = SseEvent { event_type: None, data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                state.process_event(&de);
            }
        }
        let first = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&first.arguments).ok(),
                   Some(json!({"input": "*** Delete File: a"})), "{}", first.arguments);
        // Sequential parallel calls: call 0 is read when call 1 starts, before
        // its end — policy reads the text it had.
        let sequential = vec![
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Delete File: a"}})),
            chunk(json!({"index": 1, "id": "call_2", "type": "function", "function": {"name": "Read", "arguments": "{}"}})),
            finish,
        ];
        let mut acc = text_accumulator(block_patch_deletes());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &sequential, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["choices"][0]["delta"]["tool_calls"][0]["custom"].is_object()), "{frames:?}");
    }

    /// A FUNCTION call cut off inside a string (`max_tokens` mid-argument)
    /// stays cut off everywhere: whatever its arguments look like, only a
    /// freeform call is closed by the gateway, so policy, the client and the
    /// audit all read the same truncated arguments.
    #[test]
    fn a_truncated_function_call_is_never_closed_as_if_freeform() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]});
        let frames = [
            chunk(json!({"index": 0, "id": "call_1", "type": "function", "function": {"name": "Bash", "arguments": "{\"input\":\"rm -rf /tmp/fo"}})),
            chunk(json!({"index": 1, "id": "call_2", "type": "function", "function": {"name": "Read", "arguments": "{}"}})),
            json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "length"}]}),
        ];
        let mut acc = text_accumulator(block_patch_deletes());
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut emitter = EventEmitter::new(crate::api::sse::ApiVersion::AnthropicMessages, upstream, "m", "req-1", None, None, 0, 0);
        let mut body = String::new();
        let mut out = Vec::new();
        for data in frames {
            let event = SseEvent { event_type: None, data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                out.extend(acc.process(de, None));
            }
        }
        for end in parser.finish() {
            out.extend(acc.process(end, None));
        }
        out.extend(acc.flush());
        let events: Vec<_> = out.iter().filter_map(|b| b.domain_event.clone()).collect();
        assert!(!events.iter().any(|e| matches!(e, DomainEvent::FreeformCallEnd { .. })), "{events:?}");
        for b in &out {
            for c in emitter.process_buffered(b) {
                body.push_str(std::str::from_utf8(&c).unwrap());
            }
        }
        let input: String = body.lines().filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter(|v| v["index"] == 0)
            .filter_map(|v| v["delta"]["partial_json"].as_str().map(String::from)).collect();
        assert_eq!(input, "{\"input\":\"rm -rf /tmp/fo", "{body}");
    }

    /// A custom call policy rewrote is written whole — its complete
    /// arguments in one delta — and a Chat client that declared the tool reads
    /// it as clean custom-call text.
    #[test]
    fn a_rewritten_custom_call_reaches_a_chat_client_as_clean_text() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::Responses;
        let rewrite = rules_from_json(vec![json!({
            "id": "T-6678",
            "phase": "response", "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "regex": "Delete File", "with": "Begin \\\"Patch\\\" for" }, "risk": "danger"
        })]);
        let mut acc = text_accumulator_for(upstream, rewrite);
        let facts = crate::api::domain_request::ClientToolFacts {
            freeform: ["apply_patch".to_string()].into(),
            ..Default::default()
        };
        let mut emitter = EventEmitter::new(crate::api::sse::ApiVersion::ChatCompletions, upstream, "m", "req-1", None, None, 0, 0)
            .with_client_tools(&facts);
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut body = String::new();
        let mut emit = |out: Vec<BufferedEvent>, body: &mut String| {
            for b in &out {
                for c in emitter.process_buffered(b) {
                    body.push_str(std::str::from_utf8(&c).unwrap());
                }
            }
        };
        for (name, data) in responses_custom_call_upstream("*** Delete File: a.txt") {
            let event = SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                let out = acc.process(de, Some(event.clone()));
                emit(out, &mut body);
            }
        }
        let tail = acc.flush();
        emit(tail, &mut body);
        let text: String = body.lines().filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .flat_map(|v| v["choices"][0]["delta"]["tool_calls"].as_array().cloned().unwrap_or_default())
            .filter_map(|tc| tc["custom"]["input"].as_str().map(String::from)).collect();
        assert_eq!(text, "*** Begin \"Patch\" for: a.txt", "{body}");
    }

    /// A stream read the way the held path reads it: every frame through one
    /// stream parser, each event with its piece of the frame into the audit
    /// state and the accumulator, then the parser's and the accumulator's ends.
    fn read_held(
        upstream: crate::api::sse::ApiVersion,
        frames: &[(&str, serde_json::Value)],
        acc: &mut BlockAccumulator,
    ) -> (Vec<BufferedEvent>, crate::pipeline::response::TransformState) {
        let mut state = crate::pipeline::response::TransformState::new(upstream);
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut out = Vec::new();
        for (name, data) in frames {
            let event = SseEvent { event_type: (!name.is_empty()).then(|| name.to_string()), data: data.to_string(), id: None };
            let events = parser.parse(&event);
            let raws = crate::pipeline::response_pipeline::split_frame(&event, upstream, &events, true);
            for (de, raw) in events.into_iter().zip(raws) {
                state.process_event(&de);
                out.extend(acc.process(de, raw));
            }
        }
        for end in parser.finish() {
            state.process_event(&end);
            out.extend(acc.process(end, None));
        }
        out.extend(acc.flush());
        (out, state)
    }

    /// A stream read with no call held (no response tool policy): every frame
    /// through one stream parser into the audit state, the events going to
    /// the emitter as they are, then the parser's end.
    fn read_unheld(
        upstream: crate::api::sse::ApiVersion,
        frames: &[(&str, serde_json::Value)],
    ) -> (Vec<BufferedEvent>, crate::pipeline::response::TransformState) {
        let mut state = crate::pipeline::response::TransformState::new(upstream);
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut out = Vec::new();
        let events = frames
            .iter()
            .flat_map(|(name, data)| {
                parser.parse(&SseEvent { event_type: (!name.is_empty()).then(|| name.to_string()), data: data.to_string(), id: None })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .chain(parser.finish());
        for de in events {
            state.process_event(&de);
            out.push(BufferedEvent { domain_event: Some(de), raw_sse: None });
        }
        (out, state)
    }

    /// The frames `client` is sent for `out` — a client that declared
    /// `apply_patch` custom — as JSON.
    fn render_held(
        client: crate::api::sse::ApiVersion,
        upstream: crate::api::sse::ApiVersion,
        out: &[BufferedEvent],
    ) -> Vec<serde_json::Value> {
        use crate::pipeline::response_pipeline::EventEmitter;
        let facts = crate::api::domain_request::ClientToolFacts {
            freeform: ["apply_patch".to_string()].into(),
            ..Default::default()
        };
        let mut emitter = EventEmitter::new(client, upstream, "m", "req-1", None, None, 0, 0).with_client_tools(&facts);
        let mut body = String::new();
        for b in out {
            for c in emitter.process_buffered(b) {
                body.push_str(std::str::from_utf8(&c).unwrap());
            }
        }
        for c in emitter.flush() {
            body.push_str(std::str::from_utf8(&c).unwrap());
        }
        body.lines().filter_map(|l| l.strip_prefix("data: ")).filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    /// The input an Anthropic client is given for its first content block.
    fn anthropic_first_input(frames: &[serde_json::Value]) -> String {
        frames.iter().filter(|v| v["index"] == 0).filter_map(|v| v["delta"]["partial_json"].as_str().map(String::from)).collect()
    }

    /// The custom-call text a Chat client is given.
    fn chat_custom_text(frames: &[serde_json::Value]) -> String {
        frames.iter()
            .flat_map(|v| v["choices"][0]["delta"]["tool_calls"].as_array().cloned().unwrap_or_default())
            .filter_map(|tc| tc["custom"]["input"].as_str().map(String::from))
            .collect()
    }

    /// A streamed custom call read before its end — another call started
    /// first — is closed exactly once for everyone: policy closes it when it
    /// reads it, the stream's own end then closes nothing, and the audit, an
    /// Anthropic client and a Chat client that declared the tool all hold the
    /// same whole text.
    #[test]
    fn a_streamed_custom_call_closes_once_for_policy_the_client_and_the_audit() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]}));
        let frames = [
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Add "}})),
            chunk(json!({"index": 0, "custom": {"input": "File: \"a\""}})),
            chunk(json!({"index": 1, "id": "call_2", "type": "function", "function": {"name": "Read", "arguments": "{}"}})),
            ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let text = "*** Add File: \"a\"";
        let whole = crate::api::domain_request::freeform_call_input(text).to_string();
        let mut acc = text_accumulator(block_patch_deletes());
        let (out, state) = read_held(upstream, &frames, &mut acc);
        // The audit: the call as the upstream streamed it, closed once.
        let recorded = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(recorded.arguments, whole);
        // Anthropic: the first block's input is the whole call, once.
        let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &out);
        assert_eq!(anthropic_first_input(&frames), whole, "{frames:?}");
        // Chat, the tool declared custom (the upstream's own chunks): the
        // text, as custom-call input.
        let frames = render_held(crate::api::sse::ApiVersion::ChatCompletions, upstream, &out);
        assert_eq!(chat_custom_text(&frames), text, "{frames:?}");
    }

    /// A usage count is not where a call ends. A server reporting usage on
    /// every chunk (vLLM's continuous usage) must not have a custom call
    /// closed after its first piece: policy would read that piece alone and
    /// let the call through unread, and the rest would be glued after the
    /// close.
    #[test]
    fn usage_on_every_chunk_does_not_end_a_custom_call() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let usage = json!({"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6});
        let chunk = |tc: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}], "usage": usage}));
        let frames = [
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Del"}})),
            chunk(json!({"index": 0, "custom": {"input": "ete File"}})),
            chunk(json!({"index": 0, "custom": {"input": ": a.txt"}})),
            ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}], "usage": usage})),
        ];
        let mut acc = text_accumulator(block_patch_deletes());
        let (out, state) = read_held(upstream, &frames, &mut acc);
        let recorded = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(recorded.arguments, crate::api::domain_request::freeform_call_input("*** Delete File: a.txt").to_string());
        // Policy read the whole text and blocked the call.
        let events: Vec<DomainEvent> = out.iter().filter_map(|b| b.domain_event.clone()).collect();
        assert!(!events.iter().any(|e| matches!(e, DomainEvent::ToolCallDelta { .. })), "{events:?}");
        assert!(events.iter().any(|e| matches!(e, DomainEvent::TextDelta(t) if t.contains("blocked by policy"))), "{events:?}");
    }

    /// A piece of a custom call arriving after the call's end (a lax server
    /// re-sending after `custom_tool_call_input.done`) is never glued onto the
    /// closed arguments: policy, the clients and the audit keep the call as it
    /// was closed, and the piece is withheld the way late bytes of a call
    /// policy read are — recorded, and the client told.
    #[test]
    fn a_piece_after_a_custom_calls_end_is_withheld_and_said_so() {
        let upstream = crate::api::sse::ApiVersion::Responses;
        let text = "*** Add File: a";
        let whole = crate::api::domain_request::freeform_call_input(text).to_string();
        let mut sent = responses_custom_call_upstream(text);
        let done = sent.iter().position(|(name, _)| *name == "response.custom_tool_call_input.done").unwrap();
        sent.insert(done + 1, ("response.custom_tool_call_input.delta", json!({
            "type": "response.custom_tool_call_input.delta", "item_id": "ctc_1", "output_index": 0, "delta": "EXTRA"
        })));
        let mut acc = text_accumulator_for(upstream, block_patch_deletes());
        let (out, state) = read_held(upstream, &sent, &mut acc);
        let recorded = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(recorded.arguments, whole);
        let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &out);
        assert_eq!(anthropic_first_input(&frames), whole, "{frames:?}");
        let frames = render_held(crate::api::sse::ApiVersion::ChatCompletions, upstream, &out);
        assert_eq!(chat_custom_text(&frames), text, "{frames:?}");
        assert!(acc.injection_blocks.iter().any(|b| b.content.contains("withheld")), "{:?}", acc.injection_blocks);
        let events: Vec<DomainEvent> = out.iter().filter_map(|b| b.domain_event.clone()).collect();
        assert!(events.iter().any(|e| matches!(e, DomainEvent::TextDelta(t) if t.contains("withheld"))), "{events:?}");
        // With no call held, every translated client still ends the call where
        // it was closed, and the audit row says what was left out of it.
        let (unheld, state) = read_unheld(upstream, &sent);
        assert_eq!(state.accumulated_tool_calls[0].arguments, whole);
        assert!(
            state.response_injection_blocks.iter().any(|b| b.field == "arguments" && b.content.contains("after the call ended")),
            "{:?}", state.response_injection_blocks
        );
        let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &unheld);
        assert_eq!(anthropic_first_input(&frames), whole, "{frames:?}");
        let frames = render_held(crate::api::sse::ApiVersion::ChatCompletions, upstream, &unheld);
        assert_eq!(chat_custom_text(&frames), text, "{frames:?}");
        assert!(!frames.iter().any(|v| v.pointer("/choices/0/delta/tool_calls/0/function").is_some()), "{frames:?}");
        let frames = render_held(crate::api::sse::ApiVersion::GoogleGemini, upstream, &unheld);
        let args: Vec<&serde_json::Value> = frames.iter()
            .filter_map(|v| v["candidates"][0]["content"]["parts"].as_array())
            .flatten()
            .filter_map(|p| p.get("functionCall").map(|c| &c["args"]))
            .collect();
        assert_eq!(args, [&json!({"input": text})], "{frames:?}");
    }

    /// A Chat custom call whose opening delta names the call alone — no
    /// `custom` object yet — opens its arguments on its first piece of text:
    /// the call is read whole, never as text with no arguments around it.
    #[test]
    fn a_custom_call_whose_text_starts_after_its_opening_delta_is_read_whole() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]}));
        let sent = [
            chunk(json!({"index": 0, "id": "call_1", "type": "custom"})),
            chunk(json!({"index": 0, "custom": {"name": "apply_patch", "input": "*** Delete "}})),
            chunk(json!({"index": 0, "custom": {"input": "File: a"}})),
            ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let mut acc = text_accumulator(block_patch_deletes());
        let (out, state) = read_held(upstream, &sent, &mut acc);
        let recorded = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(recorded.arguments, crate::api::domain_request::freeform_call_input("*** Delete File: a").to_string());
        let events: Vec<DomainEvent> = out.iter().filter_map(|b| b.domain_event.clone()).collect();
        assert!(!events.iter().any(|e| matches!(e, DomainEvent::ToolCallDelta { .. })), "{events:?}");
    }

    /// A Chat custom call continued after other content — its text closed
    /// when the text started — is not reopened: the late piece is withheld
    /// and said so on the held path, and a translated client given the
    /// stream unheld keeps the call as it was closed.
    #[test]
    fn a_custom_call_continued_after_text_is_not_reopened() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |delta: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": delta, "finish_reason": null}]}));
        let sent = [
            chunk(json!({"tool_calls": [{"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Add File: a"}}]})),
            chunk(json!({"content": "ok"})),
            chunk(json!({"tool_calls": [{"index": 0, "custom": {"input": "EXTRA"}}]})),
            ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let text = "*** Add File: a";
        let whole = crate::api::domain_request::freeform_call_input(text).to_string();
        let mut acc = text_accumulator(block_patch_deletes());
        let (out, state) = read_held(upstream, &sent, &mut acc);
        let recorded = state.accumulated_tool_calls.iter().find(|c| c.function_name == "apply_patch").expect("recorded");
        assert_eq!(recorded.arguments, whole);
        let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &out);
        assert_eq!(anthropic_first_input(&frames), whole, "{frames:?}");
        let events: Vec<DomainEvent> = out.iter().filter_map(|b| b.domain_event.clone()).collect();
        assert!(events.iter().any(|e| matches!(e, DomainEvent::TextDelta(t) if t.contains("withheld"))), "{events:?}");
        // Unheld, to a Responses client: one call item, its arguments whole.
        let (unheld, _) = read_unheld(upstream, &sent);
        let frames = render_held(crate::api::sse::ApiVersion::Responses, upstream, &unheld);
        let done: Vec<&serde_json::Value> = frames.iter()
            .filter(|v| v["type"] == "response.output_item.done" && v["item"]["type"] == "function_call")
            .map(|v| &v["item"]["arguments"])
            .collect();
        assert_eq!(done, [&json!(whole)], "{frames:?}");
    }

    /// A Chat custom call whose opening delta says what it is by its `type`
    /// alone, or says nothing but its id, is one custom call for every
    /// reader: the audit, and — with no call held — an Anthropic client (one
    /// block, named, its input opened and closed) and a Responses client (one
    /// call item, its arguments whole). (A Chat client of a Chat upstream is
    /// sent the upstream's own chunks; the Chat builder's reading is
    /// `a_chat_client_is_sent_a_custom_call_once_it_is_named`.)
    #[test]
    fn a_custom_call_opened_without_its_text_reaches_every_client_as_one() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]}));
        let text = "*** Begin Patch";
        let whole = crate::api::domain_request::freeform_call_input(text).to_string();
        for opening in [json!({"index": 0, "id": "call_1", "type": "custom"}), json!({"index": 0, "id": "call_1"})] {
            let sent = [
                chunk(opening.clone()),
                chunk(json!({"index": 0, "custom": {"name": "apply_patch", "input": "*** Begin "}})),
                chunk(json!({"index": 0, "custom": {"input": "Patch"}})),
                ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
            ];
            let (unheld, state) = read_unheld(upstream, &sent);
            // A delta typed `custom` is read as a custom call's from the first.
            let typed = opening.get("type").is_some();
            let first_form = unheld.iter().find_map(|b| match &b.domain_event {
                Some(DomainEvent::ToolCallDelta { form, .. }) => Some(*form),
                _ => None,
            });
            let expected = if typed { CallArguments::FreeformPiece } else { CallArguments::Json };
            assert_eq!(first_form, Some(expected), "{opening}");
            assert_eq!(state.accumulated_tool_calls.len(), 1, "{opening}");
            assert_eq!(state.accumulated_tool_calls[0].arguments, whole, "{opening}");
            let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &unheld);
            let names: Vec<&str> = frames.iter()
                .filter(|v| v["type"] == "content_block_start" && v["content_block"]["type"] == "tool_use")
                .filter_map(|v| v["content_block"]["name"].as_str())
                .collect();
            assert_eq!(names, ["apply_patch"], "{opening}: {frames:?}");
            assert_eq!(anthropic_first_input(&frames), whole, "{opening}: {frames:?}");
            let frames = render_held(crate::api::sse::ApiVersion::Responses, upstream, &unheld);
            let done: Vec<(&serde_json::Value, &serde_json::Value)> = frames.iter()
                .filter(|v| v["type"] == "response.output_item.done")
                .map(|v| (&v["item"]["name"], &v["item"]["arguments"]))
                .collect();
            assert_eq!(done, [(&json!("apply_patch"), &json!(whole))], "{opening}: {frames:?}");
        }
    }

    /// The same stream parser reads every round of an agent loop, so a round
    /// that ended without its finish leaves no call open for the next: the
    /// next round's call is a call of its own, never more of the last one.
    #[test]
    fn a_round_cut_short_leaves_no_call_open_for_the_next() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| SseEvent { event_type: None, data: json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]}).to_string(), id: None };
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        let mut state = crate::pipeline::response::TransformState::new(upstream);
        let round_one = [chunk(json!({"index": 0, "id": "c1", "type": "function", "function": {"name": "Read", "arguments": "{\"a\":"}}))];
        for event in &round_one {
            parser.parse(event).iter().for_each(|e| state.process_event(e));
        }
        parser.finish().iter().for_each(|e| state.process_event(e));
        let round_two = [chunk(json!({"index": 0, "function": {"name": "Read", "arguments": "{\"b\":1}"}}))];
        for event in &round_two {
            parser.parse(event).iter().for_each(|e| state.process_event(e));
        }
        let recorded: Vec<&str> = state.accumulated_tool_calls.iter().map(|c| c.arguments.as_str()).collect();
        assert_eq!(recorded, ["{\"a\":", "{\"b\":1}"]);
    }

    /// With no call held, an Anthropic client's blocks are sequential: a call
    /// whose deltas interleave with another's has its block closed when the
    /// other starts, and its later bytes cannot reach it. They are withheld,
    /// and said so — a notice after, once per call — never dropped unsaid.
    #[test]
    fn interleaved_calls_reach_an_anthropic_client_with_what_was_withheld_said() {
        let upstream = crate::api::sse::ApiVersion::ChatCompletions;
        let chunk = |tc: serde_json::Value| ("", json!({"id": "c", "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {"tool_calls": [tc]}, "finish_reason": null}]}));
        let sent = [
            chunk(json!({"index": 0, "id": "call_1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Add "}})),
            chunk(json!({"index": 1, "id": "call_2", "type": "function", "function": {"name": "Read", "arguments": "{}"}})),
            chunk(json!({"index": 0, "custom": {"input": "File: a"}})),
            chunk(json!({"index": 0, "custom": {"input": " more"}})),
            ("", json!({"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let (unheld, _) = read_unheld(upstream, &sent);
        let frames = render_held(crate::api::sse::ApiVersion::AnthropicMessages, upstream, &unheld);
        assert_eq!(anthropic_first_input(&frames), crate::api::domain_request::freeform_call_input("*** Add ").to_string(), "{frames:?}");
        let notices = frames.iter()
            .filter_map(|v| v["delta"]["text"].as_str())
            .filter(|t| t.contains(crate::pipeline::response::WITHHELD_NOTICE.trim()))
            .count();
        assert_eq!(notices, 1, "{frames:?}");
        // And the audit row is told which call, once.
        let mut emitter = crate::pipeline::response_pipeline::EventEmitter::new(
            crate::api::sse::ApiVersion::AnthropicMessages, upstream, "m", "req-1", None, None, 0, 0,
        );
        for b in &unheld {
            emitter.process_buffered(b);
        }
        assert_eq!(emitter.take_withheld_calls(), [(0, crate::pipeline::response::Withheld::Late)]);
        assert!(emitter.take_withheld_calls().is_empty());
    }

    /// A frame marked a server tool's input passes unscreened only where it
    /// addresses that server tool's own block or item. One addressing another
    /// — a client's call, which the client would apply it to — never reaches
    /// the client: its bytes are withheld as no call's. Whatever marked it.
    #[test]
    fn a_server_tool_frame_addressing_another_item_is_withheld() {
        let server = |arguments: &str| DomainEvent::ToolCallDelta {
            index: 1,
            id: None,
            function_name: None,
            arguments_delta: arguments.to_string(),
            form: CallArguments::ServerTool,
        };
        let frame = |name: &str, data: serde_json::Value| Some(SseEvent { event_type: Some(name.into()), data: data.to_string(), id: None });
        for (opening, own, other) in [
            (
                frame("content_block_start", json!({"type": "content_block_start", "index": 1,
                    "content_block": {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {}}})),
                frame("content_block_delta", json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{"}})),
                frame("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "rm"}})),
            ),
            (
                frame("response.output_item.added", json!({"output_index": 1, "item": {"id": "mcp_1", "type": "mcp_call", "name": "fetch"}})),
                frame("response.mcp_call_arguments.delta", json!({"item_id": "mcp_1", "output_index": 1, "delta": "{"})),
                frame("response.function_call_arguments.delta", json!({"item_id": "fc_0", "output_index": 0, "delta": "rm"})),
            ),
        ] {
            let shown = |out: &[BufferedEvent]| out.iter().map(|b| (b.domain_event.clone(), b.raw_sse.is_some())).collect::<Vec<_>>();
            let mut acc = make_tool_accumulator(vec![]);
            let opened = acc.process(server(""), opening);
            assert!(opened.iter().all(|b| b.raw_sse.is_some()), "{:?}", shown(&opened));
            let passed = acc.process(server("{"), own);
            assert!(
                matches!(passed.as_slice(), [BufferedEvent { domain_event: Some(DomainEvent::ToolCallDelta { index: 1, .. }), raw_sse: Some(_) }]),
                "{:?}",
                shown(&passed)
            );
            let withheld = acc.process(server("rm"), other);
            assert!(
                matches!(withheld.as_slice(), [BufferedEvent {
                    domain_event: Some(DomainEvent::ToolCallDelta { index: DomainEvent::NO_CALL, arguments_delta, .. }),
                    raw_sse: None,
                }] if arguments_delta == "rm"),
                "{:?}",
                shown(&withheld)
            );
        }
    }

    /// A piece of text the upstream sent for no call (before any call
    /// opened) belongs to no call: it is given a number no call has, so no
    /// reader attributes it to the call that opens next.
    #[test]
    fn a_stray_piece_belongs_to_no_call() {
        let upstream = crate::api::sse::ApiVersion::Responses;
        let text = "*** Add File: a";
        let mut sent = responses_custom_call_upstream(text);
        sent.insert(1, ("response.custom_tool_call_input.delta", json!({
            "type": "response.custom_tool_call_input.delta", "item_id": "ctc_0", "output_index": 0, "delta": "stray"
        })));
        let (unheld, state) = read_unheld(upstream, &sent);
        let stray = unheld.iter().find_map(|b| match &b.domain_event {
            Some(DomainEvent::ToolCallDelta { index, arguments_delta, .. }) if arguments_delta == "stray" => Some(*index),
            _ => None,
        });
        let numbers: Vec<usize> = state.accumulated_tool_calls.iter().map(|c| c.index).collect();
        assert!(stray.is_some_and(|n| !numbers.contains(&n)), "{stray:?} vs {numbers:?}");
        assert_eq!(state.accumulated_tool_calls[0].arguments, crate::api::domain_request::freeform_call_input(text).to_string());
    }

    /// A client whose protocol has no custom tool call is handed the call a
    /// Responses upstream streamed as that protocol's function call, carrying
    /// the free text as `{"input": …}` — never nothing.
    #[test]
    fn a_streamed_custom_tool_call_reaches_a_chat_client_as_a_call() {
        use crate::pipeline::response_pipeline::EventEmitter;
        let upstream = crate::api::sse::ApiVersion::Responses;
        let mut emitter =
            EventEmitter::new(crate::api::sse::ApiVersion::ChatCompletions, upstream, "m", "req-1", None, None, 0, 0);
        let mut body = String::new();
        let input = "*** Begin \"Patch\"\n+ line";
        let mut parser = crate::api::sse::StreamParser::new(upstream);
        for (name, data) in responses_custom_call_upstream(input) {
            let event = SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None };
            for de in parser.parse(&event) {
                for chunk in emitter.process_streaming_event(&de, Some(&event)) {
                    body.push_str(std::str::from_utf8(&chunk).unwrap());
                }
            }
        }
        for chunk in emitter.flush() {
            body.push_str(std::str::from_utf8(&chunk).unwrap());
        }
        let (mut name, mut args, mut finish) = (String::new(), String::new(), None);
        for line in body.lines().filter_map(|l| l.strip_prefix("data: ")) {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            let choice = &v["choices"][0];
            if let Some(f) = choice["finish_reason"].as_str() {
                finish = Some(f.to_string());
            }
            for tc in choice["delta"]["tool_calls"].as_array().into_iter().flatten() {
                name.push_str(tc["function"]["name"].as_str().unwrap_or_default());
                args.push_str(tc["function"]["arguments"].as_str().unwrap_or_default());
            }
        }
        assert_eq!(name, "apply_patch", "{body}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&args).unwrap(), json!({"input": input}));
        assert_eq!(finish.as_deref(), Some("tool_calls"));
    }

    #[test]
    fn a_rewritten_streamed_custom_tool_call_stays_a_custom_call() {
        let rewrite = rules_from_json(vec![json!({
            "id": "T-7188",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "arg.input", "op": "contains_any", "value": ["*** Delete File"] }],
            "action": { "kind": "replace", "with": "*** Begin Patch" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::Responses, rewrite);
        let frames = client_frames(
            crate::api::sse::ApiVersion::Responses,
            &responses_custom_call_upstream("*** Delete File: a.txt"),
            &mut acc,
        );
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "function_call"), "{frames:?}");
        let done = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.output_item.done")
            .map(|(_, d)| d["item"].clone())
            .expect("the rewritten call is closed");
        assert_eq!((done["type"].as_str(), done["name"].as_str(), done["input"].as_str()),
                   (Some("custom_tool_call"), Some("apply_patch"), Some("*** Begin Patch")), "{done}");
        assert_eq!(done["call_id"], "call_1");
        let input_done = frames.iter().find(|(_, d)| d["type"] == "response.custom_tool_call_input.done").expect("{frames:?}");
        assert_eq!(input_done.1["input"], "*** Begin Patch");
    }

    // ── Non-streaming: Anthropic Messages format ──

    #[test]
    fn non_streaming_anthropic_blocks_tool_use() {
        use crate::api::sse::ApiVersion;
        let rules = rules_from_json(vec![json!({
            "id": "T-7219",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);

        let mut response = json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me read that."},
                {"type": "tool_use", "id": "tu_1", "name": "Read", "input": {"file_path": "/etc/shadow"}},
                {"type": "tool_use", "id": "tu_2", "name": "Read", "input": {"file_path": "/home/user/file.txt"}}
            ],
            "stop_reason": "tool_use"
        });

        let (blocked_names, _blocked_infos, _arg_mods) =
            apply_response_policy_json(&mut response, ApiVersion::AnthropicMessages, &rules, &default_test_profiles(), None, None, &[]);

        let content = response["content"].as_array().unwrap();
        assert_eq!(content.len(), 3); // text block + safe tool_use + block notice
        assert_eq!(content[0]["type"].as_str().unwrap(), "text");
        assert_eq!(content[1]["name"].as_str().unwrap(), "Read");
        assert!(content[1]["input"]["file_path"].as_str().unwrap().contains("user"));
        // Block notice injected as last text block
        assert_eq!(content[2]["type"].as_str().unwrap(), "text");
        assert!(content[2]["text"].as_str().unwrap().contains("blocked by policy"));
        assert_eq!(blocked_names.len(), 1);
    }

    // ── Non-streaming: Responses API format ──

    #[test]
    fn non_streaming_responses_blocks_function_call() {
        use crate::api::sse::ApiVersion;
        let rules = rules_from_json(vec![json!({
            "id": "T-7261",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "shell_exec" },
                { "target": "any_arg", "op": "contains_any", "value": ["rm -rf"] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);

        let mut response = json!({
            "id": "resp_123",
            "status": "completed",
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "Running commands."}]},
                {"type": "function_call", "id": "fc_1", "name": "Bash", "arguments": "{\"command\": \"rm -rf /\"}"},
                {"type": "function_call", "id": "fc_2", "name": "Bash", "arguments": "{\"command\": \"ls -la\"}"}
            ]
        });

        let (blocked_names, _blocked_infos, _arg_mods) =
            apply_response_policy_json(&mut response, ApiVersion::Responses, &rules, &default_test_profiles(), None, None, &[]);

        let output = response["output"].as_array().unwrap();
        assert_eq!(output.len(), 3); // message + safe function_call + block notice
        assert_eq!(output[0]["type"].as_str().unwrap(), "message");
        assert_eq!(output[1]["name"].as_str().unwrap(), "Bash");
        assert!(output[1]["arguments"].as_str().unwrap().contains("ls -la"));
        // Block notice injected as last output item
        assert_eq!(output[2]["type"].as_str().unwrap(), "message");
        assert_eq!(blocked_names.len(), 1);
    }

    // ── Non-streaming: no rules = no filtering ──

    #[test]
    fn non_streaming_no_rules_passes_through() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "choices": [{
                "message": {
                    "content": "test",
                    "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/shadow\"}"}}
                    ]
                }
            }]
        });

        let (blocked_names, _blocked_infos, _arg_mods) =
            apply_response_policy_json(&mut response, ApiVersion::ChatCompletions, &[], &Default::default(), None, None, &[]);

        let tool_calls = response["choices"][0]["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(tool_calls.len(), 1); // nothing blocked
        assert!(blocked_names.is_empty());
    }

    // ── The finish reason must not claim a tool call the response dropped ──
    //
    // Every wire reads its finish reason as a promise about the content:
    // Anthropic documents `stop_reason: "tool_use"` as "one or more `tool_use`
    // blocks" the caller executes and answers, and OpenAI's `tool_calls` says
    // the same. A response that keeps the promise after policy removed the last
    // call is one no client can act on — Claude Code throws the whole message
    // away, block notice included, and spends a turn retrying.
    //
    // Each wire gets the removal case AND the survivor case: without the second,
    // these all keep passing if the settle degenerates into "always stop".

    /// The rule every test below blocks with: any `Bash` call running `rm -rf`.
    fn block_rm_rf() -> Vec<crate::config::tool_rules::Rule> {
        rules_from_json(vec![json!({
            "id": "T-7333",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "shell_exec" },
                { "target": "arg.command", "op": "contains_any", "value": ["rm -rf"] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })])
    }

    fn chat_call(id: &str, command: &str) -> serde_json::Value {
        json!({
            "id": id,
            "type": "function",
            "function": {"name": "Bash", "arguments": format!("{{\"command\": \"{command}\"}}")}
        })
    }

    #[test]
    fn chat_completions_stops_claiming_a_tool_call_it_no_longer_carries() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {"content": "", "tool_calls": [chat_call("c1", "rm -rf /")]}
            }]
        });

        let (blocked, _, _) = apply_response_policy_json(
            &mut response, ApiVersion::ChatCompletions, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(blocked.len(), 1);
        assert_eq!(response["choices"][0]["finish_reason"].as_str(), Some("stop"));
        // Not `[]`: a client testing the key's presence reads an empty array as
        // "there are calls to run" and loops with nothing to execute.
        assert!(
            response["choices"][0]["message"].get("tool_calls").is_none(),
            "an emptied tool_calls must be removed, not left as []: {response}"
        );
        assert!(
            response["choices"][0]["message"]["content"]
                .as_str().unwrap().contains("blocked by policy"),
            "the reason must ride the one channel every wire has"
        );
    }

    #[test]
    fn chat_completions_keeps_the_claim_when_a_call_survives() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {"content": "", "tool_calls": [
                    chat_call("c1", "rm -rf /"),
                    chat_call("c2", "ls -la"),
                ]}
            }]
        });

        apply_response_policy_json(
            &mut response, ApiVersion::ChatCompletions, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(response["choices"][0]["finish_reason"].as_str(), Some("tool_calls"));
        assert_eq!(
            response["choices"][0]["message"]["tool_calls"].as_array().unwrap().len(), 1
        );
    }

    #[test]
    fn a_finish_reason_that_claims_nothing_about_tools_is_left_alone() {
        use crate::api::sse::ApiVersion;
        // The upstream ran out of budget mid-call. Removing the call does not
        // make that false, so `length` must survive the settle.
        let mut response = json!({
            "choices": [{
                "finish_reason": "length",
                "message": {"content": "", "tool_calls": [chat_call("c1", "rm -rf /")]}
            }]
        });

        apply_response_policy_json(
            &mut response, ApiVersion::ChatCompletions, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(response["choices"][0]["finish_reason"].as_str(), Some("length"));
    }

    #[test]
    fn anthropic_stops_claiming_a_tool_use_it_no_longer_carries() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "Running it."},
                {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"command": "rm -rf /"}}
            ]
        });

        apply_response_policy_json(
            &mut response, ApiVersion::AnthropicMessages, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(response["stop_reason"].as_str(), Some("end_turn"));
        let content = response["content"].as_array().unwrap();
        assert!(
            !content.iter().any(|b| b["type"] == "tool_use"),
            "no tool_use may remain once the claim is retracted"
        );
        assert!(content.last().unwrap()["text"].as_str().unwrap().contains("blocked by policy"));
    }

    #[test]
    fn anthropic_keeps_the_claim_when_a_call_survives() {
        use crate::api::sse::ApiVersion;
        let mut response = json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "stop_reason": "tool_use",
            "content": [
                {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"command": "rm -rf /"}},
                {"type": "tool_use", "id": "tu_2", "name": "Bash", "input": {"command": "ls"}}
            ]
        });

        apply_response_policy_json(
            &mut response, ApiVersion::AnthropicMessages, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(response["stop_reason"].as_str(), Some("tool_use"));
    }

    #[test]
    fn gemini_names_the_call_it_removed() {
        use crate::api::sse::ApiVersion;
        // Gemini's FinishReason has no value meaning "the model called a
        // function" — a call is read from the parts — so there is nothing to
        // settle here and the whole obligation is the notice.
        let mut response = json!({
            "candidates": [{
                "finishReason": "STOP",
                "content": {"parts": [
                    {"functionCall": {"name": "Bash", "args": {"command": "rm -rf /"}}}
                ]}
            }]
        });

        let (blocked, _, _) = apply_response_policy_json(
            &mut response, ApiVersion::GoogleGemini, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(blocked.len(), 1);
        let parts = response["candidates"][0]["content"]["parts"].as_array().unwrap();
        assert!(!parts.iter().any(|p| p.get("functionCall").is_some()));
        assert!(
            parts.iter().any(|p| p.get("text").and_then(|t| t.as_str())
                .is_some_and(|t| t.contains("blocked by policy"))),
            "a Gemini client was told nothing at all: {response}"
        );
        assert_eq!(response["candidates"][0]["finishReason"].as_str(), Some("STOP"));
    }

    #[test]
    fn responses_removes_the_call_and_leaves_its_status_alone() {
        use crate::api::sse::ApiVersion;
        // The Responses API states completion in `status`, which says nothing
        // about tools; dropping the `function_call` item is the entire edit.
        let mut response = json!({
            "id": "resp_1", "status": "completed",
            "output": [
                {"type": "function_call", "id": "fc_1", "name": "Bash",
                 "arguments": "{\"command\": \"rm -rf /\"}"}
            ]
        });

        apply_response_policy_json(
            &mut response, ApiVersion::Responses, &block_rm_rf(),
            &default_test_profiles(), None, None,
            &[],
        );

        assert_eq!(response["status"].as_str(), Some("completed"));
        let output = response["output"].as_array().unwrap();
        assert!(!output.iter().any(|i| i["type"] == "function_call"));
        assert_eq!(output.last().unwrap()["type"].as_str(), Some("message"));
    }

    // ── Streaming counterpart ──

    /// Drive one `Bash` call through the accumulator and return the events the
    /// terminal `Done` produced. `raw` is the upstream frame a same-protocol
    /// passthrough would otherwise forward verbatim.
    fn stream_calls_then_done(
        acc: &mut BlockAccumulator,
        commands: &[&str],
    ) -> Vec<BufferedEvent> {
        for (i, command) in commands.iter().enumerate() {
            acc.process(
                DomainEvent::ToolCallDelta {
                    index: i,
                    id: Some(format!("call_{i}")),
                    function_name: Some("Bash".into()),
                    arguments_delta: format!("{{\"command\": \"{command}\"}}"),
                    form: crate::api::domain::CallArguments::Json,
                },
                None,
            );
        }
        acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                native_finish_reason: Some("tool_calls".into()),
            },
            Some(crate::api::sse::SseEvent {
                event_type: None,
                data: r#"{"choices":[{"finish_reason":"tool_calls"}]}"#.to_string(),
                id: None,
            }),
        )
    }

    fn terminal_done(events: &[BufferedEvent]) -> (&DomainEvent, &Option<crate::api::sse::SseEvent>) {
        let e = events
            .iter()
            .find(|e| matches!(e.domain_event, Some(DomainEvent::Done { .. })))
            .expect("the stream must still terminate");
        (e.domain_event.as_ref().expect("found by its domain event"), &e.raw_sse)
    }

    #[test]
    fn streaming_stops_claiming_a_tool_call_policy_removed() {
        let mut acc = make_tool_accumulator(block_rm_rf());
        let events = stream_calls_then_done(&mut acc, &["rm -rf /"]);

        let (done, raw) = terminal_done(&events);
        assert_matches!(
            done,
            DomainEvent::Done { finish_reason: Some(crate::api::domain::FinishReason::Stop), .. }
        );
        // The upstream frame is KEPT: a same-protocol passthrough rewrites its
        // finish field from the settled domain value and would otherwise have
        // no `Done` to render at all. Dropping it here loses the client's
        // finish frame entirely — see `settle_finish_reason`.
        assert!(raw.is_some(), "the passthrough's only finish frame must survive");
        // Provenance is kept: the audit row records what the upstream said.
        let DomainEvent::Done { native_finish_reason, .. } = done else { unreachable!() };
        assert_eq!(native_finish_reason.as_deref(), Some("tool_calls"));
        assert!(
            events.iter().any(|e| matches!(&e.domain_event,
                Some(DomainEvent::TextDelta(t)) if t.contains("blocked by policy"))),
            "the client must be told why the call is gone"
        );
    }

    #[test]
    fn streaming_keeps_the_claim_when_a_call_survives() {
        let mut acc = make_tool_accumulator(block_rm_rf());
        let events = stream_calls_then_done(&mut acc, &["rm -rf /", "ls -la"]);

        let (done, raw) = terminal_done(&events);
        assert_matches!(
            done,
            DomainEvent::Done { finish_reason: Some(crate::api::domain::FinishReason::ToolCalls), .. }
        );
        assert!(raw.is_some(), "an untouched claim keeps its upstream frame");
    }

    #[test]
    fn streaming_leaves_a_stream_nothing_blocked_alone() {
        let mut acc = make_tool_accumulator(block_rm_rf());
        let events = stream_calls_then_done(&mut acc, &["ls -la"]);

        let (done, _) = terminal_done(&events);
        assert_matches!(
            done,
            DomainEvent::Done { finish_reason: Some(crate::api::domain::FinishReason::ToolCalls), .. }
        );
    }

    // ── Filter correctness for compute_interests / extract_response_programs ──

    #[test]
    fn compute_interests_excludes_app_filtered_when_app_id_none() {
        let mut prog = make_response_program("cc_only", "text");
        prog.app_filter = Some("claude-code".to_string());
        let interests = compute_interests(&[prog], &[], Some("gpt-4o"), None);
        assert!(!interests.buffer_text_blocks, "app-filtered program should be excluded when app_id is None");
    }

    #[test]
    fn compute_interests_includes_app_filtered_when_app_id_matches() {
        let mut prog = make_response_program("cc_only", "text");
        prog.app_filter = Some("claude-code".to_string());
        let interests = compute_interests(&[prog], &[], Some("gpt-4o"), Some("claude-code"));
        assert!(interests.buffer_text_blocks, "app-filtered program should be included when app_id matches");
    }

    #[test]
    fn compute_interests_excludes_model_filtered_when_model_alias_none() {
        let mut prog = make_response_program("gpt_only", "text");
        prog.model_filter = Some("gpt-4o".to_string());
        let interests = compute_interests(&[prog], &[], None, Some("any-app"));
        assert!(!interests.buffer_text_blocks, "model-filtered program should be excluded when model_alias is None");
    }

    #[test]
    fn extract_response_programs_excludes_app_filtered_when_app_id_none() {
        let mut prog = make_response_program("cc_only", "text");
        prog.app_filter = Some("claude-code".to_string());
        let result = extract_response_programs(&[prog], Some("gpt-4o"), None);
        assert!(result.is_empty(), "app-filtered program should be excluded when app_id is None");
    }

    #[test]
    fn extract_response_programs_includes_app_filtered_when_app_id_matches() {
        let mut prog = make_response_program("cc_only", "text");
        prog.app_filter = Some("claude-code".to_string());
        let result = extract_response_programs(&[prog], Some("gpt-4o"), Some("claude-code"));
        assert_eq!(result.len(), 1, "app-filtered program should be included when app_id matches");
    }

    #[test]
    fn extract_response_programs_excludes_model_filtered_when_model_alias_none() {
        let mut prog = make_response_program("gpt_only", "text");
        prog.model_filter = Some("gpt-4o".to_string());
        let result = extract_response_programs(&[prog], None, Some("any-app"));
        assert!(result.is_empty(), "model-filtered program should be excluded when model_alias is None");
    }

    #[test]
    fn extract_response_programs_unfiltered_included_when_values_none() {
        let prog = make_response_program("always", "text");
        let result = extract_response_programs(&[prog], None, None);
        assert_eq!(result.len(), 1, "unfiltered program should be included even with None values");
    }

    // ── Intercept bindings round-trip ──

    #[test]
    fn accumulator_carries_intercept_bindings() {
        use crate::config::tool_rules::InterceptKind;
        use crate::proxy::content::InterceptBinding;
        let bindings = vec![
            InterceptBinding {
                original_name: "WebFetch".to_string(),
                replaced_name: "web_fetch".to_string(),
                rule_id: "WS-SUB-CC-WEB-FETCH".to_string(),
                intercept: InterceptKind::WebExecutor {
                    kind: crate::config::tool_rules::WebInterceptKind::Fetch,
                },
                action: "substitute".to_string(),
                original_server_type: None,
            },
            InterceptBinding {
                original_name: "WebSearch".to_string(),
                replaced_name: "web_search".to_string(),
                rule_id: "WS-SUB-CC-WEB-SEARCH".to_string(),
                intercept: InterceptKind::WebExecutor {
                    kind: crate::config::tool_rules::WebInterceptKind::Search,
                },
                action: "substitute".to_string(),
                original_server_type: None,
            },
        ];
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        let acc = BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            bindings,
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        );

        assert!(acc.has_intercept_bindings());
        assert_eq!(acc.intercept_bindings.len(), 2);

        let hit = acc.intercept_binding_for("web_fetch").expect("WebFetch binding should match by replaced_name");
        assert_eq!(hit.original_name, "WebFetch");
        assert_eq!(hit.rule_id, "WS-SUB-CC-WEB-FETCH");
        assert_eq!(hit.action, "substitute");

        assert!(acc.intercept_binding_for("not_substituted").is_none());
    }

    #[test]
    fn intercept_binding_lookup_falls_back_to_original_name() {
        use crate::config::tool_rules::InterceptKind;
        use crate::proxy::content::InterceptBinding;
        let bindings = vec![InterceptBinding {
            original_name: "WebFetch".to_string(),
            replaced_name: "web_fetch".to_string(),
            rule_id: "WS-SUB-CC-WEB-FETCH".to_string(),
            intercept: InterceptKind::WebExecutor {
                kind: crate::config::tool_rules::WebInterceptKind::Fetch,
            },
            action: "substitute".to_string(),
            original_server_type: None,
        }];
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        let acc = BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            bindings,
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        );

        // Upstream echoes the post-substitution wire name → matches replaced_name.
        let by_replaced = acc
            .intercept_binding_for("web_fetch")
            .expect("replaced_name must match");
        assert_eq!(by_replaced.rule_id, "WS-SUB-CC-WEB-FETCH");

        // Downstream-protocol translation reverts the wire name to the
        // pre-substitution shape → falls back to original_name.
        let by_original = acc
            .intercept_binding_for("WebFetch")
            .expect("original_name must match as fallback");
        assert_eq!(by_original.rule_id, "WS-SUB-CC-WEB-FETCH");

        // Unrelated tool name still misses.
        assert!(acc.intercept_binding_for("unrelated_tool").is_none());
    }

    #[test]
    fn intercept_binding_lookup_collision_resolves_in_list_order() {
        use crate::config::tool_rules::InterceptKind;
        use crate::proxy::content::InterceptBinding;
        // Pathological case: binding-A's `original_name` collides with
        // binding-B's `replaced_name` ("collide"). On a `"collide"`
        // lookup, `find()` walks the list in order and returns the first
        // binding that matches *either* key — the first-positioned
        // binding wins. Pinning the tiebreak so a future refactor (e.g.
        // swapping `find()` for a HashMap) doesn't silently flip
        // ownership.
        let bindings = vec![
            InterceptBinding {
                original_name: "collide".to_string(),
                replaced_name: "first_replaced".to_string(),
                rule_id: "RULE-A".to_string(),
                intercept: InterceptKind::WebExecutor {
                    kind: crate::config::tool_rules::WebInterceptKind::Fetch,
                },
                action: "substitute".to_string(),
                original_server_type: None,
            },
            InterceptBinding {
                original_name: "second_original".to_string(),
                replaced_name: "collide".to_string(),
                rule_id: "RULE-B".to_string(),
                intercept: InterceptKind::WebExecutor {
                    kind: crate::config::tool_rules::WebInterceptKind::Search,
                },
                action: "substitute".to_string(),
                original_server_type: None,
            },
        ];
        let acc = BlockAccumulator::new(
            BlockInterests {
                buffer_tool_blocks: true,
                buffer_text_blocks: false,
                buffer_thinking_blocks: false,
            },
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            bindings,
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        );
        let hit = acc
            .intercept_binding_for("collide")
            .expect("collision lookup must match the first-positioned binding");
        assert_eq!(hit.rule_id, "RULE-A");
    }

    #[test]
    fn accumulator_without_intercept_bindings_reports_empty() {
        let interests = BlockInterests::default();
        let acc = BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        );
        assert!(!acc.has_intercept_bindings());
        assert!(acc.intercept_bindings.is_empty());
        assert!(acc.intercept_binding_for("anything").is_none());
    }

    // ── Intercept suppression at flush time ──

    fn make_substitute_binding(replaced_name: &str, rule_id: &str) -> crate::proxy::content::InterceptBinding {
        make_substitute_binding_with(replaced_name, rule_id, None)
    }

    /// Visible-mode helper — the originating tool was a wire server-tool
    /// (Anthropic `web_search_20250305`, etc). Tests verifying
    /// substitution-loop synthesis of native server-tool block-pairs build
    /// their bindings through this overload.
    fn make_substitute_binding_with(
        replaced_name: &str,
        rule_id: &str,
        original_server_type: Option<&str>,
    ) -> crate::proxy::content::InterceptBinding {
        crate::proxy::content::InterceptBinding {
            original_name: replaced_name.to_string(),
            replaced_name: replaced_name.to_string(),
            rule_id: rule_id.to_string(),
            intercept: crate::config::tool_rules::InterceptKind::WebExecutor {
                kind: crate::config::tool_rules::WebInterceptKind::Search,
            },
            action: "substitute".to_string(),
            original_server_type: original_server_type.map(str::to_string),
        }
    }

    fn intercept_accumulator(bindings: Vec<crate::proxy::content::InterceptBinding>) -> BlockAccumulator {
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            bindings,
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        )
    }

    #[test]
    fn intercepted_tool_block_is_suppressed_and_queued() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB-CC-WEB-SEARCH")];
        let mut acc = intercept_accumulator(bindings);

        // Single tool call whose function_name matches a binding.
        let mut emitted = Vec::new();
        emitted.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_abc".into()),
                function_name: Some("web_search".into()),
                arguments_delta: r#"{"query":"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        emitted.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: r#""rust async"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        emitted.extend(acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                native_finish_reason: Some("tool_calls".into()),
            },
            None,
        ));

        // Renderer must NOT see any tool-use bytes for the suppressed call.
        let saw_tool_use = emitted
            .iter()
            .any(|e| matches!(e.domain_event, Some(DomainEvent::ToolCallDelta { .. })));
        assert!(
            !saw_tool_use,
            "intercepted tool call must not be forwarded to the renderer; emitted: {:?}",
            emitted.iter().map(|e| format!("{:?}", e.domain_event)).collect::<Vec<_>>()
        );

        // Done still flows through (the agent loop decides what to do with it).
        let saw_done = emitted
            .iter()
            .any(|e| matches!(e.domain_event, Some(DomainEvent::Done { .. })));
        assert!(saw_done, "Done event should pass through");

        // The intercepted call is queued for the agent loop.
        assert!(acc.has_pending_intercepted());
        let drained = acc.take_pending_intercepted();
        assert_eq!(drained.len(), 1);
        let call = &drained[0];
        assert_eq!(call.tool_use_id.as_deref(), Some("call_abc"));
        assert_eq!(call.tool_name, "web_search");
        assert_eq!(call.arguments_json, r#"{"query":"rust async"}"#);
        assert_eq!(call.binding.rule_id, "WS-SUB-CC-WEB-SEARCH");
        assert_eq!(call.tool_call_index, 0);

        // Drain consumes — second take is empty.
        assert!(!acc.has_pending_intercepted());
        assert!(acc.take_pending_intercepted().is_empty());
    }

    /// The client's `WebFetch`, swapped for the gateway's `ssai_web_fetch`.
    fn client_fetch_binding() -> crate::proxy::content::InterceptBinding {
        crate::proxy::content::InterceptBinding {
            original_name: "WebFetch".into(),
            ..make_substitute_binding("ssai_web_fetch", "WS-SUB")
        }
    }

    /// A field profile reading `tool`'s `url` as a `web_fetch` URL — and none
    /// for any other name.
    fn fetch_profile_for(tool: &str) -> crate::config::tool_rules::FieldProfileSet {
        crate::config::tool_rules::FieldProfileSet::new(vec![
            serde_json::from_value(serde_json::json!({
                "id": "P", "tool_id": "web_fetch", "tool_pattern": tool, "field": "url", "normalizer": "url",
            }))
            .unwrap(),
        ])
    }

    fn fetch_rule(action: serde_json::Value) -> crate::config::tool_rules::Rule {
        serde_json::from_value(serde_json::json!({
            "id": "NO-PASTE", "title": "No paste sites", "description": "paste sites are exfiltration",
            "risk": "danger", "phase": "response", "scope": "tool_calls", "action": action,
            "match": [
                {"target": "tool_id", "op": "in", "value": ["web_fetch"]},
                {"target": "arg.url", "op": "contains_any", "value": ["pastebin.com"]},
            ],
        }))
        .unwrap()
    }

    fn fetch_call(url: &str) -> PendingInterceptedCall {
        PendingInterceptedCall {
            binding: client_fetch_binding(),
            tool_use_id: Some("call_1".into()),
            tool_name: "ssai_web_fetch".into(),
            tool_call_index: 0,
            arguments_json: serde_json::json!({ "url": url }).to_string(),
            thought_signature: None,
            blocked: None,
        }
    }

    #[test]
    fn an_intercepted_call_is_blocked_by_a_rule_read_under_either_name() {
        // The rule reads a `web_fetch` URL; a profile names it under the
        // substitute's name or under the client's tool's — either reading
        // blocks, and a URL the rule does not name passes under both.
        let rules = [fetch_rule(serde_json::json!({"kind": "block"}))];
        for named in ["ssai_web_fetch", "WebFetch"] {
            let profiles = fetch_profile_for(named);
            let mut call = fetch_call("https://pastebin.com/raw/x");
            let record = call.police(&rules, &profiles, None, None, &[]);
            assert_eq!(call.blocked.as_deref(), Some("paste sites are exfiltration"), "read as {named}");
            let info = record.blocked.expect("the block is recorded");
            assert_eq!((info.name.as_str(), info.rule_id.as_str()), ("WebFetch", "NO-PASTE"));
            assert_eq!(info.tool_use_id.as_deref(), Some("call_1"));

            let mut call = fetch_call("https://example.com/");
            let record = call.police(&rules, &profiles, None, None, &[]);
            assert!(call.blocked.is_none() && record.blocked.is_none(), "read as {named}");
        }
    }

    /// A call the gateway would run under a name the request withheld is
    /// blocked under that tool's rule, though no answer-phase rule names it;
    /// with nothing withheld it runs.
    #[test]
    fn an_intercepted_call_under_a_withheld_name_is_blocked() {
        let withheld = [withheld_web_fetch()];
        let profiles = fetch_profile_for("WebFetch");
        let mut call = fetch_call("https://example.com/");
        let record = call.police(&[], &profiles, None, None, &withheld);
        assert_eq!(call.blocked.as_deref(), Some("WebFetch is withheld"));
        assert_eq!(record.blocked.map(|b| b.rule_id).as_deref(), Some("R-FETCH"));

        let mut call = fetch_call("https://example.com/");
        let record = call.police(&[], &profiles, None, None, &[]);
        assert!(call.blocked.is_none() && record.blocked.is_none());
    }

    #[test]
    fn a_rewrite_changes_what_the_gateway_runs() {
        let rules = [fetch_rule(serde_json::json!({"kind": "replace", "regex": "pastebin\\.com", "with": "example.com"}))];
        let mut call = fetch_call("https://pastebin.com/raw/x");
        let record = call.police(&rules, &fetch_profile_for("WebFetch"), None, None, &[]);
        assert!(call.blocked.is_none());
        assert_eq!(call.arguments_json, r#"{"url":"https://example.com/raw/x"}"#);
        assert_eq!(record.modifications.len(), 1);
    }

    /// A field profile per `(tool, tool_id)`, each reading `url`.
    fn fetch_profiles(named: &[(&str, &str)]) -> crate::config::tool_rules::FieldProfileSet {
        crate::config::tool_rules::FieldProfileSet::new(
            named
                .iter()
                .enumerate()
                .map(|(i, (tool, tool_id))| {
                    serde_json::from_value(serde_json::json!({
                        "id": format!("P{i}"), "tool_id": tool_id, "tool_pattern": tool, "field": "url", "normalizer": "url",
                    }))
                    .unwrap()
                })
                .collect(),
        )
    }

    fn url_rule(id: &str, tool_id: &str, needle: &str, action: serde_json::Value) -> crate::config::tool_rules::Rule {
        serde_json::from_value(serde_json::json!({
            "id": id, "description": id, "risk": "danger", "phase": "response", "scope": "tool_calls", "action": action,
            "match": [
                {"target": "tool_id", "op": "in", "value": [tool_id]},
                {"target": "arg.url", "op": "contains_any", "value": [needle]},
            ],
        }))
        .unwrap()
    }

    #[test]
    fn a_call_under_the_clients_name_is_also_read_as_the_substitute() {
        // The model called the client's tool by name; only the substitute's
        // name has a profile. The call is still read as the substitute.
        let rules = [fetch_rule(serde_json::json!({"kind": "block"}))];
        let profiles = fetch_profile_for("ssai_web_fetch");
        for (url, blocked) in [("https://pastebin.com/raw/x", true), ("https://example.com/", false)] {
            let mut call = PendingInterceptedCall { tool_name: "WebFetch".into(), ..fetch_call(url) };
            call.police(&rules, &profiles, None, None, &[]);
            assert_eq!(call.blocked.is_some(), blocked, "{url}");
        }
    }

    #[test]
    fn a_rewrite_never_hides_a_later_reading_s_block() {
        // Read as the substitute, the call is rewritten; read as the client's
        // tool, a rewrite rule placed before a block rule matches too — the
        // block still decides it, and the call is kept and recorded as the
        // model sent it, with no rewrite.
        let rules = [
            url_rule("SUB-REWRITE", "sub_fetch", "pastebin.com", serde_json::json!({"kind": "replace", "regex": "pastebin\\.com", "with": "paste.invalid"})),
            url_rule("CLIENT-REWRITE", "web_fetch", "paste.invalid", serde_json::json!({"kind": "replace", "regex": "raw", "with": "plain"})),
            url_rule("CLIENT-BLOCK", "web_fetch", "paste.invalid", serde_json::json!({"kind": "block"})),
        ];
        let profiles = fetch_profiles(&[("ssai_web_fetch", "sub_fetch"), ("WebFetch", "web_fetch")]);
        let mut call = fetch_call("https://pastebin.com/raw/x");
        let record = call.police(&rules, &profiles, None, None, &[]);
        assert_eq!(record.blocked.as_ref().map(|b| b.rule_id.as_str()), Some("CLIENT-BLOCK"));
        assert!(record.modifications.is_empty(), "{:?}", record.modifications);
        assert_eq!(call.arguments_json, r#"{"url":"https://pastebin.com/raw/x"}"#);
        assert_eq!(record.blocked.unwrap().arguments, Some(serde_json::json!({"url": "https://pastebin.com/raw/x"})));
    }

    #[test]
    fn an_intercepted_call_cut_at_the_buffer_limit_is_still_decided() {
        // The call's object is whole, then padded with whitespace until the
        // accumulator gives up buffering it: what arrived still parses, so it
        // is decided like any intercepted call.
        for (url, blocked) in [("https://pastebin.com/raw/x", true), ("https://example.com/", false)] {
            let mut acc = BlockAccumulator::new(
                BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: false, buffer_thinking_blocks: false },
                vec![fetch_rule(serde_json::json!({"kind": "block"}))],
                std::sync::Arc::new(fetch_profile_for("WebFetch")),
                vec![],
                None,
                None,
                false,
                ScriptFailMode::Open,
                vec![client_fetch_binding()],
                false,
                false,
                crate::api::sse::ApiVersion::ChatCompletions,
            );
            let delta = |id: Option<&str>, name: Option<&str>, args: String| DomainEvent::ToolCallDelta {
                index: 0,
                id: id.map(str::to_string),
                function_name: name.map(str::to_string),
                arguments_delta: args,
                form: crate::api::domain::CallArguments::Json,
            };
            acc.process(delta(Some("call_1"), Some("ssai_web_fetch"), format!(r#"{{"url":"{url}"}}"#)), None);
            for _ in 0..MAX_BUFFERED_EVENTS {
                acc.process(delta(None, None, " ".into()), None);
            }
            let pending = acc.take_pending_intercepted();
            assert_eq!(pending.len(), 1, "{url}: the call was not cut at the limit");
            assert_eq!(pending[0].blocked.is_some(), blocked, "{url}");
        }
    }

    #[test]
    fn a_rewrite_both_names_resolve_to_is_applied_once() {
        // One profile names the call under the substitute's name and the
        // client's: the rule reads it under both, and rewrites it once.
        let rules = [fetch_rule(serde_json::json!({"kind": "replace", "regex": "(pastebin\\.com)", "with": "$1.invalid"}))];
        let mut call = fetch_call("https://pastebin.com/raw/x");
        let record = call.police(&rules, &fetch_profile_for("ssai_web_fetch|WebFetch"), None, None, &[]);
        assert_eq!(call.arguments_json, r#"{"url":"https://pastebin.com.invalid/raw/x"}"#);
        assert_eq!(record.modifications.len(), 1);
    }

    #[test]
    fn a_streamed_intercepted_call_is_decided_on_its_healed_arguments() {
        // The model's arguments stop short of their closing brace: healed,
        // they name a paste site, so the call is queued blocked, recorded as a
        // blocked call, and nothing of it reaches the client. The same call to
        // an ordinary URL is queued to run.
        for (url, blocked) in [("https://pastebin.com/raw/x", true), ("https://example.com/", false)] {
            let mut acc = BlockAccumulator::new(
                BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: false, buffer_thinking_blocks: false },
                vec![fetch_rule(serde_json::json!({"kind": "block"}))],
                std::sync::Arc::new(fetch_profile_for("WebFetch")),
                vec![],
                None,
                None,
                false,
                ScriptFailMode::Open,
                vec![client_fetch_binding()],
                false,
                true,
                crate::api::sse::ApiVersion::ChatCompletions,
            );
            let mut emitted = acc.process(
                DomainEvent::ToolCallDelta {
                    index: 0,
                    id: Some("call_1".into()),
                    function_name: Some("ssai_web_fetch".into()),
                    arguments_delta: format!(r#"{{"url":"{url}""#),
                    form: crate::api::domain::CallArguments::Json,
                },
                None,
            );
            emitted.extend(acc.process(
                DomainEvent::Done {
                    finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                    native_finish_reason: Some("tool_calls".into()),
                },
                None,
            ));
            assert!(
                emitted.iter().all(|e| !matches!(e.domain_event, Some(DomainEvent::ToolCallDelta { .. } | DomainEvent::TextDelta(_)))),
                "{url}: the client saw the intercepted call or a notice for it"
            );
            let pending = acc.take_pending_intercepted();
            assert_eq!(pending.len(), 1, "{url}: the call is still answered in the loop");
            assert_eq!(pending[0].blocked.is_some(), blocked, "{url}");
            assert_eq!(acc.blocked_tool_infos.len(), usize::from(blocked), "{url}");
        }
    }

    #[test]
    fn non_matching_tool_block_flows_through_normally() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB-CC-WEB-SEARCH")];
        let mut acc = intercept_accumulator(bindings);

        let mut emitted = Vec::new();
        emitted.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_real".into()),
                function_name: Some("not_substituted".into()),
                arguments_delta: r#"{"x":1}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        emitted.extend(acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                native_finish_reason: Some("tool_calls".into()),
            },
            None,
        ));

        // Renderer DOES see the non-matching tool call (unchanged behaviour).
        let tool_calls: Vec<_> = emitted
            .iter()
            .filter(|e| matches!(e.domain_event, Some(DomainEvent::ToolCallDelta { .. })))
            .collect();
        assert!(
            !tool_calls.is_empty(),
            "non-intercepted tool call must reach the renderer"
        );

        // No pending intercepts captured.
        assert!(!acc.has_pending_intercepted());
    }

    #[test]
    fn mixed_pending_flushes_real_suppresses_intercepted() {
        // Plan Decision #4: mixed pending tool-calls — flush real ones,
        // suppress substituted, fold into next round.
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut acc = intercept_accumulator(bindings);

        let mut emitted = Vec::new();
        // First call: substituted, must be suppressed.
        emitted.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_intercepted".into()),
                function_name: Some("web_search".into()),
                arguments_delta: r#"{"query":"q"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        // Second call: real, must flow through.
        emitted.extend(acc.process(
            DomainEvent::ToolCallDelta {
                index: 1,
                id: Some("call_real".into()),
                function_name: Some("read_file".into()),
                arguments_delta: r#"{"path":"/etc"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        ));
        emitted.extend(acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                native_finish_reason: Some("tool_calls".into()),
            },
            None,
        ));

        // Renderer sees exactly one tool call: the real one.
        let names: Vec<String> = emitted
            .iter()
            .filter_map(|e| match &e.domain_event {
                Some(DomainEvent::ToolCallDelta { function_name, .. }) => function_name.clone(),
                _ => None,
            })
            .collect();
        // The real call's opener emits its function_name; the suppressed one is
        // never sent. Continuation deltas with id=None won't carry function_name
        // here so we filter on the opener.
        assert_eq!(names, vec!["read_file"], "only the real tool call should flow through");

        // Pending intercepts contain the substituted call.
        let drained = acc.take_pending_intercepted();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tool_name, "web_search");
        assert_eq!(drained[0].tool_use_id.as_deref(), Some("call_intercepted"));
    }

    #[test]
    fn substituted_block_queued_even_when_done_is_not_tool_calls() {
        // Decision: queueing is decoupled from the Done's finish_reason.
        // The agent loop is the gate that decides whether to dispatch
        // (it MAY refuse on Stop / Length to avoid orphaned tool_use,
        // but that's a downstream policy choice). Pin the contract here
        // so a future refactor doesn't silently change it.
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut acc = intercept_accumulator(bindings);
        let _ = acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_x".into()),
                function_name: Some("web_search".into()),
                arguments_delta: r#"{"q":"x"}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        );
        let _ = acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::Stop),
                native_finish_reason: Some("stop".into()),
            },
            None,
        );
        assert!(
            acc.has_pending_intercepted(),
            "the substituted call must still be queued — the agent loop decides whether to dispatch"
        );
        assert_eq!(acc.pending_intercepted.len(), 1);
    }

    // ── real_calls_the_policy_removes ──

    /// A substitution round is continued, rather than handed to the client,
    /// only when the answer's tool policy removes EVERY real call, each with
    /// the block that removed it. A surviving real call, no rule at all (the
    /// positive control), a Responses built-in call and a Gemini call carrying
    /// a thought signature each keep the round mixed.
    #[test]
    fn real_calls_are_continued_only_when_the_policy_removes_every_one() {
        use crate::api::sse::ApiVersion;
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let withheld = |name: &str| crate::proxy::content::BlockedToolInfo {
            not_applied: false,
            name: name.into(),
            title: "withheld".into(),
            description: "not here".into(),
            rule_id: "R".into(),
            tool_use_id: None,
            call_index: None,
            arguments: None,
        };
        let decide = |response: &serde_json::Value, version, withheld: &[crate::proxy::content::BlockedToolInfo]| {
            real_calls_the_policy_removes(response, version, &bindings, &[], &default_test_profiles(), None, None, withheld, false)
        };
        let anthropic = json!({"content": [
            {"type": "tool_use", "id": "toolu_s", "name": "web_search", "input": {"query": "X"}},
            {"type": "tool_use", "id": "toolu_r", "name": "Read", "input": {"file_path": "/tmp/x"}},
            {"type": "tool_use", "id": "toolu_g", "name": "Grep", "input": {"pattern": "y"}},
        ]});

        let removed = decide(&anthropic, ApiVersion::AnthropicMessages, &[withheld("Read"), withheld("Grep")])
            .expect("every real call is removed");
        assert_eq!(removed.blocked_names, ["Read", "Grep"]);
        let ids: Vec<_> = removed.blocked_infos.iter().map(|b| b.tool_use_id.as_deref()).collect();
        assert_eq!(ids, [Some("toolu_r"), Some("toolu_g")]);
        // The round is continued: the row keeps a later answer, where these
        // places name nothing.
        assert!(removed.blocked_infos.iter().all(|b| b.call_index.is_none()));
        assert!(!removed.healed);

        assert!(decide(&anthropic, ApiVersion::AnthropicMessages, &[withheld("Read")]).is_none(), "Grep survives");
        assert!(decide(&anthropic, ApiVersion::AnthropicMessages, &[]).is_none(), "no rule removes anything");
        assert!(decide(&json!({"content": [
            {"type": "tool_use", "id": "toolu_s", "name": "web_search", "input": {}},
        ]}), ApiVersion::AnthropicMessages, &[withheld("Read")]).is_none(), "no real call");

        let gemini = |signature: Option<&str>| {
            let mut read = json!({"functionCall": {"name": "Read", "args": {"file_path": "/tmp/x"}}});
            if let Some(s) = signature {
                read["thoughtSignature"] = json!(s);
            }
            json!({"candidates": [{"content": {"parts": [read, {"functionCall": {"name": "web_search", "args": {"query": "X"}}}]}}]})
        };
        assert!(decide(&gemini(None), ApiVersion::GoogleGemini, &[withheld("Read")]).is_some());
        assert!(
            decide(&gemini(Some("gsig")), ApiVersion::GoogleGemini, &[withheld("Read")]).is_none(),
            "a signed call keeps the round mixed"
        );

        let function = json!({"output": [
            {"type": "function_call", "call_id": "c1", "name": "web_search", "arguments": "{}"},
            {"type": "function_call", "call_id": "c2", "name": "Read", "arguments": "{\"file_path\":\"/tmp/x\"}"},
        ]});
        assert!(decide(&function, ApiVersion::Responses, &[withheld("Read")]).is_some(), "a function call is removed");
        let builtin = json!({"output": [
            {"type": "function_call", "call_id": "c1", "name": "web_search", "arguments": "{}"},
            {"type": "local_shell_call", "call_id": "c2", "action": {"type": "exec", "command": ["ls"]}},
        ]});
        assert!(
            decide(&builtin, ApiVersion::Responses, &[withheld("local_shell_call")]).is_none(),
            "a built-in call keeps the round mixed"
        );
    }

    // ── extract_pending_intercepts_from_response_json (per-protocol) ──

    #[test]
    fn extract_pending_anthropic_pure_pending() {
        let bindings = vec![make_substitute_binding(
            "web_search",
            "WS-SUB-CC-WEB-SEARCH",
        )];
        let response = json!({
            "type": "message",
            "content": [
                {"type": "text", "text": "Let me look up X"},
                {"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {"query": "X"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "web_search");
        assert_eq!(pending[0].tool_use_id.as_deref(), Some("toolu_1"));
        assert_eq!(pending[0].arguments_json, r#"{"query":"X"}"#);
        assert!(!real_present);
    }

    #[test]
    fn extract_pending_chat_completions_pure_pending() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let response = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Looking up X",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "web_search", "arguments": "{\"query\":\"X\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::ChatCompletions,
            &bindings,
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_use_id.as_deref(), Some("call_1"));
        assert_eq!(pending[0].arguments_json, r#"{"query":"X"}"#);
        assert!(!real_present);
    }

    #[test]
    fn extract_pending_responses_pure_pending() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Searching"}]},
                {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "web_search", "arguments": "{\"query\":\"X\"}"}
            ]
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::Responses,
            &bindings,
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_use_id.as_deref(), Some("call_1"));
        assert!(!real_present);
    }

    #[test]
    fn extract_pending_gemini_pure_pending() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let response = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Searching"},
                        {"functionCall": {"name": "web_search", "args": {"query": "X"}}, "thoughtSignature": "Sig1"},
                        {"functionCall": {"name": "web_search", "args": {"query": "Y"}}}
                    ]
                }
            }]
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::GoogleGemini,
            &bindings,
        );
        assert_eq!(pending.len(), 2);
        assert!(pending[0].tool_use_id.is_none(), "Gemini has no tool id on the wire");
        assert_eq!(pending[0].arguments_json, r#"{"query":"X"}"#);
        // The signature rides the part it came on, for the continuation.
        assert_eq!(pending[0].thought_signature.as_deref(), Some("Sig1"));
        assert_eq!(pending[1].thought_signature, None);
        assert!(!real_present);
    }

    #[test]
    fn extract_pending_anthropic_mixed_pending() {
        // One intercepted + one real tool_use in the same response.
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let response = json!({
            "type": "message",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {"q": "x"}},
                {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {"file_path": "/etc/passwd"}}
            ]
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "web_search");
        assert!(real_present, "Read tool_use must register as a real call");
    }

    #[test]
    fn extract_pending_no_match_when_name_differs() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let response = json!({
            "type": "message",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}}
            ]
        });
        let (pending, real_present) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        assert!(pending.is_empty());
        assert!(real_present);
    }

    #[test]
    fn extract_pending_matches_original_name_when_protocol_renamed() {
        // Cross-protocol translation can revert the substituted name back to
        // the original — the lookup must still match. Same defensive check
        // as `intercept_binding_for` on the streaming side.
        let bindings = vec![crate::proxy::content::InterceptBinding {
            original_name: "WebFetch".to_string(),
            replaced_name: "web_fetch".to_string(),
            rule_id: "WS-SUB".to_string(),
            intercept: crate::config::tool_rules::InterceptKind::WebExecutor {
                kind: crate::config::tool_rules::WebInterceptKind::Fetch,
            },
            action: "substitute".to_string(),
            original_server_type: None,
        }];
        let response = json!({
            "type": "message",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "WebFetch", "input": {"url": "https://x"}}
            ]
        });
        let (pending, _) = extract_pending_intercepts_from_response_json(
            &response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool_name, "WebFetch");
    }

    // ── splice_intercepted_from_response_json ──

    #[test]
    fn splice_anthropic_drops_matched_tool_use() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut response = json!({
            "type": "message",
            "content": [
                {"type": "text", "text": "preamble"},
                {"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {}}
            ]
        });
        splice_intercepted_from_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        assert_eq!(content.len(), 1, "tool_use removed, only text remains");
        assert_eq!(content[0]["type"], "text");
    }

    #[test]
    fn splice_chat_completions_drops_matched_and_unsets_empty_array() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut response = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "hello",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "web_search", "arguments": "{}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        splice_intercepted_from_response_json(
            &mut response,
            crate::api::sse::ApiVersion::ChatCompletions,
            &bindings,
        );
        // tool_calls field removed when empty (don't surface [] to client).
        assert!(
            response["choices"][0]["message"].get("tool_calls").is_none(),
            "empty tool_calls array should be removed from the message"
        );
    }

    #[test]
    fn splice_keeps_non_intercepted_tool_use() {
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut response = json!({
            "type": "message",
            "content": [
                {"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {}},
                {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {"file_path": "/x"}}
            ]
        });
        splice_intercepted_from_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &bindings,
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["name"], "Read");
    }

    // ── inject_substitution_marker_text ──

    #[test]
    fn inject_marker_anthropic_appends_text_block() {
        let mut response = json!({
            "type": "message",
            "content": [{"type": "text", "text": "hello"}]
        });
        inject_substitution_marker_text(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            "[cap reached]",
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "[cap reached]");
    }

    #[test]
    fn inject_marker_chat_completions_concatenates_content_string() {
        let mut response = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hello"}
            }]
        });
        inject_substitution_marker_text(
            &mut response,
            crate::api::sse::ApiVersion::ChatCompletions,
            "[cap]",
        );
        assert_eq!(
            response["choices"][0]["message"]["content"],
            json!("hello\n[cap]")
        );
    }

    // ── extract_preamble_from_response_json ──

    #[test]
    fn preamble_anthropic_concats_text_before_first_tool_use() {
        let response = json!({
            "type": "message",
            "content": [
                {"type": "text", "text": "before-A "},
                {"type": "text", "text": "before-B"},
                {"type": "tool_use", "id": "toolu_1", "name": "web_search", "input": {}},
                {"type": "text", "text": "after — must be dropped"}
            ]
        });
        let preamble = extract_preamble_from_response_json(
            &response,
            crate::api::sse::ApiVersion::AnthropicMessages,
        );
        assert_eq!(preamble, "before-A before-B");
    }

    #[test]
    fn preamble_chat_completions_returns_message_content() {
        let response = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "thinking out loud",
                    "tool_calls": [{
                        "id": "c", "type": "function",
                        "function": {"name": "web_search", "arguments": "{}"}
                    }]
                }
            }]
        });
        let preamble = extract_preamble_from_response_json(
            &response,
            crate::api::sse::ApiVersion::ChatCompletions,
        );
        assert_eq!(preamble, "thinking out loud");
    }

    #[test]
    fn preamble_responses_concats_output_text_before_function_call() {
        let response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "Searching for"},
                    {"type": "output_text", "text": " X"}
                ]},
                {"type": "function_call", "name": "web_search", "arguments": "{}"},
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "after — must be dropped"}
                ]}
            ]
        });
        let preamble = extract_preamble_from_response_json(
            &response,
            crate::api::sse::ApiVersion::Responses,
        );
        assert_eq!(preamble, "Searching for X");
    }

    #[test]
    fn preamble_gemini_concats_text_parts_before_function_call() {
        let response = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "Looking up"},
                        {"text": " X"},
                        {"functionCall": {"name": "web_search", "args": {}}},
                        {"text": "after — must be dropped"}
                    ]
                }
            }]
        });
        let preamble = extract_preamble_from_response_json(
            &response,
            crate::api::sse::ApiVersion::GoogleGemini,
        );
        assert_eq!(preamble, "Looking up X");
    }

    #[test]
    fn no_bindings_yields_no_intercept_overhead() {
        let mut acc = intercept_accumulator(vec![]);
        let emitted = acc.process(
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("c".into()),
                function_name: Some("web_search".into()),
                arguments_delta: r#"{}"#.into(),
                form: crate::api::domain::CallArguments::Json,
            },
            None,
        );
        // No bindings → web_search is just a normal tool call. Buffering is on
        // (interests.buffer_tool_blocks=true) so the opener is buffered and
        // flushes when the next event arrives or the stream completes.
        let _ = emitted;
        let final_emitted = acc.process(
            DomainEvent::Done {
                finish_reason: Some(crate::api::domain::FinishReason::ToolCalls),
                native_finish_reason: Some("tool_calls".into()),
            },
            None,
        );
        let saw_tool_use = final_emitted
            .iter()
            .any(|e| matches!(e.domain_event, Some(DomainEvent::ToolCallDelta { .. })));
        assert!(saw_tool_use, "without bindings, the tool call must reach the renderer");
        assert!(!acc.has_pending_intercepted());
    }

    // ── Visible-mode JSON splice (non-streaming) ─────────────────────────

    fn vm_round_with_one_search(
        server_type: &str,
        preamble: &str,
        query: &str,
        url: &str,
        title: &str,
    ) -> VisibleModeRound {
        VisibleModeRound {
            preamble: preamble.to_string(),
            calls: vec![VisibleModeCall {
                tool_use_id: "tu_sub_test_0".to_string(),
                server_type: server_type.to_string(),
                name: "web_search".to_string(),
                input: json!({"query": query}),
                outcome: VisibleModeOutcome::Success(json!({
                    "hits": [{"url": url, "title": title}],
                    "total_filtered": 0,
                    "backend": "test",
                })),
            }],
        }
    }

    #[test]
    fn inject_visible_mode_no_op_on_empty_rounds() {
        let mut response = json!({"content": [{"type": "text", "text": "hello"}]});
        let original = response.clone();
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &[],
        );
        assert_eq!(response, original, "empty rounds must be a no-op");
    }

    #[test]
    fn inject_visible_mode_anthropic_prepends_blocks_with_preamble() {
        let mut response = json!({
            "content": [
                {"type": "text", "text": "Based on the search, X is..."}
            ]
        });
        let rounds = vec![vm_round_with_one_search(
            "web_search_20250305",
            "Let me search for that.",
            "what is X",
            "https://example.com/x",
            "About X",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &rounds,
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        assert_eq!(content.len(), 4, "preamble + server_tool_use + result + final text = 4");
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "Let me search for that.");
        assert_eq!(content[1]["type"], "server_tool_use");
        assert_eq!(content[1]["id"], "tu_sub_test_0");
        assert_eq!(content[1]["name"], "web_search");
        assert_eq!(content[1]["input"]["query"], "what is X");
        assert_eq!(content[2]["type"], "web_search_tool_result");
        assert_eq!(content[2]["tool_use_id"], "tu_sub_test_0");
        let result_content = content[2]["content"].as_array().unwrap();
        assert_eq!(result_content[0]["type"], "web_search_result");
        assert_eq!(result_content[0]["url"], "https://example.com/x");
        assert_eq!(content[3]["type"], "text");
        assert_eq!(content[3]["text"], "Based on the search, X is...");
    }

    #[test]
    fn inject_visible_mode_anthropic_skips_preamble_block_when_empty() {
        let mut response = json!({"content": [{"type": "text", "text": "ans"}]});
        let mut round = vm_round_with_one_search(
            "web_search_20250305",
            "",
            "q",
            "https://e.com",
            "T",
        );
        round.preamble.clear();
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &[round],
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        // No preamble block at index 0 — server_tool_use leads.
        assert_eq!(content[0]["type"], "server_tool_use");
        assert_eq!(content[1]["type"], "web_search_tool_result");
        assert_eq!(content[2]["type"], "text");
    }

    #[test]
    fn inject_visible_mode_anthropic_renders_error_outcome() {
        let mut response = json!({"content": [{"type": "text", "text": "I couldn't search."}]});
        let rounds = vec![VisibleModeRound {
            preamble: String::new(),
            calls: vec![VisibleModeCall {
                tool_use_id: "tu_sub_test_err".to_string(),
                server_type: "web_search_20250305".to_string(),
                name: "web_search".to_string(),
                input: json!({"query": "q"}),
                outcome: VisibleModeOutcome::Error("no_backend".to_string()),
            }],
        }];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &rounds,
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        assert_eq!(content[0]["type"], "server_tool_use");
        assert_eq!(content[1]["type"], "web_search_tool_result");
        assert_eq!(
            content[1]["content"]["type"],
            "web_search_tool_result_error"
        );
        assert_eq!(content[1]["content"]["error_code"], "no_backend");
    }

    #[test]
    fn inject_visible_mode_anthropic_two_rounds_in_order() {
        let mut response = json!({"content": [{"type": "text", "text": "Final answer"}]});
        let r0 = vm_round_with_one_search(
            "web_search_20250305",
            "First search.",
            "q1",
            "https://r0",
            "R0",
        );
        let r1 = vm_round_with_one_search(
            "web_search_20250305",
            "Second search.",
            "q2",
            "https://r1",
            "R1",
        );
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &[r0, r1],
        );
        let content = response.get("content").and_then(|c| c.as_array()).unwrap();
        // [r0_preamble, r0_st_use, r0_result, r1_preamble, r1_st_use, r1_result, final_text]
        assert_eq!(content.len(), 7);
        assert_eq!(content[0]["text"], "First search.");
        assert_eq!(content[1]["input"]["query"], "q1");
        assert_eq!(content[3]["text"], "Second search.");
        assert_eq!(content[4]["input"]["query"], "q2");
        assert_eq!(content[6]["text"], "Final answer");
    }

    #[test]
    fn inject_visible_mode_gemini_attaches_grounding_metadata() {
        let mut response = json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Result text"}]},
                "finishReason": "STOP"
            }]
        });
        let rounds = vec![vm_round_with_one_search(
            "google_search",
            "preamble (ignored for Gemini)",
            "what is foo",
            "https://foo.example",
            "Foo",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::GoogleGemini,
            &rounds,
        );
        let grounding = response["candidates"][0]
            .get("groundingMetadata")
            .expect("groundingMetadata attached");
        let chunks = grounding.get("groundingChunks").and_then(|c| c.as_array()).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0]["web"]["uri"], "https://foo.example");
        let queries = grounding
            .get("webSearchQueries")
            .and_then(|c| c.as_array())
            .unwrap();
        assert_eq!(queries, &vec![Value::String("what is foo".to_string())]);
    }

    #[test]
    fn inject_visible_mode_gemini_dedupes_uris_across_rounds() {
        let mut response = json!({
            "candidates": [{"content": {"role": "model", "parts": []}}]
        });
        // Two rounds, second hits the same URL — single chunk in output.
        let r0 = vm_round_with_one_search(
            "google_search",
            "",
            "q1",
            "https://shared",
            "Shared",
        );
        let r1 = vm_round_with_one_search(
            "google_search",
            "",
            "q2",
            "https://shared",
            "Shared",
        );
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::GoogleGemini,
            &[r0, r1],
        );
        let grounding = &response["candidates"][0]["groundingMetadata"];
        assert_eq!(grounding["groundingChunks"].as_array().unwrap().len(), 1);
        // Queries are NOT deduped to identity: two distinct queries land
        // both. (Same query across rounds dedupes — covered by the streaming
        // unit test on the builder.)
        assert_eq!(
            grounding["webSearchQueries"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn inject_visible_mode_responses_prepends_web_search_call_items() {
        let mut response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "Done."}
                ]}
            ]
        });
        let rounds = vec![vm_round_with_one_search(
            "web_search_preview",
            "",
            "find X",
            "https://x",
            "X",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        let output = response.get("output").and_then(|o| o.as_array()).unwrap();
        assert_eq!(output.len(), 2, "web_search_call prepended ahead of message");
        assert_eq!(output[0]["type"], "web_search_call");
        assert_eq!(output[0]["id"], "tu_sub_test_0");
        assert_eq!(output[0]["status"], "completed");
        assert_eq!(output[0]["action"]["type"], "search");
        assert_eq!(output[0]["action"]["query"], "find X");
        assert_eq!(output[1]["type"], "message");
    }

    #[test]
    fn inject_visible_mode_responses_marks_failed_status_on_error() {
        let mut response = json!({"output": []});
        let rounds = vec![VisibleModeRound {
            preamble: String::new(),
            calls: vec![VisibleModeCall {
                tool_use_id: "tu_sub_err".to_string(),
                server_type: "web_search_preview".to_string(),
                name: "web_search".to_string(),
                input: json!({"query": "q"}),
                outcome: VisibleModeOutcome::Error("filter_blocked".to_string()),
            }],
        }];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        let output = response.get("output").and_then(|o| o.as_array()).unwrap();
        assert_eq!(output[0]["status"], "failed");
    }

    #[test]
    fn inject_visible_mode_responses_decorates_message_with_url_citations() {
        // The first assistant `message` item in `output[]` should gain
        // `url_citation` annotations on each `output_text` content part —
        // byte-spans when the URL appears verbatim, span-less otherwise.
        let mut response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "See https://example.com/x for more."}
                ]}
            ]
        });
        let rounds = vec![vm_round_with_one_search(
            "web_search_preview",
            "",
            "what is X",
            "https://example.com/x",
            "About X",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        let output = response.get("output").and_then(|o| o.as_array()).unwrap();
        let msg = output.iter().find(|i| i["type"] == "message").unwrap();
        let parts = msg["content"].as_array().unwrap();
        let annotations = parts[0]["annotations"].as_array().unwrap();
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["type"], "url_citation");
        assert_eq!(annotations[0]["url"], "https://example.com/x");
        assert_eq!(annotations[0]["title"], "About X");
        // "See https://example.com/x for more." — URL starts at byte 4.
        assert_eq!(annotations[0]["start_index"], 4);
        assert_eq!(annotations[0]["end_index"], 4 + "https://example.com/x".len());
    }

    #[test]
    fn inject_visible_mode_responses_url_citation_falls_back_when_no_substring_match() {
        let mut response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "Based on the search, the answer is yes."}
                ]}
            ]
        });
        let rounds = vec![vm_round_with_one_search(
            "web_search_preview",
            "",
            "q",
            "https://example.com/blog",
            "Some Blog",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        let output = response.get("output").and_then(|o| o.as_array()).unwrap();
        let msg = output.iter().find(|i| i["type"] == "message").unwrap();
        let annotations = msg["content"][0]["annotations"].as_array().unwrap();
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0]["url"], "https://example.com/blog");
        assert!(annotations[0].get("start_index").is_none());
        assert!(annotations[0].get("end_index").is_none());
    }

    #[test]
    fn inject_visible_mode_responses_url_citation_no_op_on_failed_dispatch() {
        // Failed dispatches carry no URLs to cite — annotations[] stays
        // absent and the message content is unchanged.
        let mut response = json!({
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "I couldn't search."}
                ]}
            ]
        });
        let rounds = vec![VisibleModeRound {
            preamble: String::new(),
            calls: vec![VisibleModeCall {
                tool_use_id: "tu_x".to_string(),
                server_type: "web_search_preview".to_string(),
                name: "web_search".to_string(),
                input: json!({"query": "q"}),
                outcome: VisibleModeOutcome::Error("no_backend".to_string()),
            }],
        }];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        let output = response.get("output").and_then(|o| o.as_array()).unwrap();
        let msg = output.iter().find(|i| i["type"] == "message").unwrap();
        assert!(
            msg["content"][0].get("annotations").is_none(),
            "no annotations when dispatch failed: {msg}"
        );
    }

    #[test]
    fn compute_url_citations_prefers_url_match_over_title_match() {
        let sources = vec![UrlCitationSource {
            url: "https://example.com/x".to_string(),
            title: Some("About X".to_string()),
        }];
        // Text contains both URL and title — URL match wins.
        let cites = compute_url_citations("see https://example.com/x About X", &sources);
        assert_eq!(cites.len(), 1);
        assert_eq!(cites[0].start_index, Some(4));
        assert_eq!(
            cites[0].end_index,
            Some(4 + "https://example.com/x".len())
        );
    }

    #[test]
    fn compute_url_citations_falls_back_to_title_when_url_missing() {
        let sources = vec![UrlCitationSource {
            url: "https://example.com/x".to_string(),
            title: Some("About X".to_string()),
        }];
        let cites = compute_url_citations("the doc About X covers it", &sources);
        assert_eq!(cites.len(), 1);
        // Title "About X" starts at byte 8 in "the doc About X covers it".
        assert_eq!(cites[0].start_index, Some(8));
        assert_eq!(cites[0].end_index, Some(8 + "About X".len()));
    }

    #[test]
    fn compute_url_citations_skips_title_match_below_min_bytes() {
        // 1-3 char titles ("X", "AI") would match stray prose and produce
        // wrong spans. Floor enforces a minimum byte length before the
        // title-fallback fires; URLs not matched verbatim get span-less
        // annotations.
        let sources = vec![UrlCitationSource {
            url: "https://example.com/x".to_string(),
            title: Some("AI".to_string()),
        }];
        let cites = compute_url_citations("AI is everywhere these days.", &sources);
        assert_eq!(cites.len(), 1);
        assert!(
            cites[0].start_index.is_none(),
            "short title must not match: {cites:?}"
        );
    }

    #[test]
    fn compute_url_citations_emits_spanless_when_no_match() {
        let sources = vec![UrlCitationSource {
            url: "https://example.com/x".to_string(),
            title: Some("About X".to_string()),
        }];
        let cites = compute_url_citations("nothing related here.", &sources);
        assert_eq!(cites.len(), 1);
        assert!(cites[0].start_index.is_none());
        assert!(cites[0].end_index.is_none());
    }

    #[test]
    fn collect_visible_mode_url_sources_dedups_by_url() {
        let rounds = vec![
            vm_round_with_one_search(
                "web_search_preview",
                "",
                "q1",
                "https://example.com/x",
                "X",
            ),
            vm_round_with_one_search(
                "web_search_preview",
                "",
                "q2",
                "https://example.com/x",
                "X",
            ),
        ];
        let sources = collect_visible_mode_url_sources(&rounds);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "https://example.com/x");
    }

    #[test]
    fn extract_url_citation_sources_handles_fetch_result() {
        let content = json!({
            "url": "https://example.com/page",
            "final_url": "https://example.com/page-canonical",
            "content_type": "text/html",
            "extracted_text": "body",
        });
        let sources = extract_url_citation_sources_from_search_content(&content);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].url, "https://example.com/page-canonical");
        assert_eq!(sources[0].title.as_deref(), Some("text/html"));
    }

    #[test]
    fn inject_visible_mode_anthropic_no_op_when_content_missing() {
        // Upstream-error or unexpected shape with no `content` array —
        // walker must early-return without panicking.
        let mut response = json!({"error": {"message": "boom"}});
        let original = response.clone();
        let rounds = vec![vm_round_with_one_search(
            "web_search_20250305",
            "",
            "q",
            "https://e",
            "T",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::AnthropicMessages,
            &rounds,
        );
        assert_eq!(response, original, "missing content[] must be a no-op");
    }

    #[test]
    fn inject_visible_mode_gemini_no_op_when_candidates_missing() {
        let mut response = json!({"error": {"message": "boom"}});
        let original = response.clone();
        let rounds = vec![vm_round_with_one_search(
            "google_search",
            "",
            "q",
            "https://e",
            "T",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::GoogleGemini,
            &rounds,
        );
        assert_eq!(response, original, "missing candidates[] must be a no-op");
    }

    #[test]
    fn inject_visible_mode_responses_no_op_when_output_missing() {
        let mut response = json!({"error": {"message": "boom"}});
        let original = response.clone();
        let rounds = vec![vm_round_with_one_search(
            "web_search_preview",
            "",
            "q",
            "https://e",
            "T",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::Responses,
            &rounds,
        );
        assert_eq!(response, original, "missing output[] must be a no-op");
    }

    #[test]
    fn inject_visible_mode_gemini_emits_both_keys_even_when_no_chunks() {
        // Error-only outcome: query is captured (model tried), no chunks
        // (no successful dispatch). Walker must still attach
        // `groundingMetadata` with both keys present (matches streaming
        // builder's emit_final_chunk shape).
        let mut response = json!({
            "candidates": [{"content": {"role": "model", "parts": []}}]
        });
        let rounds = vec![VisibleModeRound {
            preamble: String::new(),
            calls: vec![VisibleModeCall {
                tool_use_id: "tu_sub_e".to_string(),
                server_type: "google_search".to_string(),
                name: "web_search".to_string(),
                input: json!({"query": "Q"}),
                outcome: VisibleModeOutcome::Error("filter_blocked".to_string()),
            }],
        }];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::GoogleGemini,
            &rounds,
        );
        let grounding = &response["candidates"][0]["groundingMetadata"];
        assert!(
            grounding.get("groundingChunks").is_some()
                && grounding.get("webSearchQueries").is_some(),
            "both keys must be present on stable contract"
        );
        assert_eq!(grounding["groundingChunks"].as_array().unwrap().len(), 0);
        assert_eq!(grounding["webSearchQueries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn inject_visible_mode_chat_completions_is_no_op() {
        let mut response = json!({
            "choices": [{
                "message": {"role": "assistant", "content": "answer"},
                "finish_reason": "stop"
            }]
        });
        let original = response.clone();
        let rounds = vec![vm_round_with_one_search(
            "web_search_preview",
            "ignored",
            "q",
            "https://e.com",
            "T",
        )];
        inject_visible_mode_blocks_into_response_json(
            &mut response,
            crate::api::sse::ApiVersion::ChatCompletions,
            &rounds,
        );
        assert_eq!(response, original, "ChatCompletions has no native shape");
    }

    // ── What a pass-through client is actually handed ──
    //
    // A block held for inspection is the gateway's business; the frames around
    // it are the client's. These drive the same three steps the response
    // pipeline does — parse, accumulate, emit — and look only at the bytes that
    // reach the caller.

    /// Frames a client is handed, as `(SSE event name, data)`.
    fn client_frames(
        api: crate::api::sse::ApiVersion,
        upstream: &[(&str, serde_json::Value)],
        acc: &mut BlockAccumulator,
    ) -> Vec<(Option<String>, serde_json::Value)> {
        use crate::pipeline::response_pipeline::EventEmitter;
        assert_eq!(
            acc.calls_arrive_whole,
            api == crate::api::sse::ApiVersion::GoogleGemini,
            "build the accumulator for the upstream it reads"
        );
        let mut emitter = EventEmitter::new(api, api, "model-x", "req-1", None, None, 0, 0);
        let mut bytes: Vec<u8> = Vec::new();
        let emit = |emitter: &mut EventEmitter, out: Vec<BufferedEvent>, bytes: &mut Vec<u8>| {
            for buffered in &out {
                for chunk in emitter.process_buffered(buffered) {
                    bytes.extend_from_slice(&chunk);
                }
            }
        };
        // The stream's own parser, as the pipeline runs it: it closes a
        // freeform call where the stream ends it.
        let mut parser = crate::api::sse::StreamParser::new(api);
        for (name, data) in upstream {
            // Chat Completions and Gemini frames carry no SSE event name.
            let event = SseEvent {
                event_type: (!name.is_empty()).then(|| (*name).to_string()),
                data: data.to_string(),
                id: None,
            };
            emitter.observe_upstream(&event);
            let domain = parser.parse(&event);
            let out = if domain.is_empty() {
                acc.process_raw(
                    event.clone(),
                    crate::pipeline::response_pipeline::frame_opens_container(&event, api),
                )
            } else {
                let frames = crate::pipeline::response_pipeline::split_frame(&event, api, &domain, true);
                let mut out = Vec::new();
                for (de, raw) in domain.into_iter().zip(frames) {
                    out.extend(acc.process(de, raw));
                }
                out
            };
            emit(&mut emitter, out, &mut bytes);
        }
        for end in parser.finish() {
            let out = acc.process(end, None);
            emit(&mut emitter, out, &mut bytes);
        }
        let tail = acc.flush();
        emit(&mut emitter, tail, &mut bytes);

        let text = String::from_utf8(bytes).expect("SSE bytes are UTF-8");
        text.split("\n\n")
            .filter(|frame| !frame.trim().is_empty())
            .map(|frame| {
                let mut name = None;
                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(rest) = line.strip_prefix("event: ") {
                        name = Some(rest.to_string());
                    } else if let Some(rest) = line.strip_prefix("data: ") {
                        data.push_str(rest);
                    }
                }
                let value = serde_json::from_str(&data)
                    .unwrap_or(serde_json::Value::String(data.clone()));
                (name, value)
            })
            .collect()
    }

    fn frame_types(frames: &[(Option<String>, serde_json::Value)]) -> Vec<String> {
        frames
            .iter()
            .map(|(name, data)| {
                name.clone()
                    .or_else(|| data.get("type").and_then(|t| t.as_str()).map(str::to_string))
                    .unwrap_or_default()
            })
            .collect()
    }

    fn text_accumulator(rules: Vec<crate::config::tool_rules::Rule>) -> BlockAccumulator {
        text_accumulator_for(crate::api::sse::ApiVersion::ChatCompletions, rules)
    }

    fn text_accumulator_for(
        upstream: crate::api::sse::ApiVersion,
        rules: Vec<crate::config::tool_rules::Rule>,
    ) -> BlockAccumulator {
        BlockAccumulator::new(
            BlockInterests {
                buffer_tool_blocks: true,
                buffer_text_blocks: true,
                buffer_thinking_blocks: false,
            },
            rules,
            Arc::new(default_test_profiles()),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            upstream,
        )
    }

    /// An Anthropic message with one text block, then one tool call.
    fn anthropic_upstream() -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("message_start", json!({"type": "message_start", "message": {"id": "msg_1", "usage": {"input_tokens": 5}}})),
            ("content_block_start", json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hello"}})),
            ("content_block_stop", json!({"type": "content_block_stop", "index": 0})),
            ("content_block_start", json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"file_path\":\"/etc/passwd\"}"}})),
            ("content_block_stop", json!({"type": "content_block_stop", "index": 1})),
            ("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}})),
            ("message_stop", json!({"type": "message_stop"})),
        ]
    }

    #[test]
    fn a_buffering_pass_through_hands_the_client_every_frame_the_upstream_sent() {
        // Nothing here is blocked or rewritten — the blocks are held only to be
        // looked at. The client must still be handed the frames that open and
        // close each one and the frame that ends the message: without them the
        // stream is not a message, and an SDK refuses it.
        let mut acc = text_accumulator(vec![]);
        let upstream = anthropic_upstream();
        let frames = client_frames(crate::api::sse::ApiVersion::AnthropicMessages, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(frame_types(&frames), expected);
    }

    #[test]
    fn a_blocked_tool_call_leaves_the_client_a_block_it_can_read() {
        // The call's own opening frame went with it, so the notice that stands
        // in for it needs a block of its own — at the index the call left free,
        // since the index is the block's place in the final message. And the
        // call's closing frame must not be forwarded: it would close a block
        // the client was never given.
        let rules = rules_from_json(vec![json!({
            "id": "T-9579",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let frames = client_frames(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &anthropic_upstream(),
            &mut acc,
        );

        // Every block the client is given is opened and closed exactly once,
        // and no close arrives for a block it never got.
        let mut open: Vec<u64> = Vec::new();
        let mut closed: Vec<u64> = Vec::new();
        for (name, data) in &frames {
            let index = data.get("index").and_then(serde_json::Value::as_u64);
            match name.as_deref() {
                Some("content_block_start") => open.push(index.expect("start carries an index")),
                Some("content_block_stop") => {
                    let index = index.expect("stop carries an index");
                    assert!(open.contains(&index), "closed block {index} was never opened: {frames:?}");
                    closed.push(index);
                }
                _ => {}
            }
        }
        assert_eq!(open, vec![0, 1], "{frames:?}");
        assert_eq!(closed, vec![0, 1], "{frames:?}");

        // The notice is inside the second block, not loose between frames.
        let notice = frames
            .iter()
            .position(|(name, data)| {
                name.as_deref() == Some("content_block_delta")
                    && data["delta"]["text"].as_str().is_some_and(|t| t.contains("blocked by policy"))
            })
            .expect("the client must be told why the call is gone");
        assert_eq!(frames[notice].1["index"], 1);
        assert_eq!(frame_types(&frames)[notice - 1], "content_block_start");
        assert_eq!(frame_types(&frames)[notice + 1], "content_block_stop");
        // No tool call reached the client.
        assert!(
            !frames.iter().any(|(_, d)| d["content_block"]["type"] == "tool_use"
                || d["delta"]["type"] == "input_json_delta"),
            "{frames:?}"
        );
    }

    /// A Responses stream with one message item, then one function call. The
    /// upstream numbers its own events from 0, as the spec requires.
    fn responses_upstream() -> Vec<(&'static str, serde_json::Value)> {
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "hello", "logprobs": []}))),
            ("response.output_text.done", next(json!({"type": "response.output_text.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": "hello", "logprobs": []}))),
            ("response.content_part.done", next(json!({"type": "response.content_part.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "hello", "annotations": [], "logprobs": []}}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "hello", "annotations": [], "logprobs": []}]}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 1, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "", "status": "in_progress"}}))),
            ("response.function_call_arguments.delta", next(json!({"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 1, "delta": "{\"file_path\":\"/etc/passwd\"}"}))),
            ("response.function_call_arguments.done", next(json!({"type": "response.function_call_arguments.done", "item_id": "fc_1", "output_index": 1, "arguments": "{\"file_path\":\"/etc/passwd\"}"}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 1, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}", "status": "completed"}}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": [
                {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "hello", "annotations": [], "logprobs": []}]},
                {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}", "status": "completed"}
            ], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}}))),
        ]
    }

    #[test]
    fn a_responses_pass_through_keeps_the_frames_and_their_numbering() {
        // Every Responses event carries its position in the stream, counted
        // from 0 — over the stream the CLIENT receives, which stops being the
        // upstream's count the moment a frame is held back or added.
        let mut acc = text_accumulator(vec![]);
        let upstream = responses_upstream();
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(frame_types(&frames), expected);
        let numbers: Vec<u64> = frames
            .iter()
            .map(|(_, d)| d["sequence_number"].as_u64().expect("every event is numbered"))
            .collect();
        assert_eq!(numbers, (0..frames.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn a_message_part_open_when_the_view_diverges_is_restated_whole() {
        // Bytes of no call are withheld while a message's text is streaming,
        // and the notice saying so goes into that open part. Every statement
        // of the part's finished text then says what the client assembled
        // from the deltas — from the part's start, not from the divergence.
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        let part = |text: &str| json!({"type": "output_text", "text": text, "annotations": [], "logprobs": []});
        let upstream = vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": part("")}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "Hello ", "logprobs": []}))),
            ("response.function_call_arguments.delta", next(json!({"type": "response.function_call_arguments.delta", "item_id": "fc_9", "output_index": 7, "delta": "{\"x\":1}"}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "world", "logprobs": []}))),
            ("response.output_text.done", next(json!({"type": "response.output_text.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": "Hello world", "logprobs": []}))),
            ("response.content_part.done", next(json!({"type": "response.content_part.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": part("Hello world")}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [part("Hello world")]}}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": [
                {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [part("Hello world")]}
            ], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}}))),
        ];
        // Text is not held: "Hello " reaches the client before the divergence.
        let mut acc = intercept_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let assembled = streamed_text(&frames, 0);
        assert!(
            assembled.starts_with("Hello ") && assembled.contains(crate::pipeline::response::WITHHELD_NOTICE.trim()) && assembled.ends_with("world"),
            "{frames:?}"
        );
        let stated = |kind: &str, pointer: &str| -> String {
            frames
                .iter()
                .find(|(_, d)| d["type"] == kind)
                .and_then(|(_, d)| d.pointer(pointer).and_then(|t| t.as_str()).map(str::to_string))
                .unwrap_or_else(|| panic!("no {kind}: {frames:?}"))
        };
        assert_eq!(stated("response.output_text.done", "/text"), assembled);
        assert_eq!(stated("response.content_part.done", "/part/text"), assembled);
        assert_eq!(stated("response.output_item.done", "/item/content/0/text"), assembled);
        assert_eq!(stated("response.completed", "/response/output/0/content/0/text"), assembled);
    }

    #[test]
    fn a_blocked_call_is_replaced_by_an_item_the_client_can_read() {
        // The call's item never reached the client, so the notice standing in
        // for it opens one of its own and closes it, and nothing the client was
        // not given is addressed or closed afterwards.
        let rules = rules_from_json(vec![json!({
            "id": "T-9729",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let frames = client_frames(
            crate::api::sse::ApiVersion::Responses,
            &responses_upstream(),
            &mut acc,
        );
        let types = frame_types(&frames);

        // Numbering still counts what the client got, with no gap or repeat.
        let numbers: Vec<u64> = frames
            .iter()
            .map(|(_, d)| d["sequence_number"].as_u64().expect("every event is numbered"))
            .collect();
        assert_eq!(numbers, (0..frames.len() as u64).collect::<Vec<_>>(), "{types:?}");

        // No function call reached the client, in any frame.
        assert!(
            !frames.iter().any(|(_, d)| d["item"]["type"] == "function_call"
                || d["type"] == "response.function_call_arguments.delta"
                || d["type"] == "response.function_call_arguments.done"),
            "a blocked call reached the client: {frames:?}"
        );

        // The notice rides an item that is opened and closed around it.
        let notice = frames
            .iter()
            .position(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("blocked by policy")))
            .expect("the client must be told why the call is gone");
        assert_eq!(types[notice - 2], "response.output_item.added");
        assert_eq!(types[notice - 1], "response.content_part.added");
        assert_eq!(types[notice + 1], "response.output_text.done");
        assert_eq!(types.last().map(String::as_str), Some("response.completed"));
        // Every item the client sees opened is one it sees closed.
        let opened: Vec<u64> = frames.iter()
            .filter(|(_, d)| d["type"] == "response.output_item.added")
            .map(|(_, d)| d["output_index"].as_u64().unwrap())
            .collect();
        let done: Vec<u64> = frames.iter()
            .filter(|(_, d)| d["type"] == "response.output_item.done")
            .map(|(_, d)| d["output_index"].as_u64().unwrap())
            .collect();
        assert_eq!(opened, done, "{types:?}");
        assert_eq!(opened, vec![0, 1]);
    }

    #[test]
    fn a_chat_notice_carries_the_streams_own_identity() {
        // Every chunk of a Chat Completions stream repeats the response id,
        // model and creation time; a chunk that names none is not a chunk of
        // this stream, and a strict client rejects it.
        let rules = rules_from_json(vec![json!({
            "id": "T-9786",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let upstream = vec![
            ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "hi"}, "finish_reason": null}]})),
            ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}, "finish_reason": null}]})),
            ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let notice = frames
            .iter()
            .find(|(_, d)| d["choices"][0]["delta"]["content"]
                .as_str()
                .is_some_and(|t| t.contains("blocked by policy")))
            .expect("the client must be told why the call is gone");
        assert_eq!(notice.1["id"], "chatcmpl-9");
        assert_eq!(notice.1["model"], "gpt-x");
        assert_eq!(notice.1["created"], 1_700_000_000u64);
        assert_eq!(notice.1["object"], "chat.completion.chunk");
    }

    #[test]
    fn a_number_written_inside_a_delta_is_not_the_events_own() {
        // The model can write anything, including the shape of the field that
        // orders the stream. The number that counts is the event's, read from
        // the parsed frame — not the first one that appears in its bytes.
        let rules = rules_from_json(vec![json!({
            "id": "T-9817",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let mut upstream = responses_upstream();
        // A delta whose text is itself a sequence-number field.
        upstream[3].1["delta"] = json!("{\"sequence_number\": 99}");
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let numbers: Vec<u64> = frames
            .iter()
            .map(|(_, d)| d["sequence_number"].as_u64().expect("every event is numbered"))
            .collect();
        assert_eq!(numbers, (0..frames.len() as u64).collect::<Vec<_>>(), "{frames:?}");
    }

    #[test]
    fn two_items_open_at_once_both_reach_the_client() {
        // Whether an upstream may have two items open at a time is its choice,
        // not the gateway's: a record that can only hold one would drop the
        // frames of whichever came second, turning a working stream into a
        // broken one.
        let mut acc = text_accumulator(vec![]);
        let upstream: Vec<(&str, serde_json::Value)> = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": {"id": "rs_1", "type": "reasoning", "summary": []}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 2, "output_index": 1, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}})),
            ("response.content_part.added", json!({"type": "response.content_part.added", "sequence_number": 3, "item_id": "msg_1", "output_index": 1, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}})),
            ("response.output_text.delta", json!({"type": "response.output_text.delta", "sequence_number": 4, "item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": "hi", "logprobs": []})),
            // The first item is still open and closes last.
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 5, "output_index": 1, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "hi", "annotations": [], "logprobs": []}]}})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 6, "output_index": 0, "item": {"id": "rs_1", "type": "reasoning", "summary": []}})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 7, "response": {"id": "resp_1", "status": "completed"}})),
        ];
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(frame_types(&frames), expected);
    }

    #[test]
    fn the_terminal_sentinel_reaches_the_client_and_is_not_numbered() {
        // An OpenAI-compatible stream can end with `data: [DONE]`. It is not an
        // event and carries no number, but it is how a client's loop ends —
        // dropping it leaves the client waiting on the connection instead.
        let mut acc = text_accumulator(vec![]);
        let mut upstream = responses_upstream();
        upstream.push(("", json!("[DONE]")));
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(
            frames.last().map(|(_, d)| d.clone()),
            Some(json!("[DONE]")),
            "the sentinel never reached the client: {frames:?}"
        );
        let numbers: Vec<u64> = frames
            .iter()
            .filter_map(|(_, d)| d.get("sequence_number").and_then(serde_json::Value::as_u64))
            .collect();
        assert_eq!(numbers, (0..numbers.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn a_stream_that_ends_mid_block_still_hands_over_what_it_held() {
        // An upstream can stop anywhere. Whatever the accumulator was holding —
        // the block's content and the frames waiting behind it — is the
        // client's, and the flush at stream end is the only thing that can
        // deliver it.
        let mut acc = text_accumulator(vec![]);
        let upstream: Vec<(&str, serde_json::Value)> = anthropic_upstream()
            .into_iter()
            .take(3) // message_start, content_block_start, one delta
            .collect();
        let frames = client_frames(crate::api::sse::ApiVersion::AnthropicMessages, &upstream, &mut acc);
        assert_eq!(
            frame_types(&frames),
            vec!["message_start", "content_block_start", "content_block_delta"],
            "{frames:?}"
        );
    }

    #[test]
    fn a_second_item_keeps_its_own_text_and_the_frames_that_address_it() {
        // Two message items with a server-tool call between them: none of the
        // frames that open the second item carry content, and the accumulator
        // groups by block kind rather than by the upstream's items — so without
        // the boundary the second item's text merges into the first, leaves
        // ahead of the frames that address it, and is then dropped as naming an
        // item the client was never given.
        let mut acc = text_accumulator(vec![]);
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        let upstream: Vec<(&str, serde_json::Value)> = vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "first", "logprobs": []}))),
            ("response.content_part.done", next(json!({"type": "response.content_part.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "first", "annotations": [], "logprobs": []}}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "first", "annotations": [], "logprobs": []}]}}))),
            // A server-tool item: every one of its frames carries no domain event.
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 1, "item": {"id": "ws_1", "type": "web_search_call", "status": "in_progress"}}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 1, "item": {"id": "ws_1", "type": "web_search_call", "status": "completed"}}))),
            // The second message.
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 2, "item": {"id": "msg_2", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_2", "output_index": 2, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_2", "output_index": 2, "content_index": 0, "delta": "second", "logprobs": []}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 2, "item": {"id": "msg_2", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "second", "annotations": [], "logprobs": []}]}}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed"}}))),
        ];
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(frame_types(&frames), expected, "{frames:?}");
        let deltas: Vec<&str> = frames
            .iter()
            .filter(|(_, d)| d["type"] == "response.output_text.delta")
            .map(|(_, d)| d["delta"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(deltas, vec!["first", "second"], "{frames:?}");
    }

    #[test]
    fn a_rewritten_call_is_a_whole_item_of_its_own() {
        // A rewritten call's own `output_item.added` went with the block being
        // rebuilt, so the client never saw the item open. The replacement is a
        // complete item — opened, its arguments delivered, closed — and nothing
        // afterwards names the upstream's item, which the client does not have.
        let rules = rules_from_json(vec![json!({
            "id": "T-9948",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "arg.file_path", "op": "glob", "value": "/etc/*" }],
            "action": { "kind": "replace", "with": "/tmp/safe" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let frames = client_frames(
            crate::api::sse::ApiVersion::Responses,
            &responses_upstream(),
            &mut acc,
        );

        // The rewritten arguments reached the client.
        let delta = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.function_call_arguments.delta")
            .expect("the call never reached the client");
        assert!(
            delta.1["delta"].as_str().is_some_and(|a| a.contains("/tmp/safe")),
            "the client got the arguments policy replaced: {delta:?}"
        );

        // Every item opened is closed, and the call's item is one of them.
        let opened: Vec<u64> = frames.iter()
            .filter(|(_, d)| d["type"] == "response.output_item.added")
            .map(|(_, d)| d["output_index"].as_u64().unwrap())
            .collect();
        let done: Vec<u64> = frames.iter()
            .filter(|(_, d)| d["type"] == "response.output_item.done")
            .map(|(_, d)| d["output_index"].as_u64().unwrap())
            .collect();
        assert_eq!(opened, done, "an item was left open: {frames:?}");

        // No frame addresses the upstream's own item for that call.
        let call_item = delta.1["item_id"].as_str().expect("the delta names its item");
        assert_ne!(call_item, "fc_1");
        assert!(
            !frames.iter().any(|(_, d)| d["item_id"] == "fc_1" || d["item"]["id"] == "fc_1"),
            "a frame names an item the client was never given: {frames:?}"
        );

        // And the stream is still numbered over what the client received.
        let numbers: Vec<u64> = frames
            .iter()
            .filter_map(|(_, d)| d.get("sequence_number").and_then(serde_json::Value::as_u64))
            .collect();
        assert_eq!(numbers, (0..numbers.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn a_notice_on_a_stream_that_opened_with_a_tool_call_still_names_a_model() {
        // Many OpenAI-compatible servers put the role and the first tool call in
        // the same chunk, so the gateway is holding that chunk when the policy
        // fires and NOTHING has been forwarded. The notice is still part of the
        // upstream's stream, so it carries that stream's identity — read from
        // the chunk being held — never an empty model or a second id.
        let rules = rules_from_json(vec![json!({
            "id": "T-10006",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let upstream = vec![
            ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x", "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}, "finish_reason": null}]})),
            ("", json!({"id": "chatcmpl-9", "object": "chat.completion.chunk", "created": 1_700_000_000u64, "model": "gpt-x", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})),
        ];
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let notice = frames
            .iter()
            .find(|(_, d)| d["choices"][0]["delta"]["content"]
                .as_str()
                .is_some_and(|t| t.contains("blocked by policy")))
            .expect("the client must be told why the call is gone");
        assert_eq!(notice.1["object"], "chat.completion.chunk");
        assert_eq!(notice.1["model"], "gpt-x", "{notice:?}");
        assert_eq!(notice.1["id"], "chatcmpl-9", "{notice:?}");
        assert_eq!(notice.1["created"], 1_700_000_000u64, "{notice:?}");
    }

    #[test]
    fn a_rebuilt_call_is_never_addressed_to_a_message() {
        // With a message item still open beside the call's — upstreams may keep
        // two open — a rebuilt call must not put its arguments into the
        // message: the client would apply them to text. Its own item never
        // reached the client, so it gets a whole one.
        let rules = rules_from_json(vec![json!({
            "id": "T-10037",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "arg.file_path", "op": "glob", "value": "/etc/*" }],
            "action": { "kind": "replace", "with": "/tmp/safe" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        let upstream: Vec<(&str, serde_json::Value)> = vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            // A message item that stays open across the call.
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "looking", "logprobs": []}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 1, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "", "status": "in_progress"}}))),
            ("response.function_call_arguments.delta", next(json!({"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 1, "delta": "{\"file_path\":\"/etc/passwd\"}"}))),
            ("response.function_call_arguments.done", next(json!({"type": "response.function_call_arguments.done", "item_id": "fc_1", "output_index": 1, "arguments": "{\"file_path\":\"/etc/passwd\"}"}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 1, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}", "status": "completed"}}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "looking", "annotations": [], "logprobs": []}]}}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed"}}))),
        ];
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let delta = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.function_call_arguments.delta")
            .expect("the rewritten call never reached the client");
        assert_ne!(delta.1["item_id"], "msg_1", "{frames:?}");
        assert_ne!(delta.1["output_index"], 0, "{frames:?}");
        assert!(
            delta.1["delta"].as_str().is_some_and(|a| a.contains("/tmp/safe")),
            "{delta:?}"
        );
        // The message's own text is untouched and still addressed to it.
        let text = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.output_text.delta")
            .expect("the message text is gone");
        assert_eq!(text.1["item_id"], "msg_1");
    }

    #[test]
    fn the_tail_of_a_call_the_gateway_gave_up_on_does_not_reach_the_client() {
        // A call whose arguments outrun the analysis buffer is dropped
        // fail-closed and a notice takes its place. The argument bytes still
        // arriving belong to a block the client never saw opened — and the
        // notice now occupies that index, so forwarding them would write
        // partial tool JSON into the notice's own text.
        let mut acc = text_accumulator(vec![]);
        let mut frames: Vec<(&str, serde_json::Value)> = vec![
            ("message_start", json!({"type": "message_start", "message": {"id": "msg_1"}})),
            ("content_block_start", json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}}})),
        ];
        // Past the buffer cap, one delta at a time.
        for _ in 0..(MAX_BUFFERED_EVENTS + 2) {
            frames.push(("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "x"}})));
        }
        frames.push(("content_block_stop", json!({"type": "content_block_stop", "index": 0})));
        frames.push(("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}})));
        frames.push(("message_stop", json!({"type": "message_stop"})));
        let out = client_frames(crate::api::sse::ApiVersion::AnthropicMessages, &frames, &mut acc);

        assert!(
            out.iter().any(|(_, d)| d["delta"]["text"]
                .as_str()
                .is_some_and(|t| t.contains("was dropped"))),
            "the client was never told the call is gone: {:?}",
            frame_types(&out)
        );
        assert!(
            !out.iter().any(|(_, d)| d["delta"]["type"] == "input_json_delta"),
            "the abandoned call's arguments reached the client: {:?}",
            frame_types(&out)
        );
    }

    // ── What a client whose content policy changed is owed ──

    fn scripted_accumulator(
        scope: &str,
        source: &str,
        interests: BlockInterests,
        rules: Vec<crate::config::tool_rules::Rule>,
        signed_thinking_reaches_client: bool,
    ) -> BlockAccumulator {
        let meta = BlockRequestMeta { signed_thinking_reaches_client, ..make_block_meta() };
        BlockAccumulator::new(
            interests,
            rules,
            Arc::new(default_test_profiles()),
            vec![make_response_program_with_source("rewrite", scope, source)],
            Some(Arc::new(ScriptEngine::new())),
            Some(meta),
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::ChatCompletions,
        )
    }

    fn all_blocks() -> BlockInterests {
        BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: true,
            buffer_thinking_blocks: true,
        }
    }

    /// The text a Responses client was streamed into one item's content part.
    fn streamed_text(frames: &[(Option<String>, serde_json::Value)], output_index: u64) -> String {
        frames
            .iter()
            .filter(|(_, d)| {
                d["type"] == "response.output_text.delta" && d["output_index"] == output_index
            })
            .filter_map(|(_, d)| d["delta"].as_str())
            .collect()
    }

    fn frame_of<'a>(
        frames: &'a [(Option<String>, serde_json::Value)],
        kind: &str,
    ) -> &'a serde_json::Value {
        &frames
            .iter()
            .find(|(_, d)| d["type"] == kind)
            .unwrap_or_else(|| panic!("no {kind} reached the client: {frames:?}"))
            .1
    }

    #[test]
    fn every_final_statement_of_a_rewritten_block_says_what_the_client_was_streamed() {
        // The deltas carry the rewrite; `.done`, the finished part, the
        // finished item and the final response each restate the text. An SDK
        // that reads any of those — `get_final_response()` reads the last —
        // must be handed the rewritten text, or the rewrite is a policy it can
        // read straight past.
        let mut acc = scripted_accumulator(
            "text",
            r#"fn transform(ctx) { ctx.content = "[FILTERED]"; ctx }"#,
            all_blocks(),
            vec![],
            false,
        );
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &responses_upstream(), &mut acc);
        let streamed = streamed_text(&frames, 0);
        assert_eq!(streamed, "[FILTERED]", "{frames:?}");

        assert_eq!(frame_of(&frames, "response.output_text.done")["text"], streamed);
        assert_eq!(frame_of(&frames, "response.content_part.done")["part"]["text"], streamed);
        let item = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.output_item.done" && d["item"]["type"] == "message")
            .map(|(_, d)| &d["item"])
            .expect("the message item is finished");
        assert_eq!(item["content"][0]["text"], streamed);
        let output = &frame_of(&frames, "response.completed")["response"]["output"];
        assert_eq!(output[0]["content"][0]["text"], streamed, "{output}");
        assert!(!output.to_string().contains("hello"), "the original text survived: {output}");
    }

    #[test]
    fn a_call_policy_removed_is_not_in_the_final_response() {
        // The final response lists what the client was given: the notice that
        // stands in for the call, not the call.
        let rules = rules_from_json(vec![json!({
            "id": "T-10209",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = text_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &responses_upstream(), &mut acc);
        let output = frame_of(&frames, "response.completed")["response"]["output"]
            .as_array()
            .expect("the final response lists its output")
            .clone();
        assert!(
            !output.iter().any(|item| item["type"] == "function_call"),
            "a removed call is still in the final response: {output:?}"
        );
        assert_eq!(output.len(), 2, "{output:?}");
        assert_eq!(output[0]["content"][0]["text"], "hello");
        assert_eq!(output[1]["content"][0]["text"], streamed_text(&frames, 1));
        assert!(streamed_text(&frames, 1).contains("blocked by policy"));
    }

    /// A frame naming by id alone an item the client was never given — a call
    /// policy removed — never reaches it: it is about that item, not about the
    /// response, and its statement of the arguments is what policy removed.
    #[test]
    fn a_frame_naming_by_id_an_item_the_client_never_got_is_dropped() {
        let rules = rules_from_json(vec![json!({
            "id": "T-10237",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut upstream = responses_upstream();
        for (name, data) in upstream.iter_mut() {
            if *name == "response.function_call_arguments.done" {
                data.as_object_mut().expect("an object").remove("output_index");
            }
        }
        let mut acc = text_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let leaked: Vec<_> = frames.iter().filter(|(_, d)| d.to_string().contains("/etc/passwd")).collect();
        assert!(leaked.is_empty(), "{leaked:?}");
        assert!(streamed_text(&frames, 1).contains("blocked by policy"));
    }

    /// A custom call policy read before its end — a server tool's item opened
    /// first — still reaches a pass-through client with its
    /// `custom_tool_call_input.done`, stating what the client was given.
    #[test]
    fn a_custom_call_read_before_its_end_still_gets_its_done() {
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "output_index": 0,
                "item": {"id": "ctc_1", "type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": "", "status": "in_progress"}})),
            ("response.custom_tool_call_input.delta", json!({"type": "response.custom_tool_call_input.delta", "output_index": 0, "item_id": "ctc_1", "delta": "abc"})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "output_index": 1,
                "item": {"id": "mcp_1", "type": "mcp_call", "name": "fetch", "server_label": "srv", "arguments": "", "status": "in_progress"}})),
            ("response.custom_tool_call_input.done", json!({"type": "response.custom_tool_call_input.done", "output_index": 0, "item_id": "ctc_1", "input": "abc"})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "output_index": 0,
                "item": {"id": "ctc_1", "type": "custom_tool_call", "call_id": "call_1", "name": "apply_patch", "input": "abc", "status": "completed"}})),
        ];
        let mut acc = make_tool_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(frame_of(&frames, "response.custom_tool_call_input.done")["input"], "abc");
    }

    #[test]
    fn an_untouched_stream_ends_with_the_upstreams_own_final_response() {
        // Nothing was changed, so nothing is restated: the final response the
        // client reads is the upstream's, field for field.
        let mut acc = text_accumulator(vec![]);
        let mut upstream = responses_upstream();
        // A field only the final record states: nothing the client was
        // streamed says it, so only the upstream's own record can.
        upstream.last_mut().expect("fixture ends with the final response").1["response"]["output"][0]
            ["phase"] = json!("final_answer");
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let sent = &upstream.last().expect("fixture ends with the final response").1;
        assert_eq!(frame_of(&frames, "response.completed")["response"], sent["response"]);
        assert_eq!(frame_of(&frames, "response.output_text.done")["text"], "hello");
    }

    /// An Anthropic message whose thinking block the upstream signed.
    fn anthropic_signed_thinking_upstream(signature: &str) -> Vec<(&'static str, serde_json::Value)> {
        vec![
            ("message_start", json!({"type": "message_start", "message": {"id": "msg_1", "usage": {"input_tokens": 5}}})),
            ("content_block_start", json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "the plan"}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": signature}})),
            ("content_block_stop", json!({"type": "content_block_stop", "index": 0})),
            ("content_block_start", json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "done"}})),
            ("content_block_stop", json!({"type": "content_block_stop", "index": 1})),
            ("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 9}})),
            ("message_stop", json!({"type": "message_stop"})),
        ]
    }

    fn thinking_sent(frames: &[(Option<String>, serde_json::Value)]) -> String {
        frames
            .iter()
            .filter(|(_, d)| d["delta"]["type"] == "thinking_delta")
            .filter_map(|(_, d)| d["delta"]["thinking"].as_str())
            .collect()
    }

    const REWRITE_THINKING: &str = r#"fn transform(ctx) { ctx.content = "[MASKED]"; ctx }"#;

    #[test]
    fn a_signed_thinking_block_reaches_the_client_as_the_upstream_signed_it() {
        // The API refuses a signed thinking block that comes back changed, so
        // a client handed a rewritten one cannot continue the turn. The block
        // keeps its text, and the audit records a rewrite that was decided and
        // not applied.
        let mut acc = scripted_accumulator("thinking", REWRITE_THINKING, all_blocks(), vec![], true);
        let frames = client_frames(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &anthropic_signed_thinking_upstream("sig-1"),
            &mut acc,
        );
        assert_eq!(thinking_sent(&frames), "the plan", "{frames:?}");
        assert!(frames.iter().any(|(_, d)| d["delta"]["signature"] == "sig-1"));
        let badges = acc.badges.clone().finish();
        assert!(
            badges.contains(&crate::audit::AuditBadge::ModifiedNotApplied),
            "{badges:?}"
        );
        assert!(acc.injection_blocks.is_empty(), "nothing on the wire changed");
    }

    #[test]
    fn a_thinking_rewrite_applies_where_no_signature_reaches_the_client() {
        // A Chat or Responses client on an Anthropic upstream never receives the
        // signature — its emitter builds from events alone — so the rewrite
        // costs it nothing and applies like any other.
        let mut acc = scripted_accumulator("thinking", REWRITE_THINKING, all_blocks(), vec![], false);
        let mut reasoning = String::new();
        for (name, data) in anthropic_signed_thinking_upstream("sig-1") {
            let event = SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None };
            let domain = crate::api::sse::parse_domain_event(&event, crate::api::sse::ApiVersion::AnthropicMessages);
            let out = if domain.is_empty() {
                acc.process_raw(event, false)
            } else {
                domain.into_iter().flat_map(|de| acc.process(de, None)).collect()
            };
            for b in out {
                if let Some(DomainEvent::ReasoningDelta(t)) = b.domain_event {
                    reasoning.push_str(&t);
                }
            }
        }
        assert_eq!(reasoning, "[MASKED]");
        assert!(!acc.badges.clone().finish().contains(&crate::audit::AuditBadge::ModifiedNotApplied));
    }

    #[test]
    fn an_unsigned_thinking_block_is_rewritten() {
        // No signature, nothing to invalidate: the rewrite applies.
        let mut acc = scripted_accumulator("thinking", REWRITE_THINKING, all_blocks(), vec![], true);
        let frames = client_frames(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &anthropic_signed_thinking_upstream(""),
            &mut acc,
        );
        assert_eq!(thinking_sent(&frames), "[MASKED]", "{frames:?}");
    }

    #[test]
    fn a_non_streaming_signed_thinking_block_is_kept_and_an_unsigned_one_rewritten() {
        let engine = ScriptEngine::new();
        let programs = vec![make_response_program_with_source("rewrite", "thinking", REWRITE_THINKING)];
        let body = || {
            json!({"type": "message", "role": "assistant", "content": [
                {"type": "thinking", "thinking": "the plan", "signature": "sig-1"},
                {"type": "thinking", "thinking": "more", "signature": ""},
                {"type": "text", "text": "done"}
            ]})
        };
        let run = |reaches: bool| {
            let mut response = body();
            let meta = BlockRequestMeta { signed_thinking_reaches_client: reaches, ..make_block_meta() };
            let (badges, ..) = apply_response_scripts_json(
                &mut response,
                crate::api::sse::ApiVersion::AnthropicMessages,
                &programs,
                &engine,
                &meta,
                false,
                ScriptFailMode::Open,
            );
            (response, badges.finish())
        };

        let (kept, badges) = run(true);
        assert_eq!(kept["content"][0]["thinking"], "the plan");
        assert_eq!(kept["content"][1]["thinking"], "[MASKED]");
        assert!(badges.contains(&crate::audit::AuditBadge::ModifiedNotApplied), "{badges:?}");

        let (rewritten, badges) = run(false);
        assert_eq!(rewritten["content"][0]["thinking"], "[MASKED]");
        assert!(!badges.contains(&crate::audit::AuditBadge::ModifiedNotApplied), "{badges:?}");
    }

    fn chat_chunk(delta: serde_json::Value, finish: Option<&str>) -> serde_json::Value {
        json!({
            "id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 1, "model": "m",
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]
        })
    }

    fn chat_text(frames: &[(Option<String>, serde_json::Value)]) -> String {
        frames
            .iter()
            .filter_map(|(_, d)| d["choices"][0]["delta"]["content"].as_str())
            .collect()
    }

    #[test]
    fn text_in_the_finishing_chunk_reaches_the_client_once_and_under_policy() {
        // Ollama and vLLM put the last of the text in the chunk that carries
        // `finish_reason`. That text is content like any other: the script
        // sees it, and the client receives it exactly once — never again
        // inside the forwarded finish chunk.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "content": "the secret "}), None)),
            ("", {
                let mut last = chat_chunk(json!({"content": "is out"}), Some("stop"));
                last["usage"] = json!({"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7});
                last
            }),
        ];

        let mut plain = text_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut plain);
        assert_eq!(chat_text(&frames), "the secret is out", "{frames:?}");
        let last = &frames.last().expect("frames reached the client").1;
        assert_eq!(last["choices"][0]["finish_reason"], "stop");
        assert_eq!(last["usage"]["total_tokens"], 7, "the usage rides the finish chunk");

        let mut scripted = scripted_accumulator(
            "text",
            r#"fn transform(ctx) { ctx.content = "[FILTERED]"; ctx }"#,
            all_blocks(),
            vec![],
            false,
        );
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut scripted);
        assert_eq!(chat_text(&frames), "[FILTERED]", "{frames:?}");
    }

    #[test]
    fn a_rewritten_reasoning_chunk_keeps_the_upstreams_reasoning_field() {
        // The official Chat schema has no reasoning field; this upstream uses
        // `reasoning_content`, so a chunk the gateway writes does too. In
        // `content` the reasoning would read as the answer.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "reasoning_content": "think"}), None)),
            ("", chat_chunk(json!({"content": "answer"}), None)),
            ("", chat_chunk(json!({}), Some("stop"))),
        ];
        let mut acc = scripted_accumulator("thinking", REWRITE_THINKING, all_blocks(), vec![], false);
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let reasoning: Vec<&str> = frames
            .iter()
            .filter_map(|(_, d)| d["choices"][0]["delta"]["reasoning_content"].as_str())
            .collect();
        assert_eq!(reasoning, vec!["[MASKED]"], "{frames:?}");
        assert_eq!(chat_text(&frames), "answer", "{frames:?}");
    }

    #[test]
    fn a_gemini_chunk_split_across_events_keeps_every_part_whole_and_once() {
        // One chunk: text carrying a thought signature, a function call, and
        // the finish. Each part reaches the client once, in its own bytes —
        // the signature stays on its part, and a client resubmitting the turn
        // needs it there.
        let upstream = vec![(
            "",
            json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [
                        {"text": "calling", "thoughtSignature": "c2ln"},
                        {"functionCall": {"name": "lookup", "args": {"q": "x"}}}
                    ]},
                    "finishReason": "STOP"
                }],
                "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7}
            }),
        )];
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::GoogleGemini, vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::GoogleGemini, &upstream, &mut acc);
        let parts: Vec<&serde_json::Value> = frames
            .iter()
            .flat_map(|(_, d)| d["candidates"][0]["content"]["parts"].as_array().into_iter().flatten())
            .collect();
        assert_eq!(parts.len(), 2, "every part once: {frames:?}");
        assert_eq!(parts[0]["thoughtSignature"], "c2ln");
        assert_eq!(parts[1]["functionCall"]["name"], "lookup");
        let last = &frames.last().expect("frames reached the client").1;
        assert_eq!(last["candidates"][0]["finishReason"], "STOP");
        assert_eq!(last["usageMetadata"]["totalTokenCount"], 7);
    }

    #[test]
    fn a_gemini_call_without_an_id_is_held_for_policy_like_any_other() {
        // Gemini streams each function call whole, in one part, and often with
        // no `id`. It is still a call, and response-phase policy still decides
        // whether the client gets it.
        let rules = rules_from_json(vec![json!({
            "id": "T-10520",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let upstream = vec![(
            "",
            json!({
                "candidates": [{
                    "content": {"role": "model", "parts": [
                        {"functionCall": {"name": "Read", "args": {"file_path": "/etc/passwd"}}}
                    ]},
                    "finishReason": "STOP"
                }]
            }),
        )];
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::GoogleGemini, rules);
        let frames = client_frames(crate::api::sse::ApiVersion::GoogleGemini, &upstream, &mut acc);
        assert!(
            !frames.iter().any(|(_, d)| d.to_string().contains("functionCall")),
            "a blocked Gemini call reached the client: {frames:?}"
        );
        assert!(frames.iter().any(|(_, d)| d.to_string().contains("blocked by policy")), "{frames:?}");
    }

    #[test]
    fn arguments_for_a_call_already_checked_never_reach_the_client() {
        // Two parallel calls open in one chunk, and the first one's arguments
        // follow after the second has opened. The first call was checked — with
        // the arguments it had then — and sent; bytes arriving for it now were
        // never read by policy, so they are withheld, and the client is told.
        let rules = rules_from_json(vec![json!({
            "id": "T-10553",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_a", "type": "function", "function": {"name": "Lookup", "arguments": ""}},
                {"index": 1, "id": "call_b", "type": "function", "function": {"name": "Lookup", "arguments": "{}"}}
            ]}), None)),
            ("", chat_chunk(json!({"tool_calls": [
                {"index": 0, "function": {"arguments": "{\"file_path\":\"/etc/passwd\"}"}}
            ]}), None)),
            ("", chat_chunk(json!({"tool_calls": [
                {"index": 0, "function": {"arguments": " "}}
            ]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let text = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!text.contains("/etc/passwd"), "unchecked arguments reached the client: {frames:?}");
        assert_eq!(chat_text(&frames).matches("withheld").count(), 1, "told once: {frames:?}");
        // The audit row says the client's copy of the call stops short.
        assert!(
            acc.injection_blocks
                .iter()
                .any(|b| b.field == "arguments" && b.action == "remove" && b.content.contains("withheld")),
            "{:?}",
            acc.injection_blocks
        );
    }

    #[test]
    fn a_part_stated_only_in_its_done_is_left_as_the_upstream_stated_it() {
        // Nothing was streamed into the part, so its `.done` is the only
        // statement of its text there is — restating it from the (empty)
        // deltas would erase the answer.
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress", "output": []}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}})),
            ("response.content_part.added", json!({"type": "response.content_part.added", "sequence_number": 2, "item_id": "msg_1", "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}})),
            ("response.output_text.done", json!({"type": "response.output_text.done", "sequence_number": 3, "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": "Hello", "logprobs": []})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 4, "output_index": 0, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 5, "response": {"id": "resp_1", "status": "completed", "output": [{"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}]}})),
        ];
        let mut acc = text_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(frame_of(&frames, "response.output_text.done")["text"], "Hello");
        assert_eq!(
            frame_of(&frames, "response.completed")["response"]["output"][0]["content"][0]["text"],
            "Hello"
        );
    }

    #[test]
    fn a_chunk_of_content_and_a_running_usage_count_is_not_cut() {
        // Gemini reports usage on every chunk, vLLM can too: a chunk holding
        // one piece of content beside a usage count reaches the client whole.
        let text_and_usage = json!({
            "candidates": [{"content": {"role": "model", "parts": [{"text": "hello"}]}, "safetyRatings": []}],
            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1, "totalTokenCount": 4}
        });
        let event = SseEvent { event_type: None, data: text_and_usage.to_string(), id: None };
        let events = crate::api::sse::parse_domain_event(&event, crate::api::sse::ApiVersion::GoogleGemini);
        assert_eq!(events.len(), 2, "{events:?}");
        let frames = crate::pipeline::response_pipeline::split_frame(
            &event,
            crate::api::sse::ApiVersion::GoogleGemini,
            &events,
            true,
        );
        assert_eq!(frames[0].as_ref().map(|f| f.data.as_str()), Some(event.data.as_str()));
        assert!(frames[1].is_none());
    }

    #[test]
    fn a_call_sent_as_two_entries_of_one_index_is_forwarded_once() {
        // Some servers put a call's name and its arguments in two entries of
        // one chunk under the same index. Each entry is its own event, so
        // each piece carries its own entry — the client must not assemble the
        // arguments twice.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_a", "type": "function", "function": {"name": "Lookup", "arguments": ""}},
                {"index": 0, "function": {"arguments": "{\"q\":1}"}}
            ]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let args: String = frames
            .iter()
            .flat_map(|(_, d)| d["choices"][0]["delta"]["tool_calls"].as_array().cloned().unwrap_or_default())
            .filter_map(|tc| tc["function"]["arguments"].as_str().map(str::to_string))
            .collect();
        assert_eq!(args, "{\"q\":1}", "{frames:?}");
    }

    fn block_read_file() -> Vec<crate::config::tool_rules::Rule> {
        rules_from_json(vec![json!({
            "id": "T-10655",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "read_file" }],
            "action": { "kind": "block" },
            "risk": "danger"
        })])
    }

    /// A rule that reads a call's arguments — so it fires only when the
    /// arguments it was given are the call's whole arguments.
    fn block_passwd_argument() -> Vec<crate::config::tool_rules::Rule> {
        rules_from_json(vec![json!({
            "id": "T-10667",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "any_arg", "op": "contains_any", "value": ["/etc/passwd"] }],
            "action": { "kind": "block" },
            "risk": "danger"
        })])
    }

    #[test]
    fn a_server_tools_own_input_is_not_withheld() {
        // Anthropic's native server tools stream their input as ordinary
        // `input_json_delta`s into a block policy does not hold. Holding calls
        // must not turn them into "late arguments".
        let upstream = vec![
            ("message_start", json!({"type": "message_start", "message": {"id": "msg_1", "usage": {"input_tokens": 5}}})),
            ("content_block_start", json!({"type": "content_block_start", "index": 0, "content_block": {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {}}})),
            ("content_block_delta", json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"query\":\"paris\"}"}})),
            ("content_block_stop", json!({"type": "content_block_stop", "index": 0})),
            ("message_delta", json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 9}})),
            ("message_stop", json!({"type": "message_stop"})),
        ];
        let mut acc = text_accumulator(block_read_file());
        let frames = client_frames(crate::api::sse::ApiVersion::AnthropicMessages, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(n, _)| (*n).to_string()).collect();
        assert_eq!(frame_types(&frames), expected, "{frames:?}");
        assert!(frames.iter().any(|(_, d)| d["delta"]["partial_json"] == "{\"query\":\"paris\"}"));
    }

    #[test]
    fn a_usage_count_on_every_chunk_does_not_cut_a_held_call() {
        // vLLM's continuous usage puts a count on every chunk. The call is
        // still one call, read whole: a rule matching its full arguments fires.
        let with_usage = |mut chunk: serde_json::Value, n: u64| {
            chunk["usage"] = json!({"prompt_tokens": 3, "completion_tokens": n, "total_tokens": 3 + n});
            chunk
        };
        let upstream = vec![
            ("", with_usage(chat_chunk(json!({"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "Read", "arguments": ""}}]}), None), 1)),
            ("", with_usage(chat_chunk(json!({"tool_calls": [{"index": 0, "function": {"arguments": "{\"file_path\":"}}]}), None), 2)),
            ("", with_usage(chat_chunk(json!({"tool_calls": [{"index": 0, "function": {"arguments": "\"/etc/passwd\"}"}}]}), None), 3)),
            ("", with_usage(chat_chunk(json!({}), Some("tool_calls")), 4)),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("blocked by policy"), "{frames:?}");
        assert!(!chat_text(&frames).contains("withheld"), "{frames:?}");
    }

    #[test]
    fn a_continuation_that_names_no_call_continues_the_held_one() {
        // The spec requires an index on every tool-call delta; a lax server
        // that omits it on continuations still streams one call at a time.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"index": 1, "id": "call_b", "type": "function", "function": {"name": "Read", "arguments": ""}}]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"function": {"arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        // Read with the rest of the call, the arguments are what policy
        // checks: the rule sees the path and removes the call.
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("blocked by policy"), "{frames:?}");
        assert!(!chat_text(&frames).contains("withheld"), "{frames:?}");
    }

    #[test]
    fn a_removed_calls_late_arguments_add_no_second_notice() {
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_a", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}"}},
                {"index": 1, "id": "call_b", "type": "function", "function": {"name": "Lookup", "arguments": "{}"}}
            ]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"index": 0, "function": {"arguments": " "}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_read_file());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let text = chat_text(&frames);
        assert_eq!(text.matches("blocked by policy").count(), 1, "{text}");
        assert!(!text.contains("withheld"), "the client was already told the call is gone: {text}");
    }

    #[test]
    fn an_item_stated_only_in_the_final_response_stays_in_it() {
        // An upstream may state an item only in `response.completed`. The
        // gateway never held it back, so the client's final response lists
        // it — here beside a call policy did remove.
        let mut upstream = responses_upstream();
        upstream.last_mut().unwrap().1["response"]["output"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "ws_up", "type": "web_search_call", "status": "completed", "action": {"type": "search"}}));
        let mut acc = text_accumulator(block_read_file());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let output = frame_of(&frames, "response.completed")["response"]["output"].as_array().unwrap().clone();
        let ids: Vec<&str> = output.iter().filter_map(|i| i["id"].as_str()).collect();
        assert!(ids.contains(&"ws_up"), "{output:?}");
        assert!(!ids.contains(&"fc_1"), "{output:?}");
    }

    #[test]
    fn a_response_that_skips_the_stream_ends_as_the_upstream_sent_it() {
        // A server that streams nothing but the opening and the final
        // response: the gateway changed nothing, so it restates nothing.
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress", "output": []}})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 1, "response": {"id": "resp_1", "status": "completed", "output": [
                {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "Hello", "annotations": []}]}
            ]}})),
        ];
        let mut acc = text_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(frame_of(&frames, "response.completed")["response"], upstream[1].1["response"]);
    }

    #[test]
    fn an_untouched_stream_is_forwarded_even_where_it_disagrees_with_itself() {
        // An upstream whose `.done` text differs from its own deltas: the
        // gateway changed nothing, so it is not the gateway's to reconcile.
        let mut upstream = responses_upstream();
        for (_, data) in upstream.iter_mut() {
            if data["type"] == "response.output_text.delta" {
                data["delta"] = json!("hello ");
            }
        }
        let mut acc = text_accumulator(vec![]);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(frame_of(&frames, "response.output_text.done")["text"], "hello");
        assert_eq!(
            frame_of(&frames, "response.completed")["response"]["output"][0]["content"][0]["text"],
            "hello"
        );
    }

    #[test]
    fn a_usage_report_follows_the_content_it_counts() {
        // A held block's content and the usage that arrived while it was held
        // leave in the order the upstream sent them: a translated client reads
        // the usage as the stream's last word, and a Gemini usage chunk can
        // carry a part (an empty text with a thought signature) that seals the
        // text before it.
        let mut acc = text_accumulator(vec![]);
        let mut out = acc.process(DomainEvent::TextDelta("hello".into()), None);
        out.extend(acc.process(DomainEvent::Usage(Default::default()), None));
        assert!(out.is_empty(), "both wait for the block: {:?}", out.len());
        out.extend(acc.process(DomainEvent::TextDelta(" world".into()), None));
        out.extend(acc.process(
            DomainEvent::Done { finish_reason: None, native_finish_reason: None },
            None,
        ));
        let kinds: Vec<&str> = out
            .iter()
            .map(|b| match &b.domain_event {
                Some(DomainEvent::TextDelta(_)) => "text",
                Some(DomainEvent::Usage(_)) => "usage",
                Some(DomainEvent::Done { .. }) => "done",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["text", "text", "usage", "done"]);
    }

    #[test]
    fn a_rewritten_parts_citations_are_not_left_pointing_into_text_it_no_longer_holds() {
        let mut upstream = responses_upstream();
        let citation = json!([{"type": "url_citation", "start_index": 0, "end_index": 5, "url": "https://example.com", "title": "e"}]);
        for (_, data) in upstream.iter_mut() {
            match data["type"].as_str() {
                Some("response.content_part.done") => data["part"]["annotations"] = citation.clone(),
                Some("response.output_item.done") if data["item"]["type"] == "message" => {
                    data["item"]["content"][0]["annotations"] = citation.clone();
                }
                _ => {}
            }
        }
        let mut acc = scripted_accumulator(
            "text",
            r#"fn transform(ctx) { ctx.content = "[FILTERED]"; ctx }"#,
            all_blocks(),
            vec![],
            false,
        );
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(frame_of(&frames, "response.content_part.done")["part"]["annotations"], json!([]));
        let item = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.output_item.done" && d["item"]["type"] == "message")
            .map(|(_, d)| &d["item"])
            .unwrap();
        assert_eq!(item["content"][0]["annotations"], json!([]));
    }

    #[test]
    fn a_closed_mode_failure_suppresses_even_a_signed_thinking_block() {
        // Fail-closed is the operator's "never let unscreened content
        // through", and it outranks the client's next turn: a signed block the
        // script could not screen is suppressed like any other, not kept.
        let meta = BlockRequestMeta { signed_thinking_reaches_client: true, ..make_block_meta() };
        let mut acc = BlockAccumulator::new(
            all_blocks(),
            vec![],
            Arc::new(default_test_profiles()),
            vec![make_response_program_with_source("boom", "thinking", r#"fn transform(ctx) { throw "boom"; }"#)],
            Some(Arc::new(ScriptEngine::new())),
            Some(meta),
            false,
            ScriptFailMode::Closed,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::AnthropicMessages,
        );
        let frames = client_frames(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &anthropic_signed_thinking_upstream("sig-1"),
            &mut acc,
        );
        assert_eq!(thinking_sent(&frames), "", "{frames:?}");
        assert!(
            frames.iter().any(|(_, d)| d["delta"]["text"].as_str().is_some_and(|t| t.contains("suppressed"))),
            "{frames:?}"
        );
        assert!(!acc.badges.clone().finish().contains(&crate::audit::AuditBadge::ModifiedNotApplied));
    }

    #[test]
    fn a_call_that_names_itself_without_an_id_is_still_held() {
        // A lax server may start a call with its name and no id. It is a call,
        // and response-phase policy reads it.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"index": 0, "function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("blocked by policy"), "{frames:?}");
    }

    #[test]
    fn a_rewritten_gemini_call_keeps_its_thought_signature() {
        // Gemini refuses a turn whose function call lost its thought
        // signature. A call policy rewrote leaves in the upstream's own part,
        // signature included, with only its arguments changed.
        let rules = rules_from_json(vec![json!({
            "id": "T-10917",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "arg.file_path", "op": "glob", "value": "/etc/*" }],
            "action": { "kind": "replace", "regex": "/etc/passwd", "with": "/tmp/safe" },
            "risk": "danger"
        })]);
        let upstream = vec![(
            "",
            json!({"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "Read", "args": {"file_path": "/etc/passwd"}}, "thoughtSignature": "c2ln"}
            ]}, "finishReason": "STOP"}]}),
        )];
        let mut acc = text_accumulator_for(crate::api::sse::ApiVersion::GoogleGemini, rules);
        let frames = client_frames(crate::api::sse::ApiVersion::GoogleGemini, &upstream, &mut acc);
        let call = frames
            .iter()
            .flat_map(|(_, d)| d["candidates"][0]["content"]["parts"].as_array().cloned().unwrap_or_default())
            .find(|p| p.get("functionCall").is_some())
            .expect("the rewritten call reached the client");
        assert_eq!(call["functionCall"]["args"]["file_path"], "/tmp/safe", "{frames:?}");
        assert_eq!(call["thoughtSignature"], "c2ln", "{frames:?}");
    }

    #[test]
    fn a_streamed_intercepted_gemini_call_keeps_its_thought_signature() {
        // The continuation sends the intercepted call back to Gemini, which
        // wants the signature on the part it came on — over parallel calls,
        // the first one only.
        let bindings = vec![make_substitute_binding("web_search", "WS-SUB")];
        let mut acc = BlockAccumulator::new(
            BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: false, buffer_thinking_blocks: false },
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            bindings,
            false,
            false,
            crate::api::sse::ApiVersion::GoogleGemini,
        );
        let upstream = vec![(
            "",
            json!({"candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "web_search", "args": {"query": "X"}}, "thoughtSignature": "Sig1"},
                {"functionCall": {"name": "web_search", "args": {"query": "Y"}}}
            ]}, "finishReason": "STOP"}]}),
        )];
        client_frames(crate::api::sse::ApiVersion::GoogleGemini, &upstream, &mut acc);
        let pending = acc.take_pending_intercepted();
        let signed: Vec<(&str, Option<&str>)> =
            pending.iter().map(|p| (p.arguments_json.as_str(), p.thought_signature.as_deref())).collect();
        assert_eq!(signed, [(r#"{"query":"X"}"#, Some("Sig1")), (r#"{"query":"Y"}"#, None)]);
    }

    #[test]
    fn a_final_response_naming_no_ids_is_restated_by_position() {
        // An upstream may give its items no ids. The final response still
        // lists what the client got: the message as it was rewritten, and an
        // item stated only there, which the gateway never held back.
        let upstream: Vec<(&str, serde_json::Value)> = responses_upstream()
            .into_iter()
            .take(7)
            .map(|(n, mut d)| {
                if let Some(item) = d.get_mut("item").and_then(|i| i.as_object_mut()) {
                    item.remove("id");
                }
                (n, d)
            })
            .chain(std::iter::once((
                "response.completed",
                json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed", "output": [
                    {"type": "message", "role": "assistant", "status": "completed", "phase": "final_answer",
                     "content": [{"type": "output_text", "text": "hello", "annotations": []}]},
                    {"type": "web_search_call", "status": "completed", "action": {"type": "search"}}
                ]}}),
            )))
            .collect();
        let mut acc = scripted_accumulator(
            "text",
            r#"fn transform(ctx) { ctx.content = "[FILTERED]"; ctx }"#,
            all_blocks(),
            vec![],
            false,
        );
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let output = frame_of(&frames, "response.completed")["response"]["output"].as_array().unwrap().clone();
        assert_eq!(output.len(), 2, "{output:?}");
        assert_eq!(output[0]["content"][0]["text"], "[FILTERED]");
        assert_eq!(output[0]["phase"], "final_answer", "the upstream's own record, restated");
        assert_eq!(output[1]["type"], "web_search_call");
    }

    #[test]
    fn a_repeated_name_does_not_restart_a_call_already_read() {
        // A server that repeats the function name on every delta, streaming
        // two calls whose deltas interleave: the first call's late fragment
        // names it again, and is still a late fragment — withheld, never a
        // fresh call read on its own.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_a", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":"}},
                {"index": 1, "id": "call_b", "type": "function", "function": {"name": "Lookup", "arguments": "{}"}}
            ]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"index": 0, "function": {"name": "Read", "arguments": "\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("withheld"), "{frames:?}");
    }

    #[test]
    fn a_gemini_request_never_asks_for_streamed_call_arguments() {
        // Gemini streams a call's arguments in pieces only when the request
        // opts in; the accumulator reads every Gemini call as whole, which
        // holds because the gateway's request type does not carry the opt-in.
        let body = json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "toolConfig": {"functionCallingConfig": {"mode": "AUTO", "streamFunctionCallArguments": true}}
        });
        let parsed: crate::api::gemini::GeminiRequest = serde_json::from_value(body).unwrap();
        let sent = serde_json::to_value(&parsed).unwrap();
        assert!(!sent.to_string().contains("streamFunctionCallArguments"), "{sent}");
        assert_eq!(sent["toolConfig"]["functionCallingConfig"]["mode"], "AUTO", "the rest survives");
    }

    #[test]
    fn a_call_given_up_on_does_not_keep_the_usage_behind_it() {
        // Usage held behind a block goes out when the block does — including
        // when the accumulator gives up on it.
        let mut acc = text_accumulator(block_read_file());
        let mut out = acc.process(
            DomainEvent::ToolCallDelta { index: 0, id: Some("c".into()), function_name: Some("Read".into()), arguments_delta: String::new(), form: crate::api::domain::CallArguments::Json },
            None,
        );
        out.extend(acc.process(DomainEvent::Usage(Default::default()), None));
        for _ in 0..MAX_BUFFERED_EVENTS {
            out.extend(acc.process(
                DomainEvent::ToolCallDelta { index: 0, id: None, function_name: None, arguments_delta: "x".into(), form: crate::api::domain::CallArguments::Json },
                None,
            ));
        }
        assert!(
            out.iter().any(|b| matches!(b.domain_event, Some(DomainEvent::Usage(_)))),
            "the usage left with the notice"
        );
    }

    #[test]
    fn a_second_call_that_names_itself_is_read_on_its_own() {
        // A lax server sending each call whole, with neither id nor index:
        // both parse to index 0, and the second names a different function —
        // it is a call of its own, read under its own name.
        let rules = rules_from_json(vec![json!({
            "id": "T-11076",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "any_arg", "op": "contains_any", "value": ["/etc/passwd"] }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"function": {"name": "Read", "arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"function": {"name": "Lookup", "arguments": "{\"q\":1}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(all.contains("Lookup"), "the second call is its own, and allowed: {frames:?}");
    }

    #[test]
    fn a_repeated_id_does_not_cut_a_call() {
        // A server repeating the id on every delta: one call, read whole.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"index": 0, "id": "c1", "type": "function", "function": {"name": "Read", "arguments": "{\"file_path\":"}}]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"index": 0, "id": "c1", "function": {"arguments": "\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("blocked by policy"), "{frames:?}");
    }

    #[test]
    fn an_empty_id_on_a_continuation_does_not_start_a_call() {
        // Some servers send `"id": ""` on every delta after the first. An empty
        // id names nothing: the call is still one call, read whole.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "Read", "arguments": ""}}]}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"index": 0, "id": "", "function": {"name": "", "arguments": "{\"file_path\":\"/etc/passwd\"}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(!all.contains("passwd"), "{frames:?}");
        assert!(chat_text(&frames).contains("blocked by policy"), "{frames:?}");
    }

    #[test]
    fn a_call_to_another_function_after_a_read_one_is_its_own_call() {
        // A lax server sends neither index nor id, so every call is index 0.
        // A call naming another function after one policy already read is a
        // new call — read, and delivered — never the first one's late bytes.
        let upstream = vec![
            ("", chat_chunk(json!({"role": "assistant", "tool_calls": [{"function": {"name": "Read", "arguments": "{\"file_path\":\"a\"}"}}]}), None)),
            ("", chat_chunk(json!({"content": "and then"}), None)),
            ("", chat_chunk(json!({"tool_calls": [{"function": {"name": "Lookup", "arguments": "{\"q\":1}"}}]}), None)),
            ("", chat_chunk(json!({}), Some("tool_calls"))),
        ];
        let mut acc = text_accumulator(block_passwd_argument());
        let frames = client_frames(crate::api::sse::ApiVersion::ChatCompletions, &upstream, &mut acc);
        let all = frames.iter().map(|(_, d)| d.to_string()).collect::<String>();
        assert!(all.contains("Lookup"), "{frames:?}");
        assert!(!chat_text(&frames).contains("withheld"), "{frames:?}");
    }

    // ── The tool-call boundary rule ──

    /// One case per class the boundary rule decides — both sides of every
    /// comparison it makes.
    #[test]
    fn every_tool_call_boundary_class_is_decided() {
        let call = |id: Option<&'static str>, name: Option<&'static str>| Some(KnownCall { id, name });
        let d = |id, name, calls_arrive_whole, lax_indexes, open_at_index, closed_at_index, closed_carries_id, any_open| {
            call_delta(
                KnownCall { id, name },
                CallsSeen { calls_arrive_whole, lax_indexes, open_at_index, closed_at_index, closed_carries_id, any_open },
            )
        };
        use CallDelta::*;
        // Gemini: every call event is a call.
        assert_eq!(d(None, None, true, false, call(Some("c1"), Some("a")), None, true, true), Starts);
        // Restating a closed call's id: late bytes, open call or not.
        assert_eq!(d(Some("c1"), None, false, true, None, None, true, true), Late);
        assert_eq!(d(Some("c1"), None, false, true, None, None, false, false), Starts);
        // The open call at the index: continued unless another call is named…
        assert_eq!(d(Some("c1"), Some("a"), false, false, call(Some("c1"), Some("a")), None, false, true), ContinuesAtIndex);
        assert_eq!(d(None, None, false, false, call(Some("c1"), Some("a")), None, false, true), ContinuesAtIndex);
        assert_eq!(d(Some("c2"), None, false, false, call(Some("c1"), Some("a")), None, false, true), Starts);
        assert_eq!(d(None, Some("b"), false, false, call(Some("c1"), Some("a")), None, false, true), Starts);
        // …compared only where both sides name one: the id after the name.
        assert_eq!(d(Some("c1"), None, false, false, call(None, Some("a")), None, false, true), ContinuesAtIndex);
        // A closed call at the index: a new call only under a new id or name.
        assert_eq!(d(None, Some("a"), false, false, None, call(Some("c1"), Some("a")), false, false), Late);
        assert_eq!(d(None, Some("b"), false, false, None, call(Some("c1"), Some("a")), false, false), Starts);
        assert_eq!(d(Some("c2"), Some("a"), false, false, None, call(Some("c1"), Some("a")), false, false), Starts);
        // A fresh index: a named delta starts a call; an unnamed one continues
        // the last open call only from a lax upstream.
        assert_eq!(d(None, Some("a"), false, false, None, None, false, true), Starts);
        assert_eq!(d(None, None, false, true, None, None, false, true), ContinuesLast);
        assert_eq!(d(None, None, false, false, None, None, false, true), Late);
        assert_eq!(d(None, None, false, true, None, None, false, false), Late);
    }

    fn intercepting_accumulator(upstream: crate::api::sse::ApiVersion) -> BlockAccumulator {
        let interests = BlockInterests {
            buffer_tool_blocks: true,
            buffer_text_blocks: false,
            buffer_thinking_blocks: false,
        };
        BlockAccumulator::new(
            interests,
            vec![],
            Default::default(),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            vec![make_substitute_binding("bash", "SUB-BASH")],
            false,
            false,
            upstream,
        )
    }

    fn tool_delta(index: usize, id: Option<&str>, name: Option<&str>, args: &str) -> DomainEvent {
        DomainEvent::ToolCallDelta {
            index,
            id: id.map(String::from),
            function_name: name.map(String::from),
            arguments_delta: args.into(),
            form: crate::api::domain::CallArguments::Json,
        }
    }

    /// An Anthropic upstream numbers every block: a server tool's input at an
    /// index no call carries is not the held call's arguments — policy reads
    /// the call as the upstream sent it, and the input reaches the client.
    #[test]
    fn a_server_tool_input_never_joins_the_held_call() {
        let mut acc = intercepting_accumulator(crate::api::sse::ApiVersion::AnthropicMessages);
        let mut out = acc.process(tool_delta(1, Some("c1"), Some("bash"), r#"{"cmd":"ls"}"#), None);
        out.extend(acc.process(tool_delta(2, None, None, r#"{"query":"x"}"#), None));
        out.extend(acc.flush());
        let read: Vec<&str> = acc.pending_intercepted.iter().map(|p| p.arguments_json.as_str()).collect();
        assert_eq!(read, vec![r#"{"cmd":"ls"}"#]);
        assert!(
            out.iter().any(|b| matches!(&b.domain_event,
                Some(DomainEvent::ToolCallDelta { index: 2, arguments_delta, .. }) if arguments_delta == r#"{"query":"x"}"#)),
            "the server tool's input reaches the client"
        );
    }

    /// A call restated by its id after policy read it, at another index, is
    /// that call's late bytes — never a second call policy reads (and the
    /// client runs) under the same id.
    #[test]
    fn a_read_call_restated_by_its_id_is_not_read_twice() {
        let mut acc = intercepting_accumulator(crate::api::sse::ApiVersion::ChatCompletions);
        // The stream parser gives a delta restating a call's id that call's
        // number, whatever index it carries.
        let mut parser = crate::api::sse::StreamParser::new(crate::api::sse::ApiVersion::ChatCompletions);
        for event in [
            tool_delta(0, Some("c1"), Some("bash"), r#"{"cmd":"ls"}"#),
            DomainEvent::TextDelta("Running it.".into()),
            tool_delta(1, Some("c1"), Some("bash"), r#"{"cmd":"rm"}"#),
        ] {
            for e in parser.number(vec![event]) {
                acc.process(e, None);
            }
        }
        acc.flush();
        let read: Vec<&str> = acc.pending_intercepted.iter().map(|p| p.arguments_json.as_str()).collect();
        assert_eq!(read, vec![r#"{"cmd":"ls"}"#]);
    }

    /// A non-streaming round yields its turn as the model produced it: the
    /// thinking it sealed, unchanged and in place, and where its text and each
    /// call stand; an unsigned block and any other protocol's response yield
    /// none.
    #[test]
    fn a_non_streaming_round_yields_its_turn_as_the_model_produced_it() {
        use crate::api::domain_request::{DomainContentBlock, RoundPart};
        use crate::api::sse::ApiVersion;
        let body = json!({"content": [
            {"type": "thinking", "thinking": "plan", "signature": "sig-1"},
            {"type": "thinking", "thinking": "unsigned", "signature": ""},
            {"type": "redacted_thinking", "data": "opaque"},
            {"type": "text", "text": "Searching."},
            {"type": "tool_use", "id": "c1", "name": "web_search", "input": {}},
            {"type": "thinking", "thinking": "again", "signature": "sig-2"},
            {"type": "text", "text": "after the call"},
            {"type": "tool_use", "id": "c2", "name": "web_search", "input": {}},
        ]});
        let describe = |parts: Vec<RoundPart>| -> Vec<String> {
            parts
                .into_iter()
                .map(|p| match p {
                    RoundPart::Thinking(b) => serde_json::to_string(&b).unwrap(),
                    RoundPart::Text(t) => format!("text {t:?}"),
                    RoundPart::Call(id) => format!("call {id:?}"),
                })
                .collect()
        };
        let as_json = |b: DomainContentBlock| serde_json::to_string(&b).unwrap();
        assert_eq!(
            describe(extract_round_parts_from_response_json(&body, ApiVersion::AnthropicMessages)),
            [
                as_json(DomainContentBlock::Thinking { thinking: "plan".into(), signature: Some("sig-1".into()), signed_by: Some(crate::api::sse::ApiVersion::AnthropicMessages) }),
                as_json(DomainContentBlock::Unknown { value: json!({"type": "redacted_thinking", "data": "opaque"}) }),
                "text \"Searching.\"".to_string(),
                "call Some(\"c1\")".to_string(),
                as_json(DomainContentBlock::Thinking { thinking: "again".into(), signature: Some("sig-2".into()), signed_by: Some(crate::api::sse::ApiVersion::AnthropicMessages) }),
                "text \"after the call\"".to_string(),
                "call Some(\"c2\")".to_string(),
            ]
        );
        assert!(extract_round_parts_from_response_json(&body, ApiVersion::ChatCompletions).is_empty());
    }

    // ── Responses built-in tools the client runs ──────────────────────────────

    /// The field profile the shipped seed gives a `shell_call` — its commands
    /// read as one shell field.
    fn builtin_shell_accumulator(rules: Vec<crate::config::tool_rules::Rule>) -> BlockAccumulator {
        use crate::config::tool_rules::FieldProfile;
        use crate::config::tool_rules_normalize::Normalizer;
        let profiles = crate::config::tool_rules::FieldProfileSet::new(vec![FieldProfile {
            id: Some("test-shell_call".into()),
            description: None,
            source: None,
            tool_id: "shell_exec".into(),
            tool_pattern: "shell_call".into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: "command".into(),
            wire_field: Some("commands".into()),
            normalizer: Normalizer::Shell,
            priority: 100,
            is_builtin: false,
        }]);
        BlockAccumulator::new(
            BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: true, buffer_thinking_blocks: false },
            rules,
            Arc::new(profiles),
            vec![],
            None,
            None,
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::Responses,
        )
    }

    fn block_destructive_shell() -> Vec<crate::config::tool_rules::Rule> {
        rules_from_json(vec![json!({
            "id": "T-11338",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "shell_exec" },
                { "target": "arg.command", "op": "contains_any", "value": ["rm -rf"] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        })])
    }

    fn shell_call_item(status: &str, commands: &[&str]) -> serde_json::Value {
        json!({"id": "sh_1", "type": "shell_call", "call_id": "call_1", "status": status,
               "action": {"commands": commands, "timeout_ms": 10_000}, "environment": {"type": "local"}})
    }

    /// A Responses stream whose answer is one `shell_call` running `command`:
    /// the item opens with no commands, streams the command, and states it whole
    /// in its done and in the final response.
    fn shell_call_upstream(command: &str) -> Vec<(&'static str, serde_json::Value)> {
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": shell_call_item("in_progress", &[])}))),
            ("response.shell_call_command.added", next(json!({"type": "response.shell_call_command.added", "output_index": 0, "command_index": 0, "command": ""}))),
            ("response.shell_call_command.delta", next(json!({"type": "response.shell_call_command.delta", "output_index": 0, "command_index": 0, "delta": command}))),
            ("response.shell_call_command.done", next(json!({"type": "response.shell_call_command.done", "output_index": 0, "command_index": 0, "command": command}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": shell_call_item("completed", &[command])}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed",
                "output": [shell_call_item("completed", &[command])],
                "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}}))),
        ]
    }

    fn final_output(frames: &[(Option<String>, serde_json::Value)]) -> Vec<serde_json::Value> {
        frames
            .iter()
            .find(|(_, d)| d["type"] == "response.completed")
            .and_then(|(_, d)| d["response"]["output"].as_array().cloned())
            .expect("the stream ends with its final response")
    }

    #[test]
    fn a_blocked_built_in_shell_call_never_reaches_a_pass_through_client() {
        // The call a Responses client runs itself (`shell_call`) meets the
        // same policy as a function call: nothing of it — its item, its
        // streamed command, its final record — reaches the client, which is
        // told why.
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &shell_call_upstream("rm -rf /"), &mut acc);
        assert!(
            !frames.iter().any(|(_, d)| d["item"]["type"] == "shell_call"
                || d["type"].as_str().is_some_and(|t| t.starts_with("response.shell_call_command."))
                || d.to_string().contains("rm -rf")),
            "the blocked call reached the client: {frames:?}"
        );
        assert!(
            frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("blocked by policy"))),
            "the client must be told why the call is gone: {frames:?}"
        );
        assert!(final_output(&frames).iter().all(|item| item["type"] != "shell_call"));
        let numbers: Vec<u64> = frames.iter().map(|(_, d)| d["sequence_number"].as_u64().expect("numbered")).collect();
        assert_eq!(numbers, (0..frames.len() as u64).collect::<Vec<_>>());
        assert_eq!(acc.stats.tool_blocks_blocked, 1);
    }

    #[test]
    fn an_allowed_built_in_shell_call_reaches_a_pass_through_client_whole() {
        // The positive control: the same rule over an ordinary command gives
        // the client the call, opened and closed with the payload policy read.
        // Its streamed command frames state a payload no policy had read yet,
        // so they are not forwarded; the done states the commands whole.
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let upstream = shell_call_upstream("ls -la");
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert_eq!(
            frame_types(&frames),
            ["response.created", "response.output_item.added", "response.output_item.done", "response.completed"]
        );
        let opened = frames.iter().find(|(_, d)| d["type"] == "response.output_item.added").expect("the call's opening");
        assert_eq!(opened.1["item"]["action"]["commands"], json!(["ls -la"]));
        assert_eq!(opened.1["item"]["status"], "in_progress");
        let done = frames.iter().find(|(_, d)| d["type"] == "response.output_item.done").expect("the call's done");
        assert_eq!(done.1["item"]["action"]["commands"], json!(["ls -la"]));
        assert_eq!(final_output(&frames)[0]["action"]["commands"], json!(["ls -la"]));
        assert_eq!(acc.stats.tool_blocks_checked, 1);
        assert_eq!(acc.stats.tool_blocks_blocked, 0);
    }

    #[test]
    fn a_rewritten_built_in_shell_call_is_the_upstreams_item_with_its_payload_replaced() {
        // A replace rule rewrites the call's payload. The client is given the
        // upstream's own item — every other field kept — opened and closed,
        // never a call of another kind, and the final response states what
        // the client was given.
        let rules = rules_from_json(vec![json!({
            "id": "T-11439",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "shell_exec" }],
            "action": { "kind": "replace", "regex": "rm -rf /", "with": "echo refused" },
            "risk": "danger"
        })]);
        let mut acc = builtin_shell_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &shell_call_upstream("rm -rf /"), &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("rm -rf")), "the original command reached the client: {frames:?}");
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "function_call"), "{frames:?}");
        let items: Vec<&serde_json::Value> = frames
            .iter()
            .filter(|(_, d)| matches!(d["type"].as_str(), Some("response.output_item.added" | "response.output_item.done")))
            .map(|(_, d)| &d["item"])
            .collect();
        assert_eq!(items.len(), 2, "the call is opened and closed once: {frames:?}");
        for item in &items {
            assert_eq!(item["type"], "shell_call");
            assert_eq!(item["call_id"], "call_1");
            assert_eq!(item["environment"], json!({"type": "local"}));
        }
        // Opened and closed with the rewritten payload, nothing before it.
        for item in &items {
            assert_eq!(item["action"]["commands"], json!(["echo refused"]));
        }
        assert_eq!((items[0]["status"].as_str(), items[1]["status"].as_str()), (Some("in_progress"), Some("completed")));
        assert_eq!(final_output(&frames)[0]["action"]["commands"], json!(["echo refused"]));
    }

    #[test]
    fn a_shell_calls_done_after_policy_read_it_states_only_what_the_client_was_given() {
        // Another item opens before the shell call's done, so policy reads the
        // call before its payload is stated. The command it streamed and the
        // done stating it arrive unread: neither reaches the client as sent,
        // the client is told bytes were withheld, and the final response
        // records the call as the client has it.
        let mut seq = 0u64;
        let mut next = |mut v: serde_json::Value| {
            v["sequence_number"] = seq.into();
            seq += 1;
            v
        };
        let msg = |status: &str, text: &str| json!({"id": "msg_1", "type": "message", "role": "assistant", "status": status,
            "content": [{"type": "output_text", "text": text, "annotations": [], "logprobs": []}]});
        let upstream = vec![
            ("response.created", next(json!({"type": "response.created", "response": {"id": "resp_1", "status": "in_progress"}}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 0, "item": shell_call_item("in_progress", &[])}))),
            ("response.shell_call_command.delta", next(json!({"type": "response.shell_call_command.delta", "output_index": 0, "command_index": 0, "delta": "rm -rf /"}))),
            ("response.output_item.added", next(json!({"type": "response.output_item.added", "output_index": 1, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}}))),
            ("response.content_part.added", next(json!({"type": "response.content_part.added", "item_id": "msg_1", "output_index": 1, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": [], "logprobs": []}}))),
            ("response.output_text.delta", next(json!({"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 1, "content_index": 0, "delta": "done", "logprobs": []}))),
            ("response.output_text.done", next(json!({"type": "response.output_text.done", "item_id": "msg_1", "output_index": 1, "content_index": 0, "text": "done", "logprobs": []}))),
            ("response.content_part.done", next(json!({"type": "response.content_part.done", "item_id": "msg_1", "output_index": 1, "content_index": 0, "part": {"type": "output_text", "text": "done", "annotations": [], "logprobs": []}}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 1, "item": msg("completed", "done")}))),
            ("response.output_item.done", next(json!({"type": "response.output_item.done", "output_index": 0, "item": shell_call_item("completed", &["rm -rf /"])}))),
            ("response.completed", next(json!({"type": "response.completed", "response": {"id": "resp_1", "status": "completed",
                "output": [shell_call_item("completed", &["rm -rf /"]), msg("completed", "done")],
                "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}}))),
        ];
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("rm -rf")), "unread bytes reached the client: {frames:?}");
        assert!(
            frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("was read before its payload was stated"))),
            "the client must be told bytes were withheld: {frames:?}"
        );
        // The call was never read whole: the client is not given it at all.
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "shell_call"), "{frames:?}");
        assert!(final_output(&frames).iter().all(|item| item["type"] != "shell_call"));
    }

    #[test]
    fn a_built_in_call_read_before_its_done_never_hands_over_what_it_opened_with() {
        // An item may state its whole payload as it opens (a local shell
        // command, a patch). Policy reads a built-in call from its done; read
        // before it — the stream cut short here — the opening's payload is no
        // statement policy read, so the client is given the call empty.
        let item = |status: &str| json!({"id": "lsh_1", "type": "local_shell_call", "call_id": "call_1", "status": status,
            "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}}});
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": item("in_progress")})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 2, "response": {"id": "resp_1", "status": "completed",
                "output": [item("completed")], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let rules = rules_from_json(vec![json!({
            "id": "T-11525",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "any_arg", "op": "contains_any", "value": ["rm"] }],
            "action": { "kind": "block" },
            "risk": "danger"
        })]);
        let mut acc = builtin_shell_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("rm")), "an unread payload reached the client: {frames:?}");
        // Withheld whole — never an empty call the client could run — and said.
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "local_shell_call"), "{frames:?}");
        assert!(final_output(&frames).iter().all(|item| item["type"] != "local_shell_call"));
        assert!(frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("was read before its payload was stated"))), "{frames:?}");
        assert_eq!(
            acc.injection_blocks.iter().filter(|b| b.transform == crate::pipeline::response::TransformState::ARGUMENTS_WITHHELD).count(),
            1,
            "recorded once: {:?}", acc.injection_blocks
        );
        assert_eq!(acc.tool_calls_delivered, 0, "a call the client never got is not counted delivered");
    }

    #[test]
    fn a_computer_call_stating_a_batch_beside_its_action_is_given_only_what_policy_read() {
        // Read by its `action`; the batch beside it no policy read does not
        // ride along to the client.
        let item = |status: &str| json!({"id": "cu_1", "type": "computer_call", "call_id": "call_1", "status": status,
            "pending_safety_checks": [], "action": {"type": "wait"}, "actions": [{"type": "type", "text": "SECRET"}]});
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": item("in_progress")})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": item("completed")})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 3, "response": {"id": "resp_1", "status": "completed",
                "output": [item("completed")], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("SECRET")), "{frames:?}");
        let done = frames.iter().find(|(_, d)| d["type"] == "response.output_item.done").expect("the call reaches the client");
        assert_eq!(done.1["item"]["action"], json!({"type": "wait"}));
        // Non-streaming, the same.
        let profiles = acc.tool_field_profiles.clone();
        let mut response = json!({"output": [item("completed")]});
        apply_response_policy_json(&mut response, crate::api::sse::ApiVersion::Responses, &block_destructive_shell(), &profiles, None, None, &[]);
        assert!(!response.to_string().contains("SECRET"), "{response}");
    }

    #[test]
    fn a_hosted_shell_call_is_the_servers_and_is_never_held() {
        // A shell call in a hosted container ran on the server before the
        // response was written: it is recorded as that server tool's call, like
        // an MCP call — a block rule cannot undo it and does not pretend to.
        let hosted = |status: &str| json!({"id": "sh_1", "type": "shell_call", "call_id": "call_1", "status": status,
            "action": {"commands": if status == "completed" { json!(["rm -rf /"]) } else { json!([]) }},
            "environment": {"type": "container_auto"}});
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": hosted("in_progress")})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": hosted("completed")})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 3, "response": {"id": "resp_1", "status": "completed",
                "output": [hosted("completed")], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        let expected: Vec<String> = upstream.iter().map(|(name, _)| (*name).to_string()).collect();
        assert_eq!(frame_types(&frames), expected);
        assert_eq!(acc.stats.tool_blocks_checked, 0);
        let mut parser = crate::api::sse::StreamParser::new(crate::api::sse::ApiVersion::Responses);
        let forms: Vec<CallArguments> = upstream
            .iter()
            .flat_map(|(name, data)| parser.parse(&SseEvent { event_type: Some((*name).to_string()), data: data.to_string(), id: None }))
            .filter_map(|e| match e { DomainEvent::ToolCallDelta { form, .. } => Some(form), _ => None })
            .collect();
        assert!(!forms.is_empty() && forms.iter().all(|f| *f == CallArguments::ServerTool), "{forms:?}");
        assert!(crate::api::domain::tool_call_item(&hosted("completed")).is_none());
    }

    #[test]
    fn a_patch_diff_streamed_before_the_call_is_read_never_reaches_the_client() {
        // A patch's diff streams in frames of its own. Read before its done
        // (another item opened first), the diff policy never read stays with
        // the call and does not reach the client.
        let item = |status: &str, diff: &str| json!({"id": "ap_1", "type": "apply_patch_call", "call_id": "call_1", "status": status,
            "operation": {"type": "update_file", "path": "a.txt", "diff": diff}});
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": item("in_progress", "")})),
            ("response.apply_patch_call_operation_diff.delta", json!({"type": "response.apply_patch_call_operation_diff.delta", "sequence_number": 2, "output_index": 0, "item_id": "ap_1", "delta": "+SECRET"})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 3, "output_index": 1, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}})),
            ("response.apply_patch_call_operation_diff.done", json!({"type": "response.apply_patch_call_operation_diff.done", "sequence_number": 4, "output_index": 0, "item_id": "ap_1", "diff": "+SECRET"})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 5, "output_index": 0, "item": item("completed", "+SECRET")})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 6, "response": {"id": "resp_1", "status": "completed",
                "output": [item("completed", "+SECRET")], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("SECRET")), "an unread diff reached the client: {frames:?}");
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "apply_patch_call"), "an unread call reached the client");
        assert!(frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("was read before its payload was stated"))), "{frames:?}");
    }

    #[test]
    fn a_non_streaming_built_in_answer_translated_away_records_what_was_not_carried() {
        use crate::pipeline::response::TransformState;
        let response = json!({"output": [
            {"type": "message", "content": []},
            {"type": "function_call", "call_id": "c0", "name": "f", "arguments": "{}"},
            {"type": "local_shell_call", "call_id": "c1", "action": {"type": "exec", "command": ["ls"], "env": {}}}
        ]});
        // The row numbers the answer's calls as it recorded them — here the
        // built-in call is its call 4 (a call policy removed came before it).
        let mut state = TransformState::new(crate::api::sse::ApiVersion::ChatCompletions);
        state.accumulated_tool_calls.push(crate::pipeline::response::AccumulatedToolCall {
            index: 4,
            id: "c1".into(),
            function_name: "local_shell_call".into(),
            arguments: String::new(),
            server_tool: false,
        });
        crate::pipeline::response_pipeline::record_builtins_not_carried(&response, crate::api::sse::ApiVersion::Responses, &mut state);
        let blocks: Vec<String> = state.response_injection_blocks.iter().map(|b| format!("{} {}", b.transform, b.content)).collect();
        assert_eq!(blocks.len(), 1, "{blocks:?}");
        assert!(blocks[0].starts_with(TransformState::NOT_CARRIED) && blocks[0].contains("tool call 4:"), "{blocks:?}");
    }

    #[test]
    fn a_built_in_call_reaches_a_client_on_another_protocol_as_a_notice() {
        // Only a Responses client has the item to run. Every other client is
        // told, once, that the call was not carried — never handed a call of
        // another kind — and the audit is given the reason.
        use crate::api::sse::ApiVersion;
        use crate::pipeline::response::Withheld;
        use crate::pipeline::response_pipeline::EventEmitter;
        for client in [ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages, ApiVersion::GoogleGemini] {
            let mut emitter = EventEmitter::new(client, ApiVersion::Responses, "m", "req-1", None, None, 0, 0);
            let mut parser = crate::api::sse::StreamParser::new(ApiVersion::Responses);
            let mut out = String::new();
            for (name, data) in shell_call_upstream("ls -la") {
                let event = SseEvent { event_type: Some(name.to_string()), data: data.to_string(), id: None };
                for de in parser.parse(&event) {
                    for chunk in emitter.process_streaming_event(&de, Some(&event)) {
                        out.push_str(&String::from_utf8_lossy(&chunk));
                    }
                }
            }
            for chunk in emitter.flush() {
                out.push_str(&String::from_utf8_lossy(&chunk));
            }
            assert!(out.contains("was not carried"), "{client:?} was not told: {out}");
            assert_eq!(out.matches("was not carried").count(), 1, "{client:?} was told more than once: {out}");
            assert!(!out.contains("ls -la"), "{client:?} was handed the call: {out}");
            for call_kind in ["tool_calls", "tool_use", "functionCall"] {
                assert!(!out.contains(call_kind), "{client:?} was handed a {call_kind}: {out}");
            }
            assert_eq!(
                emitter.take_withheld_calls(),
                [(0, Withheld::NotCarried(crate::api::domain::ClientBuiltin::Shell))],
                "{client:?}"
            );
        }
    }

    #[test]
    fn a_rewritten_built_in_call_closes_complete_unless_its_done_said_otherwise() {
        // Restated from its opening alone, the call is closed as completed; a
        // done that states another status (`incomplete`) keeps it.
        let opening = |status: &str, kind: &str| SseEvent {
            event_type: Some(kind.to_string()),
            data: json!({"type": kind, "output_index": 3, "item": shell_call_item(status, &[])}).to_string(),
            id: None,
        };
        let call = DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".into()),
            function_name: Some("shell_call".into()),
            arguments_delta: String::new(),
            form: CallArguments::ClientBuiltin(crate::api::domain::ClientBuiltin::Shell),
        };
        let statuses = |block: &PendingBlock| -> Vec<serde_json::Value> {
            builtin_call_frames(block, crate::api::domain::ClientBuiltin::Shell, r#"{"commands":["ls"]}"#)
                .iter()
                .map(|f| serde_json::from_str::<serde_json::Value>(&f.data).unwrap())
                .map(|v| json!([v["type"], v["output_index"], v["item"]["status"], v["item"]["action"]]))
                .collect()
        };
        let opened_only = PendingBlock::new(BlockType::ToolUse, &call, Some(opening("in_progress", "response.output_item.added")));
        assert_eq!(statuses(&opened_only), [json!(["response.output_item.done", 3, "completed", {"commands": ["ls"]}])]);
        let mut cut_short = PendingBlock::new(BlockType::ToolUse, &call, Some(opening("in_progress", "response.output_item.added")));
        cut_short.accumulate(&call, Some(opening("incomplete", "response.output_item.done")));
        assert_eq!(statuses(&cut_short), [json!(["response.output_item.done", 3, "incomplete", {"commands": ["ls"]}])]);
    }

    #[test]
    fn a_non_streaming_rewrite_a_built_in_call_cannot_take_removes_it() {
        // The rule's regex runs on the arguments' JSON text; a greedy one eats
        // the closing brackets and leaves no JSON. A built-in call's payload
        // cannot take it, so the call is removed — never left standing with
        // the command policy meant to change.
        use crate::api::sse::ApiVersion;
        let profiles = builtin_shell_accumulator(vec![]).tool_field_profiles.clone();
        let rules = rules_from_json(vec![json!({
            "id": "T-11725",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "shell_exec" }],
            "action": { "kind": "replace", "regex": "rm -rf .*", "with": "echo refused" },
            "risk": "danger"
        })]);
        let mut response = json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["rm -rf /"]}}
        ]});
        // A script whose rewrite the call cannot take removes it too, recorded:
        // a script writes an object, which a batch of actions is not.
        let mut scripted = json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "computer_call", "id": "cu_1", "call_id": "call_1", "status": "completed", "pending_safety_checks": [],
             "actions": [{"type": "type", "text": "rm -rf /"}]}
        ]});
        let program = make_response_program_with_source("tool_script", "tool", r#"fn transform(ctx) { ctx.arguments = "{\"type\":\"wait\"}"; ctx }"#);
        let (_, _, _, injected, _) = apply_response_scripts_json(
            &mut scripted, ApiVersion::Responses, std::slice::from_ref(&program), &crate::scripting::ScriptEngine::new(),
            &make_block_meta(), false, ScriptFailMode::Open,
        );
        assert!(!scripted.to_string().contains("rm -rf"), "{scripted}");
        let notice = &scripted["output"][0];
        assert!(notice["id"].is_string() && notice["status"] == "completed" && notice["content"][0]["annotations"] == json!([]),
            "the notice is a whole output message: {notice}");
        assert!(injected.iter().any(|b| b.action == "remove" && b.field == "tool_call"), "{injected:?}");
        let (blocked, _, mods) = apply_response_policy_json(&mut response, ApiVersion::Responses, &rules, &profiles, None, None, &[]);
        assert_eq!(blocked, ["shell_call"]);
        assert!(mods.is_empty(), "a rewrite that was not written is not recorded as one");
        assert!(!response.to_string().contains("rm -rf"), "{response}");
    }

    #[test]
    fn a_streamed_rewrite_a_built_in_call_cannot_take_removes_it_as_that_rule() {
        // As on a non-streaming answer: the call is removed as blocked by the
        // rule whose rewrite it could not take, its id kept for the rule chip.
        let rules = rules_from_json(vec![json!({
            "id": "R-greedy",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "shell_exec" }],
            "action": { "kind": "replace", "regex": "rm -rf .*", "with": "echo refused" },
            "risk": "danger"
        })]);
        let mut acc = builtin_shell_accumulator(rules);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &shell_call_upstream("rm -rf /"), &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("rm -rf")), "{frames:?}");
        assert!(frames.iter().any(|(_, d)| d["delta"].as_str().is_some_and(|t| t.contains("blocked by policy"))), "{frames:?}");
        assert_eq!(acc.blocked_tool_infos.len(), 1);
        assert_eq!(acc.blocked_tool_infos[0].rule_id, "R-greedy");
        assert!(acc.tool_arg_modifications.is_empty());
    }

    fn scripted_builtin_accumulator(source: &str) -> BlockAccumulator {
        let programs = vec![make_response_program_with_source("tool_script", "tool", source)];
        BlockAccumulator::new(
            BlockInterests { buffer_tool_blocks: true, buffer_text_blocks: false, buffer_thinking_blocks: false },
            vec![],
            Default::default(),
            programs,
            Some(Arc::new(ScriptEngine::new())),
            Some(make_block_meta()),
            false,
            ScriptFailMode::Open,
            vec![],
            false,
            false,
            crate::api::sse::ApiVersion::Responses,
        )
    }

    #[test]
    fn a_script_renaming_a_built_in_call_keeps_the_call_and_its_payload() {
        // A rename is recorded, not applied; the script left the arguments, so
        // the call goes out as the upstream sent it — never emptied away.
        let mut acc = scripted_builtin_accumulator(r#"fn transform(ctx) { ctx.tool_name = "renamed"; ctx }"#);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &shell_call_upstream("ls -la"), &mut acc);
        let done = frames
            .iter()
            .find(|(_, d)| d["type"] == "response.output_item.done" && d["item"]["type"] == "shell_call")
            .unwrap_or_else(|| panic!("the call was dropped: {frames:?}"));
        assert_eq!(done.1["item"]["action"]["commands"], json!(["ls -la"]));
        assert!(acc.badges.clone().finish().contains(&crate::audit::AuditBadge::ModifiedNotApplied));
    }

    #[test]
    fn a_script_rewrite_a_built_in_call_cannot_take_removes_it_and_says_why() {
        // A script writes an object; a computer call's batched `actions` is a
        // list, so it cannot take one. Removed — and not as a call the client
        // "cannot run": the client can, the rewrite could not be written.
        let batch = |status: &str| json!({"id": "cu_1", "type": "computer_call", "call_id": "call_1", "status": status,
            "pending_safety_checks": [], "actions": [{"type": "type", "text": "SECRET"}]});
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": batch("in_progress")})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 2, "output_index": 0, "item": batch("completed")})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 3, "response": {"id": "resp_1", "status": "completed",
                "output": [batch("completed")], "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let mut acc = scripted_builtin_accumulator(r#"fn transform(ctx) { ctx.arguments = "{\"type\":\"wait\"}"; ctx }"#);
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("SECRET")), "{frames:?}");
        assert!(final_output(&frames).iter().all(|i| i["type"] != "computer_call"), "{frames:?}");
        let text: String = frames.iter().filter_map(|(_, d)| d["delta"].as_str()).collect();
        assert!(text.contains("could not be written into it") && !text.contains("cannot run"), "{text}");
    }

    #[test]
    fn a_computer_call_read_before_its_batch_is_stated_is_withheld() {
        // Opened with no payload, read before its done (another item opened
        // first); the done then states a batch in `actions` no policy read.
        // The client is given no part of the call.
        let item = |status: &str, extra: serde_json::Value| {
            let mut v = json!({"id": "cu_1", "type": "computer_call", "call_id": "call_1", "status": status, "pending_safety_checks": []});
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            v
        };
        let upstream = vec![
            ("response.created", json!({"type": "response.created", "sequence_number": 0, "response": {"id": "resp_1", "status": "in_progress"}})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": item("in_progress", json!({}))})),
            ("response.output_item.added", json!({"type": "response.output_item.added", "sequence_number": 2, "output_index": 1, "item": {"id": "msg_1", "type": "message", "role": "assistant", "status": "in_progress", "content": []}})),
            ("response.output_item.done", json!({"type": "response.output_item.done", "sequence_number": 3, "output_index": 0,
                "item": item("completed", json!({"action": null, "actions": [{"type": "type", "text": "SECRET"}]}))})),
            ("response.completed", json!({"type": "response.completed", "sequence_number": 4, "response": {"id": "resp_1", "status": "completed",
                "output": [item("completed", json!({"action": null, "actions": [{"type": "type", "text": "SECRET"}]}))],
                "usage": {"input_tokens": 5, "output_tokens": 9, "total_tokens": 14}}})),
        ];
        let mut acc = builtin_shell_accumulator(block_destructive_shell());
        let frames = client_frames(crate::api::sse::ApiVersion::Responses, &upstream, &mut acc);
        assert!(!frames.iter().any(|(_, d)| d.to_string().contains("SECRET")), "{frames:?}");
        assert!(final_output(&frames).iter().all(|i| i["type"] != "computer_call"), "an unread call stayed listed");
    }

    #[test]
    fn a_drop_rule_removes_a_built_in_call_rather_than_empty_it() {
        // `drop` rewrites to `{}`: an emptied payload is no call a client can
        // be given, so the call is removed as blocked by that rule.
        use crate::api::sse::ApiVersion;
        let rules = rules_from_json(vec![json!({
            "id": "R-drop",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "shell_exec" }],
            "action": { "kind": "replace", "drop": true },
            "risk": "danger"
        })]);
        let mut acc = builtin_shell_accumulator(rules.clone());
        let frames = client_frames(ApiVersion::Responses, &shell_call_upstream("rm -rf /"), &mut acc);
        assert!(!frames.iter().any(|(_, d)| d["item"]["type"] == "shell_call"), "{frames:?}");
        assert_eq!(acc.blocked_tool_infos.iter().map(|b| b.rule_id.as_str()).collect::<Vec<_>>(), ["R-drop"]);
        let profiles = acc.tool_field_profiles.clone();
        let mut response = json!({"output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["rm -rf /"]}}
        ]});
        let (blocked, _, _) = apply_response_policy_json(&mut response, ApiVersion::Responses, &rules, &profiles, None, None, &[]);
        assert_eq!(blocked, ["shell_call"]);
        assert!(response["output"].as_array().unwrap().iter().all(|i| i["type"] != "shell_call"), "{response}");
    }

    #[test]
    fn a_non_streaming_script_reads_a_built_in_call_and_keeps_its_name() {
        let program = make_response_program_with_source(
            "neutralise",
            "tool",
            r#"fn transform(ctx) { ctx.arguments = "{\"commands\":[\"echo safe\"]}"; ctx.tool_name = "renamed"; ctx }"#,
        );
        let mut resp = json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["rm -rf /"]}}
        ]});
        let (badges, ..) = apply_response_scripts_json(
            &mut resp,
            crate::api::sse::ApiVersion::Responses,
            std::slice::from_ref(&program),
            &crate::scripting::ScriptEngine::new(),
            &make_block_meta(),
            false,
            ScriptFailMode::Open,
        );
        assert_eq!(
            resp["output"][0],
            json!({"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["echo safe"]}})
        );
        assert!(badges.finish().contains(&crate::audit::AuditBadge::ModifiedNotApplied), "the rename it did not apply is recorded");
    }

    #[test]
    fn a_non_streaming_built_in_call_meets_the_same_policy() {
        use crate::api::sse::ApiVersion;
        let profiles = builtin_shell_accumulator(vec![]).tool_field_profiles.clone();
        let mut response = json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["rm -rf /"]}},
            {"type": "shell_call", "id": "sh_2", "call_id": "call_2", "status": "completed", "action": {"commands": ["ls -la"]}}
        ]});
        let (blocked, _, _) =
            apply_response_policy_json(&mut response, ApiVersion::Responses, &block_destructive_shell(), &profiles, None, None, &[]);
        assert_eq!(blocked, ["shell_call"]);
        let output = response["output"].as_array().unwrap();
        assert!(!response.to_string().contains("rm -rf"), "{response}");
        assert_eq!(output[0]["id"], "sh_2", "the ordinary call stays: {response}");

        let rewrite = rules_from_json(vec![json!({
            "id": "T-11925",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{ "target": "tool_id", "op": "equals", "value": "shell_exec" }],
            "action": { "kind": "replace", "regex": "rm -rf /", "with": "echo refused" },
            "risk": "danger"
        })]);
        let mut response = json!({"id": "resp_1", "status": "completed", "output": [
            {"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed", "action": {"commands": ["rm -rf /"]}, "environment": {"type": "local"}}
        ]});
        apply_response_policy_json(&mut response, ApiVersion::Responses, &rewrite, &profiles, None, None, &[]);
        assert_eq!(
            response["output"][0],
            json!({"type": "shell_call", "id": "sh_1", "call_id": "call_1", "status": "completed",
                   "action": {"commands": ["echo refused"]}, "environment": {"type": "local"}})
        );
    }
}
