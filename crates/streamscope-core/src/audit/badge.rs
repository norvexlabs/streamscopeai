//! Typed audit badges — the contract between the proxy pipeline (setter)
//! and the admin UI (consumer).
//!
//! A badge is a single user-facing chip on the audit log row. Each variant
//! carries only the data needed for its tooltip; display label, icon, and
//! color tier live in the UI registry keyed by `code`.
//!
//! **Codes are append-only.** Add a new variant + new code; never rename.
//! Setters call [`BadgeBuilder`] (it dedupes/aggregates).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::sse::ApiVersion;

/// Which side of the request/response cycle emitted this badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

/// Block kind for `BlockOverflow` (response stream block dropped fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    Text,
    Thinking,
}

/// Severity of an agent-emitted session alert.
///
/// `Info` is the default emission floor — a neutral annotation that doesn't
/// demand operator action. `Minor` requires specific evidence; `Major` is
/// reserved for active exploitation or destructive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlertLevel {
    Info,
    Minor,
    Major,
}

impl AlertLevel {
    /// The level as stored in `sessions.alert_level` and spelled on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    /// The level a stored `sessions.alert_level` names; `None` for any other text.
    pub fn parse(stored: &str) -> Option<Self> {
        [Self::Info, Self::Minor, Self::Major].into_iter().find(|l| l.as_str() == stored)
    }
}

/// What the inline injection guardrail did with a flagged verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailAction {
    /// Observe mode — the verdict was flagged and audited, content left
    /// untouched.
    Flag,
    /// Enforce mode — flagged content was stripped to a visible placeholder
    /// before the model saw it.
    Block,
}

impl GuardrailAction {
    /// Combine two actions, keeping the stronger one (`Block` over `Flag`).
    fn max(self, other: GuardrailAction) -> GuardrailAction {
        match (self, other) {
            (GuardrailAction::Block, _) | (_, GuardrailAction::Block) => {
                GuardrailAction::Block
            }
            _ => GuardrailAction::Flag,
        }
    }
}

/// A typed audit badge. Wire format is `{ "code": "<snake_case>", ...payload }`.
///
/// One variant per user-facing chip on the audit log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum AuditBadge {
    /// Request or response content was rewritten by a transform.
    /// Emitted once when at least one `injection_block` exists.
    Modified,

    /// Policy produced a rewrite that was NOT applied on the wire: the caller
    /// (an inline-AI enforcement point analyzing out-of-band) declared itself
    /// verdict-only, or the block was a thinking block the provider signed and
    /// refuses back altered. The original content went forward unmodified. The
    /// distinct code keeps the audit truthful — `modified` means the wire
    /// changed; this means it *would have*.
    ModifiedNotApplied,

    /// Context-window compression engaged.
    Compressed,

    /// Upstream returned malformed JSON; gateway repaired it.
    JsonHealed,

    /// Tool policy blocked one or more tool calls.
    /// `phase=request` for name-match blocks, `phase=response` for argument-match blocks.
    ToolBlocked {
        phase: Phase,
        count: u32,
        names: Vec<String>,
    },

    /// Tool block fail-closed because the buffered event count exceeded the analysis window.
    /// Operator should investigate.
    ToolBlockedOverflow {
        phase: Phase,
        count: u32,
        names: Vec<String>,
    },

    /// Tool policy would have blocked these calls, and they were not stopped:
    /// the enforcement point of an out-of-band `/v1/analyze` exchange forwards
    /// the original, or the analyzed answer had already reached the client.
    /// Never counted as a block.
    ToolBlockNotApplied {
        phase: Phase,
        count: u32,
        names: Vec<String>,
    },

    /// A streaming text/thinking block was dropped (fail-closed) because it
    /// exceeded the buffered-event cap during script analysis.
    BlockOverflow { kind: BlockKind, count: u32 },

    /// Rhai script chain failed in fail-closed mode.
    /// Tooltip lists the offending program names.
    ScriptError {
        phase: Phase,
        count: u32,
        programs: Vec<String>,
    },

    /// Cross-protocol translation happened. `not_carried` names each part of
    /// the request the target protocol or model has no channel for — a hosted
    /// tool, a provider-specific tool choice, a reasoning request to a model
    /// that does not reason — so a translation that dropped something says what.
    ProtocolTranslated {
        from: ApiVersion,
        to: ApiVersion,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        not_carried: Vec<String>,
    },

    /// The request needed a capability the alias's chosen upstream does not
    /// declare, so the gateway forwarded it to the next target in the chain
    /// that does. `from` is the displaced model and `reason` the capability
    /// that displaced it; the row's `model_used` records the model that
    /// actually served the request. Without this the substitution would be
    /// invisible — the alias's priority / load-balancing order silently did
    /// not decide this request.
    CapabilityRerouted { from: String, reason: String },

    /// Request hit the catch-all proxy (unmatched route).
    Catchall,

    /// Tool names were sanitized before forwarding upstream. Only emitted when `count > 0`.
    SanitizedToolNames { count: u32 },

    /// Tool names emitted by the *upstream model* in a response (streaming
    /// or non-streaming) were sanitized before being delivered to the
    /// client. Parallel to [`Self::SanitizedToolNames`] but on the response
    /// path. Only emitted when `count > 0`. Operators inspecting the audit
    /// detail can see the original→sanitized mapping in
    /// `transform_diff.injection_blocks` entries with
    /// `transform: "response_sanitize_tool_names"`.
    ResponseSanitizedToolNames { count: u32 },

    /// One expert's alert of one level. Never written by the current agent,
    /// which raises its alerts on the session (`SessionAlert`).
    AgentAlert { axis: String, level: AlertLevel },

    /// MCP request returned a JSON-RPC error. `code` is the JSON-RPC error
    /// code (`-32xxx`) — `-32429` rate limited, `-32500` upstream credential
    /// unavailable, `-32506` blocked by policy, etc. Tooltip resolves the
    /// code to a human-readable label in the UI registry.
    McpRpcError { rpc_code: i32 },

    /// MCP upstream is using the legacy `text/event-stream` GET transport
    /// instead of Streamable HTTP. Operator-visible signal that the upstream
    /// hasn't migrated to spec 2025-03-26+.
    McpLegacySse,

    /// MCP `sampling/createMessage` was intercepted by the gateway and
    /// served via a synthetic LLM call instead of being forwarded to the
    /// connected agent. Badged on the `mcp_audit` row. The linked
    /// `llm_audit` row carries the matching [`AuditBadge::LlmSyntheticSampling`].
    McpSamplingIntercepted,

    /// LLM call was synthesized by the gateway in response to an MCP
    /// `sampling/createMessage` interception (not initiated by an
    /// upstream client). Badged on the `llm_audit` row.
    LlmSyntheticSampling,

    /// Tool call with canonical id `web_search` or `web_fetch` was blocked
    /// by tool policy. Lands on the `mcp_audit` row alongside the generic
    /// `ToolBlocked` chip so the UI can show a per-domain icon without
    /// re-parsing the tool name. Fires on the canonical `tool_id`, not the
    /// wire name — so it covers `/mcp/web` direct calls (canonical id
    /// resolved via the `builtin-web` field profile) and any future MCP
    /// upstream that exposes a tool resolving to the same canonical id.
    WebBlocked,

    /// At least one URL in the call was denied by the URL-filter chain
    /// (allow / deny domains, future external HTTP filters). For search,
    /// counts hits removed; for fetch, the target URL itself was denied.
    WebUrlFiltered { count: u32 },

    /// Search returned hits but the URL-filter chain dropped every one of
    /// them — the model received an empty result.
    WebAllResultsFiltered,

    /// Upstream provider returned 429 (or equivalent quota exceeded).
    WebRateLimited,

    /// Fetched content was stripped from `audit_media_blobs` storage
    /// because it exceeded `media_blob_max_size_mb` or because
    /// `media_blob_storage_enabled = false`.
    WebContentStripped { reason: String },

    /// The gateway could not deliver this audit record whole — it was too
    /// large (`oversized`) or nested too deep (`too_deep`) for the edge's
    /// sync to admin-api — so its structured payload fields (params, results,
    /// diffs) were left out, and long text possibly replaced by a size note;
    /// its identity, status and counters were recorded.
    RecordStripped { reason: String },

    /// A body this record names — a conversation message, a tool set, the
    /// system prompt or a media blob — is not held by admin-api: the gateway
    /// could not deliver it, or the database refused to store it. The record
    /// is stored and its turn renders without that body.
    ContentUnavailable,

    /// Fetch refused because the target host resolved to an internal /
    /// loopback / link-local / IMDS address.
    WebSsrfRefused,

    /// Fetch refused because the URL scheme was not http/https.
    WebSchemeRefused,

    /// A server-side server-tool the client requested (Anthropic
    /// `web_search_20250305`, OpenAI Responses `web_search_preview`, Gemini
    /// `google_search`) was emulated by the gateway via the substitution
    /// loop. Badged on the orchestrating `llm_audit` row; the executor's
    /// `web_audit` rows carry `surface='substitution'` and
    /// `parent_request_id` linking back. Wiring lands in a follow-up PR.
    WebSubstitutedServer { server_type: String },

    /// A client-side function-tool a known client declared (Claude Code
    /// `WebFetch`/`WebSearch`, opencode `webfetch`/`websearch`) was
    /// intercepted and routed through `WebService` instead of being
    /// echoed to the client. Badged on the orchestrating `llm_audit` row.
    /// The substituted `tool_use` is invisible to the client. Wiring lands
    /// in a follow-up PR.
    WebSubstitutedClient { client_label: String },

    /// The substitution loop hit `web.substitution_max_iterations`
    /// without the upstream emitting a final non-tool-use response. The
    /// last upstream response was forwarded to the client as-is.
    WebSubstitutionMaxIter,

    /// One of the executor calls inside the substitution loop failed; the
    /// loop surfaced the error to the upstream as a tool-execution error
    /// and continued.
    WebSubstitutionToolError,

    /// Substitution agent loop ran for a round whose upstream stream
    /// terminated without a `Done` event (idle timeout / decode error /
    /// half-close) while pending intercepted calls were queued. The loop
    /// forwarded the round's last bytes as-is and DROPPED the pending
    /// intercepts (no executor ran). Appends the dropped tool names so
    /// operators can attribute the loss.
    WebSubstitutionTruncatedStream,

    /// One upstream turn emitted both real and intercepted tool_use
    /// blocks. The buffered-discard path forwarded the real blocks as-is
    /// and DROPPED the intercepted ones (no executor ran). Decision #4
    /// requires splicing both — full implementation pending PR-3. The
    /// badge surfaces the partial behaviour for now.
    WebSubstitutionMixedPending,

    /// Re-issuing the upstream call after a substitution round failed
    /// (HTTP error, transport error, retry exhaustion). The agent loop
    /// stopped and yielded an empty response to the client (with a
    /// synthetic error marker).
    WebSubstitutionForwardFailed,

    /// Re-serializing the cumulative `DomainRequest` for the next round
    /// failed (translation / encoding error). Same client effect as
    /// `WebSubstitutionForwardFailed`.
    WebSubstitutionSerializeFailed,

    /// A request matched a substitution rule but the agent loop is
    /// streaming-only — the upstream `tool_use` echo flowed back to the
    /// client unchanged. Visible-mode + non-streaming substitution land
    /// in a follow-up release.
    WebSubstitutionNonStreaming,

    /// Cumulative `DomainRequest` body re-sent upstream across substitution
    /// rounds exceeded `web.substitution_history_max_bytes`. The
    /// agent loop dropped the oldest splice (assistant tool_use + contiguous
    /// tool_result messages) one or more times and re-translated; if the
    /// body is still over cap after the bounded truncation pass, the loop
    /// surfaces this badge and aborts via the serialize-failed path. Each
    /// truncation also emits an `injection_block` with `field="history"`
    /// and `action="truncate_oldest"`.
    WebSubstitutionHistoryCap,

    /// The substitution agent loop was cancelled mid-flight — typically
    /// the client SSE response was dropped before the loop reached its
    /// terminal round. The cancellation token threaded through
    /// `WebContext` short-circuits the in-flight executor calls and
    /// upstream re-issue so the gateway stops wasting upstream egress on a
    /// conversation the client has abandoned. Pending intercepted calls
    /// surface as `injection_blocks[]` with `reason="cancelled"`.
    WebSubstitutionCancelled,

    /// One or more parked mixed-pending entries from a prior request in the
    /// same session were spliced into the inbound conversation as
    /// synthesised `assistant tool_use → user tool_result` pairs before the
    /// request was forwarded upstream. Pairs with the
    /// `WebSubstitutionMixedPending` badge on the *prior* request
    /// (which dispatched and parked the result); this badge surfaces on
    /// the *next* request, completing the audit trail for the
    /// cross-request strict-Decision-#4 splice. `count` is the number of
    /// parked entries actually folded in.
    WebSubstitutionMixedPendingSpliced { count: u32 },

    /// Inbound mixed-pending splice was attempted but failed mid-flight —
    /// either the `DomainRequest` → wire translation errored, or the
    /// re-parse of the translated bytes errored. The cache entries had
    /// already been drained, so `count` parked dispatched results were
    /// dropped without reaching the model. The "Nothing is silently
    /// discarded" invariant: every dropped parked entry shows up on this
    /// row's `injection_blocks[]` with `transform="mixed_pending_splice"`
    /// and `action="drop_on_translation_failure"` so operators can see
    /// what was lost.
    WebSubstitutionMixedPendingSpliceFailed { count: u32 },

    /// The inline injection guardrail scanned untrusted fetched/searched
    /// content and flagged at least one item. `action=flag` in observe mode
    /// (content untouched, the would-have-blocked signal); `action=block` in
    /// enforce (content stripped to a placeholder). `categories` lists the
    /// distinct finding categories; `max_confidence` is the highest positive
    /// score across the flagged items. Aggregated on the orchestrating
    /// `llm_audit` row (substitution path) or stamped on the `web_audit` row
    /// (direct `/mcp/web`).
    Guardrail {
        categories: Vec<crate::guardrail::GuardrailCategory>,
        max_confidence: f32,
        action: GuardrailAction,
    },

    /// The guardrail detector errored (timeout / transport / parse) and the
    /// tenant's `fail_mode` decided the request's fate. Surfaced so a fetch
    /// that went unscored is never silently invisible.
    GuardrailError { reason: String },

    /// The answer came from the gateway's response cache — no upstream call was
    /// made. `avoided_cost` prices the cached response's stored token usage
    /// at the alias's current rates: what this request would have cost. The row
    /// itself is charged `$0`. `age_seconds` is how long the entry had been
    /// resident when it was served; `similarity` is present only for a
    /// semantic-mode hit.
    CacheHit {
        avoided_cost: f64,
        age_seconds: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        similarity: Option<f32>,
    },

    /// A cache preset in `observe` mode matched an entry that *would* have been
    /// served. The request still went upstream and was billed normally — this
    /// records the would-be hit so an admin can measure before enforcing.
    CacheObserveHit {
        age_seconds: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        similarity: Option<f32>,
    },

    /// A cache-enabled alias produced a response that was NOT stored, and why
    /// (`tool_calls`, `error_status`, `zero_completion`, `entry_too_large`,
    /// `cache_full`, `client_bypass`). Only ever appears on an alias with
    /// caching enabled, so a cache that never fills is diagnosable instead of
    /// silently inert.
    CacheStoreSkipped { reason: String },

    /// A cache preset asked for semantic matching, and the gateway could not do
    /// it for this request (`no_embedding_alias`, `embedding_alias_unresolved`,
    /// `embedding_failed`, `embedding_timeout`). The request was served
    /// normally and exact matching still applied — but an alias that quietly
    /// stops matching semantically looks identical to one nobody is repeating
    /// prompts on, so the reason is recorded instead of inferred.
    CacheSemanticSkipped { reason: String },

    /// The request waited for upstream capacity before it was dispatched, and
    /// for how long. It says the model was saturated and this caller's turn came
    /// after others — the one thing that explains a slow request the upstream
    /// itself served quickly.
    Queued { wait_ms: u64 },

    /// The request was served by a replica other than the one it was routed to,
    /// because that one had no room at the moment it asked.
    ///
    /// The row already names the replica that answered; what this adds is that
    /// the request MOVED, which nothing else records. It is the readable form
    /// of a fleet running hot on one replica — and, for a session pinned to a
    /// replica for its prompt cache, the reason a turn was slower than the ones
    /// around it.
    Spilled,

    /// No price is known for the model this request used, so its recorded cost is
    /// a floor of zero rather than a real figure.
    ///
    /// This is NOT the same as a free model, and the distinction is the point: a
    /// zero cost skips budget accrual entirely, so an enforcing budget over an
    /// unpriced model never fires. Without the badge that failure is invisible —
    /// the cap looks configured and simply does nothing. Resolve it by pricing the
    /// model on its upstream, or by linking it to a catalog entry.
    Unpriced,

    /// The request was conformed to an upstream whose API reads the target
    /// protocol differently (`dialect`: `mistral`, `openai_compatible`, or
    /// `anthropic` for what Anthropic verifies). `adapted` names each
    /// rewrite that kept the meaning (a renamed parameter, a narrowed tool
    /// choice), `not_carried` each part the upstream has no channel for, which
    /// was removed. Recorded with or without a protocol translation: a request
    /// forwarded in its own protocol is conformed too, and the row renders the
    /// request as the client sent it.
    UpstreamAdapted {
        dialect: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        adapted: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        not_carried: Vec<String>,
    },

    /// The agent raised an alert on this LLM audit row's session: its most
    /// severe level and every expert that raised one. Derived by the audit list
    /// at read time from the session's alert columns — never stored on the row
    /// (audit rows are never rewritten).
    SessionAlert { experts: Vec<String>, level: AlertLevel },
}

impl AuditBadge {
    /// Stable wire `code` string for filtering/queries.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Modified => "modified",
            Self::ModifiedNotApplied => "modified_not_applied",
            Self::Compressed => "compressed",
            Self::JsonHealed => "json_healed",
            Self::ToolBlocked { .. } => "tool_blocked",
            Self::ToolBlockedOverflow { .. } => "tool_blocked_overflow",
            Self::ToolBlockNotApplied { .. } => "tool_block_not_applied",
            Self::BlockOverflow { .. } => "block_overflow",
            Self::ScriptError { .. } => "script_error",
            Self::ProtocolTranslated { .. } => "protocol_translated",
            Self::CapabilityRerouted { .. } => "capability_rerouted",
            Self::Catchall => "catchall",
            Self::SanitizedToolNames { .. } => "sanitized_tool_names",
            Self::ResponseSanitizedToolNames { .. } => "response_sanitized_tool_names",
            Self::AgentAlert { .. } => "agent_alert",
            Self::SessionAlert { .. } => "session_alert",
            Self::McpRpcError { .. } => "mcp_rpc_error",
            Self::McpLegacySse => "mcp_legacy_sse",
            Self::McpSamplingIntercepted => "mcp_sampling_intercepted",
            Self::LlmSyntheticSampling => "llm_synthetic_sampling",
            Self::CacheHit { .. } => "cache_hit",
            Self::CacheObserveHit { .. } => "cache_observe_hit",
            Self::CacheStoreSkipped { .. } => "cache_store_skipped",
            Self::CacheSemanticSkipped { .. } => "cache_semantic_skipped",
            Self::Queued { .. } => "queued",
            Self::Spilled => "spilled",
            Self::Unpriced => "unpriced",
            Self::UpstreamAdapted { .. } => "upstream_adapted",
            Self::WebBlocked => "web_blocked",
            Self::WebUrlFiltered { .. } => "web_url_filtered",
            Self::WebAllResultsFiltered => "web_all_results_filtered",
            Self::WebRateLimited => "web_rate_limited",
            Self::WebContentStripped { .. } => "web_content_stripped",
            Self::RecordStripped { .. } => "record_stripped",
            Self::ContentUnavailable => "content_unavailable",
            Self::WebSsrfRefused => "web_ssrf_refused",
            Self::WebSchemeRefused => "web_scheme_refused",
            Self::WebSubstitutedServer { .. } => "web_substituted_server",
            Self::WebSubstitutedClient { .. } => "web_substituted_client",
            Self::WebSubstitutionMaxIter => "web_substitution_max_iter",
            Self::WebSubstitutionToolError => "web_substitution_tool_error",
            Self::WebSubstitutionTruncatedStream => "web_substitution_truncated_stream",
            Self::WebSubstitutionMixedPending => "web_substitution_mixed_pending",
            Self::WebSubstitutionForwardFailed => "web_substitution_forward_failed",
            Self::WebSubstitutionSerializeFailed => "web_substitution_serialize_failed",
            Self::WebSubstitutionNonStreaming => "web_substitution_non_streaming",
            Self::WebSubstitutionHistoryCap => "web_substitution_history_cap",
            Self::WebSubstitutionCancelled => "web_substitution_cancelled",
            Self::WebSubstitutionMixedPendingSpliced { .. } => {
                "web_substitution_mixed_pending_spliced"
            }
            Self::WebSubstitutionMixedPendingSpliceFailed { .. } => {
                "web_substitution_mixed_pending_splice_failed"
            }
            Self::Guardrail { .. } => "guardrail",
            Self::GuardrailError { .. } => "guardrail_error",
        }
    }
}

/// Helper that aggregates badges as the pipeline runs, deduping repeat
/// emissions and rolling up per-tool / per-program detail into a single
/// variant per category.
///
/// Setters call `add_*` helpers; `finish()` drains into a `Vec<AuditBadge>`
/// for the audit record.
#[derive(Debug, Default, Clone)]
pub struct BadgeBuilder {
    modified: bool,
    modified_not_applied: bool,
    compressed: bool,
    json_healed: bool,
    catchall: bool,
    sanitized_tool_names: u32,
    response_sanitized_tool_names: u32,
    tool_blocked_request: Vec<String>,
    tool_blocked_response: Vec<String>,
    tool_blocked_overflow_request: Vec<String>,
    tool_blocked_overflow_response: Vec<String>,
    tool_block_not_applied_request: Vec<String>,
    tool_block_not_applied_response: Vec<String>,
    block_overflow_text: u32,
    block_overflow_thinking: u32,
    script_errors_request: Vec<String>,
    script_errors_response: Vec<String>,
    protocol_translated: Option<(ApiVersion, ApiVersion)>,
    /// What the translation could not carry; emitted inside
    /// `ProtocolTranslated`, so it is only ever recorded beside it.
    not_carried: Vec<String>,
    /// Displaced primary + the capability that displaced it, when
    /// capability-aware selection moved this request off the target the alias
    /// chose. At most one per row: selection runs once, before the forward loop.
    capability_rerouted: Option<(String, String)>,
    /// The dialect a request was conformed to, with what that changed.
    upstream_adapted: Option<String>,
    upstream_adapted_changes: Vec<String>,
    upstream_not_carried: Vec<String>,
    agent_alerts: Vec<(String, AlertLevel)>,
    mcp_rpc_error: Option<i32>,
    mcp_legacy_sse: bool,
    mcp_sampling_intercepted: bool,
    llm_synthetic_sampling: bool,
    web_search_substituted_servers: Vec<String>,
    web_search_substituted_clients: Vec<String>,
    web_search_substitution_max_iter: bool,
    web_search_substitution_tool_error: bool,
    web_search_substitution_truncated_stream: bool,
    web_search_substitution_mixed_pending: bool,
    web_search_substitution_forward_failed: bool,
    web_search_substitution_serialize_failed: bool,
    web_search_substitution_non_streaming: bool,
    web_search_substitution_history_cap: bool,
    web_search_substitution_cancelled: bool,
    /// Sum of `count` across every `WebSubstitutionMixedPendingSpliced`
    /// emission. The final emitted badge folds the running total into a
    /// single chip per audit row.
    web_search_substitution_mixed_pending_spliced_count: u32,
    /// Sum of `count` across every `WebSubstitutionMixedPendingSpliceFailed`
    /// emission. Drained entries that couldn't be folded into the wire
    /// request and were dropped.
    web_search_substitution_mixed_pending_splice_failed_count: u32,
    /// Accumulated guardrail finding for this row: distinct categories (union),
    /// the running max confidence, and the strongest action seen (`Block`
    /// wins). `None` action = no flagged verdict yet.
    guardrail_categories: Vec<crate::guardrail::GuardrailCategory>,
    guardrail_max_confidence: f32,
    guardrail_action: Option<GuardrailAction>,
    /// First detector-error reason for this row, if the detector failed.
    guardrail_error: Option<String>,
    /// How the response cache served this row — a hit, or an observe-mode
    /// would-be hit. At most one per row (a served hit never also observes).
    cache_serve: Option<AuditBadge>,
    /// Why the response was not stored, on a cache-enabled alias. Independent of
    /// `cache_serve` — a row can carry a serve outcome and a store refusal for
    /// unrelated reasons (e.g. a client bypass records both).
    cache_store_skipped: Option<String>,
    /// Why semantic matching could not run on a semantic alias. Independent of
    /// the other two: a request can fail to embed (so it matched exactly, or
    /// not at all) and still be stored normally.
    cache_semantic_skipped: Option<String>,
    /// Milliseconds the request waited for capacity, when it waited at all.
    queued_wait_ms: Option<u64>,
    /// Whether the request ended up on a replica other than the one it was
    /// routed to.
    spilled: bool,
    unpriced: bool,
}

impl BadgeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, badge: AuditBadge) {
        match badge {
            AuditBadge::Modified => self.modified = true,
            AuditBadge::ModifiedNotApplied => self.modified_not_applied = true,
            AuditBadge::Compressed => self.compressed = true,
            AuditBadge::JsonHealed => self.json_healed = true,
            AuditBadge::Catchall => self.catchall = true,
            AuditBadge::SanitizedToolNames { count } => {
                self.sanitized_tool_names = self.sanitized_tool_names.saturating_add(count);
            }
            AuditBadge::ResponseSanitizedToolNames { count } => {
                self.response_sanitized_tool_names =
                    self.response_sanitized_tool_names.saturating_add(count);
            }
            AuditBadge::ToolBlocked { phase, names, .. } => {
                let bucket = match phase {
                    Phase::Request => &mut self.tool_blocked_request,
                    Phase::Response => &mut self.tool_blocked_response,
                };
                for n in names {
                    if !bucket.contains(&n) {
                        bucket.push(n);
                    }
                }
            }
            AuditBadge::ToolBlockNotApplied { phase, names, .. } => {
                let target = match phase {
                    Phase::Request => &mut self.tool_block_not_applied_request,
                    Phase::Response => &mut self.tool_block_not_applied_response,
                };
                for n in names {
                    if !target.contains(&n) {
                        target.push(n);
                    }
                }
            }
            AuditBadge::ToolBlockedOverflow { phase, names, .. } => {
                let bucket = match phase {
                    Phase::Request => &mut self.tool_blocked_overflow_request,
                    Phase::Response => &mut self.tool_blocked_overflow_response,
                };
                for n in names {
                    if !bucket.contains(&n) {
                        bucket.push(n);
                    }
                }
            }
            AuditBadge::BlockOverflow { kind, count } => match kind {
                BlockKind::Text => {
                    self.block_overflow_text = self.block_overflow_text.saturating_add(count);
                }
                BlockKind::Thinking => {
                    self.block_overflow_thinking =
                        self.block_overflow_thinking.saturating_add(count);
                }
            },
            AuditBadge::ScriptError {
                phase, programs, ..
            } => {
                let bucket = match phase {
                    Phase::Request => &mut self.script_errors_request,
                    Phase::Response => &mut self.script_errors_response,
                };
                for p in programs {
                    if !bucket.contains(&p) {
                        bucket.push(p);
                    }
                }
            }
            AuditBadge::ProtocolTranslated { from, to, not_carried } => {
                self.protocol_translated = Some((from, to));
                self.add_not_carried(not_carried);
            }
            AuditBadge::CapabilityRerouted { from, reason } => {
                self.capability_rerouted = Some((from, reason));
            }
            // Derived by the audit list at read time from the session; never
            // stored on a row, so there is nothing to build.
            AuditBadge::SessionAlert { .. } => {}
            AuditBadge::AgentAlert { axis, level } => {
                let entry = (axis, level);
                if !self.agent_alerts.contains(&entry) {
                    self.agent_alerts.push(entry);
                }
            }
            AuditBadge::McpRpcError { rpc_code } => {
                self.mcp_rpc_error = Some(rpc_code);
            }
            AuditBadge::McpLegacySse => {
                self.mcp_legacy_sse = true;
            }
            AuditBadge::McpSamplingIntercepted => {
                self.mcp_sampling_intercepted = true;
            }
            AuditBadge::LlmSyntheticSampling => {
                self.llm_synthetic_sampling = true;
            }
            // Web-search badges that target the executor's own audit row
            // are emitted directly on `web_audit` rows by the service
            // layer; the LLM/MCP `BadgeBuilder` intentionally does NOT
            // aggregate them. Substitution badges (`WebSubstituted*`)
            // belong on the orchestrating LLM audit row and ARE aggregated —
            // wiring lands in a follow-up PR; for now they're accepted but
            // not yet emitted by any caller.
            b @ (AuditBadge::WebBlocked
            | AuditBadge::WebUrlFiltered { .. }
            | AuditBadge::WebAllResultsFiltered
            | AuditBadge::WebRateLimited
            | AuditBadge::WebContentStripped { .. }
            | AuditBadge::WebSsrfRefused
            | AuditBadge::WebSchemeRefused) => {
                tracing::debug!(
                    code = b.code(),
                    "web badge handed to LLM/MCP BadgeBuilder; ignoring (use WebAuditRecord.badges)"
                );
            }
            // Set on the record by the edge outbox when it cannot ship the
            // record whole, after every builder has run — never aggregated.
            b @ AuditBadge::RecordStripped { .. } => {
                tracing::debug!(code = b.code(), "record badge handed to BadgeBuilder; ignoring (set on the record)");
            }
            // Set on the record by admin-api's ingest, after every builder has
            // run — never aggregated.
            b @ AuditBadge::ContentUnavailable => {
                tracing::debug!(code = b.code(), "record badge handed to BadgeBuilder; ignoring (set on the record)");
            }
            AuditBadge::WebSubstitutedServer { server_type } => {
                if !self.web_search_substituted_servers.contains(&server_type) {
                    self.web_search_substituted_servers.push(server_type);
                }
            }
            AuditBadge::WebSubstitutedClient { client_label } => {
                if !self.web_search_substituted_clients.contains(&client_label) {
                    self.web_search_substituted_clients.push(client_label);
                }
            }
            AuditBadge::WebSubstitutionMaxIter => {
                self.web_search_substitution_max_iter = true;
            }
            AuditBadge::WebSubstitutionToolError => {
                self.web_search_substitution_tool_error = true;
            }
            AuditBadge::WebSubstitutionTruncatedStream => {
                self.web_search_substitution_truncated_stream = true;
            }
            AuditBadge::WebSubstitutionMixedPending => {
                self.web_search_substitution_mixed_pending = true;
            }
            AuditBadge::WebSubstitutionForwardFailed => {
                self.web_search_substitution_forward_failed = true;
            }
            AuditBadge::WebSubstitutionSerializeFailed => {
                self.web_search_substitution_serialize_failed = true;
            }
            AuditBadge::WebSubstitutionNonStreaming => {
                self.web_search_substitution_non_streaming = true;
            }
            AuditBadge::WebSubstitutionHistoryCap => {
                self.web_search_substitution_history_cap = true;
            }
            AuditBadge::WebSubstitutionCancelled => {
                self.web_search_substitution_cancelled = true;
            }
            AuditBadge::WebSubstitutionMixedPendingSpliced { count } => {
                self.web_search_substitution_mixed_pending_spliced_count = self
                    .web_search_substitution_mixed_pending_spliced_count
                    .saturating_add(count);
            }
            AuditBadge::WebSubstitutionMixedPendingSpliceFailed { count } => {
                self.web_search_substitution_mixed_pending_splice_failed_count = self
                    .web_search_substitution_mixed_pending_splice_failed_count
                    .saturating_add(count);
            }
            AuditBadge::Guardrail {
                categories,
                max_confidence,
                action,
            } => {
                self.add_guardrail(categories, max_confidence, action);
            }
            AuditBadge::GuardrailError { reason } => {
                self.add_guardrail_error(reason);
            }
            b @ (AuditBadge::CacheHit { .. } | AuditBadge::CacheObserveHit { .. }) => {
                self.cache_serve = Some(b);
            }
            AuditBadge::CacheStoreSkipped { reason } => {
                self.cache_store_skipped = Some(reason);
            }
            AuditBadge::CacheSemanticSkipped { reason } => {
                self.cache_semantic_skipped = Some(reason);
            }
            AuditBadge::Queued { wait_ms } => {
                self.queued_wait_ms = Some(wait_ms);
            }
            AuditBadge::Spilled => {
                self.spilled = true;
            }
            AuditBadge::Unpriced => {
                self.unpriced = true;
            }
            AuditBadge::UpstreamAdapted { dialect, adapted, not_carried } => {
                self.add_upstream_adapted(dialect, adapted, not_carried);
            }
        }
    }

    pub fn add_upstream_adapted(
        &mut self,
        dialect: impl Into<String>,
        adapted: impl IntoIterator<Item = String>,
        not_carried: impl IntoIterator<Item = String>,
    ) {
        self.upstream_adapted = Some(dialect.into());
        for a in adapted {
            if !self.upstream_adapted_changes.contains(&a) {
                self.upstream_adapted_changes.push(a);
            }
        }
        for n in not_carried {
            if !self.upstream_not_carried.contains(&n) {
                self.upstream_not_carried.push(n);
            }
        }
    }

    pub fn add_modified(&mut self) {
        self.modified = true;
    }

    /// Whether the pipeline mutated the body this row (the `Modified` chip).
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Downgrade a `Modified` chip to `ModifiedNotApplied`: the pipeline WOULD
    /// have mutated the body, but the enforcement point could only act on the
    /// verdict (an out-of-band `/v1/analyze` caller with `enforcement:
    /// verdict_only`), so the mutation never reached the wire. Keeps the audit
    /// truthful — the row must not claim a change it did not make. No-op when
    /// nothing was modified.
    pub fn demote_modified_to_not_applied(&mut self) {
        if self.modified {
            self.modified = false;
            self.modified_not_applied = true;
        }
    }

    /// Downgrade the request phase's `ToolBlocked` names to
    /// `ToolBlockNotApplied`: an enforcement point forwarding the original
    /// still offers the model what policy removed. Keeps
    /// the audit truthful as [`Self::demote_modified_to_not_applied`] does.
    pub fn demote_request_tool_blocks_to_not_applied(&mut self) {
        for name in std::mem::take(&mut self.tool_blocked_request) {
            self.add_tool_block_not_applied(Phase::Request, name);
        }
    }

    /// A call tool policy would have blocked, and that was not stopped.
    pub fn add_tool_block_not_applied(&mut self, phase: Phase, name: impl Into<String>) {
        let target = match phase {
            Phase::Request => &mut self.tool_block_not_applied_request,
            Phase::Response => &mut self.tool_block_not_applied_response,
        };
        let name = name.into();
        if !target.contains(&name) {
            target.push(name);
        }
    }

    pub fn add_compressed(&mut self) {
        self.compressed = true;
    }

    pub fn add_json_healed(&mut self) {
        self.json_healed = true;
    }

    pub fn add_sanitized_tool_names(&mut self, count: u32) {
        if count > 0 {
            self.sanitized_tool_names = self.sanitized_tool_names.saturating_add(count);
        }
    }

    pub fn add_response_sanitized_tool_names(&mut self, count: u32) {
        if count > 0 {
            self.response_sanitized_tool_names =
                self.response_sanitized_tool_names.saturating_add(count);
        }
    }

    pub fn add_tool_blocked(&mut self, phase: Phase, name: impl Into<String>) {
        let bucket = match phase {
            Phase::Request => &mut self.tool_blocked_request,
            Phase::Response => &mut self.tool_blocked_response,
        };
        let name = name.into();
        if !bucket.contains(&name) {
            bucket.push(name);
        }
    }

    pub fn add_tool_blocked_overflow(&mut self, phase: Phase, name: impl Into<String>) {
        let bucket = match phase {
            Phase::Request => &mut self.tool_blocked_overflow_request,
            Phase::Response => &mut self.tool_blocked_overflow_response,
        };
        let name = name.into();
        if !bucket.contains(&name) {
            bucket.push(name);
        }
    }

    pub fn add_block_overflow(&mut self, kind: BlockKind) {
        match kind {
            BlockKind::Text => self.block_overflow_text = self.block_overflow_text.saturating_add(1),
            BlockKind::Thinking => {
                self.block_overflow_thinking = self.block_overflow_thinking.saturating_add(1);
            }
        }
    }

    pub fn add_script_error(&mut self, phase: Phase, program: impl Into<String>) {
        let bucket = match phase {
            Phase::Request => &mut self.script_errors_request,
            Phase::Response => &mut self.script_errors_response,
        };
        let program = program.into();
        if !bucket.contains(&program) {
            bucket.push(program);
        }
    }

    pub fn add_protocol_translated(&mut self, from: ApiVersion, to: ApiVersion) {
        self.protocol_translated = Some((from, to));
    }

    /// Record what a translation could not carry. Pair with
    /// [`Self::add_protocol_translated`]: the list is emitted inside that badge.
    pub fn add_not_carried(&mut self, items: impl IntoIterator<Item = String>) {
        for item in items {
            if !self.not_carried.contains(&item) {
                self.not_carried.push(item);
            }
        }
    }

    pub fn add_capability_rerouted(
        &mut self,
        from: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.capability_rerouted = Some((from.into(), reason.into()));
    }

    pub fn add_agent_alert(&mut self, axis: impl Into<String>, level: AlertLevel) {
        let entry = (axis.into(), level);
        if !self.agent_alerts.contains(&entry) {
            self.agent_alerts.push(entry);
        }
    }

    pub fn add_mcp_rpc_error(&mut self, rpc_code: i32) {
        self.mcp_rpc_error = Some(rpc_code);
    }

    pub fn add_mcp_legacy_sse(&mut self) {
        self.mcp_legacy_sse = true;
    }

    pub fn add_llm_synthetic_sampling(&mut self) {
        self.llm_synthetic_sampling = true;
    }

    /// Record a flagged guardrail verdict: union the categories, raise the max
    /// confidence, and keep the strongest action (`Block` over `Flag`).
    pub fn add_guardrail(
        &mut self,
        categories: Vec<crate::guardrail::GuardrailCategory>,
        max_confidence: f32,
        action: GuardrailAction,
    ) {
        for c in categories {
            if !self.guardrail_categories.contains(&c) {
                self.guardrail_categories.push(c);
            }
        }
        if max_confidence > self.guardrail_max_confidence {
            self.guardrail_max_confidence = max_confidence;
        }
        self.guardrail_action = Some(match self.guardrail_action {
            Some(prev) => prev.max(action),
            None => action,
        });
    }

    /// Record a guardrail detector error (keeps the first reason).
    pub fn add_guardrail_error(&mut self, reason: impl Into<String>) {
        if self.guardrail_error.is_none() {
            self.guardrail_error = Some(reason.into());
        }
    }

    /// Merge another builder's accumulated state into this one.
    pub fn extend(&mut self, other: BadgeBuilder) {
        if other.modified {
            self.modified = true;
        }
        if other.modified_not_applied {
            self.modified_not_applied = true;
        }
        if other.compressed {
            self.compressed = true;
        }
        if other.json_healed {
            self.json_healed = true;
        }
        if other.catchall {
            self.catchall = true;
        }
        self.sanitized_tool_names = self
            .sanitized_tool_names
            .saturating_add(other.sanitized_tool_names);
        self.response_sanitized_tool_names = self
            .response_sanitized_tool_names
            .saturating_add(other.response_sanitized_tool_names);
        for n in other.tool_blocked_request {
            if !self.tool_blocked_request.contains(&n) {
                self.tool_blocked_request.push(n);
            }
        }
        for n in other.tool_blocked_response {
            if !self.tool_blocked_response.contains(&n) {
                self.tool_blocked_response.push(n);
            }
        }
        for n in other.tool_block_not_applied_request {
            self.add_tool_block_not_applied(Phase::Request, n);
        }
        for n in other.tool_block_not_applied_response {
            self.add_tool_block_not_applied(Phase::Response, n);
        }
        for n in other.tool_blocked_overflow_request {
            if !self.tool_blocked_overflow_request.contains(&n) {
                self.tool_blocked_overflow_request.push(n);
            }
        }
        for n in other.tool_blocked_overflow_response {
            if !self.tool_blocked_overflow_response.contains(&n) {
                self.tool_blocked_overflow_response.push(n);
            }
        }
        self.block_overflow_text = self
            .block_overflow_text
            .saturating_add(other.block_overflow_text);
        self.block_overflow_thinking = self
            .block_overflow_thinking
            .saturating_add(other.block_overflow_thinking);
        for p in other.script_errors_request {
            if !self.script_errors_request.contains(&p) {
                self.script_errors_request.push(p);
            }
        }
        for p in other.script_errors_response {
            if !self.script_errors_response.contains(&p) {
                self.script_errors_response.push(p);
            }
        }
        if let Some(pair) = other.protocol_translated {
            self.protocol_translated = Some(pair);
        }
        self.add_not_carried(other.not_carried);
        if let Some(dialect) = other.upstream_adapted {
            self.add_upstream_adapted(dialect, other.upstream_adapted_changes, other.upstream_not_carried);
        }
        if let Some(pair) = other.capability_rerouted {
            self.capability_rerouted = Some(pair);
        }
        for entry in other.agent_alerts {
            if !self.agent_alerts.contains(&entry) {
                self.agent_alerts.push(entry);
            }
        }
        if let Some(code) = other.mcp_rpc_error {
            self.mcp_rpc_error = Some(code);
        }
        if let Some(b) = other.cache_serve {
            self.cache_serve = Some(b);
        }
        if let Some(reason) = other.cache_store_skipped {
            self.cache_store_skipped = Some(reason);
        }
        if let Some(reason) = other.cache_semantic_skipped {
            self.cache_semantic_skipped = Some(reason);
        }
        if other.mcp_legacy_sse {
            self.mcp_legacy_sse = true;
        }
        if other.mcp_sampling_intercepted {
            self.mcp_sampling_intercepted = true;
        }
        if other.llm_synthetic_sampling {
            self.llm_synthetic_sampling = true;
        }
        for n in other.web_search_substituted_servers {
            if !self.web_search_substituted_servers.contains(&n) {
                self.web_search_substituted_servers.push(n);
            }
        }
        for n in other.web_search_substituted_clients {
            if !self.web_search_substituted_clients.contains(&n) {
                self.web_search_substituted_clients.push(n);
            }
        }
        if other.web_search_substitution_max_iter {
            self.web_search_substitution_max_iter = true;
        }
        if other.web_search_substitution_tool_error {
            self.web_search_substitution_tool_error = true;
        }
        if other.web_search_substitution_truncated_stream {
            self.web_search_substitution_truncated_stream = true;
        }
        if other.web_search_substitution_mixed_pending {
            self.web_search_substitution_mixed_pending = true;
        }
        if other.web_search_substitution_forward_failed {
            self.web_search_substitution_forward_failed = true;
        }
        if other.web_search_substitution_serialize_failed {
            self.web_search_substitution_serialize_failed = true;
        }
        if other.web_search_substitution_non_streaming {
            self.web_search_substitution_non_streaming = true;
        }
        if other.web_search_substitution_history_cap {
            self.web_search_substitution_history_cap = true;
        }
        if other.web_search_substitution_cancelled {
            self.web_search_substitution_cancelled = true;
        }
        self.web_search_substitution_mixed_pending_spliced_count = self
            .web_search_substitution_mixed_pending_spliced_count
            .saturating_add(other.web_search_substitution_mixed_pending_spliced_count);
        self.web_search_substitution_mixed_pending_splice_failed_count = self
            .web_search_substitution_mixed_pending_splice_failed_count
            .saturating_add(other.web_search_substitution_mixed_pending_splice_failed_count);
        if let Some(action) = other.guardrail_action {
            self.add_guardrail(
                other.guardrail_categories,
                other.guardrail_max_confidence,
                action,
            );
        }
        if let Some(reason) = other.guardrail_error
            && self.guardrail_error.is_none()
        {
            self.guardrail_error = Some(reason);
        }
        if other.unpriced {
            self.unpriced = true;
        }
        if let Some(wait_ms) = other.queued_wait_ms {
            self.queued_wait_ms = Some(wait_ms);
        }
        if other.spilled {
            self.spilled = true;
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.modified
            && !self.modified_not_applied
            && !self.compressed
            && !self.json_healed
            && !self.catchall
            && self.sanitized_tool_names == 0
            && self.response_sanitized_tool_names == 0
            && self.tool_blocked_request.is_empty()
            && self.tool_blocked_response.is_empty()
            && self.tool_blocked_overflow_request.is_empty()
            && self.tool_blocked_overflow_response.is_empty()
            && self.tool_block_not_applied_request.is_empty()
            && self.tool_block_not_applied_response.is_empty()
            && self.block_overflow_text == 0
            && self.block_overflow_thinking == 0
            && self.script_errors_request.is_empty()
            && self.script_errors_response.is_empty()
            && self.protocol_translated.is_none()
            && self.not_carried.is_empty()
            && self.upstream_adapted.is_none()
            && self.capability_rerouted.is_none()
            && self.agent_alerts.is_empty()
            && self.mcp_rpc_error.is_none()
            && !self.mcp_legacy_sse
            && !self.mcp_sampling_intercepted
            && !self.llm_synthetic_sampling
            && self.web_search_substituted_servers.is_empty()
            && self.web_search_substituted_clients.is_empty()
            && !self.web_search_substitution_max_iter
            && !self.web_search_substitution_tool_error
            && !self.web_search_substitution_truncated_stream
            && !self.web_search_substitution_mixed_pending
            && !self.web_search_substitution_forward_failed
            && !self.web_search_substitution_serialize_failed
            && !self.web_search_substitution_non_streaming
            && !self.web_search_substitution_history_cap
            && !self.web_search_substitution_cancelled
            && self.web_search_substitution_mixed_pending_spliced_count == 0
            && self.web_search_substitution_mixed_pending_splice_failed_count == 0
            && self.guardrail_action.is_none()
            && self.guardrail_error.is_none()
            && self.cache_serve.is_none()
            && self.cache_store_skipped.is_none()
            && self.cache_semantic_skipped.is_none()
            && self.queued_wait_ms.is_none()
            && !self.spilled
            && !self.unpriced
    }

    /// Drain into the final ordered badge vector for the audit record.
    pub fn finish(self) -> Vec<AuditBadge> {
        let mut out = Vec::new();
        if self.modified {
            out.push(AuditBadge::Modified);
        }
        if self.modified_not_applied {
            out.push(AuditBadge::ModifiedNotApplied);
        }
        if self.compressed {
            out.push(AuditBadge::Compressed);
        }
        if self.json_healed {
            out.push(AuditBadge::JsonHealed);
        }
        if !self.tool_blocked_request.is_empty() {
            out.push(AuditBadge::ToolBlocked {
                phase: Phase::Request,
                count: self.tool_blocked_request.len() as u32,
                names: self.tool_blocked_request,
            });
        }
        if !self.tool_blocked_response.is_empty() {
            out.push(AuditBadge::ToolBlocked {
                phase: Phase::Response,
                count: self.tool_blocked_response.len() as u32,
                names: self.tool_blocked_response,
            });
        }
        if !self.tool_block_not_applied_request.is_empty() {
            out.push(AuditBadge::ToolBlockNotApplied {
                phase: Phase::Request,
                count: self.tool_block_not_applied_request.len() as u32,
                names: self.tool_block_not_applied_request,
            });
        }
        if !self.tool_block_not_applied_response.is_empty() {
            out.push(AuditBadge::ToolBlockNotApplied {
                phase: Phase::Response,
                count: self.tool_block_not_applied_response.len() as u32,
                names: self.tool_block_not_applied_response,
            });
        }
        if !self.tool_blocked_overflow_request.is_empty() {
            out.push(AuditBadge::ToolBlockedOverflow {
                phase: Phase::Request,
                count: self.tool_blocked_overflow_request.len() as u32,
                names: self.tool_blocked_overflow_request,
            });
        }
        if !self.tool_blocked_overflow_response.is_empty() {
            out.push(AuditBadge::ToolBlockedOverflow {
                phase: Phase::Response,
                count: self.tool_blocked_overflow_response.len() as u32,
                names: self.tool_blocked_overflow_response,
            });
        }
        if self.block_overflow_text > 0 {
            out.push(AuditBadge::BlockOverflow {
                kind: BlockKind::Text,
                count: self.block_overflow_text,
            });
        }
        if self.block_overflow_thinking > 0 {
            out.push(AuditBadge::BlockOverflow {
                kind: BlockKind::Thinking,
                count: self.block_overflow_thinking,
            });
        }
        if !self.script_errors_request.is_empty() {
            out.push(AuditBadge::ScriptError {
                phase: Phase::Request,
                count: self.script_errors_request.len() as u32,
                programs: self.script_errors_request,
            });
        }
        if !self.script_errors_response.is_empty() {
            out.push(AuditBadge::ScriptError {
                phase: Phase::Response,
                count: self.script_errors_response.len() as u32,
                programs: self.script_errors_response,
            });
        }
        if let Some((from, to)) = self.protocol_translated {
            out.push(AuditBadge::ProtocolTranslated { from, to, not_carried: self.not_carried });
        }
        if let Some((from, reason)) = self.capability_rerouted {
            out.push(AuditBadge::CapabilityRerouted { from, reason });
        }
        if self.catchall {
            out.push(AuditBadge::Catchall);
        }
        if self.sanitized_tool_names > 0 {
            out.push(AuditBadge::SanitizedToolNames {
                count: self.sanitized_tool_names,
            });
        }
        if self.response_sanitized_tool_names > 0 {
            out.push(AuditBadge::ResponseSanitizedToolNames {
                count: self.response_sanitized_tool_names,
            });
        }
        for (axis, level) in self.agent_alerts {
            out.push(AuditBadge::AgentAlert { axis, level });
        }
        if let Some(rpc_code) = self.mcp_rpc_error {
            out.push(AuditBadge::McpRpcError { rpc_code });
        }
        if self.mcp_legacy_sse {
            out.push(AuditBadge::McpLegacySse);
        }
        if self.mcp_sampling_intercepted {
            out.push(AuditBadge::McpSamplingIntercepted);
        }
        if self.llm_synthetic_sampling {
            out.push(AuditBadge::LlmSyntheticSampling);
        }
        for server_type in self.web_search_substituted_servers {
            out.push(AuditBadge::WebSubstitutedServer { server_type });
        }
        for client_label in self.web_search_substituted_clients {
            out.push(AuditBadge::WebSubstitutedClient { client_label });
        }
        if self.web_search_substitution_max_iter {
            out.push(AuditBadge::WebSubstitutionMaxIter);
        }
        if self.web_search_substitution_tool_error {
            out.push(AuditBadge::WebSubstitutionToolError);
        }
        if self.web_search_substitution_truncated_stream {
            out.push(AuditBadge::WebSubstitutionTruncatedStream);
        }
        if self.web_search_substitution_mixed_pending {
            out.push(AuditBadge::WebSubstitutionMixedPending);
        }
        if self.web_search_substitution_forward_failed {
            out.push(AuditBadge::WebSubstitutionForwardFailed);
        }
        if self.web_search_substitution_serialize_failed {
            out.push(AuditBadge::WebSubstitutionSerializeFailed);
        }
        if self.web_search_substitution_non_streaming {
            out.push(AuditBadge::WebSubstitutionNonStreaming);
        }
        if self.web_search_substitution_history_cap {
            out.push(AuditBadge::WebSubstitutionHistoryCap);
        }
        if self.web_search_substitution_cancelled {
            out.push(AuditBadge::WebSubstitutionCancelled);
        }
        if self.web_search_substitution_mixed_pending_spliced_count > 0 {
            out.push(AuditBadge::WebSubstitutionMixedPendingSpliced {
                count: self.web_search_substitution_mixed_pending_spliced_count,
            });
        }
        if self.web_search_substitution_mixed_pending_splice_failed_count > 0 {
            out.push(AuditBadge::WebSubstitutionMixedPendingSpliceFailed {
                count: self.web_search_substitution_mixed_pending_splice_failed_count,
            });
        }
        if let Some(action) = self.guardrail_action {
            out.push(AuditBadge::Guardrail {
                categories: self.guardrail_categories,
                max_confidence: self.guardrail_max_confidence,
                action,
            });
        }
        if let Some(reason) = self.guardrail_error {
            out.push(AuditBadge::GuardrailError { reason });
        }
        if let Some(b) = self.cache_serve {
            out.push(b);
        }
        if let Some(reason) = self.cache_store_skipped {
            out.push(AuditBadge::CacheStoreSkipped { reason });
        }
        if let Some(reason) = self.cache_semantic_skipped {
            out.push(AuditBadge::CacheSemanticSkipped { reason });
        }
        if let Some(wait_ms) = self.queued_wait_ms {
            out.push(AuditBadge::Queued { wait_ms });
        }
        if self.spilled {
            out.push(AuditBadge::Spilled);
        }
        if self.unpriced {
            out.push(AuditBadge::Unpriced);
        }
        if let Some(dialect) = self.upstream_adapted {
            out.push(AuditBadge::UpstreamAdapted {
                dialect,
                adapted: self.upstream_adapted_changes,
                not_carried: self.upstream_not_carried,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn empty_builder_finishes_empty() {
        assert!(BadgeBuilder::new().finish().is_empty());
    }

    #[test]
    fn modified_only_emits_once_when_added_twice() {
        let mut b = BadgeBuilder::new();
        b.add_modified();
        b.add_modified();
        let out = b.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code(), "modified");
    }

    #[test]
    fn tool_blocked_aggregates_across_calls() {
        let mut b = BadgeBuilder::new();
        b.add_tool_blocked(Phase::Response, "Read");
        b.add_tool_blocked(Phase::Response, "Write");
        b.add_tool_blocked(Phase::Response, "Read");
        let out = b.finish();
        assert_eq!(out.len(), 1);
        match &out[0] {
            AuditBadge::ToolBlocked { phase, count, names } => {
                assert_eq!(*phase, Phase::Response);
                assert_eq!(*count, 2);
                assert_eq!(names, &vec!["Read".to_string(), "Write".to_string()]);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn request_and_response_phases_emit_separate_badges() {
        let mut b = BadgeBuilder::new();
        b.add_tool_blocked(Phase::Request, "DeleteFile");
        b.add_tool_blocked(Phase::Response, "Bash");
        let out = b.finish();
        assert_eq!(out.len(), 2);
        let phases: Vec<_> = out
            .iter()
            .filter_map(|b| match b {
                AuditBadge::ToolBlocked { phase, .. } => Some(*phase),
                _ => None,
            })
            .collect();
        assert!(phases.contains(&Phase::Request));
        assert!(phases.contains(&Phase::Response));
    }

    #[test]
    fn extend_merges_state() {
        let mut a = BadgeBuilder::new();
        a.add_modified();
        a.add_tool_blocked(Phase::Response, "Read");
        let mut b = BadgeBuilder::new();
        b.add_compressed();
        b.add_tool_blocked(Phase::Response, "Write");
        a.extend(b);
        let out = a.finish();
        let codes: Vec<_> = out.iter().map(|b| b.code()).collect();
        assert!(codes.contains(&"modified"));
        assert!(codes.contains(&"compressed"));
        assert!(codes.contains(&"tool_blocked"));
        match out.iter().find(|b| matches!(b, AuditBadge::ToolBlocked { .. })).unwrap() {
            AuditBadge::ToolBlocked { count, .. } => assert_eq!(*count, 2),
            _ => unreachable!(),
        }
    }

    #[test]
    fn serialization_round_trip() {
        let badges = vec![
            AuditBadge::Modified,
            AuditBadge::ToolBlocked {
                phase: Phase::Response,
                count: 2,
                names: vec!["Read".into(), "Write".into()],
            },
            AuditBadge::ProtocolTranslated {
                from: ApiVersion::AnthropicMessages,
                to: ApiVersion::ChatCompletions,
                not_carried: vec!["hosted tool web_search".into()],
            },
        ];
        let s = serde_json::to_string(&badges).unwrap();
        assert!(s.contains(r#""code":"modified""#));
        assert!(s.contains(r#""code":"tool_blocked""#));
        assert!(s.contains(r#""phase":"response""#));
        assert!(s.contains(r#""from":"anthropic_messages""#));
        let round: Vec<AuditBadge> = serde_json::from_str(&s).unwrap();
        assert_eq!(round, badges);
    }

    #[test]
    fn json_healed_emits_once() {
        let mut b = BadgeBuilder::new();
        b.add_json_healed();
        b.add_json_healed();
        let out = b.finish();
        assert_eq!(out.len(), 1);
        assert_matches!(out[0], AuditBadge::JsonHealed);
    }

    #[test]
    fn sanitized_tool_names_zero_drops() {
        let mut b = BadgeBuilder::new();
        b.add_sanitized_tool_names(0);
        assert!(b.finish().is_empty());
    }

    #[test]
    fn agent_alert_emits_one_badge_per_axis_level() {
        let mut b = BadgeBuilder::new();
        b.add_agent_alert("tool_policy", AlertLevel::Major);
        b.add_agent_alert("security", AlertLevel::Minor);
        b.add_agent_alert("tool_policy", AlertLevel::Major); // duplicate, dropped
        let out = b.finish();
        let alerts: Vec<_> = out
            .iter()
            .filter_map(|b| match b {
                AuditBadge::AgentAlert { axis, level } => Some((axis.clone(), *level)),
                _ => None,
            })
            .collect();
        assert_eq!(alerts.len(), 2);
        assert!(alerts.contains(&("tool_policy".to_string(), AlertLevel::Major)));
        assert!(alerts.contains(&("security".to_string(), AlertLevel::Minor)));
    }

    #[test]
    fn mcp_rpc_error_emits_once() {
        let mut b = BadgeBuilder::new();
        b.add_mcp_rpc_error(-32429);
        b.add_mcp_rpc_error(-32506); // last code wins
        let out = b.finish();
        assert_eq!(out.len(), 1);
        match &out[0] {
            AuditBadge::McpRpcError { rpc_code } => assert_eq!(*rpc_code, -32506),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn mcp_legacy_sse_emits_once() {
        let mut b = BadgeBuilder::new();
        b.add_mcp_legacy_sse();
        b.add_mcp_legacy_sse();
        let out = b.finish();
        assert_eq!(out.len(), 1);
        assert_matches!(out[0], AuditBadge::McpLegacySse);
    }

    #[test]
    fn mcp_badges_round_trip_serialization() {
        let badges = vec![
            AuditBadge::McpRpcError { rpc_code: -32506 },
            AuditBadge::McpLegacySse,
        ];
        let s = serde_json::to_string(&badges).unwrap();
        assert!(s.contains(r#""code":"mcp_rpc_error""#));
        assert!(s.contains(r#""rpc_code":-32506"#));
        assert!(s.contains(r#""code":"mcp_legacy_sse""#));
        let round: Vec<AuditBadge> = serde_json::from_str(&s).unwrap();
        assert_eq!(round, badges);
    }

    /// Exhaustive `match` on `AuditBadge` produces one example of every
    /// variant — adding a new variant fails to compile here, forcing the
    /// author to also touch this test.
    fn one_of_every_audit_badge_variant() -> Vec<AuditBadge> {
        // The match arms are deliberately exhaustive (no `_ => ...` wildcard)
        // so the compiler errors if a new `AuditBadge` variant is added
        // without extending this list.
        let _exhaustive: fn(AuditBadge) = |b| match b {
            AuditBadge::Modified => {}
            AuditBadge::ModifiedNotApplied => {}
            AuditBadge::Compressed => {}
            AuditBadge::JsonHealed => {}
            AuditBadge::ToolBlocked { .. } => {}
            AuditBadge::ToolBlockedOverflow { .. } => {}
            AuditBadge::ToolBlockNotApplied { .. } => {}
            AuditBadge::BlockOverflow { .. } => {}
            AuditBadge::ScriptError { .. } => {}
            AuditBadge::ProtocolTranslated { .. } => {}
            AuditBadge::CapabilityRerouted { .. } => {}
            AuditBadge::Catchall => {}
            AuditBadge::SanitizedToolNames { .. } => {}
            AuditBadge::ResponseSanitizedToolNames { .. } => {}
            AuditBadge::AgentAlert { .. } => {}
            AuditBadge::SessionAlert { .. } => {}
            AuditBadge::McpRpcError { .. } => {}
            AuditBadge::McpLegacySse => {}
            AuditBadge::McpSamplingIntercepted => {}
            AuditBadge::Queued { .. } => {}
            AuditBadge::Spilled => {}
            AuditBadge::Unpriced => {}
            AuditBadge::UpstreamAdapted { .. } => {}
            AuditBadge::LlmSyntheticSampling => {}
            AuditBadge::WebBlocked => {}
            AuditBadge::WebUrlFiltered { .. } => {}
            AuditBadge::WebAllResultsFiltered => {}
            AuditBadge::WebRateLimited => {}
            AuditBadge::WebContentStripped { .. } => {}
            AuditBadge::RecordStripped { .. } => {}
            AuditBadge::ContentUnavailable => {}
            AuditBadge::WebSsrfRefused => {}
            AuditBadge::WebSchemeRefused => {}
            AuditBadge::WebSubstitutedServer { .. } => {}
            AuditBadge::WebSubstitutedClient { .. } => {}
            AuditBadge::WebSubstitutionMaxIter => {}
            AuditBadge::WebSubstitutionToolError => {}
            AuditBadge::WebSubstitutionTruncatedStream => {}
            AuditBadge::WebSubstitutionMixedPending => {}
            AuditBadge::WebSubstitutionForwardFailed => {}
            AuditBadge::WebSubstitutionSerializeFailed => {}
            AuditBadge::WebSubstitutionNonStreaming => {}
            AuditBadge::WebSubstitutionHistoryCap => {}
            AuditBadge::WebSubstitutionCancelled => {}
            AuditBadge::WebSubstitutionMixedPendingSpliced { .. } => {}
            AuditBadge::WebSubstitutionMixedPendingSpliceFailed { .. } => {}
            AuditBadge::Guardrail { .. } => {}
            AuditBadge::GuardrailError { .. } => {}
            AuditBadge::CacheHit { .. } => {}
            AuditBadge::CacheObserveHit { .. } => {}
            AuditBadge::CacheStoreSkipped { .. } => {}
            AuditBadge::CacheSemanticSkipped { .. } => {}
        };
        vec![
            AuditBadge::Modified,
            AuditBadge::ModifiedNotApplied,
            AuditBadge::Compressed,
            AuditBadge::JsonHealed,
            AuditBadge::ToolBlocked {
                phase: Phase::Request,
                count: 1,
                names: vec!["t".into()],
            },
            AuditBadge::ToolBlockedOverflow {
                phase: Phase::Response,
                count: 1,
                names: vec!["t".into()],
            },
            AuditBadge::ToolBlockNotApplied {
                phase: Phase::Response,
                count: 1,
                names: vec!["t".into()],
            },
            AuditBadge::BlockOverflow {
                kind: BlockKind::Text,
                count: 1,
            },
            AuditBadge::ScriptError {
                phase: Phase::Request,
                count: 1,
                programs: vec!["p".into()],
            },
            AuditBadge::ProtocolTranslated {
                from: ApiVersion::AnthropicMessages,
                to: ApiVersion::ChatCompletions,
                not_carried: vec!["hosted tool web_search".into()],
            },
            AuditBadge::CapabilityRerouted {
                from: "text-only-primary".into(),
                reason: "Model does not support vision/image input.".into(),
            },
            AuditBadge::Catchall,
            AuditBadge::SanitizedToolNames { count: 1 },
            AuditBadge::ResponseSanitizedToolNames { count: 1 },
            AuditBadge::AgentAlert {
                axis: "x".into(),
                level: AlertLevel::Minor,
            },
            AuditBadge::SessionAlert {
                experts: vec!["x".into()],
                level: AlertLevel::Major,
            },
            AuditBadge::McpRpcError { rpc_code: -32429 },
            AuditBadge::McpLegacySse,
            AuditBadge::McpSamplingIntercepted,
            AuditBadge::LlmSyntheticSampling,
            AuditBadge::WebBlocked,
            AuditBadge::WebUrlFiltered { count: 1 },
            AuditBadge::WebAllResultsFiltered,
            AuditBadge::WebRateLimited,
            AuditBadge::WebContentStripped { reason: "size".into() },
            AuditBadge::RecordStripped { reason: "oversized".into() },
            AuditBadge::ContentUnavailable,
            AuditBadge::WebSsrfRefused,
            AuditBadge::WebSchemeRefused,
            AuditBadge::WebSubstitutedServer {
                server_type: "web_search_20250305".into(),
            },
            AuditBadge::WebSubstitutedClient {
                client_label: "claude-code:WebSearch".into(),
            },
            AuditBadge::WebSubstitutionMaxIter,
            AuditBadge::WebSubstitutionToolError,
            AuditBadge::WebSubstitutionTruncatedStream,
            AuditBadge::WebSubstitutionMixedPending,
            AuditBadge::WebSubstitutionForwardFailed,
            AuditBadge::WebSubstitutionSerializeFailed,
            AuditBadge::WebSubstitutionNonStreaming,
            AuditBadge::WebSubstitutionHistoryCap,
            AuditBadge::WebSubstitutionCancelled,
            AuditBadge::WebSubstitutionMixedPendingSpliced { count: 1 },
            AuditBadge::WebSubstitutionMixedPendingSpliceFailed { count: 1 },
            AuditBadge::Guardrail {
                categories: vec![crate::guardrail::GuardrailCategory::PromptInjection],
                max_confidence: 0.95,
                action: GuardrailAction::Flag,
            },
            AuditBadge::GuardrailError {
                reason: "timeout".into(),
            },
            AuditBadge::CacheHit {
                avoided_cost: 0.0012,
                age_seconds: 42,
                similarity: None,
            },
            AuditBadge::CacheObserveHit {
                age_seconds: 42,
                similarity: Some(0.93),
            },
            AuditBadge::CacheStoreSkipped {
                reason: "tool_calls".into(),
            },
            AuditBadge::CacheSemanticSkipped {
                reason: "embedding_timeout".into(),
            },
            AuditBadge::Queued { wait_ms: 1_500 },
            AuditBadge::Spilled,
            AuditBadge::Unpriced,
            AuditBadge::UpstreamAdapted {
                dialect: "mistral".into(),
                adapted: vec!["seed sent as random_seed".into()],
                not_carried: vec!["parameter user".into()],
            },
        ]
    }

    /// Variants the LLM/MCP `BadgeBuilder` intentionally **drops** on
    /// `add()` rather than aggregating: the web ones belong on
    /// `WebAuditRecord.badges` (the executor's own audit row) and would
    /// clutter the orchestrating LLM/MCP row if surfaced there;
    /// `record_stripped` is set on the record itself by the edge outbox, and
    /// `content_unavailable` by admin-api's ingest. Kept
    /// as a separate list so the completeness tests below assert these
    /// are the *only* drop-on-add variants — a future variant added to
    /// the LLM/MCP `add()` drop arm without being added here will fail
    /// `extend_preserves_every_aggregated_audit_badge_variant`.
    fn intentionally_dropped_on_llm_mcp_builder() -> &'static [&'static str] {
        &[
            "web_blocked",
            "web_url_filtered",
            "web_all_results_filtered",
            "web_rate_limited",
            "web_content_stripped",
            "web_ssrf_refused",
            "web_scheme_refused",
            "record_stripped",
            "content_unavailable",
            // Derived by the audit list from the session at read time.
            "session_alert",
        ]
    }

    /// Round-trip every aggregated `AuditBadge` variant through
    /// `add → extend → finish` and verify the same set of badge codes
    /// survives. Catches the `BadgeBuilder::extend` drift bug class —
    /// when a new builder field is added but `extend` isn't taught to
    /// merge it, the post-extend `finish()` produces fewer badges than
    /// the direct path. The exhaustive match in
    /// `one_of_every_audit_badge_variant` ensures callers can't drift
    /// this list quietly.
    #[test]
    fn extend_preserves_every_aggregated_audit_badge_variant() {
        let dropped: std::collections::HashSet<&str> =
            intentionally_dropped_on_llm_mcp_builder().iter().copied().collect();
        let aggregated: Vec<AuditBadge> = one_of_every_audit_badge_variant()
            .into_iter()
            .filter(|b| !dropped.contains(b.code()))
            .collect();

        // Direct path: add all aggregated badges to a single builder, finish.
        let mut direct = BadgeBuilder::new();
        for b in &aggregated {
            direct.add(b.clone());
        }
        let direct_codes: std::collections::HashSet<&str> =
            direct.finish().iter().map(|b| b.code()).collect();

        // Extend path: add to a "source" builder, then extend an empty
        // builder with it. extend() must merge every field.
        let mut source = BadgeBuilder::new();
        for b in &aggregated {
            source.add(b.clone());
        }
        let mut sink = BadgeBuilder::new();
        sink.extend(source);
        let extended_codes: std::collections::HashSet<&str> =
            sink.finish().iter().map(|b| b.code()).collect();

        let missing: Vec<&str> =
            direct_codes.difference(&extended_codes).copied().collect();
        assert!(
            missing.is_empty(),
            "BadgeBuilder::extend lost these badge codes — check that every \
             field on BadgeBuilder is merged in extend(): {missing:?}"
        );
        let extra: Vec<&str> =
            extended_codes.difference(&direct_codes).copied().collect();
        assert!(extra.is_empty(), "extend produced spurious codes: {extra:?}");
    }

    /// Per-variant `is_empty()` regression for *aggregated* variants:
    /// `add(badge)` must make `is_empty()` return false — otherwise
    /// `finish()` may end up dropping the entire badge set when paired
    /// with the conditional emission paths in the audit pipeline. The
    /// intentionally-dropped variants are excluded.
    #[test]
    fn add_makes_builder_non_empty_for_every_aggregated_variant() {
        let dropped: std::collections::HashSet<&str> =
            intentionally_dropped_on_llm_mcp_builder().iter().copied().collect();
        for badge in one_of_every_audit_badge_variant() {
            if dropped.contains(badge.code()) {
                continue;
            }
            let mut b = BadgeBuilder::new();
            b.add(badge.clone());
            assert!(
                !b.is_empty(),
                "add({badge:?}) left BadgeBuilder::is_empty() == true \
                 — a new variant was added without an is_empty() check"
            );
        }
    }

    /// Per-variant `finish()` regression: `add(badge).finish()` must
    /// produce a `Vec<AuditBadge>` containing at least one badge with
    /// `b.code()`. Catches the case where a field is added to `add()` /
    /// `extend()` / `is_empty()` but `finish()` doesn't emit it — both
    /// direct and extended paths route through `finish()`, so the other
    /// extend/is_empty tests would not catch this drift on their own.
    #[test]
    fn finish_emits_a_badge_for_every_aggregated_variant() {
        let dropped: std::collections::HashSet<&str> =
            intentionally_dropped_on_llm_mcp_builder().iter().copied().collect();
        for badge in one_of_every_audit_badge_variant() {
            if dropped.contains(badge.code()) {
                continue;
            }
            let expected = badge.code();
            let mut b = BadgeBuilder::new();
            b.add(badge.clone());
            let out = b.finish();
            assert!(
                out.iter().any(|x| x.code() == expected),
                "add({badge:?}).finish() did not emit a badge with code \
                 `{expected}` — finish() is missing the emit clause"
            );
        }
    }

    /// `code()` strings are append-only and must be unique — a collision
    /// would silently mask a variant in any `HashSet<&str>` aggregation
    /// (including the drift tests above). Locks the constraint at
    /// compile-test time rather than relying on the docs convention alone.
    #[test]
    fn audit_badge_codes_are_unique() {
        let codes: Vec<&str> = one_of_every_audit_badge_variant()
            .iter()
            .map(|b| b.code())
            .collect();
        let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
        assert_eq!(
            codes.len(),
            unique.len(),
            "duplicate AuditBadge `code()` strings found — codes must be \
             append-only and unique. Got: {codes:?}"
        );
    }

    /// Lock the intentionally-dropped contract: these specific variants
    /// must NOT make the LLM/MCP builder non-empty when added (they're
    /// routed to `WebAuditRecord.badges` instead). If a future
    /// change rewires one of them onto the LLM/MCP builder, this test
    /// fails and forces the author to also remove it from the
    /// `intentionally_dropped_on_llm_mcp_builder` list.
    #[test]
    fn intentionally_dropped_variants_remain_no_op_on_add() {
        let dropped: std::collections::HashSet<&str> =
            intentionally_dropped_on_llm_mcp_builder().iter().copied().collect();
        for badge in one_of_every_audit_badge_variant() {
            if !dropped.contains(badge.code()) {
                continue;
            }
            let mut b = BadgeBuilder::new();
            b.add(badge.clone());
            assert!(
                b.is_empty(),
                "add({badge:?}) is supposed to be a no-op on the LLM/MCP \
                 builder (web-direct badges go to \
                 WebAuditRecord), but it set state. If this is \
                 intentional, remove the code from \
                 `intentionally_dropped_on_llm_mcp_builder`."
            );
        }
    }

    #[test]
    fn guardrail_aggregates_block_wins_and_unions_categories() {
        use crate::guardrail::GuardrailCategory;
        let mut b = BadgeBuilder::new();
        b.add_guardrail(
            vec![GuardrailCategory::PromptInjection],
            0.91,
            GuardrailAction::Flag,
        );
        b.add_guardrail(
            vec![GuardrailCategory::Jailbreak],
            0.97,
            GuardrailAction::Block,
        );
        // Duplicate category + lower confidence + weaker action — folded.
        b.add_guardrail(
            vec![GuardrailCategory::PromptInjection],
            0.50,
            GuardrailAction::Flag,
        );
        let out = b.finish();
        let guardrail = out
            .iter()
            .find(|x| matches!(x, AuditBadge::Guardrail { .. }))
            .unwrap();
        match guardrail {
            AuditBadge::Guardrail {
                categories,
                max_confidence,
                action,
            } => {
                assert_eq!(categories.len(), 2);
                assert!(categories.contains(&GuardrailCategory::PromptInjection));
                assert!(categories.contains(&GuardrailCategory::Jailbreak));
                assert!((*max_confidence - 0.97).abs() < 1e-6);
                assert_eq!(*action, GuardrailAction::Block);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn guardrail_error_keeps_first_reason_and_emits() {
        let mut b = BadgeBuilder::new();
        b.add_guardrail_error("timeout");
        b.add_guardrail_error("transport"); // first wins
        let out = b.finish();
        match out.iter().find(|x| matches!(x, AuditBadge::GuardrailError { .. })) {
            Some(AuditBadge::GuardrailError { reason }) => assert_eq!(reason, "timeout"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn an_alert_level_reads_back_what_it_spells() {
        for level in [AlertLevel::Info, AlertLevel::Minor, AlertLevel::Major] {
            assert_eq!(serde_json::to_value(level).unwrap(), serde_json::json!(level.as_str()));
            assert_eq!(AlertLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(AlertLevel::parse("critical"), None);
    }

    #[test]
    fn agent_alert_round_trip_serialization() {
        let badge = AuditBadge::AgentAlert {
            axis: "tool_policy".to_string(),
            level: AlertLevel::Major,
        };
        let s = serde_json::to_string(&badge).unwrap();
        assert!(s.contains(r#""code":"agent_alert""#));
        assert!(s.contains(r#""axis":"tool_policy""#));
        assert!(s.contains(r#""level":"major""#));
        let round: AuditBadge = serde_json::from_str(&s).unwrap();
        assert_eq!(round, badge);
    }

    /// Every field of the builder must survive [`BadgeBuilder::extend`].
    ///
    /// `extend` names every field by hand, so a field added without touching it
    /// is silently dropped when the response-side builder merges into the
    /// request-side one — the badge is set, and then discarded on its way to the
    /// audit row. That failure is invisible to any test that only exercises the
    /// setter.
    ///
    /// This does NOT prove [`BadgeBuilder::is_empty`] accounts for every field:
    /// with the whole struct populated, any one remaining field keeps the answer
    /// false. Catching an omission there needs a builder per field.
    ///
    /// The struct literal below is the guard: it names every field with **no**
    /// `..` rest pattern, so adding a field to `BadgeBuilder` fails to compile
    /// until it is named here, and naming it forces it through the merge.
    #[test]
    fn every_builder_field_survives_a_merge() {
        let filled = BadgeBuilder {
            modified: true,
            modified_not_applied: true,
            compressed: true,
            json_healed: true,
            catchall: true,
            sanitized_tool_names: 3,
            response_sanitized_tool_names: 4,
            tool_blocked_request: vec!["a".into()],
            tool_blocked_response: vec!["b".into()],
            tool_blocked_overflow_request: vec!["c".into()],
            tool_blocked_overflow_response: vec!["d".into()],
            tool_block_not_applied_request: vec!["e".into()],
            tool_block_not_applied_response: vec!["f".into()],
            block_overflow_text: 5,
            block_overflow_thinking: 6,
            script_errors_request: vec!["e".into()],
            script_errors_response: vec!["f".into()],
            protocol_translated: Some((ApiVersion::ChatCompletions, ApiVersion::AnthropicMessages)),
            not_carried: vec!["reasoning".into()],
            capability_rerouted: Some(("primary".into(), "vision".into())),
            agent_alerts: vec![("security".into(), AlertLevel::Major)],
            mcp_rpc_error: Some(-32601),
            mcp_legacy_sse: true,
            mcp_sampling_intercepted: true,
            llm_synthetic_sampling: true,
            web_search_substituted_servers: vec!["srv".into()],
            web_search_substituted_clients: vec!["cli".into()],
            web_search_substitution_max_iter: true,
            web_search_substitution_tool_error: true,
            web_search_substitution_truncated_stream: true,
            web_search_substitution_mixed_pending: true,
            web_search_substitution_forward_failed: true,
            web_search_substitution_serialize_failed: true,
            web_search_substitution_non_streaming: true,
            web_search_substitution_history_cap: true,
            web_search_substitution_cancelled: true,
            web_search_substitution_mixed_pending_spliced_count: 7,
            web_search_substitution_mixed_pending_splice_failed_count: 8,
            guardrail_categories: vec![crate::guardrail::GuardrailCategory::PromptInjection],
            guardrail_max_confidence: 0.9,
            guardrail_action: Some(GuardrailAction::Block),
            guardrail_error: Some("detector down".into()),
            cache_serve: Some(AuditBadge::CacheHit {
                age_seconds: 12,
                avoided_cost: 0.5,
                similarity: None,
            }),
            cache_store_skipped: Some("tool_calls".into()),
            cache_semantic_skipped: Some("embedding_failed".into()),
            queued_wait_ms: Some(1_234),
            spilled: true,
            unpriced: true,
            upstream_adapted: Some("mistral".into()),
            upstream_adapted_changes: vec!["seed sent as random_seed".into()],
            upstream_not_carried: vec!["parameter user".into()],
        };

        assert!(
            !filled.is_empty(),
            "a builder with every field set reports empty — is_empty is missing a field"
        );

        let mut merged = BadgeBuilder::new();
        merged.extend(filled.clone());

        let mut expected = filled.finish();
        let mut actual = merged.finish();
        expected.sort_by_key(|b| format!("{b:?}"));
        actual.sort_by_key(|b| format!("{b:?}"));
        assert_eq!(
            actual, expected,
            "a badge was lost merging one builder into another — extend is missing a field"
        );
    }
}
