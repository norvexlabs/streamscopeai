//! Canonical conversation read-model — the protocol-agnostic projection of a
//! session's turns into UI-facing [`ConversationEvent`]s.
//!
//! This is the admin-side render contract for the audit / session viewer: the
//! same `DomainMessage` domain layer the proxy uses for transforms is replayed
//! here into typed events, so admin and proxy never drift on how a conversation
//! is normalized. The event **types** live in this module; the **builder**
//! (wire JSON → `DomainMessage` → `ConversationEvent`) lives in [`build`].
//!
//! It is deliberately a domain module, not a route: handlers in `routes/` map
//! DB rows into these types and serialize them, but the projection logic itself
//! is independent of the HTTP surface.

use serde::Serialize;
use streamscope_core::audit::BlobType;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::routes::audit::McpTransformDiff;

pub mod build;
pub mod spawn;
pub use build::{build_events, stored_protocol, TurnRow};
pub use spawn::{detect_spawn_points, DetectedSpawnPoint};

/// The stored blobs one request carried, read from its `chat_media_summary`:
/// the gateway writes that column from the bytes the request actually carried,
/// so it tells a blob the request sent from a `blob_ref` part it only names (a
/// part a client wrote itself, or history it did not resend).
#[derive(Debug, Default)]
pub struct CarriedMedia(std::collections::HashSet<(String, BlobType)>);

impl CarriedMedia {
    /// The blobs recorded by a request's decoded summary entries.
    pub fn of(entries: &[streamscope_core::audit::ChatMediaSummaryEntry]) -> Self {
        Self(entries.iter().map(|e| (e.content_hash.clone(), e.blob_type)).collect())
    }

    /// Name `request_id` — the request a turn's events were built from — as
    /// the owner of every stored-blob `media` event it carried (the same hash
    /// AND blob kind, the key a blob is served by) and that names none yet (`build_events` leaves it to the caller). A blob it did not
    /// carry keeps no owner: the console marks it as not carried by this
    /// request, and the portal, which proves ownership through the request,
    /// cannot fetch it.
    pub fn stamp(&self, events: &mut [ConversationEvent], request_id: Uuid) {
        for ev in events {
            if let ConversationEvent::Media { content_hash: Some(hash), blob_type: Some(kind), request_id: owner @ None, .. } = ev
                && self.0.contains(&(hash.clone(), *kind))
            {
                *owner = Some(request_id);
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct TurnMetadata {
    /// Orchestrating LLM `gateway_audit.request_id` for this turn. Surfaced
    /// so the UI can lazy-load substitution children (web) without
    /// a second roundtrip to fetch the request_id mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub tokens_in: i32,
    pub tokens_out: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<i32>,
    pub latency_ms: i64,
    pub ttft_ms: i64,
    /// The turn's charge, in the currency stamped on its audit row. `None`
    /// when the turn has no audit row or the stamped code does not parse.
    pub spend: Option<crate::routes::SpendTotal>,
    pub finish_reason: String,
    /// Typed audit badges for this turn — same shape as `AuditLogEntry::badges`.
    #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
    pub badges: Vec<streamscope_core::audit::AuditBadge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
}

/// Rule-identity payload attached to a `ConversationEvent::ToolCall` when a
/// policy rule rejected the call. The call is still rendered in the stream
/// (the model actually emitted it); this struct lets the UI overlay *which
/// rule* fired and *why*.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ToolCallBlock {
    /// Stable rule identifier (e.g. `ASI02-06`), read from the persisted
    /// `transform_diff` JSONB — never parsed back out of the description text.
    /// `None` only for an agent-call block whose finding names no rule
    /// (`A2aPolicyFinding::rule_id` is optional on its record).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Human-readable rule title (e.g. `Destructive commands`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_title: Option<String>,
    /// Full rule description carried through from the seed rule — UI uses
    /// this for tooltip / expanded detail. May contain a legacy `[ASI02]`
    /// prefix for older rules.
    pub reason: String,
    /// Where the block fired: `request` (tool stripped before LLM) or
    /// `response` (LLM emitted an arg-based-blocked call). Today only
    /// `response`-phase blocks attach to a `ToolCall` event — request-phase
    /// blocks surface only on the turn header.
    pub phase: String,
}

/// Rule-identity payload attached to a `ConversationEvent::ToolCall` when a
/// substitution rule intercepted the call and ran it server-side (the model's
/// call was diverted to the gateway's web executor, never reaching the client).
/// The call is rendered with this banner so operators see *which rule* diverted
/// it; the server-side execution + guardrail surface on the following
/// `web_call` event.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InterceptionInfo {
    /// Stable rule identifier of the substitution rule.
    pub rule_id: String,
    /// Human-readable rule title, resolved from the rule id when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_title: Option<String>,
    /// Name the upstream saw after the tool definition was rewritten.
    pub replaced_name: String,
    /// Native server-tool type when the intercepted tool was a server-tool on
    /// the wire (visible-mode); `None` for client function-tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
}

/// Kind of `ToolsChanged` event. `between_turns` signals the available tool
/// set differs from the previous turn (client added/removed/swapped tools);
/// `policy_modified` signals tool policy mutated the set on this turn.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolsChangeKind {
    BetweenTurns,
    PolicyModified,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "type")]
pub enum ConversationEvent {
    #[serde(rename = "system_prompt")]
    SystemPrompt {
        content: String,
        turn: i32,
        /// The message this event renders, in its client protocol's wire shape (raw view only).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        raw: Option<serde_json::Value>,
    },

    #[serde(rename = "message")]
    Message {
        role: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        thinking: Option<String>,
        turn: i32,
        is_new: bool,
        /// True when this assistant message came from the client's request
        /// history rather than from a proxy-captured response. Lets the UI
        /// flag client-sent history echoes that didn't originate from any
        /// captured upstream call — e.g. fabricated assistant turns. Always
        /// false for user / tool / system events.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_from_history: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<TurnMetadata>,
        /// The message this event renders, in its client protocol's wire shape (raw view only).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        raw: Option<serde_json::Value>,
        /// Inbound-prompt guardrail findings (P1/P2) that flagged this message —
        /// the user's own prose (direct injection / jailbreak), an inbound PII
        /// detection, or a tool-result the client folded into the turn (indirect
        /// injection) — before it reached the model. One message can trip
        /// several detectors at once (e.g. an injection step AND a PII step on
        /// the same prose), so every finding is carried and rendered as its own
        /// shield banner. Empty when the message was clean.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guardrails: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
    },

    #[serde(rename = "tool_call")]
    ToolCall {
        name: String,
        /// The call's arguments as the model sent them — whatever the tool's schema allows.
        #[schema(value_type = Object)]
        arguments: serde_json::Value,
        id: String,
        turn: i32,
        is_new: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<TurnMetadata>,
        /// The message this event renders, in its client protocol's wire shape (raw view only).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        raw: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        risk_level: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        risk_description: Option<String>,
        /// Populated when a policy rule rejected this tool call. The call is
        /// still rendered (name + effective args) so operators see what the
        /// model attempted, with a rule-identity banner attached. Boxed: this is
        /// the rare block path, so keeping it out-of-line keeps the common
        /// `ToolCall` variant small.
        #[serde(skip_serializing_if = "Option::is_none")]
        blocked: Option<Box<ToolCallBlock>>,
        /// Populated when a substitution rule intercepted this call and ran it
        /// server-side (web-executor). The call is rendered with an
        /// "intercepted by policy" banner; the server-side execution + guardrail
        /// surface on the following `web_call` event. Boxed for the same reason
        /// as `blocked` — a cold-path payload kept out-of-line.
        #[serde(skip_serializing_if = "Option::is_none")]
        intercepted: Option<Box<InterceptionInfo>>,
        /// Per-argument rewrites applied by policy rules or Rhai transforms.
        /// The proxy does not populate this today — the field exists so the
        /// UI can render transform-driven arg diffs once the pipeline captures
        /// them. Empty / absent means the arguments are unchanged.
        #[serde(skip_serializing_if = "Option::is_none")]
        modifications: Option<Vec<streamscope_core::proxy::content::ToolArgModification>>,
    },

    #[serde(rename = "tool_result")]
    ToolResult {
        tool_call_id: String,
        content: String,
        turn: i32,
        is_new: bool,
        /// The message this event renders, in its client protocol's wire shape (raw view only).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        raw: Option<serde_json::Value>,
        /// Populated when a request-phase `redact_result` rule rewrote or
        /// dropped this tool_result before it was forwarded to the model.
        /// The content shown is the effective (redacted) payload; this slot
        /// carries the original, the rule identity, and the reason so the UI
        /// can surface a banner with a diff toggle — matching the treatment
        /// `ToolCallBlock` gives to blocked tool calls. `None` when the
        /// result passed through untouched.
        #[serde(skip_serializing_if = "Option::is_none")]
        redacted: Option<streamscope_core::proxy::content::RedactedToolResultInfo>,
        /// Inline-guardrail findings that flagged this folded tool-result — a
        /// web tool-result carrying a prompt-injection attempt, an inbound PII
        /// detection, or both at once — before it was folded back into the
        /// model. Every finding is carried and rendered as its own shield
        /// banner. Empty when the result was clean or not web-sourced.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guardrails: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
    },

    #[serde(rename = "compaction")]
    Compaction {
        turn: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        messages_before: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        messages_after: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
    },

    /// Emitted when the client rebuilt the message array without reducing its size
    /// (e.g., different system prompt, reorganized messages). The conversation
    /// baseline was reset but no compaction occurred.
    #[serde(rename = "context_reset")]
    ContextReset { turn: i32, message_count: usize },

    #[serde(rename = "time_gap")]
    TimeGap { gap_ms: i64, before_turn: i32 },

    #[serde(rename = "turn_boundary")]
    TurnBoundary {
        turn: i32,
        #[serde(skip_serializing_if = "Option::is_none")]
        timestamp: Option<String>,
    },

    /// Emitted whenever the effective tool set differs from what the model
    /// "saw" on the previous turn (`BetweenTurns`) or what the client sent on
    /// this turn was modified by tool policy (`PolicyModified`). The UI
    /// renders a compact "tools changed" banner with an expand-to-diff
    /// affordance, dereferencing each hash via the lazy
    /// `/audit/tool-definitions/{hash}` endpoint.
    #[serde(rename = "tools_changed")]
    ToolsChanged {
        turn: i32,
        kind: ToolsChangeKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        current_hash: Option<String>,
    },

    /// Media attachment (image, document, audio) extracted from a message.
    #[serde(rename = "media")]
    Media {
        role: String,
        /// MIME type, e.g. "image/png", "application/pdf", "audio/wav"
        media_type: String,
        /// Category: "image", "document", "audio"
        content_type: String,
        /// Base64 data (inline for small media, omitted for large or stripped)
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        /// The client's own reference to the media: an external URL or a
        /// provider file id. Never a gateway URL — a stored blob is named by
        /// `content_hash` + `blob_type` (+ `request_id` when the turn carried
        /// it), from which each plane builds its own media route (the
        /// console's and the portal's differ, and the portal's needs the
        /// request to prove ownership).
        #[serde(skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Document title
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Approximate size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        size_bytes: Option<usize>,
        turn: i32,
        is_new: bool,
        /// SHA-256 content hash for blob retrieval (set for blob_ref media)
        #[serde(skip_serializing_if = "Option::is_none")]
        content_hash: Option<String>,
        /// The stored blob's kind — set whenever `content_hash` is.
        #[serde(skip_serializing_if = "Option::is_none")]
        blob_type: Option<BlobType>,
        /// The request that carried the stored blob — the turn's own request,
        /// when it sent the bytes itself. Absent when the turn only names the
        /// blob (a part the client wrote, or history it did not resend): the
        /// portal's media route requires it, so such a blob is not served
        /// there.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<Uuid>,
    },

    /// Standalone media API call (embeddings, audio, images, video) linked to a session.
    ///
    /// Carries the canonical [`DomainMediaCall`] as the single source of truth —
    /// UI reads endpoint / model / input-output blocks / params / job status
    /// directly from `media_call`. Blob hashes are embedded as `BlobRef` blocks
    /// inside `media_call.input` / `media_call.output`. Boxed so the variant
    /// doesn't bloat every other `ConversationEvent` variant on the wire.
    #[serde(rename = "media_api_call")]
    MediaApiCall {
        #[schema(value_type = streamscope_core::api::domain_request::DomainMediaCall)]
        media_call: Box<streamscope_core::api::domain_request::DomainMediaCall>,
        turn: i32,
        is_new: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata: Option<TurnMetadata>,
    },

    /// Framework-injected volatile block (e.g. `<system-reminder>…`,
    /// `<available-deferred-tools>…`, `<local-command-*>…`,
    /// `<command-*>…`) that was embedded inline inside a user or
    /// assistant text block. The event builder splits prose from these
    /// blocks so the session UI can render the prose as a normal bubble
    /// and the reminder as a collapsed card — matches the Anthropic-
    /// style collapse seen in other LLM consoles.
    ///
    /// `content` carries the full raw block including opening and
    /// closing tags so the UI shows exactly what the framework injected.
    /// `raw`, when present, is attached to the first emitted event for
    /// the parent message (same single-shot rule as `ConversationEvent::Message`).
    #[serde(rename = "framework_reminder")]
    FrameworkReminder {
        role: String,
        label: String,
        content: String,
        turn: i32,
        is_new: bool,
        /// The message this event renders, in its client protocol's wire shape (raw view only).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        raw: Option<serde_json::Value>,
    },

    /// MCP gateway call interleaved into the LLM session timeline. The
    /// proxy stamps `gateway_audit.session_id` with the same hashed value
    /// the LLM path uses, so all of an agent's MCP traffic correlates
    /// back to the LLM session by id. Rendered between turns at its
    /// actual timestamp — matches the agentic workflow (LLM proposes a
    /// tool → MCP gateway dispatches → result → next assistant turn).
    #[serde(rename = "mcp_call")]
    McpCall {
        request_id: Uuid,
        /// RFC3339 timestamp — used by the UI to position the bubble.
        timestamp: String,
        /// JSON-RPC method (`tools/call`, `prompts/get`, `resources/read`,
        /// `initialize`, `tools/list`, …).
        method: String,
        /// Resolved canonical tool id (set on `tools/call`).
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prompt_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource_uri: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        virtual_server_slug: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_server_name: Option<String>,
        /// HTTP status (`gateway_audit.status_code`).
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<i16>,
        /// JSON-RPC `-32xxx` code (`mcp_audit.error_code`).
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_message: Option<String>,
        /// Total request latency including network — `gateway_audit.latency_total_ms`.
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<i64>,
        /// Typed diff payload stamped by the MCP policy engine + multiplex
        /// pump. Same shape as `McpAuditLogEntry.transform_diff` so the
        /// session-view bubble and the audit detail render through the
        /// same UI primitives.
        #[serde(skip_serializing_if = "Option::is_none")]
        transform_diff: Option<McpTransformDiff>,
        /// JSON-RPC request `params` payload (e.g. `{name, arguments}` for
        /// `tools/call`, `{uri}` for `resources/read`). Surfaced so the
        /// session-view bubble can render the actual call body inline.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        params: Option<serde_json::Value>,
        /// JSON-RPC `result` payload returned by the upstream on success.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schema(value_type = Option<Object>)]
        result: Option<serde_json::Value>,
        /// LLM turn this call sits between (the turn whose timestamp
        /// most recently preceded this MCP call). `0` when the MCP call
        /// fires before any LLM turn.
        turn: i32,
    },
    /// Single web (search or fetch) call dispatched against the built-in Web
    /// virtual MCP server. Mirrors `McpCall`'s shape — backend-built so the
    /// session-replay bubble and the audit-detail drawer render through
    /// the same `WebCallEvent` component without reconstructing the event
    /// shape client-side.
    #[serde(rename = "web_call")]
    Web {
        request_id: Uuid,
        /// RFC3339 timestamp — used by the UI to position the bubble.
        timestamp: String,
        /// `"search"` (backend query) or `"fetch"` (URL retrieval).
        operation: String,
        /// `"mcp"` (direct `/mcp/web` traffic), `"substitution"` (agent loop),
        /// or `"admin_test"` (operator probe).
        surface: String,
        /// Configured backend code (`"searxng"` | `"brave"` | ...).
        backend: String,
        /// search → query string; fetch → URL.
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// search → hits returned post-filter; fetch → 1 on success.
        #[serde(skip_serializing_if = "Option::is_none")]
        result_count: Option<i32>,
        /// `gateway_audit.status_code`.
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<i16>,
        /// Typed error category when the call failed.
        #[serde(skip_serializing_if = "Option::is_none")]
        error_category: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_detail: Option<String>,
        /// `gateway_audit.latency_total_ms`.
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<i64>,
        /// Orchestrating LLM `request_id` when `surface == "substitution"`.
        #[serde(skip_serializing_if = "Option::is_none")]
        parent_request_id: Option<Uuid>,
        /// Stamped audit badges for this call.
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
        badges: Vec<streamscope_core::audit::AuditBadge>,
        /// Inline-guardrail findings on the content this call fetched, surfaced
        /// on the web operation itself (server-side). For `substitution` they are
        /// the turn's `guardrail_steps` entries matched by `tool_use_id` (a
        /// single fetch can trip several detectors at once); for `mcp` they are
        /// normalized from the row's guardrail badges. Empty when clean.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guardrails: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
        /// LLM turn this call sits between (matches the `McpCall.turn`
        /// semantics).
        turn: i32,
    },

    /// A2A gateway call — one agent invoking another — interleaved into the
    /// session timeline beside the LLM turns and MCP calls that surround it.
    ///
    /// This is the event that makes the orchestrator pattern legible: an LLM turn
    /// emits a `tool_use` whose implementation is an outbound `SendMessage` to a
    /// remote agent, and with the same `X-Session-Id` the decision and the
    /// agent-to-agent exchange it caused sit in one timeline.
    ///
    /// Content is carried as canonical [`DomainContentBlock`]s — the same block
    /// vocabulary the LLM protocols normalize into — so a text part, an image an
    /// agent returned, and a structured payload all render through the existing
    /// block components rather than an A2A-specific renderer.
    #[serde(rename = "a2a_call")]
    A2aCall {
        request_id: Uuid,
        /// RFC3339 timestamp — used by the UI to position the bubble.
        timestamp: String,
        /// A2A operation (`SendMessage`, `GetTask`, …).
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_slug: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_name: Option<String>,
        /// Who initiated the call — the authenticated gateway principal (the
        /// user's email, else the client app id). This is the direction the
        /// whole surface turns on: this caller is talking TO `agent_slug`, and
        /// naming it is what makes an A2A row legible ("frank → research-desk").
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_label: Option<String>,
        /// `"user"` or `"app"` — selects the caller glyph on the client; absent
        /// when the principal is unknown (keyless / pre-auth error).
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_kind: Option<String>,
        /// Wire `contextId` — the A2A conversation correlator.
        #[serde(skip_serializing_if = "Option::is_none")]
        context_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        task_id: Option<String>,
        /// Last observed `TASK_STATE_*`.
        #[serde(skip_serializing_if = "Option::is_none")]
        task_state: Option<String>,
        /// The message the caller sent, as it was sent (pre-screening).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[schema(value_type = Vec<streamscope_core::api::domain_request::DomainContentBlock>)]
        request_blocks: Vec<streamscope_core::api::domain_request::DomainContentBlock>,
        /// The agent's reply — its message plus its task status message.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[schema(value_type = Vec<streamscope_core::api::domain_request::DomainContentBlock>)]
        response_blocks: Vec<streamscope_core::api::domain_request::DomainContentBlock>,
        /// Artifacts the agent produced — an A2A task's typed output.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        artifacts: Vec<A2aArtifactView>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status_code: Option<i16>,
        /// JSON-RPC `-32xxx` code.
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<i64>,
        /// Populated when a policy rule refused the call. The call is still
        /// rendered — the caller really did attempt it — with a rule-identity
        /// banner, exactly as a blocked tool call is.
        #[serde(skip_serializing_if = "Option::is_none")]
        blocked: Option<Box<ToolCallBlock>>,
        /// Guardrail findings on the message or on the reply. Each renders its
        /// own shield banner.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        guardrails: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
        badges: Vec<streamscope_core::audit::AuditBadge>,
        /// LLM turn this call sits between (same semantics as `McpCall.turn`).
        turn: i32,
    },
}

/// One artifact an A2A agent produced, projected into canonical blocks.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct A2aArtifactView {
    pub artifact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[schema(value_type = Vec<streamscope_core::api::domain_request::DomainContentBlock>)]
    pub blocks: Vec<streamscope_core::api::domain_request::DomainContentBlock>,
}
