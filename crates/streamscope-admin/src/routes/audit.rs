//! Audit log and session query endpoints.
//!
//! Provides paginated access to audit records and session summaries with
//! filtering by user, model, app, date range, and status. Detailed session
//! views with conversation turns, tool calls, and transform diffs. All
//! queries tenant-scoped via RLS.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// Pagination defaults
const AUDIT_DEFAULT_LIMIT: i64 = 100;

use super::{
    ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, SpendTotal,
    WorkspaceIds, spend_total,
};
use crate::AdminState;
use crate::audit_store::AuditScope;
use crate::sql_pattern::search_text;
use crate::audit_store::logs::{
    list_audit_logs_web, list_audit_rows,
};
use crate::audit_store::sessions::{
    self, SESSIONS_DEFAULT_LIMIT, linked_sessions_tenant_wide, list_sessions_impl,
};
use crate::audit_store::timeline::{
    self, A2aCallRowForSession, McpCallRowForSession, WebCallRowForSession,
};
use crate::audit_store::trace;
use crate::conversation::{build_events, ConversationEvent, ToolsChangeKind, TurnMetadata, TurnRow};
use crate::db::tenant::{Scoped, TenantConn};
use streamscope_core::audit::BlobType;


/// A timeline turn's metadata: its audit row's usage, latency, cost, badges
/// and error envelope — zeros and `None`s for a turn with no audit row.
fn turn_metadata(
    row: &timeline::TimelineTurn,
    transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
) -> TurnMetadata {
    TurnMetadata {
        request_id: Some(row.request_id),
        tokens_in: row.prompt_tokens.unwrap_or(0),
        tokens_out: row.completion_tokens.unwrap_or(0),
        cache_creation_tokens: row.cache_creation_tokens,
        cache_read_tokens: row.cache_read_tokens,
        reasoning_tokens: row.reasoning_tokens,
        latency_ms: row.latency_total_ms.unwrap_or(0),
        ttft_ms: row.latency_ttft_ms.unwrap_or(0),
        spend: row
            .cost
            .and_then(|amount| spend_total(1, row.cost_currency.clone(), amount, Default::default())),
        finish_reason: row.finish_reason.clone().unwrap_or_else(|| "unknown".to_string()),
        badges: row.badges.decode("badges", row.request_id).unwrap_or_default(),
        transform_diff,
        error_category: row.error_category.clone(),
        status_code: row.status_code,
        error_detail: row.error_detail.clone(),
        model_used: row.model_used.clone(),
        model_requested: row.model_requested.clone(),
        provider: row.provider.clone(),
        upstream_server_name: row.upstream_server_name.clone(),
        workspace_name: row.workspace_name.clone(),
    }
}

/// Discriminator for the `/audit` endpoint's row families. Defaults to
/// [`AuditKind::Llm`] so callers that haven't migrated keep the existing
/// shape; native MCP clients pass `kind=mcp`; `kind=web` returns
/// rows from the `web_audit` partition (one per dispatched call,
/// including substitution-loop children); `kind=all` runs every query
/// server-side and merges by `timestamp DESC`.
#[derive(Debug, Clone, Copy, PartialEq, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    #[default]
    Llm,
    Mcp,
    Web,
    A2a,
    All,
}

#[derive(Deserialize, IntoParams, Default)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)] // Fields read via Deserialize + query builder
pub struct AuditQuery {
    // `user_id` and `workspace_ids` are private: they are the console's HTTP
    // input, read only by `console_scope`. Every other caller passes its own
    // `AuditScope`, and the store reads whose rows from that alone.
    user_id: Option<Uuid>,
    /// Comma-separated workspace ids to include (UUIDs). Applies to every `kind`
    /// (LLM / MCP / web) via the shared `gateway_audit.workspace_id`. Omit for
    /// all workspaces.
    #[param(value_type = Option<String>)]
    workspace_ids: Option<WorkspaceIds>,
    pub user_email: Option<String>,
    pub model: Option<String>,
    pub app_id: Option<String>,
    pub finish_reason: Option<String>,
    pub error_category: Option<String>,
    pub media_type: Option<String>,
    /// Inclusive window start (RFC3339).
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    /// Exact-match filter on `gateway_audit.request_id`. Used by deep-links
    /// from the tool-calls / mcp-tool-calls feeds (`/audit?request_id=…`) so
    /// a single row can be focused and auto-expanded. Applies to every `kind`.
    pub request_id: Option<Uuid>,
    /// Exact-match filter on `gateway_audit.key_id` interpreted as a spec-OAuth
    /// `jti`. The proxy stamps the JWT's `jti` straight into `key_id` for
    /// OAuth-authenticated MCP requests (see `proxy/mcp/spec_oauth.rs`), so an
    /// operator deep-linking from the Tokens view (`/audit?kind=mcp&jti=…`)
    /// lands on exactly that token's traffic. Only meaningful on `kind=mcp`.
    pub jti: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Row family to return. Default `llm`; `mcp` returns MCP gateway rows;
    /// `all` interleaves both by timestamp.
    pub kind: Option<AuditKind>,
    /// MCP-side method filter (comma-separated). Whitelisted at the handler
    /// level. The Tool Calls feed (`/tool-calls`) sends
    /// `methods=tools/call,resources/read,prompts/get` to narrow `kind=mcp`
    /// to the three caller-addressable methods. Empty / unset means no
    /// filter. Ignored on the LLM side.
    pub methods: Option<String>,
    /// MCP-side: filter to a single canonical `tool_id` (from the field-
    /// profile registry). Used by Top-Tools deep-links from the dashboards.
    pub tool_id: Option<String>,
    /// MCP-side: filter to a single resource URI. Substring match.
    pub resource_uri: Option<String>,
    /// MCP-side: filter to a single prompt id. Exact match.
    pub prompt_id: Option<String>,
    /// MCP-side: filter to one virtual server (mount slug → UUID via
    /// `mcp_virtual_servers.id`). Used by Top-Endpoints deep-links.
    pub virtual_server_id: Option<Uuid>,
    /// MCP-side: filter to one upstream server (`mcp_upstream_servers.id`).
    /// Used by Top-Upstreams deep-links.
    pub upstream_server_id: Option<Uuid>,
    /// LLM-side: filter to one upstream server by name (joined via
    /// `upstream_servers.name`). Used by the LLM dashboard Top-Servers
    /// deep-link.
    pub upstream_server: Option<String>,
    /// LLM-side: filter to one wire protocol (`chat_completions` /
    /// `responses` / `anthropic_messages` / `google_gemini`). Bound on
    /// `llm_audit.api_version`. Used by Proxy dashboard per-protocol
    /// drill-downs.
    pub api_version: Option<String>,
    /// LLM-side: when true, restrict to rows whose `llm_audit.badges` carry a
    /// response-phase `tool_blocked` event — i.e. tool calls the policy engine
    /// suppressed. Powers the Dashboard Overview's "Blocked tools" attention
    /// tile click-through. Ignored on MCP / web kinds.
    pub has_blocked: Option<bool>,
    /// When true, restrict to rows whose `badges` carry a `guardrail` event —
    /// the inline injection guardrail flagged untrusted web content. Applies to
    /// the `llm` kind (content folded back into a model on the substitution
    /// loop) and the `web` kind (direct `/mcp/web` observe scan); ignored on
    /// `mcp`. Powers the Dashboard Overview's "Web guardrail" attention tile
    /// click-through.
    pub has_guardrail: Option<bool>,
    /// Web-side: filter to one dispatch surface. Whitelisted at the handler.
    pub surface: Option<String>,
    /// Web-side: filter to one operation kind. Whitelisted at the handler.
    pub operation: Option<String>,
    /// A2A-side: filter to one registered agent by its **slug** — the agent's
    /// public identifier everywhere else in the product (the `/a2a/<slug>` mount,
    /// the `a2a_agent_filter` policy pivot, the dashboard's by-agent key), so a
    /// deep-link from any of those surfaces lands here unchanged.
    pub agent_slug: Option<String>,
    /// A2A-side: filter to one `TASK_STATE_*`. Whitelisted at the handler, so an
    /// unknown value can't reach the inline SQL literal.
    pub task_state: Option<String>,
}

impl AuditQuery {
    /// The console's scope: the `user_id` and `workspace_ids` it was sent, over
    /// the whole tenant otherwise.
    fn console_scope(&self) -> AuditScope {
        AuditScope::tenant(self.user_id, self.workspace_ids.clone())
    }
}

/// Resolve up to two tool-definition hashes to their full JSON blobs.
/// Returns `(available, effective)`. Either side is `None` when its hash is
/// `None` OR when the tenant holds no such set (defensive — the set is
/// written before the audit row). A tool-less turn issues no read.
async fn resolve_tool_definitions(
    conn: &mut Scoped,
    tenant_id: Uuid,
    available: Option<&str>,
    effective: Option<&str>,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>), ApiError> {
    let mut hashes: Vec<String> = Vec::with_capacity(2);
    if let Some(h) = available {
        hashes.push(h.to_string());
    }
    if let Some(h) = effective
        && Some(h) != available
    {
        hashes.push(h.to_string());
    }
    if hashes.is_empty() {
        return Ok((None, None));
    }
    let map = crate::content_store::tool_definitions::get_many(conn, tenant_id, &hashes)
        .await
        .map_err(|e| {
            tracing::error!("resolve_tool_definitions: {e}");
            ApiError::internal("Failed to resolve tool definitions")
        })?;
    let avail = available.and_then(|h| map.get(h).cloned());
    // When effective == available, surface only on the `request_tools` side
    // (UI shows a single "tools" pane); leave `tools_effective` None.
    let eff = match (available, effective) {
        (Some(a), Some(e)) if a == e => None,
        (_, Some(e)) => map.get(e).cloned(),
        (_, None) => None,
    };
    Ok((avail, eff))
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct AuditLogEntry {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub app_id: Option<String>,
    /// Raw client-facing session id from `gateway_audit.session_id` — the
    /// hashed X-Session-Id value used for cross-stream correlation in the
    /// session detection layer. This is NOT the conversation id used by
    /// the session-detail UI: that's the separate content-derived
    /// `conversation_session_id` below, populated only when there's an
    /// LLM turn linked via `conversation_turns.session_id`. UI callers
    /// building "View Session" links MUST use `conversation_session_id`,
    /// not this field — the two diverge for any session that didn't go
    /// through the LLM pipeline (MCP-only, web-only, etc).
    pub session_id: Option<Uuid>,
    /// Content-derived conversation id from `conversation_turns.session_id`.
    /// `None` when no `conversation_turns` row exists for this request
    /// (MCP/web audit rows, LLM rows captured before content
    /// logging was on). Use this — not `session_id` — for any UI link to
    /// `/sessions/{id}`.
    pub conversation_session_id: Option<Uuid>,
    pub user_agent: Option<String>,
    pub detection_method: Option<String>,
    /// Forwarded end-client identity, present only for Inline AI traffic where a
    /// trusted inline key relayed it (`X-Client-IP` / `X-Authenticated-User` /
    /// `X-Authenticated-Groups`). Absent/empty for direct clients.
    pub client_ip: Option<String>,
    pub end_user: Option<String>,
    /// Empty for a direct client.
    pub end_user_groups: Vec<String>,
    pub model_requested: String,
    pub model_used: String,
    pub provider: String,
    pub api_version: String,
    pub stream: bool,
    pub prompt_tokens: i32,
    pub completion_tokens: i32,
    pub reasoning_tokens: Option<i32>,
    pub cache_creation_tokens: Option<i32>,
    pub cache_read_tokens: Option<i32>,
    pub finish_reason: String,
    pub native_finish_reason: Option<String>,
    /// Human-readable label: "completed", "truncated", "tool_call", "filtered", "error"
    #[sqlx(skip)]
    pub finish_reason_display: String,
    /// The row's total, in `cost_currency` — the tenant's accounting currency
    /// as it was when the row was written, not as it is now. Stamped per row so
    /// changing the setting cannot restate spend that was already reported.
    pub cost: f64,
    #[sqlx(try_from = "String")]
    #[schema(value_type = String, example = "USD")]
    pub cost_currency: streamscope_core::pricing::Currency,
    /// What the provider charges, in the currency it quotes, and the multiplier
    /// that took one to the other. Equal to `cost` with an `fx_rate` of 1 when
    /// the model is priced in the accounting currency.
    pub source_cost: f64,
    #[sqlx(try_from = "String")]
    #[schema(value_type = String, example = "EUR")]
    pub source_currency: streamscope_core::pricing::Currency,
    pub fx_rate: f64,
    /// Per-unit decomposition of `cost`: what was charged for each thing the
    /// request consumed. Counts are what was CHARGED — a provider's reported
    /// count less anything that partitions out of it, each of which carries its
    /// own line — so the lines sum to `cost` less `embedding_cost`.
    #[sqlx(json)]
    #[serde(deserialize_with = "streamscope_core::pricing::deserialize_billed_units")]
    #[schema(value_type = std::collections::BTreeMap<String, streamscope_core::pricing::BilledUnit>)]
    pub billed_units: streamscope_core::pricing::BilledUnits,
    /// Portion of `cost` spent on the response cache's own embedding call,
    /// with the tokens it consumed. Non-zero only on a Semantic-cached alias.
    /// Present so the row's total still decomposes: without it `cost`
    /// exceeds the completion's own cost with nothing to explain the gap.
    pub embedding_cost: f64,
    pub embedding_tokens: i32,
    pub zero_completion: bool,
    /// Milliseconds from the moment the gateway started forwarding — after its
    /// own checks and transforms — to the first token: any hold for capacity
    /// (`queue_wait_ms`) and any earlier attempt it moved on from included.
    pub latency_ttft_ms: i64,
    /// Milliseconds from the moment the gateway started forwarding — after its
    /// own checks and transforms — to the end of the answer: any hold for
    /// capacity (`queue_wait_ms`) and any earlier attempt it moved on from
    /// included.
    pub latency_total_ms: i64,
    /// Typed audit badges (`streamscope_core::audit::AuditBadge`, codes
    /// append-only): the LLM row's own, plus a `session_alert` read from its session's
    /// current alert (the agent writes the alert on the session, never on the
    /// audit row).
    #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
    pub badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
    /// The row's session's alert level and the experts that raised it, folded
    /// into `badges`.
    #[serde(skip)]
    #[sqlx(default)]
    pub session_alert_level: Option<String>,
    #[serde(skip)]
    #[sqlx(default)]
    pub session_alert_axis: Option<String>,
    /// Internal pipeline-path tag (`fastpath` | `buffered`). Analytics-only,
    /// not user-facing.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub pipeline_path: Option<String>,
    /// Path/method of the catch-all hit (only populated when the request fell
    /// to the catch-all handler).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub catchall_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub catchall_method: Option<String>,
    pub status_code: Option<i16>,
    pub error_category: Option<String>,
    pub error_detail: Option<String>,
    /// On a limit refusal: which limit refused it — `organisation`,
    /// `workspace`, `member` or `key`. The UI explains a refusal from this.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub limit_bucket: Option<String>,
    /// Canonical media RPC shape — source of truth for embeddings / audio /
    /// images / video endpoint turns. `None` for chat/text routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<streamscope_core::api::domain_request::DomainMediaCall>)]
    pub media_call: Option<sqlx::types::Json<streamscope_core::api::domain_request::DomainMediaCall>>,
    /// Extracted media references for chat requests. Typed shape mirrors
    /// `streamscope_core::audit::ChatMediaSummaryEntry`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Vec<streamscope_core::audit::ChatMediaSummaryEntry>>)]
    pub chat_media_summary: Option<sqlx::types::Json<Vec<streamscope_core::audit::ChatMediaSummaryEntry>>>,
    /// Transform diff captured on `conversation_turns` — mirrors the shape in
    /// `GET /api/v1/admin/traces/{request_id}`. Present when the request had
    /// transforms applied with `capture_diffs` enabled. `None` otherwise (e.g.,
    /// media requests, non-text requests, or transforms without diff capture).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
    // Joined from users table
    pub user_email: Option<String>,
    // Joined from upstream_servers via api_keys
    pub upstream_server_name: Option<String>,
    /// The replica endpoint of the server that answered, as its URL was when
    /// it did. Null on a row with no upstream call, or from a release before
    /// endpoints.
    #[sqlx(default)]
    pub endpoint_url: Option<String>,
    /// Milliseconds the request waited for upstream capacity before it was
    /// dispatched. Part of `latency_ttft_ms` and `latency_total_ms`: the time
    /// the upstream that answered took is the latency less this and less any
    /// earlier attempt it moved on from.
    #[sqlx(default)]
    pub queue_wait_ms: Option<i32>,
    /// The QoS class the request ran as. The name is resolved by the reader
    /// against the tenant's class list — an audit row must not hold a class
    /// back from being renamed or deleted.
    #[sqlx(default)]
    pub qos_class_id: Option<uuid::Uuid>,
    // Joined from workspaces via gateway_audit
    pub workspace_name: Option<String>,
    // Joined from api_keys
    pub key_name: Option<String>,
    pub key_prefix: Option<String>,
}

/// Typed shape of `mcp_audit.transform_diff`. The MCP proxy stamps a finite
/// set of well-known keys — surfacing them as named optional fields keeps the
/// admin UI off untyped JSONB grovel and lets `openapi-typescript` generate
/// strict TS types. Adding a key here requires bumping the proxy and the UI
/// in lockstep; the keys are append-only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct McpTransformDiff {
    /// Set when the unified policy engine fired a rule on this RPC. Mirrors
    /// `streamscope_core::config::tool_rules::RiskResult` — same shape used by the
    /// LLM tool-policy path so the UI banner is shared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_classification: Option<McpPolicyClassification>,
    /// Per-call multiplex summary for streaming `tools/call` / `prompts/get`.
    /// Counters are non-zero only when the upstream emitted SSE events of
    /// the corresponding kind during the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_stream: Option<McpStreamSummary>,
    /// Stamped on rows that represent a server-initiated round-trip (the
    /// agent's reply to an upstream `sampling/createMessage` or
    /// `elicitation/create`). The `method` is the upstream's request method;
    /// `rpc_id` is opaque (JSON-RPC id can be string / number / null).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server_initiated: Option<McpServerInitiated>,
    /// Stamped on rows that represent a `notifications/{tools,resources,prompts}/list_changed`
    /// passthrough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_list_changed: Option<McpListChanged>,
    /// Stamped on rows that represent a `notifications/elicitation/complete`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_elicitation_complete: Option<McpElicitationComplete>,
    /// `"sse"` when the upstream still uses the legacy `text/event-stream`
    /// GET transport instead of Streamable HTTP. Operator-visible signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Stamped on `mcp_audit` rows for `sampling/createMessage` calls that
    /// were intercepted by the gateway. The matching `llm_audit` row is
    /// linked by shared `gateway_audit.session_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_intercept: Option<McpSamplingInterceptOutcome>,
}

/// Mirrors `streamscope_core::audit::mcp::SamplingInterceptOutcome` for wire
/// transport. Two shapes:
///
/// - `Served` — synthetic LLM call succeeded; the linked llm_audit row
///   carries the actual cost + token counts. Includes the resolved upstream
///   model and the loopback latency for at-a-glance triage.
/// - `Failed` — interception attempted but could not be served (auth
///   rejection, budget exceeded, capability mismatch). Reason is a stable
///   short string for UI dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpSamplingInterceptOutcome {
    Served {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        latency_ms: u64,
    },
    Failed {
        reason: String,
    },
}

/// Mirrors `streamscope_core::config::tool_rules::RiskResult` as the proxy's MCP
/// audit writer stamps it into `transform_diff.policy_classification`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpPolicyClassification {
    /// Id of the rule that fired. `None` when no rule fired but the action is
    /// non-allow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub risk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `"allow"` | `"classify"` | `"block"` | `"replace"`.
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

/// One policy rule that fired on an agent call, and where.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct A2aPolicyFinding {
    /// `request` (the message the caller sent) or `response` (the agent's reply).
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub risk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `classify` | `block` | `replace`.
    pub action: String,
}

/// `a2a_audit.transform_diff` — what the gateway did to an agent call.
///
/// Both lists, because both phases can fire on one call: a rule may rewrite the
/// outbound message *and* another rewrite the reply, and an operator looking at a
/// modified call has to see both.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct A2aTransformDiff {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_findings: Vec<A2aPolicyFinding>,
    /// Inline-guardrail findings on this call — the caller's message (request
    /// phase) and the agent's reply (response phase) each produce their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<streamscope_core::proxy::content::GuardrailStepDiff>)]
    pub guardrail_steps: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
}

impl A2aTransformDiff {
    /// Whether there is anything to show. An empty diff renders no banner rather
    /// than an empty one.
    fn is_empty(&self) -> bool {
        self.policy_findings.is_empty() && self.guardrail_steps.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpStreamSummary {
    pub sampling_requests: u32,
    pub elicitation_requests: u32,
    pub log_notifications: u32,
    pub list_changed_notifications: u32,
    pub elicitation_complete_notifications: u32,
    /// Total bytes streamed from upstream during the call. Wire shape is the
    /// proxy's `usize` → JSON number; we deserialize as `i64` to leave
    /// headroom past the current 8 MiB `MCP_STREAM_MAX_BYTES` cap.
    pub stream_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpServerInitiated {
    /// Opaque JSON-RPC id (string | number | null).
    #[schema(value_type = Object)]
    pub rpc_id: serde_json::Value,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpListChanged {
    /// `"tools"` | `"resources"` | `"prompts"`.
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct McpElicitationComplete {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elicitation_id: Option<String>,
}

/// MCP-side audit row exposed at `/audit?kind=mcp`. Per-call shape with the
/// joined virtual-server slug + user email + protocol_version so the audit
/// UI can render rows without an extra fan-out fetch. Operators correlate
/// across calls in the same JSON-RPC session by pasting `mcp_session_id`
/// into the audit list `search` box (substring match).
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpAuditLogEntry {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    /// Three-tier app id resolved by `extract_attribution` from `X-App-Id` /
    /// `Referer` / `User-Agent` (mirrors LLM rows). `None` when no pattern
    /// matched. Stored on `gateway_audit.app_id`.
    pub app_id: Option<String>,
    /// Hashed session id from `gateway_audit.session_id` — same shape the
    /// LLM `AuditLogEntry` carries. Cross-protocol correlation pivots on
    /// this when an MCP `sampling/createMessage` was intercepted by the
    /// gateway and answered through the LLM pipeline (the synthetic
    /// `llm_audit` row shares this id).
    pub session_id: Option<Uuid>,
    /// Raw `Mcp-Session-Id` header from the call. Distinct from
    /// `session_id` above (which is hashed).
    pub mcp_session_id: Option<String>,
    pub virtual_server_id: Uuid,
    pub virtual_server_slug: Option<String>,
    pub upstream_server_id: Option<Uuid>,
    pub upstream_server_name: Option<String>,
    /// JSON-RPC method (`initialize`, `tools/list`, `tools/call`, …).
    pub method: String,
    pub tool_id: Option<String>,
    pub prompt_id: Option<String>,
    pub resource_uri: Option<String>,
    /// HTTP status from `gateway_audit.status_code` (SMALLINT → `i16`).
    pub status_code: Option<i16>,
    /// JSON-RPC `-32xxx` code from `mcp_audit.error_code` (INT → `i32`).
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub latency_total_ms: Option<i64>,
    pub upstream_latency_ms: i64,
    pub request_bytes: Option<i32>,
    pub response_bytes: Option<i32>,
    /// MCP protocol version negotiated at `initialize` and pinned for the
    /// remainder of the session. `None` for the rare row that lands before
    /// `initialize` completes (`mcp_sessions.protocol_version` defaults to
    /// `"unknown"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub protocol_version: Option<String>,
    /// Typed audit badges — same `AuditBadge` enum as LLM rows. Codes are
    /// append-only; UI consumer is the shared `BADGE_REGISTRY`. DB column
    /// is `NOT NULL DEFAULT '[]'` so this is always present.
    #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
    pub badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
    /// Typed diff payload stamped by the MCP policy engine + multiplex pump.
    /// Each field corresponds to a key the proxy may stamp on a given row.
    /// Empty struct (`{}`) when nothing fired.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<McpTransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<McpTransformDiff>>,
    /// JSON-RPC `params` payload as the agent sent it (for `tools/call`
    /// this is the `{name, arguments}` envelope; for `resources/read` the
    /// `{uri}`; for `prompts/get` the `{name, arguments}`). Mirrors the
    /// LLM trace's `messages` field — surfaced so the audit drawer + the
    /// session-view MCP bubble can render the actual request body
    /// without an extra fetch.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub params: Option<sqlx::types::Json<serde_json::Value>>,
    /// JSON-RPC `result` payload returned by the upstream (success path
    /// only — error responses populate `error_code` / `error_message`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub result: Option<sqlx::types::Json<serde_json::Value>>,
}

/// Web audit row exposed at `/audit?kind=web`. One row per
/// dispatched call (both direct `/mcp/web` traffic with `surface='mcp'` and
/// substitution-loop children with `surface='substitution'`). `parent_request_id`
/// links substitution rows back to the orchestrating LLM `gateway_audit`
/// row; the dedicated `GET /api/v1/admin/audit/{request_id}/web`
/// endpoint queries by it.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct WebAuditLogEntry {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    /// Three-tier app id (mirrors LLM rows).
    pub app_id: Option<String>,
    /// Hashed session id from `gateway_audit.session_id`.
    pub session_id: Option<Uuid>,
    /// Synthetic `mcp_upstream_servers` row id for `builtin-web`.
    pub upstream_server_id: Uuid,
    pub upstream_server_name: Option<String>,
    /// `"search"` or `"fetch"`.
    pub operation: String,
    /// Configured backend code (`"searxng"` | `"brave"` | …).
    pub backend: String,
    /// search → query string; fetch → URL.
    pub query: Option<String>,
    /// search → hits returned to caller (post-filter); fetch → 1 on success.
    pub result_count: Option<i32>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub upstream_latency_ms: i64,
    pub upstream_status: Option<i32>,
    /// HTTP status from `gateway_audit.status_code`.
    pub status_code: Option<i16>,
    pub error_category: Option<String>,
    pub error_detail: Option<String>,
    /// `gateway_audit.latency_total_ms`.
    pub latency_total_ms: Option<i64>,
    /// `"mcp"` (direct `/mcp/web` traffic) | `"substitution"`
    /// (agent-loop dispatcher).
    pub surface: String,
    /// Orchestrating LLM `request_id` when `surface == "substitution"`;
    /// `None` for direct MCP traffic.
    pub parent_request_id: Option<Uuid>,
    #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
    pub badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
    /// Per-URL filter verdicts on every search hit / fetch target.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub url_results: Option<sqlx::types::Json<serde_json::Value>>,
    /// Ordered filter ids that ran in the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub filter_chain: Option<sqlx::types::Json<serde_json::Value>>,
    /// Caller-supplied arguments verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub request_args: Option<sqlx::types::Json<serde_json::Value>>,
    /// Response shape returned to the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub response_summary: Option<sqlx::types::Json<serde_json::Value>>,
    /// Provider-side request URL+method (credentials redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub provider_request: Option<sqlx::types::Json<serde_json::Value>>,
    /// Provider's raw response, typed as the cap-aware
    /// [`streamscope_core::web::audit::WebProviderResponse`]
    /// enum. UI branches on the `Stripped` variant for the oversized
    /// callout.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<streamscope_core::web::audit::WebProviderResponse>)]
    pub provider_response:
        Option<sqlx::types::Json<streamscope_core::web::audit::WebProviderResponse>>,
    /// For fetch operations: blob hashes/MIMEs into audit_media_blobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub fetch_content_summary: Option<sqlx::types::Json<serde_json::Value>>,
    /// Per-rule diff payload (same shape the LLM/MCP rows carry).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
}

/// Row family discriminated by `kind`. UI consumers branch on `row.kind`
/// rather than sniffing fields. All variants are boxed because
/// `AuditLogEntry` is wide (~1.5 KB) and the size mismatch with the MCP /
/// web shapes would otherwise blow up the heap allocation per row.
#[derive(Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditLogRow {
    Llm {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<AuditLogEntry>,
    },
    Mcp {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<McpAuditLogEntry>,
    },
    Web {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<WebAuditLogEntry>,
    },
    A2a {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<A2aAuditLogEntry>,
    },
}

/// A2A-side audit row exposed at `/audit?kind=a2a`. Per-call shape with the
/// joined agent slug/name + user email so the audit UI renders rows without
/// a fan-out fetch. Operators correlate calls in the same A2A conversation
/// by the raw `a2a_context_id` (and one unit of remote work by `a2a_task_id`).
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct A2aAuditLogEntry {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub app_id: Option<String>,
    /// Hashed session id from `gateway_audit.session_id` — cross-protocol
    /// correlation with LLM/MCP rows sharing the client's `X-Session-Id`.
    pub session_id: Option<Uuid>,
    pub agent_id: Uuid,
    pub agent_slug: Option<String>,
    pub agent_name: Option<String>,
    /// A2A operation (`SendMessage`, `GetTask`, …).
    pub method: String,
    /// Raw wire `contextId` — the per-protocol conversation correlator.
    pub a2a_context_id: Option<String>,
    /// Raw wire `taskId`.
    pub a2a_task_id: Option<String>,
    /// Last observed `TASK_STATE_*` for the call.
    pub task_state: Option<String>,
    /// HTTP status from `gateway_audit.status_code` (SMALLINT → `i16`).
    pub status_code: Option<i16>,
    /// Gateway-level error class shared with the LLM/MCP rows (`upstream`,
    /// `rpc_error`, `cancelled`, …) — what the error dashboards aggregate on.
    pub error_category: Option<String>,
    /// Why the call failed, in prose. On a streamed call this is where a
    /// mid-stream break, a malformed event, or the byte cap is recorded.
    pub error_detail: Option<String>,
    /// JSON-RPC `-32xxx` code from `a2a_audit.error_code` (INT → `i32`).
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub latency_total_ms: Option<i64>,
    pub upstream_latency_ms: i64,
    pub request_bytes: Option<i32>,
    pub response_bytes: Option<i32>,
    /// Negotiated A2A dialect (`"1.0"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub protocol_version: Option<String>,
    /// Typed audit badges — same `AuditBadge` enum as LLM/MCP rows.
    #[schema(value_type = Vec<streamscope_core::audit::AuditBadge>)]
    pub badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
    /// What the policy engine and the inline guardrail did to this call.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<A2aTransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<A2aTransformDiff>>,
    /// JSON-RPC `params` payload as the client sent it (polymorphic per
    /// method — `SendMessage` carries the message envelope, task ops the id).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub params: Option<sqlx::types::Json<serde_json::Value>>,
    /// JSON-RPC `result` payload from the agent (Task | Message | card —
    /// polymorphic per method). NULL on error replies.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub result: Option<sqlx::types::Json<serde_json::Value>>,
    /// Streaming calls: accumulated `StreamResponse` envelopes. NULL for
    /// non-streaming methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    #[schema(value_type = Option<Object>)]
    pub stream_events: Option<sqlx::types::Json<serde_json::Value>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/audit",
    tag = "Audit",
    params(AuditQuery),
    responses(
        (status = 200, description = "Paginated audit log entries (kind-discriminated)", body = OffsetPage<AuditLogRow>),
        (status = 400, description = "`start` is not before `end`, a search term under 3 characters, or a `kind=all` page is too deep", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_audit_logs(
    mut db: TenantConn,
    Query(query): Query<AuditQuery>,
) -> Result<Json<OffsetPage<AuditLogRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    super::check_search(query.search.as_deref())?;
    let limit = query.limit.unwrap_or(AUDIT_DEFAULT_LIMIT).clamp(1, crate::settings::admin_settings().audit_max_limit.max(1));
    let offset = crate::routes::resolve_offset(query.offset);
    let scope = query.console_scope();
    list_audit_rows(db.conn(), &query, &scope, limit, offset).await.map(Json)
}
// ---------------------------------------------------------------------------
// Trace + Session Endpoints
// ---------------------------------------------------------------------------

/// Response for a single turn trace.
#[derive(Serialize, ToSchema)]
pub struct TraceResponse {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub session_id: Option<Uuid>,
    pub turn_number: i32,
    pub parent_request_id: Option<Uuid>,
    pub is_baseline: bool,
    pub message_count: i32,
    /// Client-sent tools array, resolved from `tool_definitions` via the
    /// `tools_available_hash` reference on the row. `None` when the request
    /// had no tools (hash is NULL).
    #[schema(value_type = Option<Object>)]
    pub request_tools: Option<serde_json::Value>,
    /// Post-policy effective tools array, resolved from `tool_definitions`
    /// via `tools_effective_hash`. Set only when policy modified the tools
    /// array (otherwise equals `request_tools` and is omitted to avoid noise).
    #[schema(value_type = Option<Object>)]
    pub tools_effective: Option<serde_json::Value>,
    /// The request's sampling and wire parameters as the client sent them, in its own protocol's names.
    #[schema(value_type = Option<Object>)]
    pub request_params: Option<serde_json::Value>,
    pub system_prompt: Option<String>,
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
    pub response_content: Option<String>,
    /// The tool calls the answer carried, in the client protocol's shape; `null` when it carried none.
    #[schema(value_type = Option<Object>)]
    pub response_tool_calls: Option<serde_json::Value>,
    pub request_size_bytes: Option<i32>,
    pub response_size_bytes: Option<i32>,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<ConversationEvent>>,
    /// Media metadata from llm_audit (only for media turns)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_meta: Option<TraceMediaMeta>,
    /// Canonical request-level parameter projection (sampling, tools catalog,
    /// response format, metadata). Rendered as the per-turn side panel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<streamscope_core::api::domain_request::DomainRequestMeta>,
    /// HTTP status code from `gateway_audit.status_code`. Surfaced on the trace
    /// so error rows that never produced a `conversation_turns` entry (pre-
    /// pipeline auth / capability / transform failures) still render a useful
    /// "View Content" panel instead of a blank "no data" message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i16>,
    /// Error category from `gateway_audit.error_category` (e.g. `auth`,
    /// `upstream`, `timeout`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    /// Full error detail string from `gateway_audit.error_detail` (truncated to
    /// 500 chars at capture).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    /// Effective model the request resolved to (echo of `llm_audit.model_used`).
    /// Populated on the error-only fallback path so the UI can identify the
    /// request without needing to re-read the row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_used: Option<String>,
    /// Provider name (`llm_audit.provider`). Same rationale as `model_used`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// Full media metadata for a trace (loaded from gateway_audit + llm_audit for media turns).
/// The canonical `DomainMediaCall` carries endpoint / model / input-output
/// blocks / params / job — plus envelope fields (provider, latency, cost) that
/// live on the audit row and aren't part of the call itself.
///
/// `media_call` is `Option` because a media audit row can have been written
/// without one — e.g., a pre-request error captured by `send_media_error_audit`
/// on a malformed path. Readers MUST handle `None` rather than assume the field
/// is populated.
#[derive(Serialize, ToSchema)]
pub struct TraceMediaMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<streamscope_core::api::domain_request::DomainMediaCall>)]
    pub media_call: Option<streamscope_core::api::domain_request::DomainMediaCall>,
    pub model_requested: Option<String>,
    pub model_used: Option<String>,
    pub provider: Option<String>,
    pub latency_ms: Option<i64>,
    /// What the call cost, and in which currency. A single audit row, so the
    /// currency is whatever the ledger said when it was written — never the
    /// tenant's current setting, which cannot restate it.
    pub spend: Option<SpendTotal>,
}

/// Get a single turn trace by request_id — resolves message hashes to full content.
/// List the web calls dispatched as children of a single
/// orchestrating LLM `gateway_audit` row. Returns rows where
/// `web_audit.parent_request_id = {request_id}` AND the tenant
/// matches via `TenantConn` (RLS-scoped). Empty `items` when the LLM row
/// didn't trigger any substitution dispatch.
#[utoipa::path(
    get,
    path = "/api/v1/admin/audit/{request_id}/web",
    tag = "Audit",
    params(
        ("request_id" = Uuid, Path, description = "Orchestrating LLM request_id"),
        PageQuery,
    ),
    responses(
        (status = 200, description = "Paginated web child calls", body = OffsetPage<WebAuditLogEntry>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_web_calls_for_request(
    mut db: TenantConn,
    Path(request_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WebAuditLogEntry>>, ApiError> {
    let limit = page
        .limit
        .unwrap_or(AUDIT_DEFAULT_LIMIT)
        .clamp(1, crate::settings::admin_settings().audit_max_limit.max(1));
    let offset = crate::routes::resolve_offset(page.offset);

    // Reuse the list helper with `parent_request_id_filter` set so we get
    // identical row shape + ordering. No filter of its own: the parent filter
    // narrows to a single LLM turn's children, tenant-wide.
    let query = AuditQuery::default();
    let rows =
        list_audit_logs_web(db.conn(), &query, &AuditScope::tenant(None, None), limit, offset, Some(request_id)).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/traces/{request_id}",
    tag = "Audit",
    params(
        ("request_id" = Uuid, Path, description = "Request ID of the turn to trace"),
        TraceQuery,
    ),
    responses(
        (status = 200, description = "Turn trace with resolved messages", body = TraceResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Turn not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_trace(
    mut db: TenantConn,
    Path(request_id): Path<Uuid>,
    Query(query): Query<TraceQuery>,
) -> Result<Json<TraceResponse>, ApiError> {
    let format = query.format.unwrap_or(ResponseFormat::Raw);
    let tenant_id = db.tenant_uuid();
    get_trace_impl(db.conn(), tenant_id, request_id, format).await
}

/// The turn answering the call turn (`trace::next_turn`) and the hashes of
/// the messages it added (`trace::answer_hashes`) — `None` when the session
/// has no turn after it.
async fn answering_turn(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    session_id: Uuid,
    turn_number: i32,
    call_hashes: &[String],
) -> Result<Option<(trace::NextTurn, Vec<String>)>, ApiError> {
    let next = trace::next_turn(conn, request_id, timestamp, session_id, turn_number)
        .await
        .map_err(|e| {
            tracing::error!("get_trace next turn query: {e}");
            ApiError::internal("Failed to query next turn")
        })?;
    Ok(next.map(|mut n| {
        let hashes = trace::answer_hashes(n.sliced, n.hashes.take(), call_hashes);
        (n, hashes)
    }))
}

/// Core trace builder. Tenant scoping is the connection's RLS, and every
/// content read binds `tenant_id` too — it must be the connection's own tenant,
/// or those reads find nothing; per-user ownership is the caller's
/// responsibility — the admin handler is
/// tenant-RLS-scoped, the portal handler pre-gates with `assert_request_owned`.
pub async fn get_trace_impl(
    conn: &mut Scoped,
    tenant_id: Uuid,
    request_id: Uuid,
    format: ResponseFormat,
) -> Result<Json<TraceResponse>, ApiError> {
    let include_raw = format == ResponseFormat::ParsedRaw;

    // Media-turn details live on `llm_audit.media_call`; `conversation_turns`
    // only carries the event_type discriminator + shared chat/media envelope.
    let row = trace::turn(&mut *conn, request_id)
    .await
    .map_err(|e| {
        tracing::error!("get_trace query: {e}");
        ApiError::internal("Failed to query trace")
    })?;

    let Some(row) = row else {
        // No `conversation_turns` row. An A2A gateway call never writes one —
        // it lives in `a2a_audit`, not the chat-turn table — so before the
        // error fallback, project it through the SAME canonical `A2aCall` event
        // the session timeline renders. This is what lets the audit drawer reuse
        // one renderer for the call, on par with the LLM trace.
        if let Some(trace) = a2a_trace(&mut *conn, request_id, format_str_for(format)).await? {
            return Ok(trace);
        }
        // Otherwise this is normal for error audits that failed before the
        // request pipeline captured content (`error_record` path: auth /
        // capability / transform failures), or when
        // `content_logging_enabled = false`. Fall back to whatever
        // `gateway_audit + llm_audit` carries so the UI can still render a
        // useful "View Content" panel (error_category, error_detail, status,
        // model, etc.) instead of a blank "no data" message.
        return error_fallback_trace(&mut *conn, request_id, format_str_for(format)).await;
    };

    let trace::TraceTurn {
        request_id: t_request_id,
        timestamp: t_timestamp,
        session_id: t_session_id,
        turn_number: t_turn_number,
        parent_request_id: t_parent_request_id,
        is_baseline: t_is_baseline,
        message_hashes: t_message_hashes,
        message_count: t_message_count,
        tools_available_hash: t_tools_available_hash,
        tools_effective_hash: t_tools_effective_hash,
        request_params: t_request_params,
        system_prompt_hash: t_system_prompt_hash,
        transform_diff: t_transform_diff,
        response_content: t_response_content,
        response_tool_calls: t_response_tool_calls,
        request_size_bytes: t_request_size_bytes,
        response_size_bytes: t_response_size_bytes,
        event_type: t_event_type,
        api_version: t_api_version,
    } = row;
    let t_message_hashes = t_message_hashes.unwrap_or_default();
    let t_transform_diff = t_transform_diff.transform_diff(t_request_id);
    let t_system_prompt: Option<String> = match t_system_prompt_hash {
        Some(h) => crate::content_store::system_prompts::get_many(&mut *conn, tenant_id, std::slice::from_ref(&h))
            .await
            .map_err(|e| {
                tracing::error!("get_trace system prompt: {e}");
                ApiError::internal("Failed to query trace")
            })?
            .remove(&h),
        None => None,
    };
    // Resolve both tool-set hashes in one read.
    let (t_request_tools, t_tools_effective): (Option<serde_json::Value>, Option<serde_json::Value>) =
        resolve_tool_definitions(
            &mut *conn,
            tenant_id,
            t_tools_available_hash.as_deref(),
            t_tools_effective_hash.as_deref(),
        )
        .await?;

    let is_media = t_event_type == "media";
    let wants_events = format == ResponseFormat::Parsed || format == ResponseFormat::ParsedRaw;

    // The turn answering this one (where its calls' results arrive) is read
    // before any message when the turn's response carries a call and its own
    // protocol parses, so both turns' messages come back in one read.
    // Otherwise — or when that early read fails — it is read below, only when
    // the turn's answer renders a call, and only that later read fails the
    // trace.
    let response_calls = t_response_tool_calls
        .as_ref()
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    // The turn's protocol, parsed once: it gates the early read below and
    // drives the render.
    let t_protocol = crate::conversation::stored_protocol(&t_api_version, t_request_id);
    let mut answer: Option<Option<(trace::NextTurn, Vec<String>)>> = None;
    if wants_events
        && !is_media
        && response_calls
        && t_protocol.is_some()
        && let Some(session_id) = t_session_id
    {
        answer =
            answering_turn(&mut *conn, t_request_id, t_timestamp, session_id, t_turn_number, &t_message_hashes)
                .await
                .ok();
    }
    let answer_read = answer.is_some();

    // The turn's history, in its own order — a hash it names twice renders
    // twice, one the tenant holds no message for renders nothing.
    let joined: Vec<String>;
    let wanted: &[String] = match &answer {
        Some(Some((_, answer_hashes))) => {
            joined = t_message_hashes.iter().chain(answer_hashes).cloned().collect();
            &joined
        }
        _ => &t_message_hashes,
    };
    let bodies = crate::content_store::messages::get_many(&mut *conn, tenant_id, wanted)
        .await
        .map_err(|e| {
            tracing::error!("get_trace resolve messages: {e}");
            ApiError::internal("Failed to resolve trace messages")
        })?;
    let messages: Vec<serde_json::Value> =
        t_message_hashes.iter().filter_map(|h| bodies.get(h).cloned()).collect();

    let format_str = format_str_for(format);

    // For media turns, load the canonical media_call + envelope metadata.
    // `media_call` is nullable (pre-request error records have no body to
    // capture into a canonical shape) so the column decodes as Option.
    let media_meta = if is_media {
        let arow: Option<trace::MediaRow> = trace::media_meta(&mut *conn, request_id, t_timestamp)
        .await
        .map_err(|e| {
            tracing::error!("get_trace media query: {e}");
            ApiError::internal("Failed to query trace media")
        })?;
        arow.map(|r| TraceMediaMeta {
            media_call: r.0.decode("media_call", request_id),
            model_requested: r.1,
            model_used: r.2,
            provider: r.3,
            latency_ms: r.4,
            // One row, so one currency — a straddle is impossible here and the
            // count is 1 whenever the row carries a code we can name.
            spend: spend_total(1, r.6, r.5.unwrap_or(0.0), Default::default()),
        })
    } else {
        None
    };

    // Build parsed events for parsed/parsed_raw modes
    let mut trace_params: Option<streamscope_core::api::domain_request::DomainRequestMeta> = None;
    let events = if wants_events {
        let mut evts: Vec<ConversationEvent> = Vec::new();

        // A chat turn's protocol is the one stamped on the turn, or why it
        // does not parse: the marker then says so, as the session view does.
        // Its models are the audit row's, absent with it.
        let (chat_protocol, model_requested, model_used, carried) = if is_media {
            (None, None, None, crate::conversation::CarriedMedia::default())
        } else {
            let meta = trace::llm_meta(&mut *conn, request_id, t_timestamp)
                .await
                .map_err(|e| {
                    tracing::error!("get_trace llm_audit meta: {e}");
                    ApiError::internal("Failed to read audit log")
                })?
                .unwrap_or_default();
            // The stored blobs this request carried itself: a blob its history
            // only names keeps no owner.
            let carried = crate::conversation::CarriedMedia::of(
                meta.chat_media_summary
                    .decode::<Vec<streamscope_core::audit::ChatMediaSummaryEntry>>("chat_media_summary", t_request_id)
                    .as_deref()
                    .unwrap_or_default(),
            );
            let protocol = t_protocol.ok_or_else(|| format!("unsupported protocol {t_api_version:?}"));
            (Some(protocol), meta.model_requested, meta.model_used, carried)
        };

        if is_media {
            if let Some(m) = media_meta.as_ref()
                && let Some(call) = m.media_call.as_ref()
            {
                evts.push(ConversationEvent::MediaApiCall {
                    media_call: Box::new(call.clone()),
                    turn: t_turn_number,
                    is_new: true,
                    metadata: Some(TurnMetadata {
                        request_id: Some(t_request_id),
                        tokens_in: 0,
                        tokens_out: 0,
                        cache_creation_tokens: None,
                        cache_read_tokens: None,
                        reasoning_tokens: None,
                        latency_ms: m.latency_ms.unwrap_or(0),
                        ttft_ms: m.latency_ms.unwrap_or(0),
                        spend: m.spend,
                        finish_reason: "stop".to_string(),
                        badges: Vec::new(),
                        transform_diff: None,
                        error_category: None,
                        status_code: None,
                        error_detail: None,
                        model_used: m.model_used.clone(),
                        model_requested: m.model_requested.clone(),
                        provider: m.provider.clone(),
                        upstream_server_name: None,
                        workspace_name: None,
                    }),
                });
            }
        } else if let Some(Ok(protocol)) = chat_protocol {
            // Chat turn — emit events via canonical domain normalization.
            let messages_arr = serde_json::Value::Array(messages.clone());
            let model_str: String = model_requested
                .or(model_used)
                .unwrap_or_default();
            let turn_row = TurnRow {
                turn_number: t_turn_number,
                protocol,
                system_prompt: t_system_prompt.as_deref(),
                messages_json: &messages_arr,
                request_tools: t_request_tools.as_ref(),
                tools_available_hash: t_tools_available_hash.as_deref(),
                tools_effective_hash: t_tools_effective_hash.as_deref(),
                request_params: t_request_params.as_ref(),
                response_content: t_response_content.as_deref(),
                response_tool_calls: t_response_tool_calls.as_ref(),
                thinking: None,
                model: &model_str,
                metadata: None,
                include_raw,
                // Trace view renders the full request history for operator
                // inspection, not a dedup-filtered "new-this-turn" slice —
                // history events must report is_new: false.
                dedup_filtered: false,
                transform_diff: t_transform_diff.as_ref().map(|j| &j.0),
            };
            match build_events(&turn_row) {
                Ok(mut built) => {
                    carried.stamp(&mut built.events, t_request_id);
                    evts.extend(built.events);
                    trace_params = Some(built.params);
                }
                Err(e) => evts.push(unrendered_turn_marker(
                    t_turn_number,
                    e.to_string(),
                    None,
                    include_raw.then(|| messages_arr.clone()),
                )),
            }

            // A call is emitted in this turn's assistant response; its
            // tool_result arrives in the messages the answering turn added
            // (`trace::answer_laterals`: this turn's child when it extends
            // it, else the session's next turn). Fetch the answering turn, run
            // it through the same canonical `build_events` pipeline, and
            // append the result of each call emitted here, paired as the
            // /tools activity feed pairs them (`pair_results`).
            let has_calls = evts.iter().any(crate::conversation::takes_a_result);
            if has_calls
                && let Some(session_id) = t_session_id
            {
                let next = match answer.take() {
                    Some(read) => read,
                    None => {
                        answering_turn(&mut *conn, t_request_id, t_timestamp, session_id, t_turn_number, &t_message_hashes)
                            .await?
                    }
                };

                // An answering turn whose protocol does not parse pairs no
                // result.
                if let Some((
                    trace::NextTurn {
                        request_id: next_request_id,
                        turn_number: next_turn_number,
                        tools_available_hash: next_tools_available_hash,
                        request_params: next_request_params,
                        api_version: next_api_version,
                        model_requested: next_model_requested,
                        model_used: next_model_used,
                        ..
                    },
                    new_hashes,
                )) = next
                    && let Some(next_protocol) =
                        crate::conversation::stored_protocol(&next_api_version, next_request_id)
                {
                    // Hydrate the next turn's available-tools blob from the
                    // side table. Effective set is irrelevant for the
                    // next-turn tool_result reconciliation path.
                    let (next_request_tools, _next_tools_effective) = resolve_tool_definitions(
                        &mut *conn,
                        tenant_id,
                        next_tools_available_hash.as_deref(),
                        None,
                    )
                    .await?;
                    // `new_hashes`: the messages the client appended for the
                    // next turn (the tool_result blocks we want to pair).
                    // `dedup_filtered=true` then makes `build_events` mark
                    // them is_new=true. Read with this turn's history when the
                    // answering turn was read before it.
                    let late;
                    let next_bodies = if answer_read {
                        &bodies
                    } else {
                        late = crate::content_store::messages::get_many(&mut *conn, tenant_id, &new_hashes)
                            .await
                            .map_err(|e| {
                                tracing::error!("get_trace next turn messages: {e}");
                                ApiError::internal("Failed to resolve next turn messages")
                            })?;
                        &late
                    };
                    let next_messages_arr = serde_json::Value::Array(
                        new_hashes.iter().filter_map(|h| next_bodies.get(h).cloned()).collect(),
                    );
                    let next_model = next_model_requested
                        .or(next_model_used)
                        .unwrap_or_default();
                    let next_turn = TurnRow {
                        turn_number: next_turn_number,
                        protocol: next_protocol,
                        // Only its request is read: its ToolResult events and
                        // the calls it sends back.
                        system_prompt: None,
                        messages_json: &next_messages_arr,
                        request_tools: next_request_tools.as_ref(),
                        tools_available_hash: next_tools_available_hash.as_deref(),
                        // Effective hash on the next turn is irrelevant to
                        // the tool_result reconciliation path in this trace.
                        tools_effective_hash: None,
                        request_params: next_request_params.as_ref(),
                        response_content: None,
                        response_tool_calls: None,
                        thinking: None,
                        model: &next_model,
                        metadata: None,
                        include_raw,
                        dedup_filtered: true,
                        // Response-phase blocks on the next turn belong to
                        // its own tool calls, not this trace — skip.
                        transform_diff: None,
                    };
                    match build_events(&next_turn) {
                        Ok(b) => {
                            let paired = crate::conversation::pair_results(&evts, &b.events);
                            evts.extend(paired.into_iter().flatten());
                        }
                        Err(e) => {
                            tracing::warn!(
                                request_id = %request_id,
                                "get_trace: build_events failed for next turn: {e}"
                            );
                        }
                    }
                }
            }
        } else if let Some(Err(e)) = chat_protocol {
            evts.push(unrendered_turn_marker(
                t_turn_number,
                e,
                None,
                include_raw.then(|| serde_json::Value::Array(messages.clone())),
            ));
        }

        // Thread this request's server-side substitution web calls (joined by
        // `parent_request_id`) so the single-request trace renders the web
        // result + guardrail shield on the intercepted call, matching the
        // session view (the substitution loop persists no tool_result to anchor
        // to). Reuses the same placement + guardrail-correlation helpers.
        let web_rows = trace::substitution_web_calls(&mut *conn, request_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("get_trace web fetch: {e}");
            Vec::new()
        });
        if !web_rows.is_empty() {
            let mut gmap: std::collections::HashMap<String, Vec<streamscope_core::proxy::content::GuardrailStepDiff>> =
                std::collections::HashMap::new();
            if let Some(j) = &t_transform_diff
                && let Some(steps) = &j.0.guardrail_steps
            {
                for s in steps {
                    gmap.entry(s.tool_use_id.clone()).or_default().push(s.clone());
                }
            }
            evts = place_substitution_web_calls(evts, web_rows, &gmap);
        }
        Some(evts)
    } else {
        None
    };

    // Pull the row's error envelope so the trace view can show the error
    // banner even when a `conversation_turns` row exists (e.g. upstream 4xx /
    // 5xx that DID populate message_hashes).
    let (e_status, e_category, e_detail, e_model_used, e_provider) = trace::error_envelope(&mut *conn, request_id, t_timestamp)
    .await
    .map_err(|e| {
        tracing::error!("get_trace error envelope query: {e}");
        ApiError::internal("Failed to read audit error envelope")
    })?
    .unwrap_or((None, None, None, None, None));

    Ok(Json(TraceResponse {
        request_id: t_request_id,
        timestamp: t_timestamp,
        session_id: t_session_id,
        turn_number: t_turn_number,
        parent_request_id: t_parent_request_id,
        is_baseline: t_is_baseline,
        message_count: t_message_count,
        request_tools: t_request_tools,
        tools_effective: t_tools_effective,
        request_params: t_request_params,
        system_prompt: t_system_prompt,
        transform_diff: t_transform_diff,
        response_content: t_response_content,
        response_tool_calls: t_response_tool_calls,
        request_size_bytes: t_request_size_bytes,
        response_size_bytes: t_response_size_bytes,
        format: format_str.to_string(),
        events,
        media_meta,
        params: trace_params,
        status_code: e_status,
        error_category: e_category,
        error_detail: e_detail,
        model_used: e_model_used,
        provider: e_provider,
    }))
}

fn format_str_for(format: ResponseFormat) -> &'static str {
    match format {
        ResponseFormat::Parsed => "parsed",
        ResponseFormat::Raw => "raw",
        ResponseFormat::ParsedRaw => "parsed_raw",
    }
}

/// Trace response for an A2A gateway call. A2A rows have no `conversation_turns`
/// entry, so the LLM trace path never reaches them; this projects the one
/// `a2a_audit` row through the same `a2a_call_event` the session timeline uses,
/// so the audit drawer renders identical structured content (message / reply /
/// artifacts) through the shared `A2aCallEvent`. Returns `None` when the
/// request_id is not an A2A row, letting the caller fall through to the error
/// fallback.
async fn a2a_trace(
    conn: &mut Scoped,
    request_id: Uuid,
    format_str: &'static str,
) -> Result<Option<Json<TraceResponse>>, ApiError> {
    let row = trace::a2a_call(&mut *conn, request_id)
    .await
    .map_err(|e| {
        tracing::error!("a2a_trace query: {e}");
        ApiError::internal("Failed to query A2A trace")
    })?;

    let Some(row) = row else {
        return Ok(None);
    };

    let timestamp = row.timestamp;
    let status_code = row.status_code;
    let event = a2a_call_event(row, 0);

    Ok(Some(Json(TraceResponse {
        request_id,
        timestamp,
        session_id: None,
        turn_number: 0,
        parent_request_id: None,
        is_baseline: false,
        message_count: 0,
        request_tools: None,
        tools_effective: None,
        request_params: None,
        system_prompt: None,
        transform_diff: None,
        response_content: None,
        response_tool_calls: None,
        request_size_bytes: None,
        response_size_bytes: None,
        format: format_str.to_string(),
        events: Some(vec![event]),
        media_meta: None,
        params: None,
        status_code,
        error_category: None,
        error_detail: None,
        model_used: None,
        provider: None,
    })))
}

/// Fallback trace response built solely from `gateway_audit + llm_audit` for
/// rows that have no `conversation_turns` entry (typically `error_record`
/// audits emitted by `send_error_audit` for pre-pipeline failures). Returns a
/// minimal `TraceResponse` carrying the captured error envelope so the UI can
/// render the failure context instead of "no content data available". 404s
/// only when the audit row itself is missing.
async fn error_fallback_trace(
    conn: &mut Scoped,
    request_id: Uuid,
    format_str: &'static str,
) -> Result<Json<TraceResponse>, ApiError> {
    // Gate on an actual error envelope (4xx/5xx OR explicit error_category)
    // so the fallback ONLY kicks in for failed requests. Successful requests
    // that haven't yet had their `conversation_turns` row written
    // (`insert_audit_jsonb` lands before `bulk_insert_chat_turns` in
    // `edge_v2::writers`) continue to 404, preserving the "poll until 200" semantic
    // used by sessions/audit/cross-protocol E2E tests.
    let row: Option<trace::FallbackRow> = trace::error_fallback(conn, request_id)
    .await
    .map_err(|e| {
        tracing::error!("error_fallback_trace query: {e}");
        ApiError::internal("Failed to read audit error fallback")
    })?;

    let Some((timestamp, status_code, error_category, error_detail, model_used, provider)) = row else {
        return Err(ApiError::not_found("Audit trace not found", ApiErrorCode::AuditRecordNotFound));
    };

    Ok(Json(TraceResponse {
        request_id,
        timestamp,
        session_id: None,
        turn_number: 0,
        parent_request_id: None,
        // Pre-pipeline errors never produced a turn — `is_baseline` is the
        // "first turn in session" marker and has no meaning here. Default
        // `false` so consumers filtering on `is_baseline = true` don't pick
        // up error stubs.
        is_baseline: false,
        message_count: 0,
        request_tools: None,
        tools_effective: None,
        request_params: None,
        system_prompt: None,
        transform_diff: None,
        response_content: None,
        response_tool_calls: None,
        request_size_bytes: None,
        response_size_bytes: None,
        format: format_str.to_string(),
        events: Some(Vec::new()),
        media_meta: None,
        params: None,
        status_code,
        error_category,
        error_detail,
        model_used,
        provider,
    }))
}

/// Summary of a turn within a session timeline.
#[derive(Serialize, ToSchema)]
pub struct SessionTurnSummary {
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub turn_number: i32,
    pub parent_request_id: Option<Uuid>,
    pub is_baseline: bool,
    pub message_count: i32,
    pub response_content: Option<String>,
    /// The tool calls the turn's answer carried, in the client protocol's shape; `null` when none.
    #[schema(value_type = Option<Object>)]
    pub response_tool_calls: Option<serde_json::Value>,
    pub system_prompt: Option<String>,
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
    pub request_size_bytes: Option<i32>,
    pub response_size_bytes: Option<i32>,
    // Joined from gateway_audit + llm_audit
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub cache_creation_tokens: Option<i32>,
    pub cache_read_tokens: Option<i32>,
    pub reasoning_tokens: Option<i32>,
    /// What the turn cost, and in which currency — one audit row, so the
    /// currency is the one the ledger stamped when the row was written.
    pub spend: Option<SpendTotal>,
    pub finish_reason: Option<String>,
    pub latency_ttft_ms: Option<i64>,
    pub latency_total_ms: Option<i64>,
    pub model_used: Option<String>,
}

/// Get all turns in a session, ordered by turn_number.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sessions/{session_id}",
    tag = "Sessions",
    params(("session_id" = Uuid, Path, description = "Session ID"), PageQuery),
    responses(
        (status = 200, description = "Paginated session turns ordered by turn number", body = OffsetPage<SessionTurnSummary>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_session(
    mut db: TenantConn,
    Path(session_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<SessionTurnSummary>>, ApiError> {
    let (limit, offset) = page.resolve();
    let tenant_id = db.tenant_uuid();
    let rows = timeline::session_turns(db.conn(), session_id, limit + 1, offset)
        .await
        .map_err(|e| {
            tracing::error!("get_session query: {e}");
            ApiError::internal("Failed to query session")
        })?;
    let prompt_hashes: Vec<String> =
        rows.iter().filter_map(|(h, _)| h.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let prompts = crate::content_store::system_prompts::get_many(db.conn(), tenant_id, &prompt_hashes)
        .await
        .map_err(|e| {
            tracing::error!("get_session system prompts: {e}");
            ApiError::internal("Failed to query session")
        })?;
    let summaries: Vec<SessionTurnSummary> = rows
        .into_iter()
        .map(|(hash, mut summary)| {
            summary.system_prompt = hash.and_then(|h| prompts.get(&h).cloned());
            summary
        })
        .collect();

    Ok(Json(OffsetPage::from_overfetched(summaries, limit, offset)))
}

/// Response for GET /sessions/{id}/linked — returns parent + children.
#[derive(Serialize, ToSchema)]
pub struct LinkedSessions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parent: Option<SessionSummary>,
    pub(crate) children: Vec<SessionSummary>,
}

/// Get linked sessions (parent + children) for a given session.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sessions/{session_id}/linked",
    tag = "Sessions",
    params(("session_id" = Uuid, Path, description = "Session ID")),
    responses(
        (status = 200, description = "Parent and child sessions", body = LinkedSessions),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_session_linked(
    mut db: TenantConn,
    Path(session_id): Path<Uuid>,
) -> Result<Json<LinkedSessions>, ApiError> {
    linked_sessions_tenant_wide(db.conn(), session_id).await.map(Json)
}

/// How a session sits in a cross-session relation.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionLinkage {
    HasChildren,
    HasParent,
    Unlinked,
}

/// The order of a session list. A text search pages through its matches by
/// `updated_at`, so under a search term only `newest` and `oldest` exist.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionSort {
    /// Most recently updated first.
    #[default]
    Newest,
    /// Least recently updated first.
    Oldest,
    /// Major alerts, then minor, then the rest; most recent first within each.
    Alerts,
}

impl SessionSort {
    /// Refuse an order a search cannot serve: `alerts` would need every match
    /// read before the first row is known.
    pub fn check_with_search(sort: Option<Self>, search: Option<&str>) -> Result<(), ApiError> {
        if sort == Some(Self::Alerts) && search_text(search).is_some() {
            return Err(ApiError::bad_request(
                "sort=alerts cannot be combined with a search term; filter by alert level instead",
            )
            .code(super::ApiErrorCode::SortUnsupportedWithSearch));
        }
        Ok(())
    }
}

#[derive(Deserialize, IntoParams, Default)]
#[into_params(parameter_in = Query)]
pub struct SessionListQuery {
    // `user_id`, `workspace_ids` and `include_keyless` are private: they are the
    // console's HTTP input, read only by `console_scope`. Every other caller
    // passes its own `AuditScope`, and the store reads whose rows from that alone.
    user_id: Option<Uuid>,
    pub model: Option<String>,
    pub search: Option<String>,
    /// Inclusive window start (RFC3339).
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Default `newest`. `alerts` is refused with a `search` term
    /// (`sort_unsupported_with_search`): filter on `alert_level` instead.
    pub sort: Option<SessionSort>,
    /// Sessions whose alert is exactly this level.
    pub alert_level: Option<streamscope_core::audit::AlertLevel>,
    /// Filter sessions updated after this timestamp (RFC3339).
    pub updated_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Filter sessions updated before this timestamp (RFC3339).
    pub updated_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Filter by app_id (agent type, e.g. "opencode", "claude-code").
    pub app_id: Option<String>,
    /// Exclude sessions from this user email (exact match). Caller-supplied;
    /// no default exclusion is applied server-side.
    pub exclude_user: Option<String>,
    /// Filter by user email (ILIKE match).
    pub user_email: Option<String>,
    /// Filter by linkage.
    pub linked: Option<SessionLinkage>,
    /// Filter by parent_session_id (show children of a specific parent).
    pub parent_session_id: Option<Uuid>,
    /// Comma-separated workspace ids to include (UUIDs) — sessions whose own
    /// `workspace_id` is one of these, the same attribution shown by the row's
    /// workspace badge. Omit for all workspaces.
    #[param(value_type = Option<String>)]
    workspace_ids: Option<WorkspaceIds>,
    /// With `workspace_ids`: also include sessions carrying no workspace
    /// attribution at all. Ignored when `workspace_ids` is omitted.
    include_keyless: Option<bool>,
}

impl SessionListQuery {
    /// The console's scope: the `user_id`, `workspace_ids` and
    /// `include_keyless` it was sent, over the whole tenant otherwise.
    fn console_scope(&self) -> AuditScope {
        AuditScope::tenant(self.user_id, self.workspace_ids.clone())
            .including_keyless(self.include_keyless == Some(true))
    }
}

/// Session summary for list view.
// Decoded only inside the session store's row type, which fills `spend`.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub turn_count: i64,
    pub total_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cache_creation_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cache_read_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_reasoning_tokens: Option<i64>,
    /// What the session's turns cost, in the accounting currency they were
    /// booked in. `null` when no single figure can be stated: the turns span
    /// a change of the accounting currency.
    #[sqlx(skip)]
    pub spend: Option<SpendTotal>,
    pub first_timestamp: chrono::DateTime<chrono::Utc>,
    pub last_timestamp: chrono::DateTime<chrono::Utc>,
    pub last_latency_ms: Option<i64>,
    pub model_requested: Option<String>,
    pub model_used: Option<String>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_expert_axis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_user_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_spawn_turn: Option<i32>,
    /// Tool-call id of the spawn call in the parent this session was spawned from
    /// (a CHILD only). The UI anchors the child card to the composite
    /// `(linkage_spawn_turn, linkage_spawn_tool_call_id)` on the parent's stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_spawn_tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
}

/// List recent sessions from the materialized `sessions` table.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sessions",
    tag = "Sessions",
    params(SessionListQuery),
    responses(
        (status = 200, description = "Paginated session summaries", body = OffsetPage<SessionSummary>),
        (status = 400, description = "`start` is not before `end`, a search term under 3 characters, or `sort=alerts` with a search term", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_sessions(
    mut db: TenantConn,
    Query(query): Query<SessionListQuery>,
) -> Result<Json<OffsetPage<SessionSummary>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    super::check_search(query.search.as_deref())?;
    SessionSort::check_with_search(query.sort, query.search.as_deref())?;
    let limit = query.limit.unwrap_or(SESSIONS_DEFAULT_LIMIT).clamp(1, crate::settings::admin_settings().sessions_max_limit().max(1));
    let offset = crate::routes::resolve_offset(query.offset);
    // Overfetch limit+1 so `has_more` is cheap (no COUNT on partitioned tables).
    // Pass the already-resolved limit+1 through — impl trusts the caller's limit
    // verbatim rather than re-clamping, which would strip the +1 at the
    // max_limit boundary and hide `has_more` for the last page.
    let mut overfetched = query;
    overfetched.limit = Some(limit + 1);
    overfetched.offset = Some(offset);
    let scope = overfetched.console_scope();

    let found = list_sessions_impl(db.conn(), overfetched, &scope).await
        .map_err(|e| {
            tracing::error!("list_sessions: {e}");
            ApiError::internal("Failed to list sessions")
        })?;

    Ok(Json(OffsetPage::from_overfetched(found.rows, limit, offset).with_scan_cut(found.scan_cut)))
}


// ---------------------------------------------------------------------------
// Normalized Conversation Endpoint
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default, Clone, Copy, PartialEq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    #[default]
    Parsed,
    Raw,
    ParsedRaw,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ConversationQuery {
    pub format: Option<ResponseFormat>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TraceQuery {
    pub format: Option<ResponseFormat>,
}

#[derive(Serialize, ToSchema)]
pub struct ConversationSummary {
    pub total_turns: usize,
    pub total_tokens: i64,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cache_creation_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_cache_read_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_reasoning_tokens: Option<i64>,
    /// What the conversation cost, and in which currency. `null` when its
    /// turns straddle a change of the tenant's accounting currency — they are
    /// then stated in different denominations and no single figure states them.
    pub spend: Option<SpendTotal>,
    pub duration_ms: i64,
}

#[derive(Serialize, ToSchema)]
pub struct RawTurn {
    /// The turn's request — what a later turn's `parent_request_id` names.
    pub request_id: Uuid,
    pub turn: i32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The messages this turn added, each in the client protocol's wire shape —
    /// its whole history when `whole_history`.
    #[schema(value_type = Vec<Object>)]
    pub messages: Vec<serde_json::Value>,
    /// `messages` is the turn's whole history: the session's first turn, a
    /// turn that starts a new baseline, or one whose parent is not a turn
    /// listed before it (unknown, not recorded, or expired).
    pub whole_history: bool,
    /// The turn this one continues — its parent, which need not be the turn
    /// just before it in the list. When `whole_history` is false, the turn's whole
    /// history is the parent's first `added_from` messages followed by
    /// `messages`, up to what the client injects and withdraws between turns: a
    /// repeated message may differ from the parent's copy in a
    /// `<system-reminder>` or a cache breakpoint. The turn's trace holds its
    /// history exactly as sent.
    pub parent_request_id: Option<Uuid>,
    /// How many leading messages of this turn's history its parent carried.
    pub added_from: i32,
    pub response_content: Option<String>,
    /// The tool calls the answer carried, in the client protocol's shape; `null` when none.
    #[schema(value_type = Option<Object>)]
    pub response_tool_calls: Option<serde_json::Value>,
    pub system_prompt: Option<String>,
    #[schema(value_type = Option<streamscope_core::proxy::content::TransformDiff>)]
    pub transform_diff: Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TurnMetadata>,
}

#[derive(Serialize, ToSchema)]
pub struct ConversationResponse {
    pub session_id: Uuid,
    pub model: String,
    pub user_email: Option<String>,
    pub summary: ConversationSummary,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<ConversationEvent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_turns: Option<Vec<RawTurn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_expert_axis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_spawn_turn: Option<i32>,
    /// This session's own spawn anchor as a CHILD — the tool-call id in its parent.
    /// Present only when a spawn call was confirmed; the parent's stream anchors the
    /// child card on `(linkage_spawn_turn, linkage_spawn_tool_call_id)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linkage_spawn_tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    /// Forwarded end-client identity for the whole session, present only for Inline AI
    /// traffic where a trusted inline key relayed it (`X-Client-IP` /
    /// `X-Authenticated-User` / `X-Authenticated-Groups`) — gateway-asserted, NOT
    /// authenticated here (distinct from `user_email`, the internal account).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_user: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub end_user_groups: Vec<String>,
    /// Canonical request-level parameters per turn. Keyed by turn number.
    pub turn_params: Vec<TurnParams>,
    /// Subagent spawn points detected in THIS session's own stream (the parent
    /// side): each `Agent`/`Task`-style tool call, with the turn, id and a prompt
    /// preview. Computed on read from the built events. The cluster judge confirms
    /// a child↔spawn link from it, and the UI anchors child cards + content-matches
    /// header-linked children that carry no stored anchor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected_spawn_points: Vec<crate::conversation::DetectedSpawnPoint>,
}

/// `DomainRequestMeta` tagged with its turn number so the UI can attach the
/// "Request parameters" / "Tools available" side panel to the matching turn.
#[derive(Serialize, ToSchema)]
pub struct TurnParams {
    pub turn: i32,
    pub params: streamscope_core::api::domain_request::DomainRequestMeta,
}

/// Extract `<think>...</think>` blocks from model output.
/// Returns (thinking_content, clean_text).
pub(crate) fn extract_thinking(text: &str) -> (Option<String>, String) {
    if text.is_empty() {
        return (None, String::new());
    }

    let mut thinking: Option<String> = None;
    let mut remaining = text.to_string();

    // Try both tag variants: <thinking>...</thinking> (proxy format) and <think>...</think> (model native)
    for (open_tag, close_tag) in [("<thinking>", "</thinking>"), ("<think>", "</think>")] {
        // Case 1: <tag>content</tag>answer
        // Use rfind for the close tag to capture ALL reasoning including leaked
        // content between multiple close tags (e.g. <think>A</think>B</think>C)
        if let Some(start) = remaining.find(open_tag)
            && let Some(end) = remaining.rfind(close_tag)
        {
            let think_start = start + open_tag.len();
            if end >= think_start {
                let thought = remaining[think_start..end].trim().to_string();
                let before = remaining[..start].trim().to_string();
                let after = remaining[end + close_tag.len()..].trim().to_string();
                remaining = if before.is_empty() {
                    after
                } else {
                    format!("{before} {after}")
                };
                if !thought.is_empty() {
                    thinking = Some(thought);
                }
                break;
            }
        }

        // Case 2: </tag> without opening tag (LFM 2.5 pattern)
        if let Some(end_idx) = remaining.rfind(close_tag) {
            let thought = remaining[..end_idx].trim().to_string();
            let after = remaining[end_idx + close_tag.len()..].trim().to_string();
            if !after.is_empty() {
                if !thought.is_empty() {
                    thinking = Some(thought);
                }
                remaining = after;
                break;
            }
            // Nothing after close tag — treat the whole thing as content
            if !thought.is_empty() {
                remaining = thought;
                break;
            }
        }
    }

    // Clean any remaining stray close tags from model output in the content
    for tag in ["</thinking>", "</think>", "<thinking>", "<think>"] {
        remaining = remaining.replace(tag, "");
    }
    let remaining = remaining.trim().to_string();

    (thinking, remaining)
}

/// Stable signature of an assistant turn's captured response — concatenated
/// `response_content` (post `extract_thinking`, whitespace-normalised) plus
/// the sorted list of `tool_use` ids from `response_tool_calls`. The session
/// view stamps each turn's signature so the next turn's request-history echo
/// of the same response can be recognised and skipped instead of rendered
/// twice. Returns `None` for empty captures (no text, no tool_use ids).
pub(crate) fn captured_response_signature(
    response_content: Option<&str>,
    response_tool_calls: Option<&serde_json::Value>,
) -> Option<String> {
    use sha2::{Digest, Sha256};
    let text = response_content
        .map(|s| {
            let (_, c) = extract_thinking(s);
            c.split_whitespace().collect::<Vec<_>>().join(" ")
        })
        .unwrap_or_default();
    let mut ids: Vec<String> = response_tool_calls
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|tc| tc.get("id").and_then(|i| i.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if text.is_empty() && ids.is_empty() {
        return None;
    }
    ids.sort();
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher.update(b"\0");
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
    }
    Some(hex::encode(hasher.finalize()))
}

/// Matching signature for an assistant message present in a turn's request
/// history (`messages_json[i]`). Handles all four inbound shapes by extracting
/// text from `content` (string or array of `text`/`output_text` blocks) and
/// tool_use ids from either embedded `tool_use` blocks (Anthropic) or sibling
/// `tool_calls[]` entries (OpenAI Chat Completions). Returns `None` when the
/// message has no distinctive content.
pub(crate) fn history_assistant_signature(msg: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut text_parts: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();

    match msg.get("content") {
        Some(serde_json::Value::String(s)) => text_parts.push(s.clone()),
        Some(serde_json::Value::Array(arr)) => {
            for block in arr {
                let typ = block.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if typ == "text" || typ == "output_text" {
                    if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                        text_parts.push(t.to_string());
                    }
                } else if typ == "tool_use"
                    && let Some(id) = block.get("id").and_then(|i| i.as_str())
                {
                    ids.push(id.to_string());
                }
            }
        }
        _ => {}
    }
    if let Some(arr) = msg.get("tool_calls").and_then(|v| v.as_array()) {
        for tc in arr {
            if let Some(id) = tc.get("id").and_then(|i| i.as_str()) {
                ids.push(id.to_string());
            }
        }
    }
    let combined = text_parts.join("\n");
    let (_, clean) = extract_thinking(&combined);
    let normalized = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() && ids.is_empty() {
        return None;
    }
    ids.sort();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.update(b"\0");
    for id in &ids {
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
    }
    Some(hex::encode(hasher.finalize()))
}

/// Extract `<summary>...</summary>` block from model output (compaction marker).
fn extract_summary(text: &str) -> Option<String> {
    let start = text.find("<summary>")?;
    let end = text.rfind("</summary>")?;
    let inner = start + "<summary>".len();
    if end > inner {
        let s = text[inner..end].trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

/// Remove framework-injected volatile blocks from rendered text. Thin
/// alias over [`streamscope_core::proxy::content::strip_volatile_inline`]
/// — see that function's doc for the full list of recognized tags
/// (`<system-reminder>`, `<available-deferred-tools>`, `<session_context>`,
/// `<local-command-*>`, `<command-*>`). Kept as a named function so the
/// many event-builder call sites don't churn.
pub(crate) fn strip_system_reminders(text: &str) -> String {
    streamscope_core::proxy::content::strip_volatile_inline(text)
        .trim()
        .to_string()
}


/// No session carries this id, on any of the three sources that can know one.
///
/// Carried through `anyhow` so every caller of
/// [`get_session_conversation_impl`] — both HTTP planes and the agent — can
/// tell a genuine miss apart from a failure and answer 404 rather than 500.
/// Downcast it; never match on the message.
#[derive(Debug)]
pub struct SessionNotFound(pub Uuid);

impl std::fmt::Display for SessionNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session not found: {}", self.0)
    }
}

impl std::error::Error for SessionNotFound {}

impl SessionNotFound {
    /// Map a conversation-load failure onto its HTTP answer: 404 for a session
    /// that does not exist, 500 (logged) for anything that actually broke.
    pub(crate) fn into_api_error(err: anyhow::Error, context: &str) -> ApiError {
        if let Some(missing) = err.downcast_ref::<Self>() {
            return ApiError::not_found(missing.to_string(), ApiErrorCode::SessionNotFound);
        }
        tracing::error!("{context}: {err}");
        ApiError::internal("Failed to get session conversation")
    }
}

/// Get normalized conversation for a session — single endpoint, no N+1.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sessions/{session_id}/conversation",
    tag = "Sessions",
    params(
        ("session_id" = Uuid, Path, description = "Session ID"),
        ConversationQuery,
    ),
    responses(
        (status = 200, description = "Parsed conversation with events, summary, and metadata", body = ConversationResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "No session carries this id", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_session_conversation(
    State(_state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Path(session_id): Path<Uuid>,
    Query(query): Query<ConversationQuery>,
) -> Result<Json<ConversationResponse>, ApiError> {
    let format = query.format.unwrap_or(ResponseFormat::Parsed);
    let tenant_id = db.tenant_uuid();
    get_session_conversation_impl(db.conn(), tenant_id, session_id, format, &AuditScope::tenant(None, None)).await
        .map(Json)
        .map_err(|e| SessionNotFound::into_api_error(e, "get_session_conversation"))
}

/// The marker a chat turn renders as when its events cannot be built — its
/// stored payload or protocol did not parse (`error` says which) — in the
/// session view and the trace alike, carrying the raw history when asked for:
/// one such turn never fails either view.
fn unrendered_turn_marker(
    turn: i32,
    error: String,
    metadata: Option<TurnMetadata>,
    raw: Option<serde_json::Value>,
) -> ConversationEvent {
    tracing::warn!(turn, "turn not rendered: {error}");
    let content = format!("[corrupt turn {turn}: {error}]");
    ConversationEvent::Message {
        role: "assistant".to_string(),
        content,
        thinking: None,
        turn,
        is_new: true,
        is_from_history: false,
        metadata,
        raw,
        guardrails: Vec::new(),
    }
}

/// Core conversation logic — callable from both HTTP handler and agent code.
/// `linked` decides which linked parent the conversation may name
/// ([`AuditScope::linked_view`]): the caller's own scope on the portal, the
/// whole tenant otherwise. Every content read binds `tenant_id`, which must be
/// the connection's own tenant, or those reads find nothing.
pub async fn get_session_conversation_impl(
    conn: &mut Scoped,
    tenant_id: Uuid,
    session_id: Uuid,
    format: ResponseFormat,
    linked: &AuditScope,
) -> anyhow::Result<ConversationResponse> {
    let include_raw = format == ResponseFormat::ParsedRaw;

    // 1. Load all turns with audit data in a single query — each turn's
    //    history whole where it `reads_whole` (the first turn, a baseline, a
    //    turn whose parent is not a row before it), the added slice on every
    //    other.
    //    The raw format returns every turn's system prompt; the parsed ones
    //    read it only where the turn `opens_view`, the one place it renders.
    let rows = timeline::turns(&mut *conn, session_id, format == ResponseFormat::Raw)
    .await?;

    // Fetch session-level alert + linkage info + app_id (the latter feeds
    // post-process re-classification so rules with `app_filter` evaluate
    // identically to the proxy-time path).
    let session_row = sessions::conversation_session(&mut *conn, session_id, linked)
    // Propagated, not swallowed: absence of this row is one of the two signals
    // that decides 404 below, so a failed read must surface as the failure it is
    // rather than as a session that does not exist.
    .await?;

    // Having no LLM turn is NOT the same as not existing: an MCP-only or
    // A2A-only client that stamps a session id produces gateway audit rows and
    // no `conversation_turns` row at all. Those rows are collected further down
    // and render as a timeline of their own, so the emptiness of `rows` decides
    // nothing on its own — the materialized row does, and MCP/A2A ingest writes
    // one for exactly this case.
    //
    // Deliberately NOT a probe of `gateway_audit` by session id: that column
    // carries no index, so a miss would seq-scan every partition on an
    // attacker-supplied uuid. Nothing is lost by leaving it out — a session with
    // no materialized row appears in no listing, so it is unreachable except by
    // hand-typing its id.
    if rows.is_empty() && session_row.is_none() {
        return Err(SessionNotFound(session_id).into());
    }

    let sessions::ConversationSessionRow {
        alert_level,
        alert_expert_axis,
        alert_note,
        parent_session_id,
        linkage_confidence,
        linkage_spawn_turn,
        app_id: session_app_id,
        linkage_spawn_tool_call_id,
    } = session_row.unwrap_or_default();

    // 2. Collect all unique message hashes across all turns
    //    message_hashes is nullable (media turns have NULL). A baseline turn
    //    repeats history an earlier turn read, so the dedupe is a set.
    let mut seen: HashSet<&str> = HashSet::new();
    let turn_hashes_list: Vec<&[String]> =
        rows.iter().map(|row| row.message_hashes.as_deref().unwrap_or_default()).collect();
    let all_hashes: Vec<String> = turn_hashes_list
        .iter()
        .flat_map(|hashes| hashes.iter())
        .filter(|h| seen.insert(h.as_str()))
        .cloned()
        .collect();

    // 3. Batch-load all messages in ONE read
    let msg_map: HashMap<String, serde_json::Value> =
        crate::content_store::messages::get_many(&mut *conn, tenant_id, &all_hashes).await?;

    // 3b. Batch-load all referenced tool definitions in ONE query.
    // Tool blobs are the dominant repeated payload — fetching once across all
    // turns and zipping back by hash is the whole point of the dedup.
    //
    // Only `tools_available_hash` is consumed by the per-turn `TurnRow.request_tools`
    // hydration below. The `tools_effective_hash` blob is fetched lazily by
    // the UI via `/audit/tool-definitions/{hash}` when an operator expands a
    // `ToolsChanged{PolicyModified}` event banner — pre-loading it here
    // would waste a query in the common case where nobody clicks.
    let mut tool_hashes: Vec<String> = Vec::new();
    for row in &rows {
        if let Some(h) = &row.tools_available_hash
            && !tool_hashes.contains(h)
        {
            tool_hashes.push(h.clone());
        }
    }
    let tool_map: HashMap<String, serde_json::Value> =
        crate::content_store::tool_definitions::get_many(&mut *conn, tenant_id, &tool_hashes).await?;

    // 3c. The system prompts `turns` named — where a turn opens the view, or
    // on every turn in the raw format — in ONE read.
    let prompt_hashes: Vec<String> = rows
        .iter()
        .filter_map(|row| row.system_prompt_hash.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let prompt_map: HashMap<String, String> =
        crate::content_store::system_prompts::get_many(&mut *conn, tenant_id, &prompt_hashes).await?;
    let system_prompt_of =
        |row: &timeline::TimelineTurn| row.system_prompt_hash.as_ref().and_then(|h| prompt_map.get(h));

    // Media blobs are always served via the blob endpoint URL — no inline loading needed.

    // Compute summary data for all format modes
    let mut total_tokens: i64 = 0;
    let mut total_input_tokens: i64 = 0;
    let mut total_output_tokens: i64 = 0;
    let mut total_cache_creation_tokens: i64 = 0;
    let mut total_cache_read_tokens: i64 = 0;
    let mut total_reasoning_tokens: i64 = 0;
    let mut total_cost: f64 = 0.0;
    // Every distinct currency the turns were written in. More than one means
    // the conversation outlived a change of the tenant's accounting currency,
    // and its total states nothing.
    let mut cost_currencies: std::collections::BTreeSet<streamscope_core::pricing::Currency> =
        Default::default();
    // A turn that charged something under a currency this build cannot name is
    // the same case as two currencies: the total covers money it cannot label.
    // Tracked separately because such a turn adds to `total_cost` while adding
    // nothing to the set above, and the two must not be able to disagree.
    let mut cost_unstatable = false;
    let mut model = String::new();
    let mut user_email: Option<String> = None;
    let mut key_name: Option<String> = None;
    let mut key_prefix: Option<String> = None;
    let mut workspace_name: Option<String> = None;
    // Forwarded end-client identity — session-level (every turn on one inline key
    // shares it); take the first non-empty across turns.
    let mut client_ip: Option<String> = None;
    let mut end_user: Option<String> = None;
    let mut end_user_groups: Vec<String> = Vec::new();

    for row in &rows {
        let pt = row.prompt_tokens.unwrap_or(0) as i64;
        let ct = row.completion_tokens.unwrap_or(0) as i64;
        total_tokens += pt + ct;
        total_input_tokens += pt;
        total_output_tokens += ct;
        total_cache_creation_tokens += row.cache_creation_tokens.unwrap_or(0) as i64;
        total_cache_read_tokens += row.cache_read_tokens.unwrap_or(0) as i64;
        total_reasoning_tokens += row.reasoning_tokens.unwrap_or(0) as i64;
        let charge = row.cost.unwrap_or(0.0);
        total_cost += charge;
        match row
            .cost_currency
            .as_deref()
            .and_then(streamscope_core::pricing::Currency::parse)
        {
            Some(c) => {
                cost_currencies.insert(c);
            }
            // A turn with no audit row at all charged nothing and is simply
            // absent from the total; one that charged and cannot be labelled
            // is what makes the total unstatable.
            None if charge != 0.0 => cost_unstatable = true,
            None => {}
        }
        if model.is_empty()
            && let Some(m) = &row.model_used {
                model.clone_from(m);
            }
        if user_email.is_none() {
            user_email.clone_from(&row.user_email);
        }
        if key_name.is_none() {
            key_name.clone_from(&row.key_name);
            key_prefix.clone_from(&row.key_prefix);
        }
        if workspace_name.is_none() {
            workspace_name.clone_from(&row.workspace_name);
        }
        if client_ip.is_none() {
            client_ip.clone_from(&row.client_ip);
        }
        if end_user.is_none() {
            end_user.clone_from(&row.end_user);
        }
        if end_user_groups.is_empty() {
            end_user_groups = row.end_user_groups.clone().unwrap_or_default();
        }
    }

    let first_ts = rows
        .first()
        .map(|r| r.timestamp.timestamp_millis())
        .unwrap_or(0);
    // Zero for a session with no LLM turns — every field of the summary is
    // LLM-denominated, so an MCP/A2A-only timeline reports zeros throughout
    // rather than borrowing figures from a different measurement.
    let duration_ms = rows
        .last()
        .map(|last_row| {
            (last_row.timestamp.timestamp_millis() + last_row.latency_total_ms.unwrap_or(0)) - first_ts
        })
        .unwrap_or(0);

    // Only needed to denominate a zero — a conversation whose turns carry no
    // audit row to take a currency from.
    let accounting_currency = if cost_currencies.is_empty() {
        super::pricing::accounting_currency(&mut *conn).await
    } else {
        streamscope_core::pricing::Currency::USD
    };

    let summary = ConversationSummary {
        total_turns: rows.len(),
        total_tokens,
        total_input_tokens,
        total_output_tokens,
        total_cache_creation_tokens: if total_cache_creation_tokens > 0 { Some(total_cache_creation_tokens) } else { None },
        total_cache_read_tokens: if total_cache_read_tokens > 0 { Some(total_cache_read_tokens) } else { None },
        total_reasoning_tokens: if total_reasoning_tokens > 0 { Some(total_reasoning_tokens) } else { None },
        spend: if cost_unstatable {
            None
        } else {
            spend_total(
                cost_currencies.len() as i64,
                cost_currencies.iter().next().map(|c| c.to_string()),
                total_cost,
                accounting_currency,
            )
        },
        duration_ms,
    };

    let format_str = match format {
        ResponseFormat::Parsed => "parsed",
        ResponseFormat::Raw => "raw",
        ResponseFormat::ParsedRaw => "parsed_raw",
    };

    // Raw format: return raw turns, no event parsing. Each turn carries the
    // messages it read — its whole history where `reads_whole`, the slice it
    // added on every other — and says which.
    if format == ResponseFormat::Raw {
        let mut raw_turns = Vec::new();
        for (turn_idx, row) in rows.iter().enumerate() {
            let hashes = turn_hashes_list[turn_idx];
            let transform_diff = row.transform_diff.transform_diff(row.request_id);

            let messages: Vec<serde_json::Value> = hashes
                .iter()
                .filter_map(|h| msg_map.get(h).cloned())
                .collect();

            let meta = if row.prompt_tokens.is_some() || row.completion_tokens.is_some() {
                Some(turn_metadata(row, transform_diff.clone()))
            } else {
                None
            };

            raw_turns.push(RawTurn {
                request_id: row.request_id,
                turn: row.turn_number,
                timestamp: row.timestamp,
                messages,
                whole_history: row.reads_whole,
                parent_request_id: row.parent_request_id,
                added_from: row.added_from,
                response_content: row.response_content.clone(),
                response_tool_calls: row.response_tool_calls.clone(),
                system_prompt: system_prompt_of(row).cloned(),
                transform_diff,
                metadata: meta,
            });
        }

        return Ok(ConversationResponse {
            session_id,
            model,
            user_email,
            summary,
            format: format_str.to_string(),
            events: None,
            raw_turns: Some(raw_turns),
            alert_level: alert_level.clone(),
            alert_expert_axis: alert_expert_axis.clone(),
            alert_note: alert_note.clone(),
            parent_session_id,
            linkage_confidence: linkage_confidence.clone(),
            linkage_spawn_turn,
            linkage_spawn_tool_call_id: linkage_spawn_tool_call_id.clone(),
            key_name: key_name.clone(),
            key_prefix: key_prefix.clone(),
            workspace_name: workspace_name.clone(),
            client_ip: client_ip.clone(),
            end_user: end_user.clone(),
            end_user_groups: end_user_groups.clone(),
            turn_params: Vec::new(),
            // Raw-turns format skips the event projection, so there is nothing to
            // scan for spawn points.
            detected_spawn_points: Vec::new(),
        });
    }

    // Parsed / ParsedRaw: walk turns chronologically, emitting events
    let mut events: Vec<ConversationEvent> = Vec::new();
    let mut turn_params: Vec<TurnParams> = Vec::new();
    // Request ids of this session's LLM turns — the parent key for threading
    // substitution-loop web rows (their own `gateway_audit.session_id` isn't the
    // session's, so they join only by `parent_request_id`).
    let mut turn_request_ids: Vec<Uuid> = Vec::new();
    // tool_use_id → guardrail findings across all turns (response/web surface),
    // so a threaded substitution `web_call` can carry every shield server-side —
    // one fetch can trip several detectors, so this holds all of them, not one.
    let mut guardrail_by_tool_use: std::collections::HashMap<String, Vec<streamscope_core::proxy::content::GuardrailStepDiff>> =
        std::collections::HashMap::new();
    // Tracks the last-emitted RequestParams signature so we only push a new
    // `TurnParams` entry when the sampling params / tool catalog / model
    // actually change. Matches what the RequestParamsPanel component renders,
    // so `system_prompt` is excluded (it's surfaced separately via the
    // System Prompt event on turn 0 / baseline). Stored as `serde_json::Value`
    // (not a serialized string) so the comparison is insensitive to HashMap
    // iteration order inside `DomainRequestMeta.extra`.
    let mut last_params_signature: Option<serde_json::Value> = None;
    // Tracks the previous turn's `tools_available_hash` so we emit a
    // `ToolsChanged{BetweenTurns}` event when the client swaps the tool set.
    let mut last_tools_available_hash: Option<String> = None;
    let mut seen_hashes: HashSet<String> = HashSet::new();
    // Signatures of captured assistant responses from prior turns. A history
    // assistant message whose signature matches one of these is treated as
    // an echo of a prior captured response and skipped; one whose signature
    // does NOT match is client-fabricated and surfaces with `is_from_history`.
    let mut seen_assistant_signatures: HashSet<String> = HashSet::new();
    let mut prev_timestamp: Option<(chrono::DateTime<chrono::Utc>, i64)> = None;
    let mut prev_message_count: usize = 0;

    for (turn_idx, row) in rows.iter().enumerate() {
        let turn_number = row.turn_number;
        let timestamp = row.timestamp;
        let chat_summary: Option<Vec<streamscope_core::audit::ChatMediaSummaryEntry>> =
            row.chat_media_summary.decode("chat_media_summary", row.request_id);
        // The stored blobs this turn's request carried itself.
        let carried = crate::conversation::CarriedMedia::of(chat_summary.as_deref().unwrap_or_default());
        let is_baseline = row.is_baseline;
        let hashes = turn_hashes_list[turn_idx];
        let latency_total_ms = row.latency_total_ms;
        let response_content = &row.response_content;
        let transform_diff = row.transform_diff.transform_diff(row.request_id);
        let event_type = row.event_type.as_str();

        // Time gap between turns
        if let Some((prev_ts, prev_latency)) = prev_timestamp {
            let prev_answer_ms = prev_ts.timestamp_millis() + prev_latency;
            let curr_request_ms = timestamp.timestamp_millis();
            let gap_ms = curr_request_ms - prev_answer_ms;
            if gap_ms >= 1000 {
                events.push(ConversationEvent::TimeGap {
                    gap_ms,
                    before_turn: turn_number,
                });
            }
        }

        // Compaction marker — clear seen hashes + assistant signatures
        // (new baseline). Skip for media turns which have no message hashes.
        let mut compaction_emitted = false;
        if event_type != "media" && is_baseline && turn_idx > 0 {
            seen_hashes.clear();
            seen_assistant_signatures.clear();
            let current_msg_count = usize::try_from(row.message_count).unwrap_or(0);

            // Try to extract summary from previous turn's response
            let prev_summary = if turn_idx > 0 {
                rows[turn_idx - 1].response_content.as_deref().and_then(extract_summary)
            } else {
                None
            };

            if prev_message_count > 0 && current_msg_count < prev_message_count {
                let (messages_before, messages_after) =
                    if let Some(diff) = &transform_diff {
                        let before = Some(diff.messages_original_count);
                        let after = Some(diff.messages_after_count);
                        if before == after {
                            (Some(prev_message_count), Some(current_msg_count))
                        } else {
                            (before, after)
                        }
                    } else {
                        (Some(prev_message_count), Some(current_msg_count))
                    };
                events.push(ConversationEvent::Compaction {
                    turn: turn_number,
                    messages_before,
                    messages_after,
                    summary: prev_summary,
                });
                compaction_emitted = true;
            } else {
                events.push(ConversationEvent::ContextReset {
                    turn: turn_number,
                    message_count: current_msg_count,
                });
            }
        }

        // Turn boundary
        events.push(ConversationEvent::TurnBoundary {
            turn: turn_number,
            timestamp: Some(timestamp.to_rfc3339()),
        });

        let meta = turn_metadata(row, transform_diff.clone());

        if event_type == "media" {
            // Standalone media API call — emit a MediaApiCall event carrying the
            // canonical media_call payload from llm_audit (source of truth).
            let media_call: Option<streamscope_core::api::domain_request::DomainMediaCall> =
                row.media_call.decode("media_call", row.request_id);
            if let Some(call) = media_call {
                events.push(ConversationEvent::MediaApiCall {
                    media_call: Box::new(call),
                    turn: turn_number,
                    is_new: true,
                    metadata: Some(meta),
                });
            }
        } else {
            // Chat turn — emit events via canonical domain normalization.
            //
            // Dedup filter: keep a message only when the turn is baseline/first OR
            // the hash was first seen in this turn. For non-assistant roles the
            // hash check alone is sufficient. For assistant history, we additionally
            // check the content signature against `seen_assistant_signatures` —
            // when the signature matches a prior captured response, the message is
            // a client echo of the proxy's own response and we suppress it to avoid
            // double-rendering. When it does NOT match, the assistant content is
            // client-fabricated (not produced by any captured upstream call) and we
            // keep it; `build_events` will tag the emitted Message
            // event with `is_from_history: true` so the UI can flag it.
            let is_baseline_or_first = row.opens_view;
            let new_messages: Vec<&serde_json::Value> = hashes
                .iter()
                .filter_map(|h| {
                    let msg = msg_map.get(h)?;
                    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("");
                    let unseen = !seen_hashes.contains(h);
                    if is_baseline_or_first {
                        return Some(msg);
                    }
                    if !unseen {
                        return None;
                    }
                    if role == "assistant" {
                        match history_assistant_signature(msg) {
                            Some(sig) if seen_assistant_signatures.contains(&sig) => None,
                            _ => Some(msg),
                        }
                    } else {
                        Some(msg)
                    }
                })
                .collect();
            let messages_arr = serde_json::Value::Array(
                new_messages.into_iter().cloned().collect(),
            );

            let row_tools_available_hash = &row.tools_available_hash;
            let row_tools_effective_hash = &row.tools_effective_hash;
            let row_request_tools: Option<serde_json::Value> = row_tools_available_hash
                .as_deref()
                .and_then(|h| tool_map.get(h).cloned());
            let row_request_params = &row.request_params;

            // Emit BetweenTurns when the available tool set differs from the
            // previous turn. We compare the `Option<&str>` directly so that
            // 0-tools ↔ N-tools transitions also surface (operators want to
            // see when a tool is added or fully removed mid-session, not
            // just when the set is swapped for another non-empty set).
            // Skipped on the very first turn (no baseline yet).
            if turn_idx > 0 {
                let prev = last_tools_available_hash.as_deref();
                let curr = row_tools_available_hash.as_deref();
                if prev != curr {
                    events.push(ConversationEvent::ToolsChanged {
                        turn: turn_number,
                        kind: ToolsChangeKind::BetweenTurns,
                        previous_hash: prev.map(str::to_owned),
                        current_hash: curr.map(str::to_owned),
                    });
                }
            }
            last_tools_available_hash = row_tools_available_hash.clone();

            // A turn whose protocol this build cannot parse renders as a
            // marker below, like any turn that fails to build — one such turn
            // must not fail the whole session view.
            let protocol: Result<streamscope_core::api::sse::ApiVersion, String> =
                crate::conversation::stored_protocol(&row.api_version, row.request_id)
                    .ok_or_else(|| format!("unsupported protocol {:?}", row.api_version));

            let model_ref: String = row
                .model_used
                .clone()
                .or_else(|| row.model_requested.clone())
                .unwrap_or_default();

            let turn_row = |protocol| TurnRow {
                turn_number,
                protocol,
                // Read only where the turn opens the view (`turns`).
                system_prompt: system_prompt_of(row).map(String::as_str),
                messages_json: &messages_arr,
                request_tools: row_request_tools.as_ref(),
                tools_available_hash: row_tools_available_hash.as_deref(),
                tools_effective_hash: row_tools_effective_hash.as_deref(),
                request_params: row_request_params.as_ref(),
                response_content: response_content.as_deref(),
                response_tool_calls: row.response_tool_calls.as_ref(),
                thinking: None,
                model: &model_ref,
                metadata: Some(meta.clone()),
                include_raw,
                // Session view pre-filters messages_json above (new_messages
                // / is_baseline_or_first) so every surviving history entry
                // is genuinely first-seen in this turn.
                dedup_filtered: true,
                transform_diff: transform_diff.as_ref().map(|j| &j.0),
            };
            // Build canonical events for this turn — one corrupt turn must not
            // blow up the whole session view. On error, emit a marker message
            // carrying the raw payload so the UI still shows something.
            match protocol.and_then(|p| {
                build_events(&turn_row(p)).map_err(|e| e.to_string())
            }) {
                Ok(mut built) => {
                    carried.stamp(&mut built.events, row.request_id);
                    events.extend(built.events);
                    // Dedupe identical per-turn request params: the client
                    // typically sends the same sampling params + tool catalog
                    // on every turn of a session, so shipping and rendering
                    // an identical ~N KB tool list per turn is pure waste.
                    // Compare on everything *except* `system_prompt` (the
                    // panel doesn't render it; the dashed System Prompt
                    // event already handles it).
                    // We go through `serde_json::Value` rather than a string:
                    // `DomainRequestMeta.extra` is a `HashMap<String, Value>`,
                    // and Rust's `HashMap` iteration order is non-deterministic.
                    // `Value` equality on `Object` is order-insensitive
                    // (`serde_json::Map` sorts keys when `preserve_order` is off,
                    // which is our default), so two calls with identical content
                    // compare equal regardless of the HashMap's internal order.
                    let signature = {
                        let mut sig = built.params.clone();
                        sig.system_prompt = None;
                        serde_json::to_value(&sig).ok()
                    };
                    let changed = match (&last_params_signature, &signature) {
                        (Some(a), Some(b)) => a != b,
                        _ => true,
                    };
                    if changed {
                        turn_params.push(TurnParams { turn: turn_number, params: built.params });
                        last_params_signature = signature;
                    }
                }
                Err(why) => events.push(unrendered_turn_marker(
                    turn_number,
                    why,
                    Some(meta),
                    include_raw.then(|| messages_arr.clone()),
                )),
            }

            // Track this turn's request id + its web-surface guardrail findings
            // so substitution `web_call` rows (threaded below by
            // `parent_request_id`) can be placed after their intercepted
            // `ToolCall` and carry the guardrail shield, both keyed on
            // `tool_use_id`.
            turn_request_ids.push(row.request_id);
            if let Some(j) = &transform_diff
                && let Some(steps) = &j.0.guardrail_steps
            {
                for s in steps {
                    guardrail_by_tool_use
                        .entry(s.tool_use_id.clone())
                        .or_default()
                        .push(s.clone());
                }
            }

            // image_generation tool outputs — Responses API built-in tool that
            // produces images on a chat turn. These ride on
            // `chat_media_summary` with blob_type = "image_generation_output".
            if let Some(entries) = &chat_summary {
                for entry in entries
                    .iter()
                    .filter(|e| e.blob_type == BlobType::ImageGenerationOutput)
                {
                    events.push(ConversationEvent::Media {
                        role: "assistant".to_string(),
                        media_type: entry.media_type.clone(),
                        content_type: "image".to_string(),
                        data: None,
                        url: None,
                        title: Some("Generated Image".to_string()),
                        size_bytes: Some(entry.size_bytes),
                        turn: turn_number,
                        is_new: true,
                        content_hash: Some(entry.content_hash.clone()),
                        blob_type: Some(entry.blob_type),
                        request_id: Some(row.request_id),
                    });
                }
            }

            // Content-based compaction detection: response contains <summary> block
            if !compaction_emitted
                && let Some(resp) = &response_content
                    && let Some(summary) = extract_summary(resp) {
                        events.push(ConversationEvent::Compaction {
                            turn: turn_number,
                            messages_before: None,
                            messages_after: None,
                            summary: Some(summary),
                        });
                    }
        }

        // Update state for next iteration — cumulative seen hashes plus the
        // captured assistant signature so subsequent turns can recognise their
        // own history echoes. A turn that read only its added slice has its
        // prefix from its parent, inserted when the parent was walked; one
        // that read its whole history without opening the view (its parent
        // not a row before it) went through the `seen_hashes`
        // filter above, so only what it really added was rendered.
        for h in hashes {
            seen_hashes.insert(h.clone());
        }
        if let Some(sig) = captured_response_signature(
            response_content.as_deref(),
            row.response_tool_calls.as_ref(),
        ) {
            seen_assistant_signatures.insert(sig);
        }
        prev_message_count = usize::try_from(row.message_count).unwrap_or(0);
        prev_timestamp = Some((timestamp, latency_total_ms.unwrap_or(0)));
    }

    // Post-process: classify tool calls against risk rules.
    let risk_rules = crate::routes::analytics::load_risk_rules(&mut *conn).await;
    let field_profiles = crate::routes::analytics::load_field_profiles(&mut *conn).await;
    if !risk_rules.is_empty() {
        for event in &mut events {
            if let ConversationEvent::ToolCall {
                name,
                arguments,
                risk_level,
                risk_description,
                ..
            } = event
            {
                let result = streamscope_core::config::tool_rules::classify_tool_call(
                    &risk_rules,
                    None,
                    // Pass the session's app_id so rules with `app_filter`
                    // evaluate identically to the proxy-time path.
                    session_app_id.as_deref(),
                    Some(&field_profiles),
                    name,
                    Some(arguments),
                );
                *risk_level = Some(result.risk);
                *risk_description = result.description;
            }
        }
    }

    // ---- Phase 3b: interleave MCP gateway calls into the timeline. ----
    //
    // Correlation: `gateway_audit.session_id` is hashed by
    // `session_id_from_client(raw_header, tenant_id, user_id)` on both
    // the LLM and MCP paths — keyed on `user_id`, NOT `key_id`. So when
    // the agent stamps the same logical session id on `X-Session-Id`
    // (LLM) and `Mcp-Session-Id` (MCP), the two streams hash to the
    // same UUID and join on `g.session_id` — never on `m.mcp_session_id`,
    // which is the MCP transport's own session, not the client's.
    //
    // We collect MCP calls ordered by timestamp ASC, then merge them
    // into the LLM event stream by walking the existing `TurnBoundary`
    // markers — each MCP call lands just before the first turn
    // boundary whose timestamp exceeds the call's, matching the
    // agentic workflow (LLM proposes a tool → MCP dispatch happens
    // between turns → result → next turn picks up).
    let mcp_rows = timeline::mcp_calls(&mut *conn, session_id)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("session conversation mcp fetch: {e}");
        Vec::new()
    });

    // Web (search + fetch) calls — same shape: collect ordered ASC by
    // timestamp, then splice into the event stream via the canonical
    // turn-boundary walk. Direct `/mcp/web` calls and substitution-loop
    // children both land here under their respective `surface` values.
    // Direct `/mcp/web` + `admin_test` rows join by `g.session_id`; substitution
    // children carry the LLM turn's id only in `w.parent_request_id` (their own
    // gateway row isn't stamped with the session id), so thread those by the
    // session's turn request ids. `w.tool_use_id` joins a substitution row to
    // its intercepted `ToolCall` + `guardrail_steps`.
    let web_rows = timeline::web_calls(&mut *conn, session_id, &turn_request_ids)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("session conversation web fetch: {e}");
        Vec::new()
    });

    // A2A gateway calls — the third protocol in the timeline. Correlated the
    // same way: `gateway_audit.session_id` is hashed from the client's
    // `X-Session-Id` on every path, so an agent's LLM turns, its MCP tool calls,
    // and the agent-to-agent exchanges they triggered all join on one id.
    let a2a_rows = timeline::a2a_calls(&mut *conn, session_id)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("session conversation a2a fetch: {e}");
        Vec::new()
    });

    // A `/mcp/web` call writes BOTH an mcp_audit and a web_audit row (same
    // request_id). Render it once — as the richer `web_call` — by dropping the
    // duplicate `mcp_call`. Substitution children have no mcp_audit row, so this
    // only collapses the direct virtual-web-MCP pair.
    let web_request_ids: std::collections::HashSet<Uuid> =
        web_rows.iter().map(|w| w.request_id).collect();
    let mcp_rows: Vec<McpCallRowForSession> = mcp_rows
        .into_iter()
        .filter(|m| !web_request_ids.contains(&m.request_id))
        .collect();

    if !mcp_rows.is_empty() || !web_rows.is_empty() || !a2a_rows.is_empty() {
        // Substitution web rows are placed after their intercepted ToolCall (by
        // tool_use_id); direct (mcp/admin_test) web + mcp + a2a rows interleave by
        // timestamp.
        let (sub_web, direct_web): (Vec<_>, Vec<_>) = web_rows
            .into_iter()
            .partition(|w| w.surface == "substitution");
        let mut merged = interleave_mcp_calls(events, mcp_rows);
        merged = place_substitution_web_calls(merged, sub_web, &guardrail_by_tool_use);
        if !direct_web.is_empty() {
            merged = interleave_web_calls(merged, direct_web);
        }
        if !a2a_rows.is_empty() {
            merged = interleave_a2a_calls(merged, a2a_rows);
        }
        let detected_spawn_points = crate::conversation::detect_spawn_points(&merged);
        return Ok(ConversationResponse {
            session_id,
            model,
            user_email,
            summary,
            format: format_str.to_string(),
            events: Some(merged),
            raw_turns: None,
            alert_level,
            alert_expert_axis,
            alert_note,
            parent_session_id,
            linkage_confidence,
            linkage_spawn_turn,
            linkage_spawn_tool_call_id: linkage_spawn_tool_call_id.clone(),
            key_name,
            key_prefix,
            workspace_name,
            client_ip,
            end_user,
            end_user_groups,
            turn_params,
            detected_spawn_points,
        });
    }

    let detected_spawn_points = crate::conversation::detect_spawn_points(&events);
    Ok(ConversationResponse {
        session_id,
        model,
        user_email,
        summary,
        format: format_str.to_string(),
        events: Some(events),
        raw_turns: None,
        alert_level,
        alert_expert_axis,
        alert_note,
        parent_session_id,
        linkage_confidence,
        linkage_spawn_turn,
        linkage_spawn_tool_call_id,
        key_name,
        key_prefix,
        workspace_name,
        client_ip,
        end_user,
        end_user_groups,
        turn_params,
        detected_spawn_points,
    })
}


/// Walk through the existing event list and splice in MCP calls in
/// chronological order. The LLM event list already carries
/// `TurnBoundary { timestamp }` markers; for each MCP row we find the
/// first boundary whose timestamp is strictly greater and insert
/// immediately before it. MCP rows that arrive after the final turn are
/// appended at the end. The `turn` field on the `McpCall` is the
/// preceding turn (`0` when the call lands before any boundary).
fn interleave_mcp_calls(
    events: Vec<ConversationEvent>,
    mcp_rows: Vec<McpCallRowForSession>,
) -> Vec<ConversationEvent> {
    // Build the list of (turn, timestamp_ms) for each TurnBoundary in
    // event order — used to assign `turn` to each MCP call.
    let boundaries: Vec<(usize, i32, i64)> = events
        .iter()
        .enumerate()
        .filter_map(|(idx, ev)| {
            if let ConversationEvent::TurnBoundary { turn, timestamp: Some(ts) } = ev {
                let ms = chrono::DateTime::parse_from_rfc3339(ts)
                    .ok()?
                    .timestamp_millis();
                Some((idx, *turn, ms))
            } else {
                None
            }
        })
        .collect();

    // Walk events in original order; for each TurnBoundary, drain any
    // MCP rows whose timestamp falls before that boundary.
    let mut merged: Vec<ConversationEvent> = Vec::with_capacity(events.len() + mcp_rows.len());
    let mut mcp_iter = mcp_rows.into_iter().peekable();
    let mut current_turn: i32 = 0;
    let mut boundary_iter = boundaries.into_iter().peekable();

    for (idx, ev) in events.into_iter().enumerate() {
        if let Some((bidx, _, ms)) = boundary_iter.peek().copied()
            && bidx == idx
        {
            // Drain MCP rows that fired before this turn boundary.
            while let Some(row) = mcp_iter.peek() {
                if row.timestamp.timestamp_millis() <= ms {
                    let row = mcp_iter.next().unwrap();
                    merged.push(mcp_call_event(row, current_turn));
                } else {
                    break;
                }
            }
            // Advance the running turn pointer at every boundary.
            if let ConversationEvent::TurnBoundary { turn, .. } = &ev {
                current_turn = *turn;
            }
            boundary_iter.next();
        }
        merged.push(ev);
    }

    // Any remaining MCP rows fired after the last LLM turn — append them
    // tagged with the last seen turn number.
    for row in mcp_iter {
        merged.push(mcp_call_event(row, current_turn));
    }

    merged
}


/// Sibling of `interleave_mcp_calls` — splices web rows into an already-merged
/// (LLM + MCP) event stream by timestamp. Web rows that fire after the final
/// turn are appended at the end. Two-pass approach (rather than generalising
/// `interleave_mcp_calls` into a polymorphic merge) keeps the canonical
/// turn-boundary logic in one place — both passes walk the same
/// `TurnBoundary` markers.
fn interleave_web_calls(
    events: Vec<ConversationEvent>,
    web_rows: Vec<WebCallRowForSession>,
) -> Vec<ConversationEvent> {
    // Mirror `interleave_mcp_calls`: build the boundary index, then walk
    // events and drain web rows that landed before each boundary.
    let boundaries: Vec<(usize, i32, i64)> = events
        .iter()
        .enumerate()
        .filter_map(|(idx, ev)| {
            if let ConversationEvent::TurnBoundary { turn, timestamp: Some(ts) } = ev {
                let ms = chrono::DateTime::parse_from_rfc3339(ts)
                    .ok()?
                    .timestamp_millis();
                Some((idx, *turn, ms))
            } else {
                None
            }
        })
        .collect();

    let mut merged: Vec<ConversationEvent> = Vec::with_capacity(events.len() + web_rows.len());
    let mut web_iter = web_rows.into_iter().peekable();
    let mut current_turn: i32 = 0;
    let mut boundary_iter = boundaries.into_iter().peekable();

    for (idx, ev) in events.into_iter().enumerate() {
        if let Some((bidx, _, ms)) = boundary_iter.peek().copied()
            && bidx == idx
        {
            while let Some(row) = web_iter.peek() {
                if row.timestamp.timestamp_millis() <= ms {
                    let row = web_iter.next().unwrap();
                    let g = badge_guardrail(&row.badges.0, &row.query);
                    merged.push(web_event(row, current_turn, g));
                } else {
                    break;
                }
            }
            if let ConversationEvent::TurnBoundary { turn, .. } = &ev {
                current_turn = *turn;
            }
            boundary_iter.next();
        }
        merged.push(ev);
    }

    for row in web_iter {
        let g = badge_guardrail(&row.badges.0, &row.query);
        merged.push(web_event(row, current_turn, g));
    }

    merged
}

fn web_event(
    row: WebCallRowForSession,
    turn: i32,
    guardrails: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
) -> ConversationEvent {
    ConversationEvent::Web {
        request_id: row.request_id,
        timestamp: row.timestamp.to_rfc3339(),
        operation: row.operation,
        surface: row.surface,
        backend: row.backend,
        query: row.query,
        result_count: row.result_count,
        status_code: row.status_code,
        error_category: row.error_category,
        error_detail: row.error_detail,
        latency_ms: row.latency_total_ms,
        parent_request_id: row.parent_request_id,
        guardrails,
        badges: row.badges.0,
        turn,
    }
}

/// Normalize a direct `/mcp/web` row's guardrail badges into `GuardrailStepDiff`s
/// so the web card renders the same shields as a substitution finding. A row can
/// carry more than one guardrail badge (e.g. a detection plus a detector error),
/// so every match is returned; empty when the row carries none.
fn badge_guardrail(
    badges: &[streamscope_core::audit::AuditBadge],
    query: &Option<String>,
) -> Vec<streamscope_core::proxy::content::GuardrailStepDiff> {
    use streamscope_core::audit::badge::{AuditBadge, GuardrailAction};
    use streamscope_core::proxy::content::{GuardrailStepDiff, GuardrailStepOutcome};
    badges.iter().filter_map(|b| match b {
        AuditBadge::Guardrail { categories, max_confidence, action } => Some(GuardrailStepDiff {
            call_id: None,
            tool_use_id: String::new(),
            name: "guardrail:classifier".to_string(),
            phase: streamscope_core::audit::Phase::Response,
            target: query.clone().unwrap_or_default(),
            category: Some(categories.first().copied().unwrap_or(
                streamscope_core::guardrail::GuardrailCategory::PromptInjection,
            )),
            confidence: Some(*max_confidence),
            outcome: match action {
                GuardrailAction::Block => GuardrailStepOutcome::Blocked,
                GuardrailAction::Flag => GuardrailStepOutcome::Flagged,
            },
            error: None,
            entities: None,
        }),
        AuditBadge::GuardrailError { reason } => Some(GuardrailStepDiff {
            call_id: None,
            tool_use_id: String::new(),
            name: "guardrail:classifier".to_string(),
            phase: streamscope_core::audit::Phase::Response,
            target: query.clone().unwrap_or_default(),
            // No verdict on a detector-error step — category/confidence are None.
            category: None,
            confidence: None,
            outcome: GuardrailStepOutcome::Error,
            error: Some(reason.clone()),
            entities: None,
        }),
        _ => None,
    }).collect()
}

/// Place substitution-loop `web_call` rows directly after their intercepted
/// `ToolCall` event (matched by `tool_use_id`), carrying the turn's guardrail
/// finding so the screening shows server-side, where it happened. A row whose
/// intercepted call can't be found (shouldn't happen) is appended at the end so
/// it is never silently dropped.
fn place_substitution_web_calls(
    events: Vec<ConversationEvent>,
    web_rows: Vec<WebCallRowForSession>,
    guardrail_by_tool_use: &std::collections::HashMap<String, Vec<streamscope_core::proxy::content::GuardrailStepDiff>>,
) -> Vec<ConversationEvent> {
    if web_rows.is_empty() {
        return events;
    }
    // Index intercepted ToolCall events by id → position.
    let mut out: Vec<ConversationEvent> = Vec::with_capacity(events.len() + web_rows.len());
    // Group rows by the tool_use_id they fulfil.
    let mut by_tuid: std::collections::HashMap<String, Vec<WebCallRowForSession>> =
        std::collections::HashMap::new();
    let mut orphans: Vec<WebCallRowForSession> = Vec::new();
    for row in web_rows {
        match &row.tool_use_id {
            Some(tuid) if !tuid.is_empty() => {
                by_tuid.entry(tuid.clone()).or_default().push(row)
            }
            _ => orphans.push(row),
        }
    }
    for ev in events {
        let matched_id = match &ev {
            ConversationEvent::ToolCall { id, intercepted: Some(_), .. } => Some(id.clone()),
            _ => None,
        };
        let turn = event_turn(&ev);
        out.push(ev);
        if let Some(id) = matched_id
            && let Some(rows) = by_tuid.remove(&id)
        {
            for row in rows {
                let g = guardrail_by_tool_use.get(&id).cloned().unwrap_or_default();
                out.push(web_event(row, turn, g));
            }
        }
    }
    // Any unplaced rows (no matching intercepted ToolCall) — append, still
    // carrying their guardrail so the block is never dropped.
    for (tuid, rows) in by_tuid {
        for row in rows {
            let g = guardrail_by_tool_use.get(&tuid).cloned().unwrap_or_default();
            out.push(web_event(row, 0, g));
        }
    }
    for row in orphans {
        out.push(web_event(row, 0, Vec::new()));
    }
    out
}

/// The `turn` a rendered event belongs to, for tagging a trailing web_call.
fn event_turn(ev: &ConversationEvent) -> i32 {
    match ev {
        ConversationEvent::ToolCall { turn, .. }
        | ConversationEvent::Message { turn, .. }
        | ConversationEvent::ToolResult { turn, .. }
        | ConversationEvent::TurnBoundary { turn, .. } => *turn,
        _ => 0,
    }
}


/// Project one A2A audit row into the canonical event.
///
/// Content goes through `streamscope_core::a2a::domain` — the same projection
/// the proxy screened the call with — so what the operator reads is what the
/// policy engine and the guardrail read. A streamed call has no `result`; its
/// content is reassembled from the events the pump captured, so a streamed reply
/// renders exactly like a non-streamed one.
fn a2a_call_event(row: A2aCallRowForSession, turn: i32) -> ConversationEvent {
    use streamscope_core::a2a::domain;

    let request_blocks = row
        .params
        .as_ref()
        .map(|p| blocks_from_slots(&domain::request_slots(&p.0)))
        .unwrap_or_default();

    let (response_blocks, artifacts) = match (&row.result, &row.stream_events) {
        (Some(result), _) => (
            blocks_from_slots(&reply_content_slots(&result.0)),
            artifact_views(&result.0),
        ),
        (None, Some(events)) => {
            let slots: Vec<domain::PartsSlot> = events
                .0
                .as_array()
                .map(|evs| {
                    evs.iter()
                        .filter_map(|e| e.get("result"))
                        .flat_map(domain::stream_event_slots)
                        .collect()
                })
                .unwrap_or_default();
            (blocks_from_slots(&slots), Vec::new())
        }
        (None, None) => (Vec::new(), Vec::new()),
    };

    // The caller — a user email when the key resolves to one, else the client
    // app id. Feeds the "caller → agent" header the whole surface reads by.
    let (caller_label, caller_kind) = match (row.user_email, row.app_id) {
        (Some(email), _) => (Some(email), Some("user".to_string())),
        (None, Some(app)) => (Some(app), Some("app".to_string())),
        (None, None) => (None, None),
    };

    let diff = row.transform_diff.map(|j| j.0).filter(|d| !d.is_empty());
    let (blocked, guardrails) = match diff {
        Some(d) => {
            // A block ends the call, so at most one can have fired; the other
            // findings (classify / replace) surface through the badges and the
            // audit drawer.
            let blocked = d
                .policy_findings
                .iter()
                .find(|p| p.action == "block")
                .map(|p| {
                    Box::new(crate::conversation::ToolCallBlock {
                        rule_id: p.rule_id.clone(),
                        rule_title: p.title.clone(),
                        reason: p
                            .description
                            .clone()
                            .or_else(|| p.title.clone())
                            .unwrap_or_else(|| "blocked by tool policy".to_string()),
                        phase: p.phase.clone(),
                        not_applied: false,
                        record: None,
                    })
                });
            (blocked, d.guardrail_steps)
        }
        None => (None, Vec::new()),
    };

    ConversationEvent::A2aCall {
        request_id: row.request_id,
        timestamp: row.timestamp.to_rfc3339(),
        method: row.method,
        agent_slug: row.agent_slug,
        agent_name: row.agent_name,
        caller_label,
        caller_kind,
        context_id: row.a2a_context_id,
        task_id: row.a2a_task_id,
        task_state: row.task_state,
        request_blocks,
        response_blocks,
        artifacts,
        status_code: row.status_code,
        error_code: row.error_code,
        error_message: row.error_message,
        latency_ms: row.latency_total_ms,
        blocked,
        guardrails,
        badges: row.badges.0,
        turn,
    }
}

/// The reply's message content — the task's status message, or a bare message.
///
/// Screening reads more than this (see `reply_slots`): artifacts are rendered
/// separately below, and `history` is the agent's echo of the conversation, which
/// would duplicate the request bubble if it were folded in here. Both are still
/// screened; this is only about what the timeline shows as "the reply".
fn reply_content_slots(result: &serde_json::Value) -> Vec<streamscope_core::a2a::domain::PartsSlot> {
    streamscope_core::a2a::domain::reply_slots(result)
        .into_iter()
        .filter(|s| !s.pointer.contains("/artifacts/") && !s.pointer.contains("/history/"))
        .collect()
}

fn blocks_from_slots(
    slots: &[streamscope_core::a2a::domain::PartsSlot],
) -> Vec<streamscope_core::api::domain_request::DomainContentBlock> {
    slots
        .iter()
        .flat_map(|s| s.parts.iter())
        .map(streamscope_core::a2a::domain::part_to_block)
        .collect()
}

/// Every artifact in a reply, whatever shape the method answered with:
/// `SendMessage` wraps its Task in the `task` oneof member, `GetTask` answers
/// bare, and `ListTasks` answers `{tasks: […]}` — whose artifacts the proxy
/// screens, so leaving them out of the render would hide reviewed content from
/// the reviewer.
fn artifact_views(result: &serde_json::Value) -> Vec<crate::conversation::A2aArtifactView> {
    let payload = streamscope_core::a2a::domain::reply_payload(result);
    let tasks: Vec<&serde_json::Value> = match payload.get("tasks").and_then(serde_json::Value::as_array) {
        Some(list) => list.iter().collect(),
        None => vec![payload],
    };
    tasks
        .iter()
        .filter_map(|t| t.get("artifacts").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|a| {
            let artifact = streamscope_core::a2a::wire::v1_0::parse_artifact(a)?;
            Some(crate::conversation::A2aArtifactView {
                artifact_id: artifact.artifact_id.clone(),
                name: artifact.name.clone(),
                description: artifact.description.clone(),
                blocks: streamscope_core::a2a::domain::artifact_blocks(&artifact),
            })
        })
        .collect()
}

/// Sibling of `interleave_mcp_calls` / `interleave_web_calls` — splices A2A rows
/// into the merged event stream by timestamp, walking the same turn boundaries.
fn interleave_a2a_calls(
    events: Vec<ConversationEvent>,
    a2a_rows: Vec<A2aCallRowForSession>,
) -> Vec<ConversationEvent> {
    let boundaries: Vec<(usize, i64)> = events
        .iter()
        .enumerate()
        .filter_map(|(idx, ev)| {
            if let ConversationEvent::TurnBoundary { timestamp: Some(ts), .. } = ev {
                let ms = chrono::DateTime::parse_from_rfc3339(ts)
                    .ok()?
                    .timestamp_millis();
                Some((idx, ms))
            } else {
                None
            }
        })
        .collect();

    let mut merged: Vec<ConversationEvent> = Vec::with_capacity(events.len() + a2a_rows.len());
    let mut rows = a2a_rows.into_iter().peekable();
    let mut current_turn: i32 = 0;
    let mut boundary_iter = boundaries.into_iter().peekable();

    for (idx, ev) in events.into_iter().enumerate() {
        if let Some((bidx, ms)) = boundary_iter.peek().copied()
            && bidx == idx
        {
            while let Some(row) = rows.peek() {
                if row.timestamp.timestamp_millis() <= ms {
                    let row = rows.next().unwrap();
                    merged.push(a2a_call_event(row, current_turn));
                } else {
                    break;
                }
            }
            if let ConversationEvent::TurnBoundary { turn, .. } = &ev {
                current_turn = *turn;
            }
            boundary_iter.next();
        }
        merged.push(ev);
    }

    for row in rows {
        merged.push(a2a_call_event(row, current_turn));
    }

    merged
}

fn mcp_call_event(row: McpCallRowForSession, turn: i32) -> ConversationEvent {
    ConversationEvent::McpCall {
        request_id: row.request_id,
        timestamp: row.timestamp.to_rfc3339(),
        method: row.method,
        tool_id: row.tool_id,
        prompt_id: row.prompt_id,
        resource_uri: row.resource_uri,
        virtual_server_slug: row.virtual_server_slug,
        upstream_server_name: row.upstream_server_name,
        status_code: row.status_code,
        error_code: row.error_code,
        error_message: row.error_message,
        latency_ms: row.latency_total_ms,
        transform_diff: row.transform_diff.map(|j| j.0).filter(|d| {
            // Suppress empty passthroughs so the UI doesn't render a
            // meaningless "no diff" row.
            d.policy_classification.is_some()
                || d.mcp_stream.is_some()
                || d.mcp_server_initiated.is_some()
                || d.mcp_list_changed.is_some()
                || d.mcp_elicitation_complete.is_some()
                || d.transport.is_some()
        }),
        params: row.params.map(|j| j.0).filter(|v| !v.is_null()),
        result: row.result.map(|j| j.0).filter(|v| !v.is_null()),
        turn,
    }
}

// ---------------------------------------------------------------------------
// Media Blob Viewer
// ---------------------------------------------------------------------------

#[derive(Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct BlobQuery {
    /// Blob-type discriminator — one of the canonical `BlobType` wire values
    /// (`request_upload`, `response_body`, `chat_image`, `chat_audio`,
    /// `chat_document`, `chat_file`, `image_generation_output`). Defaults to
    /// `response_body`. An unrecognized value is rejected with `400`.
    pub blob_type: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/audit/media/{hash}",
    tag = "Audit",
    params(
        ("hash" = String, Path, description = "SHA-256 content hash"),
        BlobQuery,
    ),
    responses(
        (status = 200, description = "Binary blob data", content_type = "application/octet-stream"),
        (status = 404, description = "Blob not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_media_blob(
    mut db: TenantConn,
    Path(hash): Path<String>,
    Query(params): Query<BlobQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // The blob_type discriminator is the closed `BlobType` set — an
    // unrecognized value cannot key any row, so reject it up front with a
    // typed error rather than returning a misleading 404.
    let blob_type = match params.blob_type.as_deref() {
        Some(s) => s.parse::<BlobType>().map_err(|_| {
            ApiError::bad_request("invalid blob_type").code(ApiErrorCode::MediaBlobTypeInvalid)
        })?,
        None => BlobType::ResponseBody,
    };

    let tenant_id = db.tenant_uuid();
    let row = crate::content_store::media_blobs::get(db.conn(), tenant_id, &hash, blob_type)
        .await
        .map_err(|e| {
            tracing::error!("media blob query: {e}");
            ApiError::internal("Failed to query media blob")
        })?;

    let Some((media_type, data)) = row else {
        return Err(ApiError::not_found("Media blob not found", ApiErrorCode::MediaBlobNotFound));
    };

    Ok(media_blob_response(media_type, data))
}

/// A stored blob as both media routes serve it. Its bytes are whatever a
/// client sent or an upstream returned, under the media type recorded with
/// them — an SVG or an HTML file among them — so nothing served here runs on
/// the console's origin with the viewer's session:
/// - a type a browser renders with no script surface (a raster image, audio,
///   video) is served inline — an `<img>` / `<audio>` / `<video>` load
///   ignores a sub-resource's CSP, so the views render it inline;
/// - any other type (an SVG, an HTML file, a PDF) is an attachment: opened in
///   a tab, the browser saves it rather than rendering it;
/// - `nosniff` holds the browser to the recorded type, and a sandboxing CSP
///   with no source covers whatever is rendered anyway.
pub(crate) fn media_blob_response(media_type: String, data: Vec<u8>) -> impl IntoResponse {
    let essence = media_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let inline = matches!(
        essence.as_str(),
        "image/png" | "image/jpeg" | "image/jpg" | "image/gif" | "image/webp" | "image/avif" | "image/bmp"
    ) || essence.starts_with("audio/")
        || essence.starts_with("video/");
    let csp = "default-src 'none'; sandbox";
    let headers = [
        (axum::http::header::CONTENT_TYPE, media_type),
        (axum::http::header::CONTENT_DISPOSITION, if inline { "inline" } else { "attachment" }.to_string()),
        (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (axum::http::header::CONTENT_SECURITY_POLICY, csp.to_string()),
    ];
    (headers, data)
}

/// Lazy-fetch a single deduplicated tool-definition blob by hash. Mirrors
/// `get_media_blob` shape, but returns JSON (tool definitions are JSON, not
/// binary). The UI uses this when expanding a `tools_changed` event banner so
/// it can render the diff between the previous and current tool sets without
/// inlining the blobs on every turn.
#[derive(Serialize, ToSchema)]
pub struct ToolDefinitionBlobResponse {
    pub hash: String,
    /// The tools array as the client declared it, in its own protocol's shape.
    #[schema(value_type = Object)]
    pub definition: serde_json::Value,
    pub size_bytes: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/audit/tool-definitions/{hash}",
    tag = "Audit",
    params(
        ("hash" = String, Path, description = "SHA-256 content hash of the tool-definition blob"),
    ),
    responses(
        (status = 200, description = "Tool-definition JSON blob", body = ToolDefinitionBlobResponse),
        (status = 404, description = "Hash not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tool_definition_blob(
    mut db: TenantConn,
    Path(hash): Path<String>,
) -> Result<Json<ToolDefinitionBlobResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let row = crate::content_store::tool_definitions::get(db.conn(), tenant_id, &hash)
        .await
        .map_err(|e| {
            tracing::error!("tool definition blob query: {e}");
            ApiError::internal("Failed to query tool definition")
        })?;

    let Some((definition, size_bytes)) = row else {
        return Err(
            ApiError::not_found("Tool definition not found", ApiErrorCode::AuditRecordNotFound),
        );
    };

    Ok(Json(ToolDefinitionBlobResponse {
        hash,
        definition,
        size_bytes: size_bytes as i64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored blob is served so that nothing in it runs on the console's
    /// origin, whatever type it was recorded under: a type the views render
    /// inline stays inline, any other (an SVG or HTML file a client sent, a
    /// PDF) is an attachment, and all of them are sandboxed.
    #[test]
    fn a_served_blob_is_a_document_that_runs_nothing() {
        let served = |mt: &str| {
            let resp = media_blob_response(mt.into(), b"x".to_vec()).into_response();
            let h = resp.headers();
            assert_eq!(h[axum::http::header::CONTENT_TYPE], mt);
            assert_eq!(h[axum::http::header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{mt}");
            let csp = h[axum::http::header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
            assert!(csp.contains("default-src 'none'") && !csp.contains("allow-scripts"), "{mt}: {csp}");
            (h[axum::http::header::CONTENT_DISPOSITION].to_str().unwrap().to_string(), csp.contains("sandbox"))
        };
        for mt in ["image/svg+xml", "text/html", "text/html; charset=utf-8", "application/xhtml+xml", "text/xml", "application/octet-stream", "application/pdf"] {
            assert_eq!(served(mt), ("attachment".into(), true), "{mt}");
        }
        for mt in ["image/png", "image/jpeg", "IMAGE/WEBP", "audio/mpeg", "video/mp4"] {
            assert_eq!(served(mt), ("inline".into(), true), "{mt}");
        }
    }

    #[test]
    fn only_alerts_with_a_term_is_refused() {
        assert!(SessionSort::check_with_search(Some(SessionSort::Alerts), Some("x")).is_err());
        assert!(SessionSort::check_with_search(Some(SessionSort::Alerts), Some("  ")).is_ok());
        assert!(SessionSort::check_with_search(Some(SessionSort::Alerts), None).is_ok());
        assert!(SessionSort::check_with_search(Some(SessionSort::Oldest), Some("x")).is_ok());
    }

    #[test]
    fn test_extract_thinking_with_tags() {
        let (thinking, text) = extract_thinking("<think>Let me consider this</think>The answer is 42");
        assert_eq!(thinking, Some("Let me consider this".to_string()));
        assert_eq!(text, "The answer is 42");
    }

    #[test]
    fn test_extract_thinking_no_opening_tag() {
        let (thinking, text) = extract_thinking("internal reasoning</think>The answer is 42");
        assert_eq!(thinking, Some("internal reasoning".to_string()));
        assert_eq!(text, "The answer is 42");
    }

    #[test]
    fn test_extract_thinking_no_tags() {
        let (thinking, text) = extract_thinking("Just a normal response");
        assert!(thinking.is_none());
        assert_eq!(text, "Just a normal response");
    }

    #[test]
    fn test_extract_thinking_empty_think() {
        let (thinking, text) = extract_thinking("<think></think>The answer");
        assert!(thinking.is_none());
        assert_eq!(text, "The answer");
    }

    #[test]
    fn test_extract_thinking_with_thinking_tags() {
        let (thinking, text) = extract_thinking("<thinking>\nLet me reason\n</thinking>\n\nThe answer is 42");
        assert_eq!(thinking, Some("Let me reason".to_string()));
        assert_eq!(text, "The answer is 42");
    }

    #[test]
    fn test_extract_thinking_no_opening_thinking_tag() {
        let (thinking, text) = extract_thinking("internal reasoning</thinking>\n\nThe answer is 42");
        assert_eq!(thinking, Some("internal reasoning".to_string()));
        assert_eq!(text, "The answer is 42");
    }

    /// `captured_response_signature` and `history_assistant_signature` must
    /// yield the same hash for equivalent content — the captured/storage side
    /// (response_content + response_tool_calls) and the client-history side
    /// (an assistant message in the next turn's messages_json). This is the
    /// load-bearing invariant for the session view's "is this a real echo of
    /// our captured response, or is it client-fabricated?" dedup.
    #[test]
    fn signatures_match_across_storage_and_history_for_prose() {
        let captured = captured_response_signature(Some("hello world"), None);
        let history = history_assistant_signature(&serde_json::json!({
            "role": "assistant",
            "content": "hello world",
        }));
        assert!(captured.is_some());
        assert_eq!(captured, history);
    }

    #[test]
    fn signatures_match_across_anthropic_history_shape() {
        let captured = captured_response_signature(
            Some(""),
            Some(&serde_json::json!([
                {"type": "tool_use", "id": "toolu_98cfb47befcd", "name": "web_search", "input": {}}
            ])),
        );
        let history = history_assistant_signature(&serde_json::json!({
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "toolu_98cfb47befcd", "name": "web_search", "input": {}}
            ],
        }));
        assert!(captured.is_some());
        assert_eq!(captured, history);
    }

    #[test]
    fn signatures_match_across_openai_history_shape() {
        let captured = captured_response_signature(
            Some(""),
            Some(&serde_json::json!([
                {"id": "call_abc", "type": "function", "function": {"name": "f", "arguments": "{}"}}
            ])),
        );
        let history = history_assistant_signature(&serde_json::json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [
                {"id": "call_abc", "type": "function", "function": {"name": "f", "arguments": "{}"}}
            ],
        }));
        assert!(captured.is_some());
        assert_eq!(captured, history);
    }

    #[test]
    fn signatures_differ_when_content_differs() {
        let captured = captured_response_signature(Some("answer A"), None);
        let history = history_assistant_signature(&serde_json::json!({
            "role": "assistant",
            "content": "Classic hydration issue with dates.",
        }));
        // Different prose ⇒ different sigs ⇒ history survives dedup with
        // `is_from_history: true`.
        assert!(captured.is_some());
        assert!(history.is_some());
        assert_ne!(captured, history);
    }

    #[test]
    fn empty_assistant_yields_no_signature() {
        assert!(captured_response_signature(Some(""), None).is_none());
        assert!(history_assistant_signature(&serde_json::json!({
            "role": "assistant",
            "content": ""
        })).is_none());
    }

    /// Regression: `DomainRequestMeta.extra` is `HashMap<String, Value>`, whose
    /// iteration order is non-deterministic. The session-view dedup in
    /// `get_session_conversation_impl` must compare via `serde_json::Value`
    /// (which is order-insensitive for objects) rather than via
    /// `serde_json::to_string` (which is byte-sensitive to HashMap order).
    #[test]
    fn request_params_signature_ignores_hashmap_key_order() {
        use streamscope_core::api::domain_request::DomainRequestMeta;

        let mut a = DomainRequestMeta {
            model: "m".into(),
            ..Default::default()
        };
        a.extra.insert("context_management".into(), serde_json::json!({"enabled": true}));
        a.extra.insert("output_config".into(), serde_json::json!({"format": "json"}));

        let mut b = DomainRequestMeta {
            model: "m".into(),
            ..Default::default()
        };
        // Insert in the *opposite* order. HashMap internal state differs;
        // `serde_json::to_string` can (and on some inputs will) emit keys
        // in a different order — defeating a byte-equality dedup.
        b.extra.insert("output_config".into(), serde_json::json!({"format": "json"}));
        b.extra.insert("context_management".into(), serde_json::json!({"enabled": true}));

        let sig_a = serde_json::to_value(&a).expect("to_value a");
        let sig_b = serde_json::to_value(&b).expect("to_value b");
        assert_eq!(sig_a, sig_b, "identical content must compare equal regardless of HashMap insertion order");

        // Negative: flipping a real value must break equality.
        let mut c = b.clone();
        c.extra.insert("context_management".into(), serde_json::json!({"enabled": false}));
        let sig_c = serde_json::to_value(&c).expect("to_value c");
        assert_ne!(sig_a, sig_c, "different content must compare non-equal");
    }

    /// `strip_system_reminders` delegates to the core helper which covers
    /// every `VOLATILE_TAG_PREFIXES` entry, not only `<system-reminder>`:
    /// the admin rendering also strips `<available-deferred-tools>`,
    /// `<local-command-*>`, and `<command-*>` inline blocks from
    /// displayed text. Non-volatile strings round-trip unchanged.
    #[test]
    fn strip_system_reminders_delegates_to_core_helper() {
        // Original behavior preserved
        assert_eq!(
            strip_system_reminders("prefix<system-reminder>X</system-reminder>suffix"),
            "prefixsuffix",
        );
        // Broadened — family prefixes now also stripped
        assert_eq!(
            strip_system_reminders("A<local-command-stdout>out</local-command-stdout>B"),
            "AB",
        );
        assert_eq!(
            strip_system_reminders("X<command-name>/clear</command-name>Y"),
            "XY",
        );
        // Non-volatile unchanged
        assert_eq!(
            strip_system_reminders("Just normal prose."),
            "Just normal prose.",
        );
    }
}
