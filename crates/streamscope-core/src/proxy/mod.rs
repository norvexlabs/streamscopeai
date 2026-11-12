//! Proxy request handler and supporting infrastructure.
//!
//! Contains [`AppState`] (shared state for all request handlers), upstream
//! [`routing`] (model resolution, credential lookup, BYOK), the HTTP [`client`]
//! (connection pooling, retry with exponential backoff), and request [`content`]
//! extraction (session detection, message hashing, transform diffs).
//!
//! Audit is mandatory: [`send_audit`] blocks under backpressure rather than
//! dropping records. Stats collection is pluggable via [`ProxyStatsTrait`].

pub mod adaptive_concurrency;
pub mod analyze;
pub mod azure_entra;
pub mod cache_embed;
pub mod client;
pub mod dispatch_gate;
pub mod content;
pub mod forward_body;
pub mod google_sa;
pub mod health;
pub mod inline_exchange;
pub mod json_merge;
pub mod qos_dialect;
pub mod qos_metrics;
pub mod media;
pub mod minted_token;
pub mod response_cache;
pub mod routing;

/// Truncate `s` to at most `max_chars` UTF-8 characters. When truncation occurs,
/// appends the Unicode ellipsis `…` (U+2026) as a surface marker so operators /
/// the UI can tell a truncated value apart from one that happens to end with `...`.
///
/// The marker is the ONLY signal that a cap fired — we do not carry a parallel
/// `truncated: bool` field. Callers that need a structured signal should check
/// `.ends_with('…')` on the returned string.
pub fn truncate_with_marker(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_string()
    } else {
        let boundary = s.floor_char_boundary(max_chars);
        format!("{}…", &s[..boundary])
    }
}

/// Upper bound on a client-supplied `model` identifier (bytes). No real model
/// name approaches this; the cap keeps an oversized or junk string out of the
/// audit tables (`model_requested`/`model_used`, both unbounded `TEXT`) and
/// out of the Gemini upstream URL path. Enforced once, before routing — see the
/// check in `proxy_handler_inner`.
const MAX_MODEL_NAME_LEN: usize = 256;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use crate::api::sse::ApiVersion;
use crate::api::ApiRequest;
use crate::audit::AuditRecord;
use crate::auth;
use crate::error::AppError;
use crate::middleware::attribution;
use crate::middleware::debug_echo;

use self::client::UpstreamClient;
use crate::settings::core_settings;

/// Client's original auth header, preserved for BYOK forwarding via `/fwd/{key}/v1/...` routes.
///
/// Contains the header name and value to forward to the upstream provider.
/// The `Debug` impl redacts the value to prevent credential leakage in logs.
#[derive(Clone)]
pub struct ForwardAuthContext {
    pub header_name: String,
    pub header_value: String,
}

impl std::fmt::Debug for ForwardAuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardAuthContext")
            .field("header_name", &self.header_name)
            .field("header_value", &"[REDACTED]")
            .finish()
    }
}

/// Send an audit record to the audit channel, waiting for capacity (backpressure).
///
/// Audit is mandatory — records are never dropped. If the channel is full,
/// this will block the request handler until space is available, applying
/// natural backpressure to the proxy when the audit pipeline is saturated.
pub async fn send_audit(
    audit_tx: &crate::audit::AuditSender<AuditRecord>,
    record: AuditRecord,
    request_id: &str,
) {
    use std::sync::atomic::Ordering;
    if audit_tx.send(record).await.is_err() {
        crate::audit::EMISSION_STATS
            .channel_lost
            .fetch_add(1, Ordering::Relaxed);
        tracing::error!(request_id = %request_id, "audit channel closed — record lost");
    } else {
        crate::audit::EMISSION_STATS
            .channel_sent
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Trait for proxy stats — allows the proxy binary to provide its own stats implementation.
pub trait ProxyStatsTrait: Send + Sync + 'static {
    fn inc_requests(&self);
    fn inc_errors(&self);
    fn inc_active_streams(&self);
    fn dec_active_streams(&self);
    fn inc_http2(&self);
    fn inc_http11(&self);
    /// Record proxy processing overhead in microseconds (auth + transforms + routing).
    fn record_overhead_us(&self, _us: u64) {}
    /// Record a completed request's outcome for the `/metrics` surface: final
    /// HTTP status class + total latency (measured from when the gateway
    /// started forwarding, any hold for capacity included — see
    /// `RequestMeta.request_started_at`). Called once per finalized request
    /// (chat + media).
    fn record_request_outcome(&self, _status_code: u16, _total_ms: Option<u64>) {}
}

/// No-op stats implementation (used when stats are not wired up).
pub struct NoopStats;
impl ProxyStatsTrait for NoopStats {
    fn inc_requests(&self) {}
    fn inc_errors(&self) {}
    fn inc_active_streams(&self) {}
    fn dec_active_streams(&self) {}
    fn inc_http2(&self) {}
    fn inc_http11(&self) {}
}

/// Shared application state.
pub struct AppState {
    /// Fleet-convergent usage counters (budget spend). Edge-local cumulative;
    /// reported up + reconciled down over the heartbeat. See [`crate::usage`].
    pub usage: Arc<crate::usage::UsageTracker>,
    pub http_client: UpstreamClient,
    pub tenant_registry: crate::config::TenantRegistry,
    pub audit_tx: crate::audit::AuditSender<AuditRecord>,
    pub session_detector: content::SessionDetector,
    /// In-flight request-phase snapshots for out-of-band inline-AI (`/v1/analyze`)
    /// exchanges, held between the request-phase and response-phase calls so the
    /// response half can finalize one complete audit row through the real
    /// pipeline. Bounded + TTL-pruned. See [`inline_exchange`].
    pub inline_exchanges: inline_exchange::InlineExchangeStore,
    pub script_engine: Arc<crate::scripting::ScriptEngine>,
    /// Per-alias round-robin counters for weighted load balancing.
    pub lb_counters: dashmap::DashMap<String, std::sync::atomic::AtomicUsize>,
    /// Passive per-upstream-server circuit breaker. Deprioritizes a server that
    /// has stopped responding (transport-level failures) so a healthy sibling is
    /// tried first; recovers via a lazy half-open trial. In-memory, per-replica.
    pub circuit_breaker: Arc<health::CircuitBreaker>,
    /// Sender for breaker health transitions, forwarded to admin over the edge
    /// channel and surfaced as an operator notification. `None` in test contexts
    /// (no edge connection) — transitions are then dropped.
    pub health_event_tx: Option<tokio::sync::mpsc::Sender<health::EdgeHealthEvent>>,
    /// Live proxy stats (atomic counters, zero overhead on hot path).
    pub proxy_stats: Arc<dyn ProxyStatsTrait>,
    /// SSRF-guarded client for web search backend calls — the substitution
    /// agent loop's and the built-in `/mcp/web` server's. Separate from
    /// `http_client` so its pool and timeout don't conflict with LLM upstream
    /// tuning; it reaches an internal address only when the platform's
    /// `extensions` egress list lists it.
    pub web_search_clients: Arc<crate::extension_http::ExtensionClients>,
    /// Web-search audit channel cloned from the proxy's primary
    /// `web_audit_tx`. The substitution agent loop emits to this
    /// channel with `surface="substitution"`; rows fan into
    /// `gateway_audit (kind='web')` + `web_audit` alongside
    /// the MCP virtual server's traffic. `None` when web-search audit isn't
    /// configured (test contexts).
    pub web_audit_tx: Option<
        crate::audit::AuditSender<crate::web::WebAuditRecord>,
    >,
    /// Cross-request mixed-pending cache. Populated by the substitution
    /// agent loop when an upstream turn emits both real and intercepted
    /// `tool_use` blocks: the intercepted call is dispatched for audit and
    /// the result is parked here so the next request in the same session
    /// can splice it back into the conversation as a synthesised
    /// `assistant tool_use → user tool_result` pair (strict reading of
    /// Decision #4). TTL configured per tenant via
    /// `web_search.mixed_pending_cache_ttl_seconds`. `Arc` so the agent
    /// loop and the inbound splice path can share without taking
    /// `&AppState`.
    pub mixed_pending_cache: std::sync::Arc<crate::web::MixedPendingCache>,
    /// Response cache for the LLM plane. Only consulted for an alias whose route
    /// binds a cache preset, so an uncached deployment pays nothing for it.
    /// In-memory and per-replica; entries are lost on restart. See
    /// [`crate::proxy::response_cache`].
    pub response_cache: std::sync::Arc<response_cache::ResponseCache>,
    /// Tracks detached audit-finalization tasks: streaming LLM responses via
    /// [`crate::pipeline::response_pipeline::spawn_audit_task`], and the MCP
    /// `tools/call` SSE pump. Those tasks send into the audit channels *after*
    /// their HTTP connection future resolves, so axum's graceful shutdown does
    /// not wait for them. On shutdown the proxy `close()`s this tracker and
    /// `wait()`s for it before cancelling the audit writer tasks — otherwise a
    /// late send races a drained writer and the record is lost.
    pub audit_task_tracker: tokio_util::task::TaskTracker,
    /// Readiness signal for the `/ready` probe: flipped `true` the first time
    /// the proxy holds its whole config (a complete snapshot restored at
    /// startup, or a sync answer that left nothing unsent). Liveness (`/health`)
    /// is always 200 while the process is up; readiness gates orchestrator
    /// traffic off a still-starting replica until it can actually serve. A
    /// config-loaded proxy stays ready even when admin is unreachable (it
    /// serves from its config and buffers audit in its outbox), so readiness
    /// tracks "config loaded", not
    /// "connected".
    pub config_ready: Arc<std::sync::atomic::AtomicBool>,
    /// Decides which held request gets the next free slot on a saturated model,
    /// and how many requests this replica may have in flight at an endpoint that
    /// declares a capacity. A pool whose endpoints declare none is not gated and
    /// pays nothing. See [`crate::proxy::dispatch_gate`].
    pub dispatch_gate: Arc<dispatch_gate::DispatchGate>,
}

impl AppState {
    /// Load the tenant config for a given tenant ID — for a credential that
    /// names its tenant before it is verified (a spec-OAuth JWT). A request
    /// authenticated by key reads its `TenantRequestCtx::config` instead.
    ///
    /// Returns `None` if the tenant is not found in the registry. No fallback
    /// to SYSTEM — callers must handle missing tenants explicitly to prevent
    /// cross-tenant config leakage.
    pub fn load_tenant_config(&self, tenant_id: crate::config::TenantId) -> Option<Arc<crate::config::TenantConfig>> {
        let registry = self.tenant_registry.load();
        registry.get(&tenant_id).cloned()
    }
}

pub use crate::auth::TenantRequestCtx;

/// Content metadata captured when content logging is enabled.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContentMeta {
    /// Per-message JSON strings, aligned 1:1 with `link_hashes` — the
    /// primary capture of the request messages (no `Value` tree is built on
    /// the capture path). Consumed by the edge SQLite buffer as-is.
    pub request_messages_json: Vec<String>,
    /// True when the typed request carried a content part the finalize-time
    /// media strip/scan could match — gates the parse of
    /// `request_messages_json` back into a tree in `finalize_audit`.
    pub media_scan_needed: bool,
    pub request_tools: Option<serde_json::Value>,
    /// Post-policy effective tool blob, set only when transforms modified the
    /// tools array. Hashed + buffered + referenced via the audit row's
    /// `tools_effective_hash` column at the finalize site. Transient.
    pub effective_tools: Option<serde_json::Value>,
    pub request_params: Option<serde_json::Value>,
    pub system_prompt: Option<String>,
    pub transform_diff: Option<serde_json::Value>,
    /// The session-link hash of each message (`RequestContent::link_hashes`) — never a content-store key.
    pub link_hashes: Vec<String>,
    pub session_info: content::SessionInfo,
    pub request_size_bytes: usize,
    pub first_user_prompt: Option<String>,
}

/// Request metadata carried through the pipeline for audit assembly.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub request_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    /// Workspace the request's key belongs to — carried into the audit row.
    pub workspace_id: uuid::Uuid,
    /// Whether any applicable bucket carries an enforceable TPM cap (workspace, or
    /// the member bucket). Gates post-response TPM accrual so the minute counter
    /// only churns when a cap exists — mirroring RPM, which accrues only for capped
    /// buckets inside the pre-request check.
    pub tpm_capped: bool,
    /// Whether this key carried a member bucket. Selects the same TPM accrual
    /// buckets the pre-request check enforced (workspace always, member only
    /// when a member limit exists) so a never-enforced member minute counter is
    /// never created.
    pub rate_override: bool,
    /// Whether this key carries an explicit per-key budget. Gates post-response
    /// budget accrual to the per-key scope so a `usage_counters` row is created
    /// only for keys an operator actually capped (uncapped keys accrue to the
    /// workspace + user scopes only).
    pub key_budget_capped: bool,
    /// Whether the org-total budget ceiling applies to THIS request — the
    /// tenant carries one AND this key's workspace is funded by it
    /// (`workspaces.counts_toward_tenant_budget`, which admin expresses by
    /// baking no `tenant_budget` at all on an excluded workspace's keys). Gates
    /// post-response accrual to the tenant scope, so neither an uncapped tenant
    /// nor an excluded workspace creates a `usage_counters` row that nothing
    /// would read — and, since the same absence removes the bucket from
    /// `check_budget`, an excluded workspace is never blocked by a counter it
    /// cannot advance.
    pub tenant_budget_capped: bool,
    pub key_id: Option<uuid::Uuid>,
    pub app_id: Option<String>,
    /// Gateway-side session id: the client's `X-Session-Id` header hashed
    /// through `content::session_id_from_client(raw, tenant_id, user_id)`.
    /// `None` when the client sent no header.
    /// Every `gateway_audit.session_id` producer (LLM, media, MCP, A2A, web
    /// substitution) stores this same hashed form — never the raw header —
    /// so cross-protocol rows correlate directly on the column.
    pub session_id: Option<uuid::Uuid>,
    /// Deterministic UUID derived from `X-Parent-Session-Id` header (hierarchical session linking).
    pub parent_session_id: Option<uuid::Uuid>,
    pub user_agent: Option<String>,
    pub detection_method: Option<String>,
    /// Forwarded end-client identity — set only for Inline AI traffic, where a
    /// trusted inline key relays the gateway-resolved end client (the `client`
    /// object on `/v1/analyze`, or the `X-Client-IP`/`X-Authenticated-*` headers
    /// on the `/fwd` proxy path). Empty on a direct request. Carried into
    /// `AuditRecord::{client_ip, end_user, end_user_groups}`.
    pub client_ip: Option<String>,
    pub end_user: Option<String>,
    pub end_user_groups: Vec<String>,
    pub model_requested: String,
    pub model_used: String,
    pub provider: String,
    pub api_version: ApiVersion,
    pub is_streaming: bool,
    /// Audit badges accumulated during the request pipeline. Drained into
    /// `AuditRecord::badges` at finalize time after merging in response-side
    /// badges.
    pub badges: crate::audit::BadgeBuilder,
    /// Per-program outcomes (request phase). Drained into
    /// `transform_diff.transform_programs`.
    pub program_outcomes: Vec<crate::proxy::content::TransformProgramRef>,
    /// Internal flow-control flags from the request-phase transforms.
    pub flags: crate::pipeline::TransformFlags,
    pub content: Option<ContentMeta>,
    /// When the gateway started forwarding: the start of both latencies, so
    /// any hold for capacity counts in them (and in `queue_wait_ms`).
    pub request_started_at: std::time::Instant,
    /// Estimated input tokens from request body size (~4 chars/token).
    pub estimated_input_tokens: u32,
    /// Upstream server UUID (for audit tracking).
    pub upstream_server_id: Option<String>,
    /// The replica endpoint that answered, and its URL (for audit tracking).
    pub endpoint_id: Option<uuid::Uuid>,
    pub endpoint_url: Option<String>,
    /// Upstream model UUID (for audit tracking).
    pub upstream_model_id: Option<String>,
    /// Pricing rates for this request's upstream model.
    pub pricing: crate::pricing::Rates,
    /// Cost of the response cache's embedding call, already priced at the embed
    /// target's own rates. Added to the audit row's total *after* the completion
    /// cost is computed, because a cache hit zeroes [`Self::pricing`] and would
    /// otherwise wipe it.
    pub embedding_cost: f64,
    /// Whether [`Self::embedding_cost`] is a real figure — see
    /// [`crate::proxy::response_cache::RequestCacheContext::embedding_priced`].
    pub embedding_priced: bool,
    /// Prompt tokens the embedding consumed. Reported beside its cost, and kept
    /// out of the request's own token counts.
    pub embedding_tokens: u32,
    /// The response cache's verdict on this request — the policy that applied,
    /// what it did, and what the avoided upstream call would have cost. `None`
    /// on an alias that binds no cache preset.
    pub cache_audit: Option<crate::proxy::response_cache::CacheAudit>,
    /// What the request spent waiting for upstream capacity. Part of the
    /// latency, which starts at `request_started_at`, and reported on its own
    /// so a view of the upstream can take it out: the engine did not take this
    /// long.
    pub queue_wait_ms: u64,
    /// The part of that wait spent at the pool of the target that served it.
    pub pool_wait_ms: u64,
    /// Every attempt the request moved on from before the one that answered,
    /// in order.
    pub moved_on_from: Vec<crate::audit::EarlierAttempt>,
    /// The class this request ran as, when the tenant has classes.
    pub qos_class_id: Option<uuid::Uuid>,
    /// The endpoint slot this request holds. Dropped when the audit row is
    /// finalized — which is when the request is really over, stream and all —
    /// so the slot goes to the next waiter then and not at the first byte.
    /// Shared because the meta is cloned along the pipeline: the slot is held
    /// until the LAST copy goes, which is the end of the request by any path.
    pub gate_permit: Option<Arc<crate::proxy::dispatch_gate::GatePermit>>,
    /// The request's place among those being served
    /// ([`content::SessionDetector::detect_serving`]): an identical request is
    /// a re-send of it until it is released — by a streamed body the moment it
    /// ends, else with the last copy of the meta (the end of the request by any
    /// path). The audit task keeps the meta past a stream's last byte, which is
    /// why the body releases it first.
    pub serving: Option<Arc<content::ServingGuard>>,
    /// Tool-definition rewrites produced by `Substitute` / `InterceptOnly`
    /// rules at request phase. Empty when no such rules fired. Carried into
    /// the response pipeline so the `BlockAccumulator` (and the substitution
    /// agent loop, when wired) can recognise echoes of substituted tool
    /// names and route them through the bound intercept handler instead of
    /// forwarding to the client.
    pub intercept_bindings: Vec<crate::proxy::content::InterceptBinding>,
    /// The tools tool policy withheld from the request, each with its rule
    /// (`TransformResult::withheld_tools`): a call to one of them is refused in
    /// the answer.
    pub withheld_tools: Vec<crate::proxy::content::BlockedToolInfo>,
}

/// Context available at the point of failure, used to enrich error audit records.
struct ErrorAuditContext<'a> {
    request_id: uuid::Uuid,
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    /// Workspace that owns the spend on this row. Nil only for a pre-auth
    /// failure, which has no workspace and no cost; once the request has
    /// authenticated it must be set, because an error row can now carry real
    /// money (a bought embedding) and a nil workspace is excluded from every
    /// workspace-scoped spend view.
    workspace_id: uuid::Uuid,
    key_id: Option<uuid::Uuid>,
    model_requested: &'a str,
    model_used: Option<&'a str>,
    provider: Option<&'a str>,
    app_id: Option<&'a str>,
    /// How `app_id` was recognised.
    detection_method: Option<&'a str>,
    /// The client's User-Agent as stored.
    user_agent: Option<&'a str>,
    api_version: ApiVersion,
    /// Response-cache work already paid for when the request failed. A request
    /// can reach the cache stage, buy an embedding, and only then fail to reach
    /// any upstream; the spend is real and belongs on the row that caused it.
    /// Zero until the cache stage has run.
    embedding_cost: f64,
    embedding_tokens: u32,
    /// Whether [`Self::embedding_cost`] is a real figure. A charge the ledger
    /// could not state must badge this row too: an error row is where a
    /// disappearing charge is hardest to notice, and this path never reaches
    /// `finalize_audit`, which raises the badge for every other row.
    embedding_priced: bool,
    /// The cache verdict reached before the failure. Kept so an error row on a
    /// cached alias still counts in the hit-rate denominator — dropping it would
    /// quietly flatter every alias whose upstream is failing.
    cache_audit: Option<crate::proxy::response_cache::CacheAudit>,
    /// Cache badges accumulated before the failure, so a hit, an observe match,
    /// or a semantic-skip reason survives an error instead of vanishing with it.
    cache_badges: Vec<crate::audit::AuditBadge>,
    /// What the request had already spent waiting for capacity, and the class it
    /// waited as. A request held for ten seconds and THEN refused records no
    /// latency of its own — no upstream ever answered it — so without these its
    /// row would not show the ten seconds its caller spent at all.
    queue_wait_ms: u64,
    qos_class_id: Option<uuid::Uuid>,
    /// The part of the wait spent at the pool of the upstream in `attempted`.
    pool_wait_ms: u64,
    /// The attempts the request has moved on from, and the one under way.
    attempts: AttemptLog,
    /// Whether the request had already been moved to another replica when it
    /// failed. A spill that ends in an error is the case an operator most wants
    /// to see: it says the first replica had no room AND the one it moved to
    /// did not answer.
    spilled: bool,
    /// The upstream the request was last sent to, or whose pool refused it.
    attempted: AttemptedUpstream,
}

/// The upstream a failed request was last sent to, so its error row counts
/// against that server on every per-server view. A request that failed before
/// it was offered to any upstream names none: its failure is not the server's.
#[derive(Debug, Clone, Default)]
pub(crate) struct AttemptedUpstream {
    server_id: Option<uuid::Uuid>,
    endpoint_id: Option<uuid::Uuid>,
    endpoint_url: Option<String>,
    /// The model and provider of that target. On a failover the row must name
    /// the upstream that failed LAST as a whole — never the primary's model
    /// beside the fallback's server.
    model: Option<String>,
    provider: Option<String>,
}

impl AttemptedUpstream {
    /// A request sent to one replica of a server.
    pub(crate) fn new(server_id: Option<&str>, endpoint_id: Option<uuid::Uuid>, url: &str) -> Self {
        Self {
            server_id: server_id.and_then(|s| uuid::Uuid::parse_str(s).ok()),
            endpoint_id,
            endpoint_url: endpoint_id.map(|_| url.to_string()),
            model: None,
            provider: None,
        }
    }

    /// A request sent to this target's replica.
    pub(crate) fn sent_to(target: &routing::UpstreamTarget) -> Self {
        Self {
            model: Some(target.model.clone()),
            provider: Some(target.provider.clone()),
            ..Self::new(target.upstream_server_id.as_deref(), target.endpoint_id, &target.url)
        }
    }

    /// A request sent to this target that failed with `error`. It names the
    /// replica only when the request reached it: one that could not be built,
    /// or whose credential could not be minted, never left the gateway and says
    /// nothing about any replica — it names the server alone.
    pub(crate) fn failed_at(target: &routing::UpstreamTarget, error: &AppError) -> Self {
        match ReplicaSignal::of(Err(error)) {
            ReplicaSignal::NotReached => Self { endpoint_id: None, endpoint_url: None, ..Self::sent_to(target) },
            ReplicaSignal::Answered | ReplicaSignal::Unreachable => Self::sent_to(target),
        }
    }

    /// A request the dispatch gate refused on this target's route. The refusal
    /// belongs to the server's pool — no replica of it had room — so it names
    /// the server and no endpoint. That holds for EVERY refusal reason, the
    /// gateway-wide ones included, because the gate refuses only after finding
    /// no replica of the pool with headroom (`DispatchGate::acquire`); keep it
    /// so, or a refusal would be charged to a server that had room.
    pub(crate) fn refused_by_pool_of(target: &routing::UpstreamTarget) -> Self {
        Self { endpoint_id: None, endpoint_url: None, ..Self::sent_to(target) }
    }

    pub(crate) fn stamp(&self, record: &mut AuditRecord) {
        record.upstream_server_id = self.server_id;
        record.endpoint_id = self.endpoint_id;
        record.endpoint_url = self.endpoint_url.clone();
        if let Some(model) = &self.model {
            record.model_used = model.clone();
        }
        if let Some(provider) = &self.provider {
            record.provider = provider.clone();
        }
    }
}

/// Send an error audit record with whatever context is available at the failure point.
async fn send_error_audit(state: &AppState, ctx: &ErrorAuditContext<'_>, error: &AppError) {
    let mut record = AuditRecord::error_record(
        ctx.request_id,
        ctx.user_id,
        ctx.tenant_id,
        ctx.workspace_id,
        ctx.key_id,
        error,
    );
    record.model_requested = ctx.model_requested.to_string();
    if let Some(m) = ctx.model_used {
        record.model_used = m.to_string();
    }
    if let Some(p) = ctx.provider {
        record.provider = p.to_string();
    }
    record.app_id = ctx.app_id.map(|s| s.to_string());
    record.detection_method = ctx.detection_method.map(|s| s.to_string());
    record.user_agent = ctx.user_agent.map(|s| s.to_string());
    record.api_version = ctx.api_version;
    // A failed request bills nothing for a completion it never received, but the
    // embedding it already bought is not refunded by the failure. Budget accrual
    // happens only in `finalize_audit`, which this path never reaches — so a
    // failed request's embedding, like its input tokens, lands on the row but
    // not on the budget.
    record.embedding_cost = ctx.embedding_cost;
    record.embedding_tokens = ctx.embedding_tokens;
    record.queue_wait_ms = ctx.queue_wait_ms;
    record.pool_wait_ms = ctx.pool_wait_ms;
    record.qos_class_id = ctx.qos_class_id;
    if ctx.queue_wait_ms > 0 {
        record.badges.push(crate::audit::AuditBadge::Queued { wait_ms: ctx.queue_wait_ms });
    }
    if ctx.spilled {
        record.badges.push(crate::audit::AuditBadge::Spilled);
    }
    record.cost = ctx.embedding_cost;
    if !ctx.embedding_priced {
        record.badges.push(crate::audit::AuditBadge::Unpriced);
    }
    record.cache_mode = ctx.cache_audit.map(|c| c.mode);
    record.cache_outcome = ctx.cache_audit.map(|c| c.outcome);
    record.avoided_cost = ctx.cache_audit.map_or(0.0, |c| c.avoided_cost);
    record.badges.extend(ctx.cache_badges.iter().cloned());
    ctx.attempted.stamp(&mut record);
    record.moved_on_from = ctx.attempts.moved_on_from().to_vec();
    send_audit(&state.audit_tx, record, &ctx.request_id.to_string()).await;
}

/// The attempts a request moved on from, built as a forward loop runs. An
/// attempt that ends without an answer the request keeps — refused by its
/// server's pool, or sent and failed — is held as the current one, and joins
/// `moved_on_from` only when the NEXT attempt begins. So the attempt the
/// request ends with is never on the list, whichever way it ends: the row
/// names that one itself.
#[derive(Debug, Default)]
pub(crate) struct AttemptLog {
    moved_on_from: Vec<crate::audit::EarlierAttempt>,
    current: Option<crate::audit::EarlierAttempt>,
    /// When the attempt under way began.
    started: Option<std::time::Instant>,
}

impl AttemptLog {
    /// Another attempt begins: the one before it ended without an answer the
    /// request keeps, so the request has moved on from it.
    pub(crate) fn begin(&mut self) {
        if let Some(attempt) = self.current.take() {
            self.moved_on_from.push(attempt);
        }
        self.started = Some(std::time::Instant::now());
    }

    /// The pool of `target`'s server refused this attempt after `waited`.
    pub(crate) fn refused(&mut self, target: &routing::UpstreamTarget, reason: &'static str, waited: std::time::Duration) {
        self.current = self.at(target, None, crate::audit::EarlierAttempt::REFUSED, reason, None, waited);
    }

    /// This attempt was sent to `target` after `waited` and failed with
    /// `error`. It names the replica only when the request reached it (see
    /// [`AttemptedUpstream::failed_at`]).
    pub(crate) fn failed(&mut self, target: &routing::UpstreamTarget, error: &AppError, waited: std::time::Duration) {
        let (status, category, _) = error.audit_error_info();
        let endpoint_id = AttemptedUpstream::failed_at(target, error).endpoint_id;
        self.current = self.at(target, endpoint_id, crate::audit::EarlierAttempt::FAILED, category, Some(status), waited);
    }

    /// A target naming no server (a pass-through) is recorded too: no page
    /// counts it, but the time it took is not the answering server's.
    fn at(
        &self,
        target: &routing::UpstreamTarget,
        endpoint_id: Option<uuid::Uuid>,
        outcome: &'static str,
        reason: &str,
        status: Option<u16>,
        waited: std::time::Duration,
    ) -> Option<crate::audit::EarlierAttempt> {
        let server_id = target.upstream_server_id.as_deref().and_then(|s| s.parse().ok());
        Some(crate::audit::EarlierAttempt {
            server_id,
            endpoint_id,
            outcome: outcome.to_string(),
            reason: reason.to_string(),
            status,
            wait_ms: waited.as_millis() as u64,
            elapsed_ms: self.started.map_or(waited, |at| at.elapsed().max(waited)).as_millis() as u64,
        })
    }

    pub(crate) fn moved_on_from(&self) -> &[crate::audit::EarlierAttempt] {
        &self.moved_on_from
    }

    pub(crate) fn into_moved_on_from(self) -> Vec<crate::audit::EarlierAttempt> {
        self.moved_on_from
    }
}

/// Account for one forward attempt at `target` that failed with `error` after
/// waiting `waited` for capacity: the breaker hears what it says about the
/// replica, the row would name it as the upstream last attempted, and the
/// attempt log holds it as the one under way. The ONE place a failed attempt
/// is recorded, for every forward loop. True when another replica of the same
/// route may still answer; false when the route's slot is settled.
pub(crate) fn record_failed_attempt(
    state: &AppState,
    tenant_id: uuid::Uuid,
    target: &routing::UpstreamTarget,
    error: &AppError,
    waited: std::time::Duration,
    attempted: &mut AttemptedUpstream,
    attempts: &mut AttemptLog,
) -> bool {
    note_forward_outcome(state, tenant_id, target, Err(error));
    *attempted = AttemptedUpstream::failed_at(target, error);
    attempts.failed(target, error, waited);
    routing::another_replica_may_answer(error)
}

/// Put a route's targets in health order: a replica whose breaker is open goes
/// behind its healthy siblings, or — once its cooldown has elapsed — to the
/// front as the single half-open trial. Fail-open: an all-tripped list keeps its
/// order, so the breaker never removes the last target. Only worth doing with a
/// real choice; [`note_forward_outcome`] still runs for a lone target, so a dead
/// single-target server still raises an operator notification.
///
/// Every path that forwards to a routed target list reorders here AND reports
/// each attempt through [`note_forward_outcome`]: a trial this claims is
/// resolved only by that report.
pub(crate) fn order_by_health(
    state: &AppState,
    targets: Vec<routing::UpstreamTarget>,
) -> Vec<routing::UpstreamTarget> {
    if !state.circuit_breaker.enabled() || targets.len() < 2 {
        return targets;
    }
    let keys: Vec<String> = targets.iter().map(routing::UpstreamTarget::breaker_key).collect();
    let order = state.circuit_breaker.order_targets(&keys);
    order.into_iter().map(|i| targets[i].clone()).collect()
}

/// What one forward attempt says about the replica it was sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplicaSignal {
    /// It answered — with a success or an error status.
    Answered,
    /// Nothing answered: the connection failed or no reply came in time.
    Unreachable,
    /// The attempt failed before anything reached the replica — its credential
    /// could not be minted, the request could not be built. Says nothing about
    /// the replica, so the breaker hears nothing.
    NotReached,
}

impl ReplicaSignal {
    pub(crate) fn of(outcome: Result<(), &AppError>) -> Self {
        match outcome {
            Ok(()) | Err(AppError::Upstream { .. }) => Self::Answered,
            Err(AppError::UpstreamUnreachable { .. }) => Self::Unreachable,
            Err(_) => Self::NotReached,
        }
    }
}

/// Report what one forward attempt to a target did to the breaker, and raise
/// the operator notification when that opens or closes it.
///
/// Only a failure with NO answer (refused, DNS, TLS, timeout) counts toward
/// tripping: an error status means the server answered, which is reachable,
/// and a failure before the request left says nothing about the replica — a
/// cloud credential that cannot be refreshed must not take a healthy replica
/// out of rotation. A replica answering "model not found" is reported
/// separately.
pub(crate) fn note_forward_outcome(
    state: &AppState,
    tenant_id: uuid::Uuid,
    target: &routing::UpstreamTarget,
    outcome: Result<(), &AppError>,
) {
    let breaker_key = target.breaker_key();
    let signal = ReplicaSignal::of(outcome);
    // Reached — answered or not — so this gateway routes there: the heartbeat
    // states it (`CircuitBreaker::endpoint_states`).
    if signal != ReplicaSignal::NotReached
        && let Some(endpoint_id) = target.endpoint_id
    {
        state.circuit_breaker.note_reached(&breaker_key, tenant_id, endpoint_id, &target.url);
    }
    let transition = match signal {
        ReplicaSignal::Answered => state.circuit_breaker.record_reachable(&breaker_key),
        ReplicaSignal::Unreachable => state.circuit_breaker.record_failure(&breaker_key),
        ReplicaSignal::NotReached => None,
    };
    if let Some(tr) = transition {
        let reason = match (tr, outcome) {
            (health::Transition::Opened { .. }, Err(e)) => e.to_string(),
            _ => "recovered".to_string(),
        };
        emit_health_transition(state, tenant_id, target, tr, &reason);
    }
    if let Err(e) = outcome
        && routing::is_model_not_served(e)
    {
        emit_model_missing(state, tenant_id, target);
    }
}

/// Forward a circuit-breaker health transition to admin (best-effort) so it can
/// become an operator notification. Dropped when no edge channel is wired (tests)
/// or the bounded channel is full — a lost transition self-heals on the next one.
fn emit_health_transition(
    state: &AppState,
    tenant_id: uuid::Uuid,
    target: &routing::UpstreamTarget,
    transition: health::Transition,
    reason: &str,
) {
    let Some(tx) = &state.health_event_tx else {
        return;
    };
    let (new_status, episode_epoch) = match transition {
        health::Transition::Opened { episode_epoch } => ("down", episode_epoch),
        health::Transition::Recovered { episode_epoch } => ("up", episode_epoch),
    };
    let event = health::HealthTransitionEvent {
        tenant_id,
        upstream_server_id: target.upstream_server_id.clone(),
        endpoint_id: target.endpoint_id,
        endpoint_url: target.endpoint_id.map(|_| target.url.clone()),
        provider: target.provider.clone(),
        model: target.model.clone(),
        new_status: new_status.to_string(),
        reason: reason.to_string(),
        episode_epoch,
    };
    let _ = tx.try_send(health::EdgeHealthEvent::Transition(event));
}

/// Report a replica endpoint that answered "model not found" (best-effort,
/// at most once per endpoint and model every few minutes per process).
pub(crate) fn emit_model_missing(state: &AppState, tenant_id: uuid::Uuid, target: &routing::UpstreamTarget) {
    let Some(endpoint_id) = target.endpoint_id else {
        return;
    };
    if !routing::model_missing_due(endpoint_id, &target.model) {
        return;
    }
    tracing::warn!(
        %endpoint_id, url = %target.url, model = %target.model,
        "replica endpoint does not serve the model it was sent — trying the next endpoint"
    );
    if let Some(tx) = &state.health_event_tx {
        let _ = tx.try_send(health::EdgeHealthEvent::ModelMissing(health::EndpointModelMissing {
            tenant_id,
            endpoint_id,
            url: target.url.clone(),
            model: target.model.clone(),
        }));
    }
}
/// What an output token costs this request's fairness counter relative to an
/// input token. Generating is the scarce work, so it is weighted by the model's
/// own price ratio where there is one; an unpriced model uses the ratio the
/// major providers charge.
fn output_token_weight(target: &routing::UpstreamTarget) -> f64 {
    const UNPRICED_OUTPUT_WEIGHT: f64 = 2.0;
    // The tiering basis does not matter here: this is a ratio between two rates
    // of the same request, and a tiered rate resolves at its base price.
    let rate = |unit| target.pricing.units.get(&unit).map(|r: &crate::pricing::Rate| r.resolve(0));
    match (rate(crate::pricing::Unit::InputToken), rate(crate::pricing::Unit::OutputToken)) {
        (Some(input), Some(output)) if input > 0.0 && output > 0.0 => output / input,
        _ => UNPRICED_OUTPUT_WEIGHT,
    }
}

/// Turn a refusal from the gate into the answer the caller gets. Every one of
/// them is "come back later", so every one carries how long to wait.
fn saturated_error(
    refusal: dispatch_gate::GateRefusal,
    hold: std::time::Duration,
) -> AppError {
    let message = match refusal {
        dispatch_gate::GateRefusal::Shed => {
            "the model is busy and this request's priority class is not queued"
        }
        dispatch_gate::GateRefusal::Timeout => "the model is busy; no capacity came free in time",
        dispatch_gate::GateRefusal::Overloaded => {
            "the gateway is already holding as many requests as it may for this model"
        }
        dispatch_gate::GateRefusal::ShuttingDown => {
            "this gateway replica is shutting down and started no new upstream work"
        }
        dispatch_gate::GateRefusal::Superseded => {
            "the same request was sent again while this one waited, and waits in its place"
        }
    };
    AppError::Saturated {
        message: message.to_string(),
        reason: refusal.as_str(),
        // How long this request's own class was willing to wait, which is the
        // closest thing to an answer anyone has: nobody knows when capacity
        // returns, and quoting the deployment's ceiling would tell a caller
        // refused after 150 ms to come back in ten minutes. Never shorter
        // than a second — `Retry-After` has no finer unit. A shutdown is the
        // exception: this replica is going away, a sibling can answer now, and
        // telling a rolling restart's callers to wait would turn an ordinary
        // deploy into a stall.
        retry_after_secs: match refusal {
            dispatch_gate::GateRefusal::ShuttingDown => 1,
            _ => hold.as_secs().max(1),
        },
    }
}


/// Main proxy handler — receives client request, transforms, forwards upstream, streams back.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let http_version = req.version();
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query_credential = gemini_query_credential(&path, parts.uri.query());
    proxy_handler_inner(state, parts.headers, path, body, http_version, None, None, query_credential)
        .await
}

/// The `?key=` credential, read only where a spec puts one there.
///
/// The PATH decides — the same discriminator [`ApiVersion::from_path`] uses,
/// and the only one available before a byte of the body is read. A request's
/// body never decides a protocol, and this must not become a header sniff
/// either: Gemini's spec asks for this channel, so Gemini's surface gets it.
///
/// `/v1/chat/completions?key=…` is deliberately NOT a credential. Neither the
/// OpenAI nor the Anthropic spec defines a query channel, and a secret that may
/// ride a URL — through every access log, proxy and browser history on the way
/// — should reach exactly the surface whose own documentation put it there and
/// no other.
fn gemini_query_credential(path: &str, query: Option<&str>) -> Option<String> {
    (ApiVersion::from_path(path) == ApiVersion::GoogleGemini)
        .then(|| auth::key_query_param(query))
        .flatten()
        .map(str::to_string)
}

/// BYOK forward-auth proxy handler.
///
/// Extracts the virtual key from the URL path (`/fwd/{key}/v1/...`) for proxy auth,
/// and preserves the client's `Authorization`/`x-api-key` header for upstream forwarding.
pub async fn fwd_proxy_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    fwd_proxy_with_key(state, key, req).await
}

/// BYOK forward-auth handler for the Gemini surface
/// (`/fwd/{key}/v1beta/models/{*gemini_path}`). That route carries TWO path
/// params (the key + the catch-all gemini path, which may itself contain `/`
/// for slash-bearing model ids like `openrouter/free`), so it needs a 2-tuple
/// `Path` extractor — the single-param `fwd_proxy_handler` extractor would 500
/// with an arity mismatch. The gemini path is read from the URI downstream, so
/// the captured segment is discarded here.
pub async fn fwd_gemini_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((key, _gemini_path)): axum::extract::Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    fwd_proxy_with_key(state, key, req).await
}

/// Shared BYOK forward-auth body: authenticate by the path `key`, preserve the
/// client's credential (header or Gemini `?key=`) for upstream forwarding.
async fn fwd_proxy_with_key(
    state: Arc<AppState>,
    key: String,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let http_version = req.version();
    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let path = parts.uri.path().to_string();

    // Extract the client's original credential (header, or Gemini's `?key=`
    // query param) — forwarded to the upstream.
    let fwd_auth = extract_forward_auth_context(&headers, parts.uri.query())?;

    // Authenticate using the path key.
    // The registry guard is released here, never held across an error audit.
    let authenticated = auth::authenticate_forward(&key, &state.tenant_registry.load());
    let ctx = match authenticated {
        Ok(c) => c,
        Err(e) => {
            let prefix = auth::credential_prefix(&key, 6);
            tracing::warn!(key_prefix = %prefix, "fwd auth failed");
            return Err(e);
        }
    };

    // No gateway credential from the query: BYOK authenticates from the path
    // key, and a `?key=` on this mount is the client's own UPSTREAM credential,
    // already captured above as `fwd_auth`. Offering it as a gateway credential
    // would try to authenticate a provider's key against our own key table.
    proxy_handler_inner(state, headers, path, body, http_version, Some(fwd_auth), Some(ctx), None)
        .await
}

/// Extract the client's credential as a `ForwardAuthContext` for BYOK
/// forwarding — from a request header, or (Gemini's native auth) the `?key=`
/// query parameter, which is normalized to the `x-goog-api-key` header so the
/// upstream re-emission needs no query-param special case.
fn extract_forward_auth_context(
    headers: &axum::http::HeaderMap,
    query: Option<&str>,
) -> Result<ForwardAuthContext, AppError> {
    // Try Authorization: Bearer first
    if let Some(header) = headers.get("authorization")
        && let Ok(value) = header.to_str()
        && !value.is_empty()
    {
        return Ok(ForwardAuthContext {
            header_name: "authorization".to_string(),
            header_value: value.to_string(),
        });
    }
    // Fall back to x-api-key
    if let Some(header) = headers.get("x-api-key")
        && let Ok(value) = header.to_str()
        && !value.is_empty()
    {
        return Ok(ForwardAuthContext {
            header_name: "x-api-key".to_string(),
            header_value: value.to_string(),
        });
    }
    // Fall back to x-goog-api-key (Google Gemini)
    if let Some(header) = headers.get("x-goog-api-key")
        && let Ok(value) = header.to_str()
        && !value.is_empty()
    {
        return Ok(ForwardAuthContext {
            header_name: "x-goog-api-key".to_string(),
            header_value: value.to_string(),
        });
    }
    // Fall back to Gemini's `?key=<API_KEY>` query parameter (the gemini CLI /
    // SDK's native auth) — normalize it to the `x-goog-api-key` header, which the
    // Gemini upstream accepts and the re-emission already handles.
    if let Some(value) = auth::key_query_param(query) {
        return Ok(ForwardAuthContext {
            header_name: "x-goog-api-key".to_string(),
            header_value: value.to_string(),
        });
    }
    Err(AppError::Auth(crate::error::AuthError::MissingHeader))
}

/// Shared proxy handler implementation.
///
/// `query_credential` is the already-extracted `?key=` credential, or `None`.
/// It arrives extracted rather than as a raw query string on purpose: the query
/// carries a live key, and `path` — which every log line, audit record and
/// routing decision below reads — must stay free of it.
#[allow(clippy::too_many_arguments)]
async fn proxy_handler_inner(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    path: String,
    body: Body,
    http_version: axum::http::Version,
    fwd_auth: Option<ForwardAuthContext>,
    pre_authenticated: Option<TenantRequestCtx>,
    query_credential: Option<String>,
) -> Result<Response, AppError> {
    // Generate request ID early so all error paths can use it.
    let request_id = crate::ids::mint_request_id();

    // Track request stats (atomic, zero overhead).
    let proxy_start = std::time::Instant::now();
    state.proxy_stats.inc_requests();
    if http_version == axum::http::Version::HTTP_2 {
        state.proxy_stats.inc_http2();
    } else {
        state.proxy_stats.inc_http11();
    }

    // Log path with key redacted for /fwd/ routes.
    let log_path = if path.starts_with("/fwd/") {
        // /fwd/{key}/v1/... → /fwd/[redacted]/v1/...
        if let Some(rest) = path.splitn(4, '/').nth(3) {
            format!("/fwd/[redacted]/{rest}")
        } else {
            "/fwd/[redacted]".to_string()
        }
    } else {
        path.clone()
    };
    tracing::info!(path = %log_path, "proxy_handler invoked");

    // 3. Detect client API version from path (needed for error audit records)
    let client_api_version = ApiVersion::from_path(&path);

    // Error audit context — enriched incrementally as more info becomes available.
    let mut err_ctx = ErrorAuditContext {
        queue_wait_ms: 0,
        qos_class_id: None,
        spilled: false,
        request_id,
        user_id: uuid::Uuid::nil(),
        // Default to SYSTEM tenant for pre-auth errors. With RLS, nil UUID
        // records would be invisible to all tenants.
        tenant_id: uuid::Uuid::from_u128(1),
        workspace_id: uuid::Uuid::nil(),
        key_id: None,
        model_requested: "",
        model_used: None,
        provider: None,
        app_id: None,
        detection_method: None,
        user_agent: None,
        api_version: client_api_version,
        embedding_cost: 0.0,
        embedding_tokens: 0,
        embedding_priced: true,
        cache_audit: None,
        cache_badges: Vec::new(),
        attempted: AttemptedUpstream::default(),
        pool_wait_ms: 0,
        attempts: AttemptLog::default(),
    };

    // 1. Auth — the fwd handler's, or the header's. The key and its tenant's
    // configuration come from ONE registry load: from here, ONLY ctx.config.*
    // and ctx.user.* are read.
    let ctx = if let Some(ctx) = pre_authenticated {
        ctx
    } else {
        let bearer = match auth::extract_api_token(&headers)
            .or_else(|missing| query_credential.ok_or(missing))
        {
            Ok(b) => b,
            Err(e) => {
                send_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        };
        let authenticated = auth::authenticate_proxy(&bearer, &state.tenant_registry.load());
        match authenticated {
            Ok(c) => c,
            Err(e) => {
                send_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        }
    };

    // Enrich context with user info.
    err_ctx.user_id = ctx.user.user_id;
    err_ctx.tenant_id = ctx.user.tenant_id;
    err_ctx.workspace_id = ctx.user.workspace_id;
    err_ctx.key_id = ctx.user.key_id;

    // 2. Rate limit check (RPM + TPM). A bucket with no configured cap (the
    // unlimited default) short-circuits inside the check, so these run for every
    // request — enforcement happens iff a workspace/user cap is set.
    {
        if let Err(e) = crate::middleware::rate_limit::check_rate_limit(&ctx.user, &state.usage) {
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
        if let Err(e) = crate::middleware::rate_limit::check_tpm_limit(&ctx.user, &state.usage) {
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }

        // Budget check (daily + monthly)
        if let Err(e) = crate::middleware::rate_limit::check_budget(
            &ctx.user,
            &state.usage,
            ctx.config.pricing.accounting_currency,
        ) {
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    }

    // 4. Buffer and parse request body
    let body_bytes = match axum::body::to_bytes(body, core_settings().max_body_size).await {
        Ok(b) => b,
        Err(e) => {
            let err = AppError::BadRequest(format!("failed to read body: {e}"));
            send_error_audit(&state, &err_ctx, &err).await;
            state.proxy_stats.inc_errors();
            return Err(err);
        }
    };

    let mut api_request = match ApiRequest::parse(client_api_version, &body_bytes) {
        Ok(r) => r,
        Err(e) => {
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    // Gemini: extract model from URL path and streaming from path suffix.
    // Path format: /v1beta/models/{model}:generateContent or :streamGenerateContent
    // BYOK: /fwd/{key}/v1beta/models/{model}:generateContent
    if let ApiRequest::GoogleGemini(ref mut gemini_req) = api_request {
        if let Some(models_idx) = path.find("/models/") {
            let after_models = &path[models_idx + 8..];
            let model_name = after_models
                .split(':')
                .next()
                .unwrap_or("gemini-2.5-flash");
            gemini_req.model = model_name.to_string();
        }
        gemini_req.stream = Some(path.contains("streamGenerateContent"));
    }

    let model_requested = api_request.model().to_string();

    // Reject an oversized model identifier before routing or any audit write.
    // This covers all model-resolution outcomes with one check — BYOK pass-through
    // (forwarded verbatim), an unknown model (the routing `ModelNotFound` path,
    // which writes an error-audit row below), and curated traffic. The check sits
    // before `err_ctx.model_requested` is set so the rejection's own error-audit
    // row never stores the oversized value.
    if model_requested.len() > MAX_MODEL_NAME_LEN {
        let e = AppError::BadRequest(format!(
            "model name exceeds {MAX_MODEL_NAME_LEN} bytes"
        ));
        send_error_audit(&state, &err_ctx, &e).await;
        state.proxy_stats.inc_errors();
        return Err(e);
    }

    // `extract_request_content` runs regardless of content logging — its captured
    // content is emitted to the audit row only when logging is on (below); when
    // off the content is dropped and only the session id and the app are kept.
    // Routing does not mutate the request, so the captured pre-transform content
    // is the client's request verbatim.
    let pre_content = content::extract_request_content(&api_request, body_bytes.len());

    // 6. Extract attribution (needs config for app_patterns). A request no header
    //    named is named by its system prompt's opening — before anything reads the
    //    app, so the audit row and an app-scoped tool rule agree.
    let mut attr = attribution::extract_attribution(&headers, ctx.user.user_id, &ctx.config.app_patterns, ctx.user.inline_ai);
    attr.classify_by_system_prompt(pre_content.system_prompt.as_deref(), &ctx.config.app_patterns);

    // Enrich error context with model + app info now available.
    err_ctx.model_requested = &model_requested;
    err_ctx.app_id = attr.app_id.as_deref();
    err_ctx.detection_method = attr.detection_method.as_deref();
    err_ctx.user_agent = attr.user_agent.as_deref();

    // 7. Determine the conversation session up front so it can pin upstream
    //    selection — ALWAYS, regardless of content logging, since routing affinity
    //    does not depend on logging. Most clients send no `X-Session-Id`, so
    //    `SessionDetector::detect` rebuilds the session from the conversation's
    //    content prefix; every turn resolves to the same session id, so a
    //    multi-target alias hashes each turn to the SAME upstream and the
    //    provider's prompt cache keeps hitting across turns. This detection
    //    result is reused for audit/session-linkage below so detection runs
    //    exactly once per request.
    let key_id = ctx.user.key_id.unwrap_or(uuid::Uuid::nil());
    // What makes a later request this same one sent again: read by the
    // detector (a re-send is the same turn) and the dispatch gate (it replaces
    // its waiting copy). Taken from the request as the client sent it.
    let request_key = content::request_key(
        ctx.user.user_id,
        key_id,
        attr.session_id.as_deref(),
        client_api_version.as_str(),
        api_request.model(),
        api_request.is_streaming(),
        &body_bytes,
    );
    // `session_hashes` (whole volatile messages dropped) drives detection; the
    // link hashes ride the audit record, and the edge names each stored message
    // by the hash of its own bytes (`stored_message_key`), never by these.
    // Served from here until the request is over by any path: a copy of it
    // arriving meanwhile is this turn again (`SessionDetector::detect_serving`).
    let (session_info, serving) = state.session_detector.detect_serving(
        ctx.user.user_id,
        key_id,
        ctx.user.tenant_id,
        &pre_content.session_hashes,
        attr.session_id.as_deref(),
        request_key,
    );
    // Every request is routed with its session as the affinity key, so each
    // route's replicas come out in that session's rendezvous order (the
    // breaker moves an unhealthy one behind the rest). The dispatch gate relies
    // on it — invariant to preserve: the first replica of a route is the one
    // routing prefers for the session, and the gate is told it by id
    // (`GateRequest::preferred`) and passes a held request over for another
    // engine on that basis.
    let session_affinity = session_info.session_id.to_string();
    let affinity = Some(session_affinity.as_str());

    // 7a. Resolve upstream targets for LB/failover (primary + fallbacks),
    //     session-pinned via `affinity` (only multi-target aliases are affected).
    let resolved = routing::origin_host(&headers, &ctx.user).and_then(|origin_host| {
        routing::resolve_all_upstreams(&api_request, &ctx.user, &ctx.config.credentials, &state.lb_counters, affinity, client_api_version, origin_host, &ctx.config.endpoints)
    });
    let mut all_targets = match resolved {
        Ok(t) => t,
        Err(e) => {
            let e = e.for_model(err_ctx.model_requested);
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    // The request's QoS class: the key's own, clamped to its workspace unless an
    // admin elevated it, else the workspace's, else the tenant default. Nothing
    // in the request influences it.
    let qos_class = ctx
        .config
        .qos
        .effective_class(ctx.user.workspace_id, ctx.user.qos_class_id, ctx.user.qos_class_elevated)
        .cloned();

    // A route target may accept only some classes — that is how "background work
    // never overflows to the paid provider" is expressed. Dropping the target
    // here, before anything is tried, keeps the decision in one place; a target
    // that names no class accepts every one. If the restrictions leave nothing,
    // the targets are left as they are: refusing the request outright would make
    // a misconfigured restriction an outage, and the alias still has somewhere to
    // send it.
    if let Some(class) = &qos_class {
        let allowed: Vec<routing::UpstreamTarget> = all_targets
            .iter()
            .filter(|t| t.route_id.is_none_or(|r| ctx.config.qos.route_accepts(r, class.id)))
            .cloned()
            .collect();
        if !allowed.is_empty() {
            all_targets = allowed;
        } else {
            tracing::warn!(
                class = %class.name,
                "every target of this alias refuses the request's class; serving anyway"
            );
        }
    }

    // 7a. Circuit breaker: reorder by upstream-server health so a server that has
    //     stopped responding is tried after a healthy sibling (or, once cooldown
    //     elapses, promoted to a single half-open trial at the front). Fail-open:
    //     an all-tripped alias keeps its original order — the breaker never drops
    //     the last target. Only worth doing with a real choice (>1 target); the
    //     per-attempt record/recover below still runs for a lone target so a dead
    //     single-target server still raises an operator notification.
    all_targets = order_by_health(&state, all_targets);
    // 7b. Capability-aware target selection. Whether a target can serve this
    //     request is a property of the (request, target) pair, so a chain member
    //     that cannot serve it is no fallback for it either: keep only the
    //     targets that can, in the order priority / weighted RR / the breaker
    //     already put them in, and let the forward loop fail over among those.
    //     Each target is validated exactly once, so a single-target alias pays
    //     the one check it always did.
    let mut capable = Vec::with_capacity(all_targets.len());
    // The head is what routing chose. Keeping it — and its refusal — means a
    // request NO target can serve still fails with exactly the error, and the
    // error row, it produced when only the head was ever checked.
    let mut displaced_primary: Option<routing::UpstreamTarget> = None;
    let mut primary_refusal: Option<AppError> = None;
    for (i, target) in std::mem::take(&mut all_targets).into_iter().enumerate() {
        match crate::pipeline::capabilities::validate_capabilities(
            &api_request,
            &target.capabilities,
            target.chat_dialect(),
        ) {
            Ok(()) => capable.push(target),
            Err(e) if i == 0 => {
                displaced_primary = Some(target);
                primary_refusal = Some(e);
            }
            Err(_) => {}
        }
    }
    all_targets = capable;

    let upstream_target = match all_targets.first() {
        Some(t) => t.clone(),
        None => {
            if let Some(head) = &displaced_primary {
                err_ctx.model_used = Some(&head.model);
                err_ctx.provider = Some(&head.provider);
            }
            // No capable target: the head's own refusal when routing produced a
            // chain, `ModelNotFound` when it produced none.
            let e = primary_refusal
                .unwrap_or_else(|| AppError::ModelNotFound("no upstream target available".into()));
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };

    // A displaced primary is a routing decision no operator configured, so it is
    // badged below (the badge builder does not exist this early) — otherwise the
    // audit row would show a model the alias's own ordering never chose, with
    // nothing to say why.
    let capability_reroute = match (&displaced_primary, &primary_refusal) {
        (Some(head), Some(AppError::BadRequest(reason))) => {
            Some((head.model.clone(), reason.clone()))
        }
        (Some(head), Some(e)) => Some((head.model.clone(), e.to_string())),
        _ => None,
    };

    let upstream_api_version = upstream_target.upstream_api_version;

    // Enrich error context with upstream info now available.
    err_ctx.model_used = Some(&upstream_target.model);
    err_ctx.provider = Some(&upstream_target.provider);

    // Determine if protocol translation is needed
    let needs_translation = client_api_version != upstream_api_version;

    // 7d. Inbound mixed-pending splice. When the prior request in this
    // session emitted both real and intercepted `tool_use` blocks in one
    // round, the agent loop dispatched the intercepted call and parked the
    // result in `state.mixed_pending_cache`. Drain those entries here and
    // append a synthesised `assistant tool_use → user tool_result` pair to
    // the conversation so the model sees what it asked for. No-op when the
    // cache is empty for this session (the typical case).
    let mixed_pending_splice_outcome =
        crate::pipeline::mixed_pending_splice::apply_inbound_mixed_pending_splice(
            &mut api_request,
            &state.mixed_pending_cache,
            ctx.user.tenant_id,
            ctx.user.user_id,
            attr.session_id.as_deref(),
            client_api_version,
        );

    // 8. Apply request transforms (model rewrite, scripts, etc.)
    // Transform diffs are captured whenever content logging is on — there is no
    // separate toggle (the diff lives in the buffered-content path anyway).
    let capture_diffs = ctx.config.content_logging_enabled;
    // Tenant rules + transforms with the request's workspace overrides layered on.
    let effective_tool_rules = ctx.config.effective_tool_rules(ctx.user.workspace_id);
    let effective_transforms = ctx.config.effective_transforms(ctx.user.workspace_id);
    // Request phase: the transform chain followed by the inbound-prompt
    // injection guardrail (P1/P2 — opt-in via `guardrail.scan_inbound`, a
    // no-op otherwise; enforce mode replaces a flagged user message / folded
    // tool-result with a placeholder before the model sees it). One shared
    // entry point with the out-of-band `/v1/analyze` RPC so both apply
    // identical policy in identical order.
    let mut phase = match crate::pipeline::run_request_phase(
        &mut api_request,
        &ctx.user,
        &state.script_engine,
        &effective_transforms,
        ctx.config.effective_guardrail(ctx.user.workspace_id),
        attr.app_id.as_deref(),
        upstream_target.context_window,
        Some(&upstream_target.provider),
        needs_translation,
        capture_diffs,
        &effective_tool_rules,
        Some(&ctx.config.tool_field_profiles),
        Some(&ctx.config.mcp),
        ctx.config.sanitize_tool_names,
        ctx.config.rhai_fail_mode_enum(),
        // The splice rebuilds the request after its content was extracted:
        // the extracted keys no longer name its items.
        (mixed_pending_splice_outcome.spliced_count == 0 && mixed_pending_splice_outcome.failed_count == 0)
            .then_some(&pre_content),
        Some(session_info.session_id),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            send_error_audit(&state, &err_ctx, &e).await;
            state.proxy_stats.inc_errors();
            return Err(e);
        }
    };
    let mut badges = phase.merged_badges();
    let transform_result = phase.transform;
    let mut program_outcomes = transform_result.program_outcomes;
    let flags = transform_result.flags;
    let mut injection_blocks = transform_result.injection_blocks;
    let intercept_bindings = transform_result.intercept_bindings;
    let withheld_tools = transform_result.withheld_tools;
    // Per-message guardrail findings (anchored by reverse message index) so the
    // session / audit trace can render a banner on the exact flagged message.
    let inbound_guardrail_steps = phase.guardrail.steps;

    // Tag a capability-driven reroute, so the row records which model the alias
    // chose and why it is not the one that answered.
    if let Some((from, reason)) = capability_reroute {
        badges.add_capability_rerouted(from, reason);
    }

    // Surface inbound mixed-pending splice on the audit row: one
    // `WebSubstitutionMixedPendingSpliced` badge plus per-entry
    // `mixed_pending_splice` injection blocks. Pairs with the
    // `WebSubstitutionMixedPending` badge on the prior request that
    // parked the result. The failed-splice path emits a separate badge
    // (`MixedPendingSpliceFailed`) so an operator can distinguish folded-in
    // from data-loss outcomes; the per-entry injection blocks use a
    // distinct `action` so the audit trail stays unambiguous.
    if mixed_pending_splice_outcome.spliced_count > 0 {
        badges.add(crate::audit::badge::AuditBadge::WebSubstitutionMixedPendingSpliced {
            count: mixed_pending_splice_outcome.spliced_count,
        });
        badges.add_modified();
    }
    if mixed_pending_splice_outcome.failed_count > 0 {
        badges.add(crate::audit::badge::AuditBadge::WebSubstitutionMixedPendingSpliceFailed {
            count: mixed_pending_splice_outcome.failed_count,
        });
    }
    if !mixed_pending_splice_outcome.injection_blocks.is_empty() {
        injection_blocks.extend(mixed_pending_splice_outcome.injection_blocks);
    }

    // Track whether the model-clamp added an injection_block so we can
    // honour the "Modified once when something changed" gold-standard rule
    // even for non-script-driven changes downstream of `transform_request`.

    // Ensure the model in the request body matches the resolved upstream model.
    api_request.set_model(upstream_target.model.clone());

    // Clamp client max_tokens to upstream's max_output_tokens if it exceeds it.
    if let Some(upstream_max) = upstream_target.max_output_tokens
        && let Some(client_max) = api_request.max_tokens()
            && client_max > upstream_max as u32 {
                api_request.set_max_tokens(upstream_max as u32);
                injection_blocks.push(content::InjectionBlock {
                    transform: "max_tokens_clamp".to_string(),
                    scope: "params".to_string(),
                    field: "max_tokens".to_string(),
                    action: "clamp".to_string(),
                    content: format!("{client_max} → {upstream_max}"),
                });
                // Mirror the in-pipeline gating: any injection block triggers
                // the unified `Modified` chip.
                badges.add_modified();
            }

    let is_streaming = api_request.is_streaming();

    // 8b. Record the turn for the next turn's content-prefix match — ALWAYS
    // (in-memory only), so content-rebuilt session affinity keeps working even
    // when content logging is off. `session_info` was detected ahead of routing
    // (above) and is reused here so detection runs exactly once per request.
    let mut is_baseline = session_info.is_baseline;
    if flags.compression_applied {
        is_baseline = true;
    }
    let final_info = content::SessionInfo {
        session_id: session_info.session_id,
        parent_request_id: session_info.parent_request_id,
        turn_number: session_info.turn_number,
        is_baseline,
    };
    state.session_detector.record(
        ctx.user.user_id,
        key_id,
        request_id,
        &final_info,
        pre_content.session_hashes.clone(),
        attr.session_id.clone(),
    );

    // Emit the captured request content + transform diff to the audit row only
    // when content logging is on; the session id and linkage above are computed
    // regardless (routing needs the id; the next turn's prefix match needs the
    // recorded turn). `telemetry_dropped` is populated AFTER the forward loop so
    // it reflects the actual target used (failover may land on a different
    // protocol than the primary). Seed with an empty vec here.
    let mut content_meta = if ctx.config.content_logging_enabled {
        let ib = if injection_blocks.is_empty() { None } else { Some(injection_blocks) };
        let bt = if transform_result.blocked_tools.is_empty() { None } else { Some(transform_result.blocked_tools) };
        let rtr = if transform_result.redacted_tool_results.is_empty() { None } else { Some(transform_result.redacted_tool_results) };
        let (transform_diff, effective_tools) = content::build_transform_diff(
            &pre_content,
            &api_request,
            program_outcomes.clone(),
            flags.system_prompt_modified,
            flags.tools_modified,
            transform_result.step_diffs,
            ib,
            bt,
            rtr,
            if inbound_guardrail_steps.is_empty() { None } else { Some(inbound_guardrail_steps) },
            Vec::new(), // telemetry_dropped — populated post-forward (see below)
        );
        Some(ContentMeta {
            request_messages_json: pre_content.messages_json,
            media_scan_needed: pre_content.media_scan_needed,
            request_tools: pre_content.tools,
            effective_tools,
            request_params: pre_content.params,
            system_prompt: pre_content.system_prompt,
            transform_diff: serde_json::to_value(&transform_diff).ok(),
            link_hashes: pre_content.link_hashes,
            session_info: final_info,
            request_size_bytes: pre_content.request_size_bytes,
            first_user_prompt: pre_content.first_user_prompt,
        })
    } else {
        None
    };

    // 8c. Response-cache lookup.
    //
    // Placed here on purpose: after transforms and the inbound guardrail (so a
    // blocked prompt never reaches the cache and the key covers the *transformed*
    // request), after session detection and content capture (so a hit is audited
    // and linked exactly like a proxied turn), and before the upstream call.
    // Costs nothing on an alias with no cache preset — no key is built.
    let mut cache_ctx = response_cache::request_context(
        &state.response_cache,
        &ctx.config,
        &upstream_target,
        &api_request,
        ctx.user.tenant_id,
        ctx.user.workspace_id,
        ctx.user.user_id,
        &headers,
        // The response-shaping policy is part of the answer's identity: a stored
        // body already had these programs applied, and a hit does not re-run
        // them.
        &ctx.config.effective_transforms(ctx.user.workspace_id),
    );
    // Second stage, for a semantic alias only: embed this prompt and look for a
    // near-match behind the same exact prefix guard. Deliberately after the
    // exact lookup above — a repeated identical request is answered without ever
    // calling the embedding model.
    if let Some(c) = &mut cache_ctx {
        response_cache::semantic_lookup(
            &state,
            &ctx.user,
            &ctx.config,
            &upstream_target,
            c,
        )
        .await;
    }
    let cache_ctx = cache_ctx;
    let cache_hit = cache_ctx.as_ref().and_then(|c| c.served.clone());
    if let Some(c) = &cache_ctx {
        let cache_badges = c.badges();
        // Carry the cache outcome into the error context too: every failure from
        // here on writes an error row instead of a finalized one, and without
        // this the spend and the reason for it would disappear with the failure.
        err_ctx.embedding_cost = c.embedding_cost;
        err_ctx.embedding_tokens = c.embedding_tokens;
        err_ctx.embedding_priced = c.embedding_priced;
        err_ctx.cache_audit = Some(c.audit());
        err_ctx.cache_badges = cache_badges.clone();
        for badge in cache_badges {
            badges.add(badge);
        }
    }

    // 9. Translate request if needed (cross-protocol translation via DomainRequest hub).
    // `primary_not_carried` names what this translation has no channel for; it is
    // read BEFORE the reasoning gate drops anything, so the drop is on the list.
    // Computed on a cache hit too: a hit records what the same request proxied
    // would, so its row names the same drops.
    let mut primary_not_carried: Vec<String> = Vec::new();
    let primary_domain = needs_translation.then(|| {
        let (domain, not_carried) = upstream_target.prepare_translation(&api_request);
        primary_not_carried = not_carried;
        domain
    });
    let (upstream_body, upstream_forward_version) = if cache_hit.is_some() {
        // Served from cache — nothing is forwarded, so skip the translation pass.
        (Bytes::new(), upstream_api_version)
    } else if let Some(domain) = primary_domain {
        match domain.translate_to(upstream_api_version, &upstream_target.model, upstream_target.chat_cap_field()) {
            Ok(pair) => pair,
            Err(e) => {
                send_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        }
    } else {
        match api_request.serialize() {
            Ok(b) => (b, upstream_api_version),
            Err(e) => {
                send_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
        }
    };

    // 10. Check if debug echo is requested
    let debug_echo = ctx.config.debug_mode && debug_echo::is_debug_echo_requested(&headers);

    // Record proxy processing overhead (auth + transforms + routing).
    //
    // A semantic cache lookup calls an embedding upstream from inside this
    // window; that wait is a third party's latency, not the gateway's, so it is
    // taken back out. Leaving it in would show a slow embedding provider as a
    // proxy overhead regression — the exact signal operators are told to watch.
    let embed_elapsed = cache_ctx
        .as_ref()
        .map(|c| c.embed_elapsed)
        .unwrap_or_default();
    state.proxy_stats.record_overhead_us(
        proxy_start
            .elapsed()
            .saturating_sub(embed_elapsed)
            .as_micros() as u64,
    );

    // What this request is worth to the fairness order before any answer exists,
    // and what the audit row reports as its input estimate.
    let estimated_input_tokens =
        crate::middleware::tokens::estimate_input_tokens_from_bytes(body_bytes.len(), None);

    // 11. Forward to upstream with multi-target failover.
    //     Try the primary target first (with same-target retries), then rotate
    //     through fallback targets on retriable errors (429/5xx).
    // The start of both latencies: a hold for capacity below counts in them,
    // the gateway's own checks and transforms above do not.
    let request_started_at = std::time::Instant::now();
    // What the request spent waiting for capacity, reported on its own beside
    // the latency it is part of: the engine did not take this long, the queue
    // did.
    let mut queue_wait = std::time::Duration::ZERO;
    // The part of it spent at the pool of the attempt under way. Each attempt
    // the request moves on from keeps its own on `err_ctx.attempts`.
    let mut pool_wait = std::time::Duration::ZERO;
    // The route slots whose session replica the gate has already sent this
    // request away from: it has had its wait for that replica, and a later
    // attempt on the slot (after the replica it went to failed) does not wait
    // for it again. Per slot: a failover target on another server has a
    // session replica of its own, never waited for.
    let mut affinity_spent: std::collections::HashSet<usize> = std::collections::HashSet::new();
    // Held for the life of the attempt: dropping it hands the endpoint slot to
    // whoever the gate decides should have it next.
    let mut gate_permit: Option<dispatch_gate::GatePermit> = None;
    // ONE budget for the request, not one per route target: the gate is asked
    // once per target, and three saturated targets would otherwise hold the
    // caller for three times the wait their class asked for. It counts time
    // spent WAITING, not wall-clock — an upstream's own retries and honoured
    // `Retry-After` are not queue time, and charging them here would hand a
    // fallback target a deadline of zero and refuse it before it was asked.
    let gate_budget = qos_class
        .as_ref()
        .and_then(|c| c.queue_ttl_ms)
        .map(|ms| std::time::Duration::from_millis(u64::from(ms)))
        .unwrap_or(state.dispatch_gate.settings().default_ttl)
        .min(state.dispatch_gate.settings().max_ttl);
    let mut actual_target = upstream_target.clone();
    let mut upstream_response = None;
    let mut last_err = None;
    // Set when the loop rotates off the primary target. The cache key was built
    // from the primary's identity, so an answer produced by a fallback model
    // must NOT be filed under it — that would serve model B's answer to a later
    // request routed to model A.
    let mut failed_over = false;
    // Invocation-preset blocks for the target ACTUALLY forwarded. Reset per
    // attempt (failover-aware) and patched into the audit post-forward, mirroring
    // the `telemetry_dropped` precedent — see the patch block after the loop.
    let mut preset_blocks: Vec<content::InjectionBlock> = Vec::new();

    // Routes whose replica gave an answer no other replica would change (a
    // client error): their remaining replicas are skipped, their fallbacks are
    // not. A set — the breaker reorder can interleave one route's replicas
    // with another route's.
    let mut settled_slots: Vec<usize> = Vec::new();
    // The targets still to try, in order. A queue rather than a plain iteration
    // because the dispatch gate may send this request to a LATER replica of the
    // same route — the one with room — and the replica it skipped has to stay in
    // line rather than be passed over for good.
    let mut pending: std::collections::VecDeque<usize> =
        (0..all_targets.len()).collect();
    // What the current attempt's translation had no channel for; at loop exit it
    // is the answering attempt's — on a cache hit, the primary's.
    let mut attempt_not_carried: Vec<String> = Vec::new();
    // What conforming the current attempt's body to its upstream's Chat
    // dialect changed; at loop exit, the answering attempt's.
    let mut attempt_adapted: Option<crate::api::mistral::Conformed> = None;
    while let Some(mut i) = pending.pop_front() {
        if cache_hit.is_some() {
            // Answer already in hand; no upstream round-trip. The row names
            // what the primary's translation drops, as the miss did. Nothing
            // was forwarded, so nothing was conformed to an upstream's dialect.
            attempt_not_carried.clone_from(&primary_not_carried);
            break;
        }
        let target = &all_targets[i];
        if settled_slots.contains(&target.route_slot) {
            continue;
        }
        // The claim is about THIS attempt, so it starts false on each one. A
        // spilled attempt that fails hands the request straight back to the
        // replica it was routed to, and a slot that gives up hands it to
        // another route entirely — in both cases the attempt that answers went
        // where it was sent, and a claim left over from an earlier one would
        // contradict the row's own `failed_over`.
        err_ctx.spilled = false;
        // Whatever the last attempt held, it is not being used now. Released
        // BEFORE asking for the next slot, or a request failing over would keep
        // the replica it just left out of service for the whole of its wait.
        gate_permit = None;
        // Another endpoint of the primary's route serves the same model: the
        // prepared body goes as it is, and the answer is still the primary's
        // (a spill between replicas is not a failover). For a secondary route
        // target, re-serialize with the new model name.
        let (body, fwd_version): (Bytes, ApiVersion) = if i == 0 {
            attempt_not_carried.clone_from(&primary_not_carried);
            (upstream_body.clone(), upstream_forward_version)
        } else if target.same_route_as(&all_targets[0]) {
            // The flag describes the attempt that answers: back on the
            // primary's route after a fallback failed, the answer is the
            // primary's again.
            actual_target = target.clone();
            failed_over = false;
            attempt_not_carried.clone_from(&primary_not_carried);
            (upstream_body.clone(), upstream_forward_version)
        } else {
            actual_target = target.clone();
            failed_over = true;
            let mut retry_request = api_request.clone();
            retry_request.set_model(target.model.clone());
            let target_api_version = target.upstream_api_version;
            if client_api_version != target_api_version {
                let (domain, not_carried) = target.prepare_translation(&retry_request);
                attempt_not_carried = not_carried;
                match domain.translate_to(target_api_version, &target.model, target.chat_cap_field()) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(target = i, model = %target.model, error = %e, "failed to translate for fallback target");
                        continue;
                    }
                }
            } else {
                attempt_not_carried.clear();
                match retry_request.serialize() {
                    Ok(b) => (b, target_api_version),
                    Err(e) => {
                        tracing::warn!(target = i, model = %target.model, error = %e, "failed to serialize for fallback target");
                        continue;
                    }
                }
            }
        };

        // Force-merge this target's invocation preset onto the already-translated
        // upstream body (preset wins; unset fields pass through). The fragment is
        // authored in the target's own protocol and the body is already in that
        // protocol here, so the merge is a protocol-agnostic JSON deep-merge.
        // `preset_blocks` ends holding the SUCCESSFUL target's blocks (overwritten
        // each attempt, cleared when the target has no preset).
        let body = if target.preset_settings.as_object().is_some_and(|o| !o.is_empty()) {
            match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(mut v) => {
                    let blocks = json_merge::json_force_merge(&mut v, &target.preset_settings);
                    match serde_json::to_vec(&v) {
                        Ok(b) => {
                            preset_blocks = blocks;
                            Bytes::from(b)
                        }
                        Err(e) => {
                            tracing::warn!(target = i, error = %e, "re-serialize after preset merge failed; forwarding unmodified");
                            preset_blocks.clear();
                            body
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(target = i, error = %e, "parse for preset merge failed; forwarding unmodified");
                    preset_blocks.clear();
                    body
                }
            }
        } else {
            preset_blocks.clear();
            body
        };
        // Primary target gets 2 retries; fallback targets get 1. A target with
        // another endpoint of its route still to try gets none: the next
        // attempt goes to that replica rather than to this URL again.
        let spill_next = pending.iter().any(|j| all_targets[*j].same_route_as(target));
        let max_retries = if spill_next {
            0
        } else if target.same_route_as(&all_targets[0]) {
            2
        } else {
            1
        };

        // BYOK credential rule: forward the client's own auth ONLY when the
        // resolved target carries no stored credential of its own (pass-through,
        // or a keyless route). A target WITH a stored credential (e.g. an override
        // route to an on-prem upstream that holds its own key) uses that stored
        // key and the client's credential is NOT forwarded to it — so a BYOK key's
        // own provider credential never leaks to an override upstream. For `sk-*`
        // keys `fwd_auth` is None, so this is always None.
        let auth_override = if target.has_stored_credential {
            None
        } else {
            fwd_auth.as_ref()
        };

        // Ask for capacity on this route's replicas. The gate picks among the
        // ones still to try: a request whose session's replica is full waits a
        // few seconds for it before it is spilled past to one with room
        // (`dispatch_gate::AFFINITY_GRACE`), and is held when none has room;
        // the order held requests are released in is the fairness decision.
        let slot: Vec<(usize, &routing::UpstreamTarget)> = all_targets
            .iter()
            .enumerate()
            .filter(|(j, t)| {
                (*j == i || pending.contains(j)) && t.route_slot == target.route_slot
            })
            .collect();
        // A replica the gate cannot name is a replica it cannot bound, and a
        // refusal settles the whole slot — so gating on the rest would hold a
        // request that had an unbounded target of its own sitting right there.
        // One such replica makes the slot ungated, which is what it is.
        let slot_endpoints: Vec<(usize, dispatch_gate::GateEndpoint)> =
            if slot.iter().any(|(_, t)| t.endpoint_id.is_none()) {
                Vec::new()
            } else {
                slot.iter()
                    .filter_map(|(j, t)| {
                        t.endpoint_id.map(|id| {
                            (
                                *j,
                                dispatch_gate::GateEndpoint {
                                    id,
                                    max_in_flight: t.gate_max_in_flight,
                                    waiting_threshold: t.gate_waiting_threshold,
                                    adaptive: t.gate_adaptive,
                                },
                            )
                        })
                    })
                    .collect()
            };
        // An attempt begins here, at the gate: the one before it, if any, is
        // one the request moved on from.
        err_ctx.attempts.begin();
        let asked_at = std::time::Instant::now();
        // The replica routing put first for this session's route, while it is
        // still one this attempt may use and the request has not already been
        // sent away from it once (it waited for it then); once it has failed
        // the request, it is not, and the request has no engine of its own to
        // wait for. Named for a session's first turn too: that turn's history
        // is cached wherever it runs, and the next turns are routed here.
        let preferred = all_targets
            .iter()
            .find(|t| t.route_slot == target.route_slot)
            .and_then(|t| t.endpoint_id)
            .filter(|id| !affinity_spent.contains(&target.route_slot) && slot_endpoints.iter().any(|(_, e)| e.id == *id));
        let permit = match state
            .dispatch_gate
            .acquire(dispatch_gate::GateRequest {
                endpoints: slot_endpoints.iter().map(|(_, e)| *e).collect(),
                preferred,
                rank: qos_class.as_ref().map(|c| c.rank),
                class_id: qos_class.as_ref().map(|c| c.id),
                sheddable: qos_class.as_ref().is_some_and(|c| c.sheddable),
                scope: (ctx.user.workspace_id, ctx.user.user_id),
                weight: ctx.config.qos.weight(ctx.user.workspace_id),
                input_tokens: estimated_input_tokens,
                output_weight: output_token_weight(target),
                ttl: gate_budget.saturating_sub(queue_wait),
                resend_key: Some(request_key),
            })
            .await
        {
            Ok(permit) => permit,
            Err(refusal) => {
                // This ROUTE has no capacity to give. That is not the end of the
                // request: an alias may have a fallback target precisely for
                // this, and the route's own allowed-class list already decided
                // whether this class may go there. Settle the slot and try the
                // next one; the refusal only answers the client if nothing else
                // does.
                let e = saturated_error(refusal, gate_budget);
                tracing::info!(
                    reason = refusal.as_str(),
                    model = %target.model,
                    "no capacity on this route target"
                );
                settled_slots.push(target.route_slot);
                // The wait counts even though nothing was dispatched: it is
                // what the caller spent, so it comes off the request's budget
                // and lands on its row. Without this the next target would get
                // the full class wait again — three saturated targets, three
                // times the wait their class asked for.
                // Read once, so the total and this pool's share of it agree.
                pool_wait = asked_at.elapsed();
                queue_wait += pool_wait;
                err_ctx.qos_class_id = qos_class.as_ref().map(|c| c.id);
                err_ctx.queue_wait_ms = queue_wait.as_millis() as u64;
                err_ctx.pool_wait_ms = pool_wait.as_millis() as u64;
                err_ctx.attempted = AttemptedUpstream::refused_by_pool_of(target);
                err_ctx.attempts.refused(target, refusal.as_str(), pool_wait);
                last_err = Some(e);
                // A superseded copy has no reader: its client sent it again,
                // and the re-send is the one waiting. Another target would
                // only run it for nobody.
                if refusal == dispatch_gate::GateRefusal::Superseded {
                    break;
                }
                continue;
            }
        };
        // Accumulated, not replaced: a request that waited on one route and was
        // then served by a fallback still waited, and the row must say so. The
        // error context tracks it too, so a request refused or failed AFTER a
        // wait still shows the time its caller spent waiting.
        queue_wait += permit.waited;
        pool_wait = permit.waited;
        err_ctx.queue_wait_ms = queue_wait.as_millis() as u64;
        err_ctx.pool_wait_ms = pool_wait.as_millis() as u64;
        err_ctx.qos_class_id = qos_class.as_ref().map(|c| c.id);
        // The gate may have chosen another replica of this route; that is the
        // one this attempt goes to.
        let chosen = permit
            .endpoint()
            .and_then(|id| slot_endpoints.iter().find(|(_, e)| e.id == id).map(|(j, _)| *j))
            .filter(|j| *j != i);
        if let Some(j) = chosen {
            // Only the row can say so afterwards: the answer is the same, the
            // target is the same route, and `failed_over` stays false because a
            // spill between replicas is not a failover. Tracked on the error
            // context alone so the answering path and the failing one cannot
            // disagree about whether it happened.
            err_ctx.spilled = true;
            affinity_spent.insert(target.route_slot);
            // The gate sent this request to a replica further down the list.
            // Take that one out of the queue and put THIS one back at the front:
            // it had no room a moment ago, which is not a reason never to try it.
            //
            // Taking `j` OUT is what bounds this. The slot offered to the gate
            // is built from `i` plus what is still pending, so a replica that
            // has been spilled to is no longer a candidate on any later pass —
            // one that answers instantly with an error cannot be handed the
            // same request again. Each pass removes one index and returns at
            // most the one it took, so the loop shortens whatever the gate
            // chooses. Keep that true: re-adding `j` here would let two
            // replicas pass a failing request back and forth at wire speed.
            pending.retain(|x| *x != j);
            pending.push_front(i);
            i = j;
        }
        let target = &all_targets[i];
        // The audit row, the breaker and any substitution round all name the
        // replica that was actually used — including when the queue brings the
        // loop back to a replica the gate had spilled past.
        actual_target = target.clone();
        gate_permit = Some(permit);

        // Express the class on this target's own wire, if its server speaks a
        // scheduling dialect. Per ACTUAL target, so a vLLM replica is told the
        // class and a hosted fallback on the same alias is told nothing.
        let mut priority_header: Option<(&'static str, i32)> = None;
        let wire = qos_dialect::priority_wire(
            target.scheduling_dialect,
            qos_class.as_ref().map(|c| c.rank),
            fwd_version,
        );
        let body = match wire {
            qos_dialect::PriorityWire::None => body,
            // The engine reads this leg's class off a header, so the body is
            // neither parsed nor rewritten: a body we could not parse is no
            // reason to drop a channel that never touches it, and re-serialising
            // every request on that leg would buy nothing.
            qos_dialect::PriorityWire::Header(rank) => {
                priority_header = Some((qos_dialect::VLLM_PRIORITY_HEADER, rank));
                body
            }
            qos_dialect::PriorityWire::Body(_) => match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(mut v) => {
                    priority_header = qos_dialect::apply_priority(
                        target.scheduling_dialect,
                        qos_class.as_ref().map(|c| c.rank),
                        fwd_version,
                        &mut v,
                    );
                    match serde_json::to_vec(&v) {
                        Ok(b) => Bytes::from(b),
                        Err(e) => {
                            tracing::warn!(error = %e, "re-serialize after class merge failed; forwarding unmodified");
                            body
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "parse for class merge failed; forwarding unmodified");
                    body
                }
            },
        };
        // The LAST edit to the body, after the preset and the class: neither
        // can put back a field the upstream's dialect refuses.
        let (body, adapted) = target.conform_body(body, fwd_version, client_api_version != fwd_version);
        attempt_adapted = adapted;
        // The gateway's own header for this attempt. It travels on its own
        // channel, never in the client's header map: the forward path copies
        // only an allowlist from the client precisely so a caller cannot steer
        // the engine, and this value is the gateway's answer, not theirs.
        let gateway_headers: Vec<(&'static str, String)> = priority_header
            .map(|(name, value)| vec![(name, value.to_string())])
            .unwrap_or_default();

        match state.http_client.forward_with_retry(
            target.endpoint(), body, &headers, fwd_version,
            target.chat_endpoint_path.as_deref(), max_retries, auth_override,
            Some(target.model.as_str()), is_streaming, &gateway_headers,
        ).await {
            Ok(resp) => {
                // Server is reachable — closes the breaker if it was open.
                note_forward_outcome(&state, ctx.user.tenant_id, target, Ok(()));
                upstream_response = Some(resp);
                break;
            }
            Err(e) => {
                if !record_failed_attempt(
                    &state,
                    ctx.user.tenant_id,
                    target,
                    &e,
                    pool_wait,
                    &mut err_ctx.attempted,
                    &mut err_ctx.attempts,
                ) {
                    settled_slots.push(target.route_slot);
                }
                if all_targets.len() > 1 {
                    tracing::warn!(
                        target = i,
                        model = %target.model,
                        provider = %target.provider,
                        error = %e,
                        "upstream target failed, trying next"
                    );
                }
                last_err = Some(e);
            }
        }
    }

    // A miss with no response is a hard failure; a hit legitimately has none.
    // Checked here, before `err_ctx`'s borrowed fields move into `meta` below.
    let upstream_response = match upstream_response {
        Some(r) => Some(r),
        None => {
            if cache_hit.is_none() {
                let e = last_err
                    .unwrap_or_else(|| AppError::Internal("no upstream targets available".into()))
                    .for_model(err_ctx.model_requested);
                send_error_audit(&state, &err_ctx, &e).await;
                state.proxy_stats.inc_errors();
                return Err(e);
            }
            None
        }
    };

    // Recompute translation flags from actual target (may differ after failover).
    let upstream_api_version = actual_target.upstream_api_version;
    let needs_translation = client_api_version != upstream_api_version;

    // Tag the translation of the attempt that ANSWERED, with what its walk had
    // no channel for — the row renders the inbound request, so a part the
    // upstream never received would otherwise look delivered.
    if needs_translation {
        badges.add_protocol_translated(client_api_version, upstream_api_version);
        badges.add_not_carried(attempt_not_carried);
    }
    // A prefix the gateway set for a translated client: the answer repeats
    // it, the client's prefill expects only what follows.
    let continues_a_prefix = attempt_adapted.as_ref().is_some_and(|c| c.prefix_echo.is_some());
    let answer_prefix_echo = attempt_adapted
        .as_ref()
        .and_then(|c| c.prefix_echo.clone())
        .filter(|_| needs_translation);
    if let Some(conformed) = attempt_adapted.take()
        && !conformed.is_empty()
    {
        badges.add_upstream_adapted(conformed.dialect, conformed.adapted, conformed.not_carried);
    }

    // Patch `telemetry_dropped` on the transform_diff against the ACTUAL
    // outbound target — drops are target-dependent, and the pre-forward
    // computation was for the primary target. When failover lands on a
    // different target (e.g. primary OpenAI Responses → fallback Anthropic
    // BYOK) the audit must reflect what actually happened on the wire, not
    // what would have happened on the primary. Recomputing from the
    // post-transform `api_request` is cheap (string scans on the system
    // prompt only).
    if let Some(cm) = content_meta.as_mut()
        && let Some(td) = cm.transform_diff.as_mut()
        && let Some(td_obj) = td.as_object_mut()
    {
        let drops = if needs_translation {
            let domain_final =
                crate::api::domain_request::DomainRequest::from_api_request(&api_request);
            crate::api::domain_request::compute_telemetry_drops(
                &domain_final,
                crate::api::domain_request::ConversionTarget::from_api_version(
                    upstream_api_version,
                ),
            )
        } else {
            Vec::new()
        };
        if drops.is_empty() {
            td_obj.remove("telemetry_dropped");
        } else {
            td_obj.insert(
                "telemetry_dropped".to_string(),
                serde_json::to_value(&drops).unwrap_or(serde_json::Value::Array(Vec::new())),
            );
        }
    }

    // Append the invocation-preset injection blocks for the ACTUAL forwarded
    // target onto the transform_diff (built pre-forward at ~line 1008). Like
    // `telemetry_dropped`, the merge runs post-translation per real target, so the
    // audit is patched here rather than at diff-build time. Nothing silently
    // changed: each replaced/created param key is a visible block.
    if !preset_blocks.is_empty() {
        if let Some(cm) = content_meta.as_mut()
            && let Some(td) = cm.transform_diff.as_mut()
            && let Some(td_obj) = td.as_object_mut()
        {
            let mut existing: Vec<serde_json::Value> = td_obj
                .get("injection_blocks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for b in &preset_blocks {
                if let Ok(v) = serde_json::to_value(b) {
                    existing.push(v);
                }
            }
            td_obj.insert("injection_blocks".to_string(), serde_json::Value::Array(existing));
        }
        badges.add_modified();
    }

    // Derive deterministic UUID from X-Parent-Session-Id header (same SHA256 method as X-Session-Id).
    // Hash is keyed on `user_id` so child sessions correlate across both LLM and MCP keys.
    let parent_session_uuid = attr.parent_session_id.as_deref().map(|psid| content::session_id_from_client(psid, ctx.user.tenant_id, ctx.user.user_id));
    // A request that ran somewhere other than where it was sent says so: the
    // serving replica is on the row either way, so the move itself is the part
    // nothing else records.
    if err_ctx.spilled {
        badges.add(crate::audit::AuditBadge::Spilled);
    }
    // Taken here, before `err_ctx`'s borrowed fields move into `meta` below.
    let moved_on_from = std::mem::take(&mut err_ctx.attempts).into_moved_on_from();
    // A request that waited says so on its own row: it is the only thing that
    // explains a slow answer the upstream itself produced quickly.
    if !queue_wait.is_zero() {
        badges.add(crate::audit::AuditBadge::Queued { wait_ms: queue_wait.as_millis() as u64 });
    }

    // Shared between the meta (whose last copy ends the request) and, on a
    // stream, the body, which releases it the moment the client has the
    // whole answer.
    let serving = Some(Arc::new(serving));
    let mut meta = RequestMeta {
        request_id,
        user_id: ctx.user.user_id,
        tenant_id: ctx.user.tenant_id,
        workspace_id: ctx.user.workspace_id,
        tpm_capped: {
            let ws = &ctx.user.rate_limit;
            (!ws.exempt && ws.tokens_per_minute > 0)
                || ctx
                    .user
                    .user_rate_override
                    .as_ref()
                    .is_some_and(|o| !o.exempt && o.tokens_per_minute > 0)
        },
        rate_override: ctx.user.user_rate_override.is_some(),
        key_budget_capped: ctx.user.key_budget.is_some(),
        tenant_budget_capped: ctx.user.tenant_budget.is_some(),
        key_id: ctx.user.key_id,
        app_id: attr.app_id,
        // Hash the raw `X-Session-Id` into the gateway session UUID — the same
        // form the MCP and A2A handlers store — so `gateway_audit.session_id`
        // correlates across protocols. The raw header stays available above for
        // the consumers that hash it themselves (session detector, mixed-pending
        // splice).
        session_id: attr
            .session_id
            .as_deref()
            .map(|sid| content::session_id_from_client(sid, ctx.user.tenant_id, ctx.user.user_id)),
        parent_session_id: parent_session_uuid,
        user_agent: attr.user_agent,
        detection_method: attr.detection_method,
        client_ip: attr.client_ip,
        end_user: attr.end_user,
        end_user_groups: attr.end_user_groups,
        model_requested,
        model_used: actual_target.model.clone(),
        provider: actual_target.provider.clone(),
        api_version: client_api_version,
        is_streaming,
        badges,
        program_outcomes: std::mem::take(&mut program_outcomes),
        flags,
        content: content_meta,
        request_started_at,
        estimated_input_tokens,
        upstream_server_id: actual_target.upstream_server_id.clone(),
        // A cache hit made no upstream call, so no endpoint answered it.
        endpoint_id: actual_target.endpoint_id.filter(|_| cache_hit.is_none()),
        endpoint_url: actual_target.endpoint_id.filter(|_| cache_hit.is_none()).map(|_| actual_target.url.clone()),
        upstream_model_id: actual_target.upstream_model_id.clone(),
        pricing: actual_target.pricing.clone(),
        embedding_cost: cache_ctx.as_ref().map_or(0.0, |c| c.embedding_cost),
        embedding_priced: cache_ctx.as_ref().is_none_or(|c| c.embedding_priced),
        embedding_tokens: cache_ctx.as_ref().map_or(0, |c| c.embedding_tokens),
        cache_audit: cache_ctx.as_ref().map(|c| c.audit()),
        queue_wait_ms: queue_wait.as_millis() as u64,
        pool_wait_ms: pool_wait.as_millis() as u64,
        moved_on_from,
        qos_class_id: qos_class.as_ref().map(|c| c.id),
        gate_permit: gate_permit.take().map(Arc::new),
        serving: serving.clone(),
        intercept_bindings,
        withheld_tools,
    };

    tracing::info!(
        request_id = %request_id,
        model = %actual_target.model,
        provider = %actual_target.provider,
        is_streaming,
        needs_translation,
        "routing response"
    );

    // Build debug echo SSE event string if requested
    let debug_echo_str = if debug_echo {
        Some(debug_echo::build_debug_event(
            &actual_target.url,
            &actual_target.model,
            &upstream_body,
        ))
    } else {
        None
    };

    let max_out = actual_target.max_output_tokens.unwrap_or(0) as u32;

    // Cache hit: answer from the stored response, no upstream leg. Billing
    // inputs are zeroed here — the request cost nothing upstream, so the row
    // shows $0 and accrues no TPM, and what the hit *saved* rides the
    // `cache_hit` badge instead. RPM already counted at admission: a request
    // was served either way.
    if let Some(entry) = cache_hit {
        meta.pricing = crate::pricing::Rates::free();
        meta.tpm_capped = false;
        let served = crate::pipeline::response_pipeline::serve_cached_response(
            crate::pipeline::response_pipeline::CachedServe {
                entry,
                client_api_version,
                context_window: actual_target.context_window,
                client_context_window: actual_target.client_context_window,
                max_output_tokens: max_out,
            },
            meta,
            &state,
            &ctx.config,
        )
        .await;
        // The row itself is written inside `serve_cached_response` (success and
        // failure alike), the same way the forward path audits from within the
        // response pipeline. Only the counter is the caller's job.
        if served.is_err() {
            state.proxy_stats.inc_errors();
        }
        return served;
    }

    // Every miss either returned above or carries a response.
    let Some(upstream_response) = upstream_response else {
        return Err(AppError::Internal("no upstream response to forward".into()));
    };

    // Clone stats ref before state is moved into pipeline.
    let stats = state.proxy_stats.clone();

    // Build the substitution agent loop's forward callback when intercept
    // bindings were emitted by the request-phase tool-policy walker. Captures
    // the actual target (post-failover) so subsequent rounds re-issue against
    // the same upstream the first round landed on. Both streaming and
    // non-streaming paths engage the agent loop when bindings are present.
    let forward = if !meta.intercept_bindings.is_empty() {
        Some(crate::pipeline::response_pipeline::SubstitutionForward {
            http_client: state.http_client.clone(),
            url: actual_target.url.clone(),
            api_key: actual_target.api_key.clone(),
            headers: headers.clone(),
            api_version: upstream_api_version,
            chat_endpoint_path: actual_target.chat_endpoint_path.clone(),
            transport: actual_target.transport,
            // Same credential rule as the primary forward (mod.rs ~968): forward
            // the client's own credential ONLY when the resolved target has no
            // stored credential of its own. Without this gate a substitution
            // round against an override route to a stored-key upstream would leak
            // the BYOK client's credential to that upstream.
            auth_override: if actual_target.has_stored_credential {
                None
            } else {
                fwd_auth.clone()
            },
            upstream_model: actual_target.model.clone(),
            max_retries: 1,
            is_streaming,
            preset_settings: actual_target.preset_settings.clone(),
            chat_dialect: actual_target.chat_dialect(),
            model_reasoning: actual_target.model_reasoning(),
            client_translated: client_api_version != upstream_api_version,
            adapted: Default::default(),
            scheduling_dialect: actual_target.scheduling_dialect,
            qos_rank: qos_class.as_ref().map(|c| c.rank),
        })
    } else {
        None
    };
    // Whether the client asked for `json_schema` structured output — gates
    // JSON healing of response text. Resolved here, before the request is
    // (conditionally) moved into the pipeline, so it survives translated
    // paths where `api_request_for_pipeline` is dropped.
    let wants_structured_output = api_request.wants_json_schema();
    let client_tools = crate::api::domain_request::ClientToolFacts::of(&api_request);
    // Agent loop needs the original ApiRequest to splice messages and
    // re-serialize; the non-streaming response path also uses it for
    // upstream-model lookup when client and upstream protocols match.
    let needs_api_request = !needs_translation || forward.is_some();
    let api_request_for_pipeline = if needs_api_request {
        Some(api_request)
    } else {
        None
    };

    let pipeline = crate::pipeline::response_pipeline::ResponsePipeline {
        meta,
        state,
        tenant_config: ctx.config.clone(),
        upstream_api_version,
        client_api_version,
        upstream_model: actual_target.model.clone(),
        upstream_accepts_reasoning: actual_target.accepts_reasoning,
        answer_prefix_echo,
        upstream_chat_cap_field: actual_target.chat_cap_field(),
        upstream_facts: actual_target.translation_facts(),
        context_window: actual_target.context_window,
        max_output_tokens: max_out,
        client_context_window: actual_target.client_context_window,
        healing_enabled: actual_target.healing_enabled,
        wants_structured_output,
        client_tools,
        debug_echo: debug_echo_str,
        api_request: api_request_for_pipeline,
        forward,
        // Reported on the response so a caller (and the e2e suite) can see the
        // outcome of every request on a cache-enabled alias, not only the hits.
        cache_status: cache_ctx
            .as_ref()
            .map(|c| if c.bypass { "bypass" } else { "miss" }),
        cache_store: cache_ctx
            .as_ref()
            .filter(|c| c.should_store() && !failed_over)
            .map(|c| crate::pipeline::response_pipeline::CacheStoreTarget {
                key: c.key.clone(),
                ttl: c.policy.ttl(),
                max_entry_bytes: c.max_entry_bytes,
                multi_choice_request: c.multi_choice_request,
                continues_a_prefix,
                client_api_version,
                upstream_model: actual_target.model.clone(),
                semantic: c.semantic.clone(),
            }),
    };

    if is_streaming {
        let guard = ActiveStreamGuard::open(stats.clone());
        match pipeline.stream(upstream_response).await {
            // `stream()` returns at the response HEADERS; the body streams
            // after this handler has returned. The guard therefore rides the
            // body and closes when it ends or the client goes away.
            Ok(response) => Ok(hold_until_body_ends(response, guard, serving)),
            Err(e) => {
                stats.inc_errors();
                Err(e)
            }
        }
    } else {
        let result = pipeline.non_streaming(upstream_response).await;
        if result.is_err() {
            stats.inc_errors();
        }
        result
    }
}

/// Drop guard that decrements active_streams on drop (panic-safe).
struct ActiveStreamGuard(Arc<dyn ProxyStatsTrait>);
impl ActiveStreamGuard {
    /// Count one stream open until the guard drops.
    fn open(stats: Arc<dyn ProxyStatsTrait>) -> Self {
        stats.inc_active_streams();
        Self(stats)
    }
}
impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.0.dec_active_streams();
    }
}

/// Keep `guard` alive for as long as `response`'s body is being sent: it drops
/// when the body ends, errors, or is dropped because the client disconnected.
fn hold_until_body_ends(
    response: Response,
    guard: ActiveStreamGuard,
    serving: Option<Arc<content::ServingGuard>>,
) -> Response {
    use futures::StreamExt;
    /// Releases the request's serving guard when the body ends or the client
    /// goes away — before the audit of it finishes, which holds the guard too.
    struct ReleaseAtEnd(Option<Arc<content::ServingGuard>>);
    impl Drop for ReleaseAtEnd {
        fn drop(&mut self) {
            if let Some(serving) = &self.0 {
                serving.release();
            }
        }
    }
    let (parts, body) = response.into_parts();
    let state = (body.into_data_stream(), guard, ReleaseAtEnd(serving));
    let guarded = futures::stream::unfold(state, |(mut s, g, r)| async move {
        s.next().await.map(|item| (item, (s, g, r)))
    });
    Response::from_parts(parts, Body::from_stream(guarded))
}

/// Token counting endpoint — extracts text from messages and estimates tokens (~4 chars/token).
pub async fn count_tokens_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;

    // Auth + tenant context. Mount-agnostic: token-counting forwards no
    // upstream credential, so both `sk-*` and `vk-*` keys are valid (the
    // `/fwd/.../count_tokens` wrapper injects an already-validated `vk-*` key).
    let bearer = auth::extract_api_token(&headers)?;
    let _ctx = auth::authenticate(&bearer, &state.tenant_registry.load())?;

    // Read body
    let body_bytes = axum::body::to_bytes(body, core_settings().max_body_size)
        .await
        .map_err(|e| AppError::BadRequest(format!("failed to read body: {e}")))?;

    // Parse request and extract text content for better estimation
    let input_tokens = if let Ok(req) =
        serde_json::from_slice::<crate::api::messages::MessagesRequest>(&body_bytes)
    {
        let mut char_count: usize = 0;

        // Count system prompt
        if let Some(system) = &req.system {
            char_count += system.to_text().len();
        }

        // Count message content
        for msg in &req.messages {
            char_count += count_anthropic_content_chars(&msg.content);
        }

        // Count tool definitions
        if let Some(tools) = &req.tools {
            for tool in tools {
                char_count += tool.name.len();
                if let Some(desc) = &tool.description {
                    char_count += desc.len();
                }
                if let Some(schema) = &tool.input_schema {
                    char_count += schema.to_string().len();
                }
            }
        }

        crate::middleware::tokens::estimate_tokens_from_chars(char_count)
    } else {
        // Fallback: raw body size
        crate::middleware::tokens::estimate_input_tokens_from_bytes(body_bytes.len(), None)
    };

    let response = serde_json::json!({ "input_tokens": input_tokens });
    Ok((
        axum::http::StatusCode::OK,
        axum::Json(response),
    )
        .into_response())
}

/// Count characters in Anthropic message content for token estimation.
fn count_anthropic_content_chars(content: &crate::api::messages::AnthropicContent) -> usize {
    use crate::api::messages::{AnthropicContent, ContentBlock, ToolResultContent};
    match content {
        AnthropicContent::Text(s) => s.len(),
        AnthropicContent::Blocks(blocks) => {
            let mut count = 0;
            for block in blocks {
                match block {
                    ContentBlock::Text { text, .. } => count += text.len(),
                    ContentBlock::ToolUse { name, input, .. } => {
                        count += name.len() + input.to_string().len();
                    }
                    ContentBlock::ToolResult { content, .. } => {
                        if let Some(c) = content {
                            match c {
                                ToolResultContent::Text(s) => count += s.len(),
                                ToolResultContent::Blocks(bs) => {
                                    for b in bs {
                                        match b {
                                            crate::api::messages::ToolResultBlock::Text { text, .. } => {
                                                count += text.len();
                                            }
                                            // As a message's image or document, below.
                                            _ => count += 85,
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ContentBlock::Thinking { thinking, .. } => count += thinking.len(),
                    ContentBlock::Image { .. } | ContentBlock::Document { .. } | ContentBlock::Unknown(_) => {
                        count += 85; // ~85 tokens per image/document in Anthropic's estimation
                    }
                }
            }
            count
        }
    }
}

/// The grammar a `/v1/models` caller speaks — for the list AND for its errors.
///
/// `/v1/models` is speced by OpenAI AND by Anthropic, at the same path and the
/// same method, in two different shapes — the path cannot tell them apart.
/// `anthropic-version` is REQUIRED on every Anthropic API request, so its
/// presence is a declaration by the client of which grammar it speaks, not a
/// guess at the request's shape. Nothing else is sniffed.
pub fn model_list_grammar(headers: &axum::http::HeaderMap) -> ApiVersion {
    if headers.contains_key("anthropic-version") {
        ApiVersion::AnthropicMessages
    } else {
        ApiVersion::ChatCompletions
    }
}

/// Route layer for `/v1/models`: its errors are rendered in the grammar
/// [`model_list_grammar`] reads, the same one its list is.
pub async fn render_model_list_errors(
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let grammar = model_list_grammar(req.headers());
    crate::error::envelope::render_as(grammar, next.run(req).await)
}

/// Models endpoint — returns available model aliases for the authenticated user.
/// OpenAI-compatible format for client discovery.
pub async fn models_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let headers = req.headers().clone();

    // Auth + tenant context
    let bearer = auth::extract_api_token(&headers)?;
    // Mount-agnostic auth: this lists the key's model_map and forwards no
    // upstream credential, so both `sk-*` and `vk-*` keys are valid here — the
    // `/fwd/{key}/v1/models` wrapper injects an already-validated `vk-*` key.
    let ctx = auth::authenticate(&bearer, &state.tenant_registry.load())?;

    // Return models from the user's per-key model_map + tenant config model_map.
    let mut models: Vec<serde_json::Value> = Vec::new();

    let grammar = model_list_grammar(&headers);
    // The OpenAI shape is read by Chat Completions and Responses clients alike,
    // so it lists what a call in either grammar could reach.
    let callers: &[ApiVersion] = match grammar {
        ApiVersion::AnthropicMessages => &[ApiVersion::AnthropicMessages],
        _ => &[ApiVersion::ChatCompletions, ApiVersion::Responses],
    };
    let entries = resolved_entries(&ctx.user, callers, &headers)?;

    if grammar == ApiVersion::AnthropicMessages {
        let response = serde_json::json!({
            "data": entries.iter().map(ResolvedModelEntry::to_anthropic).collect::<Vec<_>>(),
            "first_id": entries.first().map(|e| e.alias.clone()),
            "last_id": entries.last().map(|e| e.alias.clone()),
            // The whole catalog is served in one page — an edge's alias set is
            // bounded by its own configuration, not by an upstream's inventory.
            "has_more": false,
        });
        return Ok((StatusCode::OK, axum::Json(response)).into_response());
    }

    for entry in &entries {
        models.push(entry.to_openai());
    }
    let response = serde_json::json!({
        "object": "list",
        "data": models,
    });
    Ok((StatusCode::OK, axum::Json(response)).into_response())
}

/// Gemini `ListModels` — the same catalog in Gemini's own grammar.
///
/// A separate route because Gemini lists at `/v1beta/models`, which is
/// unambiguous: no other protocol claims it. Without this a Gemini client
/// cannot enumerate the gateway's models at all, and falls back to whatever
/// its SDK assumes about a model it was told nothing about.
pub async fn gemini_models_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let headers = req.headers().clone();
    // `models.list` is spelled `?key=` in Google's own reference too, and this
    // handler is mounted on the Gemini surface only, so the channel needs no
    // further path gate. On the `/fwd` wrapper the path key is injected as a
    // header first, which wins — a BYOK client's `?key=` stays its upstream
    // credential and is never read as a gateway one.
    let bearer = auth::extract_api_token_with_query(&headers, req.uri().query())?;
    let ctx = auth::authenticate(&bearer, &state.tenant_registry.load())?;

    let entries = resolved_entries(&ctx.user, &[ApiVersion::GoogleGemini], &headers)?;

    // `nextPageToken` is omitted, not empty: Gemini's own contract is that its
    // absence ends the listing, and the whole catalog is served in one page.
    let response = serde_json::json!({
        "models": entries.iter().map(ResolvedModelEntry::to_gemini).collect::<Vec<_>>(),
    });
    Ok((StatusCode::OK, axum::Json(response)).into_response())
}

/// Gemini `GetModel` — one model's contract, in Gemini's own grammar.
///
/// Google specs this beside `models.list`, and its response is a BARE `Model`
/// object — the same shape a list entry carries, not an envelope around one, so
/// it is [`ResolvedModelEntry::to_gemini`] verbatim. That sharing is the point:
/// a client that reads a window from the list and then re-reads it here must be
/// told the same number, and the conservative failover fold that makes the list
/// honest has to reach this surface too.
///
/// The model id is the path tail after `/models/`, which is why this mounts on
/// the same catch-all the generate verbs use rather than a `{model}` segment: an
/// alias may legitimately contain a slash (`openrouter/free`).
pub async fn gemini_model_get_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let headers = req.headers().clone();
    let bearer = auth::extract_api_token_with_query(&headers, req.uri().query())?;
    let ctx = auth::authenticate(&bearer, &state.tenant_registry.load())?;

    let path = req.uri().path();
    let alias = path
        .find("/models/")
        .map(|i| &path[i + "/models/".len()..])
        .unwrap_or_default();

    // Resolve against the caller's OWN map, so this is not an existence oracle
    // for aliases the key cannot reach — an alias another workspace can use is
    // absent here exactly as an alias nobody has is.
    let entry = resolved_entries(&ctx.user, &[ApiVersion::GoogleGemini], &headers)?
        .into_iter()
        .find(|e| e.alias == alias)
        .ok_or_else(|| AppError::ModelNotFound(alias.to_string()))?;

    Ok((StatusCode::OK, axum::Json(entry.to_gemini())).into_response())
}

/// BYOK forward-auth Gemini `GetModel` — authenticates from the path key.
pub async fn fwd_gemini_model_get_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((key, _gemini_path)): axum::extract::Path<(String, String)>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let _user = auth::authenticate_forward(&key, &state.tenant_registry.load())?;
    let req = inject_path_key_as_auth(req, &key);
    gemini_model_get_handler(State(state), req).await
}

/// BYOK forward-auth Gemini models handler — authenticates from the path key.
pub async fn fwd_gemini_models_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let _user = auth::authenticate_forward(&key, &state.tenant_registry.load())?;
    let req = inject_path_key_as_auth(req, &key);
    gemini_models_handler(State(state), req).await
}

/// The advertised contract for one alias, resolved once and then encoded into
/// whichever model-list shape the caller's protocol speaks.
///
/// An alias maps to a LIST of targets (weighted round-robin at equal priority,
/// failover across priorities), so a request may be served by any of them and
/// the advertisement must hold for whichever answers. Every figure here is
/// therefore the CONSERVATIVE fold across the set — the smallest window, the
/// smallest output cap, and a capability only where EVERY target has it.
/// Advertising the highest-priority target's contract instead is a claim the
/// fleet cannot keep: the moment that target sheds load the client is working to
/// a window the serving model does not have, and it overruns rather than
/// compacting. Nothing reports this — the request just fails, or silently
/// truncates, on the failover path only.
///
/// The window is the REAL one, not `client_context_window`. The rule to
/// preserve: a window must be stated in the same units as the usage the same
/// client will be sent. Token scaling applies only where a response is BUILT as
/// Anthropic from another protocol, which a model list cannot know in advance,
/// so the honest window is the only one every consumer of this list can act on.
struct ResolvedModelEntry {
    alias: String,
    provider: String,
    context_window: Option<i32>,
    /// The operator's scaled window, folded the same conservative way. Stated
    /// only on a surface whose client will receive scaled counts — see
    /// [`ResolvedModelEntry::to_anthropic`].
    client_context_window: Option<i32>,
    /// True when ANY target already speaks the Anthropic wire. Such a leg is a
    /// passthrough whose usage is re-encoded raw, so the scaled window must not
    /// be stated for the alias at all. Folded with OR: the unscaled leg is the
    /// one that constrains the claim.
    any_target_speaks_anthropic_natively: bool,
    max_output_tokens: Option<i32>,
    caps: crate::proxy::routing::ModelCapabilities,
}

/// Fold an alias's targets into the one contract every one of them can honour.
/// `None` for an alias with no targets.
fn resolve_model_entry(
    alias: &str,
    targets: &[crate::config::model_map::UpstreamModel],
) -> Option<ResolvedModelEntry> {
    let first = targets.first()?;
    let caps = targets
        .iter()
        .map(crate::proxy::routing::ModelCapabilities::resolve)
        .reduce(|a, b| crate::proxy::routing::ModelCapabilities {
            vision: a.vision && b.vision,
            reasoning: a.reasoning && b.reasoning,
            function_calling: a.function_calling && b.function_calling,
            caching: a.caching && b.caching,
            audio_input: a.audio_input && b.audio_input,
            audio_output: a.audio_output && b.audio_output,
            video_input: a.video_input && b.video_input,
            pdf_input: a.pdf_input && b.pdf_input,
            response_schema: a.response_schema && b.response_schema,
            system_messages: a.system_messages && b.system_messages,
        })?;
    Some(ResolvedModelEntry {
        alias: alias.to_string(),
        provider: first.provider.to_string(),
        // A target with no known window is not evidence of a SMALLER one, so it
        // is skipped rather than collapsing the fold to nothing: dropping the
        // figure entirely would put every client back on its own hardcoded
        // default, which is the failure this list exists to prevent.
        context_window: targets.iter().filter_map(|t| t.context_window).min(),
        client_context_window: targets.iter().filter_map(|t| t.client_context_window).min(),
        any_target_speaks_anthropic_natively: targets.iter().any(|t| {
            crate::proxy::routing::upstream_api_version_for_provider(
                &t.provider,
                t.upstream_api_format.as_deref(),
            ) == crate::api::sse::ApiVersion::AnthropicMessages
        }),
        // Each alias is a (model, preset) pointer; if a target's preset sets an
        // output cap it is the effective per-call ceiling the proxy force-merges,
        // so it takes precedence over the model/catalog `max_output_tokens`.
        max_output_tokens: targets
            .iter()
            .filter_map(|t| {
                json_merge::preset_max_output_tokens(&t.preset_settings)
                    .and_then(|v| i32::try_from(v).ok())
                    .or(t.max_output_tokens)
            })
            .min(),
        caps,
    })
}

/// Every alias the caller's key can reach, folded and ordered — the one input
/// each model-list shape encodes.
///
/// Shared by all three shapes on purpose: a filter added to one listing and not
/// the others is a key seeing a different catalog depending on which grammar it
/// asked in, which no test of a single shape would notice. The one difference
/// is deliberate and comes from `callers`, the grammars a call reading this
/// shape could be made in: which pass-through a forward-auth key's credential
/// belongs to can depend on it, exactly as it does for the call.
///
/// Sorted by alias because a model list is a catalog, not a stream of events:
/// an unordered map returns the same key's models in a different order on every
/// call, which reads as churn to anything that diffs the list.
///
/// Each alias is folded over the targets a call from this caller may actually
/// reach in any of `callers`. A forward-auth key never reaches a keyless target
/// on a pass-through its credential does not belong to
/// ([`routing::CredentialScope`], judged from the origin host and the call's
/// grammar as routing judges it), so such a target neither lends the alias its
/// window and capabilities nor keeps an alias listed that nothing admitted
/// serves — a list is a contract the client plans against.
fn resolved_entries(
    user: &auth::UserContext,
    callers: &[ApiVersion],
    headers: &axum::http::HeaderMap,
) -> Result<Vec<ResolvedModelEntry>, AppError> {
    let origin_host = routing::origin_host(headers, user)?;
    let scopes: Vec<_> = callers.iter().map(|p| routing::CredentialScope::of(user, Some(*p), origin_host)).collect();
    let mut entries: Vec<ResolvedModelEntry> = user
        .model_map
        .mappings
        .iter()
        .filter_map(|(alias, targets)| {
            let admitted: Vec<_> =
                targets.iter().filter(|m| scopes.iter().any(|s| s.admits(m))).cloned().collect();
            resolve_model_entry(alias, &admitted)
        })
        .collect();
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(entries)
}

impl ResolvedModelEntry {
    /// OpenAI `ListModelsResponse` entry.
    ///
    /// The OpenAI model object carries NO context-window field, so every
    /// OpenAI-compatible server invented its own and every client reads the one
    /// its ecosystem uses. A client that cannot find the window falls back to a
    /// hardcoded default and compacts against the wrong number, so the window is
    /// published under every spelling a client is known to read — one value,
    /// several names:
    ///   `context_window`  ours
    ///   `max_model_len`   vLLM (`ModelCard`)
    ///   `context_length`  OpenRouter
    ///   `meta.n_ctx`      llama.cpp (`get_res_model_info`) — what Goose reads
    /// `meta.n_ctx_train` is deliberately NOT emitted: it is the model's TRAINED
    /// context, which an aliased upstream does not tell us, and llama.cpp
    /// consumers use it to decide context extension.
    /// Add a name here only with a consumer to point at — an invented spelling
    /// is read by nobody and asserts a fact we cannot stand behind.
    fn to_openai(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "id": self.alias,
            "object": "model",
            "created": 0,
            "owned_by": self.provider,
            "capabilities": {
                "vision": self.caps.vision,
                "reasoning": self.caps.reasoning,
                "function_calling": self.caps.function_calling,
                "caching": self.caps.caching,
                "audio_input": self.caps.audio_input,
                "audio_output": self.caps.audio_output,
                "video_input": self.caps.video_input,
                "pdf_input": self.caps.pdf_input,
                "response_schema": self.caps.response_schema,
                "system_messages": self.caps.system_messages,
            },
        });
        if let Some(cw) = self.context_window {
            obj["context_window"] = serde_json::json!(cw);
            obj["max_model_len"] = serde_json::json!(cw);
            obj["context_length"] = serde_json::json!(cw);
            obj["meta"] = serde_json::json!({ "n_ctx": cw });
        }
        if let Some(mot) = self.max_output_tokens {
            obj["max_output_tokens"] = serde_json::json!(mot);
        }
        obj
    }

    /// Anthropic `ModelInfo` entry. The window is `max_input_tokens` and the
    /// output ceiling is `max_tokens` — the reverse of the OpenAI vocabulary,
    /// where `max_tokens` names the output cap on the request rather than a
    /// property of the model.
    ///
    /// **This is the one shape that may state the scaled window.** The other two
    /// cannot: a list is served before any leg exists, so they do not know
    /// whether the caller's request will be translated. Here the client has
    /// already declared it speaks Anthropic to select this envelope, which is the
    /// same fact `build_route_scope` resolves — so the same rule applies, with
    /// the same conservative fold. Without this the list would contradict both
    /// the provisioned config and every `model_info` in the replies that follow
    /// it, and a client trusting the list would compact far too early.
    ///
    /// `capabilities` is `null`, deliberately. Anthropic's `ModelCapabilities`
    /// has NINE required members; the gateway can honestly answer four of them
    /// (they are the ones it enforces at the modality gate) and cannot answer
    /// `citations`, `code_execution`, `context_management` or `effort` at all —
    /// on a passthrough leg they work, on a translated one they do not, and the
    /// list does not know which. Emitting a PARTIAL required object is a schema
    /// violation a strict deserializer may reject; emitting `false` for the five
    /// is a claim we cannot stand behind. The schema types the whole object as
    /// nullable, so `null` is the spec's own way of declining the question.
    fn to_anthropic(&self) -> serde_json::Value {
        let window = if self.any_target_speaks_anthropic_natively {
            self.context_window
        } else {
            self.client_context_window.or(self.context_window)
        };
        // Emitted even when unknown, unlike the OpenAI and Gemini shapes, which
        // omit what they cannot state. Anthropic types both fields as nullable
        // and its own list returns them on every entry, so `null` is the
        // spec's way of saying "not stated" here — an absent key would be the
        // deviation, not the safe default.
        serde_json::json!({
            "id": self.alias,
            "type": "model",
            "display_name": self.alias,
            "created_at": "1970-01-01T00:00:00Z",
            "capabilities": serde_json::Value::Null,
            "max_input_tokens": window,
            "max_tokens": self.max_output_tokens,
        })
    }

    /// Gemini `Model` entry. The id is `models/{alias}` — Gemini's resource
    /// naming, which its SDKs strip back off — and the limits are
    /// `inputTokenLimit` / `outputTokenLimit`. `supportedGenerationMethods` is
    /// what a Gemini client reads to decide a model is usable for chat at all,
    /// so it must name the methods this gateway actually serves for the alias.
    fn to_gemini(&self) -> serde_json::Value {
        let mut methods = vec!["generateContent", "streamGenerateContent"];
        if self.caps.caching {
            methods.push("createCachedContent");
        }
        let mut obj = serde_json::json!({
            "name": format!("models/{}", self.alias),
            "baseModelId": self.alias,
            "displayName": self.alias,
            "supportedGenerationMethods": methods,
            "thinking": self.caps.reasoning,
        });
        if let Some(cw) = self.context_window {
            obj["inputTokenLimit"] = serde_json::json!(cw);
        }
        if let Some(mot) = self.max_output_tokens {
            obj["outputTokenLimit"] = serde_json::json!(mot);
        }
        obj
    }
}

/// BYOK forward-auth count_tokens handler — authenticates from path key.
///
/// Replaces the request's auth header with the path key before delegating,
/// since the original header contains the client's upstream credential.
pub async fn fwd_count_tokens_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let _user = auth::authenticate_forward(&key, &state.tenant_registry.load())?;
    let req = inject_path_key_as_auth(req, &key);
    count_tokens_handler(State(state), req).await
}

/// BYOK forward-auth models handler — authenticates from path key.
///
/// Replaces the request's auth header with the path key before delegating,
/// since the original header contains the client's upstream credential.
pub async fn fwd_models_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let _user = auth::authenticate_forward(&key, &state.tenant_registry.load())?;
    let req = inject_path_key_as_auth(req, &key);
    models_handler(State(state), req).await
}

/// Replace the request's auth header with the path key so downstream handlers
/// that re-authenticate from headers see the proxy key, not the client's upstream credential.
fn inject_path_key_as_auth(req: Request<Body>, key: &str) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    parts.headers.remove("authorization");
    parts.headers.remove("x-api-key");
    parts.headers.insert(
        "x-api-key",
        axum::http::HeaderValue::from_str(key).unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    Request::from_parts(parts, body)
}

/// Liveness endpoint (`/health`) — always 200 while the process runs. The body
/// is a bare status: it is served unauthenticated on the public vhost, so it
/// carries no build version or component detail to fingerprint.
pub async fn health_check(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "healthy" })),
    )
}

/// Readiness check endpoint — 200 once the proxy holds a usable config
/// snapshot, 503 until then. Distinct from `/health` (liveness): an
/// orchestrator should not route traffic to a replica that has booted but not
/// yet loaded config. Readiness tracks "config loaded", not "connected" — a
/// config-loaded proxy serves from its config, buffering audit in its outbox,
/// while admin is unreachable.
pub async fn readiness_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.config_ready.load(std::sync::atomic::Ordering::Relaxed) {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "ready" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "not_ready",
                "reason": "awaiting config",
            })),
        )
    }
}

#[cfg(test)]
mod model_list_tests {
    use super::*;
    use crate::config::model_map::{test_upstream_model, Provider, UpstreamModel};

    fn target(context_window: Option<i32>, max_output_tokens: Option<i32>) -> UpstreamModel {
        UpstreamModel {
            context_window,
            max_output_tokens,
            ..test_upstream_model(Provider::OpenAi, "m")
        }
    }

    fn resolved(targets: &[UpstreamModel]) -> ResolvedModelEntry {
        resolve_model_entry("alias", targets).expect("a non-empty target set yields an entry")
    }

    fn entry(targets: &[UpstreamModel]) -> serde_json::Value {
        resolved(targets).to_openai()
    }

    /// The OpenAI model object has no context field, so each ecosystem reads a
    /// different name. Every spelling must carry the SAME number — a client that
    /// reads one of them and gets nothing falls back to its own default.
    #[test]
    fn the_window_is_published_under_every_spelling_a_client_reads() {
        let e = entry(&[target(Some(200_000), None)]);
        for key in ["context_window", "max_model_len", "context_length"] {
            assert_eq!(e[key], serde_json::json!(200_000), "spelling `{key}`");
        }
        assert_eq!(e["meta"]["n_ctx"], serde_json::json!(200_000));
        // `n_ctx_train` is the model's TRAINED context — a fact an aliased
        // upstream never tells us, so it must not be invented.
        assert!(e["meta"].get("n_ctx_train").is_none());
    }

    /// No window resolved ⇒ no spelling is emitted. Publishing a placeholder
    /// would be worse than silence: the client would work to a number we made up
    /// rather than to its own documented default.
    #[test]
    fn an_unknown_window_publishes_no_spelling_at_all() {
        let e = entry(&[target(None, None)]);
        for key in ["context_window", "max_model_len", "context_length", "meta"] {
            assert!(e.get(key).is_none(), "spelling `{key}` present for an unknown window");
        }
    }

    /// The advertisement must hold for whichever failover target serves the
    /// request, so it is the SMALLEST window in the set — not the first target's.
    #[test]
    fn failover_advertises_the_smallest_window_not_the_first_targets() {
        let e = entry(&[target(Some(200_000), None), target(Some(32_000), None)]);
        assert_eq!(e["context_window"], serde_json::json!(32_000));
        assert_eq!(e["meta"]["n_ctx"], serde_json::json!(32_000));
        // Order must not decide it — the smaller value wins from either side.
        let reversed = entry(&[target(Some(32_000), None), target(Some(200_000), None)]);
        assert_eq!(reversed["context_window"], serde_json::json!(32_000));
    }

    /// An unstated window is "unknown", not "zero". Letting it win the fold
    /// would drop the field and send every client back to its own default —
    /// exactly the failure this endpoint exists to prevent.
    #[test]
    fn a_target_with_no_known_window_does_not_collapse_the_fold() {
        let e = entry(&[target(Some(128_000), None), target(None, None)]);
        assert_eq!(e["context_window"], serde_json::json!(128_000));
    }

    /// Same rule for the output ceiling: a client that sizes a request to the
    /// larger cap gets refused the moment the smaller target serves it.
    #[test]
    fn failover_advertises_the_smallest_output_cap() {
        let e = entry(&[target(None, Some(8192)), target(None, Some(4096))]);
        assert_eq!(e["max_output_tokens"], serde_json::json!(4096));
    }

    /// A capability is advertised only where EVERY target has it — otherwise the
    /// request 400s at the modality gate on the failover path alone.
    #[test]
    fn a_capability_is_advertised_only_when_every_target_has_it() {
        let with_vision = UpstreamModel {
            supports_vision: Some(true),
            ..target(None, None)
        };
        let without_vision = UpstreamModel {
            supports_vision: Some(false),
            ..target(None, None)
        };
        // Positive control: the capability IS advertised when the set agrees,
        // so this test cannot pass by never advertising anything.
        let agreed = entry(&[with_vision.clone(), with_vision.clone()]);
        assert_eq!(agreed["capabilities"]["vision"], serde_json::json!(true));

        let mixed = entry(&[with_vision, without_vision]);
        assert_eq!(mixed["capabilities"]["vision"], serde_json::json!(false));
    }

    #[test]
    fn an_alias_with_no_targets_yields_no_entry() {
        assert!(resolve_model_entry("alias", &[]).is_none());
    }

    /// Anthropic names the window `max_input_tokens` and the output ceiling
    /// `max_tokens` — the reverse of the OpenAI vocabulary, where `max_tokens`
    /// is a request knob. Encoding one as the other would hand its SDK the
    /// output cap as the context window.
    #[test]
    fn the_anthropic_shape_uses_anthropics_own_vocabulary() {
        let e = resolved(&[target(Some(200_000), Some(64_000))]).to_anthropic();
        assert_eq!(e["max_input_tokens"], serde_json::json!(200_000));
        assert_eq!(e["max_tokens"], serde_json::json!(64_000));
        assert_eq!(e["type"], serde_json::json!("model"));
        // `ModelCapabilities` has NINE required members and we can honestly
        // answer four, so the object is declined outright rather than emitted
        // partial — the schema types it nullable for exactly this.
        assert_eq!(e["capabilities"], serde_json::Value::Null);
        // The OpenAI spellings must not leak onto the Anthropic shape.
        assert!(e.get("context_window").is_none());
        assert!(e.get("object").is_none());
    }

    /// The Anthropic shape is the ONE list that knows its caller's protocol —
    /// the client declared it to select this envelope — so the units rule
    /// applies here exactly as it does to a provisioned config. Stating the
    /// honest window while every reply's `model_info` states the scaled one
    /// would make a client trusting the list compact far too early.
    #[test]
    fn the_anthropic_list_states_the_scaled_window_when_the_leg_translates() {
        let translating = UpstreamModel {
            context_window: Some(100_000),
            client_context_window: Some(1_000_000),
            ..test_upstream_model(Provider::OpenAi, "m")
        };
        let e = resolve_model_entry("alias", std::slice::from_ref(&translating)).expect("entry");
        assert_eq!(e.to_anthropic()["max_input_tokens"], serde_json::json!(1_000_000));
        // …but never on the OpenAI or Gemini shapes, whose clients receive
        // unscaled counts.
        assert_eq!(e.to_openai()["context_window"], serde_json::json!(100_000));
        assert_eq!(e.to_gemini()["inputTokenLimit"], serde_json::json!(100_000));

        // A target already speaking Anthropic is a passthrough — usage is
        // re-encoded raw — so one of them forces the honest window for the
        // whole alias.
        let native = UpstreamModel {
            provider: Provider::Anthropic.to_string(),
            ..translating.clone()
        };
        let mixed = resolve_model_entry("alias", &[translating, native]).expect("entry");
        assert_eq!(mixed.to_anthropic()["max_input_tokens"], serde_json::json!(100_000));
    }

    /// Gemini addresses a model by its resource name and reads
    /// `supportedGenerationMethods` to decide it is usable for chat at all.
    #[test]
    fn the_gemini_shape_uses_geminis_own_vocabulary() {
        let e = resolved(&[target(Some(1_000_000), Some(8_192))]).to_gemini();
        assert_eq!(e["name"], serde_json::json!("models/alias"));
        assert_eq!(e["baseModelId"], serde_json::json!("alias"));
        assert_eq!(e["inputTokenLimit"], serde_json::json!(1_000_000));
        assert_eq!(e["outputTokenLimit"], serde_json::json!(8_192));
        let methods = e["supportedGenerationMethods"].as_array().expect("methods listed");
        assert!(methods.iter().any(|m| m == "generateContent"));
        assert!(methods.iter().any(|m| m == "streamGenerateContent"));
        // A model with no caching support must not advertise the cache method.
        assert!(!methods.iter().any(|m| m == "createCachedContent"));

        // Positive control: it IS advertised when the alias supports caching,
        // so the assertion above cannot pass by never emitting the method.
        let cached = resolved(&[UpstreamModel {
            supports_caching: Some(true),
            ..target(None, None)
        }])
        .to_gemini();
        assert!(cached["supportedGenerationMethods"]
            .as_array()
            .expect("methods listed")
            .iter()
            .any(|m| m == "createCachedContent"));
    }

    /// The conservative fold is resolved ONCE and every shape encodes the same
    /// answer — a client must not get a different contract for asking in a
    /// different grammar.
    #[test]
    fn every_shape_states_the_same_folded_window() {
        let e = resolved(&[target(Some(200_000), None), target(Some(32_000), None)]);
        assert_eq!(e.to_openai()["context_window"], serde_json::json!(32_000));
        assert_eq!(e.to_anthropic()["max_input_tokens"], serde_json::json!(32_000));
        assert_eq!(e.to_gemini()["inputTokenLimit"], serde_json::json!(32_000));
    }
}

#[cfg(test)]
mod attempted_upstream_tests {
    use super::{routing, AppError, AttemptedUpstream, AuditRecord};

    #[test]
    fn a_refusal_names_the_server_and_no_replica_and_a_failed_send_names_both() {
        let (server, endpoint) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let target = routing::test_replica_target(server, endpoint, "http://replica-1");
        let mut row = AuditRecord::default();
        // The pool refused it: no replica had room, so none is named.
        AttemptedUpstream::refused_by_pool_of(&target).stamp(&mut row);
        assert_eq!((row.upstream_server_id, row.endpoint_id, row.endpoint_url.as_deref()), (Some(server), None, None));
        AttemptedUpstream::sent_to(&target).stamp(&mut row);
        assert_eq!(
            (row.upstream_server_id, row.endpoint_id, row.endpoint_url.as_deref()),
            (Some(server), Some(endpoint), Some("http://replica-1"))
        );
        // A request that never left names the server and no replica.
        let unbuildable = super::AppError::UpstreamUnbuildable("bad header".into());
        AttemptedUpstream::failed_at(&target, &unbuildable).stamp(&mut row);
        assert_eq!((row.upstream_server_id, row.endpoint_id, row.endpoint_url.as_deref()), (Some(server), None, None));
        let unreachable = super::AppError::UpstreamUnreachable { kind: "connection", detail: "refused".into(), model: None };
        AttemptedUpstream::failed_at(&target, &unreachable).stamp(&mut row);
        assert_eq!(row.endpoint_id, Some(endpoint), "an attempt that reached the replica names it");
        // A request offered to no upstream names none.
        AttemptedUpstream::default().stamp(&mut row);
        assert_eq!((row.upstream_server_id, row.endpoint_id, row.endpoint_url), (None, None, None));
    }

    /// Server, endpoint, outcome, reason, status and wait of one attempt.
    type Recorded<'a> = (Option<uuid::Uuid>, Option<uuid::Uuid>, &'a str, &'a str, Option<u16>, u64);

    /// What the log recorded, less `elapsed_ms`, which is wall-clock.
    fn recorded(log: &[crate::audit::EarlierAttempt]) -> Vec<Recorded<'_>> {
        log.iter()
            .map(|a| (a.server_id, a.endpoint_id, a.outcome.as_str(), a.reason.as_str(), a.status, a.wait_ms))
            .collect()
    }

    /// Each attempt that ended without an answer is kept, with its own server,
    /// replica, outcome, reason and wait — a second never overwrites the first
    /// — and the attempt the request ends with is never on the list, whichever
    /// way it ends: the row names that one.
    #[test]
    fn a_request_moves_on_from_every_attempt_but_the_one_it_ends_with() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let (a1, a2) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let replica_1 = routing::test_replica_target(a, a1, "http://a-1");
        let replica_2 = routing::test_replica_target(a, a2, "http://a-2");
        let fallback = routing::test_replica_target(b, uuid::Uuid::new_v4(), "http://b");
        let ms = std::time::Duration::from_millis;
        let unreachable = AppError::UpstreamUnreachable { kind: "connection", detail: "refused".into(), model: None };
        let unbuildable = AppError::UpstreamUnbuildable("bad header".into());

        // Waited at replica 1 and failed, spilled to replica 2 which could not
        // be built, refused at the fallback's pool: it ENDS refused, there.
        let mut log = super::AttemptLog::default();
        log.begin();
        log.failed(&replica_1, &unreachable, ms(800));
        log.begin();
        log.failed(&replica_2, &unbuildable, ms(0));
        log.begin();
        log.refused(&fallback, "queue_timeout", ms(150));
        assert_eq!(
            recorded(log.moved_on_from()),
            // The unbuildable one never reached replica 2, so names none.
            [(Some(a), Some(a1), "failed", "upstream", Some(502), 800), (Some(a), None, "failed", "internal", Some(500), 0)]
        );
        // An attempt took at least what it waited.
        assert!(log.moved_on_from()[0].elapsed_ms >= 800);

        // Refused at A's pool, then served by the fallback: the refusal is one
        // it moved on from, the served attempt is the row's own.
        let mut log = super::AttemptLog::default();
        log.begin();
        log.refused(&replica_1, "shed", ms(5));
        log.begin();
        assert_eq!(recorded(&log.into_moved_on_from()), [(Some(a), None, "refused", "shed", None, 5)]);

        // Served first time: nothing moved on from.
        let mut log = super::AttemptLog::default();
        log.begin();
        assert!(log.moved_on_from().is_empty());

        // A target naming no server is recorded without one: its time is not
        // the next target's.
        let mut passthrough = routing::test_replica_target(a, a1, "http://p");
        passthrough.upstream_server_id = None;
        let mut log = super::AttemptLog::default();
        log.begin();
        log.refused(&replica_1, "shed", ms(1));
        log.begin();
        log.failed(&passthrough, &unreachable, ms(0));
        log.begin();
        assert_eq!(
            recorded(log.moved_on_from()),
            [(Some(a), None, "refused", "shed", None, 1), (None, Some(a1), "failed", "upstream", Some(502), 0)]
        );
    }
}

#[cfg(test)]
mod replica_signal_tests {
    use super::{AppError, ReplicaSignal};

    #[test]
    fn only_a_missing_answer_counts_against_a_replica() {
        assert_eq!(ReplicaSignal::of(Ok(())), ReplicaSignal::Answered);
        // An error status is an answer: the replica is reachable.
        assert_eq!(ReplicaSignal::of(Err(&AppError::upstream(503, "busy"))), ReplicaSignal::Answered);
        let unreachable =
            AppError::UpstreamUnreachable { kind: "connection", detail: "refused".into(), model: None };
        assert_eq!(ReplicaSignal::of(Err(&unreachable)), ReplicaSignal::Unreachable);
    }

    #[test]
    fn a_failure_before_the_request_left_says_nothing_about_the_replica() {
        // A cloud credential that could not be refreshed, a request that could
        // not be built: the replica was never asked, so it is neither reachable
        // nor down.
        let not_sent = AppError::Internal("token refresh failed".into());
        assert_eq!(ReplicaSignal::of(Err(&not_sent)), ReplicaSignal::NotReached);
        let unbuildable = AppError::UpstreamUnbuildable("bad header".into());
        assert_eq!(ReplicaSignal::of(Err(&unbuildable)), ReplicaSignal::NotReached);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    /// The active-streams gauge counts a stream for as long as its body is
    /// being sent — not only until the handler returns at the headers.
    #[tokio::test]
    async fn an_open_stream_is_counted_until_its_body_ends() {
        use std::sync::atomic::{AtomicI64, Ordering};
        struct Gauge(AtomicI64);
        impl ProxyStatsTrait for Gauge {
            fn inc_requests(&self) {}
            fn inc_errors(&self) {}
            fn inc_active_streams(&self) { self.0.fetch_add(1, Ordering::SeqCst); }
            fn dec_active_streams(&self) { self.0.fetch_sub(1, Ordering::SeqCst); }
            fn inc_http2(&self) {}
            fn inc_http11(&self) {}
        }
        let gauge = Arc::new(Gauge(AtomicI64::new(0)));
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<bytes::Bytes, std::io::Error>>();
        let body = Body::from_stream(rx);
        let response = hold_until_body_ends(Response::new(body), ActiveStreamGuard::open(gauge.clone()), None);
        // The handler has returned the response; the body has not ended.
        assert_eq!(gauge.0.load(Ordering::SeqCst), 1);
        tx.unbounded_send(Ok(bytes::Bytes::from_static(b"data: 1\n\n"))).unwrap();
        drop(tx);
        let bytes = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], b"data: 1\n\n");
        assert_eq!(gauge.0.load(Ordering::SeqCst), 0);

        // A client that disconnects drops the body: the stream closes too.
        let (_tx, rx) = futures::channel::mpsc::unbounded::<Result<bytes::Bytes, std::io::Error>>();
        let body = Body::from_stream(rx);
        let response = hold_until_body_ends(Response::new(body), ActiveStreamGuard::open(gauge.clone()), None);
        assert_eq!(gauge.0.load(Ordering::SeqCst), 1);
        drop(response);
        assert_eq!(gauge.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_streamed_answer_stops_being_served_when_its_body_ends() {
        // The audit task keeps the meta — and its share of the guard — past the
        // client's last byte; the body releases the guard there, so the same
        // request sent straight back is asked again, not a re-send.
        struct Quiet;
        impl ProxyStatsTrait for Quiet {
            fn inc_requests(&self) {}
            fn inc_errors(&self) {}
            fn inc_active_streams(&self) {}
            fn dec_active_streams(&self) {}
            fn inc_http2(&self) {}
            fn inc_http11(&self) {}
        }
        let detector = content::SessionDetector::new(20, std::time::Duration::from_secs(1800));
        let (user, key) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let hashes = vec!["a".to_string()];
        let request_key = content::request_key(user, key, None, "chat_completions", "m", true, b"a");
        let served = |d: &content::SessionDetector| d.detect_serving(user, key, uuid::Uuid::nil(), &hashes, None, request_key);
        let (first, guard) = served(&detector);
        detector.record(user, key, uuid::Uuid::new_v4(), &first, hashes.clone(), None);
        let audit_share = Arc::new(guard);
        let (tx, rx) = futures::channel::mpsc::unbounded::<Result<bytes::Bytes, std::io::Error>>();
        let response = hold_until_body_ends(
            Response::new(Body::from_stream(rx)),
            ActiveStreamGuard::open(Arc::new(Quiet)),
            Some(audit_share.clone()),
        );
        // The control: mid-answer, the same request is a re-send.
        assert_eq!(served(&detector).0.session_id, first.session_id);
        tx.unbounded_send(Ok(bytes::Bytes::from_static(b"data: 1\n\n"))).unwrap();
        drop(tx);
        axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        // The body ended while the audit still holds its share.
        assert_eq!(Arc::strong_count(&audit_share), 1);
        assert_ne!(served(&detector).0.session_id, first.session_id);
    }

    use super::*;
    use crate::api::domain::{FinishReason, Usage};
    use crate::api::sse::ApiVersion;
    use crate::pipeline::response::TransformState;

    pub(crate) fn make_meta(badge_codes: Vec<&str>) -> RequestMeta {
        let mut badges = crate::audit::BadgeBuilder::new();
        for code in &badge_codes {
            match *code {
                "modified" => badges.add_modified(),
                "compressed" => badges.add_compressed(),
                "json_healed" => badges.add_json_healed(),
                _ => {}
            }
        }
        RequestMeta {
            request_id: uuid::Uuid::nil(),
            user_id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            workspace_id: uuid::Uuid::nil(),
            tpm_capped: false,
            rate_override: false,
            key_budget_capped: false,
            tenant_budget_capped: false,
            key_id: None,
            app_id: None,
            session_id: None,
            parent_session_id: None,
            user_agent: None,
            detection_method: None,
            client_ip: None,
            end_user: None,
            end_user_groups: Vec::new(),
            model_requested: "gpt-4o".to_string(),
            model_used: "gpt-4o-2024-08-06".to_string(),
            provider: "openai".to_string(),
            api_version: ApiVersion::ChatCompletions,
            is_streaming: true,
            badges,
            program_outcomes: Vec::new(),
            flags: crate::pipeline::TransformFlags::default(),
            content: None,
            request_started_at: std::time::Instant::now(),
            queue_wait_ms: 0,
            pool_wait_ms: 0,
            moved_on_from: Vec::new(),
            qos_class_id: None,
            gate_permit: None,
            serving: None,
            estimated_input_tokens: 0,
            upstream_server_id: None,
            endpoint_id: None,
            endpoint_url: None,
            upstream_model_id: None,
            pricing: crate::pricing::Rates::unknown(),
            embedding_cost: 0.0,
            embedding_priced: true,
            embedding_tokens: 0,
            cache_audit: None,
            intercept_bindings: Vec::new(),
            withheld_tools: Vec::new(),
        }
    }

    /// A priced request for the audit-assembly tests: 0.02 of input and 0.03 of
    /// output, in the tenant's own currency.
    fn make_billing() -> crate::pricing::Billing {
        use crate::pricing::{Currency, Rate, Unit};
        crate::pricing::Rates::from_units(
            std::collections::BTreeMap::from([
                (Unit::InputToken, Rate::Flat(200.0)),
                (Unit::OutputToken, Rate::Flat(600.0)),
            ]),
            Currency::USD,
        )
        .bill(
            &crate::pricing::Units::new()
                .with(Unit::InputToken, 100)
                .with(Unit::OutputToken, 50),
            Currency::USD,
            &crate::pricing::FxTable::default(),
        )
    }

    #[test]
    fn assemble_audit_record_normal_case() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        state.usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            reasoning_tokens: Some(10),
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 150,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        };
        state.finish_reason = Some(FinishReason::Stop);
        state.native_finish_reason = Some("stop".to_string());

        let mut meta = make_meta(vec!["modified"]);

        let record = crate::pipeline::response_pipeline::assemble_audit_record(&state, &mut meta, false, make_billing());

        assert_eq!(record.prompt_tokens, 100);
        assert_eq!(record.completion_tokens, 50);
        assert_eq!(record.reasoning_tokens, Some(10));
        assert_eq!(record.finish_reason, "stop");
        assert!((record.cost - 0.05).abs() < 1e-12);
        assert_eq!(record.cost_currency, crate::pricing::Currency::USD);
        assert_eq!(record.fx_rate, 1.0);
        assert!(
            (record.billed_units[&crate::pricing::Unit::InputToken].cost - 0.02).abs() < 1e-12
        );
        assert!(
            (record.billed_units[&crate::pricing::Unit::OutputToken].cost - 0.03).abs() < 1e-12
        );
        assert!(!record.zero_completion);
        assert_eq!(record.model_requested, "gpt-4o");
        assert_eq!(record.model_used, "gpt-4o-2024-08-06");
        assert!(record
            .badges
            .iter()
            .any(|b| matches!(b, crate::audit::AuditBadge::Modified)));
    }

    #[test]
    fn zero_completion_insurance_sets_cost_to_zero() {
        let mut state = TransformState::new(ApiVersion::ChatCompletions);
        state.usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 0, // zero completion tokens
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 100,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        };
        state.finish_reason = Some(FinishReason::Stop);

        let mut meta = make_meta(vec![]);

        let record = crate::pipeline::response_pipeline::assemble_audit_record(&state, &mut meta, false, make_billing());

        assert!(record.zero_completion);
        assert!((record.cost - 0.0).abs() < f64::EPSILON);
        assert!(
            record.billed_units.is_empty(),
            "the insurance must clear the breakdown too, or it contradicts the total"
        );
    }

    #[test]
    fn transforms_tracked_in_record() {
        let state = TransformState::new(ApiVersion::ChatCompletions);
        let mut meta = make_meta(vec!["modified", "compressed"]);

        let record = crate::pipeline::response_pipeline::assemble_audit_record(&state, &mut meta, true, crate::pricing::Billing::zero(crate::pricing::Currency::USD));

        assert!(record
            .badges
            .iter()
            .any(|b| matches!(b, crate::audit::AuditBadge::Modified)));
        assert!(record
            .badges
            .iter()
            .any(|b| matches!(b, crate::audit::AuditBadge::Compressed)));
        assert!(record
            .badges
            .iter()
            .any(|b| matches!(b, crate::audit::AuditBadge::JsonHealed)));
    }

    #[test]
    fn missing_finish_reason_defaults_to_unknown() {
        let state = TransformState::new(ApiVersion::ChatCompletions);
        let mut meta = make_meta(vec![]);

        let record = crate::pipeline::response_pipeline::assemble_audit_record(&state, &mut meta, false, crate::pricing::Billing::zero(crate::pricing::Currency::USD));
        assert_eq!(record.finish_reason, "unknown");
    }

    #[test]
    fn metadata_fields_propagated() {
        let state = TransformState::new(ApiVersion::ChatCompletions);
        let mut meta = make_meta(vec![]);
        meta.app_id = Some("my-app".to_string());
        // `meta.session_id` carries the already-hashed gateway session UUID
        // string; the record stores it verbatim.
        let hashed = content::session_id_from_client("sess-123", meta.tenant_id, meta.user_id);
        meta.session_id = Some(hashed);
        meta.is_streaming = false;

        let record = crate::pipeline::response_pipeline::assemble_audit_record(&state, &mut meta, false, crate::pricing::Billing::zero(crate::pricing::Currency::USD));

        assert_eq!(record.app_id.as_deref(), Some("my-app"));
        assert_eq!(record.session_id, Some(hashed));
        assert!(!record.stream);
    }

    #[test]
    fn test_forward_auth_context_debug_redacted() {
        let ctx = ForwardAuthContext {
            header_name: "authorization".to_string(),
            header_value: "Bearer sk-secret-key-12345".to_string(),
        };
        let debug = format!("{ctx:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("sk-secret-key-12345"));
        assert!(debug.contains("authorization"));
    }

    #[test]
    fn truncate_with_marker_under_cap_is_noop() {
        assert_eq!(truncate_with_marker("hello", 10), "hello");
        assert_eq!(truncate_with_marker("", 10), "");
    }

    #[test]
    fn truncate_with_marker_over_cap_appends_ellipsis() {
        let long = "a".repeat(600);
        let result = truncate_with_marker(&long, 500);
        assert!(result.ends_with('…'));
        // 500 ASCII bytes + 3-byte '…' = 503 bytes total.
        assert_eq!(result.len(), 503);
    }

    #[test]
    fn truncate_with_marker_respects_utf8_boundary() {
        // 2-byte chars ('é'), 300 of them = 600 bytes. Cap at 499 — floor_char_boundary
        // must snap back to 498 (even), then append '…'.
        let s = "é".repeat(300);
        let result = truncate_with_marker(&s, 499);
        assert!(result.ends_with('…'));
        assert!(result.is_char_boundary(result.len() - '…'.len_utf8()));
    }
}
