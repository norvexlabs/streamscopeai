//! Axum entry point for `/mcp/<slug>`.
//!
//! - Real authentication: requires a valid proxy-issued `sk-*` Bearer token
//!   (or a spec-OAuth JWT). The route layer uses
//!   [`streamscope_core::auth::authenticate_proxy`]; a `vk-*` forward-auth key
//!   on this mount is rejected with a generic 401 (it is accepted on
//!   `/fwd/{key}/mcp/<slug>`). No anonymous SYSTEM fallback.
//! - Workspace gating: the slug resolves to a virtual server, and the handler
//!   rejects the request (403) when the key's workspace allowlist doesn't
//!   permit that server.
//! - Rate limiting: per-user RPM/TPM/budget checks fire on every request, same
//!   as `/v1/*`.
//! - Resolves the slug to `(virtual_server, [routes])` from the per-tenant
//!   config snapshot, then verifies the workspace permits the addressed server.
//! - Dispatches the JSON-RPC method:
//!     * `initialize` — forwards to the first enabled route, returns merged
//!       capabilities, stamps an `Mcp-Session-Id` response header.
//!     * `tools/list` / `prompts/list` — fans out to all routes in parallel,
//!       stamps namespace prefixes, drops filtered names, concatenates.
//!     * `resources/list` — same fan-out; records each URI's origin into
//!       the session map for later `resources/read`.
//!     * `tools/call` / `prompts/get` / `resources/read` — strips the prefix
//!       (or looks up the URI's origin), routes to the single owning
//!       upstream, returns its response verbatim.
//!     * Anything else: forwards to the first route as-is (best-effort
//!       passthrough).
//! - Emits one `McpAuditRecord` per HTTP request.
//!
//! Client-filled header inputs: each routed upstream declares which headers
//! the calling client supplies (`super::upstream_auth`). Both mounts forward
//! exactly those declared names and nothing else. `/fwd/{key}/mcp/<slug>`
//! takes the gateway key in the path (any gateway key) and is required only
//! when a routed upstream takes the client's own `Authorization` header, which
//! on `/mcp/<slug>` carries the gateway credential.

use std::debug_assert_matches;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, Response, StatusCode};
use streamscope_core::audit::McpAuditRecord;
use streamscope_core::auth::{TenantRequestCtx, UserContext};
use streamscope_core::config::mcp::McpVirtualServer;
use streamscope_core::error::{AppError, AuthError};
use streamscope_core::mcp::sse_events::McpSseEventRecord;
use streamscope_core::proxy::AppState;
use uuid::Uuid;

use super::jsonrpc::{
    AUTH_REQUIRED, InboundMessage, JsonRpcRequest, JsonRpcResponse, McpScope, RATE_LIMITED, RpcId,
    classify_method, INSUFFICIENT_SCOPE, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    MCP_BLOCKED_BY_POLICY,
    MCP_OAUTH_CLIENT_NOT_CONFIGURED, MCP_UPSTREAM_SSRF_REFUSED, MCP_USER_CREDENTIAL_EXPIRED,
    MCP_USER_CREDENTIAL_MISSING, MCP_USER_OAUTH_REFRESH_FAILED,
    METHOD_NOT_FOUND, PARSE_ERROR, ROUTE_NOT_FOUND, TOOL_NOT_FOUND,
    UPSTREAM_CREDENTIAL_UNAVAILABLE, UPSTREAM_ERROR,
};
/// Ceiling on an inbound MCP request body. Shared by the normal read and by
/// [`peek_rpc_id`], which reads the same body on a pre-parse rejection — two
/// different limits would let a body be rejected by one path and accepted by
/// the other.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

use super::event_bus::{PerUserEventBus, UserEvent};
use super::modern::{self, ModernError, ProtocolEra, RequestMeta};
use super::oauth::{self, OauthState, RotationSink};
use super::session::McpSessionMap;
use super::upstream::{self, UpstreamError, UpstreamReply};
use streamscope_core::mcp::header_inputs::UpstreamAuth;
use super::virtualize;

pub struct McpAppState {
    /// Channel to the dedicated MCP audit pipeline.
    pub mcp_audit_tx: streamscope_core::audit::AuditSender<McpAuditRecord>,
    /// Channel to the dedicated web-search audit pipeline. Populated for
    /// every backend call made by the built-in `/mcp/web` virtual server.
    pub web_audit_tx: streamscope_core::audit::AuditSender<streamscope_core::web::WebAuditRecord>,
    /// Channel for proxy-side `McpSseEventRecord` rows that back the
    /// `Last-Event-ID` replay surface. Bounded; the pump uses `try_send`
    /// and drops on overflow (best-effort durability — audit row is the
    /// long-term record).
    pub mcp_sse_event_tx: streamscope_core::audit::AuditSender<McpSseEventRecord>,
    /// Per-`(tenant, mcp_session_id)` monotonic SSE sequence allocator.
    /// The pump calls `next()` immediately before encoding an SSE frame to
    /// produce the `q` field that lands inside the signed `ssevt.…` id.
    pub sse_seq: Arc<super::sse_seq::McpSseSequenceMap>,
    /// HTTP client for outbound calls to upstream MCP servers.
    pub mcp_client: reqwest::Client,
    /// Per-upstream capability cache (`tools/list`, `prompts/list`,
    /// `resources/list`, `resources/templates/list`). Keyed by `(upstream_id,
    /// cred_version, method)` — cred_version bumps invalidate naturally.
    /// `initialize` is *not* cached: stateful upstreams issue a fresh
    /// `Mcp-Session-Id` per agent, and the cache stores only the JSON body.
    pub capability_cache: Arc<super::cache::CapabilityCache>,
    /// Per-user OAuth state — single-flight refresh locks +
    /// fresh-rotation overlay.
    pub oauth_state: Arc<OauthState>,
    /// Optional sink that forwards rotated credentials to admin-api
    /// through the edge outbox. `None` in test scaffolding (refresh still works
    /// locally; persistence is best-effort).
    pub rotation_sink: Option<Arc<dyn RotationSink>>,
    /// Per-`Mcp-Session-Id` upstream + bearer pin so the agent's reply to a
    /// server-initiated `sampling`/`elicitation` request can target the
    /// originating upstream on the reverse path.
    pub session_map: Arc<McpSessionMap>,
    /// Per-(tenant, user) broadcast bus that fans server-initiated MCP events
    /// (sampling, elicitation, list_changed) out to any concurrent
    /// `GET /mcp/<slug>` SSE subscriber. Sources of events: the in-band
    /// `tools/call` / `prompts/get` SSE pump on this proxy instance, the
    /// gateway-owned upstream listeners, and the `mcp_user_event`s other
    /// instances raised, delivered in this edge's config sync answers.
    pub event_bus: Arc<PerUserEventBus>,
    /// Per-`(tenant, upstream, agent_session)` legacy SSE upstream sessions.
    /// Empty until a request hits a `transport='sse'` upstream — the GET
    /// /sse channel is opened lazily on first call.
    pub legacy_sse_map: Arc<super::legacy_sse::LegacySseSessionMap>,
    /// Gateway-maintained notification listeners, one long-lived upstream
    /// stream per `(tenant, user, virtual server, upstream)`.
    ///
    /// Without them an upstream's notifications reach the gateway only when
    /// they ride an in-flight response, so a server that announces a change
    /// with nothing in flight is silent — and, less obviously, the era a
    /// request leg speaks could not be chosen freely, because notification
    /// sourcing was a side effect of the *legacy* request path.
    pub listeners: Arc<super::upstream_listen::UpstreamListenerMap>,
    /// Cancellation token signalled at proxy shutdown. The long-lived
    /// `GET /mcp/<slug>` SSE handler races this against its broadcast
    /// receiver and the keepalive interval; on cancellation it sends a
    /// final `: shutdown\n\n` SSE comment and closes cleanly so the agent
    /// reconnects (with `Last-Event-ID` for replay) rather than seeing a
    /// TCP RST. Without this, axum's graceful_shutdown force-closes the
    /// stream and clients can't tell "voluntary close" from "crash".
    pub shutdown_token: tokio_util::sync::CancellationToken,
}

impl McpAppState {
    pub fn with_rotation_sink(
        mcp_audit_tx: streamscope_core::audit::AuditSender<McpAuditRecord>,
        mcp_sse_event_tx: streamscope_core::audit::AuditSender<McpSseEventRecord>,
        web_audit_tx: streamscope_core::audit::AuditSender<streamscope_core::web::WebAuditRecord>,
        sse_seq: Arc<super::sse_seq::McpSseSequenceMap>,
        rotation_sink: Option<Arc<dyn RotationSink>>,
        event_bus: Arc<PerUserEventBus>,
        shutdown_token: tokio_util::sync::CancellationToken,
    ) -> Arc<Self> {
        let client = streamscope_core::tls::add_custom_roots(
            reqwest::Client::builder()
                .pool_max_idle_per_host(8)
                .timeout(std::time::Duration::from_secs(
                    crate::settings::proxy_settings().mcp_http_client_timeout_secs,
                )),
            streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
        )
        .build()
        .expect("build mcp http client");
        let session_map = McpSessionMap::new();
        let legacy_sse_map = super::legacy_sse::LegacySseSessionMap::new(
            crate::settings::proxy_settings().mcp_legacy_sse_max_sessions_per_instance,
        );
        // Shares the legacy-SSE cap: both bound the number of long-lived
        // upstream connections one proxy instance holds open, which is the
        // resource that actually runs out.
        let listeners = super::upstream_listen::UpstreamListenerMap::new(
            crate::settings::proxy_settings().mcp_legacy_sse_max_sessions_per_instance,
        );
        // Periodic eviction of idle sessions + idle bus entries + idle
        // legacy-SSE upstream sessions + idle SSE-sequence counters.
        // Cheap (DashMap shard scans); one tokio task drives them all so
        // the sweep cadence stays in sync.
        {
            let map = session_map.clone();
            let bus = event_bus.clone();
            let sse = legacy_sse_map.clone();
            let listen = listeners.clone();
            let seq = sse_seq.clone();
            tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(
                    crate::settings::proxy_settings().mcp_sweep_interval_secs,
                );
                let seq_max_age = std::time::Duration::from_secs(
                    crate::settings::proxy_settings().mcp_sse_retention_secs,
                );
                loop {
                    tokio::time::sleep(interval).await;
                    let evicted = map.sweep();
                    if evicted > 0 {
                        tracing::debug!(evicted, "mcp session sweeper evicted idle entries");
                    }
                    let pruned = bus.prune_idle();
                    if pruned > 0 {
                        tracing::debug!(pruned, "mcp event bus pruned idle entries");
                    }
                    let sse_dropped = sse.sweep();
                    if sse_dropped > 0 {
                        tracing::debug!(sse_dropped, "legacy SSE session map evicted idle sessions");
                    }
                    // Listeners age on the session idle clock: one that no
                    // downstream subscriber has touched within the window is
                    // an open upstream connection nobody is reading.
                    let listeners_dropped = listen.sweep(std::time::Duration::from_secs(
                        crate::settings::proxy_settings().mcp_session_idle_ttl_secs,
                    ));
                    if listeners_dropped > 0 {
                        tracing::debug!(
                            listeners_dropped,
                            "mcp upstream listeners closed after going idle"
                        );
                    }
                    let seq_pruned = seq.prune_idle(seq_max_age);
                    if seq_pruned > 0 {
                        tracing::debug!(seq_pruned, "mcp sse sequence map pruned idle entries");
                    }
                }
            });
        }
        // Graceful shutdown closes every gateway-owned upstream stream. Left
        // running they would keep reconnecting into a sink whose audit
        // channel is draining, and the upstream would hold connections open
        // for a process that is going away.
        {
            let listen = listeners.clone();
            let token = shutdown_token.clone();
            tokio::spawn(async move {
                token.cancelled().await;
                listen.cancel_all();
            });
        }

        Arc::new(Self {
            mcp_audit_tx,
            mcp_sse_event_tx,
            web_audit_tx,
            sse_seq,
            mcp_client: client,
            capability_cache: super::cache::CapabilityCache::new(),
            oauth_state: OauthState::new(),
            rotation_sink,
            session_map,
            event_bus,
            legacy_sse_map,
            listeners,
            shutdown_token,
        })
    }
}

/// Combined per-request state — the proxy's existing `AppState` carries
/// tenant config + audit, and `McpAppState` carries the MCP-only channel.
#[derive(Clone)]
pub struct McpRouterState {
    pub app: Arc<AppState>,
    pub mcp: Arc<McpAppState>,
}

/// Per-request authentication context for the MCP dispatcher. Carries the
/// tenant + user identity (so per-user OAuth credentials can be resolved
/// against the tenant's snapshot) plus the OAuth refresh / overlay state.
///
/// Also carries the legacy-SSE dispatch handles (`legacy_sse_map`,
/// `event_bus`, `mcp_audit_tx`) — required when an upstream's transport is
/// `sse`, so `call_cached` can route into the per-agent SSE session
/// instead of the Streamable HTTP path. Passed by reference everywhere;
/// the underlying state is `Arc`/clone-cheap.
pub struct AuthCtx {
    pub tenant_id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub key_id: Option<Uuid>,
    pub virtual_server_id: Uuid,
    pub oauth_state: Arc<OauthState>,
    pub rotation_sink: Option<Arc<dyn RotationSink>>,
    pub mcp_config: streamscope_core::config::mcp::McpConfig,
    /// Per-tenant settings for the built-in `internal://web`
    /// upstream. Snapshotted at request entry so the virtual server's
    /// dispatch is independent of any concurrent config-sync update.
    pub web_settings: streamscope_core::web::WebSettings,
    /// Inline injection-guardrail settings for the built-in `internal://web`
    /// upstream. Snapshotted at request entry alongside `web_settings`; the
    /// virtual server's `build_ctx` threads it into the direct `/mcp/web`
    /// observe scan.
    pub guardrail: streamscope_core::guardrail::GuardrailSettings,
    pub legacy_sse_map: Arc<super::legacy_sse::LegacySseSessionMap>,
    /// The gateway's own notification listeners — see
    /// [`McpAppState::listeners`].
    pub listeners: Arc<super::upstream_listen::UpstreamListenerMap>,
    pub event_bus: Arc<PerUserEventBus>,
    pub mcp_audit_tx: streamscope_core::audit::AuditSender<McpAuditRecord>,
    /// Channel for the built-in `/mcp/web` audit pipeline. The
    /// virtual-server dispatch emits one record per backend call.
    pub web_audit_tx: streamscope_core::audit::AuditSender<streamscope_core::web::WebAuditRecord>,
    /// The SSRF-guarded client pair the built-in `/mcp/web` server sends
    /// its search backend calls through (`AppState::web_search_clients`).
    pub web_search_clients: Arc<streamscope_core::extension_http::ExtensionClients>,
    /// Persistence channel + sequence allocator for `Last-Event-ID` replay.
    /// Shared with the Streamable-HTTP pump (`McpAppState`) so resumption
    /// works uniformly across transports.
    pub mcp_sse_event_tx: streamscope_core::audit::AuditSender<McpSseEventRecord>,
    pub sse_seq: Arc<super::sse_seq::McpSseSequenceMap>,
    /// Session map for cross-call protocol-version stamping. Same instance
    /// the Streamable HTTP path uses; passed through so legacy-SSE audit
    /// emission (`BusAuditEventSink`) can stamp `protocol_version` on the
    /// rows it emits without a per-call lookup detour.
    pub session_map: Arc<McpSessionMap>,
    /// Which protocol era the downstream client is speaking.
    ///
    /// Read by `call_cached` to decide where an upstream's `Mcp-Session-Id`
    /// comes from: a legacy client supplies one and the gateway relays it; a
    /// modern client supplies none, so the gateway must have opened that
    /// upstream connection itself and looks the session up in its own
    /// handshake map. Getting this wrong is not a crash but a silent
    /// `-32600 Session not found` from the upstream on every call.
    pub era: ProtocolEra,
    /// The capabilities the gateway declares to a **modern upstream** on this
    /// request.
    ///
    /// The modern era declares capabilities per request, so — unlike the
    /// legacy handshake, which is opened once and shared across callers — this
    /// can state what the client on *this* request can actually do. § MRTR has
    /// a server ask for input only within what the client declared, so this
    /// value is what decides whether an upstream ever asks.
    ///
    /// **A legacy client is declared as `{}`, deliberately**, and that is the
    /// load-bearing half of how the gateway serves a legacy client from a
    /// modern upstream. A modern upstream returns a question as
    /// `InputRequiredResult` *data*; a legacy client has no way to receive
    /// one, because its revision expects a server-initiated request on a live
    /// stream and a stateless upstream holds no stream to send it on.
    /// Under-declaring means a conforming upstream never asks and the tool
    /// completes or fails honestly. Over-declaring would produce a question
    /// the gateway could only refuse — the same outcome, reached later and
    /// after the upstream has done the work.
    pub upstream_client_capabilities: serde_json::Value,
    /// The log level to opt this request's upstream calls into
    /// (`_meta.logLevel`), or `None` to opt out.
    ///
    /// A modern client sets it per request. A legacy client sets it once with
    /// `logging/setLevel`, which the modern era deleted — so for a legacy
    /// client this carries the level remembered for that authenticated
    /// caller, which is what keeps `logging/setLevel` from becoming a silent
    /// no-op against a modern upstream.
    pub upstream_log_level: Option<String>,
    /// The upstream an MRTR retry is aimed at, and that upstream's own opaque
    /// `requestState` when it minted one, recovered from the wrapper the
    /// client quoted back.
    ///
    /// The outer `None` is a first attempt, or a retry whose state the gateway
    /// minted for its own legacy-upstream bridge (there is nothing to quote
    /// back there — the bridge re-issues instead). The INNER `None` is an
    /// upstream that asked without keeping state, which § MRTR allows: the
    /// retry still has to reach that upstream, so the two absences are not
    /// the same absence.
    pub mrtr_upstream: Option<(Uuid, Option<String>)>,
    /// The digest of the params **the client sent**, before virtualization or
    /// any policy rewrite.
    ///
    /// Bound into a minted `requestState` and recomputed by
    /// `verify_request_state` on the retry, so the two must be taken from the
    /// same bytes. The client retries with what it sent, not with what the
    /// gateway forwarded.
    pub client_params_digest: String,
    /// The gateway's `serverInfo` for this mount, stamped into an
    /// `InputRequiredResult` relayed from an upstream.
    pub server_info: serde_json::Value,
    /// The inbound headers the routed upstreams declare as client-filled —
    /// only those names, minus any two upstreams both claim
    /// ([`super::upstream_auth::capture_client_inputs`]). Held for this
    /// request only; never stored.
    pub client_inputs: HeaderMap,
    /// The upstreams' stored input values this request decrypted, so each is
    /// decrypted once however often the request resolves its upstream.
    pub inputs_memo: super::upstream_auth::InputsMemo,
    /// The portal page where the caller fills their values and signs in to
    /// upstreams ([`portal_sign_ins_url`]); `None` when the tenant's console
    /// URL is unknown.
    pub sign_ins_url: Option<String>,
}

impl AuthCtx {
    /// What an MRTR retry may carry to `upstream_id`.
    ///
    /// Checks the id rather than trusting the presence of the field: a
    /// virtual server fans out across several upstreams, and handing upstream
    /// B a blob minted by upstream A — or the answers meant for A — would at
    /// best be rejected and at worst be acted on.
    pub fn mrtr_retry_for(&self, upstream_id: Uuid) -> modern::MrtrRetry<'_> {
        modern::MrtrRetry::resolve(self.mrtr_upstream.as_ref(), upstream_id)
    }
}

/// The tenant's portal page listing the caller's MCP sign-ins and values:
/// `<console>/portal/t/<tenant>/mcp/connections`, or `None` when the console
/// URL or the tenant slug is unknown.
pub(crate) fn portal_sign_ins_url(cfg: &streamscope_core::config::TenantConfig) -> Option<String> {
    let base = cfg.admin_public_url.as_deref()?.trim_end_matches('/');
    (!base.is_empty() && !cfg.tenant_slug.is_empty())
        .then(|| format!("{base}/portal/t/{}/mcp/connections", cfg.tenant_slug))
}

/// Map an `UpstreamError` to its `(code, message)` JSON-RPC pair. Pulled out
/// of the inline match so the audit emitter and the response builder use
/// exactly the same code for the same error.
pub(crate) fn upstream_error_to_jsonrpc(err: &UpstreamError, sign_ins_url: Option<&str>) -> (i32, String) {
    // Where the user acts on a missing value or sign-in: the exact portal
    // page when the console URL is known, else the portal by name.
    let where_to = |verb: &str| match sign_ins_url {
        Some(url) => format!("{verb} in the portal's MCP sign-ins page: {url}"),
        None => format!("{verb} in the portal's MCP sign-ins page"),
    };
    match err {
        UpstreamError::TransportUnsupported(t) => (
            super::jsonrpc::MCP_UPSTREAM_CONFIG_UNSUPPORTED,
            format!("upstream transport not supported: {t}"),
        ),
        // A modern upstream states a protocol refusal as a JSON-RPC code
        // inside a non-2xx body, and that code is the whole answer:
        // `-32021` names the capability that was missing, where "upstream
        // HTTP 400" names nothing. Only the three codes the specification
        // reserves for itself pass through — an arbitrary upstream code
        // relayed as the gateway's own could collide with one this gateway
        // mints and mean something else entirely. The message stays
        // synthesized: an upstream's own text is never forwarded to a client.
        UpstreamError::Http {
            status,
            jsonrpc_code: Some(code),
            ..
        } if modern::identifies_modern_server(*code) => (
            *code,
            format!("upstream refused the request ({code}, HTTP {status})"),
        ),
        // An upstream answering `-32601` is stating the method does not
        // exist, and that is exactly the answer the client needs. The gateway
        // forwards a method it does not classify rather than refusing it, so
        // "the upstream has no such method" IS "this gateway has no such
        // method". Collapsing it into `UPSTREAM_ERROR` renumbers to `-32603`
        // for a modern client — "the server broke while running it" — the one
        // reading that makes a client retry instead of reporting, and it also
        // costs the `404` the revision mandates. Deliberately NOT added to
        // `identifies_modern_server`: legacy servers emit this code too, so it
        // is evidence about the method, never about the era.
        //
        // This needs no era gate, and the reason is worth keeping: the arm can
        // only fire on a NON-2xx carrying a `-32601` body, which is the modern
        // shape (§ Protocol Version Header mandates 404 + `-32601`). A legacy
        // server states an unknown method as HTTP 200 with the error in the
        // body, which never becomes an `UpstreamError::Http` at all — it
        // arrives as an ordinary response and is relayed untouched. So what a
        // legacy client sees is unchanged in every case it can actually reach.
        UpstreamError::Http {
            jsonrpc_code: Some(code),
            ..
        } if *code == METHOD_NOT_FOUND => (
            METHOD_NOT_FOUND,
            "upstream does not implement this method".to_string(),
        ),
        UpstreamError::Http { status, .. } => (UPSTREAM_ERROR, format!("upstream HTTP {status}")),
        UpstreamError::Transport(_) => (UPSTREAM_ERROR, "upstream transport error".into()),
        UpstreamError::Decode(_) => (UPSTREAM_ERROR, "upstream returned malformed JSON".into()),
        UpstreamError::EmptyBody => (UPSTREAM_ERROR, "upstream returned empty body".into()),
        UpstreamError::ResponseTooLarge { limit } => (
            UPSTREAM_ERROR,
            format!("upstream response exceeded the {limit}-byte limit"),
        ),
        UpstreamError::BadSse => (UPSTREAM_ERROR, "upstream returned malformed SSE".into()),
        UpstreamError::ServerInitiatedRequest(v) => (
            super::jsonrpc::MCP_UPSTREAM_INPUT_UNSUPPORTED,
            format!(
                "the upstream requires interactive input ({}) on a method the gateway reads in one shot",
                v.get("method").and_then(|m| m.as_str()).unwrap_or("unknown")
            ),
        ),
        UpstreamError::CredentialUnavailable => (
            UPSTREAM_CREDENTIAL_UNAVAILABLE,
            "upstream credential is not configured".to_string(),
        ),
        UpstreamError::UserInputsMissing => (
            MCP_USER_CREDENTIAL_MISSING,
            format!(
                "this MCP server needs values only you can enter — {}",
                where_to("enter them")
            ),
        ),
        UpstreamError::ClientHeaderMissing(headers) => (
            AUTH_REQUIRED,
            format!(
                "this upstream needs a valid {headers} header from the client: it was not sent, or \
                 its value is not one the server accepts"
            ),
        ),
        UpstreamError::UserCredentialMissing => (
            MCP_USER_CREDENTIAL_MISSING,
            format!("this MCP server needs you to sign in first — {}", where_to("sign in")),
        ),
        UpstreamError::UserCredentialExpired => (
            MCP_USER_CREDENTIAL_EXPIRED,
            format!(
                "your sign-in to this MCP server expired and could not be renewed — {}",
                where_to("sign in again")
            ),
        ),
        UpstreamError::UserOauthRefreshFailed(detail) => (
            MCP_USER_OAUTH_REFRESH_FAILED,
            format!("oauth refresh failed: {detail}"),
        ),
        UpstreamError::OauthClientNotConfigured(field) => (
            MCP_OAUTH_CLIENT_NOT_CONFIGURED,
            format!("oauth client not fully configured: {field} is missing"),
        ),
        UpstreamError::SsrfRefused(detail) => (
            MCP_UPSTREAM_SSRF_REFUSED,
            format!("upstream URL refused by SSRF guard: {detail}"),
        ),
        UpstreamError::SessionLost(detail) => (
            super::jsonrpc::MCP_UPSTREAM_SESSION_LOST,
            format!("legacy SSE upstream session lost: {detail}"),
        ),
    }
}

/// Resolved per-request identity. `virtual_server_id` is the VS addressed by
/// the URL slug, already checked against the key's workspace allowlist — the
/// route layer rejects the request before this is constructed if the bearer is
/// missing, on the wrong mount, or the workspace doesn't permit the addressed
/// server.
struct Identity {
    user_id: Uuid,
    tenant_id: Uuid,
    key_id: Option<Uuid>,
    virtual_server_id: Uuid,
    user: UserContext,
    /// The configuration of the caller's tenant, from the same registry load
    /// that authenticated it: every config read of the request goes through
    /// it, never a second load.
    config: Arc<streamscope_core::config::TenantConfig>,
    /// The protocol version the client put in `MCP-Protocol-Version`, when it
    /// sent one.
    ///
    /// The audit row prefers the version *negotiated* with the upstream —
    /// pinned on the session map at `initialize` — but a modern client never
    /// performs one, so for the entire modern era that lookup would return
    /// nothing and every such row would report no version at all. Which is
    /// precisely when the column becomes interesting: it is how an operator
    /// sees which clients have moved to the new revision.
    ///
    /// `None` means the client sent no header, not that it declared nothing —
    /// the assumed spec default is deliberately not recorded here, because
    /// stamping it would attribute traffic to a revision nobody named.
    declared_protocol_version: Option<String>,
}

/// Resolve the VS addressed by `slug` and assert the key's workspace permits
/// it. Returns 403 [`AuthError::WorkspaceMcpAccessDenied`] when the workspace
/// allowlist excludes the server, and a generic invalid-key error when the
/// tenant config or slug can't be resolved (so a probing client learns nothing).
fn resolve_addressed_vs(
    ctx: &TenantRequestCtx,
    slug: &str,
    credential: &str,
) -> Result<Uuid, AppError> {
    let invalid = || {
        AppError::Auth(AuthError::UnrecognizedFormat(
            streamscope_core::auth::credential_prefix(credential, 12),
        ))
    };
    // Resolve the slug against the CALLER's tenant config only — the one the
    // credential authenticated against — never the SYSTEM snapshot, which would
    // gate workspace access against another tenant's virtual servers.
    let (vs, _) = ctx.config.mcp.lookup_by_slug(slug).ok_or_else(invalid)?;
    let ctx = &ctx.user;
    if !ctx.allows_virtual_server(vs.id) {
        return Err(AppError::Auth(AuthError::WorkspaceMcpAccessDenied {
            workspace_id: ctx.workspace_id,
            virtual_server_id: vs.id,
        }));
    }
    Ok(vs.id)
}

/// Resolve a request bearer that might be either a proxy-issued `sk-*` key or a
/// proxy-issued spec-OAuth JWT. Tried in order:
///
///   1. Three-segment JWT shape → `validate_jwt_bearer` (per-tenant signature +
///      audience-binding + revocation).
///   2. Otherwise → an `sk-*` key, authenticated against the registry.
///
/// On both paths we return the same `Identity` shape so downstream code is
/// blind to which auth flow ran.
async fn resolve_identity_with_jwt(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
) -> Result<Identity, AppError> {
    let bearer = extract_bearer(headers).ok_or(AppError::Auth(AuthError::MissingHeader))?;
    if super::spec_oauth::looks_like_jwt(&bearer) {
        let ctx = super::spec_oauth::validate_jwt_bearer(state, slug, &bearer).await?;
        let virtual_server_id = resolve_addressed_vs(&ctx, slug, &bearer)?;
        return Ok(Identity::new(ctx, virtual_server_id));
    }
    resolve_identity_from_token(state, bearer, slug, false).await
}

/// Resolve identity from a bearer/path key for the addressed `slug`.
/// `fwd_mount` selects the mount: `false` for `/mcp/<slug>`, which takes
/// proxy-issued `sk-*` keys only; `true` for `/fwd/{key}/mcp/<slug>`, which
/// takes any gateway key in its path.
async fn resolve_identity_from_token(
    state: &AppState,
    token: String,
    slug: &str,
    fwd_mount: bool,
) -> Result<Identity, AppError> {
    let registry = state.tenant_registry.load();
    let ctx = if fwd_mount {
        streamscope_core::auth::authenticate(&token, &registry)?
    } else {
        streamscope_core::auth::authenticate_proxy(&token, &registry)?
    };
    let virtual_server_id = resolve_addressed_vs(&ctx, slug, &token)?;
    Ok(Identity::new(ctx, virtual_server_id))
}

impl Identity {
    fn new(ctx: TenantRequestCtx, virtual_server_id: Uuid) -> Self {
        Self {
            user_id: ctx.user.user_id,
            tenant_id: ctx.user.tenant_id,
            key_id: ctx.user.key_id,
            virtual_server_id,
            user: ctx.user,
            config: ctx.config,
            declared_protocol_version: None,
        }
    }
}

pub(crate) fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    // RFC 7235: scheme matching is case-insensitive.
    let trimmed = value.trim_start();
    let (scheme, rest) = trimmed.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("Bearer") {
        Some(rest.trim_start().to_string())
    } else {
        None
    }
}

/// Per-spec MCP 2025-11-25 § Streamable HTTP — Security Warning: servers MUST
/// validate the `Origin` header on incoming connections (anti-DNS-rebinding)
/// and respond 403 on mismatch.
///
/// Per-tenant: the slug → tenant lookup yields the tenant's resolved
/// `proxy_public_url`. That single URL is the entire allowlist — there is
/// no global origin list. Tokens minted under tenant A's URL can only be
/// posted by browsers at that origin; cross-tenant browser traffic is
/// blocked even when the slug resolves.
///
/// Returns `None` when the request is acceptable (no Origin header, or
/// Origin matches the tenant's URL). Returns `Some(response)` — a 403
/// JSON-RPC error with no id — when the Origin header is present but
/// rejected, or when the slug resolves to a tenant with no `proxy_public_url`
/// configured (fail-closed; the operator must set the URL).
///
/// CLI / non-browser clients don't send `Origin`; allow them. Browser
/// clients send a canonical `scheme://host[:port]` value, which we compare
/// verbatim (after stripping trailing slash for robustness).
fn validate_origin_header(
    state: &AppState,
    slug: &str,
    headers: &HeaderMap,
) -> Option<Response<Body>> {
    let raw = headers.get("origin").and_then(|v| v.to_str().ok())?.trim().trim_end_matches('/');
    if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
        return None;
    }

    // Every tenant's resolved `proxy_public_url` for this slug. Two tenants
    // legitimately can share a non-OAuth slug (slug uniqueness is enforced only
    // when `oauth_enabled` is true), so we accept Origin if it matches *any*
    // candidate. Auth still binds the request to exactly one tenant downstream —
    // this guard exists for the browser-CORS contract, not for tenant routing.
    //
    // 503 only when *no* candidate tenant has a URL configured. 403 when at
    // least one URL is set but none match the inbound Origin.
    //
    // This runs before the request has authenticated, so it reads the registry's
    // prebuilt slug index rather than walking every tenant — otherwise any
    // anonymous request carrying an Origin costs O(tenants).
    let registry = state.tenant_registry.load();
    let candidates: &[String] = registry
        .mcp_slug(slug)
        .map_or(&[], |entry| entry.proxy_urls.as_slice());

    if candidates.is_empty() {
        tracing::warn!(
            slug = %slug,
            origin = %raw,
            "MCP: rejecting request — no tenant for slug has proxy_public_url configured"
        );
        return Some(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            RpcId::Null,
            INVALID_REQUEST,
            "public URL not configured for this tenant",
        ));
    }

    if candidates.iter().any(|c| c == raw) {
        return None;
    }

    tracing::warn!(
        slug = %slug,
        origin = %raw,
        allowed = ?candidates,
        "MCP: rejecting request — Origin does not match any tenant's proxy_public_url for this slug"
    );
    Some(error_response(
        StatusCode::FORBIDDEN,
        RpcId::Null,
        INVALID_REQUEST,
        "origin not allowed",
    ))
}

/// Decide which protocol **era** a request belongs to, from the
/// `MCP-Protocol-Version` header alone.
///
/// The header is the only era signal this gateway consults, deliberately. It
/// is present on every request in every revision from `2025-06-18` on, and
/// `2026-07-28` makes it mandatory *and* body-corroborated. Sniffing the body
/// shape instead ("does it carry `_meta`?") reintroduces exactly the ambiguity
/// the field exists to remove, and would let a client select an era by
/// accident.
///
/// - Missing → `2025-03-26`, per the compatibility clause both revisions
///   carry for clients that pre-date the header. A *modern* client that omits
///   it is caught later by [`validate_modern_body`], which sees the modern
///   `_meta` and rejects the missing header as a `HeaderMismatch`.
/// - Present and supported → that revision's era.
/// - Present and unknown → `UnsupportedProtocolVersion`, which is what a
///   modern client needs in order to retry at a version we both speak. A
///   legacy client sees the 400 it would have seen before; the typed body is
///   simply more than it reads.
fn resolve_protocol_era(headers: &HeaderMap) -> Result<ProtocolEra, ModernError> {
    let raw = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let Some(raw) = raw else {
        tracing::debug!(
            assumed = crate::settings::MCP_DEFAULT_PROTOCOL_VERSION,
            "MCP-Protocol-Version header missing; assuming spec default"
        );
        return Ok(ProtocolEra::Legacy(
            crate::settings::MCP_DEFAULT_PROTOCOL_VERSION.to_string(),
        ));
    };
    if !crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS.contains(&raw) {
        tracing::warn!(
            version = %raw,
            "MCP: rejecting request — unsupported MCP-Protocol-Version"
        );
        return Err(ModernError::unsupported_version(
            raw,
            crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS,
        ));
    }
    Ok(if modern::is_modern(raw) {
        ProtocolEra::Modern(raw.to_string())
    } else {
        ProtocolEra::Legacy(raw.to_string())
    })
}

/// Validate the request body against the era its header declared, and pull
/// out the modern `_meta` envelope when there is one.
///
/// Returns `Ok(None)` for anything that carries no per-request metadata — a
/// notification, or any legacy-era message — and `Ok(Some(meta))` for a
/// modern request that passed every check.
///
/// The legacy branch is not a no-op: a *modern* client that forgot the
/// `MCP-Protocol-Version` header would otherwise be silently served legacy
/// semantics, quietly losing `resultType`, the freshness hints, and the MRTR
/// bridge, with nothing anywhere reporting a problem. Catching the modern
/// `_meta` in a request the header called legacy turns that into the
/// `HeaderMismatch` the transport specifies.
fn validate_era_body(
    era: &ProtocolEra,
    headers: &HeaderMap,
    inbound: &InboundMessage,
) -> Result<Option<RequestMeta>, ModernError> {
    let body_version = |req: &JsonRpcRequest| -> Option<String> {
        req.params
            .as_ref()
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(modern::META_PROTOCOL_VERSION))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    if !era.is_modern() {
        if let InboundMessage::Request(r) | InboundMessage::Notification(r) = inbound
            && let Some(v) = body_version(r)
            && modern::is_modern(&v)
        {
            return Err(ModernError::header_mismatch(format!(
                "body declares protocol version {v} but the MCP-Protocol-Version header says {}",
                era.version()
            )));
        }
        return Ok(None);
    }

    match inbound {
        // § Sending Messages: "The client MUST NOT send JSON-RPC responses."
        // Server-initiated requests are gone in this era, so there is nothing
        // a client response could be answering — accepting one would mean
        // routing it into the legacy reverse path, which no modern client
        // could have opened.
        InboundMessage::Response(_) => Err(ModernError::invalid_request(
            "MCP 2026-07-28 defines no client-to-server responses; server input requests are answered by retrying the original request with inputResponses",
        )),
        InboundMessage::Notification(n) => {
            if modern::is_removed_notification_in_modern(&n.method) {
                return Err(ModernError::invalid_request(format!(
                    "{} was removed in MCP 2026-07-28",
                    n.method
                )));
            }
            // § Sending Messages, Note: header requirements for notification
            // POSTs are deliberately not defined by this revision, so a
            // notification is not header-validated. It also carries no
            // `_meta` envelope we need.
            Ok(None)
        }
        InboundMessage::Request(r) => {
            if modern::is_removed_in_modern(&r.method) {
                return Err(ModernError::method_not_found(format!(
                    "{} was removed in MCP 2026-07-28",
                    r.method
                )));
            }
            let meta = modern::extract_request_meta(r.params.as_ref())?;
            // § Protocol Version Header: the header value MUST match the
            // body's. They are two views of one fact, and an intermediary
            // that routed on the header while we execute on the body is
            // exactly the divergence this check exists to prevent.
            if meta.protocol_version != era.version() {
                return Err(ModernError::header_mismatch(format!(
                    "MCP-Protocol-Version header '{}' does not match body _meta protocol version '{}'",
                    era.version(),
                    meta.protocol_version
                )));
            }
            modern::validate_transport_headers(headers, r)?;
            Ok(Some(meta))
        }
    }
}

/// Render a [`ModernError`] as the HTTP response the spec prescribes: its own
/// status code, and a JSON-RPC error body carrying the typed `data` payload
/// the client branches on.
fn modern_error_response(id: RpcId, err: &ModernError) -> Response<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": err.code,
            "message": err.message,
            "data": err.data,
        }
    });
    // `data: null` is legal JSON-RPC but noise on the wire; drop it when the
    // error carries no typed payload.
    let mut body = body;
    if err.data.is_none()
        && let Some(e) = body.get_mut("error").and_then(|e| e.as_object_mut())
    {
        e.remove("data");
    }
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(err.status)
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Recover the JSON-RPC id from a body for an error raised BEFORE the normal
/// parse.
///
/// Protocol-version validation reads only headers, so it rejects a request
/// whose body was never looked at. § Responses still requires the error to
/// echo the id — the single exemption is an id that "could not be read due a
/// malformed request", which a well-formed body declaring an unsupported
/// version is not. Falling back to `Null` therefore happens only in the case
/// the exemption actually names: a body that cannot be read or parsed.
///
/// Deliberately parses to `Value` rather than `JsonRpcRequest`: a body that is
/// valid JSON but not a valid request still carries a readable id, and that id
/// is what correlates the rejection with the call.
async fn peek_rpc_id(req: Request<Body>) -> RpcId {
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), MAX_REQUEST_BODY_BYTES).await else {
        return RpcId::Null;
    };
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .and_then(|id| serde_json::from_value::<RpcId>(id).ok())
        .unwrap_or(RpcId::Null)
}

/// Axum entry — `DELETE /mcp/{slug}`.
///
/// 405 in both eras, for two different reasons that happen to agree.
/// Legacy (2025-11-25 § Session Management) explicitly permits a server to
/// decline session teardown, and this gateway keeps no per-session state that
/// needs an explicit close — sessions sweep on idle. Modern (2026-07-28
/// § Earlier Streamable HTTP Revisions) deleted protocol-level sessions
/// outright and *mandates* 405 for a DELETE.
///
/// Origin and version validation still run first so a probing browser-hosted
/// attacker can't reach past them via DELETE.
pub async fn mcp_delete_handler(
    Path(slug): Path<String>,
    State(state): State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    let headers = req.headers();
    if let Some(resp) = validate_origin_header(&state.app, &slug, headers) {
        return resp;
    }
    if let Err(e) = resolve_protocol_era(headers) {
        return modern_error_response(RpcId::Null, &e);
    }
    error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        RpcId::Null,
        INVALID_REQUEST,
        "DELETE not supported; sessions sweep on idle",
    )
}

/// Axum entry — `GET /mcp/{slug}` long-lived SSE channel.
///
/// Authenticated like the POST path (`sk-*` Bearer or proxy-issued spec-OAuth
/// JWT). The handler subscribes the caller to a per-`(tenant_id, user_id)`
/// broadcast bus and returns a `text/event-stream` response that stays open
/// until the client disconnects or `RecvError::Lagged` fires.
///
/// Sources of events:
///
/// 1. **In-band**: the `tools/call` / `prompts/get` SSE pump on this proxy
///    classifies sampling, elicitation, and `list_changed` events as it
///    forwards them to the originating POST and ALSO publishes a copy to the
///    bus. A concurrent GET subscriber for the same user sees these without
///    polling.
///
/// 2. **Upstream listeners**: the gateway-owned listener per
///    `(tenant, user, virtual server, upstream)` (`upstream_listen`) publishes
///    what an upstream sends with no request in flight.
///
/// 3. **Cross-instance**: admin-api turns a sibling instance's audited event
///    into an `mcp_user_event` for every other instance, which receives it in
///    its next config sync answer (`edge_link::dispatch_event`).
///
/// The MCP spec leaves this endpoint OPTIONAL; clients that don't want a
/// long-lived channel simply never call GET.
pub async fn mcp_get_handler(
    Path(slug): Path<String>,
    State(state): State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    serve_get_channel(slug, state, req, None).await
}

/// Axum entry — `GET /fwd/{key}/mcp/{slug}`: the same channel, the gateway
/// key read from the path (a server whose client sends its own
/// `Authorization` is reachable only on this mount).
pub async fn mcp_fwd_get_handler(
    Path((key, slug)): Path<(String, String)>,
    State(state): State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    serve_get_channel(slug, state, req, Some(key)).await
}

/// Axum entry — `DELETE /fwd/{key}/mcp/{slug}`: answered like `/mcp/{slug}`.
pub async fn mcp_fwd_delete_handler(
    Path((_key, slug)): Path<(String, String)>,
    state: State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    mcp_delete_handler(Path(slug), state, req).await
}

/// The `GET` notification channel; `path_key` is the gateway key of the
/// `/fwd/{key}/…` mount, `None` on `/mcp/{slug}` (the key or token is then in
/// `Authorization`).
async fn serve_get_channel(
    slug: String,
    state: McpRouterState,
    req: Request<Body>,
    path_key: Option<String>,
) -> Response<Body> {
    let started = Instant::now();
    let request_id = streamscope_core::ids::mint_request_id();
    let headers = req.headers().clone();
    if let Some(resp) = validate_origin_header(&state.app, &slug, &headers) {
        return resp;
    }
    let era = match resolve_protocol_era(&headers) {
        Ok(e) => e,
        Err(e) => return modern_error_response(RpcId::Null, &e),
    };
    // MCP 2026-07-28 § Earlier Streamable HTTP Revisions: the standalone GET
    // stream is gone and a modern server MUST answer 405. Its replacement is
    // `subscriptions/listen`, a POST whose response stream stays open —
    // served on the POST path below.
    //
    // The refusal happens before authentication on purpose: a modern client
    // that reaches here has made a protocol error, and answering it with a
    // 401 would send it round the OAuth flow to arrive at the same 405.
    if era.is_modern() {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            RpcId::Null,
            INVALID_REQUEST,
            "GET is not part of MCP 2026-07-28; open a notification stream with POST subscriptions/listen",
        );
    }
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mcp_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let resolved = match path_key.clone() {
        Some(key) => resolve_identity_from_token(&state.app, key, &slug, true).await,
        None => resolve_identity_with_jwt(&state.app, &headers, &slug).await,
    };
    let identity = match resolved {
        Ok(id) => id,
        Err(e) => {
            let (status, wire_message, audit_detail) = auth_error_for_response(&e);
            let mut resp = error_response(status, RpcId::Null, AUTH_REQUIRED, wire_message);
            if path_key.is_none()
                && status == StatusCode::UNAUTHORIZED
                && super::spec_oauth::slug_has_oauth_enabled(&state.app, &slug)
            {
                super::spec_oauth::add_www_authenticate(&mut resp, &state.app, &slug);
            }
            emit_unauthenticated_audit(
                &state,
                request_id,
                started,
                user_agent.clone(),
                mcp_session_id.clone(),
                Some(audit_detail),
                status,
            )
            .await;
            return resp;
        }
    };

    // Slug-vs-bound-VS check: identity carries a key-bound `virtual_server_id`;
    // refuse to subscribe to events for a slug that resolves to a different VS,
    // mirroring the POST handler's bind invariant. Resolution is via the
    // tenant config the key authenticated against — same path the POST
    // handler uses.
    let routes = match identity.config.mcp.lookup_by_slug(&slug) {
        Some((vs, routes)) if vs.id == identity.virtual_server_id => routes,
        Some(_) | None => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                RpcId::Null,
                AUTH_REQUIRED,
                "key not bound to this virtual server",
            );
        }
    };
    // The channel follows the POST path's mount rules: a server whose client
    // sends its own Authorization is reached on `/fwd` only, and a
    // pass-through key listens only where it may call.
    let upstreams: Vec<streamscope_core::config::mcp::McpUpstreamServer> = routes
        .iter()
        .filter_map(|r| identity.config.mcp.upstream_servers.get(&r.upstream_server_id).cloned())
        .collect();
    let refusal = if path_key.is_none() && super::upstream_auth::requires_fwd_mount(&upstreams) {
        Some(fwd_mount_required_message(&slug))
    } else if identity.user.forward_auth && !super::upstream_auth::pass_through_only(&upstreams) {
        Some(pass_through_refusal_message().to_string())
    } else {
        None
    };
    if let Some(message) = refusal {
        return error_response(StatusCode::BAD_REQUEST, RpcId::Null, AUTH_REQUIRED, message);
    }

    // The push channel is not method-scoped, so a narrow token must not open
    // it — see `channel_scope_check`.
    if let Err(required_scope) = super::spec_oauth::channel_scope_check(&identity.user) {
        let mut resp = error_response(
            StatusCode::FORBIDDEN,
            RpcId::Null,
            INSUFFICIENT_SCOPE,
            "the access token does not grant the server-push channel",
        );
        super::spec_oauth::add_insufficient_scope(
            &mut resp,
            &state.app,
            &slug,
            &required_scope,
        );
        return resp;
    }

    // `Last-Event-ID` resumption (MCP spec 2025-11-25 § Resumability and
    // Redelivery). Decode the token, assert identity binding (silent fresh
    // connect on tamper / expiry / cross-user). The mcp_session_id MUST come
    // from the token's `s` field — using the request's own `Mcp-Session-Id`
    // header would let a client resume into a different session entirely.
    let last_event_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let replay_target: Option<streamscope_core::mcp::tokens::DecodedEvent> = match last_event_id
        .as_deref()
    {
        Some(id) if id.starts_with("ssevt.") => {
            let ttl = crate::settings::proxy_settings().mcp_sse_token_ttl_secs;
            match streamscope_core::mcp::tokens::decode_event_id(id, ttl) {
                Ok(decoded)
                    if decoded.tenant_id == identity.tenant_id
                        && decoded.user_id == identity.user_id =>
                {
                    Some(decoded)
                }
                Ok(_) => {
                    tracing::debug!(
                        "Last-Event-ID identity mismatch; treating as fresh connect"
                    );
                    None
                }
                Err(err) => {
                    tracing::debug!(error = %err, "Last-Event-ID decode failed; fresh connect");
                    None
                }
            }
        }
        _ => None,
    };

    // Subscribe to the bus and pump into a downstream channel. Bounded so a
    // wedged client (TCP connected, never reads) can't grow the per-stream
    // buffer unbounded — `try_send` returns `Full` once the queue is at the
    // cap and we close the connection so the client reconnects from a clean
    // state. Picked the same default as the broadcast capacity; a slow
    // subscriber that lags both the broadcast AND fills this mpsc is well
    // past "best-effort live tail" semantics.
    let mut bus_rx = state.mcp.event_bus.subscribe(
        identity.tenant_id,
        identity.user_id,
        identity.virtual_server_id,
    );
    let downstream_capacity = crate::settings::proxy_settings()
        .mcp_get_bus_capacity
        .max(8);
    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(downstream_capacity);
    let keepalive_secs = crate::settings::proxy_settings().mcp_get_keepalive_secs.max(1);

    // Initial preface so curl/etc see headers + a body byte right away.
    // Bounded `try_send` is fine: queue is empty at this point.
    let _ = tx.try_send(Ok(bytes::Bytes::from_static(b": ok\n\n")));

    // If the client supplied a valid `Last-Event-ID`, replay rows from the
    // central DB BEFORE attaching the live tail so resumption is monotonic
    // (no torn ordering between replay and live publishes).
    let replay_limit = crate::settings::proxy_settings().mcp_sse_replay_limit;
    let admin_api_url = crate::settings::proxy_settings().admin_api_url.clone();
    let edge_token = std::env::var("EDGE_TOKEN").unwrap_or_default();
    let replay_target_for_task = replay_target.clone();
    let request_id_for_replay = request_id;
    // Clone the shutdown token into the spawned task so SIGTERM races
    // bus events + keepalive in the select loop below.
    let shutdown_token = state.mcp.shutdown_token.clone();

    tokio::spawn(async move {
        let mut replayed: usize = 0;
        if let Some(target) = replay_target_for_task.as_ref()
            && !edge_token.is_empty()
        {
            let url = format!("{admin_api_url}/api/v2/edge/mcp-sse-replay");
            let body = streamscope_edge_api::replay::ReplayRequest {
                tenant_id: target.tenant_id,
                mcp_session_id: target.mcp_session_id.clone(),
                after_sequence: target.sequence as i64,
                limit: replay_limit,
            };
            let http_client = match streamscope_core::tls::add_custom_roots(
                reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)),
                streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
            )
            .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "mcp sse replay: build http client failed");
                    return;
                }
            };
            let send_result = http_client
                .post(&url)
                .bearer_auth(&edge_token)
                .json(&body)
                .send()
                .await;
            match send_result {
                Ok(resp) if resp.status().is_success() => {
                    // Capped like any other egress read: the replay body is
                    // admin-api's, but the buffer it lands in is this replica's.
                    let raw = match streamscope_core::http_body::read_body_capped(
                        resp,
                        streamscope_core::mcp::MCP_MAX_RESPONSE_BYTES,
                    )
                    .await
                    {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(error = %e, "mcp GET replay: response body unreadable");
                            return;
                        }
                    };
                    match serde_json::from_slice::<streamscope_edge_api::replay::ReplayResponse>(&raw) {
                        Ok(parsed) => {
                            use base64::Engine;
                            const B64: base64::engine::GeneralPurpose =
                                base64::engine::general_purpose::STANDARD;
                            for row in &parsed.events {
                                let bytes = match B64.decode(row.event_data.as_bytes()) {
                                    Ok(b) => b,
                                    Err(_) => continue,
                                };
                                if tx.try_send(Ok(bytes::Bytes::from(bytes))).is_err() {
                                    tracing::warn!(
                                        "mcp GET replay: downstream queue full; aborting"
                                    );
                                    return;
                                }
                                replayed += 1;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "mcp sse replay parse failed"),
                    }
                }
                Ok(resp) => tracing::warn!(
                    status = %resp.status(),
                    "mcp sse replay HTTP non-success"
                ),
                Err(e) => tracing::warn!(error = %e, "mcp sse replay HTTP error"),
            }
            tracing::debug!(
                request_id = %request_id_for_replay,
                replayed,
                from_sequence = target.sequence,
                "mcp sse replay complete"
            );
        }

        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(keepalive_secs));
        keepalive.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Delay,
        );
        // First tick is immediate — skip it so the first keepalive fires
        // after the configured interval rather than back-to-back with the
        // preface above.
        keepalive.tick().await;
        loop {
            tokio::select! {
                ev = bus_rx.recv() => {
                    match ev {
                        Ok(super::event_bus::UserEvent(bytes)) => {
                            // try_send rather than send().await — if the
                            // downstream client has stalled, close the
                            // connection rather than block the bus pump.
                            if tx.try_send(Ok(bytes)).is_err() {
                                tracing::warn!(
                                    "mcp GET channel downstream queue full or closed; ending"
                                );
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped,
                                "mcp GET channel subscriber lagged; closing"
                            );
                            let _ = tx.try_send(Ok(bytes::Bytes::from_static(
                                b": lagged\n\n",
                            )));
                            break;
                        }
                    }
                }
                _ = keepalive.tick() => {
                    // Same bounded semantics on keepalive — if we can't even
                    // queue a 16-byte comment, the subscriber is wedged.
                    if tx.try_send(Ok(bytes::Bytes::from_static(b": keepalive\n\n"))).is_err() {
                        break;
                    }
                }
                _ = shutdown_token.cancelled() => {
                    // Graceful shutdown signalled. Send a final SSE comment
                    // so the client observes a clean stream end instead of
                    // a TCP RST, then close. The agent reconnects (with
                    // `Last-Event-ID` for replay) cleanly. axum's HTTP-level
                    // graceful shutdown waits `mcp_get_drain_secs` for this
                    // path to drain.
                    let _ = tx.try_send(Ok(bytes::Bytes::from_static(b": shutdown\n\n")));
                    tracing::info!("mcp GET channel shutdown signalled; closing stream");
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Axum entry — `POST /mcp/{slug}` (and GET for the compatibility surface).
///
/// Requires a valid proxy-issued `sk-*` Bearer token (`forward_auth=false`)
/// or a spec-OAuth JWT. `vk-*` forward-auth keys are rejected with a generic
/// 401 and must use the `/fwd/{key}/mcp/<slug>` mount point.
pub async fn mcp_handler(
    Path(slug): Path<String>,
    State(state): State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let request_id = streamscope_core::ids::mint_request_id();
    let headers = req.headers().clone();
    if let Some(resp) = validate_origin_header(&state.app, &slug, &headers) {
        return resp;
    }
    let era = match resolve_protocol_era(&headers) {
        Ok(e) => e,
        // The body is well-formed here — only the declared version is
        // unacceptable — so the id CAN be read, and § Responses exempts an
        // error from echoing it only when it "could not be read due a
        // malformed request". A client with several requests in flight
        // otherwise cannot tell which one was rejected.
        Err(e) => return modern_error_response(peek_rpc_id(req).await, &e),
    };
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // MCP 2026-07-28 § Earlier Streamable HTTP Revisions: a modern server
    // ignores `Mcp-Session-Id` and neither mints nor echoes one. Dropping it
    // here rather than downstream keeps the "no protocol sessions" rule in
    // one place — every consumer below reads `None` and cannot accidentally
    // route a modern request through session-keyed state.
    let mcp_session_id = if era.is_modern() {
        None
    } else {
        headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    // Real auth: `sk-*` static key or proxy-issued spec-OAuth JWT.
    // BYOK (`vk-*`) keys are rejected here and must use the
    // `/fwd/{key}/mcp/<slug>` mount point.
    let identity = match resolve_identity_with_jwt(&state.app, &headers, &slug).await {
        Ok(id) => id,
        Err(e) => {
            let (status, wire_message, audit_detail) = auth_error_for_response(&e);
            let mut resp = error_response(status, RpcId::Null, AUTH_REQUIRED, wire_message);
            // When the addressed VS has spec-OAuth enabled, attach RFC 9728
            // `WWW-Authenticate` so the client can discover our authorization
            // server. Otherwise keep the plain JSON-RPC body.
            if status == StatusCode::UNAUTHORIZED
                && super::spec_oauth::slug_has_oauth_enabled(&state.app, &slug)
            {
                super::spec_oauth::add_www_authenticate(&mut resp, &state.app, &slug);
            }
            emit_unauthenticated_audit(
                &state,
                request_id,
                started,
                user_agent.clone(),
                mcp_session_id.clone(),
                Some(audit_detail),
                status,
            )
            .await;
            return resp;
        }
    };

    handle_authenticated_request(
        state, slug, req, identity, request_id, started, user_agent, mcp_session_id, false, era,
    )
    .await
}

/// Axum entry for `POST /fwd/{key}/mcp/{slug}`.
///
/// The path key authenticates the user — any gateway key (`sk-*` or
/// `vk-*`). The request's own headers are then free to carry the client's
/// `Authorization` for an upstream that declares it client-filled, which is
/// the one case this mount is required for; every other virtual server is
/// reachable here and on `/mcp/<slug>` alike.
pub async fn mcp_fwd_handler(
    Path((key, slug)): Path<(String, String)>,
    State(state): State<McpRouterState>,
    req: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let request_id = streamscope_core::ids::mint_request_id();
    let headers = req.headers().clone();
    if let Some(resp) = validate_origin_header(&state.app, &slug, &headers) {
        return resp;
    }
    let era = match resolve_protocol_era(&headers) {
        Ok(e) => e,
        // The body is well-formed here — only the declared version is
        // unacceptable — so the id CAN be read, and § Responses exempts an
        // error from echoing it only when it "could not be read due a
        // malformed request". A client with several requests in flight
        // otherwise cannot tell which one was rejected.
        Err(e) => return modern_error_response(peek_rpc_id(req).await, &e),
    };
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // MCP 2026-07-28 § Earlier Streamable HTTP Revisions: a modern server
    // ignores `Mcp-Session-Id` and neither mints nor echoes one. Dropping it
    // here rather than downstream keeps the "no protocol sessions" rule in
    // one place — every consumer below reads `None` and cannot accidentally
    // route a modern request through session-keyed state.
    let mcp_session_id = if era.is_modern() {
        None
    } else {
        headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    // The request's `Authorization` is the client's own credential here, and
    // may be forwarded to the upstream as a client-filled input — never when
    // it carries the gateway key of the path (a client still set up for
    // `/mcp/<slug>`): that key would reach a third party. Dropped, the header
    // then reads as not sent.
    let mut req = req;
    if req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains(key.as_str()))
    {
        req.headers_mut().remove(axum::http::header::AUTHORIZATION);
    }

    // Authenticate the path key first. Same generic 401 as `/mcp/<slug>` so
    // a probing client can't tell a wrong key from a non-existent one.
    let identity = match resolve_identity_from_token(&state.app, key, &slug, true).await {
        Ok(id) => id,
        Err(e) => {
            let (status, wire_message, audit_detail) = auth_error_for_response(&e);
            let resp = error_response(status, RpcId::Null, AUTH_REQUIRED, wire_message);
            emit_unauthenticated_audit(
                &state,
                request_id,
                started,
                user_agent.clone(),
                mcp_session_id.clone(),
                Some(audit_detail),
                status,
            )
            .await;
            return resp;
        }
    };

    handle_authenticated_request(
        state, slug, req, identity, request_id, started, user_agent, mcp_session_id, true, era,
    )
    .await
}

/// Shared body for both `/mcp/<slug>` and `/fwd/{key}/mcp/<slug>` — handles
/// request read, parse, slug resolve, slug binding, rate limiting, dispatch,
/// and audit emit. The two callers differ only in where the gateway key is
/// read (`fwd_mount`), which decides whether the request's `Authorization`
/// may be a client-filled input.
#[allow(clippy::too_many_arguments)]
async fn handle_authenticated_request(
    state: McpRouterState,
    slug: String,
    req: Request<Body>,
    identity: Identity,
    request_id: Uuid,
    started: Instant,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
    fwd_mount: bool,
    era: ProtocolEra,
) -> Response<Body> {
    // Keep a copy of the request headers for attribution after the body has
    // been consumed by `into_body()`. Cheap to clone (Axum's HeaderMap is a
    // thin Map<HeaderName, HeaderValue>).
    let req_headers_for_attribution = req.headers().clone();

    // Record the version the client declared, for the audit row. Only when it
    // actually sent the header — the assumed default is not a declaration.
    // Captured before anything can refuse the request (the body read, the
    // parse, the era gate) so a refused request is still attributed to the
    // revision that got it refused, which is the whole question an operator
    // debugging a client migration is asking.
    let mut identity = identity;
    identity.declared_protocol_version = req_headers_for_attribution
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    // Read body once. Over the size cap, or not received within the body
    // deadline, the refusal is audited like any other: the caller is known.
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_REQUEST_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            let message = format!("could not read body: {e}");
            let resp = error_response(StatusCode::BAD_REQUEST, RpcId::Null, INVALID_REQUEST, message.clone());
            emit_audit(
                &state,
                &identity,
                request_id,
                &slug,
                Some(identity.virtual_server_id),
                None,
                "<unreadable>".to_string(),
                None,
                None,
                None,
                Some(INVALID_REQUEST),
                Some(message),
                started,
                Instant::now(),
                0,
                0,
                user_agent.clone(),
                mcp_session_id.clone(),
                StatusCode::BAD_REQUEST,
                None,
            )
            .await;
            return resp;
        }
    };
    let request_bytes = body_bytes.len() as i32;

    // Classify the body shape. Most traffic is Request; Notification
    // is a fire-and-forget client→server message that always gets a 202 ack
    // (per JSON-RPC 2.0 — notifications never receive a response); Response
    // is the agent's reply to a server-initiated `sampling`/`elicitation` and
    // rides the reverse-routing path through the per-session map. We capture
    // the parsed body and dispatch AFTER the slug-binding + rate-limit gates
    // below — Response and Notification both ride through those checks too.
    let inbound = match InboundMessage::parse(&body_bytes) {
        Ok(m) => m,
        Err(e) => {
            let resp = error_response(
                StatusCode::OK,
                RpcId::Null,
                PARSE_ERROR,
                format!("parse error: {e}"),
            );
            emit_audit(
                &state,
                &identity,
                request_id,
                &slug,
                None,
                None,
                "<unparseable>".to_string(),
                None,
                None,
                None,
                Some(PARSE_ERROR),
                Some(format!("parse error: {e}")),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent.clone(),
                mcp_session_id.clone(),
                StatusCode::OK,
                None,
            )
            .await;
            return resp;
        }
    };

    // Era validation. Runs before slug resolution and before any upstream
    // work: a protocol-level rejection costs nothing and reaches nothing.
    let modern_meta = match validate_era_body(&era, &req_headers_for_attribution, &inbound) {
        Ok(m) => m,
        Err(e) => {
            let (id, method) = match &inbound {
                InboundMessage::Request(r) | InboundMessage::Notification(r) => (
                    r.id.clone().unwrap_or(RpcId::Null),
                    r.method.clone(),
                ),
                InboundMessage::Response(r) => {
                    (r.id.clone(), "<client_response>".to_string())
                }
            };
            tracing::debug!(
                era = %era.version(),
                code = e.code,
                message = %e.message,
                "MCP: rejecting request at the protocol-era gate"
            );
            // Audited even though nothing was dispatched. A client that has
            // just moved to a new revision and is being refused produces no
            // upstream traffic at all, so this row is the only place the
            // refusal is visible — and "my new client gets 400s and I cannot
            // see why" is precisely what it has to answer. The virtual server
            // comes from the key, which authenticated before this point.
            emit_audit(
                &state,
                &identity,
                request_id,
                &slug,
                Some(identity.virtual_server_id),
                None,
                method,
                None,
                None,
                None,
                Some(e.code),
                Some(e.message.clone()),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent.clone(),
                mcp_session_id.clone(),
                e.status,
                None,
            )
            .await;
            return modern_error_response(id, &e);
        }
    };

    // A modern client declares itself in `_meta.clientInfo`; `User-Agent` is
    // a transport nicety its SDK need not send. Fall back to it so an audit
    // row for a modern caller still identifies who called.
    let user_agent = user_agent.or_else(|| {
        modern_meta
            .as_ref()
            .and_then(|m| m.client_info_label())
    });

    // Pull a synthetic JsonRpcRequest representation out of every variant so
    // the slug-resolve / slug-binding / rate-limit checks below stay uniform.
    // Response and Notification carry method = "<client_response>" /
    // "<notification>" only for those gates; they branch out to the dedicated
    // handlers right after the gates pass.
    let request: JsonRpcRequest = match &inbound {
        InboundMessage::Request(r) => r.clone(),
        InboundMessage::Notification(n) => n.clone(),
        InboundMessage::Response(r) => JsonRpcRequest {
            jsonrpc: r.jsonrpc.clone(),
            id: Some(r.id.clone()),
            method: "<client_response>".to_string(),
            params: None,
        },
    };

    // Resolve slug to virtual server + routes from the per-tenant config —
    // anchored to the key's tenant (which is the only tenant the key
    // authenticates). No SYSTEM fallback: the key's own tenant config, from the
    // load that authenticated it, is the sole source.
    let tenant_cfg = identity.config.clone();
    let lookup = tenant_cfg.mcp.lookup_by_slug(&slug);
    let (virtual_server, routes) = match lookup {
        Some((vs, rs)) if !rs.is_empty() => (vs.clone(), rs.to_vec()),
        Some(_) => {
            return era_error_response(
                StatusCode::NOT_FOUND,
                request.id.clone().unwrap_or(RpcId::Null),
                ROUTE_NOT_FOUND,
                "virtual server has no enabled routes",
                &era,
            );
        }
        None => {
            return era_error_response(
                StatusCode::NOT_FOUND,
                request.id.clone().unwrap_or(RpcId::Null),
                ROUTE_NOT_FOUND,
                format!("no virtual server matches /mcp/{slug}"),
                &era,
            );
        }
    };

    // Slug binding — the key must be bound to *this* virtual server.
    if virtual_server.id != identity.virtual_server_id {
        let resp = error_response(
            StatusCode::UNAUTHORIZED,
            request.id.clone().unwrap_or(RpcId::Null),
            AUTH_REQUIRED,
            "key is not bound to this virtual server",
        );
        emit_audit(
            &state,
            &identity,
            request_id,
            &slug,
            Some(virtual_server.id),
            None,
            request.method.clone(),
            None,
            None,
            None,
            Some(AUTH_REQUIRED),
            Some("virtual_server_id mismatch".to_string()),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent.clone(),
            mcp_session_id.clone(),
            StatusCode::UNAUTHORIZED,
            None,
        )
        .await;
        return resp;
    }

    // Per-user RPM / TPM — same checks as the LLM proxy. A bucket with no
    // configured cap short-circuits inside the check, so these always run and
    // enforce iff a workspace/user cap is set (mirrors `proxy::mod`).
    if let Err(e) = streamscope_core::middleware::rate_limit::check_rate_limit(
        &identity.user,
        &state.app.usage,
    ) {
        return rate_limited_response(&state, &identity, request_id, &slug, &request, &virtual_server,
            started, request_bytes, user_agent.clone(), mcp_session_id.clone(), e).await;
    }
    if let Err(e) = streamscope_core::middleware::rate_limit::check_tpm_limit(
        &identity.user,
        &state.app.usage,
    ) {
        return rate_limited_response(&state, &identity, request_id, &slug, &request, &virtual_server,
            started, request_bytes, user_agent.clone(), mcp_session_id.clone(), e).await;
    }
    if let Err(e) = streamscope_core::middleware::rate_limit::check_budget(
        &identity.user,
        &state.app.usage,
        tenant_cfg.pricing.accounting_currency,
    ) {
        return rate_limited_response(&state, &identity, request_id, &slug, &request, &virtual_server,
            started, request_bytes, user_agent.clone(), mcp_session_id.clone(), e).await;
    }

    // Build a snapshot of upstream servers for the routes we're about to use.
    let upstreams: Vec<streamscope_core::config::mcp::McpUpstreamServer> = routes
        .iter()
        .filter_map(|r| tenant_cfg.mcp.upstream_servers.get(&r.upstream_server_id).cloned())
        .collect();

    // A routed upstream that takes the client's own `Authorization` header
    // cannot be reached on `/mcp/<slug>`, where that header is the gateway
    // credential: forwarding it would hand the upstream our key, and
    // dropping it would call the upstream without the one input it needs.
    // The key DID authenticate, so this is a 400, not a 401: an MCP client
    // reads a 401 as an OAuth challenge and would start a sign-in instead of
    // showing the message that names the `/fwd` address.
    //
    // A pass-through (`vk-`) key carries no credential of the gateway's: on
    // MCP it reaches only a virtual server whose every route carries just
    // what the client sends (`pass_through_only`) — never one the gateway
    // would stamp an admin's or a user's stored value on.
    let needs_fwd = super::upstream_auth::requires_fwd_mount(&upstreams);
    let refusal = if !fwd_mount && needs_fwd {
        Some(fwd_mount_required_message(&slug))
    } else if identity.user.forward_auth && !super::upstream_auth::pass_through_only(&upstreams) {
        Some(pass_through_refusal_message().to_string())
    } else {
        None
    };
    if let Some(message) = refusal {
        let resp = error_response(
            StatusCode::BAD_REQUEST,
            request.id.clone().unwrap_or(RpcId::Null),
            AUTH_REQUIRED,
            message.clone(),
        );
        emit_audit(
            &state,
            &identity,
            request_id,
            &slug,
            Some(virtual_server.id),
            None,
            request.method.clone(),
            None,
            None,
            None,
            Some(AUTH_REQUIRED),
            Some(message),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent.clone(),
            mcp_session_id.clone(),
            StatusCode::BAD_REQUEST,
            None,
        )
        .await;
        return resp;
    }
    let client_inputs =
        super::upstream_auth::capture_client_inputs(&req_headers_for_attribution, &upstreams);

    // Response and Notification variants reach this point with all
    // gates passed (slug binding, mount, rate-limit, budget). They
    // skip the policy + dispatch flow below and route to their dedicated
    // handlers, which re-resolve the upstream's headers through the same
    // auth_ctx the dispatch path uses (so per-user-OAuth tokens stay fresh).
    let auth_ctx_for_reverse = AuthCtx {
        tenant_id: identity.tenant_id,
        workspace_id: identity.user.workspace_id,
        user_id: identity.user_id,
        key_id: identity.key_id,
        virtual_server_id: virtual_server.id,
        oauth_state: state.mcp.oauth_state.clone(),
        rotation_sink: state.mcp.rotation_sink.clone(),
        mcp_config: tenant_cfg.mcp.clone(),
        web_settings: tenant_cfg.web.clone(),
        guardrail: tenant_cfg.effective_guardrail(identity.user.workspace_id).clone(),
        legacy_sse_map: state.mcp.legacy_sse_map.clone(),
        listeners: state.mcp.listeners.clone(),
        event_bus: state.mcp.event_bus.clone(),
        mcp_audit_tx: state.mcp.mcp_audit_tx.clone(),
        web_audit_tx: state.mcp.web_audit_tx.clone(),
        web_search_clients: state.app.web_search_clients.clone(),
        mcp_sse_event_tx: state.mcp.mcp_sse_event_tx.clone(),
        sse_seq: state.mcp.sse_seq.clone(),
        session_map: state.mcp.session_map.clone(),
        era: era.clone(),
        upstream_client_capabilities: upstream_client_capabilities(modern_meta.as_ref()),
        upstream_log_level: upstream_log_level(
            modern_meta.as_ref(),
            &state.mcp.session_map,
            identity.tenant_id,
            identity.user_id,
        ),
        // A client response, a notification, `server/discover` and
        // `subscriptions/listen` are none of them an MRTR retry, so there is
        // no upstream to aim one at.
        mrtr_upstream: None,
        client_params_digest: streamscope_core::mcp::tokens::digest_request_params(
            request.params.as_ref(),
        ),
        server_info: gateway_server_info(&virtual_server),
        client_inputs: client_inputs.clone(),
        inputs_memo: Default::default(),
        sign_ins_url: portal_sign_ins_url(&tenant_cfg),
    };
    match inbound {
        InboundMessage::Response(resp_body) => {
            return handle_client_response(
                &state,
                &identity,
                request_id,
                &slug,
                resp_body,
                &auth_ctx_for_reverse,
                &upstreams,
                started,
                request_bytes,
                user_agent,
                mcp_session_id,
            )
            .await;
        }
        InboundMessage::Notification(_) => {
            // Per JSON-RPC 2.0: a notification never receives a response.
            // The handler returns 202 with empty body. Forwarding the
            // notification upstream is best-effort and only safe for the
            // standard MCP set (`notifications/initialized`,
            // `notifications/cancelled`, `notifications/roots/list_changed`)
            // — the rest could be malicious or malformed and we don't trust
            // the agent to send arbitrary methods.
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()));
        }
        InboundMessage::Request(_) => {}
    }

    // Step-up authorization (MCP 2025-11-25 § Scope Challenge Handling). Runs
    // before the policy hook and before any upstream work, so a token that was
    // never granted this method costs nothing and reaches nothing.
    //
    // 403, never 401: the credential is valid and re-authenticating with it
    // would mint the same narrow token again. The header names the scope the
    // client is missing so it can ask for exactly that.
    if let Err(required_scope) =
        super::spec_oauth::scope_check(&identity.user, &request.method)
    {
        let message = format!(
            "the access token does not grant '{}' — scope '{required_scope}' is required",
            request.method
        );
        let mut resp = error_response(
            StatusCode::FORBIDDEN,
            request.id.clone().unwrap_or(RpcId::Null),
            INSUFFICIENT_SCOPE,
            message.clone(),
        );
        super::spec_oauth::add_insufficient_scope(
            &mut resp,
            &state.app,
            &slug,
            &required_scope,
        );
        emit_audit(
            &state,
            &identity,
            request_id,
            &slug,
            Some(virtual_server.id),
            None,
            request.method.clone(),
            None,
            None,
            None,
            Some(INSUFFICIENT_SCOPE),
            Some(message),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent.clone(),
            mcp_session_id.clone(),
            StatusCode::FORBIDDEN,
            None,
        )
        .await;
        return resp;
    }

    // MRTR retry gate, both halves before any upstream work. `requestState`
    // is attacker-controlled by definition — it travels through the client —
    // so a blob minted for a different principal, method or set of arguments
    // is refused rather than acted on; and `inputResponses` is checked for
    // the shape § MRTR defines, because the gateway relays those answers to
    // an upstream and is the server this client is talking to.
    let mut mrtr_upstream: Option<(Uuid, Option<String>)> = None;
    if modern_meta.is_some()
        && let Err(e) = verify_request_state(
            request.params.as_ref(),
            &identity,
            virtual_server.id,
            &request.method,
        )
        .map(|target| mrtr_upstream = target)
        .and_then(|()| modern::validate_input_responses(request.params.as_ref()))
    {
        // Audited like the scope gate above and the era gate before it. The
        // case this exists for is a member presenting a colleague's state on a
        // call of their own choosing — a security-relevant refusal, and a
        // `tracing::warn!` is not a record an operator can query.
        emit_audit(
            &state,
            &identity,
            request_id,
            &slug,
            Some(virtual_server.id),
            None,
            request.method.clone(),
            None,
            None,
            None,
            Some(e.code),
            Some(e.message.clone()),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent.clone(),
            mcp_session_id.clone(),
            e.status,
            None,
        )
        .await;
        return modern_error_response(request.id.clone().unwrap_or(RpcId::Null), &e);
    }

    // ── Modern-era methods the gateway answers itself ────────────────────
    //
    // Both are served here rather than forwarded: they describe the *virtual
    // server*, which no single upstream knows about. They also sit outside
    // the tool-policy hook below, which classifies tool/prompt/resource calls
    // and has nothing to say about discovery or a notification stream.
    if modern_meta.is_some() {
        match request.method.as_str() {
            modern::METHOD_DISCOVER => {
                return handle_modern_discover(
                    &state,
                    &identity,
                    request_id,
                    &slug,
                    &virtual_server,
                    &routes,
                    &upstreams,
                    &auth_ctx_for_reverse,
                    &request,
                    started,
                    request_bytes,
                    user_agent,
                )
                .await;
            }
            modern::METHOD_SUBSCRIPTIONS_LISTEN => {
                return handle_modern_subscriptions_listen(
                    &state,
                    &identity,
                    request_id,
                    &slug,
                    &virtual_server,
                    &routes,
                    &upstreams,
                    &auth_ctx_for_reverse,
                    &request,
                    started,
                    request_bytes,
                    user_agent,
                )
                .await;
            }
            _ => {}
        }
    }

    let scope = classify_method(&request.method);
    // Request-phase rule eval. The policy hook runs BEFORE dispatch
    // so a `Block` rule short-circuits the upstream call entirely and a
    // `Replace` rule rewrites the params before forwarding. The authoritative
    // `mcp_server` is the route's upstream name; for `tools/call` and
    // `prompts/get` we strip the namespace prefix off `params.name`; for
    // `resources/read` we decode the route prefix out of the agent-supplied
    // `stsmcp://<prefix>/<b64>` URI directly. Non-virtualized URIs (legacy /
    // probe traffic) fall through to the first route as a best-effort anchor.
    let policy_mcp_server = resolve_policy_mcp_server(&request, &routes, &upstreams);
    let policy_attribution = streamscope_core::middleware::attribution::extract_attribution(
        &req_headers_for_attribution,
        identity.user_id,
        &tenant_cfg.app_patterns,
        false,
    );
    let policy_app_id = policy_attribution.app_id.clone();
    let policy_detection_method = policy_attribution.detection_method.clone();
    // Tenant rules with this request's workspace overrides layered on.
    let effective_tool_rules = tenant_cfg.effective_tool_rules(identity.user.workspace_id);
    let policy_decision = if let Some(server_name) = policy_mcp_server.as_deref() {
        let policy_ctx = super::policy::PolicyContext {
            field_profiles: Some(&tenant_cfg.tool_field_profiles),
            rules: &effective_tool_rules,
            mcp_server: server_name,
            app_id: policy_app_id.as_deref(),
        };
        super::policy::evaluate_request(&policy_ctx, &request, &routes)
    } else {
        super::policy::PolicyDecision::Allow(None)
    };

    // Branch on the policy decision. `Block` returns -32506 immediately.
    // `Replace` rebuilds the request with mutated params before dispatch.
    // `Allow` proceeds with the original request; any classification result
    // is captured for the audit row.
    let (request, policy_classification) = match policy_decision {
        super::policy::PolicyDecision::Block { result, message } => {
            let resp = error_response(
                StatusCode::OK,
                request.id.clone().unwrap_or(RpcId::Null),
                MCP_BLOCKED_BY_POLICY,
                message.clone(),
            );
            emit_audit_with_policy(
                &state,
                &identity,
                request_id,
                &slug,
                Some(virtual_server.id),
                None,
                request.method.clone(),
                if scope == McpScope::ToolCall { resolved_tool_id(&request) } else { None },
                {
                    let (completion_prompt_id, _) = if scope == McpScope::CompletionComplete {
                        resolved_completion_target(&request)
                    } else {
                        (None, None)
                    };
                    if scope == McpScope::PromptGet {
                        resolved_prompt_id(&request)
                    } else {
                        completion_prompt_id
                    }
                },
                {
                    let (_, completion_resource_uri) = if scope == McpScope::CompletionComplete {
                        resolved_completion_target(&request)
                    } else {
                        (None, None)
                    };
                    if matches!(
                        scope,
                        McpScope::ResourceRead | McpScope::ResourceSubscribe | McpScope::ResourceUnsubscribe
                    ) {
                        resolved_resource_uri(&request)
                    } else {
                        completion_resource_uri
                    }
                },
                Some(MCP_BLOCKED_BY_POLICY),
                Some(message),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent.clone(),
                mcp_session_id.clone(),
                StatusCode::OK,
                Some(result),
                policy_app_id.clone(),
                policy_detection_method.clone(),
                request.params.clone(),
                None,
                None, // limit_bucket
            )
            .await;
            return resp;
        }
        super::policy::PolicyDecision::Replace { result, mutated_params } => {
            let mutated_request = JsonRpcRequest {
                jsonrpc: request.jsonrpc.clone(),
                id: request.id.clone(),
                method: request.method.clone(),
                params: Some(mutated_params),
            };
            (mutated_request, Some(result))
        }
        super::policy::PolicyDecision::Allow(result) => (request, result),
    };

    let dispatch_started = Instant::now();
    let auth_ctx = AuthCtx {
        tenant_id: identity.tenant_id,
        workspace_id: identity.user.workspace_id,
        user_id: identity.user_id,
        key_id: identity.key_id,
        virtual_server_id: virtual_server.id,
        oauth_state: state.mcp.oauth_state.clone(),
        rotation_sink: state.mcp.rotation_sink.clone(),
        mcp_config: tenant_cfg.mcp.clone(),
        web_settings: tenant_cfg.web.clone(),
        guardrail: tenant_cfg.effective_guardrail(identity.user.workspace_id).clone(),
        legacy_sse_map: state.mcp.legacy_sse_map.clone(),
        listeners: state.mcp.listeners.clone(),
        event_bus: state.mcp.event_bus.clone(),
        mcp_audit_tx: state.mcp.mcp_audit_tx.clone(),
        web_audit_tx: state.mcp.web_audit_tx.clone(),
        web_search_clients: state.app.web_search_clients.clone(),
        mcp_sse_event_tx: state.mcp.mcp_sse_event_tx.clone(),
        sse_seq: state.mcp.sse_seq.clone(),
        session_map: state.mcp.session_map.clone(),
        era: era.clone(),
        upstream_client_capabilities: upstream_client_capabilities(modern_meta.as_ref()),
        upstream_log_level: upstream_log_level(
            modern_meta.as_ref(),
            &state.mcp.session_map,
            identity.tenant_id,
            identity.user_id,
        ),
        mrtr_upstream: mrtr_upstream.clone(),
        client_params_digest: streamscope_core::mcp::tokens::digest_request_params(
            request.params.as_ref(),
        ),
        server_info: gateway_server_info(&virtual_server),
        client_inputs,
        inputs_memo: Default::default(),
        sign_ins_url: portal_sign_ins_url(&tenant_cfg),
    };

    // `tools/call` and `prompts/get` are the two scopes whose upstream may
    // emit `text/event-stream` to interleave server-initiated
    // `sampling`/`elicitation` requests with the eventual result. Route both
    // through the streaming-aware path; for one-shot JSON responses it
    // returns the same shape as the synchronous `dispatch()`.
    if scope == McpScope::ToolCall || scope == McpScope::PromptGet {
        return handle_method_streaming(
            state,
            identity,
            request_id,
            slug,
            virtual_server.id,
            scope,
            request,
            policy_classification,
            policy_app_id,
            policy_detection_method,
            &routes,
            &upstreams,
            &auth_ctx,
            mcp_session_id,
            started,
            dispatch_started,
            request_bytes,
            user_agent,
            modern_meta,
            gateway_server_info(&virtual_server),
        )
        .await;
    }

    let dispatch_result = dispatch(
        &state.mcp.capability_cache,
        &auth_ctx,
        &virtual_server,
        &routes,
        &upstreams,
        &request,
        mcp_session_id.as_deref(),
    )
    .await;
    let dispatch_finished = Instant::now();

    let (resp_value, response_session_id, upstream_id, error_kind) = match dispatch_result {
        Ok(v) => v,
        Err(e) => {
            let (resp, code, message) = upstream_error_relay(
                request.id.clone().unwrap_or(RpcId::Null),
                &e,
                &era,
                auth_ctx.sign_ins_url.as_deref(),
            );
            emit_audit(
                &state,
                &identity,
                request_id,
                &slug,
                Some(virtual_server.id),
                None,
                request.method.clone(),
                resolved_tool_id(&request),
                resolved_prompt_id(&request),
                resolved_resource_uri(&request),
                Some(code),
                Some(message),
                started,
                dispatch_started,
                request_bytes,
                0,
                user_agent.clone(),
                mcp_session_id.clone(),
                resp.status(),
                None,
            )
            .await;
            return resp;
        }
    };

    let mut resp_value = resp_value;
    let status = finalize_modern_response(
        &mut resp_value,
        &request.method,
        &virtual_server,
        &upstreams,
        &era,
    );
    let body_bytes = match serde_json::to_vec(&resp_value) {
        Ok(b) => b,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                request.id.clone().unwrap_or(RpcId::Null),
                INTERNAL_ERROR,
                format!("serialize response: {e}"),
            );
        }
    };
    let response_bytes = body_bytes.len() as i32;
    let resp = stamp_session_id(
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json"),
        response_session_id.as_ref(),
        era.is_modern(),
    );
    let resp = resp
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()));

    let (rpc_err_code, rpc_err_msg) = error_kind.unzip();

    // Touch the session entry so a follow-up `set_protocol_version` lands.
    // Reverse-path routing for server-initiated sampling/elicitation rides
    // the `ssrid.…` token (see `handle_client_response`); the session map
    // only caches the negotiated protocol version for in-process audit
    // emission.
    if let Some(sid) = response_session_id.as_deref()
        && upstream_id.is_some()
    {
        state.mcp.session_map.upsert(identity.tenant_id, sid);
        // On `initialize` the upstream's `result.protocolVersion` is the
        // negotiated version; stash it so subsequent `mcp_audit` rows can
        // attribute traffic by spec revision. `upsert` preserves an existing
        // version on non-`initialize` re-upserts.
        if matches!(classify_method(&request.method), McpScope::Initialize)
            && let Some(pv) = resp_value
                .result
                .as_ref()
                .and_then(|r| r.get("protocolVersion"))
                .and_then(|v| v.as_str())
        {
            state
                .mcp
                .session_map
                .set_protocol_version(identity.tenant_id, sid, pv);
        }
    }

    // For successful dispatches we still want to capture if the upstream
    // returned a JSON-RPC error inside `result`/`error`. The dispatcher's
    // returned `error_kind` tuple covers that.
    emit_audit_with_policy(
        &state,
        &identity,
        request_id,
        &slug,
        Some(virtual_server.id),
        upstream_id,
        request.method.clone(),
        if scope == McpScope::ToolCall { resolved_tool_id(&request) } else { None },
        {
            let (completion_prompt_id, _) = if scope == McpScope::CompletionComplete {
                resolved_completion_target(&request)
            } else {
                (None, None)
            };
            if scope == McpScope::PromptGet {
                resolved_prompt_id(&request)
            } else {
                completion_prompt_id
            }
        },
        {
            let (_, completion_resource_uri) = if scope == McpScope::CompletionComplete {
                resolved_completion_target(&request)
            } else {
                (None, None)
            };
            if matches!(
                scope,
                McpScope::ResourceRead | McpScope::ResourceSubscribe | McpScope::ResourceUnsubscribe
            ) {
                resolved_resource_uri(&request)
            } else {
                completion_resource_uri
            }
        },
        rpc_err_code,
        rpc_err_msg,
        started,
        dispatch_finished,
        request_bytes,
        response_bytes,
        user_agent,
        mcp_session_id.or(response_session_id),
        status,
        policy_classification,
        policy_app_id,
        policy_detection_method.clone(),
        request.params.clone(),
        resp_value.result.clone(),
        None, // limit_bucket
    )
    .await;

    resp
}

/// `tools/call` / `prompts/get` dispatch with SSE streaming awareness.
///
/// Resolves the namespace prefix to a single upstream, applies the route
/// filter (tools_filter for `tools/call`, prompts_filter for `prompts/get`),
/// rewrites `params.name` to the unprefixed form, and calls
/// [`upstream::call_with_auth_for_streaming`]. Branches:
///
/// - Upstream replied with `application/json` → emit one audit row + return
///   the JSON body. Behaviourally identical to the synchronous path.
/// - Upstream replied with `text/event-stream` → return a streaming HTTP
///   body that pumps every upstream SSE event to the client verbatim. A side
///   task drives the pump, classifies each event for audit/log signal
///   (sampling/elicitation get info-level audit rows; notifications/message
///   get debug-log only), and emits the per-request audit row when the
///   upstream stream closes.
#[allow(clippy::too_many_arguments)]
async fn handle_method_streaming(
    state: McpRouterState,
    identity: Identity,
    request_id: Uuid,
    slug: String,
    virtual_server_id: Uuid,
    scope: McpScope,
    request: JsonRpcRequest,
    policy_classification: Option<streamscope_core::config::tool_rules::RiskResult>,
    policy_app_id: Option<String>,
    policy_detection_method: Option<String>,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    auth: &AuthCtx,
    mcp_session_id: Option<String>,
    started: Instant,
    dispatch_started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
    modern_meta: Option<RequestMeta>,
    server_info: serde_json::Value,
) -> Response<Body> {
    debug_assert_matches!(scope, McpScope::ToolCall | McpScope::PromptGet);
    let method = request.method.clone();
    // Audit-id triple: (tool_id, prompt_id, resource_uri). For tools/call we
    // stamp the resolved name on tool_id; for prompts/get on prompt_id.
    let make_audit_ids = |name: &str| -> (Option<String>, Option<String>, Option<String>) {
        if scope == McpScope::PromptGet {
            (None, Some(name.to_string()), None)
        } else {
            (Some(name.to_string()), None, None)
        }
    };
    let rpc_id = request.id.clone().unwrap_or(RpcId::Null);

    // ── Routing: prefix → route → upstream ────────────────────────────────
    let name = match request
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
    {
        Some(n) => n.to_string(),
        None => {
            let resp = error_response(
                StatusCode::OK,
                rpc_id,
                INVALID_PARAMS,
                "missing params.name",
            );
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), None, method.clone(),
                None, None, None,
                Some(INVALID_PARAMS), Some("missing params.name".into()),
                started, Instant::now(), request_bytes, 0,
                user_agent, mcp_session_id, StatusCode::OK,
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), None,
                None, // limit_bucket
            ).await;
            return resp;
        }
    };
    let resolved = virtualize::route_for_name(routes, &name)
        .map(|(route, local)| (route.clone(), local.to_string()));
    let (route, suffix) = match resolved {
        Some(found) => found,
        None => {
            let msg = format!("no route serves {name:?}");
            let resp = era_error_response(
                StatusCode::OK,
                rpc_id,
                TOOL_NOT_FOUND,
                msg.clone(),
                &auth.era,
            );
            let (tid, pid, rid) = make_audit_ids(&name);
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), None, method.clone(),
                tid, pid, rid,
                Some(TOOL_NOT_FOUND), Some(msg),
                started, Instant::now(), request_bytes, 0,
                user_agent, mcp_session_id, resp.status(),
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), None,
                None, // limit_bucket
            ).await;
            return resp;
        }
    };
    let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
        Some(u) => u.clone(),
        None => {
            let resp = error_response(
                StatusCode::OK, rpc_id, INTERNAL_ERROR, "route upstream missing",
            );
            let (tid, pid, rid) = make_audit_ids(&name);
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), None, method.clone(),
                tid, pid, rid,
                Some(INTERNAL_ERROR), Some("route upstream missing".into()),
                started, Instant::now(), request_bytes, 0,
                user_agent, mcp_session_id, StatusCode::OK,
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), None,
                None, // limit_bucket
            ).await;
            return resp;
        }
    };
    let route_filter = if scope == McpScope::PromptGet {
        route.prompts_filter.as_ref()
    } else {
        route.tools_filter.as_ref()
    };
    if let Some(f) = route_filter
        && !f.permits(&suffix)
    {
        let msg = format!("name '{suffix}' is denied by route filter");
        let resp = era_error_response(
            StatusCode::OK,
            rpc_id,
            TOOL_NOT_FOUND,
            msg.clone(),
            &auth.era,
        );
        let (tid, pid, rid) = make_audit_ids(&name);
        emit_audit_with_policy(
            &state, &identity, request_id, &slug,
            Some(virtual_server_id), Some(upstream.id), method.clone(),
            tid, pid, rid,
            Some(TOOL_NOT_FOUND), Some(msg),
            started, Instant::now(), request_bytes, 0,
            user_agent, mcp_session_id, resp.status(),
            policy_classification, policy_app_id,
            policy_detection_method.clone(),
            request.params.clone(), None,
            None, // limit_bucket
        ).await;
        return resp;
    }

    // Rewrite params.name → suffix for the wire call.
    let mut rewritten = request.clone();
    if let Some(params) = rewritten.params.as_mut()
        && let Some(obj) = params.as_object_mut()
    {
        obj.insert("name".into(), serde_json::Value::String(suffix.clone()));
    }

    // ── Header resolution ─────────────────────────────────────────────────
    let upstream_auth = match resolve_upstream_auth(auth, &upstream).await {
        Ok(a) => a,
        Err(e) => {
            let (code, msg) = upstream_error_to_jsonrpc(&e, auth.sign_ins_url.as_deref());
            let resp = error_response(StatusCode::OK, rpc_id, code, msg.clone());
            let (tid, pid, rid) = make_audit_ids(&name);
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), Some(upstream.id), method.clone(),
                tid, pid, rid,
                Some(code), Some(msg),
                started, Instant::now(), request_bytes, 0,
                user_agent, mcp_session_id, StatusCode::OK,
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), None,
                None, // limit_bucket
            ).await;
            return resp;
        }
    };

    // ── Outbound call ─────────────────────────────────────────────────────
    // Resolve the per-upstream `Mcp-Session-Id` recorded at this upstream's
    // `initialize` (Bug 1 fix). Falls back to the downstream session-id —
    // safe for single-route VS where they coincide and for sessions whose
    // initialize was handled by a sibling proxy instance (best-effort).
    // A modern client supplies no session id, so the gateway must already
    // hold — or now open — its own connection to this upstream. Doing it here
    // as well as in `call_cached` is not duplication: this path calls the
    // upstream directly (it needs the raw streaming response), so it never
    // passes through that funnel.
    let (modern_upstream, modern_handshake) = {
        match streamed_upstream_preflight(
            auth,
            &upstream,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let (resp, code, msg) = upstream_error_relay(
                    request.id.clone().unwrap_or(RpcId::Null),
                    &e,
                    &auth.era,
                    auth.sign_ins_url.as_deref(),
                );
                let (tid, pid, rid) = make_audit_ids(&name);
                emit_audit_with_policy(
                    &state, &identity, request_id, &slug,
                    Some(virtual_server_id), Some(upstream.id), method.clone(),
                    tid, pid, rid,
                    Some(code), Some(msg),
                    started, dispatch_started, request_bytes, 0,
                    user_agent, mcp_session_id, resp.status(),
                    policy_classification, policy_app_id,
                    policy_detection_method.clone(),
                    request.params.clone(), None,
                    None, // limit_bucket
                ).await;
                return resp;
            }
        }
    };

    // The protocol version to present upstream. Clients MUST send it on
    // every request after `initialize` from `2025-06-18` onwards, and this
    // gateway is the client here. `None` — a session whose `initialize` a
    // sibling replica handled — omits the header, which is exactly the
    // pre-`2025-06-18` shape the spec still tolerates.
    let negotiated_version: Option<String> = if modern_upstream {
        Some(modern::MODERN_PROTOCOL_VERSION.to_string())
    } else {
        match &modern_handshake {
            Some(h) => Some(h.protocol_version.clone()),
            None => mcp_session_id
                .as_deref()
                .and_then(|ds| state.mcp.session_map.protocol_version(identity.tenant_id, ds)),
        }
    };

    let upstream_sid_owned: Option<String> = if modern_upstream {
        // A modern server neither mints nor accepts one, and the downstream
        // client's id — if it even sent one — names a session on the gateway,
        // not on this upstream.
        None
    } else {
        match &modern_handshake {
            Some(h) => h.session_id.clone(),
            None => match mcp_session_id.as_deref() {
                Some(ds) if !ds.is_empty() => state
                    .mcp
                    .session_map
                    .upstream_session(identity.tenant_id, ds, upstream.id)
                    .or_else(|| Some(ds.to_string())),
                _ => None,
            },
        }
    };
    let effective_sid = upstream_sid_owned.as_deref();

    // Bring the body into the upstream's era. A modern upstream is handed the
    // `_meta` envelope and any MRTR retry re-pointed at itself; a legacy one
    // is spared both. This path calls the upstream directly for its raw
    // streaming response, so it never passes through `call_cached` — the two
    // conversions are the same functions, called from the two places that
    // reach an upstream.
    let rewritten = if modern_upstream {
        modern_outbound_request(auth, &upstream, &rewritten)
    } else if auth.era.is_modern() {
        JsonRpcRequest {
            jsonrpc: rewritten.jsonrpc.clone(),
            id: rewritten.id.clone(),
            method: rewritten.method.clone(),
            params: modern::downgrade_request_params(rewritten.params.as_ref()),
        }
    } else {
        rewritten
    };

    // Built once and cloned into the pump: the same conversion has to run on
    // a one-shot reply and on the final event of a stream.
    let modern_relay =
        modern_upstream.then(|| ModernUpstreamRelay::from_auth(auth, &upstream, &method));

    // Legacy SSE upstream: dispatch through the persistent GET-channel
    // session and synthesise a one-shot reply. Server-initiated events
    // arrive on the GET channel and are surfaced via the per-(tenant, user)
    // event bus rather than the POST response, so the agent's `tools/call`
    // sees a single JSON body.
    //
    // Built-in sentinel: `internal://*` upstreams short-circuit into a
    // gateway-internal handler. The reply is always one-shot JSON
    // (no streaming SSE today) so we wrap it in `UpstreamReply::Single`.
    let reply = if super::virtual_servers::is_internal(&upstream) {
        match super::virtual_servers::dispatch(
            auth,
            &upstream,
            &rewritten,
        )
        .await
        {
            Ok((resp, sid)) => Ok(UpstreamReply::Single(resp, sid)),
            Err(e) => Err(e),
        }
    } else if matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::Sse
    ) {
        match dispatch_legacy_sse(
            auth,
            &upstream,
            upstream_auth.clone(),
            &rewritten,
            effective_sid,
            &route.prefix,
        )
        .await
        {
            Ok((resp, sid)) => Ok(UpstreamReply::Single(resp, sid)),
            Err(e) => Err(e),
        }
    } else {
        upstream::call_with_auth_for_streaming(
            &upstream,
            &upstream_auth,
            &rewritten,
            effective_sid,
            negotiated_version.as_deref(),
        )
        .await
    };

    let reply = match reply {
        Ok(r) => r,
        Err(e) => {
            let (resp, code, msg) = upstream_error_relay(
                request.id.clone().unwrap_or(RpcId::Null),
                &e,
                &auth.era,
                auth.sign_ins_url.as_deref(),
            );
            let (tid, pid, rid) = make_audit_ids(&name);
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), Some(upstream.id), method.clone(),
                tid, pid, rid,
                Some(code), Some(msg),
                started, dispatch_started, request_bytes, 0,
                user_agent, mcp_session_id, resp.status(),
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), None,
                None, // limit_bucket
            ).await;
            return resp;
        }
    };

    match reply {
        UpstreamReply::Single(mut resp_value, response_session_id) => {
            // Pin the session for reverse routing once the upstream's
            // session-id is known (or just use the inbound session id).
            let session_for_pin = response_session_id
                .clone()
                .or_else(|| mcp_session_id.clone());
            if let Some(sid) = session_for_pin.as_deref() {
                // Touch the entry so a follow-up `set_protocol_version` lands.
                // Reverse-path routing rides the `ssrid.…` token.
                state.mcp.session_map.upsert(identity.tenant_id, sid);
            }
            // Record any upstream-side session-id refresh so the next
            // request lands on the right upstream session (Bug 1 fix).
            if let Some(new_sid) = response_session_id.as_deref()
                && let Some(ds) = mcp_session_id.as_deref()
                && !new_sid.is_empty()
                && !ds.is_empty()
            {
                state.mcp.session_map.set_upstream_session(
                    identity.tenant_id,
                    ds,
                    upstream.id,
                    new_sid,
                );
            }
            // Rewrite resource URIs inside the JSON-RPC response so
            // resource_link / embedded-resource blocks returned by `tools/call`
            // (or messages returned by `prompts/get`) carry the
            // `stsmcp://<route_prefix>/` envelope — see streaming pump above
            // for the symmetric path. An error's `data.uri` is virtualized on
            // the same pass: it names a resource too.
            super::multiplex::rewrite_response_uris(&mut resp_value, &route.prefix);
            // A modern upstream's answer may be a question rather than a
            // result, and its error vocabulary may be one this client's
            // revision does not define. Runs before the audit tuple is read
            // so the row records what the client was actually told when the
            // gateway had to refuse a question on its behalf.
            if let Some(relay) = &modern_relay {
                relay.adapt_response(&mut resp_value);
            }
            // Audit records the upstream's own error code; only the wire copy
            // is renumbered for a modern client, so an operator reading the
            // row still sees what the upstream actually said.
            let err_tuple = resp_value.error.as_ref().map(|e| (e.code, e.message.clone()));
            if auth.era.is_modern() {
                if let Some(result) = resp_value.result.as_mut() {
                    modern::stamp_result(
                        result,
                        &method,
                        &server_info,
                        modern_cache_hint(&method, std::slice::from_ref(&upstream)),
                    );
                }
                if let Some(err) = resp_value.error.as_mut() {
                    modern::modernize_error(err);
                }
            }
            let body_bytes = serde_json::to_vec(&resp_value).unwrap_or_else(|_| b"{}".to_vec());
            let response_bytes = body_bytes.len() as i32;
            let builder = stamp_session_id(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json"),
                response_session_id.as_ref(),
                auth.era.is_modern(),
            );
            let resp = builder
                .body(Body::from(body_bytes))
                .unwrap_or_else(|_| Response::new(Body::empty()));
            let (tid, pid, rid) = make_audit_ids(&name);
            emit_audit_with_policy(
                &state, &identity, request_id, &slug,
                Some(virtual_server_id), Some(upstream.id), method.clone(),
                tid, pid, rid,
                err_tuple.as_ref().map(|(c, _)| *c),
                err_tuple.map(|(_, m)| m),
                started, Instant::now(), request_bytes, response_bytes,
                user_agent, mcp_session_id.or(response_session_id),
                StatusCode::OK,
                policy_classification, policy_app_id,
                policy_detection_method.clone(),
                request.params.clone(), resp_value.result.clone(),
                None, // limit_bucket
            ).await;
            resp
        }
        UpstreamReply::Streaming(upstream_resp, response_session_id) => {
            // Pin the session BEFORE returning so the agent's reply to a
            // server-initiated request finds the upstream.
            let session_for_pin = response_session_id
                .clone()
                .or_else(|| mcp_session_id.clone());
            if let Some(sid) = session_for_pin.as_deref() {
                // Touch the entry so a follow-up `set_protocol_version` lands.
                // Reverse-path routing rides the `ssrid.…` token.
                state.mcp.session_map.upsert(identity.tenant_id, sid);
            }
            // Record any upstream-side session-id refresh so the next
            // request lands on the right upstream session (Bug 1 fix).
            if let Some(new_sid) = response_session_id.as_deref()
                && let Some(ds) = mcp_session_id.as_deref()
                && !new_sid.is_empty()
                && !ds.is_empty()
            {
                state.mcp.session_map.set_upstream_session(
                    identity.tenant_id,
                    ds,
                    upstream.id,
                    new_sid,
                );
            }

            // Build the SSE body. The pump task drives the upstream stream,
            // re-encodes events, sends them to the downstream channel, and
            // emits side-channel audit/log signals along the way. The
            // per-request audit row fires when the pump finishes.
            let mrtr = modern_meta.as_ref().map(|meta| ModernStreamCtx {
                era: auth.era.clone(),
                wants_log_notifications: meta.wants_log_notifications(),
                client_capabilities: meta.client_capabilities.clone(),
                input_responses: modern::InputResponses::parse(request.params.as_ref()),
                tenant_id: identity.tenant_id,
                user_id: identity.user_id,
                virtual_server_id,
                method: method.clone(),
                params_digest: streamscope_core::mcp::tokens::digest_request_params(
                    request.params.as_ref(),
                ),
                rpc_id: request.id.clone().unwrap_or(RpcId::Null),
                server_info: server_info.clone(),
                seen: std::collections::BTreeMap::new(),
            });
            if let Some(ctx) = &mrtr
                && !ctx.input_responses.is_empty()
            {
                // The retry leg. Worth a line at info: the upstream call is
                // about to run a second time, which is the one cost of
                // bridging MRTR onto a legacy upstream, and an operator
                // debugging a double side-effect needs to see it.
                tracing::info!(
                    method = %ctx.method,
                    answers = ctx.input_responses.len(),
                    "MCP MRTR: re-issuing the upstream call with the client's input"
                );
            }

            stream_method_response(
                state.clone(),
                identity,
                request_id,
                slug,
                virtual_server_id,
                scope,
                method,
                upstream.clone(),
                route.prefix.clone(),
                upstream_resp,
                response_session_id,
                // A modern client sends no session id, so the reverse path an
                // MRTR answer travels on is the gateway's own handshake
                // session — without this the bridge would find no channel to
                // deliver the client's input on and fail every retry.
                mcp_session_id.or(upstream_sid_owned),
                upstream_auth,
                request,
                Some(name),
                policy_classification,
                policy_app_id,
                policy_detection_method,
                started,
                request_bytes,
                user_agent,
                mrtr,
                modern_relay,
            )
        }
    }
}

// ── Multi Round-Trip Requests (MCP 2026-07-28 § MRTR) ────────────────────
//
// A legacy upstream asks the client for input by sending its own JSON-RPC
// *request* down the response stream. A modern client cannot receive one:
// § Receiving Messages forbids the server from sending independent requests,
// and MRTR replaces the mechanism entirely. The bridge below converts between
// the two.
//
// The conversion is **re-issue on retry**, which is what makes it stateless.
// When the upstream asks a question we have no answer for, the gateway
// abandons the upstream call and answers the client with an
// `InputRequiredResult`. The client gathers the input and retries the
// original call carrying `inputResponses`; the gateway re-issues it upstream,
// and when the upstream asks the same question again it is answered inline
// from those responses. No parked stream, no replica affinity, nothing to
// resume — which is the property that lets the retry land on any instance.
//
// The cost is honest and worth naming: an upstream tool re-runs whatever it
// did *before* it asked. Tools ask before doing the work, so this is
// ordinarily free, but it is not free by construction.

/// What the bridge decided about one upstream server-initiated message.
enum MrtrOutcome {
    /// Not an input request, or nothing to bridge. Continue the normal
    /// forwarding path.
    NotApplicable,
    /// The client had already answered this question; the answer went
    /// upstream and the stream continues.
    Answered,
    /// The stream ends now, with this JSON-RPC message as its final one.
    Terminate(serde_json::Value),
}

/// The modern-era context for one streamed method call: everything the MRTR
/// bridge needs, plus the per-request log opt-in.
struct ModernStreamCtx {
    era: ProtocolEra,
    /// Whether this request opted in to `notifications/message`.
    ///
    /// § Logging makes the opt-in per request and mandatory: with no
    /// `io.modelcontextprotocol/logLevel` in `_meta`, the server MUST NOT emit
    /// log notifications for it. There is no `logging/setLevel` any more, so
    /// there is no connection-scoped level to fall back on either.
    wants_log_notifications: bool,
    /// The capabilities the client declared **on this request**. Never
    /// inherited from a previous one: the era is stateless, and a server MUST
    /// NOT infer a capability the current request did not declare.
    client_capabilities: serde_json::Value,
    /// Answers this attempt carried, keyed exactly as we asked for them.
    input_responses: modern::InputResponses,
    tenant_id: Uuid,
    user_id: Uuid,
    virtual_server_id: Uuid,
    /// Identity of the originating call, bound into the minted `requestState`
    /// so it cannot be replayed onto a different one.
    method: String,
    params_digest: String,
    /// The downstream JSON-RPC id an `InputRequiredResult` must answer.
    rpc_id: RpcId,
    server_info: serde_json::Value,
    /// How many input requests of each method this stream has already seen.
    ///
    /// Load-bearing, not bookkeeping: an upstream may ask two elicitations in
    /// one call. Both would otherwise be filed under the same key, and on the
    /// re-issue the second question would be answered with the first
    /// question's answer. The ordinal makes the Nth question of a given
    /// method map to the same key on every attempt — which is exactly the
    /// property the re-issue model depends on.
    seen: std::collections::BTreeMap<String, usize>,
}

impl ModernStreamCtx {
    /// The key for the next input request of `method` in this stream.
    fn next_key(&mut self, method: &str) -> String {
        let ordinal = self.seen.entry(method.to_string()).or_insert(0);
        let key = modern::input_request_key(method, *ordinal);
        *ordinal += 1;
        key
    }
}

/// Apply the modern result stamps to a JSON-RPC response riding an SSE stream.
///
/// The final response to a streamed `tools/call` / `prompts/get` arrives as one
/// more event on the upstream's stream and is forwarded like any other, so it
/// never passes through [`finalize_modern_response`] — which handles only the
/// one-shot reply. Without this, a modern client would get `resultType` on
/// every list method and on a non-streaming tool call, and *not* on a
/// streaming one: the same method, stamped or unstamped depending on how the
/// upstream chose to answer.
///
/// Returns `None` for anything that is not a response to our request, leaving
/// notifications and server-initiated requests untouched.
///
/// The two streaming methods are not `CacheableResult`s, so no freshness hint
/// is added — passing one here would attach `ttlMs` to a tool call.
fn stamp_streamed_response(
    raw: &str,
    method: &str,
    server_info: &serde_json::Value,
) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let obj = value.as_object_mut()?;
    if obj.contains_key("method") || !obj.contains_key("id") {
        return None;
    }
    if let Some(result) = obj.get_mut("result") {
        modern::stamp_result(result, method, server_info, None);
    } else if let Some(err) = obj.get_mut("error")
        && let Ok(mut parsed) =
            serde_json::from_value::<super::jsonrpc::JsonRpcError>(err.clone())
    {
        // Renumber through `modernize_error` rather than re-deriving it here.
        // Hand-rolling the same rewrite meant this path read the code alone,
        // so an error whose meaning is carried in its `data` renumbered one way
        // on a streamed response and another on a one-shot — the same wire, two
        // answers, decided by which pump happened to carry it.
        let before = parsed.code;
        modern::modernize_error(&mut parsed);
        if parsed.code == before {
            return None;
        }
        *err = serde_json::to_value(&parsed).ok()?;
    } else {
        return None;
    }
    serde_json::to_string(&value).ok()
}

/// What one pumped SSE event decided about the rest of the stream.
///
/// Two unrelated endings stay distinct: the downstream client going away,
/// and the *gateway* ending the stream on purpose after writing a final
/// message. They need different audit rows — the first is a disconnect, the
/// second is an ordinary MRTR leg that worked — and a `bool` collapsing them
/// would file every successful `input_required` response as `-32003 client
/// disconnected mid-stream`.
enum PumpOutcome {
    /// Keep reading the upstream stream.
    Continue,
    /// The downstream client is gone. Stop, and audit it as a disconnect.
    ClientGone,
    /// The gateway ended the stream itself, having already written the final
    /// message. `Some` carries the error to record; `None` means the ending
    /// was a *successful* result (an `input_required` leg) and the row must
    /// carry no error at all.
    Terminated(Option<(i32, String)>),
}

/// A JSON-RPC error message for the MRTR terminate path, with the code brought
/// into the era's legal range.
///
/// This path is the one that writes an error **straight to the wire**: a
/// `Terminate` message is framed and sent by `process_event` before anything
/// reaches `stamp_streamed_response`, so none of the other renumbering sites
/// can see it. Building the envelope by hand here without this would put a
/// frozen-range gateway code in front of a modern client while every other
/// path renumbered — the inconsistency being the bug, since a receiver is told
/// to assign no meaning to a code from that band.
fn mrtr_error(rpc_id: &RpcId, code: i32, message: &str, era: &ProtocolEra) -> serde_json::Value {
    let mut err = super::jsonrpc::JsonRpcError {
        code,
        message: message.to_string(),
        data: None,
    };
    if era.is_modern() {
        modern::modernize_error(&mut err);
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": err,
    })
}

/// Bridge one upstream server-initiated request into the MRTR pattern.
async fn mrtr_bridge(
    ev: &streamscope_core::api::sse::SseEvent,
    mrtr: &mut ModernStreamCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    upstream_auth: &UpstreamAuth,
    upstream_session_id: Option<&str>,
) -> MrtrOutcome {
    if !mrtr.era.is_modern() {
        return MrtrOutcome::NotApplicable;
    }
    let Ok(message) = serde_json::from_str::<serde_json::Value>(&ev.data) else {
        return MrtrOutcome::NotApplicable;
    };
    let Some((method, params)) = modern::input_request_entry(&message) else {
        return MrtrOutcome::NotApplicable;
    };
    // § MRTR: only `tools/call`, `prompts/get` and `resources/read` may
    // answer with an `InputRequiredResult`. This path is reached only from the
    // first two, so a failure here means a new caller was wired in without
    // checking — assert it rather than emit a result type the client is
    // entitled to reject as invalid.
    if !modern::supports_input_required(&mrtr.method) {
        tracing::error!(
            method = %mrtr.method,
            "MCP MRTR: an input request arrived on a method that may not answer with one"
        );
        return MrtrOutcome::NotApplicable;
    }

    let upstream_id = message.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let key = mrtr.next_key(&method);

    // ── Retry leg: answer the upstream inline from what the client sent ──
    if let Some(answer) = mrtr.input_responses.get(&key) {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": upstream_id,
            "result": answer,
        });
        match upstream_session_id {
            Some(sid) => {
                if let Err(e) = upstream::forward_client_response(
                    &upstream.upstream_url,
                    upstream_auth,
                    &payload,
                    sid,
                    upstream.request_timeout_ms,
                )
                .await
                {
                    // The upstream is waiting on an answer it will now never
                    // get, so the stream is dead either way. Ending it with a
                    // fresh `InputRequiredResult` would loop the client;
                    // reporting the failure lets it surface something true.
                    tracing::warn!(
                        upstream_id = %upstream.id,
                        key = %key,
                        error = %e,
                        "MCP MRTR: could not deliver the client's input to the upstream"
                    );
                    return MrtrOutcome::Terminate(mrtr_error(
                        &mrtr.rpc_id,
                        UPSTREAM_ERROR,
                        "the upstream did not accept the supplied input",
                        &mrtr.era,
                    ));
                }
                MrtrOutcome::Answered
            }
            None => {
                // No reverse path exists, so the answer cannot be delivered.
                tracing::warn!(
                    upstream_id = %upstream.id,
                    "MCP MRTR: upstream issued an input request with no session to answer on"
                );
                MrtrOutcome::Terminate(mrtr_error(
                    &mrtr.rpc_id,
                    UPSTREAM_ERROR,
                    "the upstream asked for input but offered no way to return it",
                    &mrtr.era,
                ))
            }
        }
    } else {
        // ── First leg: hand the question to the client as data ──
        //
        // § MRTR server requirement 7: never ask for input the client has not
        // declared it can produce. `-32021` names exactly what it is missing,
        // which is the client's cue to reconnect with that capability rather
        // than to retry blindly.
        let meta = RequestMeta {
            protocol_version: mrtr.era.version().to_string(),
            client_info: None,
            client_capabilities: mrtr.client_capabilities.clone(),
            log_level: None,
        };
        if !meta.supports_input_request(&method) {
            let err = ModernError::missing_client_capability(
                modern::required_capability_for(&method),
                format!("the upstream requires {method}, which this request did not declare support for"),
            );
            return MrtrOutcome::Terminate(serde_json::json!({
                "jsonrpc": "2.0",
                "id": mrtr.rpc_id,
                "error": {
                    "code": err.code,
                    "message": err.message,
                    "data": err.data,
                }
            }));
        }

        let request_state = match streamscope_core::mcp::tokens::encode_request_state(
            mrtr.tenant_id,
            mrtr.user_id,
            mrtr.virtual_server_id,
            &mrtr.method,
            &mrtr.params_digest,
            // The gateway's own bridge over a LEGACY upstream: the retry is
            // answered by re-issuing the call, so there is no upstream blob
            // to quote back and no upstream to name.
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "MCP MRTR: could not mint requestState");
                return MrtrOutcome::Terminate(mrtr_error(
                    &mrtr.rpc_id,
                    INTERNAL_ERROR,
                    "could not prepare the input request",
                    &mrtr.era,
                ));
            }
        };

        let mut requests = serde_json::Map::new();
        requests.insert(
            key,
            serde_json::json!({ "method": method, "params": params }),
        );
        MrtrOutcome::Terminate(serde_json::json!({
            "jsonrpc": "2.0",
            "id": mrtr.rpc_id,
            "result": modern::input_required_result(&requests, &request_state, &mrtr.server_info),
        }))
    }
}

/// Verify the `requestState` a modern client quoted back on a retry.
///
/// § MRTR treats `requestState` as attacker-controlled. The HMAC proves we
/// minted it; these checks prove it belongs to *this* call by *this* caller:
/// a different principal, a different method, or different arguments all
/// reject. Without them a member could lift a colleague's state off the wire
/// and present it on a call of their own choosing.
///
/// Absent state is fine — that is simply a first attempt.
///
/// Returns the upstream this retry is aimed at, when the state wraps one: a
/// modern upstream's question carries the upstream's own opaque blob, and the
/// re-issue has to quote *that* back rather than the wrapper. `None` covers
/// both a first attempt and the gateway's own legacy-upstream bridge, which
/// re-issues instead of quoting.
fn verify_request_state(
    params: Option<&serde_json::Value>,
    identity: &Identity,
    virtual_server_id: Uuid,
    method: &str,
) -> Result<Option<(Uuid, Option<String>)>, ModernError> {
    let Some(raw) = params
        .and_then(|p| p.get("requestState"))
        .and_then(|v| v.as_str())
    else {
        return Ok(None);
    };
    let decoded = streamscope_core::mcp::tokens::decode_request_state(
        raw,
        streamscope_core::mcp::tokens::DEFAULT_REQUEST_STATE_TTL_SECS,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "MCP MRTR: requestState failed verification");
        ModernError::invalid_params("requestState is not valid or has expired")
    })?;

    let expected_digest = streamscope_core::mcp::tokens::digest_request_params(params);
    if decoded.tenant_id != identity.tenant_id
        || decoded.user_id != identity.user_id
        || decoded.virtual_server_id != virtual_server_id
        || decoded.method != method
        || decoded.params_digest != expected_digest
    {
        tracing::warn!(
            tenant_matches = decoded.tenant_id == identity.tenant_id,
            user_matches = decoded.user_id == identity.user_id,
            vs_matches = decoded.virtual_server_id == virtual_server_id,
            method_matches = decoded.method == method,
            "MCP MRTR: requestState presented on a request it was not minted for"
        );
        return Err(ModernError::invalid_params(
            "requestState does not belong to this request",
        ));
    }
    Ok(match (decoded.upstream_id, decoded.upstream_state) {
        // The upstream that asked, plus its own blob when it minted one.
        // § MRTR makes the server's `requestState` optional, so an id with no
        // state is a conforming retry rather than half a wrapper — the retry
        // still routes there, it just quotes nothing back.
        (Some(id), state) => Some((id, state)),
        // State naming no upstream cannot have come from this gateway: the id
        // and the blob are written by one call, and the legacy bridge writes
        // neither. Treat it as no upstream rather than quoting a blob at an
        // unnamed server.
        (None, _) => None,
    })
}

/// Drive an upstream SSE stream (`tools/call` or `prompts/get`) into the
/// downstream HTTP response, classifying each event for the audit pipeline.
///
/// The returned `Response` is sent to the agent immediately with a chunked
/// `text/event-stream` body backed by an unbounded mpsc channel; a spawned
/// task pumps the upstream stream into that channel. When the upstream
/// stream closes (or we hit a hard bound), the task emits the per-request
/// `mcp_audit` row stamped with the original method (`tools/call` or
/// `prompts/get`).
#[allow(clippy::too_many_arguments)]
fn stream_method_response(
    state: McpRouterState,
    identity: Identity,
    request_id: Uuid,
    slug: String,
    virtual_server_id: Uuid,
    scope: McpScope,
    method: String,
    upstream: streamscope_core::config::mcp::McpUpstreamServer,
    route_prefix: String,
    upstream_resp: reqwest::Response,
    response_session_id: Option<String>,
    inbound_session_id: Option<String>,
    upstream_auth: UpstreamAuth,
    original_request: JsonRpcRequest,
    resolved_name: Option<String>,
    policy_classification: Option<streamscope_core::config::tool_rules::RiskResult>,
    policy_app_id: Option<String>,
    policy_detection_method: Option<String>,
    started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
    mrtr: Option<ModernStreamCtx>,
    modern_relay: Option<ModernUpstreamRelay>,
) -> Response<Body> {
    use bytes::{Bytes, BytesMut};
    use futures::StreamExt;
    use streamscope_core::api::sse::SseDecoder;
    use tokio_util::codec::Decoder;

    // Bounded channel: the pump's `tx.send().await` blocks when the
    // downstream client hasn't drained the buffer, propagating backpressure
    // up the upstream `bytes_stream` poll. Without this bound, a stalled
    // client + chatty upstream would queue events in proxy memory unbounded
    // until the per-stream byte cap fires (and even then, all already-queued
    // events stay in memory). 64 events is enough headroom for normal
    // bursts without amplifying memory under N stalled clients.
    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);

    // Bound the per-stream byte count so a runaway upstream can't blow memory.
    // Operator-configurable via `MCP_STREAM_MAX_BYTES`; default 8 MiB.
    let stream_byte_cap: usize = crate::settings::proxy_settings().mcp_stream_max_bytes;

    // Bearer captured here is the upstream credential resolved at stream
    // open. The sampling-intercept fork uses it to POST the synthesised
    // JSON-RPC response back upstream (same as the agent would).
    // Capture the inbound JSON-RPC params before the pump task takes
    // ownership of `original_request` — the success-path audit row at
    // the bottom of this task wants `mcp_audit.params` populated so the
    // session-view bubble can render the actual call body.
    let request_params_for_audit = original_request.params.clone();
    let state_for_task = state.clone();
    let slug_for_task = slug.clone();
    let response_session_id_for_header = response_session_id.clone();
    let response_session_id_for_task = response_session_id.clone();
    let dispatch_started = Instant::now();

    // Tracked, not bare `tokio::spawn`: this pump emits the per-request audit
    // row after the SSE response's connection future has resolved. Proxy
    // graceful shutdown waits on the tracker before draining the audit
    // writers so the row is never lost.
    let audit_tracker = state.app.audit_task_tracker.clone();
    // `mrtr` is constructed only for a modern client (from `modern_meta`), so
    // its presence IS the era here. Captured before the pump task takes
    // ownership, because the response builder below runs after the spawn.
    let downstream_is_modern = mrtr.is_some();

    audit_tracker.spawn(async move {
        let mut mrtr = mrtr;
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut decoder = SseDecoder::new();
        let mut buf = BytesMut::with_capacity(8 * 1024);
        let mut total_bytes: usize = 0;
        let sampling_count: u32 = 0;
        let elicitation_count: u32 = 0;
        let log_count: u32 = 0;
        let mut response_bytes_out: i32 = 0;
        let mut had_error: Option<(i32, String)> = None;

        // Inner closure to process one decoded event. Returns false if the
        // downstream channel is closed (client disconnect) so the outer loop
        // can exit and still emit the per-request audit row.
        async fn process_event(
            mut ev: streamscope_core::api::sse::SseEvent,
            tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
            state_for_task: &McpRouterState,
            identity: &Identity,
            virtual_server_id: Uuid,
            upstream: &streamscope_core::config::mcp::McpUpstreamServer,
            route_prefix: &str,
            session_for_audit: Option<String>,
            upstream_auth: &UpstreamAuth,
            counters: &mut (u32, u32, u32, u32, u32),
            response_bytes_out: &mut i32,
            mrtr: Option<&mut ModernStreamCtx>,
            modern_relay: Option<&ModernUpstreamRelay>,
        ) -> PumpOutcome {
            // ── Sampling intercept fork ──
            //
            // Before any forwarding, check whether this event is a
            // `sampling/createMessage` AND the originating virtual server has
            // [`SamplingInterceptConfig`] populated. If so, the gateway
            // answers the upstream itself via an HTTP loopback into
            // `/v1/messages` and skips the agent fan-out entirely. See
            // `super::sampling`.
            if maybe_intercept_sampling(
                &ev,
                state_for_task,
                identity,
                virtual_server_id,
                upstream,
                session_for_audit.as_deref(),
                upstream_auth,
            )
            .await
            .is_some()
            {
                // Intercept fired (success OR failure). The audit row was
                // emitted and the JSON-RPC response was POSTed to the
                // upstream; we deliberately skip agent fan-out + GET-channel
                // bus publish + Last-Event-ID persistence here so the agent
                // never sees this event (no double-billing on failure).
                counters.0 += 1;
                return PumpOutcome::Continue;
            }

            // Captured before the fork below takes the borrow. Both are
            // modern-era facts about the whole stream, not about one event.
            let suppress_log_notifications = mrtr
                .as_ref()
                .is_some_and(|m| !m.wants_log_notifications);
            let modern_stamp: Option<(String, serde_json::Value)> = mrtr
                .as_ref()
                .map(|m| (m.method.clone(), m.server_info.clone()));
            let suppress_removed_server_notifications = mrtr.is_some();

            // ── MRTR fork (modern clients only) ──
            //
            // Runs AFTER the sampling intercept, deliberately: when the
            // virtual server is configured to answer sampling itself, the
            // client should never be asked at all. What reaches here is a
            // question only the client can answer.
            //
            // A modern client cannot receive a server-initiated request, so
            // the stream either continues with the answer it already gave, or
            // ends now with the question as data.
            if let Some(mrtr) = mrtr {
                match mrtr_bridge(
                    &ev,
                    mrtr,
                    upstream,
                    upstream_auth,
                    session_for_audit.as_deref(),
                )
                .await
                {
                    MrtrOutcome::NotApplicable => {}
                    MrtrOutcome::Answered => {
                        counters.1 += 1;
                        return PumpOutcome::Continue;
                    }
                    MrtrOutcome::Terminate(message) => {
                        // The audit outcome is read off the message we are
                        // about to send, so the row says what the client was
                        // actually told. An `input_required` result is a
                        // SUCCESS — the bridge worked — and must leave the row
                        // free of any error; only a genuine error terminate
                        // carries one.
                        let audit_outcome = message.get("error").and_then(|e| {
                            let code = e.get("code")?.as_i64()? as i32;
                            let msg = e
                                .get("message")?
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            Some((code, msg))
                        });
                        let wire = format!(
                            "event: message\ndata: {}\n\n",
                            serde_json::to_string(&message).unwrap_or_else(|_| "{}".into())
                        );
                        *response_bytes_out += wire.len() as i32;
                        if tx.send(Ok(Bytes::from(wire))).await.is_err() {
                            // The client vanished while we were answering it,
                            // so this genuinely IS a disconnect.
                            return PumpOutcome::ClientGone;
                        }
                        // Stopping here abandons the upstream call, which IS
                        // the pattern: the client retries with its answers and
                        // the call is re-issued.
                        return PumpOutcome::Terminated(audit_outcome);
                    }
                }
            }

            // Virtualize sampling/elicitation request ids before classify +
            // encode so the agent (and any cross-instance bus subscriber) sees
            // an `ssrid.…` token instead of the upstream's raw id. The agent's
            // POST response quotes this token back; any proxy replica decodes
            // it to recover the originating upstream — closes the cross-
            // instance reverse-path bug. Falls through unchanged when no
            // session id is in scope (no virtualization possible).
            let mut audit_id_override: Option<serde_json::Value> = None;
            if let Some(sid) = session_for_audit.as_deref()
                && let Some(virt) = super::multiplex::virtualize_server_initiated_id(
                    &ev.data,
                    upstream.id,
                    sid,
                    identity.tenant_id,
                    identity.user_id,
                )
            {
                audit_id_override = Some(virt.original_id);
                ev.data = virt.data;
            }
            // Rewrite `notifications/resources/updated` URIs to the
            // `stsmcp://<route_prefix>/<b64>` envelope so agents that
            // subscribed by envelope URI can correlate the notification.
            // No-op for events that aren't resources/updated or that already
            // carry an enveloped URI (idempotent on bus replay).
            if let Some(rewritten) =
                super::multiplex::rewrite_resource_updated_uri(&ev.data, route_prefix)
            {
                ev.data = rewritten;
            }
            // Rewrite resource URIs inside `tools/call` / `prompts/get` JSON-
            // RPC responses (`result.content[]` resource_link / resource
            // blocks, `result.messages[].content[]` for prompts) so the
            // envelope contract holds across every URI the agent sees. Same
            // idempotency guarantee — already-enveloped URIs are skipped.
            if let Some(rewritten) =
                super::multiplex::rewrite_response_resource_uris(&ev.data, route_prefix)
            {
                ev.data = rewritten;
            }
            // Derived before the match below so the borrow of `mrtr` inside
            // the MRTR fork has ended by the time the log arm reads it.
            let suppress_log = suppress_log_notifications;

            // A MODERN upstream's answer is not yet in the shape this client
            // can receive: an `InputRequiredResult` has to be re-wrapped
            // around a state only this gateway can verify, and the era's own
            // error codes mean nothing to a legacy client. Runs for BOTH
            // downstream eras — what decides whether it is needed is the
            // UPSTREAM's era, not the client's — and before the modern stamps
            // below, which would otherwise stamp a body that is about to be
            // replaced.
            if let Some(relay) = modern_relay
                && let Some(adapted) = relay.adapt_stream_event(&ev.data)
            {
                ev.data = adapted;
            }

            // Bring the final response up to modern shape. Runs after every
            // URI rewrite above so the stamps land on the body the client
            // actually receives, and before the classification below so the
            // bus copy and the `Last-Event-ID` replay row carry them too — a
            // replayed event that differed from the original would be a
            // second, quieter version of the same bug.
            if let Some((method, server_info)) = &modern_stamp
                && let Some(stamped) = stamp_streamed_response(&ev.data, method, server_info)
            {
                ev.data = stamped;
            }

            let classified = super::multiplex::classify_sse_event(&ev.data);
            let publish_to_bus = matches!(
                classified.kind,
                super::multiplex::EventKind::Sampling { .. }
                    | super::multiplex::EventKind::Elicitation { .. }
                    | super::multiplex::EventKind::ListChanged { .. }
                    | super::multiplex::EventKind::ResourceUpdated { .. }
                    | super::multiplex::EventKind::ElicitationComplete { .. }
            );
            // Mint a stable `ssevt.…` event id for resumable kinds (the GET
            // channel's `Last-Event-ID` replay surface). Replace ev.id BEFORE
            // encoding so the wire bytes carry the synthesized id; the
            // upstream's id (if any) is irrelevant — it has no meaning to
            // the downstream client.
            //
            // Persist the encoded wire bytes via the SSE-event channel so any
            // proxy replica can serve a `Last-Event-ID` replay from the DB —
            // closes the cross-instance resumption gap (see plan).
            let mut minted_event_id: Option<String> = None;
            let mut minted_sequence: Option<i64> = None;
            let mut minted_session_id: Option<String> = None;
            if publish_to_bus
                && let Some(sid) = session_for_audit.as_deref()
            {
                let seq = state_for_task
                    .mcp
                    .sse_seq
                    .next(identity.tenant_id, sid);
                match streamscope_core::mcp::tokens::encode_event_id(
                    identity.tenant_id,
                    identity.user_id,
                    sid,
                    seq,
                ) {
                    Ok(token) => {
                        ev.id = Some(token.clone());
                        minted_event_id = Some(token);
                        minted_sequence = Some(seq as i64);
                        minted_session_id = Some(sid.to_string());
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "failed to mint ssevt id; client cannot resume this event"
                        );
                    }
                }
            }
            // Pre-encode the event so the same bytes flow to the downstream
            // tools/call SSE response AND any concurrent GET-channel
            // subscriber for this user.
            let wire = super::multiplex::encode_sse_event(&ev);
            let bus_bytes = Bytes::from(wire.clone());
            match &classified.kind {
                super::multiplex::EventKind::Sampling { rpc_id } => {
                    counters.0 += 1;
                    let audit_id = audit_id_override.as_ref().unwrap_or(rpc_id);
                    emit_server_initiated_audit(
                        state_for_task,
                        identity,
                        virtual_server_id,
                        upstream.id,
                        "sampling/createMessage",
                        audit_id,
                        session_for_audit,
                        audit_id_override.is_some(),
                    )
                    .await;
                }
                super::multiplex::EventKind::Elicitation { rpc_id } => {
                    counters.1 += 1;
                    let audit_id = audit_id_override.as_ref().unwrap_or(rpc_id);
                    emit_server_initiated_audit(
                        state_for_task,
                        identity,
                        virtual_server_id,
                        upstream.id,
                        "elicitation/create",
                        audit_id,
                        session_for_audit,
                        audit_id_override.is_some(),
                    )
                    .await;
                }
                super::multiplex::EventKind::LogNotification { level, logger } => {
                    counters.2 += 1;
                    tracing::debug!(
                        upstream_id = %upstream.id,
                        level = ?level,
                        logger = ?logger,
                        "mcp upstream log notification"
                    );
                    // § Logging: a modern request that did not name a
                    // `logLevel` MUST NOT receive log notifications. The
                    // upstream is a legacy server with no per-request notion
                    // of the opt-in, so the gateway enforces it — dropping
                    // the event here rather than forwarding it, while the
                    // debug line above and the counter keep it visible to
                    // operators. Legacy clients are unaffected: they opted in
                    // with `logging/setLevel` and `suppress_log` is false.
                    if suppress_log {
                        return PumpOutcome::Continue;
                    }
                }
                super::multiplex::EventKind::ListChanged { which } => {
                    counters.3 += 1;
                    emit_list_changed_audit(
                        state_for_task,
                        identity,
                        virtual_server_id,
                        upstream.id,
                        *which,
                        session_for_audit,
                    )
                    .await;
                }
                super::multiplex::EventKind::ResourceUpdated { uri } => {
                    // No audit row today — high-cardinality, low-signal per
                    // change. The classification + bus publish are what
                    // matter (envelope-URI rewrite already happened above).
                    tracing::debug!(
                        upstream_id = %upstream.id,
                        uri = ?uri,
                        "mcp upstream resource updated"
                    );
                }
                super::multiplex::EventKind::ElicitationComplete { elicitation_id } => {
                    counters.4 += 1;
                    emit_elicitation_complete_audit(
                        state_for_task,
                        identity,
                        virtual_server_id,
                        upstream.id,
                        elicitation_id.as_deref(),
                        session_for_audit,
                    )
                    .await;
                    // The audit row above is written either way — the upstream
                    // did emit this, and it is not silently discarded. What a
                    // modern client must not receive is the notification
                    // itself: `2026-07-28` removed it, so its revision gives
                    // the method no meaning, and under MRTR there is nothing
                    // for it to correlate against.
                    //
                    // The method is named here and tested against the removed
                    // list rather than assumed from the arm, so the list stays
                    // the single place the rule lives: drop the method from it
                    // and this arm stops suppressing, with no second edit.
                    if suppress_removed_server_notifications
                        && modern::is_removed_server_notification_in_modern(
                            "notifications/elicitation/complete",
                        )
                    {
                        return PumpOutcome::Continue;
                    }
                }
                super::multiplex::EventKind::Passthrough => {}
            }
            if publish_to_bus {
                state_for_task.mcp.event_bus.publish(
                    identity.tenant_id,
                    identity.user_id,
                    virtual_server_id,
                    UserEvent(bus_bytes),
                );
            }
            // Persist the encoded wire bytes for `Last-Event-ID` replay. The
            // channel is bounded; on overflow drop with a debug log — the
            // long-term record is the audit row, this row is best-effort
            // replay. Only persist when we successfully minted an event id
            // (i.e. one of the resumable kinds AND a session was in scope).
            if let (Some(event_id), Some(seq), Some(sid)) =
                (minted_event_id, minted_sequence, minted_session_id)
            {
                let record = streamscope_core::mcp::sse_events::McpSseEventRecord {
                    tenant_id: identity.tenant_id,
                    user_id: identity.user_id,
                    mcp_session_id: sid,
                    virtual_server_id: Some(virtual_server_id),
                    event_id,
                    sequence: seq,
                    event_data: wire.clone(),
                    created_at: chrono::Utc::now(),
                };
                if let Err(err) = state_for_task.mcp.mcp_sse_event_tx.try_send(record) {
                    tracing::debug!(error = %err, "mcp sse event tx full; dropped row (replay best-effort)");
                }
            }
            *response_bytes_out += wire.len() as i32;
            if tx.send(Ok(Bytes::from(wire))).await.is_ok() {
                PumpOutcome::Continue
            } else {
                PumpOutcome::ClientGone
            }
        }

        let mut counters = (
            sampling_count,
            elicitation_count,
            log_count,
            0u32, /* list_changed */
            0u32, /* elicitation_complete */
        );
        let mut client_connected = true;
        // Set when the GATEWAY ended the stream on purpose (an MRTR leg).
        // Distinct from `client_connected`, because the two produce opposite
        // audit rows.
        let mut gateway_terminated = false;

        'pump: while let Some(chunk) = byte_stream.next().await {
            let bytes = match chunk {
                Ok(b) => b,
                Err(e) => {
                    had_error = Some((UPSTREAM_ERROR, format!("upstream stream error: {e}")));
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break 'pump;
                }
            };
            total_bytes += bytes.len();
            if total_bytes > stream_byte_cap {
                had_error = Some((UPSTREAM_ERROR, "upstream stream exceeded byte cap".into()));
                let _ = tx
                    .send(Err(std::io::Error::other("byte cap exceeded")))
                    .await;
                break 'pump;
            }
            buf.extend_from_slice(&bytes);

            loop {
                match decoder.decode(&mut buf) {
                    Ok(Some(ev)) => {
                        // Prefer the upstream's view of `Mcp-Session-Id`
                        // (captured from the upstream's response header) over
                        // the agent-supplied inbound id when encoding ssrid
                        // tokens — strict upstreams that re-mint the session
                        // on `initialize` would otherwise see an unfamiliar
                        // id when the agent's POST response comes back.
                        let session_for_audit = response_session_id_for_task
                            .clone()
                            .or_else(|| inbound_session_id.clone());
                        match process_event(
                            ev,
                            &tx,
                            &state_for_task,
                            &identity,
                            virtual_server_id,
                            &upstream,
                            &route_prefix,
                            session_for_audit,
                            &upstream_auth,
                            &mut counters,
                            &mut response_bytes_out,
                            mrtr.as_mut(),
                            modern_relay.as_ref(),
                        )
                        .await
                        {
                            PumpOutcome::Continue => {}
                            PumpOutcome::ClientGone => {
                                // Stop pumping but still emit the per-request
                                // audit row so the call is visible to
                                // operators ("nothing silently discarded").
                                client_connected = false;
                                break 'pump;
                            }
                            PumpOutcome::Terminated(outcome) => {
                                // The gateway ended the stream deliberately
                                // and has already written the client's final
                                // message. The client is fine, so this must
                                // NOT be recorded as a disconnect; the row
                                // carries whatever the client was actually
                                // told, which for an `input_required` leg is
                                // no error at all.
                                had_error = outcome;
                                gateway_terminated = true;
                                break 'pump;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let msg = format!("malformed upstream SSE: {e}");
                        had_error = Some((UPSTREAM_ERROR, msg.clone()));
                        let _ = tx.send(Err(std::io::Error::other(msg))).await;
                        break 'pump;
                    }
                }
            }
        }

        // Drain any tail buffered between the last `\n\n` boundary and EOF.
        // Streamable-HTTP upstreams sometimes terminate without a trailing
        // blank line; without this call the final event (often the actual
        // `tools/call` result) would silently disappear.
        if client_connected
            && let Ok(Some(ev)) = decoder.decode_eof(&mut buf)
        {
            // Same priority flip as the inner pump loop: upstream's view of
            // `Mcp-Session-Id` is authoritative for ssrid encoding.
            let session_for_audit = response_session_id_for_task
                .clone()
                .or_else(|| inbound_session_id.clone());
            if let PumpOutcome::Terminated(outcome) = process_event(
                ev,
                &tx,
                &state_for_task,
                &identity,
                virtual_server_id,
                &upstream,
                &route_prefix,
                session_for_audit,
                &upstream_auth,
                &mut counters,
                &mut response_bytes_out,
                mrtr.as_mut(),
                modern_relay.as_ref(),
            )
            .await
            {
                had_error = outcome;
                gateway_terminated = true;
            }
        }
        let (
            sampling_count,
            elicitation_count,
            log_count,
            list_changed_count,
            elicitation_complete_count,
        ) = counters;
        if !client_connected && !gateway_terminated && had_error.is_none() {
            had_error = Some((UPSTREAM_ERROR, "client disconnected mid-stream".into()));
        }

        // Per-request audit row for the original tools/call. Annotates the
        // multiplex counts on `transform_diff` so operators can see what
        // happened inside the stream without hunting through individual
        // child rows.
        let mut diff = serde_json::Map::new();
        if let Some(rc) = &policy_classification
            && (rc.id.is_some() || rc.action != "allow")
        {
            diff.insert(
                "policy_classification".into(),
                serde_json::json!({
                    "rule_id": rc.id,
                    "risk": rc.risk,
                    "title": rc.title,
                    "description": rc.description,
                    "action": rc.action,
                    "tool_id": rc.tool_id,
                    "profile_id": rc.profile_id,
                }),
            );
        }
        diff.insert(
            "mcp_stream".into(),
            serde_json::json!({
                "sampling_requests": sampling_count,
                "elicitation_requests": elicitation_count,
                "log_notifications": log_count,
                "list_changed_notifications": list_changed_count,
                "elicitation_complete_notifications": elicitation_complete_count,
                "stream_bytes": total_bytes,
            }),
        );
        let transform_diff = serde_json::Value::Object(diff);
        let total_ms = started.elapsed().as_millis() as u64;
        let upstream_ms = dispatch_started.elapsed().as_millis() as u64;
        let session_id_hashed = inbound_session_id.as_ref().map(|raw| {
            // user_id (not key_id) — see `session_id_from_client` doc.
            streamscope_core::proxy::content::session_id_from_client(
                raw, identity.tenant_id, identity.user_id,
            )
        });
        let pump_session_for_pv = inbound_session_id
            .as_deref()
            .or(response_session_id_for_task.as_deref());
        let pump_protocol_version = pump_session_for_pv
            .and_then(|sid| {
                state_for_task
                    .mcp
                    .session_map
                    .protocol_version(identity.tenant_id, sid)
            })
            .or_else(|| identity.declared_protocol_version.clone());
        let (rpc_err_code, rpc_err_msg) = match had_error {
            Some((c, m)) => (Some(c), Some(m)),
            None => (None, None),
        };
        let now = chrono::Utc::now();
        let record = McpAuditRecord {
            request_id,
            timestamp: now,
            tenant_id: identity.tenant_id,
            workspace_id: identity.user.workspace_id,
            user_id: identity.user_id,
            key_id: identity.key_id,
            app_id: policy_app_id.clone(),
            session_id: session_id_hashed,
            user_agent: user_agent.clone(),
            ip: None,
            detection_method: policy_detection_method.clone(),
            latency_total_ms: total_ms,
            status_code: Some(200),
            error_category: rpc_err_code.is_some().then(|| "rpc_error".to_string()),
            error_detail: rpc_err_msg.clone(),
            limit_bucket: None,
            virtual_server_id,
            upstream_server_id: Some(upstream.id),
            mcp_session_id: inbound_session_id.clone().or_else(|| response_session_id_for_task.clone()),
            method: method.clone(),
            // Pump runs only for ToolCall and PromptGet (debug_assert at the
            // entry of `handle_method_streaming`). Match exhaustively so a
            // future third scope is a compile-time error rather than a silent
            // mis-stamp.
            tool_id: match scope {
                McpScope::ToolCall => resolved_name.clone(),
                McpScope::PromptGet => None,
                _ => unreachable!("pump scope must be ToolCall or PromptGet"),
            },
            prompt_id: match scope {
                McpScope::ToolCall => None,
                McpScope::PromptGet => resolved_name.clone(),
                _ => unreachable!("pump scope must be ToolCall or PromptGet"),
            },
            resource_uri: None,
            params: cap_audit_payload(request_params_for_audit.clone()),
            // Streaming `tools/call` / `prompts/get` responses are SSE
            // sequences — there's no single JSON-RPC `result` to capture.
            // The session-view bubble renders the upstream's full SSE
            // multiplex via `transform_diff.mcp_stream` instead.
            result: None,
            error_code: rpc_err_code,
            error_message: rpc_err_msg.clone(),
            upstream_latency_ms: upstream_ms,
            request_bytes: Some(request_bytes),
            response_bytes: Some(response_bytes_out),
            protocol_version: pump_protocol_version,
            badges: build_mcp_audit_badges(policy_classification.as_ref(), rpc_err_code),
            transform_diff,
        };
        if let Err(e) = state_for_task.mcp.mcp_audit_tx.send(record).await {
            tracing::error!("mcp audit channel send failed (stream): {e}");
        }
        let _ = slug_for_task;
    });

    // Build the streaming response body — bounded receiver wrapped to a
    // futures Stream so axum can forward backpressure to the upstream pump.
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = Body::from_stream(stream);
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache");
    let builder = stamp_session_id(
        builder,
        response_session_id_for_header.as_ref(),
        downstream_is_modern,
    );
    builder.body(body).unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Emit one `mcp_audit` row at info level for a server-initiated
/// MCP request the proxy forwarded mid-stream. The row uses the upstream's
/// method name (`sampling/createMessage` / `elicitation/create`) so the
/// admin UI surfaces it alongside the original `tools/call` invocation.
#[allow(clippy::too_many_arguments)]
async fn emit_server_initiated_audit(
    state: &McpRouterState,
    identity: &Identity,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    method: &str,
    rpc_id: &serde_json::Value,
    mcp_session_id: Option<String>,
    request_id_virtualized: bool,
) {
    let pv = mcp_session_id
        .as_deref()
        .and_then(|sid| state.mcp.session_map.protocol_version(identity.tenant_id, sid))
        .or_else(|| identity.declared_protocol_version.clone());
    emit_server_initiated_audit_to(
        &state.mcp.mcp_audit_tx,
        identity.tenant_id,
        identity.user.workspace_id,
        identity.user_id,
        identity.key_id,
        virtual_server_id,
        upstream_id,
        method,
        rpc_id,
        mcp_session_id,
        pv,
        request_id_virtualized,
    )
    .await;
}

/// Channel-direct variant: emit a server-initiated audit row without an
/// `&Identity`/`&McpRouterState` handle. Used by the legacy-SSE drain
/// task (`legacy_sse::UpstreamEventSink` impl), which has the IDs and the
/// audit channel directly but never sees the per-request identity.
///
/// Backpressure: callers can pass `try_only=true` to `try_send` instead of
/// awaiting the channel. The bus event sink uses this so a stuck audit
/// consumer doesn't pile up tokio tasks against the bounded mpsc.
#[allow(clippy::too_many_arguments)]
async fn emit_server_initiated_audit_to(
    audit_tx: &streamscope_core::audit::AuditSender<McpAuditRecord>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    key_id: Option<Uuid>,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    method: &str,
    rpc_id: &serde_json::Value,
    mcp_session_id: Option<String>,
    protocol_version: Option<String>,
    request_id_virtualized: bool,
) {
    let now = chrono::Utc::now();
    let session_id_hashed = mcp_session_id.as_ref().map(|raw| {
        // user_id (not key_id) — see `session_id_from_client` doc.
        streamscope_core::proxy::content::session_id_from_client(raw, tenant_id, user_id)
    });
    let mut diff = serde_json::Map::new();
    diff.insert(
        "mcp_server_initiated".into(),
        serde_json::json!({
            "rpc_id": rpc_id,
            "method": method,
        }),
    );
    if request_id_virtualized {
        // Surfaced as a chip in the session-detail UI so operators can see
        // which rows used the cross-instance reverse-path token. Pairs with
        // the `mcp_virtualization.resource_uri` marker from the URI path.
        diff.insert(
            "mcp_virtualization".into(),
            serde_json::json!({ "request_id": "encoded" }),
        );
    }
    let record = McpAuditRecord {
        request_id: streamscope_core::ids::mint_request_id(),
        timestamp: now,
        tenant_id,
        workspace_id,
        user_id,
        key_id,
        app_id: None,
        session_id: session_id_hashed,
        user_agent: None,
        ip: None,
        detection_method: None,
        latency_total_ms: 0,
        status_code: Some(200),
        error_category: None,
        error_detail: None,
        limit_bucket: None,
        virtual_server_id,
        upstream_server_id: Some(upstream_id),
        mcp_session_id,
        method: method.to_string(),
        tool_id: None,
        prompt_id: None,
        resource_uri: None,
        params: None,
        result: None,
        error_code: None,
        error_message: None,
        upstream_latency_ms: 0,
        request_bytes: None,
        response_bytes: None,
        protocol_version,
        badges: Vec::new(),
        transform_diff: serde_json::Value::Object(diff),
    };
    if let Err(e) = audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed (server-initiated): {e}");
    }
}

/// Forks the SSE pump's sampling/createMessage handling: when the originating
/// virtual server has [`SamplingInterceptConfig`] populated, the gateway
/// answers the upstream itself via [`super::sampling::try_intercept`] (HTTP
/// loopback into `/v1/messages`) and skips the agent fan-out entirely.
///
/// Returns `Some(())` when the intercept was attempted (success OR explicit
/// failure — both write a JSON-RPC response back to the upstream and emit an
/// `mcp_audit` row). Returns `None` when no intercept is configured for this
/// VS, the event is not a `sampling/createMessage`, or the proxy can't load
/// the per-tenant config — caller falls through to the legacy forward path.
async fn maybe_intercept_sampling(
    ev: &streamscope_core::api::sse::SseEvent,
    state: &McpRouterState,
    identity: &Identity,
    virtual_server_id: Uuid,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    session_for_audit: Option<&str>,
    upstream_auth: &UpstreamAuth,
) -> Option<()> {
    // Whether the virtual server intercepts sampling, read from the config the
    // request authenticated against — the one `upstream` came from.
    let vs = identity.config.mcp.virtual_servers.get(&virtual_server_id)?;
    let intercept = vs.sampling_intercept.as_ref()?;

    // Cheap early exit: only fork on `sampling/createMessage`. Parse the
    // event payload once; classify_value is cheap (single field lookup).
    let parsed: serde_json::Value = serde_json::from_str(&ev.data).ok()?;
    if !matches!(
        super::multiplex::classify_value(&parsed),
        super::multiplex::EventKind::Sampling { .. }
    ) {
        return None;
    }
    let original_rpc_id = parsed
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Run the loopback. The outcome carries (a) the JSON-RPC payload to POST
    // back to the upstream, (b) the audit signal, and (c) the rpc error code
    // (None on success).
    let outcome =
        super::sampling::try_intercept(state, intercept, &ev.data, &original_rpc_id, session_for_audit)
            .await;

    // POST the synthesized JSON-RPC response back to the upstream. This
    // mirrors what `handle_client_response` does on the agent's behalf —
    // upstream sees a normal answer, never knows the agent didn't produce it.
    // Without an upstream session id we have no reverse-path target; emit an
    // audit row but skip the POST (best-effort).
    if let Some(sid) = session_for_audit {
        let post_result = super::upstream::forward_client_response(
            &upstream.upstream_url,
            upstream_auth,
            &outcome.upstream_payload,
            sid,
            // Generous timeout: the upstream just needs to ack 202.
            15_000,
        )
        .await;
        if let Err(e) = post_result {
            tracing::warn!(
                upstream_id = %upstream.id,
                error = %e,
                "mcp sampling intercept: forward-to-upstream failed"
            );
        }
    } else {
        tracing::warn!(
            upstream_id = %upstream.id,
            "mcp sampling intercept: no upstream session id; cannot POST response"
        );
    }

    emit_sampling_intercept_audit(
        state,
        identity,
        virtual_server_id,
        upstream.id,
        session_for_audit.map(str::to_string),
        &outcome,
    )
    .await;

    Some(())
}

/// Emit the typed audit row for an attempted sampling intercept — paired
/// with the LLM audit row produced by the loopback request itself. Cross-
/// link is via the shared `gateway_audit.session_id` (both rows hash from
/// the same upstream `Mcp-Session-Id`).
async fn emit_sampling_intercept_audit(
    state: &McpRouterState,
    identity: &Identity,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    mcp_session_id: Option<String>,
    outcome: &super::sampling::InterceptOutcome,
) {
    use streamscope_core::audit::badge::AuditBadge;

    let now = chrono::Utc::now();
    let session_id_hashed = mcp_session_id.as_ref().map(|raw| {
        streamscope_core::proxy::content::session_id_from_client(
            raw,
            identity.tenant_id,
            identity.user_id,
        )
    });
    let pv = mcp_session_id
        .as_deref()
        .and_then(|sid| state.mcp.session_map.protocol_version(identity.tenant_id, sid))
        .or_else(|| identity.declared_protocol_version.clone());

    let mut diff = serde_json::Map::new();
    diff.insert(
        "sampling_intercept".into(),
        outcome.audit_outcome.to_diff_value(),
    );
    let record = McpAuditRecord {
        request_id: streamscope_core::ids::mint_request_id(),
        timestamp: now,
        tenant_id: identity.tenant_id,
        workspace_id: identity.user.workspace_id,
        user_id: identity.user_id,
        key_id: identity.key_id,
        app_id: None,
        session_id: session_id_hashed,
        user_agent: None,
        ip: None,
        detection_method: None,
        latency_total_ms: match &outcome.audit_outcome {
            streamscope_core::audit::mcp::SamplingInterceptOutcome::Served {
                latency_ms, ..
            } => *latency_ms,
            _ => 0,
        },
        status_code: Some(if outcome.rpc_error_code.is_some() { 502 } else { 200 }),
        error_category: outcome.rpc_error_code.is_some().then(|| "intercept_failed".to_string()),
        error_detail: match &outcome.audit_outcome {
            streamscope_core::audit::mcp::SamplingInterceptOutcome::Failed { reason } => {
                Some(reason.clone())
            }
            _ => None,
        },
        limit_bucket: None,
        virtual_server_id,
        upstream_server_id: Some(upstream_id),
        mcp_session_id,
        method: "sampling/createMessage".to_string(),
        tool_id: None,
        prompt_id: None,
        resource_uri: None,
        params: None,
        result: None,
        error_code: outcome.rpc_error_code,
        error_message: match &outcome.audit_outcome {
            streamscope_core::audit::mcp::SamplingInterceptOutcome::Failed { reason } => {
                Some(reason.clone())
            }
            _ => None,
        },
        upstream_latency_ms: 0,
        request_bytes: None,
        response_bytes: None,
        protocol_version: pv,
        badges: vec![AuditBadge::McpSamplingIntercepted],
        transform_diff: serde_json::Value::Object(diff),
    };
    if let Err(e) = state.mcp.mcp_audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed (sampling intercept): {e}");
    }
}

/// Emit one `mcp_audit` row at info level for a `notifications/.../list_changed`
/// upstream notification. These are catalog-drift signals: the upstream is
/// telling the agent to re-fetch its tool / resource / prompt list. We surface
/// them in the admin UI so operators see drift; we do NOT auto-invalidate the
/// proxy capability cache here (that's keyed on `cred_version`, which does
/// not change in this case — operators explicitly refresh by bumping
/// credentials or restarting the upstream connection).
async fn emit_list_changed_audit(
    state: &McpRouterState,
    identity: &Identity,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    which: super::multiplex::ListChangedKind,
    mcp_session_id: Option<String>,
) {
    let pv = mcp_session_id
        .as_deref()
        .and_then(|sid| state.mcp.session_map.protocol_version(identity.tenant_id, sid))
        .or_else(|| identity.declared_protocol_version.clone());
    emit_list_changed_audit_to(
        &state.mcp.mcp_audit_tx,
        identity.tenant_id,
        identity.user.workspace_id,
        identity.user_id,
        identity.key_id,
        virtual_server_id,
        upstream_id,
        which,
        mcp_session_id,
        pv,
    )
    .await;
}

/// Channel-direct variant of [`emit_list_changed_audit`]; same factoring as
/// [`emit_server_initiated_audit_to`].
#[allow(clippy::too_many_arguments)]
async fn emit_list_changed_audit_to(
    audit_tx: &streamscope_core::audit::AuditSender<McpAuditRecord>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    key_id: Option<Uuid>,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    which: super::multiplex::ListChangedKind,
    mcp_session_id: Option<String>,
    protocol_version: Option<String>,
) {
    let now = chrono::Utc::now();
    let session_id_hashed = mcp_session_id.as_ref().map(|raw| {
        // user_id (not key_id) — see `session_id_from_client` doc.
        streamscope_core::proxy::content::session_id_from_client(raw, tenant_id, user_id)
    });
    let mut diff = serde_json::Map::new();
    diff.insert(
        "mcp_list_changed".into(),
        serde_json::json!({
            "kind": match which {
                super::multiplex::ListChangedKind::Tools => "tools",
                super::multiplex::ListChangedKind::Resources => "resources",
                super::multiplex::ListChangedKind::Prompts => "prompts",
            },
        }),
    );
    let record = McpAuditRecord {
        request_id: streamscope_core::ids::mint_request_id(),
        timestamp: now,
        tenant_id,
        workspace_id,
        user_id,
        key_id,
        app_id: None,
        session_id: session_id_hashed,
        user_agent: None,
        ip: None,
        detection_method: None,
        latency_total_ms: 0,
        status_code: Some(200),
        error_category: None,
        error_detail: None,
        limit_bucket: None,
        virtual_server_id,
        upstream_server_id: Some(upstream_id),
        mcp_session_id,
        method: which.method().to_string(),
        tool_id: None,
        prompt_id: None,
        resource_uri: None,
        params: None,
        result: None,
        error_code: None,
        error_message: None,
        upstream_latency_ms: 0,
        request_bytes: None,
        response_bytes: None,
        protocol_version,
        badges: Vec::new(),
        transform_diff: serde_json::Value::Object(diff),
    };
    if let Err(e) = audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed (list_changed): {e}");
    }
}

/// Emit one `mcp_audit` row at info level for a `notifications/elicitation/complete`
/// event the upstream forwarded. Mirrors [`emit_list_changed_audit`]; the
/// `elicitation_id` from the params correlates with the original
/// `elicitation/create` request the URL-mode flow started (per MCP 2025-11-25
/// § Elicitation).
async fn emit_elicitation_complete_audit(
    state: &McpRouterState,
    identity: &Identity,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    elicitation_id: Option<&str>,
    mcp_session_id: Option<String>,
) {
    let pv = mcp_session_id
        .as_deref()
        .and_then(|sid| state.mcp.session_map.protocol_version(identity.tenant_id, sid))
        .or_else(|| identity.declared_protocol_version.clone());
    emit_elicitation_complete_audit_to(
        &state.mcp.mcp_audit_tx,
        identity.tenant_id,
        identity.user.workspace_id,
        identity.user_id,
        identity.key_id,
        virtual_server_id,
        upstream_id,
        elicitation_id,
        mcp_session_id,
        pv,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn emit_elicitation_complete_audit_to(
    audit_tx: &streamscope_core::audit::AuditSender<McpAuditRecord>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    key_id: Option<Uuid>,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    elicitation_id: Option<&str>,
    mcp_session_id: Option<String>,
    protocol_version: Option<String>,
) {
    let now = chrono::Utc::now();
    let session_id_hashed = mcp_session_id.as_ref().map(|raw| {
        streamscope_core::proxy::content::session_id_from_client(raw, tenant_id, user_id)
    });
    let mut diff = serde_json::Map::new();
    diff.insert(
        "mcp_elicitation_complete".into(),
        serde_json::json!({
            "elicitation_id": elicitation_id,
        }),
    );
    let record = McpAuditRecord {
        request_id: streamscope_core::ids::mint_request_id(),
        timestamp: now,
        tenant_id,
        workspace_id,
        user_id,
        key_id,
        app_id: None,
        session_id: session_id_hashed,
        user_agent: None,
        ip: None,
        detection_method: None,
        latency_total_ms: 0,
        status_code: Some(200),
        error_category: None,
        error_detail: None,
        limit_bucket: None,
        virtual_server_id,
        upstream_server_id: Some(upstream_id),
        mcp_session_id,
        method: "notifications/elicitation/complete".to_string(),
        tool_id: None,
        prompt_id: None,
        resource_uri: None,
        params: None,
        result: None,
        error_code: None,
        error_message: None,
        upstream_latency_ms: 0,
        request_bytes: None,
        response_bytes: None,
        protocol_version,
        badges: Vec::new(),
        transform_diff: serde_json::Value::Object(diff),
    };
    if let Err(e) = audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed (elicitation_complete): {e}");
    }
}

/// Reverse path: the agent posted a JSON-RPC **response** body
/// (id + result/error, no method) as its reply to a server-initiated
/// `sampling/createMessage` / `elicitation/create`. The response carries an
/// `ssrid.…` token (minted by the SSE relay path) as its id; decoding the
/// token recovers `(upstream_id, upstream_session_id, original_id)` from
/// the token alone — any proxy replica forwards correctly with no
/// `session_map` consulted. Closes the cross-instance reverse-path bug.
///
/// Routing + safety:
/// - `Mcp-Session-Id` is required per MCP spec § Session Management.
///   Routing no longer depends on it (the token has the upstream session id),
///   but missing-header still rejects with `-32600`.
/// - The token's HMAC + TTL is verified on decode. Tampered, expired, or
///   non-virtualized ids reject with `-32401` — there is **no fallback** to
///   the per-process session map (the previous fallback path was the bug).
/// - The decoded `(tenant_id, user_id)` MUST equal the inbound identity.
///   This blocks the cross-user replay where one tenant member captures
///   another's `ssrid.…` token (e.g. via shared logs) and posts it as their
///   own response. Generic 401 on mismatch.
/// - The decoded upstream MUST belong to a route on the identity-bound
///   `virtual_server_id`. Defense-in-depth — the identity check above is
///   strictly stronger, but the VS check stays trip-wired for future
///   Identity-minting changes.
/// - The upstream's headers are **always re-resolved** from its current
///   state (declared inputs, per-user-OAuth lookup) so per-user-OAuth tokens
///   that rotated since the original `tools/call` are refreshed.
#[allow(clippy::too_many_arguments)]
async fn handle_client_response(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    slug: &str,
    mut response: JsonRpcResponse,
    auth: &AuthCtx,
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
) -> Response<Body> {
    if mcp_session_id.is_none() {
        let resp = error_response(
            StatusCode::BAD_REQUEST,
            response.id.clone(),
            INVALID_REQUEST,
            "JSON-RPC response requires Mcp-Session-Id header",
        );
        emit_audit(
            state,
            identity,
            request_id,
            slug,
            None,
            None,
            "client_response".to_string(),
            None,
            None,
            None,
            Some(INVALID_REQUEST),
            Some("missing Mcp-Session-Id".into()),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent,
            None,
            StatusCode::BAD_REQUEST,
            None,
        )
        .await;
        return resp;
    }

    // Decode the virtualized request id. Tampered / expired / non-virtualized
    // ids reject with -32401; there is no fallback to `session_map.lookup`
    // (the prior fallback was the cross-instance bug this scheme replaces).
    let id_token = match &response.id {
        RpcId::String(s) => s.as_str(),
        _ => "",
    };
    let decoded = match streamscope_core::mcp::tokens::decode_request_id(
        id_token,
        crate::settings::proxy_settings().mcp_token_ttl_secs,
    ) {
        Ok(d) => d,
        Err(_) => {
            let resp = error_response(
                StatusCode::UNAUTHORIZED,
                response.id.clone(),
                AUTH_REQUIRED,
                "JSON-RPC response id is not a valid request token",
            );
            emit_audit(
                state,
                identity,
                request_id,
                slug,
                None,
                None,
                "client_response".to_string(),
                None,
                None,
                None,
                Some(AUTH_REQUIRED),
                Some("invalid request id token".into()),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent,
                mcp_session_id.clone(),
                StatusCode::UNAUTHORIZED,
                None,
            )
            .await;
            return resp;
        }
    };

    // Identity binding: the token MUST have been minted by the same identity
    // replaying it. Without this check a tenant member could capture another
    // member's `ssrid.…` from a shared log and drive their reverse-path. The
    // VS-membership check below is defense-in-depth — identity equality is
    // strictly stronger (one identity binds to one VS at auth time).
    if decoded.tenant_id != identity.tenant_id || decoded.user_id != identity.user_id {
        let resp = error_response(
            StatusCode::UNAUTHORIZED,
            response.id.clone(),
            AUTH_REQUIRED,
            "request id token was minted for a different identity",
        );
        emit_audit(
            state,
            identity,
            request_id,
            slug,
            Some(identity.virtual_server_id),
            Some(decoded.upstream_id),
            "client_response".to_string(),
            None,
            None,
            None,
            Some(AUTH_REQUIRED),
            Some("ssrid identity mismatch".into()),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent,
            mcp_session_id.clone(),
            StatusCode::UNAUTHORIZED,
            None,
        )
        .await;
        return resp;
    }

    // Defense-in-depth: the decoded upstream MUST be reachable from a route
    // on the identity's bound VS. Redundant with the identity check above
    // (an identity from VS X can't decode-and-replay a token bound to VS Y
    // because the identity tuple would have to match), but cheap and keeps
    // the surface trip-wired against future Identity-minting changes.
    let routes_for_vs = auth
        .mcp_config
        .routes_by_virtual_server
        .get(&identity.virtual_server_id)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    if !routes_for_vs
        .iter()
        .any(|r| r.upstream_server_id == decoded.upstream_id)
    {
        let resp = error_response(
            StatusCode::UNAUTHORIZED,
            response.id.clone(),
            AUTH_REQUIRED,
            "session does not belong to this virtual server",
        );
        emit_audit(
            state,
            identity,
            request_id,
            slug,
            Some(identity.virtual_server_id),
            Some(decoded.upstream_id),
            "client_response".to_string(),
            None,
            None,
            None,
            Some(AUTH_REQUIRED),
            Some("session VS mismatch".into()),
            started,
            Instant::now(),
            request_bytes,
            0,
            user_agent,
            mcp_session_id.clone(),
            StatusCode::UNAUTHORIZED,
            None,
        )
        .await;
        return resp;
    }

    let upstream = match upstreams.iter().find(|u| u.id == decoded.upstream_id) {
        Some(u) => u,
        None => {
            // Config drift: the upstream this token bound to is gone.
            let resp = error_response(
                StatusCode::NOT_FOUND,
                response.id.clone(),
                ROUTE_NOT_FOUND,
                "upstream for this request id no longer exists",
            );
            emit_audit(
                state,
                identity,
                request_id,
                slug,
                Some(identity.virtual_server_id),
                Some(decoded.upstream_id),
                "client_response".to_string(),
                None,
                None,
                None,
                Some(ROUTE_NOT_FOUND),
                Some("upstream gone".into()),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent,
                mcp_session_id.clone(),
                StatusCode::NOT_FOUND,
                None,
            )
            .await;
            return resp;
        }
    };

    // Restore the upstream's original JSON-RPC id so the upstream sees the id
    // it minted, not our virtualized token.
    response.id = rpc_id_from_value(decoded.original_id.clone());

    // Re-resolve the upstream's headers freshly from its current state so
    // per-user-OAuth tokens that rotated since the original `tools/call` are
    // refreshed, and a changed admin or user input takes effect immediately.
    // A caller who can no longer reach the upstream gets that error rather
    // than a reply posted without its credentials.
    let body_value = serde_json::to_value(&response).unwrap_or_else(|_| serde_json::json!({}));
    let dispatch_started = Instant::now();
    let result = match resolve_upstream_auth(auth, upstream).await {
        Ok(upstream_auth) => {
            upstream::forward_client_response(
                &upstream.upstream_url,
                &upstream_auth,
                &body_value,
                // Use the upstream's session id from the decoded token, not the
                // agent-supplied header — they should match, but the token is the
                // authoritative source.
                decoded.upstream_session_id.as_str(),
                // Use a generous default timeout — the upstream just needs to ack 202.
                15_000,
            )
            .await
        }
        Err(e) => Err(e),
    };
    let dispatch_finished = Instant::now();

    let (status, error_code, error_message) = match result {
        Ok(_status) => (StatusCode::ACCEPTED, None, None),
        Err(e) => {
            let (code, msg) = upstream_error_to_jsonrpc(&e, auth.sign_ins_url.as_deref());
            (StatusCode::OK, Some(code), Some(msg))
        }
    };

    // Build the actual HTTP response — the spec says a client response posts
    // gets a `202 Accepted` with no body when delivery succeeded.
    let resp = if status == StatusCode::ACCEPTED {
        Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Content-Type", "application/json")
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()))
    } else {
        error_response(
            status,
            response.id.clone(),
            error_code.unwrap_or(INTERNAL_ERROR),
            error_message.clone().unwrap_or_else(|| "forward failed".into()),
        )
    };

    emit_audit(
        state,
        identity,
        request_id,
        slug,
        Some(identity.virtual_server_id),
        Some(decoded.upstream_id),
        format!("client_response:{}", rpc_id_to_str(&response.id)),
        None,
        None,
        None,
        error_code,
        error_message,
        started,
        dispatch_started.max(dispatch_finished),
        request_bytes,
        0,
        user_agent,
        mcp_session_id,
        status,
        None,
    )
    .await;

    resp
}

fn rpc_id_from_value(v: serde_json::Value) -> RpcId {
    match v {
        // Pass `Number` through verbatim — `serde_json::Number` covers the
        // full JSON numeric domain (i64, u64, f64), so out-of-i64 ids round-
        // trip byte-identically. JSON-RPC spec § 4 requires the response id
        // to equal the request id; collapsing to Null here would silently
        // drop responses whose upstream-minted id exceeds i64::MAX.
        serde_json::Value::Number(n) => RpcId::Number(n),
        serde_json::Value::String(s) => RpcId::String(s),
        _ => RpcId::Null,
    }
}

fn rpc_id_to_str(id: &RpcId) -> String {
    match id {
        RpcId::Number(n) => n.to_string(),
        RpcId::String(s) => s.clone(),
        RpcId::Null => "null".to_string(),
    }
}

/// Figure out the authoritative `mcp_server` to feed into rule
/// evaluation. The handler stamps the route's upstream `name` (NEVER the
/// wire prefix the agent supplied) so an agent can't impersonate another
/// upstream by spoofing `gh__do_dangerous_thing`.
///
/// For `tools/call` and `prompts/get`: strip the namespace prefix off the
/// wire `name` and look up the matching route's upstream.
///
/// For `resources/read`: decode the route prefix out of the gateway's
/// virtualized `stsmcp://<prefix>/<b64>` URI to find the owning upstream.
/// Falls back to the first route on a non-stsmcp URI (legacy / probe call) so
/// rules that don't gate on `mcp_server` still fire — the dispatcher's strict
/// decode then rejects the call before any upstream contact.
fn resolve_policy_mcp_server(
    req: &JsonRpcRequest,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
) -> Option<String> {
    let scope = classify_method(&req.method);
    let lookup_upstream_name = |upstream_id: Uuid| -> Option<String> {
        upstreams
            .iter()
            .find(|u| u.id == upstream_id)
            .map(|u| u.name.clone())
    };
    match scope {
        McpScope::ToolCall | McpScope::PromptGet => {
            let name = req
                .params
                .as_ref()?
                .get("name")
                .and_then(|v| v.as_str())?;
            let (route, _local) = virtualize::route_for_name(routes, name)?;
            lookup_upstream_name(route.upstream_server_id)
        }
        McpScope::ResourceRead | McpScope::ResourceSubscribe | McpScope::ResourceUnsubscribe => {
            // Non-`stsmcp://` URIs (or unknown prefixes) fall back to the
            // first enabled route as a best-effort anchor. This is
            // load-bearing: the caller (`mcp_handler`) skips policy
            // evaluation entirely when this returns `None`, so probe
            // traffic / legacy clients / tests with raw `file://` URIs
            // would silently bypass `Scope::ResourceReads` block rules
            // without the fallback. The dispatch arm still rejects
            // undecodable URIs with `-32001` after policy fires, so the
            // worst-case audit attribution is "this URI-rule-blocked call
            // would have hit the first route" — strictly better than no
            // policy attribution.
            let uri = req
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str());
            let prefix_from_uri = uri.and_then(|u| {
                streamscope_core::mcp::tokens::decode_resource_uri(u)
                    .ok()
                    .map(|(prefix, _)| prefix)
            });
            let route = match prefix_from_uri.as_deref() {
                Some(prefix) => virtualize::route_for_prefix(routes, Some(prefix)),
                None => routes.first(),
            };
            route.and_then(|r| lookup_upstream_name(r.upstream_server_id))
        }
        McpScope::CompletionComplete => {
            // Same routing logic as the dispatch arm — recover the route
            // prefix from the ref so policy rules pivot on the right
            // `mcp_server`. ref/prompt: resolve the stamped name.
            // ref/resource: decode `stsmcp://<prefix>/<b64>`.
            let ref_obj = req
                .params
                .as_ref()
                .and_then(|p| p.get("ref"))
                .and_then(|v| v.as_object())?;
            let ref_type = ref_obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let route = match ref_type {
                "ref/prompt" => {
                    let name = ref_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    virtualize::route_for_name(routes, name).map(|(route, _local)| route)
                }
                "ref/resource" => {
                    let prefix = ref_obj
                        .get("uri")
                        .and_then(|v| v.as_str())
                        .and_then(|u| {
                            streamscope_core::mcp::tokens::decode_resource_uri(u)
                                .ok()
                                .map(|(p, _)| p)
                        });
                    virtualize::route_for_prefix(routes, prefix.as_deref())
                }
                _ => virtualize::route_for_prefix(routes, None),
            }?;
            lookup_upstream_name(route.upstream_server_id)
        }
        _ => None,
    }
}

fn resolved_tool_id(req: &JsonRpcRequest) -> Option<String> {
    req.params
        .as_ref()?
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn resolved_prompt_id(req: &JsonRpcRequest) -> Option<String> {
    req.params
        .as_ref()?
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn resolved_resource_uri(req: &JsonRpcRequest) -> Option<String> {
    req.params
        .as_ref()?
        .get("uri")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// For `completion/complete`, return the per-ref-type audit-key value: the
/// `ref.uri` for a `ref/resource` (lifted into `resource_uri`) or the
/// `ref.name` for a `ref/prompt` (lifted into `prompt_id`). Returns `None`
/// when the ref is malformed — the dispatch arm rejects malformed completion
/// refs with `-32600` so the audit row will at least surface the error.
fn resolved_completion_target(req: &JsonRpcRequest) -> (Option<String>, Option<String>) {
    let Some(ref_obj) = req
        .params
        .as_ref()
        .and_then(|p| p.get("ref"))
        .and_then(|v| v.as_object())
    else {
        return (None, None);
    };
    let ref_type = ref_obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match ref_type {
        "ref/resource" => {
            let uri = ref_obj
                .get("uri")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            (None, uri)
        }
        "ref/prompt" => {
            let name = ref_obj
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            (name, None)
        }
        _ => (None, None),
    }
}

/// Returns `(response_value, mcp_session_id, upstream_server_id_used, error_tuple)`.
/// `error_tuple` is `Some((code, message))` if the JSON-RPC response carried
/// an `error` field — surfaces in the audit row.
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    cache: &Arc<super::cache::CapabilityCache>,
    auth: &AuthCtx,
    virtual_server: &McpVirtualServer,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    request: &JsonRpcRequest,
    mcp_session_id: Option<&str>,
) -> Result<
    (JsonRpcResponse, Option<String>, Option<Uuid>, Option<(i32, String)>),
    UpstreamError,
> {
    let scope = classify_method(&request.method);
    let request_id = request.id.clone().unwrap_or(RpcId::Null);

    // An aggregated list hides an upstream the caller lacks inputs for — but
    // when that leaves nothing callable, hiding a missing client header would
    // answer an empty catalog to a misconfigured client, so the first missing
    // client header is named instead (a missing user input keeps hiding: the
    // portal shows the user what to connect).
    if matches!(
        scope,
        McpScope::ToolList | McpScope::PromptList | McpScope::ResourceList | McpScope::ResourceTemplatesList
    ) && !some_route_is_callable(auth, routes, upstreams)
    {
        for route in routes {
            if let Some(upstream) = upstreams.iter().find(|u| u.id == route.upstream_server_id)
                && let Err(e @ UpstreamError::ClientHeaderMissing(_)) = auth.inputs_memo.resolve_quiet(
                    upstream,
                    auth.mcp_config.user_inputs(auth.user_id, upstream.id),
                    &auth.client_inputs,
                )
            {
                return Err(e);
            }
        }
    }

    match scope {
        McpScope::Initialize => {
            // Forward to the first route; merge `capabilities` from every
            // upstream that responds successfully.
            let mut per_caps: Vec<serde_json::Value> = Vec::new();
            let mut response_session_id: Option<String> = None;
            let mut first_response_value: Option<serde_json::Value> = None;
            let mut authoritative_upstream: Option<Uuid> = None;
            // (upstream_id, upstream_session_id) — used to populate the
            // per-upstream session map after the loop, keyed by the agent-
            // facing downstream session-id (= the first upstream's sid).
            let mut per_upstream_sids: Vec<(Uuid, String)> = Vec::new();
            let mut per_instructions: Vec<String> = Vec::new();

            // Every route is initialized, the first as the leader, and each one
            // that answers gets its own upstream session id mapped to the
            // downstream one. A leader the caller cannot call yet fails the
            // initialize, naming what is missing; a secondary route it cannot
            // call yet is left without a session of its own until the client
            // initializes again.
            for (idx, route) in routes.iter().enumerate() {
                let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                    Some(u) => u,
                    None => continue,
                };
                let is_leader = idx == 0;
                match call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await {
                    Ok((resp, sid)) => {
                        if let Some(s) = sid.as_deref()
                            && !s.is_empty()
                        {
                            per_upstream_sids.push((upstream.id, s.to_string()));
                        }
                        if let Some(result) = &resp.result {
                            if let Some(caps) = result.get("capabilities") {
                                per_caps.push(caps.clone());
                            }
                            // `instructions` is per-upstream LLM guidance, so
                            // a multi-route virtual server must aggregate it:
                            // relaying only the first route's would silently
                            // drop every sibling's, and the tool names the
                            // guidance refers to all carry that route's
                            // namespace prefix — hence the prefix label.
                            if let Some(text) = result
                                .get("instructions")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                per_instructions.push(if route.prefix.is_empty() {
                                    text.to_string()
                                } else {
                                    format!("[{}] {text}", route.prefix)
                                });
                            }
                            if first_response_value.is_none() {
                                first_response_value = Some(result.clone());
                                authoritative_upstream = Some(upstream.id);
                                response_session_id = sid;
                            }
                        }
                    }
                    Err(e) => {
                        // The leader's failure is fatal — initialize is
                        // routed to the leader so the agent gets a stable
                        // protocolVersion. If a secondary upstream errors,
                        // continue and just skip its capabilities.
                        if is_leader {
                            return Err(e);
                        }
                        tracing::warn!(error = %e, route = %route.id, "initialize: secondary upstream failed");
                    }
                }
            }

            // Bug 1 fix: populate the per-upstream session-id map keyed by
            // the *downstream* session-id (which equals the first upstream's
            // sid — that's what the proxy stamps on its response to the
            // agent). On subsequent fan-out calls, `call_cached` looks up
            // each upstream's own session-id by this key.
            if let Some(ds_sid) = response_session_id.as_deref() {
                for (upstream_id, sid) in &per_upstream_sids {
                    auth.session_map.set_upstream_session(
                        auth.tenant_id,
                        ds_sid,
                        *upstream_id,
                        sid,
                    );
                }
            }

            let mut result = first_response_value.unwrap_or_else(|| serde_json::json!({}));
            if let Some(obj) = result.as_object_mut() {
                obj.insert(
                    "capabilities".to_string(),
                    virtualize::merge_capabilities(&per_caps),
                );
                // The virtual server's own description leads, then each
                // route's. Both eras assemble this the same way — a legacy
                // client must not be told less about the server it is
                // talking to than a modern one reading `server/discover`.
                let mut instructions = Vec::new();
                if let Some(text) = &virtual_server.description
                    && !text.is_empty()
                {
                    instructions.push(text.clone());
                }
                instructions.extend(per_instructions);
                if instructions.is_empty() {
                    obj.remove("instructions");
                } else {
                    obj.insert(
                        "instructions".to_string(),
                        serde_json::Value::String(instructions.join("\n\n")),
                    );
                }
                // `serverInfo` per MCP 2025-11-25 § Lifecycle §
                // Implementation. `name`/`version`/`description` are the
                // gateway-level identity (a virtual server's `name` is
                // operator-facing; the wire identity stays the gateway's).
                // `title` and `websiteUrl` are optional 2025-11-25 fields
                // sourced from the virtual server itself when set — they
                // give the operator a way to customise the client UI per
                // mount without having to fork the gateway identity.
                let mut server_info = serde_json::json!({
                    "name": "streamscope-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Streamscope AI MCP gateway — fan-out to upstream MCP servers with audit, policy, and unified auth",
                });
                if let Some(info_obj) = server_info.as_object_mut() {
                    if let Some(title) = &virtual_server.display_title {
                        info_obj.insert(
                            "title".to_string(),
                            serde_json::Value::String(title.clone()),
                        );
                    }
                    if let Some(url) = &virtual_server.website_url {
                        info_obj.insert(
                            "websiteUrl".to_string(),
                            serde_json::Value::String(url.clone()),
                        );
                    }
                }
                obj.insert("serverInfo".to_string(), server_info);
            }
            Ok((JsonRpcResponse::ok(request_id, result), response_session_id, authoritative_upstream, None))
        }

        McpScope::ToolList | McpScope::PromptList => {
            // Fan out to all routes; stamp prefix; concatenate.
            let mut combined: Vec<serde_json::Value> = Vec::new();
            let mut response_session_id: Option<String> = None;
            let array_key = if scope == McpScope::ToolList { "tools" } else { "prompts" };

            for route in routes {
                let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                    Some(u) => u,
                    None => continue,
                };
                // Skip per_user_oauth upstreams the user hasn't
                // authorized — their tools/prompts simply don't appear in
                // the merged catalog. The portal surfaces "N upstreams to
                // connect" so the agent doesn't see broken tools.
                if !user_has_credential_for(auth, upstream) {
                    continue;
                }
                let filter = if scope == McpScope::ToolList {
                    route.tools_filter.as_ref()
                } else {
                    route.prompts_filter.as_ref()
                };
                match call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await {
                    Ok((resp, sid)) => {
                        if response_session_id.is_none() {
                            response_session_id = sid;
                        }
                        if let Some(mut result) = resp.result
                            && let Some(arr) = result.get_mut(array_key)
                        {
                            virtualize::stamp_named_array(arr, &route.prefix, filter);
                            virtualize::retain_routable(arr, routes, route);
                            if let Some(items) = arr.as_array() {
                                combined.extend(items.iter().cloned());
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, route = %route.id, "list fan-out: upstream failed");
                    }
                }
            }
            let result = serde_json::json!({ array_key: combined });
            Ok((JsonRpcResponse::ok(request_id, result), response_session_id, None, None))
        }

        McpScope::ResourceList => {
            // Fan out across every authorized route, drop entries denied by
            // the per-route filter, and rewrite every surviving URI as
            // `stsmcp://<route_prefix>/<b64(original_uri)>`. The encoded
            // URI carries the route in its prefix so a later `resources/read`
            // is fully self-routing — no per-session map, no cross-instance
            // sync.
            let mut combined: Vec<serde_json::Value> = Vec::new();
            let mut response_session_id: Option<String> = None;

            for route in routes {
                let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                    Some(u) => u,
                    None => continue,
                };
                if !user_has_credential_for(auth, upstream) {
                    continue;
                }
                match call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await {
                    Ok((resp, sid)) => {
                        if response_session_id.is_none() {
                            response_session_id = sid;
                        }
                        if let Some(mut result) = resp.result
                            && let Some(arr) = result.get_mut("resources")
                        {
                            virtualize::rewrite_resource_uris(
                                arr,
                                &route.prefix,
                                route.resources_filter.as_ref(),
                            );
                            if let Some(items) = arr.as_array() {
                                combined.extend(items.iter().cloned());
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, route = %route.id, "resources/list fan-out failed");
                    }
                }
            }
            Ok((
                JsonRpcResponse::ok(request_id, serde_json::json!({ "resources": combined })),
                response_session_id,
                None,
                None,
            ))
        }

        McpScope::ToolCall | McpScope::PromptGet => {
            // Routed through `handle_method_streaming` upstream of `dispatch()`
            // (see `handle_authenticated_request`'s scope gate). Both scopes
            // need the streaming-aware path so server-initiated events
            // interleaved by the upstream get classified rather than collapsed
            // to last-event.
            unreachable!("ToolCall / PromptGet routed through handle_method_streaming");
        }

        McpScope::ResourceRead => {
            // Decode the virtualized URI to recover (route_prefix, upstream
            // URI). The route prefix self-routes to the owning upstream — no
            // per-session map needed. URIs that don't carry the gateway's
            // `stsmcp://` scheme are rejected: clients must round-trip what
            // we handed them on `resources/list`.
            let read_uri = request
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str());
            let Some(read_uri) = read_uri else {
                return Ok((
                    JsonRpcResponse::err(request_id, INVALID_REQUEST, "missing uri"),
                    None,
                    None,
                    Some((INVALID_REQUEST, "missing uri".into())),
                ));
            };
            let (prefix, original_uri) = match streamscope_core::mcp::tokens::decode_resource_uri(read_uri) {
                Ok(parts) => parts,
                Err(_) => {
                    return Ok((
                        resource_not_found(request_id, read_uri),
                        None,
                        None,
                        Some((ROUTE_NOT_FOUND, "unknown resource uri".into())),
                    ));
                }
            };
            let route = match virtualize::route_for_prefix(routes, Some(&prefix)) {
                Some(r) => r,
                None => {
                    return Ok((
                        resource_not_found(request_id, read_uri),
                        None,
                        None,
                        Some((ROUTE_NOT_FOUND, "no route for resource".into())),
                    ));
                }
            };
            let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                Some(u) => u,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, INTERNAL_ERROR, "route upstream missing"),
                        None,
                        None,
                        Some((INTERNAL_ERROR, "route upstream missing".into())),
                    ));
                }
            };
            // Substitute the decoded upstream URI into the request body before
            // forwarding so the upstream sees its own URI back.
            let mut request = request.clone();
            if let Some(params) = request.params.as_mut()
                && let Some(obj) = params.as_object_mut()
            {
                obj.insert("uri".into(), serde_json::Value::String(original_uri));
            }
            let (mut resp, sid) =
                call_cached(cache, auth, upstream, &request, mcp_session_id, &route.prefix).await?;
            // Rewrite the response's resource URIs so the agent sees the same
            // `stsmcp://<route_prefix>/<b64>` envelope it just sent: agents
            // round-trip URIs and we already enforce the envelope on the
            // request side. Without this the upstream URI leaks back and a
            // follow-up `resources/read` would `-32001` — which is as true of
            // the URI a failed read names under `error.data.uri` as it is of
            // `result.contents[].uri`.
            super::multiplex::rewrite_response_uris(&mut resp, &route.prefix);
            let err_tuple = resp.error.as_ref().map(|e| (e.code, e.message.clone()));
            Ok((resp, sid, Some(upstream.id), err_tuple))
        }

        McpScope::ResourceSubscribe | McpScope::ResourceUnsubscribe => {
            // Mirrors `ResourceRead`: decode the virtualized URI to recover
            // (route_prefix, upstream URI), route to the owning upstream,
            // rewrite to the original URI before forwarding. Subscribe and
            // unsubscribe carry the same `params.uri` shape per MCP spec
            // 2025-11-25 § Resources / Subscriptions.
            //
            // Stays self-routing: any proxy replica decodes the same `stsmcp://`
            // URI from the agent's body without consulting per-session state,
            // so subscriptions survive cross-instance routing the same way
            // resource reads do.
            let sub_uri = request
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str());
            let Some(sub_uri) = sub_uri else {
                return Ok((
                    JsonRpcResponse::err(request_id, INVALID_REQUEST, "missing uri"),
                    None,
                    None,
                    Some((INVALID_REQUEST, "missing uri".into())),
                ));
            };
            let (prefix, original_uri) = match streamscope_core::mcp::tokens::decode_resource_uri(sub_uri) {
                Ok(parts) => parts,
                Err(_) => {
                    return Ok((
                        JsonRpcResponse::err(request_id, ROUTE_NOT_FOUND, "unknown resource uri"),
                        None,
                        None,
                        Some((ROUTE_NOT_FOUND, "unknown resource uri".into())),
                    ));
                }
            };
            let route = match virtualize::route_for_prefix(routes, Some(&prefix)) {
                Some(r) => r,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, ROUTE_NOT_FOUND, "no route for resource"),
                        None,
                        None,
                        Some((ROUTE_NOT_FOUND, "no route for resource".into())),
                    ));
                }
            };
            let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                Some(u) => u,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, INTERNAL_ERROR, "route upstream missing"),
                        None,
                        None,
                        Some((INTERNAL_ERROR, "route upstream missing".into())),
                    ));
                }
            };
            let mut request = request.clone();
            if let Some(params) = request.params.as_mut()
                && let Some(obj) = params.as_object_mut()
            {
                obj.insert("uri".into(), serde_json::Value::String(original_uri));
            }
            let (resp, sid) =
                call_cached(cache, auth, upstream, &request, mcp_session_id, &route.prefix).await?;
            let err_tuple = resp.error.as_ref().map(|e| (e.code, e.message.clone()));
            Ok((resp, sid, Some(upstream.id), err_tuple))
        }

        McpScope::CompletionComplete => {
            // Per MCP spec 2025-11-25 § Server / Utilities / Completion the
            // `params.ref` has two variants:
            //   - `{ "type": "ref/prompt",   "name": "<prefix>__<original>" }`
            //   - `{ "type": "ref/resource", "uri":  "stsmcp://<prefix>/<b64>" }`
            // Route by ref type: prompt-style resolves the stamped name the
            // same way `prompts/get` does; resource-style decodes the `stsmcp://`
            // URI the same way `resources/read` does. Either way we rewrite
            // the ref back to the upstream's original shape before forwarding
            // so the upstream's completer sees its own native names/URIs.
            let ref_obj = request
                .params
                .as_ref()
                .and_then(|p| p.get("ref"))
                .and_then(|v| v.as_object());
            let Some(ref_obj) = ref_obj else {
                return Ok((
                    JsonRpcResponse::err(request_id, INVALID_REQUEST, "missing ref"),
                    None,
                    None,
                    Some((INVALID_REQUEST, "missing ref".into())),
                ));
            };
            let ref_type = ref_obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

            let (route, rewritten_ref): (Option<&streamscope_core::config::mcp::McpVirtualRoute>, serde_json::Value) = match ref_type {
                "ref/prompt" => {
                    let name = ref_obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let resolved = virtualize::route_for_name(routes, name);
                    let local = resolved.map_or(name, |(_, local)| local);
                    let mut new_ref = ref_obj.clone();
                    new_ref.insert("name".into(), serde_json::Value::String(local.to_string()));
                    (resolved.map(|(route, _)| route), serde_json::Value::Object(new_ref))
                }
                "ref/resource" => {
                    let uri = ref_obj.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                    match streamscope_core::mcp::tokens::decode_resource_uri(uri) {
                        Ok((prefix, original_uri)) => {
                            let mut new_ref = ref_obj.clone();
                            new_ref.insert("uri".into(), serde_json::Value::String(original_uri));
                            (
                                virtualize::route_for_prefix(routes, Some(&prefix)),
                                serde_json::Value::Object(new_ref),
                            )
                        }
                        Err(_) => {
                            // A ref naming something that does not resolve is a
                            // bad parameter, not a missing method — but that is
                            // a claim about the MODERN wire only. Carrying the
                            // uri is what lets the era gate renumber it to
                            // `-32602` there while legacy keeps the `-32001` it
                            // has read for three revisions.
                            return Ok((
                                resource_not_found(request_id, uri),
                                None,
                                None,
                                Some((ROUTE_NOT_FOUND, "unknown resource uri in completion ref".into())),
                            ));
                        }
                    }
                }
                other => {
                    return Ok((
                        JsonRpcResponse::err(
                            request_id,
                            INVALID_REQUEST,
                            format!("unsupported completion ref type: {other}"),
                        ),
                        None,
                        None,
                        Some((INVALID_REQUEST, format!("unsupported completion ref type: {other}"))),
                    ));
                }
            };

            let route = match route {
                Some(r) => r,
                None => {
                    // A `ref/resource` names a URI, so it answers exactly as the
                    // unresolvable ref above and as `resources/read` does —
                    // otherwise one unroutable resource ref renumbers to
                    // `-32602` and its neighbour to `-32601` for the same
                    // method. A `ref/prompt` has no URI to name, so it keeps the
                    // bare code: there is nothing for the era gate to recognise,
                    // and inventing a `uri` field to trigger it would put a
                    // value on the wire that names nothing.
                    let resp = match ref_obj.get("uri").and_then(|v| v.as_str()) {
                        Some(uri) if ref_type == "ref/resource" => {
                            resource_not_found(request_id, uri)
                        }
                        _ => JsonRpcResponse::err(
                            request_id,
                            ROUTE_NOT_FOUND,
                            "no route for completion ref",
                        ),
                    };
                    return Ok((
                        resp,
                        None,
                        None,
                        Some((ROUTE_NOT_FOUND, "no route for completion ref".into())),
                    ));
                }
            };
            // Honour the route's `prompts_filter` for `ref/prompt` so an
            // operator-denied prompt can't be probed via completion. Without
            // this, an agent denied `prompts/get` for `ns_beta__hidden_prompt`
            // could still issue `completion/complete` against it and observe
            // argument-completion suggestions — leaks which prompts exist and
            // what their parameters look like. Mirrors `handle_method_streaming`'s
            // tools/prompts filter check.
            //
            // ref/resource doesn't carry a `name` — `resources_filter` is
            // name-based and applies at `resources/list` time only — so URI
            // gating is handled by the tool-risk policy engine (Scope::ResourceReads
            // rules also fire on completion via `policy::evaluate_request`).
            if ref_type == "ref/prompt"
                && let Some(filter) = route.prompts_filter.as_ref()
            {
                let unprefixed_name = rewritten_ref
                    .as_object()
                    .and_then(|o| o.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !filter.permits(unprefixed_name) {
                    let msg = format!("prompt '{unprefixed_name}' is denied by route filter");
                    return Ok((
                        JsonRpcResponse::err(request_id, TOOL_NOT_FOUND, msg.clone()),
                        None,
                        None,
                        Some((TOOL_NOT_FOUND, msg)),
                    ));
                }
            }
            let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                Some(u) => u,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, INTERNAL_ERROR, "route upstream missing"),
                        None,
                        None,
                        Some((INTERNAL_ERROR, "route upstream missing".into())),
                    ));
                }
            };
            let mut request = request.clone();
            if let Some(params) = request.params.as_mut()
                && let Some(obj) = params.as_object_mut()
            {
                obj.insert("ref".into(), rewritten_ref);
            }
            let (resp, sid) =
                call_cached(cache, auth, upstream, &request, mcp_session_id, &route.prefix).await?;
            let err_tuple = resp.error.as_ref().map(|e| (e.code, e.message.clone()));
            Ok((resp, sid, Some(upstream.id), err_tuple))
        }

        McpScope::ResourceTemplatesList => {
            // Aggregate fan-out across every authorized route — mirror of
            // `ResourceList` but rewriting `uriTemplate` under the
            // `stsmcp+<prefix>+<scheme>://` envelope so RFC 6570 placeholder
            // expansion preserves the route prefix client-side. The downstream
            // `resources/read` (which receives the agent's expanded URI) reuses
            // the same `decode_resource_uri` path — no separate read arm.
            let mut combined: Vec<serde_json::Value> = Vec::new();
            let mut response_session_id: Option<String> = None;

            for route in routes {
                let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                    Some(u) => u,
                    None => continue,
                };
                if !user_has_credential_for(auth, upstream) {
                    continue;
                }
                match call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await {
                    Ok((resp, sid)) => {
                        if response_session_id.is_none() {
                            response_session_id = sid;
                        }
                        if let Some(mut result) = resp.result
                            && let Some(arr) = result.get_mut("resourceTemplates")
                        {
                            virtualize::rewrite_resource_template_uris(
                                arr,
                                &route.prefix,
                                route.resources_filter.as_ref(),
                            );
                            if let Some(items) = arr.as_array() {
                                combined.extend(items.iter().cloned());
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, route = %route.id, "resources/templates/list fan-out failed");
                    }
                }
            }
            Ok((
                JsonRpcResponse::ok(
                    request_id,
                    serde_json::json!({ "resourceTemplates": combined }),
                ),
                response_session_id,
                None,
                None,
            ))
        }

        McpScope::LoggingSetLevel => {
            // Fan out to every enabled route. The gateway advertises the
            // `logging` capability through the merge guard, so a `setLevel`
            // call MUST land on every upstream that declared it — falling back
            // to first-route-only would break the advertise/deliver invariant.
            //
            // Aggregation: success if any route accepts; warn-log per-route
            // failures so operators can spot a partially-broken upstream.
            // No body translation — `params.level` is an opaque string per
            // MCP spec 2025-11-25 § Server / Utilities / Logging.
            let mut accepted_any = false;
            let mut response_session_id: Option<String> = None;
            let mut last_err_tuple: Option<(i32, String)> = None;

            for route in routes {
                let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                    Some(u) => u,
                    None => continue,
                };
                if !user_has_credential_for(auth, upstream) {
                    continue;
                }
                match call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await {
                    Ok((resp, sid)) => {
                        if response_session_id.is_none() {
                            response_session_id = sid;
                        }
                        if let Some(err) = resp.error.as_ref() {
                            tracing::warn!(
                                route = %route.id,
                                code = err.code,
                                msg = %err.message,
                                "logging/setLevel: upstream returned error"
                            );
                            last_err_tuple = Some((err.code, err.message.clone()));
                        } else {
                            accepted_any = true;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, route = %route.id, "logging/setLevel: upstream call failed");
                        // Capture transport error so the client gets the
                        // underlying reason if EVERY route failed at the
                        // transport layer (no JSON-RPC error to bubble up).
                        last_err_tuple = Some((UPSTREAM_ERROR, format!("logging/setLevel: upstream call failed: {e}")));
                    }
                }
            }
            if accepted_any {
                // Remember the level for the session. The modern era deleted
                // `logging/setLevel` and put the level on each request's
                // `_meta` instead, so a modern upstream's answer above was the
                // gateway's own — without this the call would be accepted and
                // then quietly change nothing, and the client would wait for
                // log notifications the gateway never asked for.
                if let Some(level) = request
                    .params
                    .as_ref()
                    .and_then(|p| p.get("level"))
                    .and_then(|v| v.as_str())
                {
                    auth.session_map
                        .set_log_level(auth.tenant_id, auth.user_id, level);
                }
                Ok((
                    JsonRpcResponse::ok(request_id, serde_json::json!({})),
                    response_session_id,
                    None,
                    None,
                ))
            } else {
                let (code, msg) = last_err_tuple.unwrap_or((
                    UPSTREAM_ERROR,
                    "logging/setLevel: no upstream accepted".into(),
                ));
                Ok((
                    JsonRpcResponse::err(request_id, code, msg.clone()),
                    response_session_id,
                    None,
                    Some((code, msg)),
                ))
            }
        }

        McpScope::Notification => {
            // Notifications have no id; we forward to the first enabled
            // route and don't return a body. Best-effort.
            let route = match routes.first() {
                Some(r) => r,
                None => {
                    return Ok((
                        JsonRpcResponse::ok(request_id, serde_json::json!({})),
                        None,
                        None,
                        None,
                    ));
                }
            };
            if let Some(upstream) = upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                let _ = call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await;
            }
            Ok((JsonRpcResponse::ok(request_id, serde_json::json!({})), None, None, None))
        }

        McpScope::Other => {
            // Best-effort passthrough to the first route. Logs at warn so an
            // unrecognized method is visible in operator metrics.
            tracing::warn!(method = %request.method, "MCP: forwarding unknown method to first route");
            let route = match routes.first() {
                Some(r) => r,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, METHOD_NOT_FOUND, "no routes"),
                        None,
                        None,
                        Some((METHOD_NOT_FOUND, "no routes".into())),
                    ));
                }
            };
            let upstream = match upstreams.iter().find(|u| u.id == route.upstream_server_id) {
                Some(u) => u,
                None => {
                    return Ok((
                        JsonRpcResponse::err(request_id, INTERNAL_ERROR, "route upstream missing"),
                        None,
                        None,
                        Some((INTERNAL_ERROR, "route upstream missing".into())),
                    ));
                }
            };
            let (resp, sid) =
                call_cached(cache, auth, upstream, request, mcp_session_id, &route.prefix).await?;
            let err_tuple = resp.error.as_ref().map(|e| (e.code, e.message.clone()));
            Ok((resp, sid, Some(upstream.id), err_tuple))
        }
    }
}

/// Build a JSON-RPC error response with a custom HTTP status.
/// [`error_response`], with the code brought into the era's legal range.
///
/// Use this wherever the gateway raises one of its OWN codes on a path a
/// modern client can reach. A bare `error_response` there would put a code
/// from the frozen `-32000..=-32019` band on the wire, which the revision says
/// a receiver MUST NOT assign meaning to — so the client learns nothing at all.
///
/// The renumbering is not a loss: the original rides under
/// `data.streamscopeCode`, so an operator reading the response still sees which
/// gateway condition fired. A code that needs no renumbering is passed through
/// untouched and gains no `data`.
fn era_error_response(
    status: StatusCode,
    id: RpcId,
    code: i32,
    message: impl Into<String>,
    era: &ProtocolEra,
) -> Response<Body> {
    era_render_error(status, JsonRpcResponse::err(id, code, message), era)
}

/// [`era_error_response`], carrying the typed `data` payload a client branches
/// on.
///
/// Kept distinct rather than widening the common form with an `Option`, for
/// the reason [`JsonRpcResponse::err_with_data`] records: `data` is meaningful
/// on a handful of errors, and a `None` at every other call site would read as
/// "this error has no payload" when it means "nobody considered one".
fn era_error_response_with_data(
    status: StatusCode,
    id: RpcId,
    code: i32,
    message: impl Into<String>,
    data: serde_json::Value,
    era: &ProtocolEra,
) -> Response<Body> {
    era_render_error(
        status,
        JsonRpcResponse::err_with_data(id, code, message, data),
        era,
    )
}

/// Render an already-built error response onto the wire the era admits.
///
/// **`status` is what a LEGACY client gets.** For a modern one the status is
/// derived from the renumbered code, exactly as [`finalize_modern_response`]
/// derives it on the success path — the two are the gateway's only egress
/// points for an error and a client cannot tell which one answered it. The
/// caller's status survives only where the map has nothing to say
/// ([`modern::http_status_for_error`] returns `OK` for everything the
/// revision does not mandate), so a deliberate non-200 on a path the map does
/// not name is still honoured.
///
/// This matters beyond tidiness: § Backward Compatibility has a dual-era
/// client read a `400` carrying a recognized modern error as proof the server
/// is modern. Answering `200` there does not merely mis-report the error — it
/// removes the signal the client decides on, so it neither falls back nor
/// reports.
fn era_render_error(
    status: StatusCode,
    mut body: JsonRpcResponse,
    era: &ProtocolEra,
) -> Response<Body> {
    let mut status = status;
    if let Some(err) = body.error.as_mut() {
        if era.is_modern() {
            // Renumber first, then choose the status from the renumbered code:
            // the status must agree with the code the client actually reads.
            modern::modernize_error(err);
            let mandated = modern::http_status_for_error(err.code);
            if mandated != StatusCode::OK {
                status = mandated;
            }
        } else {
            // The mirror direction, and it is not hypothetical now that an
            // upstream may speak the modern era: its `-32020`/`-32021`/
            // `-32022` reach here through `upstream_error_to_jsonrpc`, and a
            // legacy client's revision reserves that whole band with no
            // meaning assigned. `-32600` is the code its spec defines for the
            // same condition.
            modern::legacyize_error(err);
        }
    }
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Render an upstream's failure as the response the client gets, together with
/// the `(code, message)` the audit row records.
///
/// One function because the three relay sites must not be able to disagree.
/// What the client is told and what the row says are the same fact — and the
/// typed payload a `-32021` carries is reachable only from the error VALUE, so
/// a site building its response from the `(code, message)` pair alone drops it
/// silently. That is exactly how `requiredCapabilities` went missing: three
/// correct-looking call sites over one channel that did not exist.
fn upstream_error_relay(
    id: RpcId,
    err: &UpstreamError,
    era: &ProtocolEra,
    sign_ins_url: Option<&str>,
) -> (Response<Body>, i32, String) {
    let (code, message) = upstream_error_to_jsonrpc(err, sign_ins_url);
    let resp = match relayed_error_data(err, code, era) {
        Some(data) => {
            era_error_response_with_data(StatusCode::OK, id, code, message.clone(), data, era)
        }
        None => era_error_response(StatusCode::OK, id, code, message.clone(), era),
    };
    (resp, code, message)
}

/// The one part of an upstream's error `data` the gateway relays.
///
/// § Client Capability Constraints makes `error.data.requiredCapabilities` the
/// substance of a `-32021`: without it a client is told it lacks *something*
/// and cannot learn what, so it can only retry blindly. The gateway forwards
/// the client's own `clientCapabilities` upstream verbatim, so an upstream's
/// complaint about them applies unchanged to the client — this is the client's
/// own declaration handed back, not the upstream's prose, which is why it is
/// the sole exception to "an upstream's own text is never forwarded".
///
/// Two gates, both load-bearing:
/// * **the code**, so the field cannot ride an error that is not about
///   capabilities;
/// * **the era**, because the field is a 2026-07-28 construct. A legacy
///   client's revision does not define it, and `legacyize_error` exists
///   precisely to keep that band's vocabulary off the legacy wire.
fn relayed_error_data(
    err: &UpstreamError,
    code: i32,
    era: &ProtocolEra,
) -> Option<serde_json::Value> {
    if !era.is_modern() || code != modern::MISSING_REQUIRED_CLIENT_CAPABILITY {
        return None;
    }
    match err {
        UpstreamError::Http {
            required_capabilities: Some(caps),
            ..
        } => Some(serde_json::json!({ "requiredCapabilities": caps })),
        _ => None,
    }
}

/// Stamp the upstream's `Mcp-Session-Id` onto a downstream response — for a
/// **legacy client only**.
///
/// MCP 2026-07-28 § Earlier Streamable HTTP Revisions: a modern server neither
/// mints nor echoes session ids. The value here is the *gateway's own* upstream
/// session — for a modern client the gateway opened that connection itself, so
/// echoing it both breaks the revision and discloses internal routing state the
/// client has no business seeing and no way to use.
///
/// Every response that can carry the header goes through this one function, on
/// purpose. There are three such egress points (the one-shot dispatch, the
/// streaming path's JSON arm, and its SSE arm) and they are far apart in this
/// file; applying the rule at two of them and forgetting the third is exactly
/// how this was wrong before.
fn stamp_session_id(
    builder: axum::http::response::Builder,
    session_id: Option<&String>,
    downstream_is_modern: bool,
) -> axum::http::response::Builder {
    match session_id {
        Some(sid) if !downstream_is_modern => builder.header("Mcp-Session-Id", sid),
        _ => builder,
    }
}

fn error_response(
    status: StatusCode,
    id: RpcId,
    code: i32,
    message: impl Into<String>,
) -> Response<Body> {
    rpc_error_response(status, &JsonRpcResponse::err(id, code, message))
}

/// A JSON-RPC error body (built by the caller, e.g. with `data`) as an HTTP
/// response.
fn rpc_error_response(status: StatusCode, body: &JsonRpcResponse) -> Response<Body> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The JSON-RPC error for a `resources/read` naming a resource that does not
/// exist.
///
/// § Error Handling is explicit that this is `-32602` (Invalid Params), and
/// its example carries the URI that was not found under `data.uri` so a
/// client can say *which* read failed when several are in flight. The
/// gateway's own reason for failing — a URI that is not one we minted, or a
/// prefix naming no live route — is not a distinction the client can act on,
/// so both answer the same way; the specific reason still reaches the audit
/// row.
///
/// The wire code stays `ROUTE_NOT_FOUND` and is renumbered to `-32602` for a
/// modern client by `modernize_error`, which recognises this case by the
/// `data.uri` below. Emitting `-32602` here instead would renumber nothing —
/// it would change what LEGACY clients read, and they have read `-32001` for
/// three shipped revisions. SEP-2164 is a 2026-07-28 requirement, so it binds
/// the modern wire only; the era gate is the single place that knows which
/// wire is in front of it, and `dispatch` is not it.
fn resource_not_found(id: RpcId, uri: &str) -> JsonRpcResponse {
    JsonRpcResponse::err_with_data(
        id,
        ROUTE_NOT_FOUND,
        "resource not found",
        serde_json::json!({ "uri": uri }),
    )
}

/// The freshness hint to attach to a modern result, or `None` when the method
/// is not a `CacheableResult`.
///
/// The positive hint is the gateway's own capability-cache TTL, because that
/// is literally how long we would hand the client the same bytes back. It is
/// advertised only when the answer really would come from that cache: an
/// upstream with a per-caller input or OAuth token is never cached, so its catalog can change
/// between one call and the next and a non-zero hint would be a promise we
/// cannot keep. One uncacheable route makes the whole aggregate uncacheable —
/// the client sees a single merged list and cannot cache half of it.
fn modern_cache_hint(
    method: &str,
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
) -> Option<modern::CacheHint> {
    if !modern::is_cacheable_result(method) {
        return None;
    }
    let servable_from_cache = super::cache::is_cacheable_method(method)
        && !upstreams.is_empty()
        && upstreams.iter().all(super::cache::is_cacheable);
    Some(if servable_from_cache {
        modern::CacheHint::fresh_for(
            crate::settings::proxy_settings().mcp_capability_cache_ttl_secs * 1_000,
        )
    } else {
        modern::CacheHint::stale()
    })
}

fn finalize_modern_response(
    resp: &mut JsonRpcResponse,
    method: &str,
    virtual_server: &McpVirtualServer,
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    era: &ProtocolEra,
) -> StatusCode {
    if !era.is_modern() {
        return StatusCode::OK;
    }
    if let Some(result) = resp.result.as_mut() {
        modern::stamp_result(
            result,
            method,
            &gateway_server_info(virtual_server),
            modern_cache_hint(method, upstreams),
        );
    }
    if let Some(err) = resp.error.as_mut() {
        // Renumber first, then choose the status from the renumbered code:
        // the status must agree with the code the client actually reads, and
        // `modernize_error` is what decides that code.
        modern::modernize_error(err);
        return modern::http_status_for_error(err.code);
    }
    StatusCode::OK
}

/// What the gateway learned by opening its connection to every enabled route.
struct UpstreamCapabilityView {
    /// The union of what every reachable route advertises — what the virtual
    /// server *offers*, and what `server/discover` reports.
    merged: serde_json::Value,
    /// The same, kept per upstream. `subscriptions/listen` re-merges the
    /// subset whose listener actually came up, so its acknowledgement names
    /// what will arrive rather than what the servers between them support.
    per_upstream: Vec<(Uuid, serde_json::Value)>,
    instructions: Option<String>,
    /// False when a secondary upstream could not be reached: the capability
    /// set is then a partial view, which the caller must not let a client
    /// cache.
    complete: bool,
}

/// Open — or reuse — the gateway's connection to every enabled route, and
/// return the union of what those upstreams advertise.
async fn merge_modern_upstream_capabilities(
    auth: &AuthCtx,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
) -> Result<UpstreamCapabilityView, UpstreamError> {
    let mut per_caps: Vec<serde_json::Value> = Vec::new();
    let mut per_upstream: Vec<(Uuid, serde_json::Value)> = Vec::new();
    let mut instructions: Vec<String> = Vec::new();
    let mut complete = true;
    // The leader is the first route the caller can call: with several routes,
    // one lacking the caller's inputs is skipped rather than made fatal (a
    // modern client holds no session per route, so skipping costs nothing).
    let mut leader_pending = true;
    let skip_uncallable = some_route_is_callable(auth, routes, upstreams);

    for route in routes {
        let Some(upstream) = upstreams.iter().find(|u| u.id == route.upstream_server_id) else {
            continue;
        };
        if skip_uncallable && !user_has_credential_for(auth, upstream) {
            // The answer leaves this route out for this caller only.
            complete = false;
            continue;
        }
        let is_leader = std::mem::replace(&mut leader_pending, false);
        match ensure_upstream_connection(auth, upstream).await {
            Ok(h) => {
                per_caps.push(h.capabilities.clone());
                per_upstream.push((upstream.id, h.capabilities.clone()));
                // Upstream `instructions` are LLM-facing guidance about that
                // server's tools. Prefixing each with the route's namespace
                // keeps the guidance attached to the names the client will
                // actually see, which carry that same prefix.
                if let Some(text) = &h.instructions {
                    instructions.push(if route.prefix.is_empty() {
                        text.clone()
                    } else {
                        format!("[{}] {text}", route.prefix)
                    });
                }
            }
            Err(e) => {
                // Mirrors the legacy `initialize` fan-out: the first route is
                // the authority, so its failure is the request's failure. A
                // secondary route that is down degrades the capability set
                // rather than the whole call — but the caller is told, so it
                // does not hand the client a partial answer to cache.
                if is_leader {
                    return Err(e);
                }
                complete = false;
                tracing::warn!(
                    error = %e,
                    route = %route.id,
                    "MCP modern discover: secondary upstream handshake failed"
                );
            }
        }
    }

    Ok(UpstreamCapabilityView {
        merged: virtualize::merge_capabilities(&per_caps),
        per_upstream,
        instructions: (!instructions.is_empty()).then(|| instructions.join("\n\n")),
        complete,
    })
}

/// `server/discover` — MCP 2026-07-28 § Discovery.
///
/// Every modern server MUST implement it. It is the era's replacement for
/// `initialize`: one round trip that reports the versions we serve, the
/// capabilities the virtual server actually offers, and our identity. A
/// dual-era client also uses it as the probe that tells a modern server from
/// a legacy one.
#[allow(clippy::too_many_arguments)]
async fn handle_modern_discover(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    slug: &str,
    virtual_server: &McpVirtualServer,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    auth: &AuthCtx,
    request: &JsonRpcRequest,
    started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
) -> Response<Body> {
    let rpc_id = request.id.clone().unwrap_or(RpcId::Null);
    let view = match merge_modern_upstream_capabilities(
        auth,
        routes,
        upstreams,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            let (code, message) = upstream_error_to_jsonrpc(&e, auth.sign_ins_url.as_deref());
            let resp = error_response(StatusCode::OK, rpc_id, code, message.clone());
            emit_audit(
                state,
                identity,
                request_id,
                slug,
                Some(virtual_server.id),
                None,
                request.method.clone(),
                None,
                None,
                None,
                Some(code),
                Some(message),
                started,
                Instant::now(),
                request_bytes,
                0,
                user_agent,
                None,
                StatusCode::OK,
                None,
            )
            .await;
            return resp;
        }
    };

    let mut result = serde_json::json!({
        "supportedVersions": crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": view.merged,
    });
    if let Some(obj) = result.as_object_mut() {
        let mut instructions = Vec::new();
        if let Some(text) = &virtual_server.description
            && !text.is_empty()
        {
            instructions.push(text.clone());
        }
        if let Some(text) = view.instructions {
            instructions.push(text);
        }
        if !instructions.is_empty() {
            obj.insert(
                "instructions".to_string(),
                serde_json::Value::String(instructions.join("\n\n")),
            );
        }
    }

    // A partial capability view MUST NOT be cached: the client would go on
    // believing a whole upstream's tools do not exist for as long as the hint
    // lasts. Zero means "re-fetch every time", which is exactly right while a
    // route is down.
    let hint = if view.complete {
        modern::CacheHint::fresh_for(
            crate::settings::proxy_settings().mcp_capability_cache_ttl_secs * 1_000,
        )
    } else {
        modern::CacheHint::stale()
    };
    modern::stamp_result(
        &mut result,
        modern::METHOD_DISCOVER,
        &gateway_server_info(virtual_server),
        Some(hint),
    );

    let body = serde_json::to_vec(&JsonRpcResponse::ok(rpc_id.clone(), result.clone()))
        .unwrap_or_else(|_| b"{}".to_vec());
    let response_bytes = body.len() as i32;

    emit_audit(
        state,
        identity,
        request_id,
        slug,
        Some(virtual_server.id),
        None,
        request.method.clone(),
        None,
        None,
        None,
        None,
        None,
        started,
        Instant::now(),
        request_bytes,
        response_bytes,
        user_agent,
        None,
        StatusCode::OK,
        None,
    )
    .await;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The gateway's `serverInfo`, as a modern client sees it.
///
/// The wire identity is the gateway's, not the virtual server's — the
/// operator-facing VS name is not what a client is talking to. `title` and
/// `websiteUrl` are the per-mount customisations the VS may set.
fn gateway_server_info(virtual_server: &McpVirtualServer) -> serde_json::Value {
    let mut info = gateway_implementation();
    if let Some(obj) = info.as_object_mut() {
        if let Some(title) = &virtual_server.display_title {
            obj.insert(
                "title".to_string(),
                serde_json::Value::String(title.clone()),
            );
        }
        if let Some(url) = &virtual_server.website_url {
            obj.insert(
                "websiteUrl".to_string(),
                serde_json::Value::String(url.clone()),
            );
        }
    }
    info
}

/// Extract the JSON payload from one framed SSE event on the user event bus.
///
/// The bus carries wire bytes (`event: …\ndata: {…}\n\n`) because the legacy
/// GET stream forwards them verbatim. A modern listen stream cannot: it has
/// to stamp a subscription id into every message, so it parses, edits and
/// re-frames.
fn sse_payload(bytes: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut payload: Option<&str> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            payload = Some(rest.trim_start_matches(' '));
        }
    }
    serde_json::from_str(payload?).ok()
}

/// Narrow a subscription filter to the notification types this token's scope
/// permits.
///
/// The scope check that admitted `subscriptions/listen` only proved the token
/// carries *some* read scope. Without this, a tools-only token would open a
/// stream and then receive resource-update notifications carrying URIs it may
/// not read — a scope escape through a channel nobody thought to gate,
/// because the gating happens per method and this method carries every kind
/// of content at once.
fn narrow_filter_by_scope(
    filter: &modern::SubscriptionFilter,
    user: &UserContext,
) -> modern::SubscriptionFilter {
    // The gate is `scope_check` in `handle_authenticated_request`, which has
    // already admitted this request. What follows narrows what an admitted
    // request may RECEIVE, reusing the same per-method rules so the two can
    // never disagree.
    let permits =
        |m: &str| super::spec_oauth::scope_check(user, m).is_ok(); // scope-narrowing-ok: post-gate
    modern::SubscriptionFilter {
        tools_list_changed: filter.tools_list_changed && permits("tools/list"),
        prompts_list_changed: filter.prompts_list_changed && permits("prompts/list"),
        resources_list_changed: filter.resources_list_changed && permits("resources/list"),
        resource_subscriptions: if permits("resources/read") {
            filter.resource_subscriptions.clone()
        } else {
            Vec::new()
        },
    }
}

/// `subscriptions/listen` — MCP 2026-07-28 § Subscriptions.
///
/// Replaces both the standalone GET stream and `resources/subscribe`. The
/// response to this one request *is* the long-lived stream: an acknowledgement
/// naming the subset we agreed to honor, then only the notification types the
/// client opted in to, each carrying the subscription id.
#[allow(clippy::too_many_arguments)]
async fn handle_modern_subscriptions_listen(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    slug: &str,
    virtual_server: &McpVirtualServer,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
    auth: &AuthCtx,
    request: &JsonRpcRequest,
    started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
) -> Response<Body> {
    let rpc_id = request.id.clone().unwrap_or(RpcId::Null);
    let subscription_id = serde_json::to_value(&rpc_id).unwrap_or(serde_json::Value::Null);

    let requested = modern::SubscriptionFilter::parse(request.params.as_ref());
    let scoped = narrow_filter_by_scope(&requested, &identity.user);

    // What the upstreams can actually source. A type we cannot deliver is
    // omitted from the acknowledgement rather than accepted silently — the
    // client would otherwise wait forever on a notification that is not
    // coming, indistinguishable from a quiet server.
    let view = match merge_modern_upstream_capabilities(
        auth,
        routes,
        upstreams,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            let (code, message) = upstream_error_to_jsonrpc(&e, auth.sign_ins_url.as_deref());
            return error_response(StatusCode::OK, rpc_id, code, message);
        }
    };
    // Open the gateway's own notification stream to every route FIRST, with
    // the scope-narrowed request rather than the honored set — the honored set
    // is derived from which of these came up, so deriving it first would be
    // circular. A listener that asks for slightly more than is ultimately
    // honored costs bandwidth on a stream the gateway narrows again per
    // subscriber; the reverse would promise a client something nothing is
    // listening for.
    let mut sourceable: Vec<serde_json::Value> = Vec::new();
    let mut live: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for route in routes {
        let Some(upstream) = upstreams.iter().find(|u| u.id == route.upstream_server_id) else {
            continue;
        };
        let per_route = route_filter(&scoped, &route.prefix);
        if ensure_upstream_listener(
            auth,
            upstream,
            &route.prefix,
            &per_route,
        )
        .await
        {
            live.insert(upstream.id);
        } else {
            tracing::warn!(
                upstream_id = %upstream.id,
                "MCP subscriptions/listen: no notification stream for this route; not honoring it"
            );
        }
    }
    for (upstream_id, caps) in &view.per_upstream {
        if live.contains(upstream_id) {
            sourceable.push(caps.clone());
        }
    }

    // Narrowed by what a LIVE listener can actually source, not by what the
    // servers between them support. The acknowledgement is where the spec puts
    // the authoritative statement of what one stream will deliver, and a type
    // named here that never arrives is indistinguishable from a quiet server.
    let honored = scoped.honored(&virtualize::merge_capabilities(&sourceable));

    if honored.is_empty() {
        tracing::debug!(
            slug = %slug,
            "MCP subscriptions/listen: nothing honored; stream will stay quiet"
        );
    }

    // A LEGACY upstream additionally has to be told which resources to watch:
    // that era registers subscriptions out of band, where the modern one
    // carries them in the listen filter above. The dispatcher already decodes
    // the `stsmcp://` envelope and routes the call, so this reuses that path
    // rather than re-deriving the routing — two decoders would drift.
    for uri in &honored.resource_subscriptions {
        let sub = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(RpcId::String(format!("sts-sub-{}", Uuid::new_v4()))),
            method: "resources/subscribe".to_string(),
            params: Some(serde_json::json!({ "uri": uri })),
        };
        match dispatch(
            &state.mcp.capability_cache,
            auth,
            virtual_server,
            routes,
            upstreams,
            &sub,
            None,
        )
        .await
        {
            Ok((resp, ..)) => {
                // A modern upstream refuses the method — correctly, it was
                // deleted — and the listen filter above is how that
                // subscription is really placed. Debug, not warn: it is the
                // expected answer, not a fault.
                if let Some(err) = resp.error.as_ref() {
                    tracing::debug!(
                        uri = %uri,
                        code = err.code,
                        "MCP subscriptions/listen: upstream declined resources/subscribe"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    uri = %uri,
                    error = %e,
                    "MCP subscriptions/listen: upstream resources/subscribe failed"
                );
            }
        }
    }

    let mut bus_rx = state.mcp.event_bus.subscribe(
        identity.tenant_id,
        identity.user_id,
        virtual_server.id,
    );

    emit_audit(
        state,
        identity,
        request_id,
        slug,
        Some(virtual_server.id),
        None,
        request.method.clone(),
        None,
        None,
        None,
        None,
        None,
        started,
        Instant::now(),
        request_bytes,
        0,
        user_agent,
        None,
        StatusCode::OK,
        None,
    )
    .await;

    let keepalive_secs = crate::settings::proxy_settings().mcp_get_keepalive_secs.max(1);
    let shutdown_token = state.mcp.shutdown_token.clone();
    // The listeners feeding this stream, so the keepalive tick can keep them
    // alive. An open subscription makes no requests, so without this the
    // upstream streams behind it would look idle and be reaped out from under
    // a client that is still reading.
    let listener_map = state.mcp.listeners.clone();
    let listener_keys: Vec<super::upstream_listen::ListenerKey> = routes
        .iter()
        .map(|r| super::upstream_listen::ListenerKey {
            tenant_id: identity.tenant_id,
            user_id: identity.user_id,
            virtual_server_id: virtual_server.id,
            upstream_id: r.upstream_server_id,
            route_prefix: r.prefix.clone(),
        })
        .collect();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(
        crate::settings::proxy_settings().mcp_get_bus_capacity.max(8),
    );

    tokio::spawn(async move {
        // § Acknowledgment: this MUST be the first message carrying the
        // subscription's id, before any notification on it.
        let ack = modern::subscription_ack(&subscription_id, &honored);
        let frame = format!(
            "event: message\ndata: {}\n\n",
            serde_json::to_string(&ack).unwrap_or_else(|_| "{}".into())
        );
        if tx.try_send(Ok(bytes::Bytes::from(frame.into_bytes()))).is_err() {
            return;
        }

        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(keepalive_secs));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;

        loop {
            tokio::select! {
                ev = bus_rx.recv() => {
                    match ev {
                        Ok(super::event_bus::UserEvent(bytes)) => {
                            let Some(mut payload) = sse_payload(&bytes) else {
                                continue;
                            };
                            let method = payload
                                .get("method")
                                .and_then(|m| m.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let uri = payload
                                .get("params")
                                .and_then(|p| p.get("uri"))
                                .and_then(|u| u.as_str())
                                .map(str::to_string);
                            if !honored.accepts(&method, uri.as_deref()) {
                                continue;
                            }
                            modern::stamp_subscription_id(&mut payload, &subscription_id);
                            let frame = format!(
                                "event: message\ndata: {}\n\n",
                                serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into())
                            );
                            if tx.try_send(Ok(bytes::Bytes::from(frame.into_bytes()))).is_err() {
                                tracing::warn!(
                                    "MCP subscriptions/listen: downstream queue full or closed; ending"
                                );
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped,
                                "MCP subscriptions/listen: subscriber lagged; closing"
                            );
                            break;
                        }
                    }
                }
                _ = keepalive.tick() => {
                    // § Receiving Messages recommends a periodic SSE comment
                    // on a long-lived stream so intermediaries and client
                    // idle timers do not close a subscription that is merely
                    // quiet. The same tick is what keeps the upstream
                    // listeners behind this stream from being reaped as idle.
                    for key in &listener_keys {
                        listener_map.touch(key);
                    }
                    if tx.try_send(Ok(bytes::Bytes::from_static(b": keepalive\n\n"))).is_err() {
                        break;
                    }
                }
                _ = shutdown_token.cancelled() => {
                    // § Graceful Closure: when the *server* ends the
                    // subscription it SHOULD answer the long-lived request
                    // before closing, so the client can tell a clean
                    // teardown from a dropped connection and decide whether
                    // to reconnect.
                    let close = modern::subscription_close(&subscription_id);
                    let frame = format!(
                        "event: message\ndata: {}\n\n",
                        serde_json::to_string(&close).unwrap_or_else(|_| "{}".into())
                    );
                    let _ = tx.try_send(Ok(bytes::Bytes::from(frame.into_bytes())));
                    tracing::info!("MCP subscriptions/listen: shutdown signalled; closing stream");
                    break;
                }
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Resolve the headers to present to `upstream` for this caller: its
/// declared inputs (admin values, the caller's own, the client's captured
/// headers) and, on a `per_user_oauth` upstream, the user's OAuth token as
/// `Authorization: Bearer` — refreshed if needed, which is why this is
/// `async`.
///
/// Split out of [`call_cached`] because the gateway also opens upstream
/// connections **on its own initiative** (see [`ensure_upstream_connection`]),
/// and that path must resolve credentials by exactly the same rules. Two
/// copies of this would drift, and the drift would be a request reaching an
/// upstream with the wrong user's token.
async fn resolve_upstream_auth(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<UpstreamAuth, upstream::UpstreamError> {
    use streamscope_core::config::mcp::McpAuthMode;
    let mut upstream_auth = auth.inputs_memo.resolve(
        upstream,
        auth.mcp_config.user_inputs(auth.user_id, upstream.id),
        &auth.client_inputs,
    )?;
    if upstream.auth_mode == McpAuthMode::PerUserOauth {
        let snapshot = auth.mcp_config.user_credential(auth.user_id, upstream.id);
        let token = oauth::resolve_user_bearer(
            &auth.oauth_state,
            auth.tenant_id,
            auth.user_id,
            upstream,
            snapshot,
            auth.rotation_sink.as_ref(),
        )
        .await?;
        super::upstream_auth::push_oauth_token(&mut upstream_auth, upstream, &token)?;
    }
    Ok(upstream_auth)
}

/// The capabilities the gateway declares when it opens a **legacy** upstream
/// connection on its own behalf, to serve a modern client.
///
/// All three client capabilities are declared because the gateway *can* relay
/// each one — sampling and elicitation reach the client through MRTR, and
/// sampling may additionally be answered by the gateway itself when the
/// virtual server configures interception.
///
/// The declaration is deliberately the **baseline** shape of each (`{}`), not
/// the richer sub-mode forms. This handshake is per `(user, upstream)` and is
/// reused across requests from different clients, so it cannot honestly claim
/// a sub-mode — URL-mode elicitation, sampling tool use — that the client
/// arriving on the *next* request may not support. An upstream that asks for
/// something the current client did not declare is answered with
/// `-32021 MissingRequiredClientCapability`, which is precisely the spec's
/// remedy.
///
/// A **modern** upstream is told something narrower and more honest — see
/// [`AuthCtx::upstream_client_capabilities`] — because that era declares
/// capabilities per request rather than per connection.
///
/// Legacy clients are unaffected: their own `initialize` is forwarded
/// verbatim, so their capability negotiation stays exact and per-client.
fn gateway_upstream_capabilities() -> serde_json::Value {
    serde_json::json!({
        "roots": {},
        "sampling": {},
        "elicitation": {},
    })
}

/// Resolve [`AuthCtx::upstream_client_capabilities`] for one request.
fn upstream_client_capabilities(meta: Option<&RequestMeta>) -> serde_json::Value {
    match meta {
        Some(m) => m.client_capabilities.clone(),
        None => serde_json::json!({}),
    }
}

/// Resolve [`AuthCtx::upstream_log_level`] for one request.
///
/// A modern client states it per request. A legacy client stated it once, and
/// the session remembers.
fn upstream_log_level(
    meta: Option<&RequestMeta>,
    session_map: &McpSessionMap,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Option<String> {
    match meta {
        Some(m) => m.log_level.clone(),
        None => session_map.log_level(tenant_id, user_id),
    }
}

/// The gateway's self-description, sent as `clientInfo` upstream and returned
/// as `serverInfo` downstream.
fn gateway_implementation() -> serde_json::Value {
    serde_json::json!({
        "name": "streamscope-mcp",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// What one `server/discover` probe learned about an upstream.
enum DiscoverOutcome {
    /// It answered with a discovery result. Modern, and this *is* the
    /// discovery — there is nothing else to ask it.
    Discovered(serde_json::Value),
    /// It understood the modern envelope and objected to it, in the modern
    /// error vocabulary. Modern, but not usable as configured.
    ModernRefusal(super::jsonrpc::JsonRpcError),
    /// It does not implement `server/discover`. Every modern server MUST, so
    /// this one is legacy.
    NotModern,
    /// Something answered, but it said nothing about the era: an auth
    /// challenge, a throttle, a gateway in front of the upstream during a
    /// deploy.
    ///
    /// A distinct variant rather than folded into [`Self::NotModern`], and
    /// the distinction is the whole point: `NotModern` is a verdict worth
    /// **caching**, and caching a 502 as "legacy" would leave a modern-only
    /// upstream mis-addressed for the entire idle window — every call failing
    /// at a handshake that server deleted, seconds after the 502 cleared, with
    /// nothing to re-probe it. The caller serves this attempt as legacy (the
    /// safe assumption for the overwhelmingly common case) and caches
    /// nothing, so the next request re-probes and the window closes itself.
    ///
    /// Carries the error it could not read a verdict from, so a caller that
    /// genuinely needed the discovery — rather than just the era — can report
    /// what actually happened instead of a verdict nobody reached.
    Inconclusive(upstream::UpstreamError),
}

/// HTTP statuses that cannot carry a verdict about which era a server speaks.
///
/// An auth challenge, a proxy throttle and a load balancer's 5xx are all
/// answers to something other than the question the probe asked. Everything
/// else — a `404`/`405` from a server that does not route the method, a `400`
/// whose body is not JSON-RPC — is the origin telling us `server/discover` is
/// not there, which is exactly what a legacy server would say.
fn status_answers_nothing_about_era(status: u16) -> bool {
    matches!(status, 401 | 403 | 407 | 408 | 429) || status >= 500
}

/// Send one `server/discover` to `upstream` and classify the answer.
///
/// This is the era probe *and* the discovery: for a modern upstream the two
/// are the same call, which is why nothing here is split into a "probe" and a
/// "connect". § Backward Compatibility prescribes exactly this — try the
/// modern RPC and read the failure — and it is the only shape that costs a
/// modern upstream nothing.
async fn discover_upstream(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<DiscoverOutcome, upstream::UpstreamError> {
    let upstream_auth = resolve_upstream_auth(auth, upstream).await?;
    let probe = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RpcId::String(format!("sts-discover-{}", Uuid::new_v4()))),
        method: modern::METHOD_DISCOVER.to_string(),
        params: Some(modern::upgrade_request_params(
            None,
            &auth.upstream_client_capabilities,
            &gateway_implementation(),
            None,
        )),
    };

    match upstream::call_with_auth(
        upstream,
        &upstream_auth,
        &probe,
        None,
        Some(modern::MODERN_PROTOCOL_VERSION),
    )
    .await
    {
        Ok((resp, _)) => Ok(match (resp.result, resp.error) {
            (Some(result), _) => DiscoverOutcome::Discovered(result),
            (None, Some(err)) if modern::identifies_modern_server(err.code) => {
                DiscoverOutcome::ModernRefusal(err)
            }
            // It spoke JSON-RPC and declined the one RPC every modern server
            // must implement.
            (None, _) => DiscoverOutcome::NotModern,
        }),
        // A protocol refusal often rides an HTTP failure status: a modern
        // server handed a legacy `MCP-Protocol-Version` answers 400 with
        // `-32022`, and a legacy server that requires a session answers 400
        // with `-32600`. The JSON-RPC code inside the body is the only thing
        // that tells the two apart, which is why it is captured before the
        // body is redacted for logging.
        Err(e) => {
            let (status, code) = match &e {
                upstream::UpstreamError::Http {
                    status,
                    jsonrpc_code,
                    ..
                } => (*status, *jsonrpc_code),
                // A transport failure answered nothing at all. Propagating
                // rather than guessing is what keeps a network blip out of
                // the era cache, where it would mis-address the upstream for
                // the whole window and present as every call failing at the
                // handshake.
                _ => return Err(e),
            };
            if let Some(code) = code {
                if modern::identifies_modern_server(code) {
                    let message = match &e {
                        upstream::UpstreamError::Http { body, .. } => body.clone(),
                        _ => String::new(),
                    };
                    return Ok(DiscoverOutcome::ModernRefusal(
                        super::jsonrpc::JsonRpcError {
                            code,
                            message,
                            data: None,
                        },
                    ));
                }
                // The body is JSON-RPC, so the origin itself answered and
                // declined the one RPC every modern server must implement.
                return Ok(DiscoverOutcome::NotModern);
            }
            if status_answers_nothing_about_era(status) {
                tracing::debug!(
                    upstream_id = %upstream.id,
                    status,
                    "MCP era probe: this status says nothing about the era; caching no verdict"
                );
                return Ok(DiscoverOutcome::Inconclusive(e));
            }
            tracing::debug!(
                upstream_id = %upstream.id,
                status,
                "MCP era probe: upstream refused server/discover; treating it as legacy"
            );
            Ok(DiscoverOutcome::NotModern)
        }
    }
}

/// Which eras `upstream` implements, probing at most once per
/// `(tenant, upstream)` per idle window.
///
/// Two shapes are legacy by construction and are never probed:
///
/// - `internal://` virtual servers dispatch in-process against code this repo
///   owns, which implements the legacy surface.
/// - The `sse` transport *is* the pre-Streamable-HTTP protocol. The modern era
///   deleted the standalone stream outright, so a server reachable only that
///   way cannot be modern — and probing it would open a long-lived channel
///   just to be told so.
///
/// For everything else the probe answers two independent questions, and keeps
/// **both** answers rather than collapsing them into one era.
///
/// **Does it offer the modern era?** `server/discover` answers that, and
/// [`modern::offers_modern_era`] applies the same rule the reference clients
/// do. Anything short of positive evidence is a legacy advertisement.
///
/// **Does it still answer the handshake?** Asked only of a modern-advertising
/// server, and not to *choose* for it — [`modern::era_for_request`] chooses,
/// per request, matching the client. Keeping the pair is what lets a modern
/// client reach a dual-era server natively (its questions relay as data
/// instead of costing the upstream a re-run) while a legacy client reaches the
/// same server natively too (keeping the live stream its revision needs to be
/// asked anything at all). The two legs are not a shared resource: the modern
/// one holds no session.
///
/// Nothing that failed to *answer* is cached — see
/// [`status_answers_nothing_about_era`].
async fn resolve_upstream_support(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<modern::UpstreamEraSupport, upstream::UpstreamError> {
    use streamscope_core::config::mcp::McpTransport;
    if super::virtual_servers::is_internal(upstream)
        || matches!(upstream.transport, McpTransport::Sse)
    {
        return Ok(modern::UpstreamEraSupport::LEGACY_ONLY);
    }
    if let Some(support) = auth
        .session_map
        .upstream_era_support(auth.tenant_id, upstream.id)
    {
        return Ok(support);
    }

    let support = match discover_upstream(auth, upstream).await? {
        DiscoverOutcome::Discovered(result) if modern::offers_modern_era(&result) => {
            // The probe's answer IS the modern connection — there is no
            // handshake behind it — so record it now rather than repeat the
            // call, whichever era the first request turns out to want.
            auth.session_map.set_handshake(
                auth.tenant_id,
                auth.user_id,
                upstream.id,
                inputs_key(auth, upstream),
                super::session::UpstreamHandshake::modern(
                    result
                        .get("capabilities")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                    result
                        .get("instructions")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                ),
            );
            match legacy_handshake(auth, upstream).await {
                Ok(_) => {
                    tracing::info!(
                        upstream_id = %upstream.id,
                        "MCP era probe: upstream serves both eras; each client gets its own"
                    );
                    modern::UpstreamEraSupport::BOTH
                }
                // It answered and refused, which is the modern-only shape.
                // Any answered refusal counts, without a table of which codes
                // mean "no handshake here": `server/discover` already
                // succeeded, so the upstream demonstrably speaks modern and
                // the worst a misread costs is the legacy leg until the window
                // lapses. A transport failure answered nothing at all and is
                // propagated instead.
                Err(upstream::UpstreamError::Http { status, .. }) => {
                    tracing::info!(
                        upstream_id = %upstream.id,
                        status,
                        "MCP era probe: upstream refused the handshake; modern only"
                    );
                    modern::UpstreamEraSupport::MODERN_ONLY
                }
                Err(e) => return Err(e),
            }
        }
        // It answered `server/discover` but advertised no modern revision we
        // share. The reference clients read that as a legacy advertisement
        // rather than an incompatibility, and so does this.
        DiscoverOutcome::Discovered(_) => modern::UpstreamEraSupport::LEGACY_ONLY,
        DiscoverOutcome::ModernRefusal(err) => {
            tracing::warn!(
                upstream_id = %upstream.id,
                code = err.code,
                message = %err.message,
                "MCP era probe: modern upstream refused the gateway's discovery envelope"
            );
            modern::UpstreamEraSupport::MODERN_ONLY
        }
        DiscoverOutcome::NotModern => modern::UpstreamEraSupport::LEGACY_ONLY,
        // Answered nothing about the era. Serve this attempt as legacy — the
        // right assumption for all but a handful of servers — but record
        // NOTHING, so the next request re-probes instead of living with a
        // verdict a throttle or a deploy handed us.
        DiscoverOutcome::Inconclusive(_) => {
            return Ok(modern::UpstreamEraSupport::LEGACY_ONLY);
        }
    };
    auth.session_map
        .set_upstream_era_support(auth.tenant_id, upstream.id, support);
    Ok(support)
}

/// The era to address `upstream` in for **this** request — the client's own,
/// wherever the server implements both.
async fn resolve_upstream_era(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<modern::UpstreamEra, upstream::UpstreamError> {
    let support = resolve_upstream_support(auth, upstream).await?;
    Ok(modern::era_for_request(auth.era.is_modern(), support))
}

/// The inputs a gateway-owned handshake with `upstream` is opened under: the
/// stored admin and user values, the user's OAuth credential and the client's
/// values for its client-filled headers. A cached handshake opened under other inputs (an admin rotation,
/// the user's changed values, another client's token) is not found, so a
/// caller never rides an upstream session another credential opened.
fn inputs_key(auth: &AuthCtx, upstream: &streamscope_core::config::mcp::McpUpstreamServer) -> u64 {
    super::upstream_auth::inputs_fingerprint(
        upstream,
        auth.mcp_config.user_inputs(auth.user_id, upstream.id),
        auth.mcp_config.user_credential(auth.user_id, upstream.id),
        &auth.client_inputs,
    )
}

/// Open — or reuse — the gateway's own connection to `upstream`, in the era
/// this request is addressing it in.
///
/// Needed whenever the gateway must speak for itself rather than relay a
/// client's handshake: a modern client sends no `initialize`, and a modern
/// upstream has none to send. Legacy upstreams overwhelmingly refuse to serve
/// `tools/list` before `initialize` *and* `notifications/initialized`, so both
/// are sent here, in that order; a modern upstream gets neither, because
/// `server/discover` already told us everything a handshake would have.
///
/// Cached per `(tenant, user, upstream, era)` — keyed on the authenticated
/// user, never on anything from the wire — holding the inputs it was opened
/// under ([`inputs_key`]), and reused until the idle TTL
/// lapses or an upstream tells us the session is gone. **The era is in the key
/// because a dual-era upstream carries both legs at once**, one per client
/// generation, and they share no state.
async fn ensure_upstream_connection(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<super::session::UpstreamHandshake, upstream::UpstreamError> {
    // The built-in virtual servers (`internal://…`) are dispatched in-process
    // and hold no session state, so there is nothing to hand-shake. Record an
    // entry anyway, with the capabilities they advertise, so `server/discover`
    // and the subscription filter see them.
    if super::virtual_servers::is_internal(upstream) {
        if let Some(h) = auth.session_map.handshake(
            auth.tenant_id,
            auth.user_id,
            upstream.id,
            inputs_key(auth, upstream),
            modern::UpstreamEra::Legacy,
        ) {
            return Ok(h);
        }
        let init = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(RpcId::String(format!("sts-init-{}", Uuid::new_v4()))),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({
                "protocolVersion": crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION,
                "capabilities": gateway_upstream_capabilities(),
                "clientInfo": gateway_implementation(),
            })),
        };
        let (resp, _) =
            super::virtual_servers::dispatch(auth, upstream, &init).await?;
        let caps = resp
            .result
            .as_ref()
            .and_then(|r| r.get("capabilities"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        return Ok(auth.session_map.set_handshake(
            auth.tenant_id,
            auth.user_id,
            upstream.id,
            inputs_key(auth, upstream),
            super::session::UpstreamHandshake::legacy(
                None,
                caps,
                crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION.to_string(),
                None,
            ),
        ));
    }

    // Resolved first: it decides which slot to read, and a cold probe of a
    // modern-capable upstream fills the modern slot as a side effect of
    // answering — so looking before resolving would miss it and pay for a
    // second `server/discover`.
    let era = resolve_upstream_era(auth, upstream).await?;
    if let Some(h) = auth
        .session_map
        .handshake(auth.tenant_id, auth.user_id, upstream.id, inputs_key(auth, upstream), era)
    {
        return Ok(h);
    }

    if era.is_modern() {
        return match discover_upstream(auth, upstream).await? {
            DiscoverOutcome::Discovered(result) => Ok(auth.session_map.set_handshake(
                auth.tenant_id,
                auth.user_id,
                upstream.id,
                inputs_key(auth, upstream),
                super::session::UpstreamHandshake::modern(
                    result
                        .get("capabilities")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({})),
                    result
                        .get("instructions")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                ),
            )),
            DiscoverOutcome::ModernRefusal(err) => Err(UpstreamError::Http {
                status: 400,
                body: format!("server/discover refused: {} ({})", err.message, err.code),
                jsonrpc_code: Some(err.code),
                // `server/discover` is the gateway's own handshake, not a
                // client request, so a capability refusal here is about what
                // WE declared upstream — nothing the client could correct.
                required_capabilities: None,
            }),
            // The era says modern but the discovery this call needs did not
            // arrive. Report what actually happened rather than a verdict
            // nobody reached — and leave the cached support alone, because a
            // throttle or a deploy is not evidence about which eras a server
            // implements.
            DiscoverOutcome::Inconclusive(e) => Err(e),
            // The cached assumption failed, which § Backward Compatibility
            // names as the one trigger for re-probing. Drop it so the next
            // call classifies afresh, and serve this one as legacy.
            DiscoverOutcome::NotModern => {
                tracing::warn!(
                    upstream_id = %upstream.id,
                    "MCP era: upstream no longer answers server/discover; re-probing"
                );
                auth.session_map
                    .forget_upstream_era(auth.tenant_id, upstream.id);
                legacy_handshake(auth, upstream).await
            }
        };
    }

    // The symmetric self-heal. § Backward Compatibility names a failing
    // cached assumption as the one trigger for re-probing, and it has to work
    // in both directions: an upstream upgraded to a modern-only build answers
    // our `initialize` with a refusal, and without this the cached support
    // would stand for the rest of the window while every legacy-era call
    // failed at a handshake that server no longer implements. Only an
    // *answered* refusal counts — a transport failure is the upstream being
    // down, not the support being wrong, and forgetting on one would re-probe
    // on every blip.
    match legacy_handshake(auth, upstream).await {
        Ok(h) => Ok(h),
        Err(e) => {
            if matches!(e, upstream::UpstreamError::Http { .. }) {
                tracing::info!(
                    upstream_id = %upstream.id,
                    "MCP era: upstream refused the handshake it was cached as accepting; re-probing"
                );
                auth.session_map
                    .forget_upstream_era(auth.tenant_id, upstream.id);
            }
            Err(e)
        }
    }
}

/// The gateway's own `initialize` + `notifications/initialized` against a
/// legacy upstream.
async fn legacy_handshake(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<super::session::UpstreamHandshake, upstream::UpstreamError> {
    let upstream_auth = resolve_upstream_auth(auth, upstream).await?;

    let init = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RpcId::String(format!("sts-init-{}", Uuid::new_v4()))),
        method: "initialize".to_string(),
        params: Some(serde_json::json!({
            "protocolVersion": crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION,
            "capabilities": gateway_upstream_capabilities(),
            "clientInfo": gateway_implementation(),
        })),
    };

    let (resp, sid) = if matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::Sse
    ) {
        // A legacy-SSE upstream keys its persistent channel on the agent
        // session id. Modern clients have none, so the gateway's own key
        // stands in — it is stable per (tenant, user, upstream), which is
        // exactly the grain that channel needs.
        dispatch_legacy_sse(
            auth,
            upstream,
            upstream_auth.clone(),
            &init,
            Some(&modern_upstream_channel_key(auth)),
            "",
        )
        .await?
    } else {
        upstream::call_with_auth(upstream, &upstream_auth, &init, None, None).await?
    };

    if let Some(err) = &resp.error {
        tracing::warn!(
            upstream_id = %upstream.id,
            code = err.code,
            message = %err.message,
            "MCP modern: gateway-owned initialize refused by upstream"
        );
        return Err(UpstreamError::Http {
            status: 200,
            body: format!("initialize refused: {} ({})", err.message, err.code),
            jsonrpc_code: Some(err.code),
            // The gateway's own handshake, not a client request: a capability
            // refusal here is about what WE declared upstream, so there is
            // nothing for the client to correct.
            required_capabilities: None,
        });
    }

    let result = resp.result.unwrap_or_else(|| serde_json::json!({}));
    let capabilities = result
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let negotiated = result
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION)
        .to_string();

    // The legacy handshake is not complete until the client acknowledges it.
    // Skipping this leaves conforming upstreams answering `-32600 Server not
    // initialized` to every subsequent call — and the failure looks like a
    // broken tool rather than a missing notification.
    if !matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::Sse
    ) {
        let initialized = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        });
        if let Err(e) = upstream::forward_client_response(
            &upstream.upstream_url,
            &upstream_auth,
            &initialized,
            sid.as_deref().unwrap_or(""),
            upstream.request_timeout_ms,
        )
        .await
        {
            // Best-effort: some upstreams answer the notification with a 4xx
            // they would not have answered a request with. The handshake
            // itself succeeded, so continue and let the first real call
            // report any genuine problem.
            tracing::debug!(
                upstream_id = %upstream.id,
                error = %e,
                "MCP modern: notifications/initialized was not accepted"
            );
        }
    }

    let instructions = result
        .get("instructions")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(auth.session_map.set_handshake(
        auth.tenant_id,
        auth.user_id,
        upstream.id,
        inputs_key(auth, upstream),
        super::session::UpstreamHandshake::legacy(sid, capabilities, negotiated, instructions),
    ))
}

/// The stable channel key a modern client's traffic uses where the legacy
/// machinery wants an agent session id (the legacy-SSE session map, the SSE
/// event sequencer).
///
/// Derived from the authenticated identity, never from a header: a modern
/// request carries no session id, and inventing one from client-supplied
/// bytes would let a tenant member address a sibling's channel.
fn modern_upstream_channel_key(auth: &AuthCtx) -> String {
    format!("modern:{}:{}", auth.user_id, auth.virtual_server_id)
}

/// Resolve the upstream's era and, where one is needed, the gateway's own
/// connection to it — the two facts the streaming path must have before it can
/// shape a request.
///
/// A gateway-owned handshake is needed for exactly one combination: a modern
/// *client*, whose `initialize` never arrived, talking to a legacy *upstream*,
/// which will not serve anything without one. A modern upstream has no
/// handshake to open, and a legacy client opened its own.
async fn streamed_upstream_preflight(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> Result<(bool, Option<super::session::UpstreamHandshake>), upstream::UpstreamError> {
    let modern_upstream = resolve_upstream_era(auth, upstream)
        .await?
        .is_modern();
    let handshake = if auth.era.is_modern() && !modern_upstream {
        Some(ensure_upstream_connection(auth, upstream).await?)
    } else {
        None
    };
    Ok((modern_upstream, handshake))
}

/// Everything needed to bring a **modern upstream's** answer into the shape
/// the downstream client can receive.
///
/// Owned rather than borrowed from [`AuthCtx`] because the streaming pump is a
/// spawned task: the same conversion has to run on a one-shot JSON reply and
/// on the final event of an SSE stream, and two copies of it would drift on
/// exactly the case neither is tested for.
#[derive(Debug, Clone)]
struct ModernUpstreamRelay {
    /// The era of the **client**, which decides what can be relayed. The
    /// upstream's era is already known — this type only exists for a modern
    /// one.
    downstream_era: ProtocolEra,
    /// What the client declared it can produce, as it was declared to the
    /// upstream. § MRTR forbids asking for input outside this set, and the
    /// gateway is the asking party as far as the client is concerned.
    client_capabilities: serde_json::Value,
    tenant_id: Uuid,
    user_id: Uuid,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    /// The downstream method. Bound into the minted `requestState` and checked
    /// against § MRTR's list of methods that may answer with a question.
    method: String,
    /// Digest of the params the CLIENT sent — the bytes it will retry with.
    params_digest: String,
    server_info: serde_json::Value,
}

impl ModernUpstreamRelay {
    fn from_auth(
        auth: &AuthCtx,
        upstream: &streamscope_core::config::mcp::McpUpstreamServer,
        method: &str,
    ) -> Self {
        Self {
            downstream_era: auth.era.clone(),
            client_capabilities: auth.upstream_client_capabilities.clone(),
            tenant_id: auth.tenant_id,
            user_id: auth.user_id,
            virtual_server_id: auth.virtual_server_id,
            upstream_id: upstream.id,
            method: method.to_string(),
            params_digest: auth.client_params_digest.clone(),
            server_info: auth.server_info.clone(),
        }
    }

    /// What to do with a result a modern upstream returned.
    ///
    /// `Ok(None)` — an ordinary result; relay it untouched.
    /// `Ok(Some(result))` — relay this instead (an `InputRequiredResult`
    /// re-wrapped around a state only this gateway can verify).
    /// `Err((code, message))` — the client cannot be asked; fail the call.
    fn adapt_result(
        &self,
        result: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, (i32, String)> {
        let required = match modern::parse_input_required(result) {
            modern::InputRequiredShape::No => return Ok(None),
            modern::InputRequiredShape::Malformed => {
                tracing::warn!(
                    upstream_id = %self.upstream_id,
                    method = %self.method,
                    "MCP MRTR: upstream claimed input_required without the fields to answer it"
                );
                return Err((
                    UPSTREAM_ERROR,
                    "the upstream asked for input but did not say what to answer".to_string(),
                ));
            }
            modern::InputRequiredShape::Yes(r) => r,
        };

        // § MRTR: only three RPCs may answer with a question. An upstream
        // returning one anywhere else is not a request we can retry, because
        // the client's own revision would not know to.
        if !modern::supports_input_required(&self.method) {
            return Err((
                UPSTREAM_ERROR,
                format!("the upstream answered {} with an input request, which that method may not carry", self.method),
            ));
        }

        // A legacy client cannot receive a question as data, and the gateway
        // declared `{}` upstream precisely so a conforming server never asks.
        // Reaching here means either that the upstream ignored that
        // declaration, or that it shed load — which no capability declaration
        // suppresses, because it asks nothing. Either way the client's
        // revision does not define this result shape, so the honest answer is
        // to say so rather than relay it. (Redeeming a load-shed retry on the
        // client's behalf would be a bounded re-issue loop the gateway does
        // not have; nothing here silently degrades into one.)
        if !self.downstream_era.is_modern() {
            return Err((
                super::jsonrpc::MCP_UPSTREAM_INPUT_UNSUPPORTED,
                "the upstream requires interactive input, which this protocol revision cannot carry through the gateway".to_string(),
            ));
        }

        let meta = RequestMeta {
            protocol_version: self.downstream_era.version().to_string(),
            client_info: None,
            client_capabilities: self.client_capabilities.clone(),
            log_level: None,
        };
        for asked in modern::input_required_methods(&required.input_requests) {
            if !meta.supports_input_request(&asked) {
                let err = ModernError::missing_client_capability(
                    modern::required_capability_for(&asked),
                    format!(
                        "the upstream requires {asked}, which this request did not declare support for"
                    ),
                );
                return Err((err.code, err.message));
            }
        }

        // The upstream's own `requestState` is opaque and says nothing about
        // which upstream minted it. Wrapping it under the gateway's HMAC —
        // alongside the principal, the method and the argument digest that
        // already bind an MRTR retry — is what makes the retry routable and
        // keeps it un-replayable onto another call.
        //
        // A wrapper is minted even when the upstream kept NO state of its own.
        // § MRTR server requirement 3 makes emitting one the gateway's choice,
        // and it is the only thing that names the upstream a fanned-out
        // virtual server must send the answers back to — without it the retry
        // is indistinguishable from a first attempt carrying stray
        // `inputResponses`, and the principal/TTL binding is lost too.
        let state = match streamscope_core::mcp::tokens::encode_request_state(
            self.tenant_id,
            self.user_id,
            self.virtual_server_id,
            &self.method,
            &self.params_digest,
            Some((self.upstream_id, required.request_state.as_deref())),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "MCP MRTR: could not wrap the upstream's requestState");
                return Err((
                    INTERNAL_ERROR,
                    "could not prepare the input request".to_string(),
                ));
            }
        };

        Ok(Some(modern::input_required_result(
            &required.input_requests,
            &state,
            &self.server_info,
        )))
    }

    /// Bring a modern upstream's error code into the client's vocabulary.
    /// A no-op for a modern client, which shares that vocabulary.
    fn adapt_error(&self, err: &mut super::jsonrpc::JsonRpcError) {
        if !self.downstream_era.is_modern() {
            modern::legacyize_error(err);
        }
    }

    /// Strip a modern upstream's result down to what a **legacy** client's
    /// revision defines. See [`modern::downgrade_result`] for what goes and
    /// why; a modern client reaches `stamp_result` instead and needs none of
    /// it.
    ///
    /// Returns whether anything changed, so a stream event with nothing to
    /// rewrite keeps its original bytes.
    fn downgrade_for_legacy(&self, result: &mut serde_json::Value) -> bool {
        if self.downstream_era.is_modern() {
            return false;
        }
        modern::downgrade_result(result)
    }

    /// Apply both halves to a one-shot JSON-RPC reply.
    fn adapt_response(&self, resp: &mut JsonRpcResponse) {
        if let Some(err) = resp.error.as_mut() {
            self.adapt_error(err);
            return;
        }
        let Some(result) = resp.result.as_ref() else {
            return;
        };
        match self.adapt_result(result) {
            Ok(None) => {
                if let Some(r) = resp.result.as_mut() {
                    self.downgrade_for_legacy(r);
                }
            }
            Ok(Some(replacement)) => resp.result = Some(replacement),
            Err((code, message)) => {
                *resp = JsonRpcResponse::err(resp.id.clone(), code, message);
            }
        }
    }

    /// Apply both halves to one raw SSE event, returning the rewritten wire
    /// payload when anything changed.
    ///
    /// Only a response to *our* request is touched: a notification (method,
    /// no id) or a server-initiated request passes through, because neither
    /// is the answer this conversion is about.
    fn adapt_stream_event(&self, raw: &str) -> Option<String> {
        let mut value: serde_json::Value = serde_json::from_str(raw).ok()?;
        let obj = value.as_object_mut()?;
        if obj.contains_key("method") || !obj.contains_key("id") {
            return None;
        }
        if let Some(err) = obj.get_mut("error") {
            let mut parsed: super::jsonrpc::JsonRpcError =
                serde_json::from_value(err.clone()).ok()?;
            let before = parsed.code;
            self.adapt_error(&mut parsed);
            if parsed.code == before {
                // Nothing to translate. Returning the re-serialized value
                // anyway would replace the upstream's bytes with our own
                // key ordering on every error event, and those exact bytes
                // are what the audit copy and the `Last-Event-ID` replay row
                // are built from.
                return None;
            }
            *err = serde_json::to_value(&parsed).ok()?;
            return serde_json::to_string(&value).ok();
        }
        let result = obj.get("result")?;
        match self.adapt_result(result) {
            Ok(None) => {
                let downgraded = obj
                    .get_mut("result")
                    .is_some_and(|r| self.downgrade_for_legacy(r));
                if !downgraded {
                    return None;
                }
                serde_json::to_string(&value).ok()
            }
            Ok(Some(replacement)) => {
                obj.insert("result".to_string(), replacement);
                serde_json::to_string(&value).ok()
            }
            Err((code, message)) => {
                obj.remove("result");
                obj.insert(
                    "error".to_string(),
                    serde_json::json!({ "code": code, "message": message }),
                );
                serde_json::to_string(&value).ok()
            }
        }
    }
}

/// One call to an upstream that speaks the **modern** era.
///
/// Structurally simpler than the legacy path, and deliberately so: there is no
/// handshake to have performed, no session id to look up, and nothing kept
/// between calls. The `_meta` envelope every request restates is what replaces
/// all of it.
///
/// The downstream client's era is irrelevant here except at the two points
/// where it is named — a legacy client reaches a modern upstream through this
/// same function.
async fn call_modern_upstream(
    cache: &Arc<super::cache::CapabilityCache>,
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    request: &JsonRpcRequest,
) -> Result<(JsonRpcResponse, Option<String>), upstream::UpstreamError> {
    let rpc_id = request.id.clone().unwrap_or(RpcId::Null);
    match modern::modern_upstream_action(&request.method) {
        modern::ModernUpstreamAction::FromDiscovery => {
            let conn = ensure_upstream_connection(auth, upstream).await?;
            // Negotiated from the request BODY. `auth.era` came off
            // `MCP-Protocol-Version`, which a legacy client is not required
            // to send on the handshake itself — using it here would answer
            // every `initialize` with the header's `2025-03-26` default and
            // silently downgrade a client that asked for more.
            let version = modern::negotiated_initialize_version(
                request.params.as_ref(),
                crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS,
                crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION,
            );
            Ok((
                JsonRpcResponse::ok(
                    rpc_id,
                    modern::discovery_as_initialize_result(
                        &conn.capabilities,
                        conn.instructions.as_deref(),
                        &version,
                    ),
                ),
                None,
            ))
        }
        modern::ModernUpstreamAction::EmptyResult => {
            // `logging/setLevel` is the case that matters: the level is
            // remembered for the session and rides `_meta.logLevel` on every
            // later call, so answering here is a translation and not a
            // discard. `ping` has no session to keep alive.
            Ok((JsonRpcResponse::ok(rpc_id, serde_json::json!({})), None))
        }
        modern::ModernUpstreamAction::DropNotification => {
            Ok((JsonRpcResponse::ok(rpc_id, serde_json::json!({})), None))
        }
        modern::ModernUpstreamAction::Unsupported(reason) => Ok((
            JsonRpcResponse::err(
                rpc_id,
                super::jsonrpc::MCP_UPSTREAM_CONFIG_UNSUPPORTED,
                reason.to_string(),
            ),
            None,
        )),
        modern::ModernUpstreamAction::Forward => {
            let upstream_auth = resolve_upstream_auth(auth, upstream).await?;
            let outbound = modern_outbound_request(auth, upstream, request);
            let relay = ModernUpstreamRelay::from_auth(auth, upstream, &request.method);

            let cacheable = super::cache::is_cacheable(upstream)
                && super::cache::is_cacheable_method(&request.method);
            let cache_key = cacheable.then(|| super::cache::CacheKey {
                tenant_id: auth.tenant_id,
                upstream_id: upstream.id,
                cred_version: upstream.cred_version,
                method: request.method.clone(),
                // This is the modern leg; see `CacheKey::upstream_is_modern`.
                upstream_is_modern: true,
            });
            if let Some(key) = &cache_key
                && let Some(mut cached) = cache.get(key)
            {
                cached.id = rpc_id;
                // Through the same relay as a fresh answer. Nothing an entry
                // can hold needs converting — a question and an error are
                // both refused entry below — but a hit that skipped the one
                // funnel would be a second, quieter path for the next thing
                // added to it.
                relay.adapt_response(&mut cached);
                return Ok((cached, None));
            }

            let (mut resp, _) = upstream::call_with_auth(
                upstream,
                &upstream_auth,
                &outbound,
                // A modern server neither mints nor accepts a session id.
                None,
                Some(modern::MODERN_PROTOCOL_VERSION),
            )
            .await?;
            // Cached BEFORE the relay runs, so the entry holds the upstream's
            // own answer rather than one wrapped around a `requestState`
            // minted for this caller — and never when the answer is a
            // question, which is single-use by construction and would be
            // served to a second caller with a state they cannot redeem.
            // `is_cacheable_method` already excludes every method that may
            // ask, so this is a second lock on the same door; it is cheap and
            // what it prevents is silent.
            if let Some(key) = cache_key
                && resp.error.is_none()
                && resp.result.as_ref().is_some_and(|r| {
                    matches!(modern::parse_input_required(r), modern::InputRequiredShape::No)
                })
            {
                cache.insert(key, resp.clone());
            }
            relay.adapt_response(&mut resp);
            Ok((resp, None))
        }
    }
}

/// Wrap a request for a modern upstream: point any MRTR retry at the upstream
/// that asked, then restate the envelope.
///
/// The order is load-bearing. `retarget_request_state` rewrites the MRTR
/// fields; `upgrade_request_params` then writes `_meta` over whatever the
/// client put there. Doing it the other way round would let a client's own
/// `requestState` — minted by *us* and verifiable only by us — reach the
/// upstream as though it were the upstream's.
fn modern_outbound_request(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    request: &JsonRpcRequest,
) -> JsonRpcRequest {
    let retargeted = modern::retarget_request_state(
        request.params.as_ref(),
        auth.mrtr_retry_for(upstream.id),
    );
    JsonRpcRequest {
        jsonrpc: request.jsonrpc.clone(),
        id: request.id.clone(),
        method: request.method.clone(),
        params: Some(modern::upgrade_request_params(
            retargeted.as_ref(),
            &auth.upstream_client_capabilities,
            &gateway_implementation(),
            auth.upstream_log_level.as_deref(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn call_cached(
    cache: &Arc<super::cache::CapabilityCache>,
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    request: &JsonRpcRequest,
    mcp_session_id: Option<&str>,
    route_prefix: &str,
) -> Result<(JsonRpcResponse, Option<String>), upstream::UpstreamError> {
    // Which era THIS upstream speaks — independent of the client's. Resolved
    // first because it decides the shape of everything below: a modern
    // upstream takes the `_meta` envelope a legacy one must be spared, holds
    // no session, and answers a different set of methods.
    if resolve_upstream_era(auth, upstream)
        .await?
        .is_modern()
    {
        return call_modern_upstream(cache, auth, upstream, request).await;
    }

    // A modern client's request carries a `_meta` envelope and the MRTR retry
    // fields, none of which a legacy upstream has ever heard of — and one of
    // which (`io.modelcontextprotocol/protocolVersion`) would tell it a
    // revision it did not negotiate. Strip them here, at the single point
    // every upstream call funnels through, so no dispatch arm can forget to.
    let downgraded;
    let request = if auth.era.is_modern() {
        downgraded = JsonRpcRequest {
            jsonrpc: request.jsonrpc.clone(),
            id: request.id.clone(),
            method: request.method.clone(),
            params: modern::downgrade_request_params(request.params.as_ref()),
        };
        &downgraded
    } else {
        request
    };

    // Built-in sentinel: `internal://*` upstream URLs short-circuit the
    // outbound HTTP call and dispatch into a gateway-internal handler. The
    // returned response flows through the rest of the pipeline (capability
    // stamping, audit, etc.) exactly like a real upstream's reply.
    if super::virtual_servers::is_internal(upstream) {
        return super::virtual_servers::dispatch(auth, upstream, request).await;
    }

    // A modern client sends no session id, so the gateway must have opened
    // this upstream connection on its own behalf before any method call can
    // land. Doing it here rather than at the handler makes it impossible to
    // reach an upstream un-handshaken by adding a new dispatch arm.
    let modern_handshake = if auth.era.is_modern() {
        Some(ensure_upstream_connection(auth, upstream).await?)
    } else {
        None
    };

    let upstream_auth = resolve_upstream_auth(auth, upstream).await?;

    // Legacy SSE upstreams bypass the capability cache: the cache key is
    // `(upstream_id, cred_version, method)`, but the persistent SSE channel
    // is per-agent-session, and the response payload races back over a
    // shared upstream socket — caching one agent's `tools/list` reply could
    // leak credentials embedded in tool descriptions to a sibling agent.
    // Same hazard `is_cacheable` already locks out for `PerUserOauth`.
    if matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::Sse
    ) {
        // The legacy-SSE channel is keyed per agent session. A modern client
        // has none, so the gateway's own stable per-(user, virtual server)
        // key stands in — the same key `ensure_upstream_connection` opened the
        // channel with, or the two would address different channels.
        let sse_channel_key: Option<String> = if auth.era.is_modern() {
            Some(modern_upstream_channel_key(auth))
        } else {
            mcp_session_id.map(str::to_string)
        };
        return dispatch_legacy_sse(
            auth,
            upstream,
            upstream_auth,
            request,
            sse_channel_key.as_deref(),
            route_prefix,
        )
        .await;
    }

    // Look up the per-upstream `Mcp-Session-Id` we recorded at this
    // upstream's `initialize`. Without this, every fan-out / per-route
    // call would be stamped with the *first* upstream's session-id (the
    // one the proxy returns to the agent), and any sibling upstream
    // would reject with `-32600 Session not found`. Falls back to the
    // downstream session-id when no mapping exists yet — that path is
    // safe for single-route VS (downstream sid == upstream sid) and for
    // sessions whose `initialize` was handled by a sibling proxy
    // instance (best-effort; the upstream may reject and the agent will
    // re-handshake).

    // The protocol version this upstream negotiated. Clients MUST send it on
    // every request after `initialize` from `2025-06-18` onwards, and this
    // gateway is the client here. `None` — a session whose `initialize` a
    // sibling replica handled — omits the header, which is exactly the
    // pre-`2025-06-18` shape the spec still tolerates.
    let negotiated_version: Option<String> = match &modern_handshake {
        Some(h) => Some(h.protocol_version.clone()),
        None => mcp_session_id
            .and_then(|ds| auth.session_map.protocol_version(auth.tenant_id, ds)),
    };

    let upstream_sid_owned: Option<String> = match &modern_handshake {
        // Modern era: the only session id that exists is the one the gateway
        // itself was issued. `mcp_session_id` is always `None` here (the
        // handler drops the header), and MUST NOT be consulted even if it
        // were not — a modern server neither mints nor echoes session ids.
        Some(h) => h.session_id.clone(),
        None => match mcp_session_id {
            Some(ds) if !ds.is_empty() => auth
                .session_map
                .upstream_session(auth.tenant_id, ds, upstream.id)
                .or_else(|| Some(ds.to_string())),
            _ => None,
        },
    };
    let effective_sid = upstream_sid_owned.as_deref();

    // An upstream with a per-caller input or OAuth token is never cached —
    // see `cache::is_cacheable`.
    let cacheable = super::cache::is_cacheable(upstream)
        && super::cache::is_cacheable_method(&request.method);
    if cacheable {
        let cache_key = super::cache::CacheKey {
            tenant_id: auth.tenant_id,
            upstream_id: upstream.id,
            cred_version: upstream.cred_version,
            method: request.method.clone(),
            // This is the legacy leg; see `CacheKey::upstream_is_modern`.
            upstream_is_modern: false,
        };
        if let Some(mut cached) = cache.get(&cache_key) {
            cached.id = request.id.clone().unwrap_or(RpcId::Null);
            return Ok((cached, None));
        }
        let (resp, sid) =
            upstream::call_with_auth(upstream, &upstream_auth, request, effective_sid, negotiated_version.as_deref())
                .await?;
        if resp.error.is_none() && resp.result.is_some() {
            cache.insert(cache_key, resp.clone());
        }
        record_upstream_session(auth, upstream, mcp_session_id, sid.as_deref(), &modern_handshake);
        note_lost_upstream_session(auth, upstream, &resp, &modern_handshake);
        return Ok((resp, sid));
    }

    let (resp, sid) =
        upstream::call_with_auth(upstream, &upstream_auth, request, effective_sid, negotiated_version.as_deref())
            .await?;
    record_upstream_session(auth, upstream, mcp_session_id, sid.as_deref(), &modern_handshake);
    note_lost_upstream_session(auth, upstream, &resp, &modern_handshake);
    Ok((resp, sid))
}

/// Remember a session id the upstream (re)issued mid-conversation, on
/// whichever map this era keys its sessions in.
fn record_upstream_session(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    mcp_session_id: Option<&str>,
    new_sid: Option<&str>,
    modern_handshake: &Option<super::session::UpstreamHandshake>,
) {
    let Some(new_sid) = new_sid.filter(|s| !s.is_empty()) else {
        return;
    };
    match modern_handshake {
        Some(h) => {
            if h.session_id.as_deref() == Some(new_sid) {
                return;
            }
            // A modern server neither mints nor accepts a session id, so a
            // header from one is noise rather than state. Persisting it would
            // start stamping `Mcp-Session-Id` onto every later request to a
            // server whose spec revision does not define the header — and the
            // handshake's era would silently flip with it.
            if h.era.is_modern() {
                return;
            }
            auth.session_map.set_handshake(
                auth.tenant_id,
                auth.user_id,
                upstream.id,
                inputs_key(auth, upstream),
                super::session::UpstreamHandshake::legacy(
                    Some(new_sid.to_string()),
                    h.capabilities.clone(),
                    h.protocol_version.clone(),
                    h.instructions.clone(),
                ),
            );
        }
        None => {
            if let Some(ds) = mcp_session_id.filter(|s| !s.is_empty()) {
                auth.session_map
                    .set_upstream_session(auth.tenant_id, ds, upstream.id, new_sid);
            }
        }
    }
}

/// Drop a gateway-owned handshake the upstream has told us it no longer holds.
///
/// A legacy upstream sweeps idle sessions on its own clock. When it does, the
/// session id we cached becomes a `-32600`, and because that error is
/// *inside* a 200 response it is not a transport failure anything else would
/// notice — every subsequent call would keep presenting the same dead id and
/// the tool would look permanently broken. Forgetting it makes the next call
/// re-handshake.
///
/// Only the modern path needs this: a legacy client owns its own session and
/// re-handshakes when its client library sees the same error.
fn note_lost_upstream_session(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    resp: &JsonRpcResponse,
    modern_handshake: &Option<super::session::UpstreamHandshake>,
) {
    if modern_handshake.is_none() {
        return;
    }
    let Some(err) = &resp.error else { return };
    // `-32600 Invalid Request` is what the reference implementations return
    // for both "session not found" and "server not initialized"; both mean
    // our handshake is gone. Matching on the code alone rather than on the
    // message keeps this from depending on an upstream's wording.
    if err.code != INVALID_REQUEST {
        return;
    }
    tracing::info!(
        upstream_id = %upstream.id,
        message = %err.message,
        "MCP modern: upstream rejected the gateway session; re-handshaking on next call"
    );
    // Only the legacy slot holds a session to lose; the modern one holds
    // nothing an upstream could tell us it has forgotten.
    auth.session_map.forget_handshake(
        auth.tenant_id,
        auth.user_id,
        upstream.id,
        modern::UpstreamEra::Legacy,
    );
}

/// Dispatch a JSON-RPC request through the per-`(tenant, upstream,
/// agent_session)` legacy SSE session. Returns a one-shot
/// `(JsonRpcResponse, Option<session_id>)` that mirrors the Streamable
/// HTTP contract — server-initiated events that arrive on the GET channel
/// flow to the per-(tenant, user) event bus + `mcp_audit` rows via
/// [`BusAuditEventSink`].
async fn dispatch_legacy_sse(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    upstream_auth: UpstreamAuth,
    request: &JsonRpcRequest,
    mcp_session_id: Option<&str>,
    route_prefix: &str,
) -> Result<(JsonRpcResponse, Option<String>), upstream::UpstreamError> {
    use streamscope_core::config::mcp::McpTransport;
    debug_assert_matches!(upstream.transport, McpTransport::Sse);
    let egress = upstream::MCP_EGRESS;
    if let Err(e) =
        streamscope_mcp_auth::ssrf::check_url_for(&upstream.upstream_url, egress)
    {
        return Err(upstream::UpstreamError::SsrfRefused(e.to_string()));
    }
    // External egress: the SSRF-guarded client pins the resolved IP for every
    // `messages_url` POST (the GET drain fetches its own on each connection).
    // The loopback sampling path keeps the unguarded shared client.
    let client = upstream::guarded_upstream_client(egress);

    // Agent-session-id keys the upstream connection. When the agent omits
    // the header on the first call (initialize), we synthesise one so the
    // session map has a stable key — the response is stamped back on the
    // outbound `Mcp-Session-Id` header so the agent uses it on every
    // subsequent call.
    let agent_session_id = match mcp_session_id {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => Uuid::new_v4().to_string(),
    };

    let proxy_settings = crate::settings::proxy_settings();
    let request_timeout = std::time::Duration::from_millis(
        proxy_settings.mcp_legacy_sse_request_timeout_ms.max(1),
    );
    let reconnect_backoff = std::time::Duration::from_millis(
        proxy_settings.mcp_legacy_sse_reconnect_backoff_ms.max(1),
    );

    let key = super::legacy_sse::SessionKey {
        tenant_id: auth.tenant_id,
        user_id: auth.user_id,
        upstream_id: upstream.id,
        agent_session_id: agent_session_id.clone(),
    };

    let sink: Arc<dyn super::legacy_sse::UpstreamEventSink> = Arc::new(BusAuditEventSink {
        bus: auth.event_bus.clone(),
        audit_tx: auth.mcp_audit_tx.clone(),
        sse_event_tx: auth.mcp_sse_event_tx.clone(),
        sse_seq: auth.sse_seq.clone(),
        tenant_id: auth.tenant_id,
        workspace_id: auth.workspace_id,
        user_id: auth.user_id,
        key_id: auth.key_id,
        virtual_server_id: auth.virtual_server_id,
        upstream_id: upstream.id,
        agent_session_id: Some(agent_session_id.clone()),
        session_map: auth.session_map.clone(),
        route_prefix: route_prefix.to_string(),
    });

    let session = match auth.legacy_sse_map.get_or_open(
        key,
        upstream,
        upstream_auth,
        request_timeout,
        reconnect_backoff,
        sink,
    ) {
        Some(s) => s,
        None => {
            return Err(upstream::UpstreamError::SessionLost(
                "legacy SSE session map at capacity".to_string(),
            ));
        }
    };

    let resp = session.call_request(&client, request).await?;
    Ok((resp, Some(agent_session_id)))
}

/// `legacy_sse::UpstreamEventSink` adapter: forwards upstream-originated
/// JSON-RPC events to the per-(tenant, user) event bus AND emits one
/// `mcp_audit` row per server-initiated request / list_changed
/// notification — same shape the Streamable HTTP per-request stream pump
/// emits, so admin UI surfaces look identical regardless of upstream
/// transport.
/// Make sure the gateway holds a live notification stream to `upstream` for
/// this caller's virtual server, so an announcement with nothing in flight
/// still reaches the bus.
///
/// Returns whether the route can source notifications at all — which is NOT
/// the same as whether a listener came up. A legacy route sources them in-band
/// too, riding an in-flight response, so it stays sourceable however the
/// listener fares; a modern route has no other path, because that era deleted
/// `resources/subscribe` and puts its notifications only on a
/// `subscriptions/listen` stream.
///
/// Best-effort by construction: every failure path returns quietly rather than
/// failing the caller's `subscriptions/listen`, because a listener is an
/// *improvement* to delivery and not the delivery itself.
///
/// Three shapes are skipped. A legacy-SSE upstream already keeps a long-lived
/// channel of its own (`LegacySseSessionMap`), so a second would duplicate
/// every event onto the bus. An `internal://` virtual server is dispatched
/// in-process and pushes nothing. An upstream with a client-filled input
/// cannot be reached without the client's request.
async fn ensure_upstream_listener(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
    route_prefix: &str,
    want: &modern::SubscriptionFilter,
) -> bool {
    use streamscope_core::config::mcp::McpTransport;
    // Neither needs one, and neither is a failure: an `internal://` virtual
    // server is dispatched in-process, and an `sse` upstream already keeps a
    // long-lived channel of its own — a second would duplicate every event
    // onto the bus.
    if super::virtual_servers::is_internal(upstream)
        || matches!(upstream.transport, McpTransport::Sse)
    {
        return true;
    }

    let Ok(era) = resolve_upstream_era(auth, upstream).await else {
        return false;
    };
    // An upstream with a client-filled input is reachable only with a client
    // request behind it: a listener would reconnect long after that request,
    // holding the client's value past it. It gets no listener, so its
    // notifications reach only a request in flight — which a legacy route
    // delivers in-band and a modern one cannot.
    if super::upstream_auth::has_client_inputs(upstream) {
        return !era.is_modern();
    }
    // A LEGACY route can source notifications whether or not this listener
    // comes up: events also reach the bus in-band, riding an in-flight
    // `tools/call` / `prompts/get` response, exactly as they did before
    // listeners existed. Most legacy Streamable-HTTP servers offer no `GET`
    // stream at all and answer `405`, so treating that as "cannot source"
    // would withdraw a capability the gateway has always delivered. Only a
    // MODERN route depends on the listener, because that era has no other
    // path: it deleted `resources/subscribe`, and its notifications exist
    // only on a `subscriptions/listen` stream.
    let sourceable_without_listener = !era.is_modern();
    let Ok(upstream_auth) = resolve_upstream_auth(auth, upstream).await else {
        return sourceable_without_listener;
    };

    let transport = if era.is_modern() {
        super::upstream_listen::ListenTransport::ModernListen {
            // `{}`, not the gateway's usual baseline. A listener reads
            // notifications and can answer nothing, so declaring roots,
            // sampling or elicitation on it would claim a capability that has
            // no channel behind it.
            client_capabilities: serde_json::json!({}),
            client_info: gateway_implementation(),
        }
    } else {
        // A legacy stream is scoped to a session, and the only one the gateway
        // owns is its own — a downstream client's id names a session on the
        // gateway, not on this upstream.
        let Ok(conn) = ensure_upstream_connection(auth, upstream).await
        else {
            return sourceable_without_listener;
        };
        super::upstream_listen::ListenTransport::LegacyGet {
            session_id: conn.session_id.clone(),
            protocol_version: Some(conn.protocol_version.clone()),
        }
    };

    let sink: Arc<dyn super::legacy_sse::UpstreamEventSink> = Arc::new(BusAuditEventSink {
        bus: auth.event_bus.clone(),
        audit_tx: auth.mcp_audit_tx.clone(),
        sse_event_tx: auth.mcp_sse_event_tx.clone(),
        sse_seq: auth.sse_seq.clone(),
        tenant_id: auth.tenant_id,
        workspace_id: auth.workspace_id,
        user_id: auth.user_id,
        key_id: auth.key_id,
        virtual_server_id: auth.virtual_server_id,
        upstream_id: upstream.id,
        // The reverse-path key for anything the upstream asks on this stream.
        // Derived from the authenticated identity, never from the wire: a
        // listener has no request behind it to take a session id from.
        agent_session_id: Some(modern_upstream_channel_key(auth)),
        session_map: auth.session_map.clone(),
        route_prefix: route_prefix.to_string(),
    });

    auth.listeners.ensure(
        super::upstream_listen::ListenRequest {
            key: super::upstream_listen::ListenerKey {
                tenant_id: auth.tenant_id,
                user_id: auth.user_id,
                virtual_server_id: auth.virtual_server_id,
                upstream_id: upstream.id,
                route_prefix: route_prefix.to_string(),
            },
            upstream_url: upstream.upstream_url.clone(),
            upstream_auth,
            inputs_fingerprint: inputs_key(auth, upstream),
            transport,
            filter: want.clone(),
        },
        sink,
    ) || sourceable_without_listener
}

/// The slice of a subscription filter one route can actually serve.
///
/// Resource URIs reach the gateway in the `stsmcp://<prefix>/<b64>` envelope;
/// an upstream has never heard of that and must be asked about its own URI. A
/// URI belonging to a different route is dropped rather than decoded and sent
/// anyway — the upstream would either not know it or, worse, know a resource
/// of its own by that name.
fn route_filter(
    want: &modern::SubscriptionFilter,
    route_prefix: &str,
) -> modern::SubscriptionFilter {
    let mut out = modern::SubscriptionFilter {
        tools_list_changed: want.tools_list_changed,
        prompts_list_changed: want.prompts_list_changed,
        resources_list_changed: want.resources_list_changed,
        resource_subscriptions: Vec::new(),
    };
    for uri in &want.resource_subscriptions {
        if let Ok((prefix, original)) = streamscope_core::mcp::tokens::decode_resource_uri(uri)
            && prefix == route_prefix
        {
            out.resource_subscriptions.push(original);
        }
    }
    out
}

pub(crate) struct BusAuditEventSink {
    bus: Arc<PerUserEventBus>,
    audit_tx: streamscope_core::audit::AuditSender<McpAuditRecord>,
    /// SSE event persistence channel + per-session sequence allocator —
    /// shared with the Streamable-HTTP pump so `Last-Event-ID` replay works
    /// uniformly across transports.
    sse_event_tx: streamscope_core::audit::AuditSender<McpSseEventRecord>,
    sse_seq: Arc<super::sse_seq::McpSseSequenceMap>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    key_id: Option<Uuid>,
    virtual_server_id: Uuid,
    upstream_id: Uuid,
    agent_session_id: Option<String>,
    /// For protocol-version stamping on the rows this sink emits. Same
    /// instance the Streamable HTTP path uses, plumbed through `AuthCtx`.
    session_map: Arc<McpSessionMap>,
    /// Route prefix this upstream is bound to in the originating VS. Used
    /// to rewrite `notifications/resources/updated.params.uri` to the
    /// `stsmcp://<prefix>/<b64>` envelope before publishing to the bus.
    route_prefix: String,
}

impl super::legacy_sse::UpstreamEventSink for BusAuditEventSink {
    fn on_event(&self, payload: serde_json::Value) {
        // Virtualize sampling/elicitation request ids before publishing to
        // the agent's GET channel. Mirrors the Streamable-HTTP SSE pump:
        // any proxy replica decodes the agent's POST response without
        // consulting per-process state. Without this step the agent would
        // see the upstream's raw id, POST it back, and `handle_client_response`
        // would `-32401` because the id has no `ssrid.` prefix.
        let mut payload = payload;
        let original_id_opt = self.agent_session_id.as_deref().and_then(|sid| {
            super::multiplex::virtualize_server_initiated_id_value(
                &mut payload,
                self.upstream_id,
                sid,
                self.tenant_id,
                self.user_id,
            )
        });
        let request_id_virtualized = original_id_opt.is_some();
        // Rewrite `notifications/resources/updated.params.uri` to the
        // `stsmcp://<route_prefix>/<b64>` envelope before classify so the
        // bus + audit see the agent-facing URI.
        super::multiplex::rewrite_resource_updated_uri_value(&mut payload, &self.route_prefix);
        // Re-classify after the (possibly mutated) id / uri so the rpc_id
        // captured for audit / publish-gate checks matches what the wire
        // carries.
        let kind = super::multiplex::classify_value(&payload);
        let publish = matches!(
            kind,
            super::multiplex::EventKind::Sampling { .. }
                | super::multiplex::EventKind::Elicitation { .. }
                | super::multiplex::EventKind::ListChanged { .. }
                | super::multiplex::EventKind::ResourceUpdated { .. }
                | super::multiplex::EventKind::ElicitationComplete { .. }
        );
        if publish
            && let Ok(raw) = serde_json::to_string(&payload)
        {
            // Mint a stable `ssevt.…` event id so a `Last-Event-ID` reconnect
            // can resume from any proxy replica. Same shape as the
            // Streamable-HTTP pump above; the `id:` line is embedded in the
            // synthetic frame so the bus consumer (and persistence row)
            // carries it byte-identical.
            let mut id_line = String::new();
            let mut sse_record: Option<streamscope_core::mcp::sse_events::McpSseEventRecord> = None;
            if let Some(sid) = self.agent_session_id.as_deref() {
                let seq = self.sse_seq.next(self.tenant_id, sid);
                if let Ok(token) = streamscope_core::mcp::tokens::encode_event_id(
                    self.tenant_id,
                    self.user_id,
                    sid,
                    seq,
                ) {
                    id_line = format!("id: {token}\n");
                    let frame_bytes_for_persist =
                        format!("event: notification\n{id_line}data: {raw}\n\n").into_bytes();
                    sse_record = Some(streamscope_core::mcp::sse_events::McpSseEventRecord {
                        tenant_id: self.tenant_id,
                        user_id: self.user_id,
                        mcp_session_id: sid.to_string(),
                        virtual_server_id: Some(self.virtual_server_id),
                        event_id: token,
                        sequence: seq as i64,
                        event_data: frame_bytes_for_persist,
                        created_at: chrono::Utc::now(),
                    });
                }
            }
            let frame = format!("event: notification\n{id_line}data: {raw}\n\n");
            self.bus.publish(
                self.tenant_id,
                self.user_id,
                self.virtual_server_id,
                UserEvent(bytes::Bytes::from(frame.into_bytes())),
            );
            if let Some(record) = sse_record
                && let Err(err) = self.sse_event_tx.try_send(record)
            {
                tracing::debug!(error = %err, "mcp sse event tx full; legacy-SSE event drop (replay best-effort)");
            }
        }
        // Audit rows: build the McpAuditRecord inline (sync) and try_send
        // — the audit mpsc is bounded; spawning a task per event to
        // `await` send() would pile up indefinitely against a stuck
        // consumer. Drop + log on Full is the same best-effort semantics
        // the LLM audit pipeline uses. For sampling/elicitation rows we
        // record the **original** upstream-minted rpc_id (recovered above),
        // not the virtualized token, so audit pivots stay clean.
        let record_opt = match &kind {
            super::multiplex::EventKind::Sampling { rpc_id } => {
                let audit_id = original_id_opt.as_ref().unwrap_or(rpc_id);
                Some(self.build_audit_record(
                    "sampling/createMessage",
                    Some(audit_id),
                    None,
                    None,
                    request_id_virtualized,
                ))
            }
            super::multiplex::EventKind::Elicitation { rpc_id } => {
                let audit_id = original_id_opt.as_ref().unwrap_or(rpc_id);
                Some(self.build_audit_record(
                    "elicitation/create",
                    Some(audit_id),
                    None,
                    None,
                    request_id_virtualized,
                ))
            }
            super::multiplex::EventKind::ListChanged { which } => Some(self.build_audit_record(
                which.method(),
                None,
                Some(*which),
                None,
                false,
            )),
            super::multiplex::EventKind::ElicitationComplete { elicitation_id } => {
                Some(self.build_audit_record(
                    "notifications/elicitation/complete",
                    None,
                    None,
                    elicitation_id.as_deref(),
                    false,
                ))
            }
            super::multiplex::EventKind::LogNotification { level, logger } => {
                tracing::debug!(
                    upstream_id = %self.upstream_id,
                    level = ?level,
                    logger = ?logger,
                    "legacy SSE upstream log notification"
                );
                None
            }
            super::multiplex::EventKind::ResourceUpdated { uri } => {
                // High-cardinality, low-signal — no audit row. The bus
                // publish above carries the (already URI-rewritten)
                // notification to any GET-channel subscriber.
                tracing::debug!(
                    upstream_id = %self.upstream_id,
                    uri = ?uri,
                    "legacy SSE upstream resource updated"
                );
                None
            }
            super::multiplex::EventKind::Passthrough => None,
        };
        if let Some(record) = record_opt
            && let Err(e) = self.audit_tx.try_send(record)
        {
            tracing::warn!(error = %e, "legacy SSE audit drop (channel full or closed)");
        }
    }
}

impl BusAuditEventSink {
    /// Build a `McpAuditRecord` matching the shape the Streamable HTTP
    /// per-request stream pump emits (server-initiated requests carry
    /// `mcp_server_initiated`; list_changed notifications carry
    /// `mcp_list_changed`). Inline so `try_send` can be used directly,
    /// avoiding the per-event tokio::spawn that would queue against a
    /// stuck audit consumer.
    fn build_audit_record(
        &self,
        method: &str,
        sampling_rpc_id: Option<&serde_json::Value>,
        list_changed: Option<super::multiplex::ListChangedKind>,
        elicitation_id: Option<&str>,
        request_id_virtualized: bool,
    ) -> McpAuditRecord {
        let now = chrono::Utc::now();
        let session_id_hashed = self.agent_session_id.as_ref().map(|raw| {
            // user_id (not key_id) — see `session_id_from_client` doc.
            streamscope_core::proxy::content::session_id_from_client(
                raw,
                self.tenant_id,
                self.user_id,
            )
        });
        let mut diff = serde_json::Map::new();
        if let Some(rpc_id) = sampling_rpc_id {
            diff.insert(
                "mcp_server_initiated".into(),
                serde_json::json!({"rpc_id": rpc_id, "method": method}),
            );
        }
        if request_id_virtualized {
            diff.insert(
                "mcp_virtualization".into(),
                serde_json::json!({ "request_id": "encoded" }),
            );
        }
        if let Some(which) = list_changed {
            diff.insert(
                "mcp_list_changed".into(),
                serde_json::json!({"kind": match which {
                    super::multiplex::ListChangedKind::Tools => "tools",
                    super::multiplex::ListChangedKind::Resources => "resources",
                    super::multiplex::ListChangedKind::Prompts => "prompts",
                }}),
            );
        }
        if let Some(eid) = elicitation_id {
            diff.insert(
                "mcp_elicitation_complete".into(),
                serde_json::json!({"elicitation_id": eid}),
            );
        }
        diff.insert("transport".into(), serde_json::json!("sse"));
        let pv = self.agent_session_id.as_deref().and_then(|sid| {
            self.session_map.protocol_version(self.tenant_id, sid)
        });
        McpAuditRecord {
            request_id: streamscope_core::ids::mint_request_id(),
            timestamp: now,
            tenant_id: self.tenant_id,
            workspace_id: self.workspace_id,
            user_id: self.user_id,
            key_id: self.key_id,
            app_id: None,
            session_id: session_id_hashed,
            user_agent: None,
            ip: None,
            detection_method: None,
            latency_total_ms: 0,
            status_code: Some(200),
            error_category: None,
            error_detail: None,
            limit_bucket: None,
            virtual_server_id: self.virtual_server_id,
            upstream_server_id: Some(self.upstream_id),
            mcp_session_id: self.agent_session_id.clone(),
            method: method.to_string(),
            tool_id: None,
            prompt_id: None,
            resource_uri: None,
            params: None,
            result: None,
            error_code: None,
            error_message: None,
            upstream_latency_ms: 0,
            request_bytes: None,
            response_bytes: None,
            protocol_version: pv,
            // The whole sink is the legacy `text/event-stream` GET path —
            // every row carries the `mcp_legacy_sse` chip so operators can
            // see at a glance which upstreams haven't migrated to
            // Streamable HTTP.
            badges: vec![streamscope_core::audit::AuditBadge::McpLegacySse],
            transform_diff: serde_json::Value::Object(diff),
        }
    }
}

/// True if the caller can call this upstream right now: every required user
/// input is filled and every required client header was sent on this request,
/// and on a `per_user_oauth` upstream the user holds a stored credential.
/// Used by the aggregated calls (`tools/list` fan-out and its siblings) to
/// hide such an upstream, so its tools never appear broken; a direct call to
/// it reports what is missing instead.
fn user_has_credential_for(
    auth: &AuthCtx,
    upstream: &streamscope_core::config::mcp::McpUpstreamServer,
) -> bool {
    use streamscope_core::config::mcp::McpAuthMode;
    if auth.inputs_memo.lacks_caller_inputs(
        upstream,
        auth.mcp_config.user_inputs(auth.user_id, upstream.id),
        &auth.client_inputs,
    ) {
        return false;
    }
    match upstream.auth_mode {
        McpAuthMode::Headers => true,
        McpAuthMode::PerUserOauth => auth
            .oauth_state
            .lookup(
                auth.tenant_id,
                auth.user_id,
                upstream.id,
                auth.mcp_config.user_credential(auth.user_id, upstream.id),
            )
            .is_some(),
    }
}

/// Whether the caller can call at least one of `routes` — the condition for
/// modern discovery to skip the routes it cannot, and for an aggregated list
/// to hide them: when none is callable, the error (connect in the portal, send
/// the header) reaches the client instead of an empty answer.
fn some_route_is_callable(
    auth: &AuthCtx,
    routes: &[streamscope_core::config::mcp::McpVirtualRoute],
    upstreams: &[streamscope_core::config::mcp::McpUpstreamServer],
) -> bool {
    routes.iter().any(|r| {
        upstreams
            .iter()
            .find(|u| u.id == r.upstream_server_id)
            .is_some_and(|u| user_has_credential_for(auth, u))
    })
}

/// The refusal for a pass-through (`vk-`) key on a virtual server it may not
/// reach ([`super::upstream_auth::pass_through_only`]).
fn pass_through_refusal_message() -> &'static str {
    "a pass-through key reaches only a virtual server whose every upstream takes just the client's \
     own Authorization header; use a gateway key"
}

/// The `-32401` message for a virtual server reached on `/mcp/<slug>` whose
/// routed upstream takes the client's own `Authorization` header.
fn fwd_mount_required_message(slug: &str) -> String {
    format!(
        "this virtual server forwards the client's own Authorization header to its upstream: \
         call it at /fwd/<gateway-key>/mcp/{slug}"
    )
}

/// Map an `AppError` from `resolve_identity` to a `(status, wire_message,
/// audit_detail)` triple. The wire message is intentionally generic
/// ("unauthorized") for every failure mode so a probing client can't
/// distinguish "key exists but wrong family" from "invalid key" /
/// "revoked" / "expired" / "missing header"; the fine-grained reason is
/// captured separately on the audit row.
fn auth_error_for_response(e: &AppError) -> (StatusCode, &'static str, String) {
    // Workspace-allowlist denials are a genuine 403 (the server exists, this
    // workspace just can't reach it); everything else stays a generic 401 so a
    // probing client can't distinguish a wrong/non-existent key.
    let (status, wire_message, audit_detail) = match e {
        AppError::Auth(AuthError::WorkspaceMcpAccessDenied { .. }) => {
            (StatusCode::FORBIDDEN, "forbidden", "workspace access denied")
        }
        AppError::Auth(AuthError::MissingHeader) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "missing authorization")
        }
        AppError::Auth(AuthError::InvalidKey(_)) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "invalid key")
        }
        AppError::Auth(AuthError::KeyRevoked(_)) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "key revoked")
        }
        AppError::Auth(AuthError::KeyExpired(_)) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "key expired")
        }
        AppError::Auth(AuthError::UnrecognizedFormat(_)) => {
            (StatusCode::UNAUTHORIZED, "unauthorized", "unrecognized credential")
        }
        AppError::Auth(AuthError::Forbidden(_)) => {
            (StatusCode::FORBIDDEN, "forbidden", "forbidden")
        }
        // The gateway could not decide, which is not the same as deciding
        // "no". A 401 here carries `WWW-Authenticate`, so a conforming client
        // reads it as "your token is bad", discards a perfectly good one and
        // re-runs the whole authorization dance — against an authorization
        // server that is failing for the same reason this request did. 503
        // says what actually happened and is retryable.
        AppError::Auth(AuthError::ServiceUnavailable(_) | AuthError::Cache(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "service unavailable",
            "authentication temporarily unavailable",
        ),
        _ => (StatusCode::UNAUTHORIZED, "unauthorized", "unauthorized"),
    };
    (status, wire_message, audit_detail.to_string())
}

/// Emit an audit row for a request that was rejected at auth — no identity
/// resolved, so we record the SYSTEM tenant + nil user_id. The slug is
/// intentionally dropped since the key never proved tenant ownership.
async fn emit_unauthenticated_audit(
    state: &McpRouterState,
    request_id: Uuid,
    started: Instant,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
    error_message: Option<String>,
    status: StatusCode,
) {
    let now = chrono::Utc::now();
    let total_ms = started.elapsed().as_millis() as u64;
    let record = McpAuditRecord {
        request_id,
        timestamp: now,
        tenant_id: streamscope_core::config::TenantId::SYSTEM.0,
        // SYSTEM-tenant audit (no customer workspace).
        workspace_id: Uuid::nil(),
        user_id: Uuid::nil(),
        key_id: None,
        app_id: None,
        session_id: None,
        user_agent,
        ip: None,
        detection_method: None,
        latency_total_ms: total_ms,
        status_code: Some(status.as_u16()),
        error_category: Some("auth".to_string()),
        error_detail: error_message.clone(),
        limit_bucket: None,
        virtual_server_id: Uuid::nil(),
        upstream_server_id: None,
        mcp_session_id,
        method: "<unauthenticated>".to_string(),
        tool_id: None,
        prompt_id: None,
        resource_uri: None,
        params: None,
        result: None,
        error_code: Some(AUTH_REQUIRED),
        error_message,
        upstream_latency_ms: 0,
        request_bytes: None,
        response_bytes: None,
        protocol_version: None,
        // Stamps `mcp_rpc_error` so the audit drawer surfaces the
        // -32401 chip the same way as any other RPC failure.
        badges: build_mcp_audit_badges(None, Some(AUTH_REQUIRED)),
        transform_diff: serde_json::Value::Object(Default::default()),
    };
    if let Err(e) = state.mcp.mcp_audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed (auth path): {e}");
    }
}

/// Map a rate-limit / budget `AppError` to a 429 response with the matching
/// audit row. Mirrors the LLM proxy's rate-limit shape.
#[allow(clippy::too_many_arguments)]
async fn rate_limited_response(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    slug: &str,
    request: &JsonRpcRequest,
    virtual_server: &McpVirtualServer,
    started: Instant,
    request_bytes: i32,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
    err: AppError,
) -> Response<Body> {
    let (rpc_code, http_status, msg): (i32, StatusCode, String) = match &err {
        AppError::RateLimited { message, .. } | AppError::BudgetExceeded { message, .. } => {
            (RATE_LIMITED, StatusCode::TOO_MANY_REQUESTS, message.clone())
        }
        // The rate-limit checks only ever raise the two variants above, so this
        // arm is unreachable today. It is `INTERNAL_ERROR` rather than the
        // `-32099` it used to be because that code sits inside the band MCP
        // 2026-07-28 reserves for the specification, where an implementation
        // MUST NOT emit anything the spec has not defined. Unreachable is one
        // refactor away from reachable, and this is a MUST.
        _ => (INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    // Which limit refused, on the wire (`error.data.bucket`, the JSON-RPC
    // counterpart of the HTTP error body's `bucket`) and on the audit row.
    let bucket = err.limit_bucket();
    let id = request.id.clone().unwrap_or(RpcId::Null);
    let body = match bucket {
        Some(b) => JsonRpcResponse::err_with_data(id, rpc_code, msg.clone(), serde_json::json!({ "bucket": b.as_str() })),
        None => JsonRpcResponse::err(id, rpc_code, msg.clone()),
    };
    let resp = rpc_error_response(http_status, &body);
    emit_audit_with_policy(
        state,
        identity,
        request_id,
        slug,
        Some(virtual_server.id),
        None,
        request.method.clone(),
        None,
        None,
        None,
        Some(rpc_code),
        Some(msg),
        started,
        Instant::now(),
        request_bytes,
        0,
        user_agent,
        mcp_session_id,
        http_status,
        None, // policy_classification
        None, // app_id
        None, // detection_method
        None, // params
        None, // result
        bucket,
    )
    .await;
    resp
}

#[allow(clippy::too_many_arguments)]
/// Cap a JSON-RPC `params` / `result` payload before it lands on the
/// audit row. A misbehaving upstream that returns a multi-MB `result`
/// would otherwise blow up the audit-list response size linearly with
/// `LIMIT` — and the edge's ingest requests with it. Over the
/// configured cap we substitute a `{_stripped, size_bytes, reason}`
/// marker (mirrors the "Nothing is silently discarded" pattern used by
/// the media-blob extractor: never blank the field, always leave a
/// breadcrumb).
fn cap_audit_payload(value: Option<serde_json::Value>) -> Option<serde_json::Value> {
    let v = value?;
    let max = crate::settings::proxy_settings().mcp_audit_payload_max_bytes;
    let serialised = match serde_json::to_vec(&v) {
        Ok(b) => b,
        Err(_) => return Some(v),
    };
    if serialised.len() <= max {
        return Some(v);
    }
    Some(serde_json::json!({
        "_stripped": true,
        "size_bytes": serialised.len(),
        "reason": "oversized",
        "limit_bytes": max,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn emit_audit(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    slug: &str,
    virtual_server_id: Option<Uuid>,
    upstream_server_id: Option<Uuid>,
    method: String,
    tool_id: Option<String>,
    prompt_id: Option<String>,
    resource_uri: Option<String>,
    error_code: Option<i32>,
    error_message: Option<String>,
    started: Instant,
    dispatch_started: Instant,
    request_bytes: i32,
    response_bytes: i32,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
    status: StatusCode,
    detection_method: Option<String>,
) {
    emit_audit_with_policy(
        state,
        identity,
        request_id,
        slug,
        virtual_server_id,
        upstream_server_id,
        method,
        tool_id,
        prompt_id,
        resource_uri,
        error_code,
        error_message,
        started,
        dispatch_started,
        request_bytes,
        response_bytes,
        user_agent,
        mcp_session_id,
        status,
        None,             // policy_classification
        None,             // app_id
        detection_method, // detection_method
        None,             // params
        None,             // result,
        None, // limit_bucket
    )
    .await;
}

/// Build the per-record badge vector from policy classification + JSON-RPC
/// error code. Mirrors the LLM proxy's `BadgeBuilder` flow for the MCP
/// signals operators care about today:
///
/// - **`tool_blocked`** — fires when policy action == `"block"`. Reuses the
///   shared LLM badge variant so the UI's `BADGE_REGISTRY` rendering is one
///   path. Phase is hard-coded to `Request` because the MCP gateway only
///   runs the policy gate before dispatch — if a future response-phase MCP
///   policy lands, this assumption needs revisiting.
/// - **`web_blocked`** — additional specialised chip emitted alongside
///   `tool_blocked` when the blocked tool's canonical id is `web_search` or
///   `web_fetch`, so the audit drawer can render the web-search domain icon
///   without re-parsing the tool name.
/// - **`mcp_rpc_error`** — fires whenever the audit row carries any JSON-RPC
///   error code (`-32xxx`). Tooltip in the UI registry resolves the code to
///   a human-readable label.
fn build_mcp_audit_badges(
    policy: Option<&streamscope_core::config::tool_rules::RiskResult>,
    error_code: Option<i32>,
) -> Vec<streamscope_core::audit::AuditBadge> {
    let mut bb = streamscope_core::audit::BadgeBuilder::new();
    let web_blocked = if let Some(rc) = policy
        && rc.action == "block"
    {
        // Prefer the canonical tool_id; fall back to the rule id so the
        // tooltip carries SOMETHING actionable when no profile resolved.
        let label = rc
            .tool_id
            .clone()
            .or_else(|| rc.id.clone())
            .unwrap_or_else(|| "<unresolved>".to_string());
        bb.add_tool_blocked(streamscope_core::audit::Phase::Request, label);
        matches!(rc.tool_id.as_deref(), Some("web_search" | "web_fetch"))
    } else {
        false
    };
    if let Some(code) = error_code {
        bb.add_mcp_rpc_error(code);
    }
    let mut badges = bb.finish();
    // The shared LLM/MCP BadgeBuilder intentionally drops WebBlocked
    // into the executor-row bucket — append it to the mcp_audit vector by
    // hand so it lands next to the generic ToolBlocked chip on a blocked
    // tools/call audit row.
    if web_blocked {
        badges.push(streamscope_core::audit::AuditBadge::WebBlocked);
    }
    badges
}

/// Audit emit that also captures a [`RiskResult`] from policy
/// evaluation and the resolved `app_id`. The classification rides on
/// `transform_diff.policy_classification` (a typed object the admin UI can
/// destructure for tool-blocked banners and chips); the app_id rides on
/// the `app_id` audit column the same way the LLM path uses it.
#[allow(clippy::too_many_arguments)]
async fn emit_audit_with_policy(
    state: &McpRouterState,
    identity: &Identity,
    request_id: Uuid,
    _slug: &str,
    virtual_server_id: Option<Uuid>,
    upstream_server_id: Option<Uuid>,
    method: String,
    tool_id: Option<String>,
    prompt_id: Option<String>,
    resource_uri: Option<String>,
    error_code: Option<i32>,
    error_message: Option<String>,
    started: Instant,
    dispatch_started: Instant,
    request_bytes: i32,
    response_bytes: i32,
    user_agent: Option<String>,
    mcp_session_id: Option<String>,
    status: StatusCode,
    policy_classification: Option<streamscope_core::config::tool_rules::RiskResult>,
    app_id: Option<String>,
    // Three-tier app detection method ("header" | "referer" | "user_agent")
    // from `extract_attribution`. Lands on `gateway_audit.detection_method`
    // for parity with the LLM path.
    detection_method: Option<String>,
    // `params` carries the JSON-RPC `params` from the inbound request —
    // persisted to `mcp_audit.params` so the audit drawer + session-view
    // bubble render the actual call body. Pass `None` only on synthetic
    // rows that had no inbound request (auth-fail / rate-limit).
    // `result` carries the upstream's JSON-RPC `result` on success;
    // pass `None` on every error path and on result-less success.
    params: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    // The limit bucket that refused the call, on a rate-limit / budget
    // refusal — lands on `gateway_audit.limit_bucket` like the LLM path's.
    limit_bucket: Option<streamscope_core::middleware::rate_limit::LimitBucket>,
) {
    let vs_id = virtual_server_id.unwrap_or(Uuid::nil());
    let now = chrono::Utc::now();
    let total_ms = started.elapsed().as_millis() as u64;
    let upstream_ms = dispatch_started.elapsed().as_millis() as u64;

    let session_id_hashed = mcp_session_id.as_ref().map(|raw| {
        // user_id (not key_id) — see `session_id_from_client` doc.
        streamscope_core::proxy::content::session_id_from_client(
            raw,
            identity.tenant_id,
            identity.user_id,
        )
    });

    // Negotiated MCP protocol version, captured at `initialize` time and
    // pinned on the session map. Falls back to the spec default when this
    // session's `initialize` happened on a sibling instance (or hasn't yet).
    // The version negotiated with the upstream is authoritative when there was
    // a handshake to negotiate it. A modern client performs none, and a legacy
    // session whose `initialize` landed on a sibling replica has none recorded
    // here either — in both cases what the client declared is the honest
    // second-best, and reporting nothing is the worst of the three.
    let protocol_version = mcp_session_id
        .as_deref()
        .and_then(|sid| state.mcp.session_map.protocol_version(identity.tenant_id, sid))
        .or_else(|| identity.declared_protocol_version.clone());

    // Build transform_diff from the classification (if any). A bare allow
    // result with no rule id is dropped — there's nothing operator-visible
    // to surface.
    let transform_diff = match policy_classification.as_ref() {
        Some(r) if r.id.is_some() || r.action != "allow" => {
            serde_json::json!({
                "policy_classification": {
                    "rule_id": r.id,
                    "risk": r.risk,
                    "title": r.title,
                    "description": r.description,
                    "action": r.action,
                    "tool_id": r.tool_id,
                    "profile_id": r.profile_id,
                }
            })
        }
        _ => serde_json::Value::Object(Default::default()),
    };

    let badges = build_mcp_audit_badges(policy_classification.as_ref(), error_code);

    let record = McpAuditRecord {
        request_id,
        timestamp: now,
        tenant_id: identity.tenant_id,
        workspace_id: identity.user.workspace_id,
        user_id: identity.user_id,
        key_id: identity.key_id,
        app_id,
        session_id: session_id_hashed,
        user_agent,
        ip: None,
        detection_method,
        latency_total_ms: total_ms,
        status_code: Some(status.as_u16()),
        error_category: error_code.is_some().then(|| "rpc_error".to_string()),
        error_detail: error_message.clone(),
        virtual_server_id: vs_id,
        upstream_server_id,
        mcp_session_id,
        method,
        tool_id,
        prompt_id,
        resource_uri,
        params: cap_audit_payload(params),
        result: cap_audit_payload(result),
        error_code,
        error_message,
        upstream_latency_ms: upstream_ms,
        request_bytes: Some(request_bytes),
        response_bytes: Some(response_bytes),
        protocol_version,
        badges,
        transform_diff,
        limit_bucket: limit_bucket.map(|b| b.as_str().to_string()),
    };

    if let Err(e) = state.mcp.mcp_audit_tx.send(record).await {
        tracing::error!("mcp audit channel send failed: {e}");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Unit tests for the transport-validation helpers (`validate_origin_header`,
// `resolve_protocol_era`, `validate_era_body`). These are pure functions over
// a `HeaderMap` and a parsed body, so they're cheap to test in isolation —
// the surrounding axum handlers are E2E-only because they require the full
// proxy + admin-api + DB stack.
//
// `mcp_delete_handler` is also exercised at the E2E layer (`test_mcp_transport.py`).
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    // `validate_origin_header` is per-tenant — it requires an
    // `AppState` with a populated `tenant_registry` to look up the slug's
    // tenant + resolved `proxy_public_url`. Behaviour is exercised in the
    // E2E suite (`test_mcp_transport.py`) where a real tenant snapshot
    // is in place.

    #[test]
    fn a_missing_version_header_resolves_to_the_legacy_default() {
        let h = header_map(&[]);
        let era = resolve_protocol_era(&h).expect("missing header is allowed");
        assert_eq!(era, ProtocolEra::Legacy(
            crate::settings::MCP_DEFAULT_PROTOCOL_VERSION.to_string()
        ));
    }

    #[test]
    fn every_supported_version_resolves_to_its_own_era() {
        for v in crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS {
            let h = header_map(&[("mcp-protocol-version", v)]);
            let era = resolve_protocol_era(&h)
                .unwrap_or_else(|_| panic!("supported version {v} must be accepted"));
            assert_eq!(era.version(), *v);
            assert_eq!(
                era.is_modern(),
                modern::is_modern(v),
                "{v} resolved to the wrong era"
            );
        }
    }

    /// The set must contain exactly one modern revision today, and the legacy
    /// ones must not drift into the modern era by accident — an era
    /// misclassification would serve a legacy client stateless semantics it
    /// cannot parse, or a modern client a handshake it will never send.
    #[test]
    fn the_era_split_is_where_it_should_be() {
        let h = header_map(&[("mcp-protocol-version", "2026-07-28")]);
        assert!(resolve_protocol_era(&h).unwrap().is_modern());
        for v in ["2025-11-25", "2025-06-18", "2025-03-26"] {
            let h = header_map(&[("mcp-protocol-version", v)]);
            assert!(!resolve_protocol_era(&h).unwrap().is_modern(), "{v}");
        }
    }

    /// Spec compatibility: per § Protocol Version Header, servers SHOULD
    /// assume `2025-03-26` when the header is missing.
    /// `MCP_DEFAULT_PROTOCOL_VERSION` documents that constant; the
    /// supported-versions list MUST include it so that absent / present-as-
    /// default header both pass validation.
    #[test]
    fn default_protocol_version_is_in_supported_set() {
        assert!(
            crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS
                .contains(&crate::settings::MCP_DEFAULT_PROTOCOL_VERSION),
            "spec compat clause requires {} to be acceptable",
            crate::settings::MCP_DEFAULT_PROTOCOL_VERSION
        );
    }

    /// The version the gateway asks an upstream for must be one it can also
    /// serve, and must be LEGACY: it is sent in an `initialize`, which only
    /// the legacy era has.
    #[test]
    fn the_gateway_upstream_version_is_a_supported_legacy_one() {
        let v = crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION;
        assert!(crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS.contains(&v));
        assert!(!modern::is_modern(v), "{v} must be a legacy revision");
    }

    #[test]
    fn an_unknown_version_is_refused_with_the_list_to_retry_from() {
        let h = header_map(&[("mcp-protocol-version", "1999-12-31")]);
        let err = resolve_protocol_era(&h).expect_err("unsupported version must be rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, modern::UNSUPPORTED_PROTOCOL_VERSION);
        let data = err.data.expect("must name what we do support");
        assert_eq!(data["requested"], "1999-12-31");
        assert_eq!(
            data["supported"].as_array().unwrap().len(),
            crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS.len()
        );
    }

    #[test]
    fn an_empty_version_header_is_treated_as_absent() {
        // The spec is silent on empty values — treat them like missing.
        let h = header_map(&[("mcp-protocol-version", "")]);
        assert_eq!(
            resolve_protocol_era(&h).unwrap(),
            ProtocolEra::Legacy(crate::settings::MCP_DEFAULT_PROTOCOL_VERSION.to_string())
        );
    }

    // ── body/era agreement ───────────────────────────────────────────────

    fn modern_request(method: &str, mut params: serde_json::Value) -> InboundMessage {
        if let Some(o) = params.as_object_mut() {
            o.insert(
                "_meta".into(),
                serde_json::json!({
                    modern::META_PROTOCOL_VERSION: modern::MODERN_PROTOCOL_VERSION,
                    modern::META_CLIENT_CAPABILITIES: {},
                }),
            );
        }
        InboundMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(RpcId::Number(1.into())),
            method: method.into(),
            params: Some(params),
        })
    }

    #[test]
    fn a_well_formed_modern_request_yields_its_meta() {
        let era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        let msg = modern_request("tools/list", serde_json::json!({}));
        let h = header_map(&[("mcp-method", "tools/list")]);
        let meta = validate_era_body(&era, &h, &msg)
            .expect("a conforming request must pass")
            .expect("a modern request carries meta");
        assert_eq!(meta.protocol_version, modern::MODERN_PROTOCOL_VERSION);
    }

    /// A modern client that omits the header would otherwise be served legacy
    /// semantics in silence — losing `resultType`, the freshness hints and
    /// the MRTR bridge with nothing reporting a problem.
    #[test]
    fn modern_body_without_the_header_is_a_header_mismatch() {
        let era = ProtocolEra::Legacy(crate::settings::MCP_DEFAULT_PROTOCOL_VERSION.to_string());
        let msg = modern_request("tools/list", serde_json::json!({}));
        let h = header_map(&[("mcp-method", "tools/list")]);
        let err = validate_era_body(&era, &h, &msg).unwrap_err();
        assert_eq!(err.code, modern::HEADER_MISMATCH);
    }

    #[test]
    fn a_header_and_body_that_name_different_versions_are_refused() {
        let era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        let msg = InboundMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(RpcId::Number(1.into())),
            method: "tools/list".into(),
            params: Some(serde_json::json!({"_meta": {
                modern::META_PROTOCOL_VERSION: "2025-11-25",
                modern::META_CLIENT_CAPABILITIES: {},
            }})),
        });
        let h = header_map(&[("mcp-method", "tools/list")]);
        let err = validate_era_body(&era, &h, &msg).unwrap_err();
        assert_eq!(err.code, modern::HEADER_MISMATCH);
    }

    #[test]
    fn a_removed_method_is_a_404_in_the_modern_era_and_fine_in_the_legacy_one() {
        let modern_era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        let legacy_era = ProtocolEra::Legacy("2025-11-25".into());
        for method in ["initialize", "ping", "logging/setLevel", "resources/subscribe"] {
            let msg = modern_request(method, serde_json::json!({}));
            let h = header_map(&[("mcp-method", method)]);
            let err = validate_era_body(&modern_era, &h, &msg).unwrap_err();
            assert_eq!(err.code, METHOD_NOT_FOUND, "{method}");
            assert_eq!(err.status, StatusCode::NOT_FOUND, "{method}");

            // Positive control: the same method is ordinary legacy traffic.
            // Without this the assertion above would keep passing if the
            // gateway stopped serving these to legacy clients too.
            let legacy = InboundMessage::Request(JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(RpcId::Number(1.into())),
                method: method.into(),
                params: Some(serde_json::json!({})),
            });
            assert!(validate_era_body(&legacy_era, &h, &legacy).is_ok(), "{method}");
        }
    }

    #[test]
    fn a_client_response_has_no_meaning_in_the_modern_era() {
        // Server-initiated requests are gone, so nothing a client response
        // could answer exists. Accepting one would route it into the legacy
        // reverse path no modern client could have opened.
        let era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        let msg = InboundMessage::Response(JsonRpcResponse::ok(
            RpcId::Number(1.into()),
            serde_json::json!({}),
        ));
        let err = validate_era_body(&era, &header_map(&[]), &msg).unwrap_err();
        assert_eq!(err.code, INVALID_REQUEST);
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_notification_is_not_header_validated_but_a_removed_one_is_refused() {
        let era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        let live = InboundMessage::Notification(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/cancelled".into(),
            params: None,
        });
        // No `Mcp-Method` header, and no `_meta`: § Sending Messages leaves
        // notification headers undefined, so this must still pass.
        assert!(validate_era_body(&era, &header_map(&[]), &live).unwrap().is_none());

        for gone in ["notifications/initialized", "notifications/roots/list_changed"] {
            let msg = InboundMessage::Notification(JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: None,
                method: gone.into(),
                params: None,
            });
            let err = validate_era_body(&era, &header_map(&[]), &msg).unwrap_err();
            assert_eq!(err.code, INVALID_REQUEST, "{gone}");
        }
    }

    #[test]
    fn a_legacy_request_is_never_header_validated() {
        // Legacy clients predate the mirrored headers entirely; requiring
        // them would break every client on a supported revision.
        let era = ProtocolEra::Legacy("2025-11-25".into());
        let msg = InboundMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(RpcId::Number(1.into())),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "x"})),
        });
        assert!(validate_era_body(&era, &header_map(&[]), &msg).unwrap().is_none());
    }

    // ── era probe: which HTTP statuses carry a verdict ───────────────────

    #[test]
    fn a_status_that_answers_a_different_question_is_no_era_verdict() {
        // Each of these is an answer to something other than "which era do
        // you speak": a credential challenge, a proxy throttle, a load
        // balancer with nothing behind it yet. Reading one as "legacy" and
        // caching it leaves a modern-only upstream mis-addressed for the
        // whole idle window — every call failing at a handshake that server
        // deleted, seconds after the blip cleared.
        for status in [401, 403, 407, 408, 429] {
            assert!(status_answers_nothing_about_era(status), "{status}");
        }
        // The 5xx boundary, both sides. 499 is a client-side class and says
        // the origin answered; 500 is the first status that does not.
        assert!(!status_answers_nothing_about_era(499));
        assert!(status_answers_nothing_about_era(500));
        assert!(status_answers_nothing_about_era(503));
        // `501 Not Implemented` is deliberately INSIDE the 5xx class rather
        // than carved out as a routing refusal. From an origin it would be a
        // verdict; from an intermediary it is a server error, and nothing in
        // the response distinguishes them. Carving it out would buy a faster
        // answer for a shape MCP servers do not actually emit — they answer
        // an unknown method with JSON-RPC `-32601` at HTTP 200, which the
        // body-code branch catches before status is consulted at all — and
        // would cost a carve-out that has to stay justified.
        assert!(status_answers_nothing_about_era(501));
    }

    #[test]
    fn a_routing_refusal_is_a_verdict_and_legacy_is_the_right_one() {
        // A server that does not route `server/discover` is telling us
        // exactly what a legacy server would. Treating these as inconclusive
        // instead would re-probe on every single request to every legacy
        // upstream — the common case, made permanently slower to guard
        // against a case that cannot arise, since a modern server MUST
        // implement the method.
        for status in [400, 404, 405, 410] {
            assert!(!status_answers_nothing_about_era(status), "{status}");
        }
    }

    // ── cache hints ──────────────────────────────────────────────────────

    #[test]
    fn a_non_cacheable_method_gets_no_hint_whatever_the_upstreams_are() {
        assert!(modern_cache_hint("tools/call", &[]).is_none());
        assert!(modern_cache_hint("prompts/get", &[]).is_none());
    }

    #[test]
    fn a_cacheable_method_with_no_upstreams_is_advertised_as_immediately_stale() {
        // Promising freshness for a catalog we cannot serve from cache would
        // be a promise we have no mechanism to keep.
        let hint = modern_cache_hint("tools/list", &[]).unwrap();
        assert_eq!(hint.ttl_ms, 0);
        assert_eq!(hint.scope, "private");
    }

    // ── error renumbering ────────────────────────────────────────────────

    async fn error_body(resp: Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The gateway's own `-32004` sits in the sub-range this revision froze,
    /// where a receiver MUST NOT assign it meaning. A modern client gets the
    /// standard code instead — and the original under `data`, so the
    /// renumbering costs an operator nothing.
    /// The session header is the gateway's own upstream session id. A modern
    /// server neither mints nor echoes one, and echoing this particular value
    /// additionally discloses internal routing state.
    #[test]
    fn the_session_header_is_stamped_for_legacy_clients_only() {
        let sid = "upstream-sid-1".to_string();

        let legacy = stamp_session_id(Response::builder(), Some(&sid), false)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            legacy.headers().get("Mcp-Session-Id").unwrap(),
            "upstream-sid-1",
            "a legacy client must keep the session id it has used for three revisions"
        );

        let modern = stamp_session_id(Response::builder(), Some(&sid), true)
            .body(Body::empty())
            .unwrap();
        assert!(
            modern.headers().get("Mcp-Session-Id").is_none(),
            "a modern client must never receive the gateway's upstream session id"
        );

        // Absent upstream session: nothing to stamp in either era.
        for is_modern in [false, true] {
            let none = stamp_session_id(Response::builder(), None, is_modern)
                .body(Body::empty())
                .unwrap();
            assert!(none.headers().get("Mcp-Session-Id").is_none());
        }
    }

    #[tokio::test]
    async fn gateway_codes_are_renumbered_for_a_modern_client() {
        let resp = era_error_response(
            StatusCode::OK,
            RpcId::Number(1.into()),
            TOOL_NOT_FOUND,
            "no such tool",
            &ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string()),
        );
        let body = error_body(resp).await;
        assert_eq!(body["error"]["code"], INVALID_PARAMS);
        assert_eq!(body["error"]["data"]["streamscopeCode"], TOOL_NOT_FOUND);
    }

    /// The positive control, and the reason the renumbering is era-gated at
    /// all: legacy clients have read these codes across three shipped
    /// revisions, so changing them there would be a breaking wire change for
    /// no conformance gain.
    #[tokio::test]
    async fn gateway_codes_are_untouched_for_a_legacy_client() {
        let resp = era_error_response(
            StatusCode::OK,
            RpcId::Number(1.into()),
            TOOL_NOT_FOUND,
            "no such tool",
            &ProtocolEra::Legacy("2025-11-25".into()),
        );
        let body = error_body(resp).await;
        assert_eq!(body["error"]["code"], TOOL_NOT_FOUND);
        assert!(body["error"].get("data").is_none(), "{body}");
    }

    /// A code outside both contested bands carries documented meaning for our
    /// clients and must survive either era unchanged.
    #[tokio::test]
    async fn codes_outside_the_contested_bands_survive_both_eras() {
        for era in [
            ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string()),
            ProtocolEra::Legacy("2025-11-25".into()),
        ] {
            let resp = era_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                RpcId::Number(1.into()),
                RATE_LIMITED,
                "slow down",
                &era,
            );
            assert_eq!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "a status the revision does not mandate stays the caller's: {era:?}"
            );
            let body = error_body(resp).await;
            assert_eq!(body["error"]["code"], RATE_LIMITED, "{era:?}");
            assert!(body["error"].get("data").is_none(), "{era:?}");
        }
    }

    // ── the status is part of the error's meaning ────────────────────────

    fn http_error(status: u16, code: Option<i32>, caps: Option<serde_json::Value>) -> UpstreamError {
        UpstreamError::Http {
            status,
            body: "upstream said something we do not forward".into(),
            jsonrpc_code: code,
            required_capabilities: caps,
        }
    }

    /// § Backward Compatibility has a dual-era client read a `400` carrying a
    /// recognized modern error as proof the server is modern, and § Protocol
    /// Version Header makes an unimplemented RPC a `404`. Answering `200`
    /// removes the signal the client routes on, so the status has to be
    /// derived from the code the client actually reads — on the error egress
    /// as much as on the success one.
    #[tokio::test]
    async fn a_modern_client_gets_the_status_its_revision_mandates() {
        for (code, expected) in [
            (METHOD_NOT_FOUND, StatusCode::NOT_FOUND),
            (
                modern::MISSING_REQUIRED_CLIENT_CAPABILITY,
                StatusCode::BAD_REQUEST,
            ),
            (modern::UNSUPPORTED_PROTOCOL_VERSION, StatusCode::BAD_REQUEST),
        ] {
            let resp = era_error_response(
                StatusCode::OK,
                RpcId::Number(1.into()),
                code,
                "refused",
                &ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string()),
            );
            assert_eq!(resp.status(), expected, "code {code}");
            let body = error_body(resp).await;
            assert_eq!(body["error"]["code"], code, "code {code}");
        }
    }

    /// The positive control for the era gate above: a legacy client has read
    /// these conditions as a `200` carrying a JSON-RPC error across three
    /// shipped revisions, and moving its status would be a breaking wire
    /// change for no conformance gain.
    #[tokio::test]
    async fn a_legacy_client_keeps_the_json_rpc_convention_of_a_200() {
        let resp = era_error_response(
            StatusCode::OK,
            RpcId::Number(1.into()),
            METHOD_NOT_FOUND,
            "refused",
            &ProtocolEra::Legacy("2025-11-25".into()),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body = error_body(resp).await;
        assert_eq!(body["error"]["code"], METHOD_NOT_FOUND);
    }

    /// A `-32021` whose `data` does not name the missing capability tells a
    /// client it lacks *something* it cannot learn, so it can only retry
    /// blindly. The gateway forwards the client's own `clientCapabilities`
    /// upstream verbatim, which is what makes the upstream's complaint about
    /// them the client's to act on.
    #[tokio::test]
    async fn a_relayed_capability_refusal_names_what_the_client_is_missing() {
        let err = http_error(
            400,
            Some(modern::MISSING_REQUIRED_CLIENT_CAPABILITY),
            Some(serde_json::json!({ "sampling": {} })),
        );
        let (resp, code, message) = upstream_error_relay(
            RpcId::Number(1.into()),
            &err,
            &ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string()),
            None,
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(code, modern::MISSING_REQUIRED_CLIENT_CAPABILITY);
        assert!(
            !message.contains("we do not forward"),
            "the upstream's own prose must not reach the client: {message}"
        );
        let body = error_body(resp).await;
        assert_eq!(
            body["error"]["data"]["requiredCapabilities"],
            serde_json::json!({ "sampling": {} })
        );
    }

    /// The era gate on the payload. `requiredCapabilities` is a 2026-07-28
    /// construct; a legacy client's revision does not define it, and the whole
    /// reserved band is renumbered away for that client anyway.
    #[tokio::test]
    async fn a_capability_refusal_carries_no_modern_payload_on_a_legacy_wire() {
        let err = http_error(
            400,
            Some(modern::MISSING_REQUIRED_CLIENT_CAPABILITY),
            Some(serde_json::json!({ "sampling": {} })),
        );
        let (resp, _, _) = upstream_error_relay(
            RpcId::Number(1.into()),
            &err,
            &ProtocolEra::Legacy("2025-11-25".into()),
            None,
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let body = error_body(resp).await;
        assert!(
            body["error"]["data"].get("requiredCapabilities").is_none(),
            "{body}"
        );
    }

    /// The code gate. An upstream failure that is not about capabilities must
    /// not acquire the payload just because the error value could carry one —
    /// and an upstream that answered `-32021` with nothing usable must not
    /// make the gateway invent a shape.
    #[tokio::test]
    async fn only_a_capability_refusal_carries_the_capability_payload() {
        let modern_era = ProtocolEra::Modern(modern::MODERN_PROTOCOL_VERSION.to_string());
        for err in [
            // Same payload present, but the failure is an ordinary 500.
            http_error(500, None, Some(serde_json::json!({ "sampling": {} }))),
            // Right code, nothing captured (the upstream named no shape, or
            // named an array, which `jsonrpc_required_capabilities` refuses).
            http_error(400, Some(modern::MISSING_REQUIRED_CLIENT_CAPABILITY), None),
        ] {
            let (resp, _, _) =
                upstream_error_relay(RpcId::Number(1.into()), &err, &modern_era, None);
            let body = error_body(resp).await;
            assert!(
                body["error"]["data"].get("requiredCapabilities").is_none(),
                "{body}"
            );
        }
    }

    /// Each way an upstream's headers fail to resolve reaches the client as
    /// its own code: the user connects (-32501), the client sends a header it
    /// is told the name of (-32401), or the admin fixes the upstream (-32500).
    /// A missing value or sign-in tells the user where to act: the tenant's
    /// portal sign-ins page when the console URL is known, the portal by name
    /// otherwise; an error the user cannot fix names no page.
    #[test]
    fn a_missing_value_or_sign_in_names_the_portal_sign_ins_page() {
        let url = "https://console.example/portal/t/acme/mcp/connections";
        for err in [
            UpstreamError::UserInputsMissing,
            UpstreamError::UserCredentialMissing,
            UpstreamError::UserCredentialExpired,
        ] {
            let (_, with) = upstream_error_to_jsonrpc(&err, Some(url));
            assert!(with.ends_with(&format!("sign-ins page: {url}")), "{with}");
            let (_, without) = upstream_error_to_jsonrpc(&err, None);
            assert!(without.ends_with("sign-ins page") && !without.contains("https://"), "{without}");
        }
        let (_, other) = upstream_error_to_jsonrpc(&UpstreamError::CredentialUnavailable, Some(url));
        assert!(!other.contains(url), "{other}");

        let mut cfg = streamscope_core::config::TenantConfig::default();
        assert_eq!(portal_sign_ins_url(&cfg), None);
        cfg.admin_public_url = Some("https://console.example/".into());
        assert_eq!(portal_sign_ins_url(&cfg), None, "no tenant slug, no page");
        cfg.tenant_slug = "acme".into();
        assert_eq!(portal_sign_ins_url(&cfg).as_deref(), Some(url));
    }

    #[test]
    fn each_input_failure_maps_to_who_can_fix_it() {
        assert_eq!(upstream_error_to_jsonrpc(&UpstreamError::UserInputsMissing, None).0, MCP_USER_CREDENTIAL_MISSING);
        let (code, msg) = upstream_error_to_jsonrpc(&UpstreamError::ClientHeaderMissing("X-Token".into()), None);
        assert_eq!(code, AUTH_REQUIRED);
        assert!(msg.contains("X-Token"), "{msg}");
        assert_eq!(
            upstream_error_to_jsonrpc(&UpstreamError::CredentialUnavailable, None).0,
            UPSTREAM_CREDENTIAL_UNAVAILABLE
        );
    }

    #[test]
    fn the_fwd_refusal_names_the_mount_to_use() {
        let msg = fwd_mount_required_message("jira");
        assert!(msg.contains("/fwd/<gateway-key>/mcp/jira"), "{msg}");
    }
}
