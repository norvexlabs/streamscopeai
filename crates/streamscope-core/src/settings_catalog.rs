//! The settings catalog — the single source of truth for every environment
//! variable that configures a Streamscope process.
//!
//! Each [`SettingMeta`] entry carries the variable's token, the process it
//! belongs to, a UI grouping category, its value type, default, description,
//! and whether it can be centrally overridden. The catalog is consumed by:
//!
//! - the admin `runtime-config` endpoint, to render and validate the Advanced
//!   settings tab — admin-api does not depend on `streamscope-proxy`, so proxy
//!   metadata must live here;
//! - [`crate::settings::read_runtime_overrides`], to drop non-overridable
//!   tokens from a persisted override file;
//! - per-crate drift tests, which pin the catalog to the real settings structs.
//!
//! Adding a runtime setting means adding a `SettingMeta` entry here alongside
//! the struct field — the per-crate `catalog_matches_*` test fails otherwise.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Which process a setting configures. `Secret` covers secrets and bootstrap
/// variables — reference-only entries with no backing settings struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SettingGroup {
    Core,
    Proxy,
    Admin,
    Secret,
}

/// A setting's value type — drives override validation and the UI input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SettingKind {
    Integer,
    Bool,
    Text,
    Url,
    Secret,
}

/// One catalog entry — pure `const` metadata.
#[derive(Debug, Clone, Copy)]
pub struct SettingMeta {
    /// Environment variable name.
    pub token: &'static str,
    /// Which process this setting configures.
    pub group: SettingGroup,
    /// UI grouping label.
    pub category: &'static str,
    /// Value type.
    pub kind: SettingKind,
    /// Default value, formatted as a string (`""` for secrets / unset strings).
    pub default: &'static str,
    /// One-line operator-facing description.
    pub description: &'static str,
    /// Whether this setting can be centrally overridden and pushed to edges.
    pub overridable: bool,
}

/// A catalog entry plus its current desired override — the API wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SettingDescriptor {
    pub token: String,
    pub group: SettingGroup,
    pub category: String,
    pub kind: SettingKind,
    pub default: String,
    pub description: String,
    pub overridable: bool,
    /// The desired central override, if one is set.
    pub override_value: Option<String>,
}

impl SettingMeta {
    /// Build the API descriptor, attaching the current override (if any).
    pub fn to_descriptor(&self, override_value: Option<String>) -> SettingDescriptor {
        SettingDescriptor {
            token: self.token.to_string(),
            group: self.group,
            category: self.category.to_string(),
            kind: self.kind,
            default: self.default.to_string(),
            description: self.description.to_string(),
            overridable: self.overridable,
            override_value,
        }
    }
}

/// First catalog entry for `token`, if any.
pub fn lookup(token: &str) -> Option<&'static SettingMeta> {
    SETTINGS_CATALOG.iter().find(|m| m.token == token)
}

/// Whether `token` is a known, centrally-overridable setting.
pub fn is_overridable(token: &str) -> bool {
    SETTINGS_CATALOG.iter().any(|m| m.token == token && m.overridable)
}

macro_rules! meta {
    ($token:literal, $group:ident, $cat:literal, $kind:ident, $default:literal, $over:expr, $desc:literal) => {
        SettingMeta {
            token: $token,
            group: SettingGroup::$group,
            category: $cat,
            kind: SettingKind::$kind,
            default: $default,
            description: $desc,
            overridable: $over,
        }
    };
}

/// The complete environment-variable catalog. Order is the UI render order.
pub static SETTINGS_CATALOG: &[SettingMeta] = &[
    // ── Core ────────────────────────────────────────────────────────────────
    meta!("WORKER_THREADS", Core, "Runtime", Integer, "0", false,
        "Tokio worker threads for this process; 0 = auto. Auto sizes to the cgroup CPU quota when set (e.g. a Kubernetes CPU limit), else, on a shared host, gives the proxy nearly all cores while reserving headroom for the control plane and database."),
    meta!("CONTROL_PLANE_CPU_RESERVE", Core, "Runtime", Integer, "0", false,
        "Cores held back from the proxy on a shared host (no cgroup quota) for the admin-api and postgres; 0 = auto (~25%, at least one, never the whole host)."),
    meta!("MAX_BODY_SIZE_BYTES", Core, "Request limits", Integer, "10485760", true,
        "Max HTTP request body size, in bytes."),
    meta!("MAX_UPSTREAM_BODY_SIZE_BYTES", Core, "Request limits", Integer, "67108864", true,
        "Max upstream LLM response body buffered into memory, in bytes — a defense-in-depth cap so a hostile or buggy upstream can't exhaust the edge's memory. Media, search, and classifier responses have their own surface-specific caps."),
    meta!("REQUEST_BODY_DEADLINE_SECS", Core, "Request limits", Integer, "120", true,
        "Time a request body has to arrive in full once the service starts reading it, in seconds — a client sending it slower is refused, so a trickled body cannot hold a connection open. Applies to the gateway's model, MCP and A2A routes and to every admin-api route but edge sync; admin-api reads it from its own environment only, so a central override reaches the gateways alone. 0 = no deadline."),
    meta!("MEDIA_REQUEST_BODY_DEADLINE_SECS", Core, "Request limits", Integer, "600", true,
        "The same deadline on the gateway's media routes (embeddings, audio, images, video) and its pass-through /v1 routes, whose uploads are larger, in seconds; 0 = no deadline."),
    meta!("UPSTREAM_POOL_MAX_IDLE", Core, "Upstream client", Integer, "256", true,
        "Max idle connections kept per upstream host."),
    meta!("UPSTREAM_POOL_IDLE_TIMEOUT_SECS", Core, "Upstream client", Integer, "90", true,
        "Idle upstream connection timeout, in seconds."),
    meta!("UPSTREAM_CONNECT_TIMEOUT_SECS", Core, "Upstream client", Integer, "10", true,
        "TCP connect timeout to upstream, in seconds."),
    meta!("UPSTREAM_REQUEST_TIMEOUT_SECS", Core, "Upstream client", Integer, "300", true,
        "Total upstream request timeout including the response body, in seconds."),
    meta!("UPSTREAM_RETRY_BACKOFF_MS", Core, "Upstream client", Integer, "500", true,
        "Exponential retry base delay, in milliseconds."),
    meta!("UPSTREAM_PROBE_TIMEOUT_SECS", Core, "Upstream client", Integer, "10", false,
        "Reachability-probe timeout for upstream provider liveness checks and model discovery, in seconds (admin-api)."),
    meta!("CUSTOM_CA_BUNDLE_PEM", Core, "Upstream client", Text, "", true,
        "PEM CA bundle trusted for all outbound HTTPS (upstream providers, liveness probe, model discovery) on top of the system roots. Empty = system roots only. Applied on the edge's next restart."),
    meta!("AUDIT_CHANNEL_CAPACITY", Core, "Audit pipeline", Integer, "10000", true,
        "Audit MPSC channel capacity — the backpressure threshold."),
    meta!("AUDIT_BATCH_SIZE", Core, "Audit pipeline", Integer, "500", true,
        "Max audit records drained per batch."),
    meta!("AUDIT_BATCH_DEADLINE_MS", Core, "Audit pipeline", Integer, "100", true,
        "Audit batch collection deadline, in milliseconds."),
    meta!("EDGE_BLOB_MAX_MB", Core, "Audit pipeline", Integer, "32", false,
        "The largest media blob, in MiB, a gateway captures for the audit trail and admin-api accepts from it. A tenant's own media blob cap is held to it; a larger blob is recorded as stripped."),
    meta!("WEB_FETCH_TIMEOUT_SECS", Core, "Egress", Integer, "30", true,
        "Total HTTP timeout for the built-in web-fetch tool, in seconds."),

    // ── Proxy ───────────────────────────────────────────────────────────────
    meta!("PORT", Proxy, "Networking", Integer, "8080", false,
        "HTTP listen port."),
    meta!("METRICS_PORT", Proxy, "Networking", Integer, "0", false,
        "Dedicated Prometheus /metrics listen port; 0 disables the metrics listener. Unauthenticated — keep it off the public surface (each deploy shape publishes it internally only)."),
    meta!("TCP_BACKLOG", Proxy, "Networking", Integer, "2048", false,
        "TCP listen backlog for burst handling."),
    meta!("PROXY_CORS_ORIGIN", Proxy, "Networking", Text, "", false,
        "Optional CORS origin restriction; empty allows all origins."),
    meta!("ADMIN_API_URL", Proxy, "Networking", Url, "http://admin-api:9090", false,
        "Base URL (scheme, host, port) of the admin API's edge endpoints, which the edge polls for config and ships audit to."),
    meta!("DATA_DIR", Proxy, "Networking", Text, "/var/lib/streamscope", false,
        "Persistent state directory — config snapshot, outbox, runtime-override file."),
    meta!("PUBLIC_METADATA_RATE_LIMIT_MAX", Proxy, "Rate limiting", Integer, "600", true,
        "Per-source-IP request cap on the gateway's unauthenticated discovery documents (the MCP protected-resource metadata and the A2A agent card) per window. These are served before any credential is presented and each one scans the tenant registry, so the cap bounds what an anonymous caller can drive. 0 disables it; keep generous — many users can share one IP behind a NAT. Counted per proxy replica."),
    meta!("PUBLIC_METADATA_RATE_LIMIT_WINDOW_SECS", Proxy, "Rate limiting", Integer, "300", true,
        "Window, in seconds, the public-metadata cap is counted over."),
    meta!("RESPONSE_CACHE_MAX_MB", Proxy, "Response cache", Integer, "", true,
        "Memory ceiling for cached LLM responses on this edge replica, in MB, across all tenants; 0 refuses every store. Unset: 15% of the replica's memory limit, or 256 MB when it has none."),
    meta!("RESPONSE_CACHE_MAX_ENTRIES_PER_TENANT", Proxy, "Response cache", Integer, "2000", true,
        "Cached responses one tenant may hold on this edge replica, so no tenant can fill the cache."),
    meta!("QOS_QUEUE_TTL_MS", Proxy, "Priority and fairness", Integer, "10000", true,
        "How long a request waits for capacity on a saturated model when its priority class names no wait of its own, in milliseconds. On expiry the caller is refused with a retry hint rather than held longer."),
    meta!("QOS_QUEUE_TTL_MAX_MS", Proxy, "Priority and fairness", Integer, "540000", true,
        "The longest wait any priority class may ask for, in milliseconds: how long a caller's connection may sit with nothing sent on it. Keep it below any read timeout of a proxy in front of the gateway and below your clients' own request timeout (OpenAI's and Anthropic's SDKs wait 10 minutes). A replica shutting down refuses every waiting request at once, whatever this is."),
    meta!("QOS_MAX_HELD_REQUESTS", Proxy, "Priority and fairness", Integer, "512", true,
        "How many requests this replica may hold waiting for capacity at once. Beyond it, callers are refused immediately instead of queued."),
    meta!("QOS_METRICS_POLL_SECS", Proxy, "Priority and fairness", Integer, "2", true,
        "How often each capacity-limited upstream endpoint's own metrics are read, in seconds. A failed read never counts as \"busy\": the gateway's own in-flight count remains the bound."),
    meta!("SESSION_DETECTOR_CAPACITY", Proxy, "Session detector", Integer, "50", true,
        "LRU session-detector entries per user."),
    meta!("SESSION_DETECTOR_MAX_ENTRIES", Proxy, "Session detector", Integer, "20000", true,
        "Global session-detector memory cap, in entries."),
    meta!("SESSION_DETECTOR_TTL_SECS", Proxy, "Session detector", Integer, "604800", true,
        "Session-detector entry TTL, in seconds."),
    meta!("SESSION_PRUNE_INTERVAL_SECS", Proxy, "Session detector", Integer, "3600", true,
        "Expired session-entry sweep interval, in seconds."),
    meta!("SESSION_SNAPSHOT_INTERVAL_SECS", Proxy, "Session detector", Integer, "30", true,
        "Session snapshot persistence interval, in seconds."),
    meta!("EDGE_BACKOFF_INITIAL_SECS", Proxy, "Edge connection", Integer, "1", false,
        "First wait after a failed request to the admin API, in seconds; it doubles with each further failure."),
    meta!("EDGE_BACKOFF_MAX_SECS", Proxy, "Edge connection", Integer, "60", false,
        "Longest wait between failed audit shipments to the admin API, in seconds. Config sync retries at most every 5 seconds whatever this says, so the edge never reads as offline."),
    meta!("EDGE_SYNC_INTERVAL_MS", Proxy, "Edge connection", Integer, "2000", true,
        "How often the edge asks the admin API for config changes and events, in milliseconds (at most 5000)."),
    meta!("EDGE_SHIP_INTERVAL_MS", Proxy, "Edge connection", Integer, "1000", true,
        "How often the edge ships buffered audit to the admin API, in milliseconds."),
    meta!("EDGE_STATE_INTERVAL_SECS", Proxy, "Edge connection", Integer, "30", true,
        "How often the edge reports its state (runtime stats, endpoint load and health, effective settings), in seconds."),
    meta!("EDGE_USAGE_SYNC_INTERVAL_SECS", Proxy, "Edge connection", Integer, "5", true,
        "Fleet-counter (RPM/TPM/budget) report interval, in seconds — faster than the state report so per-minute rate windows converge promptly."),
    meta!("EDGE_REQUEST_TIMEOUT_SECS", Proxy, "Edge connection", Integer, "10", false,
        "Timeout of one request to the admin API, in seconds. Keep it below 15: an edge is shown live for 15 seconds after its last request."),
    meta!("UPSTREAM_CIRCUIT_BREAKER_ENABLED", Proxy, "Upstream health", Bool, "true", true,
        "Passively take an upstream target out of rotation after repeated connection failures so a healthy alternate is tried first; it auto-recovers via a half-open trial. When off, every target is always considered healthy."),
    meta!("UPSTREAM_CIRCUIT_BREAKER_FAILURE_THRESHOLD", Proxy, "Upstream health", Integer, "3", true,
        "Consecutive transport-level failures (connection refused / DNS / TLS / timeout — not HTTP error statuses) before a target is taken out of rotation."),
    meta!("UPSTREAM_CIRCUIT_BREAKER_COOLDOWN_SECS", Proxy, "Upstream health", Integer, "30", true,
        "How long an out-of-rotation target waits before the next request is allowed through as a single recovery trial, in seconds."),
    meta!("SQLITE_POOL_SIZE", Proxy, "Edge outbox", Integer, "2", false,
        "Outbox SQLite connection pool size."),
    meta!("AUDIT_DEBUG_ENDPOINT", Proxy, "Edge outbox", Bool, "false", false,
        "Expose the unauthenticated /debug/buffered-audit introspection endpoint (cumulative counts of audit records committed to the on-disk outbox, and the live count of records not yet delivered to the admin API). Diagnostic only; leave off in production."),
    meta!("APPLIANCE_HOST_MEMORY", Proxy, "Edge connection", Bool, "false", false,
        "Report whole-host memory pressure (used / total RAM) in the state report instead of this container's own cgroup working-set and limit. Set on the single-host VM appliance, where the platform-health signal is the whole VM's memory rather than the proxy's slice of its own cap. Leave off on Kubernetes, where the per-pod cgroup percentage is the real OOM signal."),
    meta!("EDGE_OUTBOX_MAX_MB", Proxy, "Edge outbox", Integer, "1024", true,
        "Hard cap on the edge's outbox (audit waiting for the admin API), in MiB; past it the oldest records are evicted and logged at error. 0 disables the cap."),
    meta!("A2A_STREAM_MAX_BYTES", Proxy, "A2A gateway", Integer, "8388608", true,
        "Per-stream byte cap on SendStreamingMessage and SubscribeToTask SSE responses."),
    meta!("A2A_AUDIT_STREAM_MAX_BYTES", Proxy, "A2A gateway", Integer, "262144", true,
        "Max serialized size of the accumulated a2a_audit stream_events array before further events are dropped behind a truncation marker. The wire stream is never truncated — only what audit retains."),
    meta!("A2A_STREAM_TIMEOUT_SECS", Proxy, "A2A gateway", Integer, "3600", true,
        "Wall-clock ceiling on one streamed A2A call, start to close. Generous, since an agent task can legitimately run for minutes. 0 disables the ceiling."),
    meta!("A2A_STREAM_IDLE_TIMEOUT_SECS", Proxy, "A2A gateway", Integer, "300", true,
        "How long the gateway waits for the next byte from a silent agent mid-stream before failing the call. 0 disables the idle bound."),
    meta!("MCP_STREAM_MAX_BYTES", Proxy, "MCP gateway", Integer, "8388608", true,
        "Per-stream byte cap on tools/call and prompts/get SSE responses."),
    meta!("MCP_AUDIT_PAYLOAD_MAX_BYTES", Proxy, "MCP gateway", Integer, "65536", true,
        "Max serialized size of an mcp_audit params/result payload before it is replaced with a stripped marker."),
    meta!("MCP_GET_KEEPALIVE_SECS", Proxy, "MCP gateway", Integer, "25", true,
        "Keepalive comment interval for the long-lived GET /mcp SSE channel, in seconds."),
    meta!("MCP_GET_BUS_CAPACITY", Proxy, "MCP gateway", Integer, "256", true,
        "Per-(tenant, user) GET fan-out broadcast channel capacity."),
    meta!("MCP_LEGACY_SSE_MAX_SESSIONS_PER_INSTANCE", Proxy, "MCP gateway", Integer, "256", true,
        "Hard cap on concurrent legacy-SSE upstream sessions per proxy instance."),
    meta!("MCP_LEGACY_SSE_RECONNECT_BACKOFF_MS", Proxy, "MCP gateway", Integer, "1000", true,
        "Backoff before reconnecting a terminated legacy-SSE upstream channel, in milliseconds."),
    meta!("MCP_LEGACY_SSE_REQUEST_TIMEOUT_MS", Proxy, "MCP gateway", Integer, "30000", true,
        "Per-call timeout on legacy-SSE upstreams, in milliseconds."),
    meta!("MCP_TOKEN_TTL_SECS", Proxy, "MCP gateway", Integer, "86400", true,
        "TTL on virtualized MCP tokens (resource URIs, server-initiated request ids), in seconds."),
    meta!("MCP_SSE_RETENTION_SECS", Proxy, "MCP gateway", Integer, "3600", false,
        "Retention window for mcp_sse_events hourly partitions, in seconds — bounds Last-Event-ID replay reach. Env-only: must agree with the admin-api value, which a central override could not keep in sync."),
    meta!("MCP_SSE_REPLAY_LIMIT", Proxy, "MCP gateway", Integer, "1000", true,
        "Max rows replayed per Last-Event-ID reconnect."),
    meta!("MCP_SSE_TOKEN_TTL_SECS", Proxy, "MCP gateway", Integer, "3600", true,
        "Last-Event-ID token TTL, in seconds."),
    meta!("MCP_SSE_EVENT_TX_BUFFER", Proxy, "MCP gateway", Integer, "4096", true,
        "Bounded MPSC capacity for the SSE event-persistence channel."),
    meta!("MCP_CAPABILITY_CACHE_TTL_SECS", Proxy, "MCP gateway", Integer, "60", true,
        "Capability cache TTL for tools/prompts/resources list responses, in seconds."),
    meta!("MCP_CAPABILITY_CACHE_MAX_ENTRIES", Proxy, "MCP gateway", Integer, "4096", true,
        "Capability cache hard entry cap."),
    meta!("MCP_SESSION_IDLE_TTL_SECS", Proxy, "MCP gateway", Integer, "1800", true,
        "Idle TTL for MCP and legacy-SSE session-map entries, in seconds."),
    meta!("MCP_SESSION_MAX_ENTRIES", Proxy, "MCP gateway", Integer, "4096", true,
        "Hard cap on MCP session-map entries."),
    meta!("MCP_LEGACY_SSE_ABANDONED_TTL_SECS", Proxy, "MCP gateway", Integer, "60", true,
        "Legacy-SSE abandoned pending-request id TTL, in seconds."),
    meta!("MCP_OAUTH_EXPIRY_SAFETY_MARGIN_SECS", Proxy, "MCP gateway", Integer, "30", true,
        "OAuth refresh expiry safety margin, in seconds."),
    meta!("MCP_SWEEP_INTERVAL_SECS", Proxy, "MCP gateway", Integer, "60", true,
        "Periodic sweep cadence for the unified MCP map sweeper, in seconds."),
    meta!("MCP_HTTP_CLIENT_TIMEOUT_SECS", Proxy, "MCP gateway", Integer, "60", true,
        "Default request timeout on the proxy's outbound HTTP client to upstream MCP servers, in seconds. Also bounds the read that classifies a notification-stream answer which turned out not to be a stream."),
    meta!("MCP_GET_DRAIN_SECS", Proxy, "MCP gateway", Integer, "2", true,
        "Drain window for in-flight GET /mcp SSE subscribers on graceful shutdown, in seconds."),
    meta!("GRACEFUL_DRAIN_TIMEOUT_SECS", Proxy, "Shutdown", Integer, "10", true,
        "Upper bound on the post-shutdown drain (audit flush, offline-buffer ship), in seconds."),

    // ── Admin ───────────────────────────────────────────────────────────────
    meta!("PORT", Admin, "Networking", Integer, "9090", false,
        "HTTP listen port."),
    meta!("METRICS_PORT", Admin, "Networking", Integer, "0", false,
        "Dedicated Prometheus /metrics listen port; 0 disables the metrics listener. Unauthenticated — keep it off the public surface (each deploy shape publishes it internally only)."),
    meta!("DB_MAX_CONNECTIONS", Admin, "Database", Integer, "20", false,
        "PostgreSQL connection pool size for tenant-scoped work. A second pool for global reads (edge sync and auth, pre-auth lookups) adds half as many again, at least 4."),
    meta!("DB_ACQUIRE_TIMEOUT_SECS", Admin, "Database", Integer, "5", false,
        "Database connection acquire timeout, in seconds."),
    meta!("DB_MANAGE_APP_ROLE", Admin, "Database", Bool, "true", false,
        "Whether startup sets the runtime database role's password (from DATABASE_URL) and its transaction timeout. Set false when you manage that role yourself (managed Postgres where the migration role cannot alter it, IAM authentication, external rotation). Read at startup only."),
    meta!("DB_APP_TRANSACTION_TIMEOUT", Admin, "Database", Text, "1h", false,
        "Longest transaction the runtime database role may run (a Postgres interval such as 1h; 0 disables), set at startup while DB_MANAGE_APP_ROLE is true."),
    meta!("JWT_EXPIRY_HOURS", Admin, "Auth", Integer, "8", false,
        "Session token lifetime (admin and portal), in hours."),
    meta!("OIDC_CLIENT_TIMEOUT_SECS", Admin, "Auth", Integer, "5", false,
        "OIDC discovery HTTP timeout, in seconds."),
    meta!("OIDC_SKIP_TLS_VERIFY", Admin, "Auth", Bool, "false", false,
        "Skip TLS verification for OIDC discovery (development only)."),
    meta!("AUTH_MODE", Admin, "Auth", Text, "", false,
        "Auth mode override; empty defers to the DB-configured mode."),
    meta!("HEADER_AUTH_TENANT_SLUG", Admin, "Auth", Text, "", false,
        "Which tenant a header-auth deployment serves. Your reverse proxy proves who the user is; this says which tenant they belong to. Leave empty to serve the system tenant."),
    meta!("HEADER_AUTH_TRUSTED_PROXY", Admin, "Auth", Text, "", false,
        "Names the reverse proxy that authenticates users in header-auth mode. Required to start with AUTH_MODE=header: in that mode a request naming an existing account is accepted without a credential, so the proxy in front is the only thing authenticating anyone. Setting this states that the API is reachable only through it."),
    meta!("HEADER_AUTH_TRUST_TENANT_HEADER", Admin, "Auth", Bool, "false", false,
        "Let an inbound X-Tenant-Slug header choose the tenant in header-auth mode. Only turn this on if your reverse proxy SETS that header itself, overwriting whatever the caller sent — otherwise a caller can pick their own tenant."),
    meta!("ALLOW_OIDC_CLAIM_EXCHANGE", Admin, "Auth", Bool, "false", false,
        "Accept a console or portal identity asserted by an internal caller on its own word, instead of one verified from a provider signature. The gateway's own sign-in paths do not use it; leave off unless another system provisions your accounts."),
    meta!("API_DOCS_PUBLIC", Admin, "Auth", Bool, "true", false,
        "Expose the interactive OpenAPI docs (/api/docs) and spec (/api/docs/openapi.json). Set false to 404 them on a public deployment."),
    meta!("RATE_LIMIT_WINDOW_SECS", Admin, "Rate limiting", Integer, "300", false,
        "Shared rate-limit window, in seconds."),
    meta!("RATE_LIMIT_LOGIN_MAX", Admin, "Rate limiting", Integer, "10", false,
        "Login / invite attempts allowed per window."),
    meta!("RATE_LIMIT_INSTANCE_COUNT", Admin, "Rate limiting", Integer, "1", false,
        "Number of admin-api instances; rate limits are divided by this."),
    meta!("PRE_AUTH_IP_RATE_LIMIT_MAX", Admin, "Rate limiting", Integer, "600", false,
        "Per-source-IP request cap on the unauthenticated pre-auth surfaces (login, OIDC/OAuth, invite, auth-info, MCP-OAuth) per window. 0 disables it; keep generous — many users can share one IP behind a NAT."),
    meta!("AUTOMATION_KEY_RATE_LIMIT_MAX", Admin, "Rate limiting", Integer, "3000", false,
        "Per-key request cap on authenticated `ak-` automation traffic (admin + portal API) per window. Bounds a leaked automation key, which the pre-auth IP limiter never sees because it authenticates. 0 disables it; keep generous — this is a blast-radius ceiling, not a quota."),
    meta!("AUTOMATION_KEY_IP_RATE_LIMIT_MAX", Admin, "Rate limiting", Integer, "60", false,
        "How many DISTINCT `ak-` automation keys one source may fail to authenticate with per window. The per-key limiter bounds one leaked key; this bounds a prober who varies the token and would otherwise drive an unthrottled tenant-resolve scan per attempt. Counting distinct keys means a client repeating one revoked key never trips it, however long it runs. 0 disables it."),
    meta!("TRUSTED_PROXY_HOPS", Core, "Rate limiting", Integer, "1", false,
        "Number of trusted reverse proxies in front of the gateway. Controls how X-Forwarded-For is read for client-IP attribution (audit, the pre-auth IP limiter, and the gateway's public-metadata limiter): the client is the Nth entry from the right. 0 = directly exposed, ignore forwarding headers. Describes your topology, so set it identically on both services."),
    meta!("RETENTION_CYCLE_INTERVAL_SECS", Admin, "Retention", Integer, "21600", false,
        "Retention purge cycle interval, in seconds."),
    meta!("RETENTION_BATCH_SIZE", Admin, "Retention", Integer, "10000", false,
        "Large-table batch delete size. Values below 2 are raised to 2 (a smaller batch would never finish)."),
    meta!("RETENTION_BATCH_SLEEP_MS", Admin, "Retention", Integer, "100", false,
        "Sleep between retention batches, in milliseconds."),
    meta!("DB_SIZE_MIN_RETENTION_DAYS", Admin, "Retention", Integer, "7", false,
        "Retention (days) a purge under hard disk pressure keeps, across every tenant; a soft-pressure purge keeps 15 days, or this when it is longer. At least 1."),
    meta!("EDGE_SYNC_REFRESH_MS", Admin, "Config sync", Integer, "2000", false,
        "How often each admin replica rebuilds the edge config bodies whose change counters moved, in milliseconds."),
    meta!("EDGE_EVENT_TTL_SECS", Admin, "Config sync", Integer, "600", false,
        "How long an event for edges (an MCP user event) stays deliverable to an edge that has not polled yet, in seconds."),
    meta!("EDGE_HEARTBEAT_INTERVAL_SECS", Admin, "Edge sync", Integer, "30", false,
        "How often edges report their state, in seconds (set it to the proxies' EDGE_STATE_INTERVAL_SECS). An edge silent for five intervals no longer counts as connected."),
    meta!("USAGE_JANITOR_INTERVAL_SECS", Admin, "Edge sync", Integer, "3600", false,
        "How often the leader-elected janitor GCs elapsed-window fleet usage counters, in seconds."),
    meta!("ALERT_DISPATCH_INTERVAL_SECS", Admin, "Notifications", Integer, "300", false,
        "How often the leader-elected alert dispatcher evaluates budget crossings and delivers pending notifications, in seconds (also woken on demand)."),
    meta!("SHUTDOWN_DRAIN_TIMEOUT_SECS", Admin, "Shutdown", Integer, "20", false,
        "Upper bound on the post-shutdown wait for background workers, in seconds."),
    meta!("AUDIT_MAX_LIMIT", Admin, "Pagination", Integer, "1000", false,
        "Max audit / session page size."),
    meta!("MODEL_AUTOSYNC_INTERVAL_HOURS", Admin, "Model sync", Integer, "24", false,
        "How often the autosync worker re-discovers each auto-sync-enabled upstream server, in hours."),
    meta!("AGENT_HTTP_TIMEOUT_SECS", Admin, "Agent", Integer, "300", false,
        "Agent LLM call timeout, in seconds. Generous so small/local reasoning models that think for minutes aren't cut off."),
    meta!("AGENT_SESSION_CONCURRENCY", Admin, "Agent", Integer, "4", false,
        "Max concurrent per-session expert LLM calls in a batch, so a slow upstream call doesn't serialize the cycle."),
    meta!("AGENT_HTTP_MAX_RETRIES", Admin, "Agent", Integer, "2", false,
        "Retry attempts for a transient agent->proxy failure (connect / 429 / 5xx); a timeout is retried at most once."),
    meta!("AGENT_SESSION_BATCH_LIMIT", Admin, "Agent", Integer, "50", false,
        "Sessions analyzed per agent batch."),
    meta!("AGENT_SUGGESTIONS_PER_CYCLE_CAP", Admin, "Agent", Integer, "3", false,
        "Max new suggestions stored per (tenant, expert axis, cycle, kind)."),
    meta!("AGENT_SUGGESTION_MIN_SEEN", Admin, "Agent", Integer, "2", false,
        "Cycles a pending suggestion must be re-proposed before it surfaces to operators."),
    meta!("MAX_SCRIPT_SIZE", Admin, "Misc", Integer, "100000", false,
        "Max Rhai script upload size, in bytes."),
    meta!("SEEDS_DIR", Admin, "Misc", Text, "seeds", false,
        "Seed data directory."),
    meta!("AGENT_PROXY_URL", Admin, "Agent", Url, "http://proxy:8080", false,
        "Gateway URL the expert/agent worker calls to run its analysis (admin-api → proxy). The Helm chart sets the in-cluster <release>-proxy Service so the agent works on Kubernetes."),
    meta!("GATEWAY_CA_FILE", Admin, "Misc", Text, "", false,
        "Path to the gateway root CA (PEM) served by GET /api/v1/cli/ca so the CLI installer can trust the stable root. A deployment whose front uses an internal CA mounts the published root at /cli-ca/ca.pem; empty = endpoint 404s."),
    meta!("MCP_OAUTH_PENDING_TTL_SECS", Admin, "MCP", Integer, "600", false,
        "Pending MCP OAuth authorization TTL, in seconds."),
    meta!("MCP_OAUTH_DCR_PER_TENANT_CAP", Admin, "MCP", Integer, "1000", false,
        "Per-tenant cap on dynamically-registered MCP OAuth clients."),
    meta!("MCP_SSE_RETENTION_SECS", Admin, "MCP", Integer, "3600", false,
        "Retention window for mcp_sse_events partitions, in seconds (must agree with the proxy value)."),
    meta!("STOWAGE_HOST_SOCKET", Admin, "Appliance", Text, "", false,
        "Path of the host daemon's app socket. Set ONLY on the Kairos VM appliance; empty elsewhere. Doubles as the appliance discriminator — when empty the web Appliance surface (lifecycle, backup, network, upgrade-check) is off."),
    meta!("APPLIANCE_UPGRADE_CHECK_INTERVAL_SECS", Admin, "Appliance", Integer, "21600", false,
        "How often the appliance upgrade-check worker polls the host daemon for a new OS version (raising an upgrade-available notification). Inert unless STOWAGE_HOST_SOCKET is set."),

    // ── Secrets & bootstrap (reference-only) ─────────────────────────────────
    meta!("AUTH_SECRET", Secret, "Secrets", Secret, "", false,
        "Signing secret for session JWTs and MCP tokens. Required by the admin API; the gateway never holds it."),
    meta!("AUTH_SECRET_SECONDARY", Secret, "Secrets", Secret, "", false,
        "A second signing secret that is only verified against, never signed with. Holds the incoming secret while a rotation is staged and the outgoing one while it drains. Clear it to end the overlap and invalidate everything issued before the rotation."),
    meta!("ENCRYPTION_KEY", Secret, "Secrets", Secret, "", false,
        "AES-256-GCM key for upstream credentials at rest. Required at startup."),
    meta!("DATABASE_URL", Secret, "Secrets", Secret, "", false,
        "PostgreSQL connection string for the runtime role. Required."),
    meta!("MIGRATION_DATABASE_URL", Secret, "Secrets", Secret, "", false,
        "PostgreSQL connection string for the owner role used to run migrations."),
    meta!("INTERNAL_SERVICE_SECRET", Secret, "Secrets", Secret, "", false,
        "Shared secret authenticating internal service-to-service calls."),
    meta!("STOWAGE_HOST_TOKEN", Secret, "Secrets", Secret, "", false,
        "Bearer token for the host daemon's app socket. Set by the Kairos VM alongside STOWAGE_HOST_SOCKET."),
    meta!("EDGE_TOKEN", Secret, "Secrets", Secret, "", false,
        "Bearer token authenticating an edge node to the admin API."),
    meta!("BOOTSTRAP_PROXY_PUBLIC_URL", Secret, "Bootstrap", Url, "", false,
        "Public proxy URL seeded into the SYSTEM tenant on first boot."),
    meta!("BOOTSTRAP_ADMIN_PUBLIC_URL", Secret, "Bootstrap", Url, "", false,
        "Public admin-UI URL seeded into the SYSTEM tenant on first boot."),
    meta!("BOOTSTRAP_API_PUBLIC_URL", Secret, "Bootstrap", Url, "", false,
        "Optional public admin-API URL seeded into the SYSTEM tenant on first boot. Only set when the admin-API is deployed on a hostname distinct from the admin/portal URL."),
];
