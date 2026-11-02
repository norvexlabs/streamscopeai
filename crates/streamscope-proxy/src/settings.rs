//! Process-level settings for the edge proxy.
//!
//! Centralized runtime configuration. Each field resolves, in precedence order,
//! to: a central override pushed from admin-api (persisted in the
//! `runtime_overrides.json` file), then an environment variable, then the
//! compiled-in default. Uses `LazyLock` — auto-initializes on first access.
//!
//! Access via [`proxy_settings()`]. Touch early in `main()` to trigger init +
//! startup logging. The `streamscope_core::settings_catalog` is the single
//! source of truth for every token, default, and description.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

use streamscope_core::settings::{read_runtime_overrides, resolve_setting};

static SETTINGS: LazyLock<ProxySettings> = LazyLock::new(ProxySettings::load);

/// Edge proxy settings.
pub struct ProxySettings {
    // -- Networking --
    /// HTTP listen port. Env: `PORT`. Default: 8080.
    pub port: u16,
    /// Dedicated Prometheus /metrics listen port; 0 disables the listener.
    /// Env: `METRICS_PORT`. Default: 0.
    pub metrics_port: u16,
    /// TCP listen backlog for burst handling. Env: `TCP_BACKLOG`. Default: 2048.
    pub tcp_backlog: u32,
    /// Optional CORS restriction. Env: `PROXY_CORS_ORIGIN`. Default: None (allow all).
    pub cors_origin: Option<String>,
    /// Base URL of admin-api's edge endpoints (scheme, host, port). Env:
    /// `ADMIN_API_URL`. Default: `http://admin-api:9090`.
    pub admin_api_url: String,
    /// Persistent state directory. Env: `DATA_DIR`. Default: `/var/lib/streamscope`.
    pub data_dir: String,

    // -- Rate limiting --
    /// Per-source-IP request cap on the unauthenticated discovery documents (MCP
    /// protected-resource metadata, the A2A agent card), per
    /// [`Self::public_metadata_rate_limit_window`]. `0` disables the limiter.
    /// Env: `PUBLIC_METADATA_RATE_LIMIT_MAX`. Default: 600.
    ///
    /// Counted per replica: a discovery GET is cheap enough that the fleet-wide
    /// counter's sync traffic would cost more than the ceiling it tightens, and
    /// the limiter bounds a scan rather than metering a quota.
    pub public_metadata_rate_limit_max: u32,
    /// Window the public-metadata cap is counted over. Env:
    /// `PUBLIC_METADATA_RATE_LIMIT_WINDOW_SECS`. Default: 300s.
    pub public_metadata_rate_limit_window: Duration,

    // -- Response cache --
    /// Total memory ceiling for cached LLM responses across every tenant on this
    /// replica, in MB; unset = sized from the memory limit, see
    /// [`ProxySettings::response_cache_max_bytes`]; 0 refuses every store.
    /// Env: `RESPONSE_CACHE_MAX_MB`. Default: unset.
    pub response_cache_max_mb: Option<u64>,
    /// Per-tenant entry cap, so one tenant cannot fill the replica's cache.
    /// Env: `RESPONSE_CACHE_MAX_ENTRIES_PER_TENANT`. Default: 2000.
    pub response_cache_max_entries_per_tenant: usize,

    // -- Dispatch gate (priority and fairness under load) --
    /// How long a held request waits for capacity when its class names no hold
    /// of its own. Env: `QOS_QUEUE_TTL_MS`. Default: 10000.
    pub qos_queue_ttl_ms: u64,
    /// The longest hold any class may ask for: how long a caller's connection
    /// may sit with nothing sent on it, so below any read timeout of a proxy in
    /// front and below the clients' own request timeout — nine minutes, under
    /// the ten OpenAI's and Anthropic's SDKs wait, leaving one to answer. Keep
    /// it at or under the class schema's maximum (`qos_classes.rs`
    /// `MAX_QUEUE_TTL_MS`, ten minutes). Shutdown does not depend on it:
    /// SIGTERM refuses every hold at once (`DispatchGate::begin_shutdown`).
    /// Env: `QOS_QUEUE_TTL_MAX_MS`. Default: 540000.
    pub qos_queue_ttl_max_ms: u64,
    /// How many requests this replica may hold at once before refusing rather
    /// than queueing. Env: `QOS_MAX_HELD_REQUESTS`. Default: 512.
    pub qos_max_held_requests: usize,
    /// How often each gated endpoint's own metrics are read. Env:
    /// `QOS_METRICS_POLL_SECS`. Default: 2.
    pub qos_metrics_poll_secs: u64,

    // -- Session detector --
    /// LRU entries per user. Env: `SESSION_DETECTOR_CAPACITY`. Default: 50.
    pub session_detector_capacity: usize,
    /// Global memory cap (~30 MB at 1.5 KB/entry). Env: `SESSION_DETECTOR_MAX_ENTRIES`. Default: 20000.
    pub session_detector_max_entries: usize,
    /// Entry TTL. Must survive weekends/holidays. Env: `SESSION_DETECTOR_TTL_SECS`. Default: 604800 (7 days).
    pub session_detector_ttl: Duration,
    /// Expired entry sweep interval. Env: `SESSION_PRUNE_INTERVAL_SECS`. Default: 3600.
    pub session_prune_interval: Duration,
    /// Snapshot persistence interval. Env: `SESSION_SNAPSHOT_INTERVAL_SECS`. Default: 30.
    pub session_snapshot_interval_secs: u64,

    // -- Edge connection --
    /// First wait after a failed request to admin-api; doubles per failure.
    /// Env: `EDGE_BACKOFF_INITIAL_SECS`. Default: 1.
    pub edge_backoff_initial_secs: u64,
    /// Longest wait between failed ingest requests to admin-api. Config sync
    /// retries (and polls) at most every 5 s whatever this says, so the
    /// instance stays live. Env: `EDGE_BACKOFF_MAX_SECS`. Default: 60.
    pub edge_backoff_max_secs: u64,
    /// How often the edge asks admin-api for config changes and events.
    /// Env: `EDGE_SYNC_INTERVAL_MS`. Default: 2000.
    pub edge_sync_interval_ms: u64,
    /// How often the edge ships buffered audit to admin-api.
    /// Env: `EDGE_SHIP_INTERVAL_MS`. Default: 1000.
    pub edge_ship_interval_ms: u64,
    /// How often the edge reports its instance state (stats, endpoint load and
    /// stands, effective settings). Env: `EDGE_STATE_INTERVAL_SECS`. Default: 30.
    pub edge_state_interval_secs: u64,
    /// Fleet-counter (RPM/TPM/budget) report interval — faster than the heartbeat
    /// so per-minute windows converge promptly. Env: `EDGE_USAGE_SYNC_INTERVAL_SECS`. Default: 5.
    pub edge_usage_sync_interval_secs: u64,
    /// Timeout of one request to admin-api, below admin-api's 15 s liveness
    /// window. Env: `EDGE_REQUEST_TIMEOUT_SECS`. Default: 10.
    pub edge_request_timeout: Duration,

    // -- Upstream health --
    /// Passively deprioritize an upstream server after repeated transport
    /// failures (per-server circuit breaker); recovers via a half-open trial.
    /// Env: `UPSTREAM_CIRCUIT_BREAKER_ENABLED`. Default: true.
    pub upstream_circuit_breaker_enabled: bool,
    /// Consecutive transport-level failures before a server is taken out of
    /// rotation. Env: `UPSTREAM_CIRCUIT_BREAKER_FAILURE_THRESHOLD`. Default: 3.
    pub upstream_circuit_breaker_failure_threshold: u32,
    /// Cooldown before an out-of-rotation server gets a single recovery trial.
    /// Env: `UPSTREAM_CIRCUIT_BREAKER_COOLDOWN_SECS`. Default: 30.
    pub upstream_circuit_breaker_cooldown_secs: u64,

    // -- Outbox --
    /// Outbox connection pool size. Env: `SQLITE_POOL_SIZE`. Default: 2.
    pub sqlite_pool_size: u32,
    /// Hard cap on the edge's outbox (audit waiting for admin-api), in MiB.
    /// Past the cap the oldest records are evicted. `0` disables the cap.
    /// Env: `EDGE_OUTBOX_MAX_MB`. Default: 1024.
    pub edge_outbox_max_mb: u64,
    /// Expose the unauthenticated `/debug/buffered-audit` introspection
    /// endpoint (cumulative counts of audit records committed to the SQLite
    /// outbox, and the live `outbox_pending`). Diagnostic only — a test
    /// harness gates SIGKILL on crash-durability and waits for a drain on it.
    /// Env: `AUDIT_DEBUG_ENDPOINT`. Default: false.
    pub audit_debug_endpoint: bool,
    /// Report whole-host memory pressure (used / total RAM) in the heartbeat
    /// instead of this container's own cgroup working-set / `memory.max`. Set on
    /// the single-host VM appliance, where every service shares one VM and the
    /// platform-health signal is the whole VM's memory — not the proxy's slice of
    /// its own 512M cap (which reads as a meaningless single-digit %). Off on K8s
    /// (per-pod cgroup % is the real OOM signal) and local dev. Env:
    /// `APPLIANCE_HOST_MEMORY`. Default: false.
    pub appliance_host_memory: bool,

    // -- A2A gateway --
    /// Per-stream byte cap on `SendStreamingMessage` / `SubscribeToTask` SSE
    /// responses. Env: `A2A_STREAM_MAX_BYTES`. Default: 8388608 (8 MiB).
    pub a2a_stream_max_bytes: usize,
    /// Max serialised size of the accumulated `a2a_audit.stream_events` array
    /// before further events are dropped behind a truncation marker (the wire
    /// stream itself is never truncated — only what audit retains).
    /// Env: `A2A_AUDIT_STREAM_MAX_BYTES`. Default: 262144 (256 KiB).
    pub a2a_audit_stream_max_bytes: usize,
    /// Wall-clock ceiling on one streamed A2A call, start to close. Generous by
    /// design — an A2A task can legitimately run for minutes — but never
    /// unbounded: the pump holds a shutdown-drain guard for its lifetime.
    /// 0 disables the ceiling.
    /// Env: `A2A_STREAM_TIMEOUT_SECS`. Default: 3600.
    pub a2a_stream_timeout_secs: u64,
    /// Idle bound within a stream: how long the gateway waits for the next byte
    /// from a silent agent before failing the call. This — not the total
    /// ceiling — is what reaps a hung upstream promptly.
    /// 0 disables the idle bound.
    /// Env: `A2A_STREAM_IDLE_TIMEOUT_SECS`. Default: 300.
    pub a2a_stream_idle_timeout_secs: u64,

    // -- MCP gateway --
    /// Per-stream byte cap on `tools/call` / `prompts/get` SSE responses.
    /// Env: `MCP_STREAM_MAX_BYTES`. Default: 8388608 (8 MiB).
    pub mcp_stream_max_bytes: usize,
    /// Max serialised size of a single `mcp_audit` params/result payload before
    /// it is replaced with a stripped marker. Env: `MCP_AUDIT_PAYLOAD_MAX_BYTES`.
    /// Default: 65536 (64 KiB).
    pub mcp_audit_payload_max_bytes: usize,
    /// Keepalive comment interval for `GET /mcp/<slug>` long-lived SSE.
    /// Env: `MCP_GET_KEEPALIVE_SECS`. Default: 25.
    pub mcp_get_keepalive_secs: u64,
    /// Per-(tenant, user) GET fan-out broadcast channel capacity.
    /// Env: `MCP_GET_BUS_CAPACITY`. Default: 256.
    pub mcp_get_bus_capacity: usize,
    /// Hard cap on concurrent legacy-SSE upstream sessions per proxy instance.
    /// Env: `MCP_LEGACY_SSE_MAX_SESSIONS_PER_INSTANCE`. Default: 256.
    pub mcp_legacy_sse_max_sessions_per_instance: usize,
    /// Backoff before reconnecting a terminated legacy-SSE upstream channel.
    /// Env: `MCP_LEGACY_SSE_RECONNECT_BACKOFF_MS`. Default: 1000.
    pub mcp_legacy_sse_reconnect_backoff_ms: u64,
    /// Per-call timeout on legacy SSE upstreams.
    /// Env: `MCP_LEGACY_SSE_REQUEST_TIMEOUT_MS`. Default: 30000.
    pub mcp_legacy_sse_request_timeout_ms: u64,
    /// TTL on virtualized MCP tokens. Env: `MCP_TOKEN_TTL_SECS`. Default: 86400 (24h).
    pub mcp_token_ttl_secs: u64,
    /// Hourly partition retention window for `mcp_sse_events`.
    /// Env: `MCP_SSE_RETENTION_SECS`. Default: 3600 (1h).
    pub mcp_sse_retention_secs: u64,
    /// Hard cap on rows replayed per `Last-Event-ID` reconnect.
    /// Env: `MCP_SSE_REPLAY_LIMIT`. Default: 1000.
    pub mcp_sse_replay_limit: i64,
    /// `Last-Event-ID` token TTL. Env: `MCP_SSE_TOKEN_TTL_SECS`. Default: 3600 (1h).
    pub mcp_sse_token_ttl_secs: u64,
    /// Bounded MPSC capacity for the event-persistence channel.
    /// Env: `MCP_SSE_EVENT_TX_BUFFER`. Default: 4096.
    pub mcp_sse_event_tx_buffer: usize,
    /// Capability cache TTL for list responses. Env: `MCP_CAPABILITY_CACHE_TTL_SECS`. Default: 60.
    pub mcp_capability_cache_ttl_secs: u64,
    /// Capability cache hard entry cap. Env: `MCP_CAPABILITY_CACHE_MAX_ENTRIES`. Default: 4096.
    pub mcp_capability_cache_max_entries: usize,
    /// Idle TTL for session-map entries. Env: `MCP_SESSION_IDLE_TTL_SECS`. Default: 1800.
    pub mcp_session_idle_ttl_secs: u64,
    /// Hard cap on `McpSessionMap` entries. Env: `MCP_SESSION_MAX_ENTRIES`. Default: 4096.
    pub mcp_session_max_entries: usize,
    /// Legacy-SSE pending-request abandoned-id TTL.
    /// Env: `MCP_LEGACY_SSE_ABANDONED_TTL_SECS`. Default: 60.
    pub mcp_legacy_sse_abandoned_ttl_secs: u64,
    /// OAuth refresh expiry safety margin.
    /// Env: `MCP_OAUTH_EXPIRY_SAFETY_MARGIN_SECS`. Default: 30.
    pub mcp_oauth_expiry_safety_margin_secs: i64,
    /// Periodic sweep cadence for the unified MCP map sweeper.
    /// Env: `MCP_SWEEP_INTERVAL_SECS`. Default: 60.
    pub mcp_sweep_interval_secs: u64,
    /// Default request timeout on the outbound HTTP client to upstream MCP servers.
    /// Env: `MCP_HTTP_CLIENT_TIMEOUT_SECS`. Default: 60.
    pub mcp_http_client_timeout_secs: u64,
    /// Drain window for in-flight `GET /mcp/<slug>` SSE subscribers on shutdown.
    /// Env: `MCP_GET_DRAIN_SECS`. Default: 2.
    pub mcp_get_drain_secs: u64,

    // -- Shutdown --
    /// Upper bound on the post-shutdown drain. Env: `GRACEFUL_DRAIN_TIMEOUT_SECS`. Default: 10.
    pub graceful_drain_timeout_secs: u64,

    /// The central-override subset actually applied this run (token → value),
    /// for the edge's runtime report. Never an env var or default.
    pub loaded_overrides: HashMap<String, String>,
}

/// MCP protocol versions the gateway is willing to serve, newest first.
///
/// The set spans **both protocol eras**. `2026-07-28` is *modern*: stateless,
/// no `initialize`, per-request `_meta`. The three older revisions are
/// *legacy*: an `initialize` handshake establishes connection state. The
/// gateway serves both on the same mount and decides per request, from the
/// negotiated version alone — see `mcp::modern::ProtocolEra`.
///
/// Order is load-bearing: this list is what an `UnsupportedProtocolVersion`
/// error hands a client to retry with, and § Protocol Version Negotiation has
/// the client pick from it, so the version we would rather serve comes first.
///
/// A new revision is added here **and**, if it is modern, to
/// `mcp::modern::MODERN_PROTOCOL_VERSIONS`. Membership of that second list is
/// the only thing that decides a request's era; adding a modern version here
/// alone would have the gateway accept it and then serve it legacy semantics.
pub const MCP_SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

/// Default protocol version per MCP 2025-11-25 § Protocol Version Header:
/// when a client sends a request without `MCP-Protocol-Version`, the spec
/// instructs servers to assume `2025-03-26` (back-compat clause for clients
/// that pre-date the header). The proxy's `validate_protocol_version_header`
/// uses this as the documented spec-default for the missing-header branch
/// (we currently allow without rewriting). Audit rows stay NULL when this
/// session's `initialize` wasn't seen on this proxy instance — silently
/// stamping the default would mis-attribute traffic from sessions that
/// actually negotiated a newer revision.
pub const MCP_DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";

/// The version the gateway asks for when it opens an upstream connection **on
/// its own behalf** — which is what serving a modern client requires, because
/// a modern client sends no `initialize` for us to forward.
///
/// It is the newest *legacy* revision rather than the newest revision overall:
/// today every upstream this gateway speaks to is legacy, and asking a legacy
/// server for a modern version it cannot serve would fail the handshake
/// outright. An upstream that offers less negotiates down in its `initialize`
/// reply, as the legacy handshake is designed to.
pub const MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION: &str = "2025-11-25";

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            port: 8080,
            metrics_port: 0,
            tcp_backlog: 2048,
            cors_origin: None,
            admin_api_url: "http://admin-api:9090".to_string(),
            data_dir: "/var/lib/streamscope".to_string(),
            public_metadata_rate_limit_max: 600,
            public_metadata_rate_limit_window: Duration::from_secs(300),
            response_cache_max_mb: None,
            response_cache_max_entries_per_tenant: 2_000,
            qos_queue_ttl_ms: 10_000,
            qos_queue_ttl_max_ms: 540_000,
            qos_max_held_requests: 512,
            qos_metrics_poll_secs: 2,
            session_detector_capacity: 50,
            session_detector_max_entries: 20_000,
            session_detector_ttl: Duration::from_secs(7 * 24 * 3600),
            session_prune_interval: Duration::from_secs(3600),
            session_snapshot_interval_secs: 30,
            edge_backoff_initial_secs: 1,
            edge_backoff_max_secs: 60,
            edge_sync_interval_ms: 2000,
            edge_ship_interval_ms: 1000,
            edge_state_interval_secs: 30,
            edge_usage_sync_interval_secs: 5,
            edge_request_timeout: Duration::from_secs(10),
            upstream_circuit_breaker_enabled: true,
            upstream_circuit_breaker_failure_threshold: 3,
            upstream_circuit_breaker_cooldown_secs: 30,
            sqlite_pool_size: 2,
            edge_outbox_max_mb: 1024,
            audit_debug_endpoint: false,
            appliance_host_memory: false,
            a2a_stream_max_bytes: 8 * 1024 * 1024,
            a2a_audit_stream_max_bytes: 256 * 1024,
            a2a_stream_timeout_secs: 3600,
            a2a_stream_idle_timeout_secs: 300,
            mcp_stream_max_bytes: 8 * 1024 * 1024,
            mcp_audit_payload_max_bytes: 64 * 1024,
            mcp_get_keepalive_secs: 25,
            mcp_get_bus_capacity: 256,
            mcp_legacy_sse_max_sessions_per_instance: 256,
            mcp_legacy_sse_reconnect_backoff_ms: 1_000,
            mcp_legacy_sse_request_timeout_ms: 30_000,
            mcp_token_ttl_secs: streamscope_core::mcp::tokens::DEFAULT_TOKEN_TTL_SECS,
            mcp_sse_retention_secs: 3600,
            mcp_sse_replay_limit: 1000,
            mcp_sse_token_ttl_secs: 3600,
            mcp_sse_event_tx_buffer: 4096,
            mcp_capability_cache_ttl_secs: 60,
            mcp_capability_cache_max_entries: 4096,
            mcp_session_idle_ttl_secs: 30 * 60,
            mcp_session_max_entries: 4096,
            mcp_legacy_sse_abandoned_ttl_secs: 60,
            mcp_oauth_expiry_safety_margin_secs: 30,
            mcp_sweep_interval_secs: 60,
            mcp_http_client_timeout_secs: 60,
            mcp_get_drain_secs: 2,
            graceful_drain_timeout_secs: 10,
            loaded_overrides: HashMap::new(),
        }
    }
}

/// The response cache's share of the process's memory limit when
/// `RESPONSE_CACHE_MAX_MB` is unset, and its ceiling when the process has none.
const RESPONSE_CACHE_LIMIT_PERCENT: u64 = 15;
const RESPONSE_CACHE_NO_LIMIT_MB: u64 = 256;

/// The response cache's byte ceiling: `explicit_mb` when set (0 refuses
/// every store), else [`RESPONSE_CACHE_LIMIT_PERCENT`] of the process's memory
/// `limit`, else [`RESPONSE_CACHE_NO_LIMIT_MB`].
fn response_cache_bytes(explicit_mb: Option<u64>, limit: Option<u64>) -> u64 {
    const MB: u64 = 1024 * 1024;
    match (explicit_mb, limit) {
        (Some(mb), _) => mb.saturating_mul(MB),
        (None, Some(limit)) => limit / 100 * RESPONSE_CACHE_LIMIT_PERCENT,
        (None, None) => RESPONSE_CACHE_NO_LIMIT_MB * MB,
    }
}

/// Treats an empty or whitespace-only environment value as absent.
///
/// A deploy shape that names a variable to make it settable — compose
/// `${VAR:-}`, a Helm value with no default — hands the process an empty string
/// rather than nothing. For a setting whose blank state is a real, documented
/// behaviour (`PROXY_CORS_ORIGIN` blank = allow any origin), `Some("")` would be
/// read as a value and select the opposite behaviour: an allowed origin no
/// browser can ever send. The blank has to survive the trip through a template.
fn non_empty(raw: Option<String>) -> Option<String> {
    raw.filter(|v| !v.trim().is_empty())
}

impl ProxySettings {
    fn load() -> Self {
        let mut cfg = Self::default();
        let data_dir =
            std::env::var("DATA_DIR").unwrap_or_else(|_| "/var/lib/streamscope".to_string());
        let overrides = read_runtime_overrides(&data_dir);
        let mut loaded = HashMap::new();
        macro_rules! parse_setting {
            ($var:expr, $field:expr) => {
                if let Some(raw) = resolve_setting(&overrides, $var) {
                    if let Ok(n) = raw.parse() {
                        $field = n;
                        if overrides.contains_key($var) {
                            loaded.insert($var.to_string(), raw);
                        }
                    } else if overrides.contains_key($var) {
                        tracing::warn!("ignoring unparseable runtime override {}={:?}", $var, raw);
                    }
                }
            };
            ($var:expr, $field:expr, opt) => {
                if let Some(raw) = resolve_setting(&overrides, $var) {
                    if let Ok(n) = raw.parse() {
                        $field = Some(n);
                        if overrides.contains_key($var) {
                            loaded.insert($var.to_string(), raw);
                        }
                    } else if overrides.contains_key($var) {
                        tracing::warn!("ignoring unparseable runtime override {}={:?}", $var, raw);
                    }
                }
            };
            ($var:expr, $field:expr, secs) => {
                if let Some(raw) = resolve_setting(&overrides, $var) {
                    if let Ok(n) = raw.parse::<u64>() {
                        $field = Duration::from_secs(n);
                        if overrides.contains_key($var) {
                            loaded.insert($var.to_string(), raw);
                        }
                    } else if overrides.contains_key($var) {
                        tracing::warn!("ignoring unparseable runtime override {}={:?}", $var, raw);
                    }
                }
            };
        }
        parse_setting!("PORT", cfg.port);
        parse_setting!("METRICS_PORT", cfg.metrics_port);
        parse_setting!("TCP_BACKLOG", cfg.tcp_backlog);
        parse_setting!("PUBLIC_METADATA_RATE_LIMIT_MAX", cfg.public_metadata_rate_limit_max);
        parse_setting!(
            "PUBLIC_METADATA_RATE_LIMIT_WINDOW_SECS",
            cfg.public_metadata_rate_limit_window,
            secs
        );
        // CORS origin, admin-api URL, and data dir are bootstrap/transport
        // strings — env-only, never centrally overridable.
        if let Some(v) = non_empty(std::env::var("PROXY_CORS_ORIGIN").ok()) {
            cfg.cors_origin = Some(v);
        }
        if let Ok(v) = std::env::var("ADMIN_API_URL") {
            cfg.admin_api_url = v.trim_end_matches('/').to_string();
        }
        if let Ok(v) = std::env::var("DATA_DIR") {
            cfg.data_dir = v;
        }
        parse_setting!("RESPONSE_CACHE_MAX_MB", cfg.response_cache_max_mb, opt);
        parse_setting!("QOS_QUEUE_TTL_MS", cfg.qos_queue_ttl_ms);
        parse_setting!("QOS_QUEUE_TTL_MAX_MS", cfg.qos_queue_ttl_max_ms);
        parse_setting!("QOS_MAX_HELD_REQUESTS", cfg.qos_max_held_requests);
        parse_setting!("QOS_METRICS_POLL_SECS", cfg.qos_metrics_poll_secs);
        parse_setting!(
            "RESPONSE_CACHE_MAX_ENTRIES_PER_TENANT",
            cfg.response_cache_max_entries_per_tenant
        );
        parse_setting!("SESSION_DETECTOR_CAPACITY", cfg.session_detector_capacity);
        parse_setting!("SESSION_DETECTOR_MAX_ENTRIES", cfg.session_detector_max_entries);
        parse_setting!("SESSION_DETECTOR_TTL_SECS", cfg.session_detector_ttl, secs);
        parse_setting!("SESSION_PRUNE_INTERVAL_SECS", cfg.session_prune_interval, secs);
        parse_setting!("SESSION_SNAPSHOT_INTERVAL_SECS", cfg.session_snapshot_interval_secs);
        parse_setting!("EDGE_BACKOFF_INITIAL_SECS", cfg.edge_backoff_initial_secs);
        parse_setting!("EDGE_BACKOFF_MAX_SECS", cfg.edge_backoff_max_secs);
        parse_setting!("EDGE_SYNC_INTERVAL_MS", cfg.edge_sync_interval_ms);
        parse_setting!("EDGE_SHIP_INTERVAL_MS", cfg.edge_ship_interval_ms);
        parse_setting!("EDGE_STATE_INTERVAL_SECS", cfg.edge_state_interval_secs);
        parse_setting!("EDGE_USAGE_SYNC_INTERVAL_SECS", cfg.edge_usage_sync_interval_secs);
        parse_setting!("EDGE_REQUEST_TIMEOUT_SECS", cfg.edge_request_timeout, secs);
        parse_setting!(
            "UPSTREAM_CIRCUIT_BREAKER_ENABLED",
            cfg.upstream_circuit_breaker_enabled
        );
        parse_setting!(
            "UPSTREAM_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            cfg.upstream_circuit_breaker_failure_threshold
        );
        parse_setting!(
            "UPSTREAM_CIRCUIT_BREAKER_COOLDOWN_SECS",
            cfg.upstream_circuit_breaker_cooldown_secs
        );
        parse_setting!("SQLITE_POOL_SIZE", cfg.sqlite_pool_size);
        parse_setting!("EDGE_OUTBOX_MAX_MB", cfg.edge_outbox_max_mb);
        parse_setting!("AUDIT_DEBUG_ENDPOINT", cfg.audit_debug_endpoint);
        parse_setting!("APPLIANCE_HOST_MEMORY", cfg.appliance_host_memory);
        parse_setting!("A2A_STREAM_MAX_BYTES", cfg.a2a_stream_max_bytes);
        parse_setting!("A2A_AUDIT_STREAM_MAX_BYTES", cfg.a2a_audit_stream_max_bytes);
        parse_setting!("A2A_STREAM_TIMEOUT_SECS", cfg.a2a_stream_timeout_secs);
        parse_setting!("A2A_STREAM_IDLE_TIMEOUT_SECS", cfg.a2a_stream_idle_timeout_secs);
        parse_setting!("MCP_STREAM_MAX_BYTES", cfg.mcp_stream_max_bytes);
        parse_setting!("MCP_AUDIT_PAYLOAD_MAX_BYTES", cfg.mcp_audit_payload_max_bytes);
        parse_setting!("MCP_GET_KEEPALIVE_SECS", cfg.mcp_get_keepalive_secs);
        parse_setting!("MCP_GET_BUS_CAPACITY", cfg.mcp_get_bus_capacity);
        parse_setting!(
            "MCP_LEGACY_SSE_MAX_SESSIONS_PER_INSTANCE",
            cfg.mcp_legacy_sse_max_sessions_per_instance
        );
        parse_setting!(
            "MCP_LEGACY_SSE_RECONNECT_BACKOFF_MS",
            cfg.mcp_legacy_sse_reconnect_backoff_ms
        );
        parse_setting!(
            "MCP_LEGACY_SSE_REQUEST_TIMEOUT_MS",
            cfg.mcp_legacy_sse_request_timeout_ms
        );
        parse_setting!("MCP_TOKEN_TTL_SECS", cfg.mcp_token_ttl_secs);
        parse_setting!("MCP_SSE_RETENTION_SECS", cfg.mcp_sse_retention_secs);
        parse_setting!("MCP_SSE_REPLAY_LIMIT", cfg.mcp_sse_replay_limit);
        parse_setting!("MCP_SSE_TOKEN_TTL_SECS", cfg.mcp_sse_token_ttl_secs);
        parse_setting!("MCP_SSE_EVENT_TX_BUFFER", cfg.mcp_sse_event_tx_buffer);
        parse_setting!("MCP_CAPABILITY_CACHE_TTL_SECS", cfg.mcp_capability_cache_ttl_secs);
        parse_setting!(
            "MCP_CAPABILITY_CACHE_MAX_ENTRIES",
            cfg.mcp_capability_cache_max_entries
        );
        parse_setting!("MCP_SESSION_IDLE_TTL_SECS", cfg.mcp_session_idle_ttl_secs);
        parse_setting!("MCP_SESSION_MAX_ENTRIES", cfg.mcp_session_max_entries);
        parse_setting!(
            "MCP_LEGACY_SSE_ABANDONED_TTL_SECS",
            cfg.mcp_legacy_sse_abandoned_ttl_secs
        );
        parse_setting!(
            "MCP_OAUTH_EXPIRY_SAFETY_MARGIN_SECS",
            cfg.mcp_oauth_expiry_safety_margin_secs
        );
        parse_setting!("MCP_SWEEP_INTERVAL_SECS", cfg.mcp_sweep_interval_secs);
        parse_setting!("MCP_HTTP_CLIENT_TIMEOUT_SECS", cfg.mcp_http_client_timeout_secs);
        parse_setting!("MCP_GET_DRAIN_SECS", cfg.mcp_get_drain_secs);
        parse_setting!("GRACEFUL_DRAIN_TIMEOUT_SECS", cfg.graceful_drain_timeout_secs);
        cfg.loaded_overrides = loaded;
        cfg
    }

    /// Current effective value of every setting, keyed by env-var token.
    pub fn effective_values(&self) -> HashMap<String, String> {
        HashMap::from([
            ("PORT".to_string(), self.port.to_string()),
            ("METRICS_PORT".to_string(), self.metrics_port.to_string()),
            ("TCP_BACKLOG".to_string(), self.tcp_backlog.to_string()),
            (
                "PROXY_CORS_ORIGIN".to_string(),
                self.cors_origin.clone().unwrap_or_default(),
            ),
            ("ADMIN_API_URL".to_string(), self.admin_api_url.clone()),
            ("DATA_DIR".to_string(), self.data_dir.clone()),
            (
                "PUBLIC_METADATA_RATE_LIMIT_MAX".to_string(),
                self.public_metadata_rate_limit_max.to_string(),
            ),
            (
                "PUBLIC_METADATA_RATE_LIMIT_WINDOW_SECS".to_string(),
                self.public_metadata_rate_limit_window.as_secs().to_string(),
            ),
            (
                "RESPONSE_CACHE_MAX_MB".to_string(),
                self.response_cache_max_mb.map_or_else(String::new, |mb| mb.to_string()),
            ),
            (
                "RESPONSE_CACHE_MAX_ENTRIES_PER_TENANT".to_string(),
                self.response_cache_max_entries_per_tenant.to_string(),
            ),
            ("QOS_QUEUE_TTL_MS".to_string(), self.qos_queue_ttl_ms.to_string()),
            ("QOS_QUEUE_TTL_MAX_MS".to_string(), self.qos_queue_ttl_max_ms.to_string()),
            ("QOS_MAX_HELD_REQUESTS".to_string(), self.qos_max_held_requests.to_string()),
            ("QOS_METRICS_POLL_SECS".to_string(), self.qos_metrics_poll_secs.to_string()),
            (
                "SESSION_DETECTOR_CAPACITY".to_string(),
                self.session_detector_capacity.to_string(),
            ),
            (
                "SESSION_DETECTOR_MAX_ENTRIES".to_string(),
                self.session_detector_max_entries.to_string(),
            ),
            (
                "SESSION_DETECTOR_TTL_SECS".to_string(),
                self.session_detector_ttl.as_secs().to_string(),
            ),
            (
                "SESSION_PRUNE_INTERVAL_SECS".to_string(),
                self.session_prune_interval.as_secs().to_string(),
            ),
            (
                "SESSION_SNAPSHOT_INTERVAL_SECS".to_string(),
                self.session_snapshot_interval_secs.to_string(),
            ),
            ("EDGE_BACKOFF_INITIAL_SECS".to_string(), self.edge_backoff_initial_secs.to_string()),
            ("EDGE_BACKOFF_MAX_SECS".to_string(), self.edge_backoff_max_secs.to_string()),
            ("EDGE_SYNC_INTERVAL_MS".to_string(), self.edge_sync_interval_ms.to_string()),
            ("EDGE_SHIP_INTERVAL_MS".to_string(), self.edge_ship_interval_ms.to_string()),
            ("EDGE_STATE_INTERVAL_SECS".to_string(), self.edge_state_interval_secs.to_string()),
            (
                "EDGE_USAGE_SYNC_INTERVAL_SECS".to_string(),
                self.edge_usage_sync_interval_secs.to_string(),
            ),
            (
                "EDGE_REQUEST_TIMEOUT_SECS".to_string(),
                self.edge_request_timeout.as_secs().to_string(),
            ),
            ("SQLITE_POOL_SIZE".to_string(), self.sqlite_pool_size.to_string()),
            ("EDGE_OUTBOX_MAX_MB".to_string(), self.edge_outbox_max_mb.to_string()),
            ("AUDIT_DEBUG_ENDPOINT".to_string(), self.audit_debug_endpoint.to_string()),
            ("APPLIANCE_HOST_MEMORY".to_string(), self.appliance_host_memory.to_string()),
            ("A2A_STREAM_MAX_BYTES".to_string(), self.a2a_stream_max_bytes.to_string()),
            (
                "A2A_AUDIT_STREAM_MAX_BYTES".to_string(),
                self.a2a_audit_stream_max_bytes.to_string(),
            ),
            (
                "A2A_STREAM_TIMEOUT_SECS".to_string(),
                self.a2a_stream_timeout_secs.to_string(),
            ),
            (
                "A2A_STREAM_IDLE_TIMEOUT_SECS".to_string(),
                self.a2a_stream_idle_timeout_secs.to_string(),
            ),
            ("MCP_STREAM_MAX_BYTES".to_string(), self.mcp_stream_max_bytes.to_string()),
            (
                "MCP_AUDIT_PAYLOAD_MAX_BYTES".to_string(),
                self.mcp_audit_payload_max_bytes.to_string(),
            ),
            ("MCP_GET_KEEPALIVE_SECS".to_string(), self.mcp_get_keepalive_secs.to_string()),
            ("MCP_GET_BUS_CAPACITY".to_string(), self.mcp_get_bus_capacity.to_string()),
            (
                "MCP_LEGACY_SSE_MAX_SESSIONS_PER_INSTANCE".to_string(),
                self.mcp_legacy_sse_max_sessions_per_instance.to_string(),
            ),
            (
                "MCP_LEGACY_SSE_RECONNECT_BACKOFF_MS".to_string(),
                self.mcp_legacy_sse_reconnect_backoff_ms.to_string(),
            ),
            (
                "MCP_LEGACY_SSE_REQUEST_TIMEOUT_MS".to_string(),
                self.mcp_legacy_sse_request_timeout_ms.to_string(),
            ),
            ("MCP_TOKEN_TTL_SECS".to_string(), self.mcp_token_ttl_secs.to_string()),
            ("MCP_SSE_RETENTION_SECS".to_string(), self.mcp_sse_retention_secs.to_string()),
            ("MCP_SSE_REPLAY_LIMIT".to_string(), self.mcp_sse_replay_limit.to_string()),
            ("MCP_SSE_TOKEN_TTL_SECS".to_string(), self.mcp_sse_token_ttl_secs.to_string()),
            ("MCP_SSE_EVENT_TX_BUFFER".to_string(), self.mcp_sse_event_tx_buffer.to_string()),
            (
                "MCP_CAPABILITY_CACHE_TTL_SECS".to_string(),
                self.mcp_capability_cache_ttl_secs.to_string(),
            ),
            (
                "MCP_CAPABILITY_CACHE_MAX_ENTRIES".to_string(),
                self.mcp_capability_cache_max_entries.to_string(),
            ),
            (
                "MCP_SESSION_IDLE_TTL_SECS".to_string(),
                self.mcp_session_idle_ttl_secs.to_string(),
            ),
            ("MCP_SESSION_MAX_ENTRIES".to_string(), self.mcp_session_max_entries.to_string()),
            (
                "MCP_LEGACY_SSE_ABANDONED_TTL_SECS".to_string(),
                self.mcp_legacy_sse_abandoned_ttl_secs.to_string(),
            ),
            (
                "MCP_OAUTH_EXPIRY_SAFETY_MARGIN_SECS".to_string(),
                self.mcp_oauth_expiry_safety_margin_secs.to_string(),
            ),
            ("MCP_SWEEP_INTERVAL_SECS".to_string(), self.mcp_sweep_interval_secs.to_string()),
            (
                "MCP_HTTP_CLIENT_TIMEOUT_SECS".to_string(),
                self.mcp_http_client_timeout_secs.to_string(),
            ),
            ("MCP_GET_DRAIN_SECS".to_string(), self.mcp_get_drain_secs.to_string()),
            (
                "GRACEFUL_DRAIN_TIMEOUT_SECS".to_string(),
                self.graceful_drain_timeout_secs.to_string(),
            ),
            (
                "UPSTREAM_CIRCUIT_BREAKER_ENABLED".to_string(),
                self.upstream_circuit_breaker_enabled.to_string(),
            ),
            (
                "UPSTREAM_CIRCUIT_BREAKER_FAILURE_THRESHOLD".to_string(),
                self.upstream_circuit_breaker_failure_threshold.to_string(),
            ),
            (
                "UPSTREAM_CIRCUIT_BREAKER_COOLDOWN_SECS".to_string(),
                self.upstream_circuit_breaker_cooldown_secs.to_string(),
            ),
        ])
    }

    /// Response-cache byte ceiling: the explicit `RESPONSE_CACHE_MAX_MB`, else
    /// 15% of this process's memory limit, else 256 MB when no limit is set.
    pub fn response_cache_max_bytes(&self) -> u64 {
        response_cache_bytes(self.response_cache_max_mb, streamscope_core::cgroup::memory_limit_bytes())
    }

    /// Log any settings that differ from their compiled-in default.
    pub fn log_non_defaults(&self) {
        let defaults = Self::default().effective_values();
        for (token, value) in self.effective_values() {
            if defaults.get(&token) != Some(&value) {
                let default = defaults.get(&token).map(String::as_str).unwrap_or("?");
                tracing::info!("settings override: {token}={value} (default: {default})");
            }
        }
    }
}

/// Access proxy settings. Auto-initializes on first call.
pub fn proxy_settings() -> &'static ProxySettings {
    &SETTINGS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use streamscope_core::settings_catalog::{SETTINGS_CATALOG, SettingGroup};

    /// Unset is "size it from the limit", 0 is "refuse every store": with a limit
    /// the ceiling is 15% of it, without one 256 MB, and an explicit value wins
    /// over both — including on a process that has a limit. Locks the
    /// production constants, not only the shape of the rule.
    #[test]
    fn the_response_cache_is_explicit_else_15_percent_of_the_limit_else_256_mb() {
        const MB: u64 = 1024 * 1024;
        assert_eq!(response_cache_bytes(None, Some(512 * MB)), 512 * MB / 100 * 15);
        assert_eq!(response_cache_bytes(None, Some(2048 * MB)), 2048 * MB / 100 * 15);
        assert_eq!(response_cache_bytes(None, None), 256 * MB);
        assert_eq!(response_cache_bytes(Some(0), Some(512 * MB)), 0);
        assert_eq!(response_cache_bytes(Some(1), Some(512 * MB)), MB);
        assert_eq!(response_cache_bytes(Some(300), None), 300 * MB);
        assert_eq!(response_cache_bytes(Some(u64::MAX), None), u64::MAX);
    }

    /// A blank value must read as "not set", because blank is itself the
    /// documented permissive default for CORS. Treating it as a value inverts
    /// the behaviour — the gateway locks to an origin nothing can send — and no
    /// integration test would see it, since every deploy shape that reaches
    /// this state does so by naming the variable with an empty default.
    #[test]
    fn a_blank_env_value_reads_as_unset_not_as_the_empty_string() {
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("   ".to_string())), None);
        assert_eq!(
            non_empty(Some("https://app.example.com".to_string())),
            Some("https://app.example.com".to_string())
        );
    }

    #[test]
    fn catalog_matches_proxy_settings() {
        let effective = ProxySettings::default().effective_values();
        let catalog: Vec<_> = SETTINGS_CATALOG
            .iter()
            .filter(|m| m.group == SettingGroup::Proxy)
            .collect();

        let catalog_tokens: HashSet<&str> = catalog.iter().map(|m| m.token).collect();
        let effective_tokens: HashSet<&str> = effective.keys().map(String::as_str).collect();
        assert_eq!(
            catalog_tokens, effective_tokens,
            "proxy catalog tokens must match ProxySettings::effective_values"
        );

        for meta in &catalog {
            assert_eq!(
                effective.get(meta.token).map(String::as_str),
                Some(meta.default),
                "catalog default for {} must match the struct default",
                meta.token
            );
        }
    }
}
