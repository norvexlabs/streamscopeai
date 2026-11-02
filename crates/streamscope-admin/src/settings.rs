//! Process-level settings for the admin API.
//!
//! Centralized runtime configuration loaded from environment variables at startup.
//! Uses `LazyLock` — auto-initializes on first access, no explicit `init()` needed.
//! All fields have sane defaults; env vars override only when explicitly set.
//!
//! Access via [`admin_settings()`]. Touch early in `main()` to trigger init + startup logging.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

static SETTINGS: LazyLock<AdminSettings> = LazyLock::new(AdminSettings::from_env);

/// Admin API settings.
pub struct AdminSettings {
    // -- Networking --
    /// HTTP listen port. Env: `PORT`. Default: 9090.
    pub port: u16,
    /// Dedicated Prometheus /metrics listen port; 0 disables the listener.
    /// Env: `METRICS_PORT`. Default: 0.
    pub metrics_port: u16,

    // -- Database --
    /// PostgreSQL pool size. Env: `DB_MAX_CONNECTIONS`. Default: 20.
    pub db_max_connections: u32,
    /// Connection acquire timeout. Env: `DB_ACQUIRE_TIMEOUT_SECS`. Default: 5.
    pub db_acquire_timeout: Duration,
    /// Whether startup sets `streamscope_app`'s password (from `DATABASE_URL`)
    /// and its `transaction_timeout`; `false` when the operator owns the role.
    /// Read only at migration time. Env: `DB_MANAGE_APP_ROLE`. Default: true.
    pub db_manage_app_role: bool,
    /// `transaction_timeout` set on `streamscope_app` while the role is
    /// managed (`0` disables). Env: `DB_APP_TRANSACTION_TIMEOUT`. Default: `1h`.
    pub db_app_transaction_timeout: String,

    // -- Auth --
    /// Session token lifetime (admin + portal). Env: `JWT_EXPIRY_HOURS`. Default: 8.
    pub jwt_expiry_hours: i64,
    /// OIDC discovery HTTP timeout. Env: `OIDC_CLIENT_TIMEOUT_SECS`. Default: 5.
    pub oidc_client_timeout: Duration,
    /// Skip TLS verification for OIDC (dev only). Env: `OIDC_SKIP_TLS_VERIFY`. Default: false.
    pub oidc_skip_tls_verify: bool,
    /// Auth mode override. Env: `AUTH_MODE`. Default: empty.
    pub auth_mode: String,
    /// The tenant a header-auth deployment serves. In `AUTH_MODE=header` the
    /// reverse proxy proves *identity*; this names the *tenant* that identity
    /// belongs to, and it is deliberately not something a request can carry —
    /// choosing your own tenant is choosing your own permissions.
    /// Env: `HEADER_AUTH_TENANT_SLUG`. Default: empty (the SYSTEM tenant).
    pub header_auth_tenant_slug: String,
    /// The proxy that authenticates users in `AUTH_MODE=header`, named by the
    /// operator. **Required to start in header mode** — see the boot check in
    /// `main`.
    ///
    /// Header mode makes `GET /api/v1/auth/me` mint a console session from an
    /// `X-Auth-Request-Email` header with no credential, because a proxy in
    /// front is supposed to have already authenticated the request. That is a
    /// sound design and a total compromise if the proxy is not there: this
    /// process is published on its own vhost on every deploy shape, so an
    /// unprotected one hands a session to anyone who names an existing address.
    ///
    /// The value is not parsed or matched against the peer — a CIDR check would
    /// be a lockout waiting to happen, since the peer is a container or pod
    /// address that changes. Its job is to make the requirement **impossible to
    /// meet by accident**: header mode cannot be switched on without stating
    /// what is doing the authenticating.
    /// Env: `HEADER_AUTH_TRUSTED_PROXY`. Default: empty.
    pub header_auth_trusted_proxy: String,
    /// Honour an inbound `X-Tenant-Slug` as the header-auth tenant selector.
    ///
    /// Only for a topology where the reverse proxy *sets* that header per
    /// vhost, overwriting whatever the client sent — one admin-api serving
    /// several tenants. Nothing inside this process can tell an overwritten
    /// header from a forged one, so it is off unless an operator asserts the
    /// topology. `header_auth_tenant_slug` still wins where both are set: a
    /// pinned deployment must not be steerable.
    /// Env: `HEADER_AUTH_TRUST_TENANT_HEADER`. Default: false.
    pub header_auth_trust_tenant_header: bool,
    /// Accept an identity asserted by an internal caller on its own word,
    /// rather than one this process verified from a provider signature.
    ///
    /// Covers BOTH planes: `POST /api/v1/auth/oidc-exchange` (console) and the
    /// service-secret path of `GET /api/v1/portal/auth/header-me` (portal).
    /// Past either, the caller names the user and the tenant and receives a
    /// session for them, so the shared secret is standing in for proof of
    /// identity — which is why one setting governs both.
    ///
    /// The gateway's own login paths do not use it; enable only for a
    /// deployment provisioning accounts from its own already-verified identity
    /// source. Env: `ALLOW_OIDC_CLAIM_EXCHANGE`. Default: false.
    pub allow_oidc_claim_exchange: bool,
    /// Expose the interactive OpenAPI docs (`/api/docs`) and spec
    /// (`/api/docs/openapi.json`). Set false to 404 both on a public
    /// deployment where the API surface shouldn't be enumerable.
    /// Env: `API_DOCS_PUBLIC`. Default: true.
    pub api_docs_public: bool,

    // -- Rate limiting --
    /// Shared rate limit window. Env: `RATE_LIMIT_WINDOW_SECS`. Default: 300.
    pub rate_limit_window_secs: u64,
    /// Login/invite attempts per window. Env: `RATE_LIMIT_LOGIN_MAX`. Default: 10.
    pub rate_limit_login_max: u32,
    /// Number of admin-api instances. Rate limits divided by this. Env: `RATE_LIMIT_INSTANCE_COUNT`. Default: 1.
    pub rate_limit_instance_count: u32,
    /// Per-source-IP request cap on the unauthenticated pre-auth surfaces
    /// (login, setup, OIDC/OAuth exchange, invite acceptance, tenant auth-info,
    /// MCP-OAuth metadata/grant/register), per `rate_limit_window_secs`. Bounds
    /// a single IP that varies the identity string to slip past the per-account
    /// limiter. 0 disables it. Generous by default — many legitimate users can
    /// share one IP behind a NAT. Env: `PRE_AUTH_IP_RATE_LIMIT_MAX`. Default: 600.
    pub pre_auth_ip_rate_limit_max: u32,
    /// Per-key request cap on authenticated `ak-` automation traffic, per
    /// `rate_limit_window_secs`. The pre-auth IP limiter does not cover these —
    /// they authenticate, so without this a leaked automation key runs the admin
    /// or portal API at whatever rate it likes. Checked on the presented key's
    /// hash before any lookup, so a flooding key costs no database work.
    /// 0 disables it. Generous by default: automation is legitimately chatty and
    /// this is a blast-radius ceiling, not a quota. Env:
    /// `AUTOMATION_KEY_RATE_LIMIT_MAX`. Default: 3000.
    pub automation_key_rate_limit_max: u32,
    /// How many **distinct** `ak-` keys one source may fail to authenticate
    /// with, per `rate_limit_window_secs`. The per-key limiter above bounds
    /// repetition of ONE key (the leaked-key case) and is no help against a
    /// prober, who varies the token and draws a fresh bucket every time while
    /// still driving a full O(tenants) resolve scan. This bounds that by source.
    /// Counting *distinct keys* is what separates a prober (a new key each
    /// attempt) from a misconfigured client (one stale key forever, so it never
    /// trips however long it runs). 0 disables it. Env:
    /// `AUTOMATION_KEY_IP_RATE_LIMIT_MAX`. Default: 60.
    pub automation_key_ip_rate_limit_max: u32,

    // -- Retention --
    /// Purge cycle interval. Env: `RETENTION_CYCLE_INTERVAL_SECS`. Default: 21600 (6h).
    pub retention_cycle_interval: Duration,
    /// Large table batch delete size. Env: `RETENTION_BATCH_SIZE`. Default: 10000.
    pub retention_batch_size: i64,
    /// Sleep between retention batches. Env: `RETENTION_BATCH_SLEEP_MS`. Default: 100.
    pub retention_batch_sleep_ms: u64,
    /// Retention a disk-pressure purge goes down to under hard pressure, and
    /// the floor a soft one never goes below (`pressure_retention_days`; read
    /// as at least 1). Env: `DB_SIZE_MIN_RETENTION_DAYS`. Default: 7.
    pub db_size_min_retention_days: i64,

    // -- Config sync --
    /// How often each replica rebuilds the edge config bodies whose change
    /// counters moved. Env: `EDGE_SYNC_REFRESH_MS`. Default: 2000.
    pub edge_sync_refresh_ms: u64,
    /// How long an edge event stays deliverable. Env: `EDGE_EVENT_TTL_SECS`. Default: 600.
    pub edge_event_ttl_secs: u64,

    // -- Edge sync --
    /// How often edges report their state (the proxies' `EDGE_STATE_INTERVAL_SECS`);
    /// see [`Self::edge_connected_window`]. Env: `EDGE_HEARTBEAT_INTERVAL_SECS`. Default: 30.
    pub edge_heartbeat_interval_secs: u64,
    /// How often the leader-elected usage janitor GCs elapsed-window fleet usage
    /// counters + watermarks. Env: `USAGE_JANITOR_INTERVAL_SECS`. Default: 3600.
    pub usage_janitor_interval_secs: u64,
    /// How often the leader-elected alert dispatcher evaluates budget crossings
    /// and delivers pending notifications. Also woken immediately by
    /// `pg_notify('notify_pending')` on a new event. Env:
    /// `ALERT_DISPATCH_INTERVAL_SECS`. Default: 300.
    pub alert_dispatch_interval_secs: u64,

    // -- Shutdown --
    /// Upper bound on the post-shutdown wait for background workers (agent,
    /// retention, MCP OAuth cleanup, …) to
    /// exit voluntarily after SIGTERM/SIGINT. On timeout the process exits
    /// anyway. Env: `SHUTDOWN_DRAIN_TIMEOUT_SECS`. Default: 20.
    pub shutdown_drain_timeout: Duration,

    // -- Pagination --
    /// Max audit/session page size. Env: `AUDIT_MAX_LIMIT`. Default: 1000.
    pub audit_max_limit: i64,

    // -- Model sync --
    /// How often the autosync worker re-discovers each upstream marked
    /// `auto_sync_enabled`. A server is due when `last_auto_sync_at` is NULL or
    /// older than this. Env: `MODEL_AUTOSYNC_INTERVAL_HOURS`. Default: 24.
    pub model_autosync_interval_hours: u64,

    // -- Agent --
    /// LLM call timeout. Env: `AGENT_HTTP_TIMEOUT_SECS`. Default: 300.
    /// Generous by design: small / local reasoning models can legitimately
    /// think for several minutes before emitting the `submit_analysis` call.
    pub agent_http_timeout: Duration,
    /// Max concurrent per-session expert LLM calls within one batch. Bounds the
    /// fan-out so a slow/hung upstream call no longer serializes the whole cycle.
    /// Env: `AGENT_SESSION_CONCURRENCY`. Default: 4.
    pub agent_session_concurrency: usize,
    /// Retry attempts for a transient agent→proxy failure (connect error / 429 /
    /// 5xx). A request timeout is retried at most once regardless. Env:
    /// `AGENT_HTTP_MAX_RETRIES`. Default: 2.
    pub agent_http_max_retries: usize,
    /// Sessions per analysis batch. Env: `AGENT_SESSION_BATCH_LIMIT`. Default: 50.
    pub agent_session_batch_limit: i64,
    /// Maximum new suggestions stored per (tenant, expert axis, cycle, kind).
    /// Excess proposals from a single analysis call are truncated with a warn
    /// log. Prevents a single noisy cycle from flooding the suggestions queue.
    /// Env: `AGENT_SUGGESTIONS_PER_CYCLE_CAP`. Default: 3.
    pub agent_suggestions_per_cycle_cap: usize,
    /// Minimum number of cycles a pending suggestion must be re-proposed
    /// before it surfaces to operators. One-shot hallucinations accumulate
    /// `seen_count = 1` and never reach the UI; only patterns the agent
    /// re-proposes across multiple cycles cross the gate. Set to `1` to
    /// surface every proposal on first sight (legacy behavior).
    /// Env: `AGENT_SUGGESTION_MIN_SEEN`. Default: 2.
    pub agent_suggestion_min_seen: i32,

    // -- Misc --
    /// Max Rhai script upload size (bytes). Env: `MAX_SCRIPT_SIZE`. Default: 100000.
    pub max_script_size: usize,
    /// Seed data directory. Env: `SEEDS_DIR`. Default: `seeds`.
    pub seeds_dir: String,
    /// Public origin shared by admin-api + admin-ui (scheme + host[:port], no
    /// Pending OAuth authorization TTL (seconds). The portal's connect flow
    /// inserts a row with `expires_at = now + this`; the leader sweeper
    /// reaps expired rows on a 5-minute cadence.
    /// Env: `MCP_OAUTH_PENDING_TTL_SECS`. Default: 600 (10 minutes).
    pub mcp_oauth_pending_ttl_secs: i64,
    /// Per-tenant cap on `mcp_oauth_clients` rows registered via RFC 7591
    /// dynamic client registration. The endpoint is unauthenticated by spec,
    /// so the cap is the load-bearing abuse control. Manually-issued clients
    /// (operator-side) count against the same cap.
    /// Env: `MCP_OAUTH_DCR_PER_TENANT_CAP`. Default: 1000.
    pub mcp_oauth_dcr_per_tenant_cap: i64,
    /// Hourly partition retention window for `mcp_sse_events`. The retention
    /// sweeper drops partitions older than this. Must agree with the proxy's
    /// `MCP_SSE_RETENTION_SECS` so writes don't outrun the partition coverage.
    /// Env: `MCP_SSE_RETENTION_SECS`. Default: 3600 (1h).
    pub mcp_sse_retention_secs: u64,
    /// Where the expert/agent worker reaches the gateway to run its analysis
    /// (admin-api → proxy `/v1/chat/completions`). The default service name
    /// `proxy` resolves on the VM/compose deploy; the Helm chart overrides it to
    /// the in-cluster `<release>-proxy` Service so the agent works on Kubernetes.
    /// A per-tenant `agent_proxy_url` setting still wins when present.
    /// Env: `AGENT_PROXY_URL`. Default: `http://proxy:8080`.
    pub agent_proxy_url: String,
    /// Filesystem path to the gateway's root CA certificate (PEM), served by
    /// `GET /api/v1/cli/ca` so the CLI installer can trust-on-first-use the
    /// *root* (the stable anchor) rather than the rotated intermediate the TLS
    /// handshake presents. Set on deployments that terminate TLS with a private
    /// CA: the VM appliance points this at the shared `cli-ca/ca.pem`. Empty (the
    /// default) — and on publicly-trusted deployments — leaves the endpoint
    /// 404ing, so the installer refuses rather than trusting the served leaf.
    /// Env: `GATEWAY_CA_FILE`. Default: empty.
    pub gateway_ca_file: String,
    /// Path of the host daemon's app socket, which the VM mounts into this
    /// container. Set **only** on the Kairos VM; empty everywhere else
    /// (Kubernetes, Docker, dev). It is both the daemon's address AND the "is
    /// this an appliance?" discriminator: when empty, the whole web Appliance
    /// surface (lifecycle, backup, network, upgrade-check worker) is off and its
    /// routes answer `ApplianceUnavailable`. The socket's bearer token is the
    /// secret `STOWAGE_HOST_TOKEN`, read directly.
    /// Env: `STOWAGE_HOST_SOCKET`. Default: empty.
    pub stowage_host_socket: String,
    /// How often the leader-elected worker polls the host daemon for an
    /// available OS upgrade (and raises an `ApplianceUpgradeAvailable`
    /// notification). Inert unless `stowage_host_socket` is set.
    /// Env: `APPLIANCE_UPGRADE_CHECK_INTERVAL_SECS`. Default: 21600 (6h).
    pub appliance_upgrade_check_interval_secs: u64,
}

impl AdminSettings {
    /// True on the Kairos VM appliance (the host daemon's socket is mounted);
    /// false on every other shape. Gates the entire web Appliance surface.
    pub fn is_appliance(&self) -> bool {
        !self.stowage_host_socket.is_empty()
    }
}

impl Default for AdminSettings {
    fn default() -> Self {
        Self {
            port: 9090,
            metrics_port: 0,
            db_max_connections: 20,
            db_acquire_timeout: Duration::from_secs(5),
            db_manage_app_role: true,
            db_app_transaction_timeout: "1h".to_string(),
            jwt_expiry_hours: 8,
            oidc_client_timeout: Duration::from_secs(5),
            oidc_skip_tls_verify: false,
            auth_mode: String::new(),
            header_auth_tenant_slug: String::new(),
            header_auth_trusted_proxy: String::new(),
            header_auth_trust_tenant_header: false,
            allow_oidc_claim_exchange: false,
            api_docs_public: true,
            rate_limit_window_secs: 300,
            rate_limit_login_max: 10,
            rate_limit_instance_count: 1,
            pre_auth_ip_rate_limit_max: 600,
            automation_key_rate_limit_max: 3000,
            automation_key_ip_rate_limit_max: 60,
            retention_cycle_interval: Duration::from_secs(6 * 3600),
            retention_batch_size: 10_000,
            retention_batch_sleep_ms: 100,
            db_size_min_retention_days: 7,
            edge_sync_refresh_ms: 2000,
            edge_event_ttl_secs: 600,
            edge_heartbeat_interval_secs: 30,
            usage_janitor_interval_secs: 3600,
            alert_dispatch_interval_secs: 300,
            shutdown_drain_timeout: Duration::from_secs(20),
            audit_max_limit: 1000,
            model_autosync_interval_hours: 24,
            agent_http_timeout: Duration::from_secs(300),
            agent_session_concurrency: 4,
            agent_http_max_retries: 2,
            agent_session_batch_limit: 50,
            agent_suggestions_per_cycle_cap: 3,
            agent_suggestion_min_seen: 2,
            max_script_size: 100_000,
            seeds_dir: "seeds".to_string(),
            mcp_oauth_pending_ttl_secs: 600,
            mcp_oauth_dcr_per_tenant_cap: 1000,
            mcp_sse_retention_secs: 3600,
            agent_proxy_url: crate::agent::DEFAULT_AGENT_PROXY_URL.to_string(),
            gateway_ca_file: String::new(),
            stowage_host_socket: String::new(),
            appliance_upgrade_check_interval_secs: 21_600,
        }
    }
}

impl AdminSettings {
    fn from_env() -> Self {
        let mut cfg = Self::default();
        macro_rules! parse_env {
            ($var:expr, $field:expr) => {
                if let Ok(v) = std::env::var($var)
                    && let Ok(n) = v.parse() { $field = n; }
            };
        }
        parse_env!("PORT", cfg.port);
        parse_env!("METRICS_PORT", cfg.metrics_port);
        parse_env!("DB_MAX_CONNECTIONS", cfg.db_max_connections);
        if let Ok(v) = std::env::var("DB_ACQUIRE_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>() { cfg.db_acquire_timeout = Duration::from_secs(n); }
        if let Ok(v) = std::env::var("DB_MANAGE_APP_ROLE") {
            cfg.db_manage_app_role =
                !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off");
        }
        if let Ok(v) = std::env::var("DB_APP_TRANSACTION_TIMEOUT")
            && !v.trim().is_empty()
        {
            cfg.db_app_transaction_timeout = v.trim().to_string();
        }
        parse_env!("JWT_EXPIRY_HOURS", cfg.jwt_expiry_hours);
        if let Ok(v) = std::env::var("OIDC_CLIENT_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>() { cfg.oidc_client_timeout = Duration::from_secs(n); }
        cfg.oidc_skip_tls_verify = std::env::var("OIDC_SKIP_TLS_VERIFY")
            .unwrap_or_default() == "true";
        if let Ok(v) = std::env::var("AUTH_MODE") {
            cfg.auth_mode = v;
        }
        if let Ok(v) = std::env::var("HEADER_AUTH_TENANT_SLUG") {
            cfg.header_auth_tenant_slug = v.trim().to_string();
        }
        if let Ok(v) = std::env::var("HEADER_AUTH_TRUSTED_PROXY") {
            cfg.header_auth_trusted_proxy = v.trim().to_string();
        }
        cfg.header_auth_trust_tenant_header = std::env::var("HEADER_AUTH_TRUST_TENANT_HEADER")
            .unwrap_or_default() == "true";
        cfg.allow_oidc_claim_exchange = std::env::var("ALLOW_OIDC_CLAIM_EXCHANGE")
            .unwrap_or_default() == "true";
        cfg.api_docs_public = std::env::var("API_DOCS_PUBLIC")
            .map(|v| v != "false")
            .unwrap_or(true);
        parse_env!("RATE_LIMIT_WINDOW_SECS", cfg.rate_limit_window_secs);
        parse_env!("RATE_LIMIT_LOGIN_MAX", cfg.rate_limit_login_max);
        parse_env!("RATE_LIMIT_INSTANCE_COUNT", cfg.rate_limit_instance_count);
        parse_env!("PRE_AUTH_IP_RATE_LIMIT_MAX", cfg.pre_auth_ip_rate_limit_max);
        parse_env!("AUTOMATION_KEY_RATE_LIMIT_MAX", cfg.automation_key_rate_limit_max);
        parse_env!("AUTOMATION_KEY_IP_RATE_LIMIT_MAX", cfg.automation_key_ip_rate_limit_max);
        if let Ok(v) = std::env::var("RETENTION_CYCLE_INTERVAL_SECS")
            && let Ok(n) = v.parse::<u64>() { cfg.retention_cycle_interval = Duration::from_secs(n); }
        parse_env!("RETENTION_BATCH_SIZE", cfg.retention_batch_size);
        cfg.retention_batch_size = retention_batch_floor(cfg.retention_batch_size);
        parse_env!("RETENTION_BATCH_SLEEP_MS", cfg.retention_batch_sleep_ms);
        parse_env!("DB_SIZE_MIN_RETENTION_DAYS", cfg.db_size_min_retention_days);
        parse_env!("EDGE_SYNC_REFRESH_MS", cfg.edge_sync_refresh_ms);
        parse_env!("EDGE_EVENT_TTL_SECS", cfg.edge_event_ttl_secs);
        parse_env!("EDGE_HEARTBEAT_INTERVAL_SECS", cfg.edge_heartbeat_interval_secs);
        parse_env!("USAGE_JANITOR_INTERVAL_SECS", cfg.usage_janitor_interval_secs);
        parse_env!("ALERT_DISPATCH_INTERVAL_SECS", cfg.alert_dispatch_interval_secs);
        if let Ok(v) = std::env::var("SHUTDOWN_DRAIN_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>() { cfg.shutdown_drain_timeout = Duration::from_secs(n); }
        parse_env!("AUDIT_MAX_LIMIT", cfg.audit_max_limit);
        parse_env!("MODEL_AUTOSYNC_INTERVAL_HOURS", cfg.model_autosync_interval_hours);
        if let Ok(v) = std::env::var("AGENT_HTTP_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>() { cfg.agent_http_timeout = Duration::from_secs(n); }
        parse_env!("AGENT_SESSION_CONCURRENCY", cfg.agent_session_concurrency);
        parse_env!("AGENT_HTTP_MAX_RETRIES", cfg.agent_http_max_retries);
        parse_env!("AGENT_SESSION_BATCH_LIMIT", cfg.agent_session_batch_limit);
        parse_env!("AGENT_SUGGESTIONS_PER_CYCLE_CAP", cfg.agent_suggestions_per_cycle_cap);
        parse_env!("AGENT_SUGGESTION_MIN_SEEN", cfg.agent_suggestion_min_seen);
        parse_env!("MAX_SCRIPT_SIZE", cfg.max_script_size);
        if let Ok(v) = std::env::var("SEEDS_DIR") {
            cfg.seeds_dir = v;
        }
        parse_env!("MCP_OAUTH_PENDING_TTL_SECS", cfg.mcp_oauth_pending_ttl_secs);
        parse_env!("MCP_OAUTH_DCR_PER_TENANT_CAP", cfg.mcp_oauth_dcr_per_tenant_cap);
        parse_env!("MCP_SSE_RETENTION_SECS", cfg.mcp_sse_retention_secs);
        if let Ok(v) = std::env::var("AGENT_PROXY_URL") {
            cfg.agent_proxy_url = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_CA_FILE") {
            cfg.gateway_ca_file = v;
        }
        if let Ok(v) = std::env::var("STOWAGE_HOST_SOCKET") {
            cfg.stowage_host_socket = v;
        }
        parse_env!(
            "APPLIANCE_UPGRADE_CHECK_INTERVAL_SECS",
            cfg.appliance_upgrade_check_interval_secs
        );
        cfg
    }

    // -- Derived values --

    /// Invite rate limit max (same as login — same risk profile).
    pub fn rate_limit_invite_max(&self) -> u32 {
        self.rate_limit_login_max
    }

    /// Rate limiter cleanup threshold: derived as 2 * the login cap.
    pub fn rate_limit_cleanup_threshold(&self) -> usize {
        2 * self.rate_limit_login_max as usize
    }

    /// Sessions max page size: derived as audit_max_limit / 5 (heavier joins).
    pub fn sessions_max_limit(&self) -> i64 {
        self.audit_max_limit / 5
    }

    /// Message/turn batch size for retention: derived as retention_batch_size / 2.
    pub fn retention_batch_messages(&self) -> i64 {
        self.retention_batch_size / 2
    }

    /// How recently a gateway must have reported its state to count as present
    /// for what that state feeds: five state intervals. A live replica reports
    /// its load and endpoint stands every interval, so anything older is from
    /// a gateway that is gone. The replica-endpoint reads (server health, live
    /// load, connected replicas) read it, and a stand unchanged is rewritten
    /// every fifth of it.
    /// (Config-sync liveness — the edge-node list and convergence — is the
    /// shorter `INSTANCE_LIVE_SECS` on the last sync.)
    pub fn edge_connected_window(&self) -> chrono::Duration {
        chrono::Duration::seconds(
            i64::try_from(self.edge_heartbeat_interval_secs.max(1).saturating_mul(5)).unwrap_or(i64::MAX / 1000),
        )
    }

    /// Current effective value of every setting, keyed by env-var token.
    /// admin-api settings are display-only — there is no central-override layer.
    pub fn effective_values(&self) -> HashMap<String, String> {
        HashMap::from([
            ("PORT".to_string(), self.port.to_string()),
            ("METRICS_PORT".to_string(), self.metrics_port.to_string()),
            ("DB_MAX_CONNECTIONS".to_string(), self.db_max_connections.to_string()),
            (
                "DB_ACQUIRE_TIMEOUT_SECS".to_string(),
                self.db_acquire_timeout.as_secs().to_string(),
            ),
            ("DB_MANAGE_APP_ROLE".to_string(), self.db_manage_app_role.to_string()),
            ("DB_APP_TRANSACTION_TIMEOUT".to_string(), self.db_app_transaction_timeout.clone()),
            ("JWT_EXPIRY_HOURS".to_string(), self.jwt_expiry_hours.to_string()),
            (
                "OIDC_CLIENT_TIMEOUT_SECS".to_string(),
                self.oidc_client_timeout.as_secs().to_string(),
            ),
            ("OIDC_SKIP_TLS_VERIFY".to_string(), self.oidc_skip_tls_verify.to_string()),
            ("AUTH_MODE".to_string(), self.auth_mode.clone()),
            (
                "HEADER_AUTH_TENANT_SLUG".to_string(),
                self.header_auth_tenant_slug.clone(),
            ),
            (
                "HEADER_AUTH_TRUSTED_PROXY".to_string(),
                self.header_auth_trusted_proxy.clone(),
            ),
            (
                "HEADER_AUTH_TRUST_TENANT_HEADER".to_string(),
                self.header_auth_trust_tenant_header.to_string(),
            ),
            (
                "ALLOW_OIDC_CLAIM_EXCHANGE".to_string(),
                self.allow_oidc_claim_exchange.to_string(),
            ),
            ("API_DOCS_PUBLIC".to_string(), self.api_docs_public.to_string()),
            ("RATE_LIMIT_WINDOW_SECS".to_string(), self.rate_limit_window_secs.to_string()),
            ("RATE_LIMIT_LOGIN_MAX".to_string(), self.rate_limit_login_max.to_string()),
            (
                "RATE_LIMIT_INSTANCE_COUNT".to_string(),
                self.rate_limit_instance_count.to_string(),
            ),
            (
                "PRE_AUTH_IP_RATE_LIMIT_MAX".to_string(),
                self.pre_auth_ip_rate_limit_max.to_string(),
            ),
            (
                "AUTOMATION_KEY_RATE_LIMIT_MAX".to_string(),
                self.automation_key_rate_limit_max.to_string(),
            ),
            (
                "AUTOMATION_KEY_IP_RATE_LIMIT_MAX".to_string(),
                self.automation_key_ip_rate_limit_max.to_string(),
            ),
            (
                "RETENTION_CYCLE_INTERVAL_SECS".to_string(),
                self.retention_cycle_interval.as_secs().to_string(),
            ),
            ("RETENTION_BATCH_SIZE".to_string(), self.retention_batch_size.to_string()),
            ("RETENTION_BATCH_SLEEP_MS".to_string(), self.retention_batch_sleep_ms.to_string()),
            (
                "DB_SIZE_MIN_RETENTION_DAYS".to_string(),
                self.db_size_min_retention_days.to_string(),
            ),
            ("EDGE_SYNC_REFRESH_MS".to_string(), self.edge_sync_refresh_ms.to_string()),
            ("EDGE_EVENT_TTL_SECS".to_string(), self.edge_event_ttl_secs.to_string()),
            (
                "EDGE_HEARTBEAT_INTERVAL_SECS".to_string(),
                self.edge_heartbeat_interval_secs.to_string(),
            ),
            (
                "USAGE_JANITOR_INTERVAL_SECS".to_string(),
                self.usage_janitor_interval_secs.to_string(),
            ),
            (
                "ALERT_DISPATCH_INTERVAL_SECS".to_string(),
                self.alert_dispatch_interval_secs.to_string(),
            ),
            (
                "SHUTDOWN_DRAIN_TIMEOUT_SECS".to_string(),
                self.shutdown_drain_timeout.as_secs().to_string(),
            ),
            ("AUDIT_MAX_LIMIT".to_string(), self.audit_max_limit.to_string()),
            (
                "MODEL_AUTOSYNC_INTERVAL_HOURS".to_string(),
                self.model_autosync_interval_hours.to_string(),
            ),
            (
                "AGENT_HTTP_TIMEOUT_SECS".to_string(),
                self.agent_http_timeout.as_secs().to_string(),
            ),
            (
                "AGENT_SESSION_CONCURRENCY".to_string(),
                self.agent_session_concurrency.to_string(),
            ),
            (
                "AGENT_HTTP_MAX_RETRIES".to_string(),
                self.agent_http_max_retries.to_string(),
            ),
            (
                "AGENT_SESSION_BATCH_LIMIT".to_string(),
                self.agent_session_batch_limit.to_string(),
            ),
            (
                "AGENT_SUGGESTIONS_PER_CYCLE_CAP".to_string(),
                self.agent_suggestions_per_cycle_cap.to_string(),
            ),
            (
                "AGENT_SUGGESTION_MIN_SEEN".to_string(),
                self.agent_suggestion_min_seen.to_string(),
            ),
            ("MAX_SCRIPT_SIZE".to_string(), self.max_script_size.to_string()),
            ("SEEDS_DIR".to_string(), self.seeds_dir.clone()),
            (
                "MCP_OAUTH_PENDING_TTL_SECS".to_string(),
                self.mcp_oauth_pending_ttl_secs.to_string(),
            ),
            (
                "MCP_OAUTH_DCR_PER_TENANT_CAP".to_string(),
                self.mcp_oauth_dcr_per_tenant_cap.to_string(),
            ),
            ("MCP_SSE_RETENTION_SECS".to_string(), self.mcp_sse_retention_secs.to_string()),
            ("AGENT_PROXY_URL".to_string(), self.agent_proxy_url.clone()),
            ("GATEWAY_CA_FILE".to_string(), self.gateway_ca_file.clone()),
            ("STOWAGE_HOST_SOCKET".to_string(), self.stowage_host_socket.clone()),
            (
                "APPLIANCE_UPGRADE_CHECK_INTERVAL_SECS".to_string(),
                self.appliance_upgrade_check_interval_secs.to_string(),
            ),
        ])
    }

    /// Log any settings that differ from defaults.
    pub fn log_non_defaults(&self) {
        let d = Self::default();
        macro_rules! check {
            ($field:ident, $env:expr) => {
                if self.$field != d.$field {
                    tracing::info!("settings override: {}={:?} (default: {:?})", $env, self.$field, d.$field);
                }
            };
        }
        check!(port, "PORT");
        check!(metrics_port, "METRICS_PORT");
        check!(db_max_connections, "DB_MAX_CONNECTIONS");
        check!(db_acquire_timeout, "DB_ACQUIRE_TIMEOUT_SECS");
        check!(db_manage_app_role, "DB_MANAGE_APP_ROLE");
        check!(db_app_transaction_timeout, "DB_APP_TRANSACTION_TIMEOUT");
        check!(jwt_expiry_hours, "JWT_EXPIRY_HOURS");
        check!(oidc_client_timeout, "OIDC_CLIENT_TIMEOUT_SECS");
        check!(oidc_skip_tls_verify, "OIDC_SKIP_TLS_VERIFY");
        check!(auth_mode, "AUTH_MODE");
        check!(header_auth_tenant_slug, "HEADER_AUTH_TENANT_SLUG");
        check!(header_auth_trusted_proxy, "HEADER_AUTH_TRUSTED_PROXY");
        check!(header_auth_trust_tenant_header, "HEADER_AUTH_TRUST_TENANT_HEADER");
        check!(allow_oidc_claim_exchange, "ALLOW_OIDC_CLAIM_EXCHANGE");
        check!(api_docs_public, "API_DOCS_PUBLIC");
        check!(rate_limit_window_secs, "RATE_LIMIT_WINDOW_SECS");
        check!(rate_limit_login_max, "RATE_LIMIT_LOGIN_MAX");
        check!(rate_limit_instance_count, "RATE_LIMIT_INSTANCE_COUNT");
        check!(pre_auth_ip_rate_limit_max, "PRE_AUTH_IP_RATE_LIMIT_MAX");
        check!(automation_key_rate_limit_max, "AUTOMATION_KEY_RATE_LIMIT_MAX");
        check!(automation_key_ip_rate_limit_max, "AUTOMATION_KEY_IP_RATE_LIMIT_MAX");
        check!(retention_cycle_interval, "RETENTION_CYCLE_INTERVAL_SECS");
        check!(retention_batch_size, "RETENTION_BATCH_SIZE");
        check!(retention_batch_sleep_ms, "RETENTION_BATCH_SLEEP_MS");
        check!(db_size_min_retention_days, "DB_SIZE_MIN_RETENTION_DAYS");
        check!(edge_sync_refresh_ms, "EDGE_SYNC_REFRESH_MS");
        check!(edge_event_ttl_secs, "EDGE_EVENT_TTL_SECS");
        check!(edge_heartbeat_interval_secs, "EDGE_HEARTBEAT_INTERVAL_SECS");
        check!(usage_janitor_interval_secs, "USAGE_JANITOR_INTERVAL_SECS");
        check!(alert_dispatch_interval_secs, "ALERT_DISPATCH_INTERVAL_SECS");
        check!(shutdown_drain_timeout, "SHUTDOWN_DRAIN_TIMEOUT_SECS");
        check!(audit_max_limit, "AUDIT_MAX_LIMIT");
        check!(model_autosync_interval_hours, "MODEL_AUTOSYNC_INTERVAL_HOURS");
        check!(agent_http_timeout, "AGENT_HTTP_TIMEOUT_SECS");
        check!(agent_session_concurrency, "AGENT_SESSION_CONCURRENCY");
        check!(agent_http_max_retries, "AGENT_HTTP_MAX_RETRIES");
        check!(agent_session_batch_limit, "AGENT_SESSION_BATCH_LIMIT");
        check!(agent_suggestions_per_cycle_cap, "AGENT_SUGGESTIONS_PER_CYCLE_CAP");
        check!(agent_suggestion_min_seen, "AGENT_SUGGESTION_MIN_SEEN");
        check!(max_script_size, "MAX_SCRIPT_SIZE");
        check!(seeds_dir, "SEEDS_DIR");
        check!(mcp_oauth_pending_ttl_secs, "MCP_OAUTH_PENDING_TTL_SECS");
        check!(mcp_oauth_dcr_per_tenant_cap, "MCP_OAUTH_DCR_PER_TENANT_CAP");
        check!(mcp_sse_retention_secs, "MCP_SSE_RETENTION_SECS");
        check!(agent_proxy_url, "AGENT_PROXY_URL");
        check!(gateway_ca_file, "GATEWAY_CA_FILE");
        check!(stowage_host_socket, "STOWAGE_HOST_SOCKET");
        check!(appliance_upgrade_check_interval_secs, "APPLIANCE_UPGRADE_CHECK_INTERVAL_SECS");
    }
}

/// Access admin settings. Auto-initializes from env vars on first call.
pub fn admin_settings() -> &'static AdminSettings {
    &SETTINGS
}

/// The smallest `RETENTION_BATCH_SIZE` honoured. Every retention batch loop
/// ends when a batch comes back short (`deleted < batch`), so a batch of 0
/// would loop forever and a negative one fails every sweep; the message and
/// tool-definition purges use half of it, so it must stay ≥ 2 for those to be
/// ≥ 1.
const RETENTION_BATCH_SIZE_MIN: i64 = 2;

fn retention_batch_floor(configured: i64) -> i64 {
    configured.max(RETENTION_BATCH_SIZE_MIN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use streamscope_core::settings_catalog::{SETTINGS_CATALOG, SettingGroup};

    #[test]
    fn a_retention_batch_too_small_to_make_progress_is_raised_to_the_floor() {
        for (configured, honoured) in [(-5, 2), (0, 2), (1, 2), (2, 2), (3, 3), (10_000, 10_000)] {
            assert_eq!(retention_batch_floor(configured), honoured, "{configured}");
        }
    }

    #[test]
    fn catalog_matches_admin_settings() {
        let effective = AdminSettings::default().effective_values();
        let catalog: Vec<_> = SETTINGS_CATALOG
            .iter()
            .filter(|m| m.group == SettingGroup::Admin)
            .collect();

        let catalog_tokens: HashSet<&str> = catalog.iter().map(|m| m.token).collect();
        let effective_tokens: HashSet<&str> = effective.keys().map(String::as_str).collect();
        assert_eq!(
            catalog_tokens, effective_tokens,
            "admin catalog tokens must match AdminSettings::effective_values"
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
