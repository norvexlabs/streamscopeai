//! Process-level settings for streamscope-core.
//!
//! Centralized runtime configuration. Each field resolves, in precedence order,
//! to: a central override pushed from admin-api (persisted in the
//! `runtime_overrides.json` file), then an environment variable, then the
//! compiled-in default. Uses `LazyLock` — auto-initializes on first access.
//!
//! Access via [`core_settings()`]. Touch early in `main()` to trigger init +
//! startup logging. The [`crate::settings_catalog`] is the single source of
//! truth for every token, default, and description.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

static SETTINGS: LazyLock<CoreSettings> = LazyLock::new(CoreSettings::load);

/// Path of the persisted runtime-override file an edge writes when it receives
/// config from admin-api.
pub fn runtime_overrides_path(data_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(data_dir).join("runtime_overrides.json")
}

/// Read the persisted runtime-override file, keeping only known, overridable
/// tokens. Returns empty on a missing or unparseable file — central overrides
/// are best-effort, the env/default layers always remain.
pub fn read_runtime_overrides(data_dir: &str) -> HashMap<String, String> {
    let path = runtime_overrides_path(data_dir);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let parsed: HashMap<String, String> = match serde_json::from_str(&raw) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                "ignoring unparseable runtime override file {}: {e}",
                path.display()
            );
            return HashMap::new();
        }
    };
    parsed
        .into_iter()
        .filter(|(token, _)| crate::settings_catalog::is_overridable(token))
        .collect()
}

/// Resolve a setting token: central override wins, then environment variable.
pub fn resolve_setting(overrides: &HashMap<String, String>, token: &str) -> Option<String> {
    overrides
        .get(token)
        .cloned()
        .or_else(|| std::env::var(token).ok())
}

/// Core settings shared between proxy and admin-api.
pub struct CoreSettings {
    // -- Runtime --
    /// Tokio worker-thread override; `0` = auto (cgroup-quota- and host-aware,
    /// see [`crate::runtime`]). Env: `WORKER_THREADS`.
    pub worker_threads: usize,
    /// Cores held back from the data plane on a shared host (no cgroup quota) for
    /// the control plane + postgres; `0` = auto. Env: `CONTROL_PLANE_CPU_RESERVE`.
    pub control_plane_cpu_reserve: usize,

    // -- Request limits --
    /// Max HTTP request body size (bytes). Env: `MAX_BODY_SIZE_BYTES`.
    pub max_body_size: usize,
    /// Max upstream LLM *response* body buffered into memory (bytes) — a
    /// defense-in-depth cap so a hostile/buggy upstream can't OOM the shared
    /// edge. Env: `MAX_UPSTREAM_BODY_SIZE_BYTES`.
    pub max_upstream_body_size: usize,
    /// Time an inbound request body has to arrive in full, from the first read
    /// of it — on the gateway and on admin-api alike. Env:
    /// `REQUEST_BODY_DEADLINE_SECS`.
    pub request_body_deadline: Duration,
    /// The same deadline on the media and pass-through routes, whose uploads
    /// are larger. Env: `MEDIA_REQUEST_BODY_DEADLINE_SECS`.
    pub media_request_body_deadline: Duration,

    // -- Upstream client --
    /// Max idle connections per upstream host. Env: `UPSTREAM_POOL_MAX_IDLE`.
    pub upstream_pool_max_idle: usize,
    /// Idle connection timeout. Env: `UPSTREAM_POOL_IDLE_TIMEOUT_SECS`.
    pub upstream_pool_idle_timeout: Duration,
    /// TCP connect timeout to upstream. Env: `UPSTREAM_CONNECT_TIMEOUT_SECS`.
    pub upstream_connect_timeout: Duration,
    /// Total request timeout including response body. Env: `UPSTREAM_REQUEST_TIMEOUT_SECS`.
    pub upstream_request_timeout: Duration,
    /// Exponential retry base delay. Env: `UPSTREAM_RETRY_BACKOFF_MS`.
    pub upstream_retry_backoff_ms: u64,
    /// Reachability-probe timeout for upstream liveness + model-discovery calls
    /// (admin-api provider health / model sync). Env: `UPSTREAM_PROBE_TIMEOUT_SECS`.
    pub upstream_probe_timeout: Duration,
    /// Extra PEM CA bundle to trust for all outbound HTTPS, on top of the system
    /// roots — applied to the proxy upstream client. `None` when empty. Env /
    /// override: `CUSTOM_CA_BUNDLE_PEM`. Applied at process start (the upstream
    /// client is built once), so a change takes effect on the edge's next restart.
    pub custom_ca_bundle: Option<String>,

    // -- Audit pipeline --
    /// MPSC channel capacity — backpressure threshold. Env: `AUDIT_CHANNEL_CAPACITY`.
    pub audit_channel_capacity: usize,
    /// Max records per batch drain. Env: `AUDIT_BATCH_SIZE`.
    pub audit_batch_size: usize,
    /// Batch collection deadline (ms). Env: `AUDIT_BATCH_DEADLINE_MS`.
    pub audit_batch_deadline_ms: u64,
    /// The largest media blob, in MiB, a gateway captures and admin-api
    /// accepts: a tenant's own `media_blob_max_size_mb` is held to it. Both
    /// services read it, so they agree. Env: `EDGE_BLOB_MAX_MB`.
    pub edge_blob_max_mb: u64,

    // -- Egress --
    /// Total HTTP timeout for the built-in web-fetch tool (arbitrary end-user /
    /// agent supplied URLs). Env: `WEB_FETCH_TIMEOUT_SECS`.
    pub web_fetch_timeout: Duration,

    // -- Client-IP attribution --
    /// Number of trusted reverse proxies between a client and this process, used
    /// to read `X-Forwarded-For` (see
    /// [`crate::middleware::ip_rate_limit::extract_client_ip`]). Env:
    /// `TRUSTED_PROXY_HOPS`. Default: 1 — every shipped deploy shape fronts both
    /// services with one proxy (the appliance's Caddy, the chart's ingress).
    ///
    /// Read by admin-api (pre-auth IP limiter, audit `actor_ip`) **and** the
    /// proxy (public-metadata limiter). It describes the deployment's topology,
    /// not one process's policy, so it is deliberately ONE setting rather than a
    /// per-process pair an operator could set on one side and forget on the
    /// other — a mismatch reads as a spoofable limiter key on whichever side is
    /// wrong.
    pub trusted_proxy_hops: u32,

    /// The central-override subset actually applied this run (token → value),
    /// for the edge's runtime report. Never an env var or default.
    pub loaded_overrides: HashMap<String, String>,
}

impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            control_plane_cpu_reserve: 0,
            max_body_size: 10 * 1024 * 1024,
            max_upstream_body_size: 64 * 1024 * 1024,
            request_body_deadline: Duration::from_secs(120),
            media_request_body_deadline: Duration::from_secs(600),
            upstream_pool_max_idle: 256,
            upstream_pool_idle_timeout: Duration::from_secs(90),
            upstream_connect_timeout: Duration::from_secs(10),
            upstream_request_timeout: Duration::from_secs(300),
            upstream_retry_backoff_ms: 500,
            upstream_probe_timeout: Duration::from_secs(10),
            custom_ca_bundle: None,
            audit_channel_capacity: 10_000,
            audit_batch_size: 500,
            audit_batch_deadline_ms: 100,
            edge_blob_max_mb: 32,
            web_fetch_timeout: Duration::from_secs(30),
            trusted_proxy_hops: 1,
            loaded_overrides: HashMap::new(),
        }
    }
}

impl CoreSettings {
    /// [`Self::edge_blob_max_mb`] in bytes.
    pub fn edge_blob_max_bytes(&self) -> usize {
        usize::try_from(self.edge_blob_max_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX)
    }

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
        parse_setting!("WORKER_THREADS", cfg.worker_threads);
        parse_setting!("CONTROL_PLANE_CPU_RESERVE", cfg.control_plane_cpu_reserve);
        parse_setting!("MAX_BODY_SIZE_BYTES", cfg.max_body_size);
        parse_setting!("MAX_UPSTREAM_BODY_SIZE_BYTES", cfg.max_upstream_body_size);
        parse_setting!("REQUEST_BODY_DEADLINE_SECS", cfg.request_body_deadline, secs);
        parse_setting!("MEDIA_REQUEST_BODY_DEADLINE_SECS", cfg.media_request_body_deadline, secs);
        parse_setting!("UPSTREAM_POOL_MAX_IDLE", cfg.upstream_pool_max_idle);
        parse_setting!("UPSTREAM_POOL_IDLE_TIMEOUT_SECS", cfg.upstream_pool_idle_timeout, secs);
        parse_setting!("UPSTREAM_CONNECT_TIMEOUT_SECS", cfg.upstream_connect_timeout, secs);
        parse_setting!("UPSTREAM_REQUEST_TIMEOUT_SECS", cfg.upstream_request_timeout, secs);
        parse_setting!("UPSTREAM_RETRY_BACKOFF_MS", cfg.upstream_retry_backoff_ms);
        parse_setting!("UPSTREAM_PROBE_TIMEOUT_SECS", cfg.upstream_probe_timeout, secs);
        // String setting — the numeric `parse_setting!` macro doesn't fit. An
        // empty/whitespace value means "no custom CA" (same as unset).
        if let Some(raw) = resolve_setting(&overrides, "CUSTOM_CA_BUNDLE_PEM")
            && !raw.trim().is_empty()
        {
            cfg.custom_ca_bundle = Some(raw.clone());
            if overrides.contains_key("CUSTOM_CA_BUNDLE_PEM") {
                loaded.insert("CUSTOM_CA_BUNDLE_PEM".to_string(), raw);
            }
        }
        parse_setting!("AUDIT_CHANNEL_CAPACITY", cfg.audit_channel_capacity);
        parse_setting!("AUDIT_BATCH_SIZE", cfg.audit_batch_size);
        parse_setting!("AUDIT_BATCH_DEADLINE_MS", cfg.audit_batch_deadline_ms);
        parse_setting!("EDGE_BLOB_MAX_MB", cfg.edge_blob_max_mb);
        parse_setting!("WEB_FETCH_TIMEOUT_SECS", cfg.web_fetch_timeout, secs);
        parse_setting!("TRUSTED_PROXY_HOPS", cfg.trusted_proxy_hops);
        cfg.loaded_overrides = loaded;
        cfg
    }

    /// Current effective value of every setting, keyed by env-var token.
    pub fn effective_values(&self) -> HashMap<String, String> {
        HashMap::from([
            ("WORKER_THREADS".to_string(), self.worker_threads.to_string()),
            (
                "CONTROL_PLANE_CPU_RESERVE".to_string(),
                self.control_plane_cpu_reserve.to_string(),
            ),
            ("MAX_BODY_SIZE_BYTES".to_string(), self.max_body_size.to_string()),
            (
                "MAX_UPSTREAM_BODY_SIZE_BYTES".to_string(),
                self.max_upstream_body_size.to_string(),
            ),
            (
                "REQUEST_BODY_DEADLINE_SECS".to_string(),
                self.request_body_deadline.as_secs().to_string(),
            ),
            (
                "MEDIA_REQUEST_BODY_DEADLINE_SECS".to_string(),
                self.media_request_body_deadline.as_secs().to_string(),
            ),
            ("UPSTREAM_POOL_MAX_IDLE".to_string(), self.upstream_pool_max_idle.to_string()),
            (
                "UPSTREAM_POOL_IDLE_TIMEOUT_SECS".to_string(),
                self.upstream_pool_idle_timeout.as_secs().to_string(),
            ),
            (
                "UPSTREAM_CONNECT_TIMEOUT_SECS".to_string(),
                self.upstream_connect_timeout.as_secs().to_string(),
            ),
            (
                "UPSTREAM_REQUEST_TIMEOUT_SECS".to_string(),
                self.upstream_request_timeout.as_secs().to_string(),
            ),
            ("UPSTREAM_RETRY_BACKOFF_MS".to_string(), self.upstream_retry_backoff_ms.to_string()),
            (
                "UPSTREAM_PROBE_TIMEOUT_SECS".to_string(),
                self.upstream_probe_timeout.as_secs().to_string(),
            ),
            (
                "CUSTOM_CA_BUNDLE_PEM".to_string(),
                self.custom_ca_bundle.clone().unwrap_or_default(),
            ),
            ("AUDIT_CHANNEL_CAPACITY".to_string(), self.audit_channel_capacity.to_string()),
            ("AUDIT_BATCH_SIZE".to_string(), self.audit_batch_size.to_string()),
            ("AUDIT_BATCH_DEADLINE_MS".to_string(), self.audit_batch_deadline_ms.to_string()),
            ("EDGE_BLOB_MAX_MB".to_string(), self.edge_blob_max_mb.to_string()),
            (
                "WEB_FETCH_TIMEOUT_SECS".to_string(),
                self.web_fetch_timeout.as_secs().to_string(),
            ),
            ("TRUSTED_PROXY_HOPS".to_string(), self.trusted_proxy_hops.to_string()),
        ])
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

/// Access core settings. Auto-initializes on first call.
pub fn core_settings() -> &'static CoreSettings {
    &SETTINGS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings_catalog::{SETTINGS_CATALOG, SettingGroup};
    use std::collections::HashSet;

    #[test]
    fn catalog_matches_core_settings() {
        let effective = CoreSettings::default().effective_values();
        let catalog: Vec<_> = SETTINGS_CATALOG
            .iter()
            .filter(|m| m.group == SettingGroup::Core)
            .collect();

        let catalog_tokens: HashSet<&str> = catalog.iter().map(|m| m.token).collect();
        let effective_tokens: HashSet<&str> = effective.keys().map(String::as_str).collect();
        assert_eq!(
            catalog_tokens, effective_tokens,
            "core catalog tokens must match CoreSettings::effective_values"
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

    #[test]
    fn read_runtime_overrides_filters_to_overridable() {
        let dir = std::env::temp_dir().join(format!("ss-core-overrides-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let body = serde_json::json!({
            "AUDIT_BATCH_SIZE": "999",     // overridable core setting — kept
            "PORT": "1234",                 // non-overridable — dropped
            "NOT_A_REAL_TOKEN": "x"         // unknown — dropped
        });
        std::fs::write(runtime_overrides_path(dir.to_str().unwrap()), body.to_string()).unwrap();

        let overrides = read_runtime_overrides(dir.to_str().unwrap());
        assert_eq!(overrides.get("AUDIT_BATCH_SIZE").map(String::as_str), Some("999"));
        assert!(!overrides.contains_key("PORT"));
        assert!(!overrides.contains_key("NOT_A_REAL_TOKEN"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
