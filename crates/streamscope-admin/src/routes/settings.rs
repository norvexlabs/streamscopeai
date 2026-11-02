//! System settings — feature flags, retention, agent config, and DB statistics.
//!
//! Key-value settings stored in `system_settings` (tenant-scoped, PK is
//! `(key, tenant_id)`). Includes agent configuration, retention days, app
//! registry, tool risk rules, and custom feature flags. Sensitive keys like
//! `agent_api_key` are encrypted at rest and filtered from list responses.

use crate::db::Global;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ApiError, ApiErrorResponse};
use crate::AdminState;
use crate::db::tenant::{Scoped, TenantConn};

// The internal proxy↔admin config-sync channel uses an untyped HashMap in
// `ConfigResponse.settings` — that's a separate WS protocol.

// ---------------------------------------------------------------------------
// TenantSettings — typed wire shape for GET/PATCH /api/v1/admin/settings
// ---------------------------------------------------------------------------

/// Typed per-tenant settings surface. Every field is `Option<T>` with `#[serde(default)]`
/// so PATCH requests can carry partial updates and GET responses remain stable when new
/// fields land.
///
/// Wire shape for both `GET /api/v1/admin/settings` and `PATCH /api/v1/admin/settings`.
/// Partial updates are the norm — send only the fields you want to change.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct TenantSettings {
    // --- Core feature flags ---
    pub healing_enabled: Option<bool>,
    pub debug_mode: Option<bool>,
    pub audit_enabled: Option<bool>,
    pub content_logging_enabled: Option<bool>,
    pub sanitize_tool_names: Option<bool>,

    // --- Runtime tuning ---
    /// One of "error", "warn", "info", "debug".
    pub log_level: Option<String>,
    /// One of "open", "closed".
    pub rhai_fail_mode: Option<String>,
    pub stream_idle_timeout_secs: Option<u64>,
    pub retention_days: Option<i64>,

    // --- Agent configuration ---
    pub agent_enabled: Option<bool>,
    pub agent_interval_secs: Option<u64>,
    pub agent_session_cooldown_mins: Option<i64>,
    /// When true, the agent only runs analysis cycles whose current UTC
    /// hour falls inside `[agent_run_window_start_hour_utc,
    /// agent_run_window_end_hour_utc)`. Outside the window, cycles are
    /// skipped with a log line. Lets operators reserve agent load for
    /// off-hours on shared on-premise LLMs.
    pub agent_run_window_enabled: Option<bool>,
    /// Window start hour in UTC (0..=23 inclusive). When `start < end` the
    /// window is `[start, end)`; when `start > end` it wraps past midnight
    /// (`[start, 24) ∪ [0, end)`). `start == end` disables the window
    /// (treated as empty).
    pub agent_run_window_start_hour_utc: Option<i32>,
    /// Window end hour in UTC (0..=23 inclusive, exclusive bound). See
    /// `agent_run_window_start_hour_utc` for wrap-around semantics.
    pub agent_run_window_end_hour_utc: Option<i32>,

    // --- Default per-key budgets (RPM/TPM have no tenant default — unset = unlimited) ---
    pub default_daily_budget: Option<f64>,
    pub default_monthly_budget: Option<f64>,

    // --- Org-total ceiling (the tenant's OWN cap, not a workspace default) ---
    /// Daily ceiling across every workspace in the tenant, in the tenant's
    /// accounting currency. `0` = uncapped.
    /// Distinct from `default_daily_budget`, which is only the value a
    /// workspace inherits when it sets none: this one caps the organisation.
    pub tenant_daily_budget: Option<f64>,
    /// Monthly ceiling across every workspace in the tenant, in the tenant's
    /// accounting currency. `0` = uncapped.
    pub tenant_monthly_budget: Option<f64>,
    /// `"enforce"` (default) rejects a request once the org total is over cap;
    /// `"alert_only"` keeps accruing and still fires the crossing notification,
    /// without blocking.
    pub tenant_budget_mode: Option<String>,

    // --- Media blob storage ---
    pub media_blob_storage_enabled: Option<bool>,
    pub media_blob_max_size_mb: Option<u64>,

    // --- Access ---
    pub admin_group: Option<String>,

    // --- Public URLs (per-tenant override; SYSTEM-tenant row is the default) ---
    /// Public URL of the proxy gateway (scheme + host[:port], no trailing
    /// slash, no path). Used by Quickstart snippets, MCP OAuth audience,
    /// and MCP CORS allowlist. Empty/unset on a non-SYSTEM tenant means
    /// "inherit the SYSTEM default"; unset on SYSTEM means dependent
    /// surfaces fail closed for every tenant that doesn't override.
    pub proxy_public_url: Option<String>,
    /// Public URL of the admin/portal UI for this tenant. Used by login
    /// links, invite/email URLs, OIDC RP-initiated-logout post-redirect,
    /// MCP OAuth admin redirect, admin/portal CORS allow-list. Same layering
    /// rules as `proxy_public_url`.
    pub admin_public_url: Option<String>,
    /// Public URL of the admin-API for external scripting / CLI access.
    /// Caddy serves the admin-API at this FQDN; operators set this value
    /// so the UI can display the canonical script-callable URL (copy-out
    /// for `curl` / SDKs). Not in any CORS allowlist — scripts aren't
    /// browsers, and the UI calls the admin-API same-origin through the
    /// SvelteKit proxy at `admin_public_url`. Same layering rules as
    /// `proxy_public_url` (per-tenant override over SYSTEM default).
    pub api_public_url: Option<String>,

    // --- Structured sub-objects ---
    /// Tool risk classification rules — stored as `{ rules: [ToolRule...] }`.
    pub tool_rules: Option<ToolRulesConfig>,

    /// App registry — client detection patterns for incoming requests. The only
    /// apps-edit surface: a full-array replace written to the `apps` table.
    pub app_registry: Option<Vec<crate::routes::analytics::AppInfo>>,
}

/// Read-only effective values after layering tenant override over the SYSTEM
/// default. The keys mirror SYSTEM-defaulted entries on `TenantSettings`. A
/// `None` entry means *neither* layer is configured — the dependent surface
/// fails closed for this tenant. Generic carrier: any future
/// SYSTEM-defaulted setting lands here too.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct InheritedDefaults {
    pub proxy_public_url: Option<String>,
    pub admin_public_url: Option<String>,
    pub api_public_url: Option<String>,
}

impl InheritedDefaults {
    /// Derived read-only value: the exact redirect URI to register at an
    /// external IdP for per-user upstream MCP OAuth. Rides the resolved API
    /// origin (`api_public_url`, falling back to `admin_public_url` — the
    /// shared OAuth discovery-origin rule). `None` when neither origin is
    /// configured; the UI shows a configuration hint instead.
    pub(crate) fn mcp_oauth_redirect_uri(&self) -> Option<String> {
        crate::tenant_public_url::OauthDiscoveryOrigins::from_layered(
            self.admin_public_url.clone(),
            self.api_public_url.clone(),
        )
        .map(|o| super::portal_mcp_connections::oauth_callback_uri(&o.api))
    }
}

/// Wire shape for `GET /api/v1/admin/settings`. Bundles the writable per-tenant
/// `TenantSettings` with the read-only `inherited` block so the UI can show
/// "Currently inheriting `<X>`" chips without a follow-up call.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetSettingsResponse {
    #[serde(flatten)]
    pub settings: TenantSettings,
    pub inherited: InheritedDefaults,
    /// Read-only derived value — see [`InheritedDefaults::mcp_oauth_redirect_uri`].
    pub mcp_oauth_redirect_uri: Option<String>,
}

/// Container for the `tool_rules` setting — wraps the array of rules so
/// future per-tenant knobs (e.g. rule ordering, disabled flags) have a place.
#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ToolRulesConfig {
    pub rules: Vec<crate::routes::analytics::ToolRule>,
}

impl TenantSettings {
    /// Derive the defaulted settings from a `TenantConfig`. Used as the base in
    /// `get_settings` so empty DB rows still yield a complete response.
    pub fn from_tenant_config(cfg: &streamscope_core::config::TenantConfig) -> Self {
        Self {
            healing_enabled: Some(cfg.healing_enabled),
            debug_mode: Some(cfg.debug_mode),
            audit_enabled: Some(cfg.audit_enabled),
            content_logging_enabled: Some(cfg.content_logging_enabled),
            sanitize_tool_names: Some(cfg.sanitize_tool_names),
            log_level: Some(cfg.log_level.clone()),
            rhai_fail_mode: Some(cfg.rhai_fail_mode.clone()),
            stream_idle_timeout_secs: Some(cfg.stream_idle_timeout_secs),
            retention_days: Some(crate::retention::DEFAULT_RETENTION_DAYS),
            agent_enabled: Some(false),
            agent_interval_secs: Some(crate::agent::DEFAULT_AGENT_INTERVAL_SECS),
            agent_session_cooldown_mins: Some(crate::agent::DEFAULT_AGENT_SESSION_COOLDOWN_MINS),
            agent_run_window_enabled: Some(false),
            agent_run_window_start_hour_utc: Some(22),
            agent_run_window_end_hour_utc: Some(6),
            default_daily_budget: Some(0.0),
            default_monthly_budget: Some(0.0),
            tenant_daily_budget: Some(0.0),
            tenant_monthly_budget: Some(0.0),
            tenant_budget_mode: Some("enforce".to_string()),
            media_blob_storage_enabled: Some(cfg.media_blob_storage_enabled),
            media_blob_max_size_mb: Some(cfg.media_blob_max_size_mb),
            admin_group: Some(String::new()),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            // Defaults leave rules empty — the tenant seeder populates them
            // from `seeds/tool-policy/rules.json` on first startup.
            tool_rules: Some(ToolRulesConfig::default()),
            app_registry: None,
        }
    }
}

/// The two collection settings: edited wholesale, with no override row to delete.
const COLLECTION_SETTINGS: [&str; 2] = ["app_registry", "tool_rules"];

/// The settings keys an explicit `null` clears: every scalar field of
/// [`TenantSettings`], read from its serialized form (every field serializes,
/// `null` included), minus the two collections that have no override row.
static CLEARABLE_SETTING_KEYS: std::sync::LazyLock<std::collections::HashSet<String>> =
    std::sync::LazyLock::new(|| match serde_json::to_value(TenantSettings::default()) {
        Ok(serde_json::Value::Object(m)) => m
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| !COLLECTION_SETTINGS.contains(&k.as_str()))
            .collect(),
        _ => std::collections::HashSet::new(),
    });

#[cfg(test)]
mod tenant_settings_tests {
    use super::*;

    /// Every field the published schema names is clearable or one of the two
    /// collections. A field hidden from the serialized form (a
    /// `skip_serializing_if`) would otherwise make its `null` a silent no-op.
    #[test]
    fn every_scalar_setting_in_the_schema_can_be_cleared() {
        use utoipa::PartialSchema;
        let schema = serde_json::to_value(TenantSettings::schema()).expect("schema serialises");
        let mut documented: Vec<String> = schema["properties"]
            .as_object()
            .expect("TenantSettings has properties")
            .keys()
            .filter(|k| !COLLECTION_SETTINGS.contains(&k.as_str()))
            .cloned()
            .collect();
        let mut clearable: Vec<String> = CLEARABLE_SETTING_KEYS.iter().cloned().collect();
        documented.sort();
        clearable.sort();
        assert!(clearable.len() > 20, "only {} clearable keys", clearable.len());
        assert_eq!(documented, clearable);
    }

    /// Ensure TenantSettings round-trips: default TenantConfig → TenantSettings →
    /// JSON → TenantSettings. Fails loudly if a field is added to TenantConfig but
    /// not surfaced, or vice versa.
    #[test]
    fn round_trip_from_default_tenant_config() {
        let cfg = streamscope_core::config::TenantConfig::default();
        let settings = TenantSettings::from_tenant_config(&cfg);
        let json = serde_json::to_value(&settings).expect("serialize");
        let back: TenantSettings = serde_json::from_value(json.clone()).expect("deserialize");
        // Re-serializing must yield identical JSON — no silent field drops.
        let json_again = serde_json::to_value(&back).expect("reserialize");
        assert_eq!(json, json_again, "round-trip drift detected in TenantSettings");
    }

    /// An empty JSON object must deserialize successfully thanks to `#[serde(default)]`
    /// — critical so PATCH requests can carry partial updates.
    #[test]
    fn partial_update_deserializes() {
        let empty = serde_json::json!({});
        let partial: TenantSettings = serde_json::from_value(empty).expect("empty payload ok");
        assert!(partial.healing_enabled.is_none());
        let some = serde_json::json!({ "healing_enabled": true, "log_level": "debug" });
        let partial: TenantSettings = serde_json::from_value(some).expect("partial payload ok");
        assert_eq!(partial.healing_enabled, Some(true));
        assert_eq!(partial.log_level.as_deref(), Some("debug"));
        assert!(partial.debug_mode.is_none());
    }

    /// `api_public_url` round-trips through the typed shape alongside the
    /// other two public URLs. Regression guard for the field being silently
    /// dropped on serialize/deserialize.
    #[test]
    fn api_public_url_round_trips() {
        let payload = serde_json::json!({
            "proxy_public_url": "https://gw.example.com",
            "admin_public_url": "https://admin.example.com",
            "api_public_url": "https://api.example.com",
        });
        let parsed: TenantSettings = serde_json::from_value(payload).expect("deserialize");
        assert_eq!(parsed.proxy_public_url.as_deref(), Some("https://gw.example.com"));
        assert_eq!(parsed.admin_public_url.as_deref(), Some("https://admin.example.com"));
        assert_eq!(parsed.api_public_url.as_deref(), Some("https://api.example.com"));
        let back = serde_json::to_value(&parsed).expect("serialize");
        assert_eq!(back.get("api_public_url").and_then(|v| v.as_str()), Some("https://api.example.com"));
    }
}

#[derive(Serialize, ToSchema)]
pub struct TableStats {
    pub name: String,
    pub rows: i64,
    pub size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partitions: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct ContentDedupStats {
    pub unique_messages: i64,
    pub total_message_refs: i64,
    pub stored_bytes: i64,
    pub projected_bytes: i64,
    pub savings_pct: f64,
}

#[derive(Serialize, ToSchema)]
pub struct MediaDedupStats {
    pub total_blobs: i64,
    pub unique_hashes: i64,
    /// References to stored blobs from live audit rows.
    pub total_refs: i64,
    pub stored_bytes: i64,
    pub savings_pct: f64,
}

/// Tool-definition dedup stats. Mirrors `ContentDedupStats` shape.
/// `total_tool_set_refs` is the sum of hash references from both
/// `conversation_turns.tools_available_hash` and `tools_effective_hash`.
/// `stored_bytes` is the deduplicated side-table payload size;
/// `projected_bytes` is what the in-row JSONB shape would have cost.
#[derive(Serialize, ToSchema)]
pub struct ToolsDedupStats {
    pub unique_tool_sets: i64,
    pub total_tool_set_refs: i64,
    pub stored_bytes: i64,
    pub projected_bytes: i64,
    pub savings_pct: f64,
}

#[derive(Serialize, ToSchema)]
pub struct DbStatsResponse {
    pub tables: Vec<TableStats>,
    pub total_db_size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_dedup: Option<ContentDedupStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_dedup: Option<MediaDedupStats>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_dedup: Option<ToolsDedupStats>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings",
    tag = "Settings",
    responses(
        (status = 200, description = "Current tenant settings", body = GetSettingsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_settings(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
) -> Result<Json<GetSettingsResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let settings = load_merged_settings(db.conn(), tenant_id).await?;
    let inherited = load_inherited_defaults(&state.db, tenant_id).await?;
    let mcp_oauth_redirect_uri = inherited.mcp_oauth_redirect_uri();
    Ok(Json(GetSettingsResponse { settings, inherited, mcp_oauth_redirect_uri }))
}

/// Build the read-only `inherited` block on the settings GET. Each field is
/// the layered effective value (override ?? SYSTEM default) for the matching
/// `system_settings` key. `None` means *neither* layer is configured.
pub(crate) async fn load_inherited_defaults(
    pool: &crate::db::Db,
    tenant_id: uuid::Uuid,
) -> Result<InheritedDefaults, ApiError> {
    use crate::tenant_public_url::{try_resolve_public_url, PublicUrlKey};
    Ok(InheritedDefaults {
        proxy_public_url: try_resolve_public_url(pool, tenant_id, PublicUrlKey::Proxy).await?,
        admin_public_url: try_resolve_public_url(pool, tenant_id, PublicUrlKey::Admin).await?,
        api_public_url: try_resolve_public_url(pool, tenant_id, PublicUrlKey::Api).await?,
    })
}

/// Read system_settings rows for the tenant, layer them over `TenantConfig`
/// defaults, and project into the typed `TenantSettings` wire shape. Shared
/// by `get_settings` and `update_settings` so the PATCH response reflects the
/// full merged state after upsert rather than just the partial payload.
///
/// Stale DB rows written under pre-rework free-form JSON shapes (e.g. an old
/// `tool_rules` structure) would otherwise crash the whole handler.
/// Each override is applied and validated individually; any row that fails
/// to project is logged and dropped, so a single bad field can't take the
/// settings page offline.
async fn load_merged_settings(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<TenantSettings, ApiError> {
    let rows = sqlx::query_as::<_, (String, serde_json::Value)>(
        // Admin-only keys (internal bookkeeping, secrets) never round-trip
        // through the public API.
        "SELECT key, value FROM system_settings \
          WHERE tenant_id = $1 AND NOT config_admin_only_setting(key) ORDER BY key",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("failed to load settings: {e}");
        ApiError::internal("internal error")
    })?;

    let defaults = streamscope_core::config::TenantConfig::default();
    let base_value = serde_json::to_value(TenantSettings::from_tenant_config(&defaults))
        .unwrap_or(serde_json::Value::Null);
    let mut base_map = match base_value {
        serde_json::Value::Object(m) => m,
        _ => {
            tracing::error!("TenantSettings defaults did not serialize to a JSON object");
            return Err(ApiError::internal("internal error"));
        }
    };

    for (key, value) in rows {
        let mut candidate = base_map.clone();
        candidate.insert(key.clone(), value);
        match serde_json::from_value::<TenantSettings>(serde_json::Value::Object(candidate.clone())) {
            Ok(_) => {
                base_map = candidate;
            }
            Err(e) => {
                tracing::warn!("dropping stale/invalid setting '{key}' for tenant {tenant_id}: {e}");
            }
        }
    }

    let mut settings: TenantSettings =
        serde_json::from_value(serde_json::Value::Object(base_map)).map_err(|e| {
            tracing::error!("failed to project TenantSettings from defaults: {e}");
            ApiError::internal("internal error")
        })?;
    // The app registry lives in the `apps` table now, not a `system_settings`
    // row; surface the live (non-suppressed) set so the GET reflects current
    // state (the PATCH round-trips through it).
    settings.app_registry = Some(crate::routes::analytics::load_apps_snapshot(conn, tenant_id).await);
    Ok(settings)
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings",
    tag = "Settings",
    request_body = TenantSettings,
    responses(
        (status = 200, description = "Settings updated", body = GetSettingsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_settings(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(raw): Json<serde_json::Value>,
) -> Result<Json<GetSettingsResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Effective settings before the write, for the audit before/after diff
    // (secret-shaped fields are scrubbed centrally by the audit middleware).
    let before_settings = load_merged_settings(db.conn(), tenant_id).await.ok();

    // Validate the body against the typed shape — keep the raw JSON map
    // around afterwards so we can distinguish "key absent" (no-op) from
    // "key explicitly null" (DELETE the override row, fall back to the
    // SYSTEM default). The serde-derived `Option<T>` projection collapses
    // both into `None`.
    let payload: TenantSettings = serde_json::from_value(raw.clone())
        .map_err(|e| ApiError::bad_request(format!("invalid settings body: {e}")))?;
    let raw_map: &serde_json::Map<String, serde_json::Value> = match &raw {
        serde_json::Value::Object(m) => m,
        _ => return Err(ApiError::bad_request("settings body must be a JSON object")),
    };

    // tool_rules has a dedicated CRUD surface at /api/v1/admin/tool-rules.
    // Accepting it here would create two write paths over the same storage — reject
    // with a code the UI can branch on.
    if payload.tool_rules.is_some() {
        return Err(ApiError::bad_request(
            "tool_rules is managed at /api/v1/admin/tool-rules — per-rule CRUD only",
        )
        .code(super::ApiErrorCode::ToolRiskConfigReadOnly));
    }

    // Constrained-enum settings: reject unknown values up-front so a typo
    // never makes it into `system_settings`. The pipeline still falls back
    // safely (unknown fail-mode → Open, unknown log-level → ignored), but
    // surfacing the error to the UI is strictly better than silent fallback.
    if let Some(v) = raw_map.get("rhai_fail_mode")
        && !v.is_null()
    {
        let s = v.as_str().ok_or_else(|| {
            ApiError::bad_request("rhai_fail_mode must be a string")
                .code(super::ApiErrorCode::SettingInvalid)
        })?;
        if !matches!(s, "open" | "closed") {
            return Err(ApiError::bad_request(format!(
                "rhai_fail_mode must be 'open' or 'closed' (got '{s}')"
            ))
            .code(super::ApiErrorCode::SettingInvalid));
        }
    }
    if let Some(v) = raw_map.get("log_level")
        && !v.is_null()
    {
        let s = v.as_str().ok_or_else(|| {
            ApiError::bad_request("log_level must be a string")
                .code(super::ApiErrorCode::SettingInvalid)
        })?;
        if !matches!(s, "error" | "warn" | "info" | "debug") {
            return Err(ApiError::bad_request(format!(
                "log_level must be one of 'error', 'warn', 'info', 'debug' (got '{s}')"
            ))
            .code(super::ApiErrorCode::SettingInvalid));
        }
    }

    if let Some(v) = raw_map.get("tenant_budget_mode")
        && !v.is_null()
    {
        let s = v.as_str().ok_or_else(|| {
            ApiError::bad_request("tenant_budget_mode must be a string")
                .code(super::ApiErrorCode::SettingInvalid)
        })?;
        if !matches!(s, "enforce" | "alert_only") {
            return Err(ApiError::bad_request(format!(
                "tenant_budget_mode must be 'enforce' or 'alert_only' (got '{s}')"
            ))
            .code(super::ApiErrorCode::SettingInvalid));
        }
    }
    // A negative ceiling would read as "uncapped" (enforcement gates on
    // `> 0`), which is not what an operator typing one means.
    for key in ["tenant_daily_budget", "tenant_monthly_budget"] {
        if let Some(v) = raw_map.get(key)
            && !v.is_null()
            && v.as_f64().is_none_or(|n| n < 0.0)
        {
            return Err(ApiError::bad_request(format!(
                "{key} must be a non-negative number of USD (0 = uncapped)"
            ))
            .code(super::ApiErrorCode::SettingInvalid));
        }
    }
    // A window of zero or fewer days would purge everything (the retention read
    // ignores one, so storing it would show a value that does not apply), and
    // one past `RETENTION_DAYS_MAX` overflows the purge's cutoff date.
    if let Some(days) = payload.retention_days
        && !(1..=crate::retention::RETENTION_DAYS_MAX).contains(&days)
    {
        return Err(ApiError::bad_request(format!(
            "retention_days must be between 1 and {} (got {days})",
            crate::retention::RETENTION_DAYS_MAX
        ))
        .code(super::ApiErrorCode::SettingInvalid));
    }

    // SYSTEM-tenant write guard: SYSTEM never proxies traffic, so most
    // per-tenant settings are no-ops there. Reject any key outside the
    // SYSTEM-meaningful allowlist (platform-default URLs + log_level).
    // Runs after enum validation so a SYSTEM admin sending a malformed
    // enum still gets the specific `SettingInvalid` code.
    if tenant_id == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
        const SYSTEM_ALLOWED: &[&str] = &[
            "proxy_public_url",
            "admin_public_url",
            "api_public_url",
            "log_level",
        ];
        for key in raw_map.keys() {
            if !SYSTEM_ALLOWED.contains(&key.as_str()) {
                return Err(ApiError::bad_request(format!(
                    "setting '{key}' is not meaningful on the SYSTEM tenant — \
                     only platform-default keys are accepted here"
                ))
                .code(super::ApiErrorCode::SettingNotMeaningfulForSystem));
            }
        }
    }

    // Explicit `null` on a scalar key clears the tenant's override (deletes the
    // row), so the setting reads its built-in default again — the public URLs
    // inherit the SYSTEM tenant's. Only keys of the typed shape qualify, never
    // the two collections, which have no override row.
    let clears: Vec<&String> = raw_map
        .iter()
        .filter(|(k, v)| v.is_null() && CLEARABLE_SETTING_KEYS.contains(k.as_str()))
        .map(|(k, _)| k)
        .collect();

    // Public URL keys: a non-empty string upserts; empty string is rejected
    // (`null` clears, above). Validate any non-empty incoming URL before it
    // hits the DB.
    for label in ["proxy_public_url", "admin_public_url", "api_public_url"] {
        let Some(v) = raw_map.get(label) else { continue };
        if v.is_null() {
            continue;
        }
        let Some(s) = v.as_str() else {
            return Err(ApiError::bad_request(format!("{label} must be a string or null"))
                .code(super::ApiErrorCode::PublicUrlInvalid));
        };
        if s.is_empty() {
            return Err(ApiError::bad_request(format!(
                "{label}: empty string is not allowed; send null to clear the override"
            ))
            .code(super::ApiErrorCode::PublicUrlInvalid));
        }
        crate::tenant_public_url::validate_public_url(s).map_err(|mut e| {
            e.message = format!("{label}: {}", e.message);
            e
        })?;
    }

    // Project the partial struct to a flat key → value map. Skip None — that's
    // how PATCH-style partial updates thread through. (Clears are handled
    // separately via DELETE below.)
    let mut payload_map: serde_json::Map<String, serde_json::Value> = match serde_json::to_value(&payload) {
        Ok(serde_json::Value::Object(map)) => map.into_iter()
            .filter(|(_, v)| !v.is_null())
            .collect(),
        _ => serde_json::Map::new(),
    };

    // Apply the writes in one transaction. Most keys are replaced wholesale from
    // the typed payload (last-write-wins is correct PATCH semantics) into their
    // `system_settings` row. The `app_registry` payload is the one collection
    // still edited through this surface — a full-array replace written to the
    // per-row `apps` table (suppressed-aware), so it is pulled out of the generic
    // key loop. No blob lock is needed: per-row tables don't share a JSON row.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    // Route the app registry to the `apps` table, then drop it from the generic
    // key loop below so no stale `system_settings` blob row is written.
    if let Some(apps_value) = payload_map.remove("app_registry") {
        let apps: Vec<crate::routes::analytics::AppInfo> = serde_json::from_value(apps_value)
            .map_err(|e| ApiError::bad_request(format!("invalid app_registry: {e}")))?;
        crate::routes::analytics::replace_apps(&mut tx, tenant_id, &apps).await?;
    }

    // Clears: delete the override row, so the next read falls back to the
    // default.
    for key in &clears {
        sqlx::query(
            "DELETE FROM system_settings WHERE key = $1 AND tenant_id = $2",
        )
        .bind(key)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("failed to clear setting {key}: {e}");
            ApiError::internal("failed to update settings")
        })?;
    }

    // settings-blob-ok: every remaining key here is a SCALAR setting
    // (log_level, *_budget, *_public_url, feature flags, …) replaced wholesale
    // from the typed payload — last-write-wins PATCH semantics, never a
    // read-modify-write of a shared document, so a full replace cannot lose an
    // update. The collection settings that used to ride this loop (app_registry,
    // expert_prompt_snippets) are per-row tables now (app_registry is pulled out
    // above).
    for (key, value) in &payload_map {
        sqlx::query(
            "INSERT INTO system_settings (key, tenant_id, value, updated_at) VALUES ($1, $2, $3, now())
             ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(key)
        .bind(tenant_id)
        .bind(value)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("failed to update setting {key}: {e}");
            ApiError::internal("failed to update settings")
        })?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("commit settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    // Re-read the merged settings + inherited block so the caller doesn't
    // need a follow-up GET. Inherited values resolve through the layered public-URL reader; merged
    // settings use the RLS-scoped tenant connection.
    let settings = load_merged_settings(db.conn(), tenant_id).await?;
    let inherited = load_inherited_defaults(&state.db, tenant_id).await?;

    audit_sink.record(before_settings.as_ref(), Some(&settings));

    let mcp_oauth_redirect_uri = inherited.mcp_oauth_redirect_uri();
    Ok(Json(GetSettingsResponse { settings, inherited, mcp_oauth_redirect_uri }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/maintenance/purge-audit",
    tag = "Settings",
    responses(
        (status = 200, description = "Purge completed", body = PurgeResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_purge(
    mut db: TenantConn,
) -> Result<Json<PurgeResponse>, ApiError> {
    match crate::retention::run_purge_tenant(db.conn()).await {
        Ok(summary) => Ok(Json(PurgeResponse {
            status: "ok".into(),
            summary,
        })),
        Err(e) => {
            tracing::error!("manual purge failed: {e}");
            Err(ApiError::internal("purge failed"))
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct PurgeResponse {
    pub status: String,
    pub summary: crate::retention::PurgeSummary,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/db-stats",
    tag = "Settings",
    responses(
        (status = 200, description = "Database statistics", body = DbStatsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_db_stats(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
) -> Result<Json<DbStatsResponse>, ApiError> {
    let db_err = |e: sqlx::Error| {
        tracing::error!("db stats query failed: {e}");
        ApiError::internal("internal error")
    };

    let tables_of_interest = [
        "gateway_audit",
        "llm_audit",
        "mcp_audit",
        "a2a_audit",
        "web_audit",
        "conversation_turns",
        "conversation_messages",
        "turn_history_chunks",
        "system_prompts",
        "conversation_session_messages",
        "tool_definitions",
        "sessions",
        "audit_media_blobs",
    ];
    let partitioned_tables = [
        "gateway_audit",
        "llm_audit",
        "mcp_audit",
        "a2a_audit",
        "web_audit",
        "conversation_turns",
    ];

    let mut tables = Vec::new();

    for table in &tables_of_interest {
        // Approximate row count from pg_class (fast, no seq scan)
        let rows: i64 = sqlx::query_scalar::<_, f32>(
            "SELECT COALESCE(SUM(c2.reltuples), 0) \
             FROM pg_class c \
             LEFT JOIN pg_inherits i ON i.inhparent = c.oid \
             LEFT JOIN pg_class c2 ON c2.oid = COALESCE(i.inhrelid, c.oid) \
             WHERE c.relname = $1 AND c.relkind IN ('r', 'p')",
        )
        .bind(table)
        .fetch_one(state.db.global(Global::CatalogStats))
        .await
        .map(|v| v.max(0.0) as i64)
        .map_err(db_err)?;

        // Total size including indexes and partitions
        let size_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(pg_total_relation_size(c2.oid)), 0)::bigint \
             FROM pg_class c \
             LEFT JOIN pg_inherits i ON i.inhparent = c.oid \
             LEFT JOIN pg_class c2 ON c2.oid = COALESCE(i.inhrelid, c.oid) \
             WHERE c.relname = $1 AND c.relkind IN ('r', 'p')",
        )
        .bind(table)
        .fetch_one(state.db.global(Global::CatalogStats))
        .await
        .map_err(db_err)?;

        let partitions = if partitioned_tables.contains(table) {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_inherits i \
                 JOIN pg_class c ON i.inhrelid = c.oid \
                 JOIN pg_class p ON i.inhparent = p.oid \
                 WHERE p.relname = $1",
            )
            .bind(table)
            .fetch_one(state.db.global(Global::CatalogStats))
            .await
            .map_err(db_err)?;
            Some(count)
        } else {
            None
        };

        tables.push(TableStats {
            name: table.to_string(),
            rows,
            size_bytes,
            partitions,
        });
    }

    let total_db_size_bytes: i64 = sqlx::query_scalar(
        "SELECT pg_database_size(current_database())",
    )
    .fetch_one(state.db.global(Global::CatalogStats))
    .await
    .map_err(db_err)?;

    // Content dedup stats: queries tenant-scoped tables — use RLS connection.
    // Every turn records its history's length and stored size, so the logical
    // volume is a sum over turns, never a walk of their histories.
    let content_dedup = crate::audit_store::stats::message_dedup(db.conn())
    .await
    .ok()
    .and_then(|(unique, refs, stored, projected)| {
        if unique == 0 {
            None
        } else {
            let savings_pct = if projected > 0 {
                (1.0 - stored as f64 / projected as f64) * 100.0
            } else {
                0.0
            };
            Some(ContentDedupStats {
                unique_messages: unique,
                total_message_refs: refs,
                stored_bytes: stored,
                projected_bytes: projected,
                savings_pct,
            })
        }
    });

    // Media blob dedup stats — tenant-scoped via RLS. References are counted
    // where the purge looks for them: the blob_ref blocks of a media call and
    // the entries of a chat's media summary.
    let media_dedup = crate::audit_store::stats::media_dedup(db.conn())
    .await
    .ok()
    .and_then(|(total, unique, refs, stored)| {
        if total == 0 {
            None
        } else {
            let savings_pct = if unique > 0 && total > unique {
                (1.0 - unique as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            Some(MediaDedupStats {
                total_blobs: total,
                unique_hashes: unique,
                total_refs: refs,
                stored_bytes: stored,
                savings_pct,
            })
        }
    });

    // Tool-definition dedup stats — unions ref counts across both
    // `tools_available_hash` and `tools_effective_hash`, so a turn with a
    // policy-modified effective set contributes two refs (and we get the
    // savings_pct that reflects both sides).
    let tools_dedup = crate::audit_store::stats::tool_definition_dedup(db.conn())
    .await
    .ok()
    .and_then(|(unique, refs, stored, projected)| {
        if unique == 0 {
            None
        } else {
            let savings_pct = if projected > 0 {
                (1.0 - stored as f64 / projected as f64) * 100.0
            } else {
                0.0
            };
            Some(ToolsDedupStats {
                unique_tool_sets: unique,
                total_tool_set_refs: refs,
                stored_bytes: stored,
                projected_bytes: projected,
                savings_pct,
            })
        }
    });

    Ok(Json(DbStatsResponse {
        tables,
        total_db_size_bytes,
        content_dedup,
        media_dedup,
        tools_dedup,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/maintenance/wipe-sessions",
    tag = "Settings",
    responses(
        (status = 200, description = "Audit and session data wiped", body = WipeResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn wipe_audit_sessions(
    mut db: TenantConn,
) -> Result<Json<WipeResponse>, ApiError> {
    let db_err = |e: sqlx::Error| {
        tracing::error!("wipe failed: {e}");
        ApiError::internal("wipe failed")
    };

    // One transaction: a statement failing part-way (a timeout on a large
    // tenant) leaves the tenant as it was, never half-wiped. DELETE, not
    // TRUNCATE, so RLS confines every statement to this tenant. Order: turns
    // first (they reference sessions), then audit, content, sessions.
    let mut tx = db.conn().begin().await.map_err(db_err)?;
    crate::audit_store::purge::wipe_facts(&mut tx).await.map_err(db_err)?;
    // Every content store (messages, tool sets, system prompts, history chunks,
    // media blobs), then the suggestions drawn from the conversations and the
    // sessions — a session's message membership goes with its session.
    crate::content_store::purge::wipe(&mut tx).await.map_err(db_err)?;
    for sql in [
        "DELETE FROM program_suggestions",
        "DELETE FROM tool_rule_suggestions",
        "DELETE FROM sessions",
    ] {
        sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
    }
    tx.commit().await.map_err(db_err)?;

    tracing::info!("wiped audit logs, sessions, conversation data, and media blobs for tenant");

    Ok(Json(WipeResponse { status: "ok".into() }))
}

#[derive(Serialize, ToSchema)]
pub struct WipeResponse {
    pub status: String,
}

