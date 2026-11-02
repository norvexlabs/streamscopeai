//! Per-tenant public-URL resolver.
//!
//! Three settings follow the SYSTEM-default-with-tenant-override pattern:
//!
//! | Key | Used by |
//! |-----|---------|
//! | `proxy_public_url` | Quickstart snippets, MCP OAuth audience, MCP CORS |
//! | `admin_public_url` | Login links, invite emails, MCP OAuth admin redirect, admin/portal CORS |
//! | `api_public_url`   | Documented FQDN for external scripting / CLI access to the admin-API. Caddy already serves the API at this hostname; the setting is what operators set, document, and the UI displays for copy-out. Not in any CORS allowlist (scripts aren't browsers; the UI is same-origin via the SvelteKit proxy). |
//!
//! Resolution chain:
//! 1. `system_settings` row for `(key, tenant_id=<T>)` — per-tenant override.
//! 2. `system_settings` row for `(key, tenant_id=SYSTEM)` — platform default.
//! 3. Both empty → fail closed (`ApiError` with the matching `*Unset` code).
//!
//! `system_settings` is RLS-scoped, and the two layers live under different
//! tenants, so the lookup is two tenant-scoped reads (caller's tenant, then
//! SYSTEM) rather than one unscoped one — an unscoped read would see neither row.

use uuid::Uuid;

use crate::db::Db;
use crate::db::tenant::TenantId;
use crate::routes::{ApiError, ApiErrorCode};

/// Discriminator for the two layered public-URL keys. Adding a new layered
/// setting is a one-variant edit here plus a `match` arm in `key_str` and
/// `unset_error_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicUrlKey {
    Proxy,
    Admin,
    Api,
}

impl PublicUrlKey {
    /// Every public-URL key in the system. Iteration order is the
    /// canonical order for both UI listing and seeder traversal — adding
    /// a new variant is the only edit needed for the bootstrap seeder,
    /// the host-mode script, and the inherited-defaults block to pick
    /// the new key up.
    pub const ALL: &'static [PublicUrlKey] =
        &[PublicUrlKey::Proxy, PublicUrlKey::Admin, PublicUrlKey::Api];

    pub fn key_str(self) -> &'static str {
        match self {
            PublicUrlKey::Proxy => "proxy_public_url",
            PublicUrlKey::Admin => "admin_public_url",
            PublicUrlKey::Api => "api_public_url",
        }
    }

    /// One-shot bootstrap env var read at admin-api startup. Never
    /// referenced at runtime; only applied when the SYSTEM row is empty.
    pub fn bootstrap_env_var(self) -> &'static str {
        match self {
            PublicUrlKey::Proxy => "BOOTSTRAP_PROXY_PUBLIC_URL",
            PublicUrlKey::Admin => "BOOTSTRAP_ADMIN_PUBLIC_URL",
            PublicUrlKey::Api => "BOOTSTRAP_API_PUBLIC_URL",
        }
    }

    fn unset_error_code(self) -> ApiErrorCode {
        match self {
            PublicUrlKey::Proxy => ApiErrorCode::ProxyPublicUrlUnset,
            PublicUrlKey::Admin => ApiErrorCode::AdminPublicUrlUnset,
            PublicUrlKey::Api => ApiErrorCode::ApiPublicUrlUnset,
        }
    }

    /// The canonical fail-closed error for an unconfigured key — shared by
    /// every resolver that surfaces "neither layer is set" as a 4xx.
    fn unset_error(self) -> ApiError {
        ApiError::bad_request(format!(
            "{} is not configured for this tenant or as the platform default — \
             configure it under Settings → Proxy (system tenant for the default, \
             your tenant to override).",
            self.key_str()
        ))
        .code(self.unset_error_code())
    }
}

/// Resolve a layered public URL. Returns the effective value (tenant
/// override if set, else SYSTEM default). `Err` when *both* layers are
/// empty — handlers surface that as `ProxyPublicUrlUnset` /
/// `AdminPublicUrlUnset` and the UI shows the configuration CTA.
pub async fn resolve_public_url(
    pool: &Db,
    tenant_id: Uuid,
    key: PublicUrlKey,
) -> Result<String, ApiError> {
    try_resolve_public_url(pool, tenant_id, key)
        .await?
        .ok_or_else(|| key.unset_error())
}

/// Non-erroring variant: returns `None` when both layers are empty. Used by
/// the settings GET so the UI can render the "not configured" banner
/// without a 4xx.
///
/// `system_settings` is RLS-scoped, and the two layers live under different
/// tenants, so each read runs on its own tenant-scoped connection: the caller's
/// tenant for the override, then SYSTEM for the platform default. The SYSTEM read
/// only happens when there is no override.
pub async fn try_resolve_public_url(
    pool: &Db,
    tenant_id: Uuid,
    key: PublicUrlKey,
) -> Result<Option<String>, ApiError> {
    let read_for = async |t: TenantId| -> Result<Option<serde_json::Value>, ApiError> {
        let mut db = pool.tenant(t).await.map_err(|e| {
            tracing::error!(?e, "failed to acquire tenant connection");
            ApiError::internal("internal error")
        })?;
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1 AND tenant_id = $2")
            .bind(key.key_str())
            .bind(t.as_uuid())
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!(?e, key = key.key_str(), tenant = %t, "failed to load public-url setting");
                ApiError::internal("internal error")
            })
    };

    let pick = |v: Option<serde_json::Value>| {
        v.as_ref()
            .and_then(|x| x.as_str())
            .map(|s| s.trim_end_matches('/'))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    if let Some(s) = pick(read_for(TenantId::from_row(tenant_id)).await?) {
        return Ok(Some(s));
    }
    Ok(pick(read_for(TenantId::SYSTEM).await?))
}

/// Resolved origin pair for an OAuth discovery surface (CLI and MCP alike):
/// browser-facing endpoints (consent pages) ride `admin`; machine-facing
/// endpoints (issuer / token / registration / jwks) ride `api`.
pub struct OauthDiscoveryOrigins {
    /// The admin/portal UI origin (`admin_public_url`, fail-closed when
    /// neither layer is configured).
    pub admin: String,
    /// The canonical admin-API origin (`api_public_url`), falling back to
    /// `admin` when unset — the production deploy shapes serve UI and API on
    /// separate vhosts and the UI origin never routes `/api/v1/*`; an unset
    /// `api_public_url` means the API is co-resident with the UI
    /// (single-domain installs, e2e).
    pub api: String,
}

impl OauthDiscoveryOrigins {
    /// The api-falls-back-to-admin rule over already-resolved layered
    /// values — the single home of the rule; change it here, never
    /// per-surface (a per-surface copy is how the CLI and MCP documents
    /// once diverged on split-vhost deploys). `None` when the admin origin
    /// is unconfigured: the api origin alone can't host browser consent,
    /// so no OAuth surface is servable.
    pub fn from_layered(admin: Option<String>, api: Option<String>) -> Option<Self> {
        let admin = admin?;
        let api = api.unwrap_or_else(|| admin.clone());
        Some(Self { admin, api })
    }
}

/// Resolve the admin + API origin pair every OAuth discovery surface needs.
/// Fails closed with `AdminPublicUrlUnset` when neither layer configures the
/// admin origin. Display surfaces that want a hint instead of a 4xx resolve
/// the two keys with `try_resolve_public_url` and feed
/// [`OauthDiscoveryOrigins::from_layered`].
pub async fn resolve_oauth_discovery_origins(
    pool: &Db,
    tenant_id: Uuid,
) -> Result<OauthDiscoveryOrigins, ApiError> {
    let admin = try_resolve_public_url(pool, tenant_id, PublicUrlKey::Admin).await?;
    let api = try_resolve_public_url(pool, tenant_id, PublicUrlKey::Api).await?;
    OauthDiscoveryOrigins::from_layered(admin, api)
        .ok_or_else(|| PublicUrlKey::Admin.unset_error())
}

/// Validate a public-URL string. Used at PUT time so we never persist a
/// malformed value. Rules: scheme is `http` or `https`, host non-empty,
/// no path/query/fragment, no trailing slash. Empty input is rejected by
/// the caller before reaching here (empty = "clear the override").
///
/// Lightweight string parser — `url::Url` would pull a new dep.
pub fn validate_public_url(input: &str) -> Result<(), ApiError> {
    let invalid = |msg: &'static str| {
        ApiError::bad_request(format!("public URL: {msg}")).code(ApiErrorCode::PublicUrlInvalid)
    };
    let rest = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .ok_or_else(|| invalid("scheme must be http:// or https://"))?;
    if rest.is_empty() {
        return Err(invalid("missing host"));
    }
    if rest.contains(['/', '?', '#']) {
        return Err(invalid("must not include a path, query, or fragment"));
    }
    if input.ends_with('/') {
        return Err(invalid("must not end with a trailing slash"));
    }
    // Reject embedded credentials (`user:pass@host`) and whitespace.
    if rest.contains('@') || rest.chars().any(char::is_whitespace) {
        return Err(invalid("host must not contain '@' or whitespace"));
    }
    // Host must contain at least one non-colon char (i.e. not only ":port").
    if rest.starts_with(':') {
        return Err(invalid("missing host"));
    }
    Ok(())
}

/// One-shot bootstrap seeder. Iterates every `PublicUrlKey` variant, reads
/// the matching `BOOTSTRAP_*_PUBLIC_URL` env var, and upserts into
/// `system_settings (key, tenant_id=SYSTEM)` **only when the SYSTEM row is
/// empty/missing**. Operator-set values are never overwritten.
///
/// Runs once at admin-api startup, after migrations, before serving. Not a
/// runtime fallback — the resolver never reads env vars; this code path
/// only fires when the SYSTEM row is missing on a fresh deploy.
///
/// `system_settings` is RLS-scoped per `tenant_id` and the runtime role does not
/// bypass RLS, so the whole seed runs on one SYSTEM-scoped connection.
pub async fn run_bootstrap_seed(pool: &Db) -> Result<(), sqlx::Error> {
    let mut db = pool.tenant(TenantId::SYSTEM).await?;
    let conn = db.conn();
    for key in PublicUrlKey::ALL {
        let env_name = key.bootstrap_env_var();
        let Ok(value) = std::env::var(env_name) else {
            continue;
        };
        let value = value.trim().trim_end_matches('/').to_string();
        if value.is_empty() {
            continue;
        }
        if let Err(e) = validate_public_url(&value) {
            tracing::warn!(
                env = env_name,
                error = %e.message,
                "bootstrap seed: ignoring malformed env value"
            );
            continue;
        }

        // Skip if SYSTEM row already has a non-empty value — never
        // overwrite operator config on subsequent boots.
        let existing: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT value FROM system_settings WHERE key = $1 AND tenant_id = $2",
        )
        .bind(key.key_str())
        .bind(TenantId::SYSTEM.as_uuid())
        .fetch_optional(&mut *conn)
        .await?;
        if existing
            .as_ref()
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            tracing::info!(
                key = key.key_str(),
                env = env_name,
                "bootstrap seed: SYSTEM row already configured (boot env ignored)"
            );
            continue;
        }

        sqlx::query(
            "INSERT INTO system_settings (key, tenant_id, value, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (tenant_id, key) DO UPDATE \
             SET value = EXCLUDED.value, updated_at = now()",
        )
        .bind(key.key_str())
        .bind(TenantId::SYSTEM.as_uuid())
        .bind(serde_json::Value::String(value.clone()))
        .execute(&mut *conn)
        .await?;
        tracing::info!(
            key = key.key_str(),
            env = env_name,
            value = %value,
            "bootstrap seed: SYSTEM row populated from env"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_urls_accepted() {
        for u in [
            "https://gw.example.com",
            "http://localhost:9090",
            "https://gw.example.com:8443",
            "https://proxy.local:8443",
        ] {
            validate_public_url(u).unwrap_or_else(|_| panic!("expected {u} to be valid"));
        }
    }

    #[test]
    fn invalid_urls_rejected() {
        for u in [
            "",
            "ftp://gw.example.com",
            "https://gw.example.com/",
            "https://gw.example.com/v1",
            "https://gw.example.com?x=1",
            "https://gw.example.com#frag",
            "not-a-url",
        ] {
            assert!(validate_public_url(u).is_err(), "expected {u} to be rejected");
        }
    }

    #[test]
    fn key_strings_match_db_keys() {
        assert_eq!(PublicUrlKey::Proxy.key_str(), "proxy_public_url");
        assert_eq!(PublicUrlKey::Admin.key_str(), "admin_public_url");
        assert_eq!(PublicUrlKey::Api.key_str(), "api_public_url");
    }
}
