//! OIDC provider configuration management.
//!
//! Stores and retrieves OIDC settings (issuer URL, client ID/secret, scopes)
//! per tenant. Used by the admin UI and portal to enable SSO login flows.

use crate::db::Global;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AdminState;
use crate::db::tenant::TenantConn;
use super::{ApiError, ApiErrorCode, ApiErrorResponse};

/// Bound on an OIDC discovery document. Real documents are a few kilobytes;
/// 1 MiB is far past any of them and far short of anything that hurts.
const DISCOVERY_BODY_CAP: u64 = 1024 * 1024;

/// Column defaults of `tenant_auth_configs.oidc_groups_claim` / `oidc_email_claim`
/// — keep in sync with the migration that adds them.
const DEFAULT_GROUPS_CLAIM: &str = "groups";
const DEFAULT_EMAIL_CLAIM: &str = "email";

/// The values `tenant_auth_configs.oidc_response_mode` takes — the column's CHECK.
pub(crate) const RESPONSE_MODE_QUERY: &str = "query";
pub(crate) const RESPONSE_MODE_FORM_POST: &str = "form_post";

/// A claim name as stored: trimmed, and refused when blank — a blank name would
/// read as "no groups" (revoking every console role on the next login) or
/// refuse every login outright.
fn claim_name(field: &'static str, value: Option<&String>) -> Result<Option<String>, ApiError> {
    match value.map(|v| v.trim()) {
        None => Ok(None),
        Some("") => Err(ApiError::bad_request(format!("{field} must not be blank"))
            .code(ApiErrorCode::ValidationFailed)),
        Some(v) => Ok(Some(v.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct AuthConfigResponse {
    pub auth_mode: String,
    pub oidc_issuer_url: Option<String>,
    pub oidc_client_id: Option<String>,
    /// A fixed `****` when a secret is stored, `None` when none is — a
    /// presence flag, never any part of the value.
    pub oidc_client_secret_masked: Option<String>,
    pub oidc_scopes: String,
    /// IdP group whose members get console role `Admin` (OIDC mode).
    pub admin_group: Option<String>,
    /// IdP group whose members get console role `ReadOnly` (OIDC mode).
    /// `admin_group` wins if a user is in both.
    pub readonly_group: Option<String>,
    /// The ID-token claim whose values are matched against `admin_group` /
    /// `readonly_group`. A single string or a list, whichever the provider
    /// sends. Default `groups`; AD FS names it `group`.
    pub oidc_groups_claim: String,
    /// The ID-token claim the account is keyed on — it must hold exactly one
    /// address. Default `email`; `upn` for a directory without mailboxes.
    pub oidc_email_claim: String,
    /// Accept an address the provider made no verification statement about.
    /// Never overrides an explicit `email_verified: false`. Only a claim other
    /// than `email` is always unstated — the provider's `email_verified`
    /// describes `email` alone. Default `false`.
    pub oidc_allow_unverified_email: bool,
    /// How the provider returns the authorization code: `query` (default) or
    /// `form_post`. AD FS puts the claims its rules issue into the ID token only
    /// for a `form_post` authorization.
    pub oidc_response_mode: String,
    pub allowed_domains: Option<Vec<String>>,
    /// When true, the spec-OAuth `/authorize` endpoint delegates
    /// user authentication to the tenant's OIDC IdP (reuses
    /// `oidc_issuer_url` / `oidc_client_id` / `encrypted_oidc_client_secret`
    /// for the consent step) instead of relying on a portal session JWT.
    /// The proxy still mints the access token; the IdP only proves identity.
    /// Defaults to `false`. The admin UI exposes a toggle on the auth-config
    /// page when `auth_mode = oidc`.
    pub mcp_oauth_delegate_to_oidc: bool,
    /// Whether this tenant accepts CIMD (Client ID Metadata Document) clients —
    /// an OAuth client that publishes its metadata at an HTTPS URL and presents
    /// that URL as its `client_id`, with no registration step.
    ///
    /// Defaults to `true`. Turning it off makes the tenant's RFC 8414 document
    /// advertise `client_id_metadata_document_supported: false`, refuses a
    /// URL-shaped `client_id` at `/authorize`, and refuses a
    /// `client_id_metadata_url` at `/register` — closing the one path on which
    /// an unauthenticated caller can name a URL this deployment will fetch.
    pub mcp_oauth_cimd_enabled: bool,
}

/// Partial update. Absent leaves a field as stored; `null` clears a nullable
/// one (the issuer, client id, groups and allowed domains).
#[derive(Deserialize, ToSchema)]
pub struct UpdateAuthConfigRequest {
    pub auth_mode: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub oidc_issuer_url: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub oidc_client_id: Option<Option<String>>,
    /// A write-only secret: absent or `null` keeps the stored one, `""` clears it.
    pub oidc_client_secret: Option<String>,
    pub oidc_scopes: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub admin_group: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub readonly_group: Option<Option<String>>,
    /// See [`AuthConfigResponse::oidc_groups_claim`]. Must not be blank.
    pub oidc_groups_claim: Option<String>,
    /// See [`AuthConfigResponse::oidc_email_claim`]. Must not be blank.
    pub oidc_email_claim: Option<String>,
    /// See [`AuthConfigResponse::oidc_allow_unverified_email`].
    pub oidc_allow_unverified_email: Option<bool>,
    /// See [`AuthConfigResponse::oidc_response_mode`]. `query` or `form_post`.
    pub oidc_response_mode: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub allowed_domains: Option<Option<Vec<String>>>,
    /// See [`AuthConfigResponse::mcp_oauth_delegate_to_oidc`].
    pub mcp_oauth_delegate_to_oidc: Option<bool>,
    /// See [`AuthConfigResponse::mcp_oauth_cimd_enabled`].
    pub mcp_oauth_cimd_enabled: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct TenantAuthInfoResponse {
    pub slug: String,
    pub name: String,
    pub auth_mode: String,
    pub oidc_issuer_url: Option<String>,
    pub oidc_client_id: Option<String>,
    /// When true, the spec-OAuth `/authorize` consent step
    /// delegates user authentication to the tenant's OIDC IdP. The portal
    /// consent page reads this to decide whether to redirect to OIDC begin
    /// instead of rendering the credential-based session check.
    pub mcp_oauth_delegate_to_oidc: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct OidcTestRequest {
    pub oidc_issuer_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OidcTestResponse {
    pub success: bool,
    pub message: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Auth config routes (behind admin_auth middleware — self-service for tenant admins).
pub fn auth_config_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/config", get(get_auth_config).patch(update_auth_config))
        .route("/config/actions/test", post(test_oidc_config))
}

/// Public tenant auth info (no auth required).
pub fn public_auth_info_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/{slug}/auth-info", get(get_tenant_auth_info))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/config",
    tag = "Auth Config",
    responses(
        (status = 200, description = "Current auth configuration", body = AuthConfigResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn get_auth_config(
    mut db: TenantConn,
) -> Result<Json<AuthConfigResponse>, ApiError> {
    #[derive(sqlx::FromRow)]
    struct ConfigRow {
        auth_mode: String,
        oidc_issuer_url: Option<String>,
        oidc_client_id: Option<String>,
        encrypted_oidc_client_secret: Option<String>,
        oidc_scopes: String,
        admin_group: Option<String>,
        readonly_group: Option<String>,
        oidc_groups_claim: String,
        oidc_email_claim: String,
        oidc_allow_unverified_email: bool,
        oidc_response_mode: String,
        allowed_domains: Option<Vec<String>>,
        mcp_oauth_delegate_to_oidc: bool,
        mcp_oauth_cimd_enabled: bool,
    }

    let row = sqlx::query_as::<_, ConfigRow>(
        "SELECT auth_mode, oidc_issuer_url, oidc_client_id, encrypted_oidc_client_secret, \
         oidc_scopes, admin_group, readonly_group, oidc_groups_claim, oidc_email_claim, \
         oidc_allow_unverified_email, oidc_response_mode, allowed_domains, mcp_oauth_delegate_to_oidc, \
         mcp_oauth_cimd_enabled \
         FROM tenant_auth_configs WHERE tenant_id = current_tenant_id()",
    )
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get auth config: {e}");
        ApiError::internal("failed to get auth config")
    })?;

    let Some(r) = row else {
        return Ok(Json(AuthConfigResponse {
            auth_mode: "internal".to_string(),
            oidc_issuer_url: None,
            oidc_client_id: None,
            oidc_client_secret_masked: None,
            oidc_scopes: "openid email profile".to_string(),
            admin_group: None,
            readonly_group: None,
            oidc_groups_claim: DEFAULT_GROUPS_CLAIM.to_string(),
            oidc_email_claim: DEFAULT_EMAIL_CLAIM.to_string(),
            oidc_allow_unverified_email: false,
            oidc_response_mode: RESPONSE_MODE_QUERY.to_string(),
            allowed_domains: None,
            mcp_oauth_delegate_to_oidc: false,
            mcp_oauth_cimd_enabled: true,
        }));
    };

    // Mask client secret (last 4 chars only).
    let masked = r.encrypted_oidc_client_secret.as_ref().map(|_| "****".to_string());

    Ok(Json(AuthConfigResponse {
        auth_mode: r.auth_mode,
        oidc_issuer_url: r.oidc_issuer_url,
        oidc_client_id: r.oidc_client_id,
        oidc_client_secret_masked: masked,
        oidc_scopes: r.oidc_scopes,
        admin_group: r.admin_group,
        readonly_group: r.readonly_group,
        oidc_groups_claim: r.oidc_groups_claim,
        oidc_email_claim: r.oidc_email_claim,
        oidc_allow_unverified_email: r.oidc_allow_unverified_email,
        oidc_response_mode: r.oidc_response_mode,
        allowed_domains: r.allowed_domains,
        mcp_oauth_delegate_to_oidc: r.mcp_oauth_delegate_to_oidc,
        mcp_oauth_cimd_enabled: r.mcp_oauth_cimd_enabled,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/config",
    tag = "Auth Config",
    request_body = UpdateAuthConfigRequest,
    responses(
        (status = 200, description = "Auth configuration updated", body = AuthConfigResponse),
        (status = 400, description = "Bad request (invalid auth_mode or OIDC URL)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "ENCRYPTION_KEY not configured", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn update_auth_config(
    mut db: TenantConn,
    Json(req): Json<UpdateAuthConfigRequest>,
) -> Result<Json<AuthConfigResponse>, ApiError> {
    // Validate auth_mode if provided.
    // Note: switching to OIDC does not require a linked OIDC admin — the first
    // admin OIDC login auto-links via the callback flow.
    // WARNING: if OIDC is misconfigured, password login is disabled for this tenant.
    // Recovery: a super-admin can switch the tenant back to internal via PATCH /config
    // from the SYSTEM tenant, or via direct DB update.
    if let Some(mode) = &req.auth_mode
        && mode != "internal" && mode != "oidc"
    {
        return Err(ApiError::bad_request("auth_mode must be 'internal' or 'oidc'")
            .code(ApiErrorCode::AuthModeInvalid));
    }

    // Validate OIDC issuer URL uses HTTPS (prevents plaintext token exchange).
    if let Some(Some(url)) = &req.oidc_issuer_url
        && !url.is_empty()
        && !url.starts_with("https://")
    {
        return Err(ApiError::bad_request("oidc_issuer_url must use HTTPS")
            .code(ApiErrorCode::OidcIssuerRequiresHttps));
    }

    let groups_claim = claim_name("oidc_groups_claim", req.oidc_groups_claim.as_ref())?;
    let email_claim = claim_name("oidc_email_claim", req.oidc_email_claim.as_ref())?;
    if let Some(mode) = req.oidc_response_mode.as_deref()
        && mode != RESPONSE_MODE_QUERY
        && mode != RESPONSE_MODE_FORM_POST
    {
        return Err(ApiError::bad_request("oidc_response_mode must be 'query' or 'form_post'")
            .code(ApiErrorCode::ValidationFailed));
    }

    // Encrypt client secret if provided.
    let encrypted_secret = if let Some(secret) = &req.oidc_client_secret {
        if secret.is_empty() {
            None
        } else {
            let key = streamscope_core::crypto::get_encryption_key()
                .ok_or_else(|| ApiError::server_misconfigured("ENCRYPTION_KEY not configured"))?;
            Some(streamscope_core::crypto::encrypt(secret, &key).map_err(|e| {
                tracing::error!("encrypt oidc secret: {e}");
                ApiError::internal("failed to encrypt OIDC secret")
            })?)
        }
    } else {
        None
    };

    // Upsert config. Uses CASE to distinguish "field omitted" (NULL → keep old)
    // from "field explicitly set" (non-NULL → replace, even if empty string).
    // The $8 flags array indicates which fields were provided in the request.
    let provided_flags: Vec<bool> = vec![
        req.auth_mode.is_some(),
        req.oidc_issuer_url.is_some(),
        req.oidc_client_id.is_some(),
        encrypted_secret.is_some() || req.oidc_client_secret.as_ref().is_some_and(|s| s.is_empty()),
        req.oidc_scopes.is_some(),
        req.admin_group.is_some(),
        req.allowed_domains.is_some(),
        req.mcp_oauth_delegate_to_oidc.is_some(),
        req.readonly_group.is_some(),
        req.mcp_oauth_cimd_enabled.is_some(),
        groups_claim.is_some(),
        email_claim.is_some(),
        req.oidc_allow_unverified_email.is_some(),
        req.oidc_response_mode.is_some(),
    ];

    sqlx::query(
        "INSERT INTO tenant_auth_configs (tenant_id, auth_mode, oidc_issuer_url, oidc_client_id, \
         encrypted_oidc_client_secret, oidc_scopes, admin_group, allowed_domains, \
         mcp_oauth_delegate_to_oidc, readonly_group, mcp_oauth_cimd_enabled, \
         oidc_groups_claim, oidc_email_claim, oidc_allow_unverified_email, oidc_response_mode, \
         updated_at) \
         VALUES (current_tenant_id(), \
                 COALESCE($1, 'internal'), $2, $3, $4, COALESCE($5, 'openid email profile'), $6, $7, \
                 COALESCE($9, false), $10, COALESCE($11, true), \
                 COALESCE($12, $16), COALESCE($13, $17), COALESCE($14, false), \
                 COALESCE($15, $18), NOW()) \
         ON CONFLICT (tenant_id) DO UPDATE SET \
            auth_mode = CASE WHEN $8[1] THEN COALESCE($1, 'internal') ELSE tenant_auth_configs.auth_mode END, \
            oidc_issuer_url = CASE WHEN $8[2] THEN $2 ELSE tenant_auth_configs.oidc_issuer_url END, \
            oidc_client_id = CASE WHEN $8[3] THEN $3 ELSE tenant_auth_configs.oidc_client_id END, \
            encrypted_oidc_client_secret = CASE WHEN $8[4] THEN $4 ELSE tenant_auth_configs.encrypted_oidc_client_secret END, \
            oidc_scopes = CASE WHEN $8[5] THEN COALESCE($5, 'openid email profile') ELSE tenant_auth_configs.oidc_scopes END, \
            admin_group = CASE WHEN $8[6] THEN $6 ELSE tenant_auth_configs.admin_group END, \
            allowed_domains = CASE WHEN $8[7] THEN $7 ELSE tenant_auth_configs.allowed_domains END, \
            mcp_oauth_delegate_to_oidc = CASE WHEN $8[8] THEN COALESCE($9, false) ELSE tenant_auth_configs.mcp_oauth_delegate_to_oidc END, \
            readonly_group = CASE WHEN $8[9] THEN $10 ELSE tenant_auth_configs.readonly_group END, \
            mcp_oauth_cimd_enabled = CASE WHEN $8[10] THEN COALESCE($11, true) ELSE tenant_auth_configs.mcp_oauth_cimd_enabled END, \
            oidc_groups_claim = CASE WHEN $8[11] THEN $12 ELSE tenant_auth_configs.oidc_groups_claim END, \
            oidc_email_claim = CASE WHEN $8[12] THEN $13 ELSE tenant_auth_configs.oidc_email_claim END, \
            oidc_allow_unverified_email = CASE WHEN $8[13] THEN COALESCE($14, false) ELSE tenant_auth_configs.oidc_allow_unverified_email END, \
            oidc_response_mode = CASE WHEN $8[14] THEN COALESCE($15, $18) ELSE tenant_auth_configs.oidc_response_mode END, \
            updated_at = NOW()",
    )
    .bind(&req.auth_mode)
    .bind(req.oidc_issuer_url.as_ref().and_then(Option::as_ref))
    .bind(req.oidc_client_id.as_ref().and_then(Option::as_ref))
    .bind(&encrypted_secret)
    .bind(&req.oidc_scopes)
    .bind(req.admin_group.as_ref().and_then(Option::as_ref))
    .bind(req.allowed_domains.as_ref().and_then(Option::as_ref))
    .bind(&provided_flags)
    .bind(req.mcp_oauth_delegate_to_oidc)
    .bind(req.readonly_group.as_ref().and_then(Option::as_ref))
    .bind(req.mcp_oauth_cimd_enabled)
    .bind(&groups_claim)
    .bind(&email_claim)
    .bind(req.oidc_allow_unverified_email)
    .bind(&req.oidc_response_mode)
    .bind(DEFAULT_GROUPS_CLAIM)
    .bind(DEFAULT_EMAIL_CLAIM)
    .bind(RESPONSE_MODE_QUERY)
    .execute(db.conn())
    .await
    .map_err(|e| {
        // `chk_oidc_email_claim_needs_opt_in`: a claim other than `email` carries
        // no verification statement, so without the opt-in no sign-in could pass.
        if super::is_check_violation(&e)
            && e.as_database_error().and_then(|d| d.constraint()) == Some("chk_oidc_email_claim_needs_opt_in")
        {
            return ApiError::bad_request(
                "an email claim other than 'email' needs oidc_allow_unverified_email — \
                 the provider states no verification for any other claim",
            )
            .code(ApiErrorCode::ValidationFailed);
        }
        tracing::error!("update auth config: {e}");
        ApiError::internal("failed to update auth config")
    })?;

    // A save is the event that makes a remembered discovery failure stale. Drop
    // it, so an admin who has just corrected the issuer URL is not told the old
    // error for another minute and left wondering whether the fix took.
    if let Some(Some(issuer)) = req.oidc_issuer_url.as_ref() {
        crate::routes::oidc_rp::forget_provider_failure(issuer).await;
    }

    // Note: password-only accounts are NOT auto-disabled on mode switch.
    // Auth enforcement already blocks password login when mode=oidc, so these
    // accounts are harmless. Admins can manually disable them from the Auth page.

    // Return updated config.
    get_auth_config(db).await
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/config/actions/test",
    tag = "Auth Config",
    request_body = OidcTestRequest,
    responses(
        (status = 200, description = "OIDC discovery test result", body = OidcTestResponse),
        (status = 400, description = "Bad request (missing or invalid issuer URL)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 502, description = "OIDC discovery request failed", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn test_oidc_config(
    mut db: TenantConn,
    Json(req): Json<OidcTestRequest>,
) -> Result<Json<OidcTestResponse>, ApiError> {
    // Fresh trusted-CA read: the cache is process-local and only the replica
    // that handled the import refreshes it, so an outbound TLS hop on a
    // sibling replica would otherwise use a stale trust set.
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    // Release the pooled connection before the DNS resolve + HTTPS fetch
    // below: holding one across two network operations lets a slow or
    // unreachable issuer tie up a pool slot for the whole timeout.
    drop(db);
    let issuer_url = req.oidc_issuer_url.as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("oidc_issuer_url is required")
            .code(ApiErrorCode::OidcIssuerUrlRequired))?;

    if !issuer_url.starts_with("https://") {
        return Err(ApiError::bad_request("OIDC issuer URL must use HTTPS")
            .code(ApiErrorCode::OidcIssuerRequiresHttps));
    }

    let well_known = format!("{}/.well-known/openid-configuration", issuer_url.trim_end_matches('/'));

    let settings = crate::settings::admin_settings();
    let skip_tls = settings.oidc_skip_tls_verify;

    // SSRF: refuse private/loopback/link-local/IMDS addresses, both as
    // IP literals in the URL and as DNS resolution results. Pin verified
    // addrs into reqwest so the actual TCP connect uses an IP we already
    // vetted (closes the DNS-rebinding window). Redirects are disabled
    // because the OIDC `.well-known/openid-configuration` endpoint is meant
    // to be served directly — a redirect to a fresh hostname would not be
    // covered by `resolve_to_addrs`. An internal address passes only when the
    // platform's `oidc` egress list lists it.
    let mut builder = streamscope_core::tls::add_custom_roots(
        reqwest::Client::builder()
            .timeout(settings.oidc_client_timeout)
            .danger_accept_invalid_certs(skip_tls)
            .redirect(reqwest::redirect::Policy::none()),
        crate::custom_ca::current().as_deref(),
    );

    {
        // Bound the DNS lookup so a slow resolver can't tie up an admin worker.
        let resolve =
            tokio::time::timeout(
                settings.oidc_client_timeout,
                streamscope_mcp_auth::ssrf::resolve_and_pin_addrs_for(&well_known, crate::oidc::http::OIDC_EGRESS),
            )
            .await
            .map_err(|_| {
                tracing::warn!("OIDC issuer DNS lookup timed out");
                ApiError::bad_gateway("OIDC issuer DNS lookup timed out")
            })?;
        let (_url, host, addrs) = resolve.map_err(|e| match e {
            streamscope_mcp_auth::SsrfError::InternalAddress => {
                ApiError::bad_request(
                    "OIDC issuer resolves to a private/internal address the platform's oidc egress \
                     list does not list — refused for SSRF safety",
                )
                .code(ApiErrorCode::OidcIssuerSsrfBlocked)
            }
            streamscope_mcp_auth::SsrfError::DnsLookup(msg) => {
                tracing::warn!("OIDC issuer DNS lookup failed: {msg}");
                ApiError::bad_gateway("OIDC issuer DNS lookup failed")
            }
            streamscope_mcp_auth::SsrfError::NoAddresses => {
                ApiError::bad_gateway("OIDC issuer host has no addresses")
            }
            streamscope_mcp_auth::SsrfError::UrlParse(_)
            | streamscope_mcp_auth::SsrfError::PlainHttp
            | streamscope_mcp_auth::SsrfError::BadScheme
            | streamscope_mcp_auth::SsrfError::MissingHost => {
                ApiError::bad_request("OIDC issuer URL invalid")
                    .code(ApiErrorCode::OidcIssuerUrlInvalid)
            }
        })?;
        builder = builder.resolve_to_addrs(&host, &addrs);
    }

    let client = builder
        .build()
        .map_err(|e| {
            tracing::error!("test oidc client: {e}");
            ApiError::internal("failed to build HTTP client")
        })?;

    let res = client.get(&well_known).send().await.map_err(|e| {
        tracing::warn!("OIDC discovery request failed: {e}");
        ApiError::bad_gateway("OIDC discovery request failed")
    })?;

    if !res.status().is_success() {
        return Ok(Json(OidcTestResponse {
            success: false,
            message: format!("Discovery returned HTTP {}", res.status()),
            authorization_endpoint: None,
            token_endpoint: None,
        }));
    }

    // The issuer is operator-supplied, so this read is bounded like every other
    // egress read: a discovery document is a few kilobytes, and an unbounded
    // read makes a hostile or broken issuer URL a way to OOM this replica.
    let raw = streamscope_core::http_body::read_body_capped(res, DISCOVERY_BODY_CAP)
        .await
        .map_err(|e| {
            tracing::warn!("OIDC discovery body read failed: {e}");
            ApiError::bad_gateway("invalid discovery response")
        })?;
    let config: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        tracing::warn!("OIDC discovery JSON parse failed: {e}");
        ApiError::bad_gateway("invalid discovery response")
    })?;

    Ok(Json(OidcTestResponse {
        success: true,
        message: "Discovery successful".to_string(),
        authorization_endpoint: config.get("authorization_endpoint").and_then(|v| v.as_str()).map(|s| s.to_string()),
        token_endpoint: config.get("token_endpoint").and_then(|v| v.as_str()).map(|s| s.to_string()),
    }))
}

/// Public endpoint: minimal auth info for a tenant (no secrets).
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{slug}/auth-info",
    tag = "Auth Config",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Tenant auth info (public)", body = TenantAuthInfoResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 429, description = "Too many requests", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
)]
pub(crate) async fn get_tenant_auth_info(
    State(state): State<Arc<AdminState>>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> Result<Json<TenantAuthInfoResponse>, ApiError> {
    // Bounded per visitor by `pre_auth_ip_rate_limit_mw` at its mount, and only
    // there: a public, non-secret read keyed by the organisation alone would let
    // any visitor exhaust every other visitor's sign-in page.
    // Step 1: resolve the slug to a tenant.
    let row: Option<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT id, name, slug FROM tenants WHERE slug = $1 AND is_active = true",
    )
    .bind(&slug)
    .fetch_optional(state.db.global(Global::PreAuth))
    .await
    .map_err(|e| {
        tracing::error!("get_tenant_auth_info: {e}");
        super::db_read_error(&e, "the tenant could not be looked up")
    })?;

    let Some((tenant_id, name, slug)) = row else {
        return Err(ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound));
    };

    // Step 2: read the auth config inside the tenant's RLS context.
    let mut db = TenantConn::acquire(&state.db, crate::db::tenant::TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("get_tenant_auth_info TenantConn: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    let config: Option<(String, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT auth_mode, oidc_issuer_url, oidc_client_id, mcp_oauth_delegate_to_oidc \
         FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get_tenant_auth_info config: {e}");
        super::db_read_error(&e, "the sign-in settings could not be read")
    })?;

    let (auth_mode, issuer_url, client_id, delegate) =
        config.unwrap_or(("internal".to_string(), None, None, false));

    Ok(Json(TenantAuthInfoResponse {
        slug,
        name,
        auth_mode,
        oidc_issuer_url: issuer_url,
        oidc_client_id: client_id,
        mcp_oauth_delegate_to_oidc: delegate,
    }))
}
