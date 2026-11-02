//! CLI provisioning OAuth 2.1 surface — `ssai login`.
//!
//! Mirrors the MCP spec-OAuth surface (`mcp_oauth`) over the shared
//! `oauth_common` plumbing and the surface-discriminated
//! `oauth_authorization_codes` / `oauth_issued_tokens` tables
//! (`surface = 'cli'`), with the differences a first-party native client
//! implies:
//!
//! * **One static public client** — [`CLI_CLIENT_ID`]. No DCR/CIMD, no DB
//!   row: PKCE (S256-only) + loopback-only redirect URIs + the consent page
//!   carry the security.
//! * **Loopback-only redirects** — the authorization code can only land on
//!   the machine that initiated the login (`http://127.0.0.1[:port]/...`).
//! * **Access token = a portal-plane JWT** ([`PortalClaims`]) with
//!   `scope = "provision"` and a revocable `jti` — fenced by `portal_auth`
//!   to the provisioning allowlist, never the admin plane.
//!
//! Route surface (public, mounted under `/api/v1/cli/oauth/{tenant_slug}`):
//! metadata (RFC 8414), `/authorize/{preview,approve}` (portal-JWT gated
//! consent backend for the SvelteKit page at `/portal/t/<slug>/cli/authorize`),
//! `/device_authorization` + `/device/{preview,approve,deny}` (RFC 8628
//! device grant — headless logins; the approval page is
//! `/portal/t/<slug>/cli/device`), `/token` (code + device + rotating-refresh
//! grants), `/revoke` (RFC 7009 — backs `ssai logout`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_mcp_auth::jwt::new_jti;
use streamscope_mcp_auth::metadata::AuthorizationServerMetadata;
use streamscope_mcp_auth::{verify_s256_challenge, Keyring, SURFACE_CLI, TOKEN_ISSUER};

use super::admin_auth::keyring;
use super::oauth_common::{
    authorization_error_redirect, authorization_redirect, decode_refresh_jwt, encode_refresh_jwt,
    generate_authorization_code, surface_issuer, OauthSurface,
    require_tenant_portal_session, credential_ok, resolve_tenant_id, retire_chain_on_reuse,
    token_ok, urlencode,
    validate_loopback_redirect_uri, AuthorizeApproveResponse, AuthorizeRejection, CredentialReply,
    TokenReply, TokenRequest, TokenResponse,
    ACCESS_TOKEN_TTL_SECS, AUTH_CODE_TTL_SECS, DEVICE_CODE_TTL_SECS,
    DEVICE_POLL_INTERVAL_SECS, REFRESH_TOKEN_TTL_SECS, REFRESH_TOKEN_TYP,
};
use super::oauth_error::{OauthError, OauthErrorCode, OauthErrorResponse, OauthForm};
use super::portal_auth::{PortalClaims, SCOPE_PROVISION};
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn, TenantId};
use crate::AdminState;

/// The single, well-known public client id of the `ssai` CLI. First
/// party and PKCE-protected, so no per-deploy registration is needed.
pub const CLI_CLIENT_ID: &str = "streamscope-cli";

/// Device labels are operator-visible (consent page, token listings) —
/// bound so a hostile client can't stuff megabytes into the row.
const DEVICE_NAME_MAX_CHARS: usize = 64;

/// RFC 8628 §3.4 device-grant `grant_type` value.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// RFC 8628 §6.1 recommended user-code charset: uppercase consonants only —
/// no vowels (no accidental words), no confusable I/O/0/1.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Generate a `XXXX-XXXX` user code (20^8 ≈ 25.6e9 combinations — far above
/// the RFC's minimum entropy for a 10-minute-TTL code behind a rate limit).
fn generate_user_code() -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    let mut code = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        code.push(USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())] as char);
    }
    code
}

/// Canonicalise what the user typed on the approval page — case, the dash,
/// and stray whitespace are display sugar, not part of the code (RFC 8628
/// §6.1). Returns the canonical `XXXX-XXXX` form, or `None` when the input
/// can't be a user code.
fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if letters.len() != 8 || !letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)) {
        return None;
    }
    Some(format!("{}-{}", &letters[..4], &letters[4..]))
}

fn normalize_device_name(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    let end = s.floor_char_boundary(DEVICE_NAME_MAX_CHARS.min(s.len()));
    Some(s[..end].to_string())
}

// ===========================================================================
// RFC 8414 metadata
// ===========================================================================

#[utoipa::path(
    get,
    path = "/api/v1/cli/oauth/{tenant_slug}/.well-known/oauth-authorization-server",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_authorization_server_metadata",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Authorization server metadata", body = AuthorizationServerMetadata),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
    ),
)]
pub async fn cli_authorization_server_metadata(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
) -> Result<Json<AuthorizationServerMetadata>, ApiError> {
    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    // Token/portal endpoints live on the canonical admin-API origin (the UI
    // origin carries only the browser-facing consent page plus a GET-only
    // passthrough for this discovery document and the binary downloads) —
    // `resolve_oauth_discovery_origins` owns the split-vhost fallback rule.
    let origins =
        crate::tenant_public_url::resolve_oauth_discovery_origins(&state.db, tenant_id)
            .await?;
    let api_origin = origins.api;
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Cli).await?;
    Ok(Json(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        // The consent UI is the SvelteKit `/portal/t/<slug>/cli/authorize`
        // page — under the per-tenant URL prefix so the path-scoped
        // portal_session cookie reaches it after the user authenticates.
        authorization_endpoint: format!(
            "{}/portal/t/{tenant_slug}/cli/authorize",
            origins.admin
        ),
        registration_endpoint: None,
        token_endpoint: format!("{issuer}/token"),
        revocation_endpoint: Some(format!("{issuer}/revoke")),
        device_authorization_endpoint: Some(format!("{issuer}/device_authorization")),
        // No `jwks_uri`: this surface's access tokens are HS256 and are only
        // ever presented back to us, so there is no public key to publish and
        // nothing that could use one.
        jwks_uri: None,
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
            DEVICE_CODE_GRANT_TYPE.to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        scopes_supported: vec![SCOPE_PROVISION.to_string()],
        resource_parameter_supported: false,
        client_id_metadata_document_supported: false,
        api_origin: Some(api_origin),
        authorization_response_iss_parameter_supported: true,
    }))
}

// ===========================================================================
// /authorize (consent backend — called by the SvelteKit consent page)
// ===========================================================================

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CliAuthorizeRequest {
    /// Must be [`CLI_CLIENT_ID`].
    pub client_id: String,
    /// Loopback-only: `http://127.0.0.1[:port]/...` or `http://localhost[:port]/...`.
    pub redirect_uri: String,
    pub state: String,
    /// PKCE — fixed `S256`.
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// Only [`SCOPE_PROVISION`] (the default) is grantable.
    #[serde(default)]
    pub scope: Option<String>,
    /// Self-reported device label ("laptop hostname") shown on the consent
    /// page and stored on the issued tokens.
    #[serde(default)]
    pub device_name: Option<String>,
}

/// Payload returned by `POST /authorize/preview`.
///
/// Two dispositions for the RFC 6749 §4.1.2.1 split — see the MCP surface's
/// twin for why the server, not the consent page, decides which one applies.
#[derive(Serialize, ToSchema)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum CliAuthorizePreviewResponse {
    /// The request validated. Render the "Streamscope CLI on X wants to
    /// provision" copy.
    Ok {
        /// The authenticated portal user the grant would bind to.
        user_email: String,
        device_name: Option<String>,
        scope: String,
    },
    /// The request is invalid, but the client and its loopback redirect URI
    /// check out — so the error belongs at that URI.
    Redirect { redirect_to: String },
}

/// Entry checks shared by every grant's starting endpoint (`/authorize/*`
/// and `/device_authorization`): the one static public client, the one
/// grantable scope.
fn validate_client_and_scope(client_id: &str, scope: Option<&str>) -> Result<(), ApiError> {
    if client_id != CLI_CLIENT_ID {
        return Err(ApiError::not_found("unknown OAuth client", ApiErrorCode::OauthClientNotFound));
    }
    if let Some(scope) = scope
        && scope != SCOPE_PROVISION
    {
        return Err(ApiError::bad_request("only the 'provision' scope is grantable")
            .code(ApiErrorCode::OauthInvalidGrant));
    }
    Ok(())
}

/// Validate an `/authorize` body for the CLI surface.
///
/// **The order of these checks is the RFC 6749 §4.1.2.1 contract** — see
/// [`AuthorizeRejection`]. The client identifier and the redirect URI come
/// first and render on failure; everything after the marked boundary redirects.
/// For this surface the loopback rule *is* the registration check: the CLI is a
/// public native client (RFC 8252) with no stored URI list, so a URI that
/// passes the rule is the only kind we ever vouch for.
fn validate_cli_authorize(body: &CliAuthorizeRequest) -> Result<(), AuthorizeRejection> {
    if body.client_id != CLI_CLIENT_ID {
        return Err(AuthorizeRejection::Render(
            ApiError::not_found("unknown OAuth client", ApiErrorCode::OauthClientNotFound),
        ));
    }
    if !validate_loopback_redirect_uri(&body.redirect_uri) {
        return Err(AuthorizeRejection::Render(
            ApiError::bad_request(
                "redirect_uri must be a loopback URI (http://127.0.0.1[:port]/...)",
            )
            .code(ApiErrorCode::OauthRedirectUriInvalid),
        ));
    }

    // ---- Redirect boundary: the client and its URI are now vouched for. ----

    if let Some(scope) = body.scope.as_deref()
        && scope != SCOPE_PROVISION
    {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidScope,
            "only the 'provision' scope is grantable",
        ));
    }
    if body.code_challenge_method != "S256" {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
        ));
    }
    if body.code_challenge.is_empty() {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidRequest,
            "code_challenge required",
        ));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/authorize/preview",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_authorize_preview",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = CliAuthorizeRequest,
    responses(
        (status = 200, description = "Preview", body = CliAuthorizePreviewResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_authorize_preview(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CliAuthorizeRequest>,
) -> Result<Json<CliAuthorizePreviewResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Cli).await?;
    if let Err(rejection) = validate_cli_authorize(&body) {
        return match rejection {
            AuthorizeRejection::Render(e) => Err(e),
            AuthorizeRejection::Redirect { error, description } => {
                Ok(Json(CliAuthorizePreviewResponse::Redirect {
                    redirect_to: authorization_error_redirect(
                        &body.redirect_uri,
                        error,
                        &description,
                        &body.state,
                        &issuer,
                    ),
                }))
            }
        };
    }
    Ok(Json(CliAuthorizePreviewResponse::Ok {
        user_email: portal.email,
        device_name: normalize_device_name(body.device_name.as_deref()),
        scope: SCOPE_PROVISION.to_string(),
    }))
}

/// The subject refused the grant (RFC 6749 §4.1.2.1 `access_denied`).
///
/// The CLI twin of the MCP surface's deny — see there for why an authorization
/// *response* is built by the authorization server rather than by the page that
/// rendered the button. The device-grant flow on this same surface already had
/// its own `device/deny` endpoint, so this closes the odd one out.
#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/authorize/deny",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_authorize_deny",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = CliAuthorizeRequest,
    responses(
        (status = 200, description = "Where to send the user-agent", body = AuthorizeApproveResponse),
        (status = 400, description = "Parameters did not validate", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_authorize_deny(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CliAuthorizeRequest>,
) -> Result<Json<AuthorizeApproveResponse>, ApiError> {
    let (_portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Cli).await?;

    // Both validation outcomes prove the loopback redirect URI checks out, so
    // both are safe to bounce to; only a `Render` rejection stays on our page.
    if let Err(rejection) = validate_cli_authorize(&body) {
        return match rejection {
            AuthorizeRejection::Render(e) => Err(e),
            AuthorizeRejection::Redirect { error, description } => {
                Ok(Json(AuthorizeApproveResponse {
                    redirect_to: authorization_error_redirect(
                        &body.redirect_uri,
                        error,
                        &description,
                        &body.state,
                        &issuer,
                    ),
                }))
            }
        };
    }

    Ok(Json(AuthorizeApproveResponse {
        redirect_to: authorization_error_redirect(
            &body.redirect_uri,
            OauthErrorCode::AccessDenied,
            "User denied authorization",
            &body.state,
            &issuer,
        ),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/authorize/approve",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_authorize_approve",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = CliAuthorizeRequest,
    responses(
        (status = 200, description = "Approved — redirect to the CLI's loopback listener", body = AuthorizeApproveResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_authorize_approve(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CliAuthorizeRequest>,
) -> Result<Json<AuthorizeApproveResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    // RFC 9207 — see the MCP surface for why this must match the metadata
    // `issuer` byte for byte. Resolved up front because an error redirect has
    // to carry the same `iss` a success would.
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Cli).await?;
    if let Err(rejection) = validate_cli_authorize(&body) {
        return match rejection {
            AuthorizeRejection::Render(e) => Err(e),
            AuthorizeRejection::Redirect { error, description } => {
                Ok(Json(AuthorizeApproveResponse {
                    redirect_to: authorization_error_redirect(
                        &body.redirect_uri,
                        error,
                        &description,
                        &body.state,
                        &issuer,
                    ),
                }))
            }
        };
    }

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli authorize_approve: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    let code = generate_authorization_code();
    let expires_at = Utc::now() + Duration::seconds(AUTH_CODE_TTL_SECS);
    let device_name = normalize_device_name(body.device_name.as_deref());

    sqlx::query(
        r#"INSERT INTO oauth_authorization_codes
               (code, tenant_id, surface, client_id, user_id, device_name,
                code_challenge, redirect_uri, scope, expires_at)
           VALUES ($1, $2, 'cli', $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(&code)
    .bind(tenant_id)
    .bind(CLI_CLIENT_ID)
    .bind(portal.user_id)
    .bind(&device_name)
    .bind(&body.code_challenge)
    .bind(&body.redirect_uri)
    .bind(SCOPE_PROVISION)
    .bind(expires_at)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli authorize_approve: insert code: {e}");
        ApiError::internal("failed to issue authorization code")
    })?;

    let redirect_to = authorization_redirect(
        &body.redirect_uri,
        &[("code", &code), ("state", &body.state)],
        &issuer,
    );
    Ok(Json(AuthorizeApproveResponse { redirect_to }))
}

// ===========================================================================
// Device authorization grant (RFC 8628) — headless `ssai login --device`
// ===========================================================================

#[derive(Deserialize, ToSchema)]
pub struct DeviceAuthorizationRequest {
    /// Must be [`CLI_CLIENT_ID`].
    pub client_id: String,
    /// Only [`SCOPE_PROVISION`] (the default) is grantable.
    #[serde(default)]
    pub scope: Option<String>,
    /// Self-reported device label ("laptop hostname") shown on the approval
    /// page and stored on the issued tokens.
    #[serde(default)]
    pub device_name: Option<String>,
}

/// RFC 8628 §3.2 device-authorization response.
#[derive(Serialize, ToSchema)]
pub struct DeviceAuthorizationResponse {
    /// The device's polling secret — presented to `/token` with the device
    /// grant. Never shown to the user.
    pub device_code: String,
    /// The short code the user types on the approval page.
    pub user_code: String,
    /// The portal approval page (`/portal/t/<slug>/cli/device`).
    pub verification_uri: String,
    /// The approval page with the user code pre-filled.
    pub verification_uri_complete: String,
    /// Seconds until the device code expires.
    pub expires_in: i64,
    /// Minimum seconds the device must wait between `/token` polls.
    pub interval: i32,
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/device_authorization",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_device_authorization",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body(content = DeviceAuthorizationRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Device + user code pair issued", body = DeviceAuthorizationResponse),
        (status = 400, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
        (status = 401, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
    ),
)]
pub async fn cli_device_authorization(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthForm(body): OauthForm<DeviceAuthorizationRequest>,
) -> Result<CredentialReply<DeviceAuthorizationResponse>, OauthError> {
    validate_client_and_scope(&body.client_id, body.scope.as_deref())?;
    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    // The approval page rides the admin (UI) origin — resolving it up front
    // also fails the flow early when no public URL is configured, before a
    // user is sent chasing a verification URI that can't exist.
    let admin_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Admin,
    )
    .await?;

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli device_authorization: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    let device_code = generate_authorization_code();
    let device_name = normalize_device_name(body.device_name.as_deref());
    let expires_at = Utc::now() + Duration::seconds(DEVICE_CODE_TTL_SECS);

    // 20^8 user codes make a same-tenant collision among live rows all but
    // impossible — but "all but" still deserves one retry instead of a 500.
    let mut user_code = generate_user_code();
    for attempt in 0..2 {
        let res = sqlx::query(
            r#"INSERT INTO oauth_device_codes
                   (device_code, tenant_id, user_code, client_id, scope,
                    device_name, poll_interval_secs, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(&device_code)
        .bind(tenant_id)
        .bind(&user_code)
        .bind(CLI_CLIENT_ID)
        .bind(SCOPE_PROVISION)
        .bind(&device_name)
        .bind(DEVICE_POLL_INTERVAL_SECS)
        .bind(expires_at)
        .execute(db.conn())
        .await;
        match res {
            Ok(_) => break,
            Err(sqlx::Error::Database(db_err))
                if db_err.is_unique_violation() && attempt == 0 =>
            {
                user_code = generate_user_code();
            }
            Err(e) => {
                tracing::error!("cli device_authorization: insert: {e}");
                return Err(OauthError::server_error("failed to issue device code"));
            }
        }
    }

    let verification_uri = format!("{admin_origin}/portal/t/{tenant_slug}/cli/device");
    Ok(credential_ok(DeviceAuthorizationResponse {
        device_code,
        verification_uri_complete: format!(
            "{verification_uri}?user_code={}",
            urlencode(&user_code)
        ),
        verification_uri,
        user_code,
        expires_in: DEVICE_CODE_TTL_SECS,
        interval: DEVICE_POLL_INTERVAL_SECS,
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct DeviceConsentRequest {
    /// The code shown on the device — case, the dash, and whitespace are
    /// normalised away.
    pub user_code: String,
}

/// Payload returned by `POST /device/preview` so the approval page can render
/// the "device X wants to provision as you" copy.
#[derive(Serialize, ToSchema)]
pub struct DeviceConsentPreviewResponse {
    /// Canonical `XXXX-XXXX` form of the code — the page submits this.
    pub user_code: String,
    /// The authenticated portal user the grant would bind to.
    pub user_email: String,
    pub device_name: Option<String>,
    pub scope: String,
}

/// Canonicalise the user's typed code or reject it as unparseable. Shared by
/// the preview/approve/deny consent backends.
fn pending_user_code(raw: &str) -> Result<String, ApiError> {
    normalize_user_code(raw).ok_or_else(|| {
        ApiError::bad_request("that doesn't look like a device code — check for typos")
            .code(ApiErrorCode::OauthInvalidGrant)
    })
}

fn invalid_user_code() -> ApiError {
    ApiError::bad_request("unknown, expired, or already-used device code")
        .code(ApiErrorCode::OauthInvalidGrant)
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/device/preview",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_device_preview",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = DeviceConsentRequest,
    responses(
        (status = 200, description = "Preview", body = DeviceConsentPreviewResponse),
        (status = 400, description = "Invalid or unknown user code", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_device_preview(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DeviceConsentRequest>,
) -> Result<Json<DeviceConsentPreviewResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    let user_code = pending_user_code(&body.user_code)?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli device preview: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;
    // `consumed_at` needs no predicate: consume requires `approved`, so a
    // pending row is never consumed. The explicit tenant bind makes the
    // UNIQUE(tenant_id, user_code) index the access path (the RLS GUC
    // predicate alone isn't indexable).
    let row: Option<(Option<String>, String)> = sqlx::query_as(
        r#"SELECT device_name, scope FROM oauth_device_codes
            WHERE tenant_id = $1 AND user_code = $2
              AND status = 'pending' AND expires_at > NOW()"#,
    )
    .bind(tenant_id)
    .bind(&user_code)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli device preview: lookup: {e}");
        ApiError::internal("failed to look up device code")
    })?;
    let Some((device_name, scope)) = row else {
        return Err(invalid_user_code());
    };
    Ok(Json(DeviceConsentPreviewResponse {
        user_code,
        user_email: portal.email,
        device_name,
        scope,
    }))
}

/// Shared by approve/deny: flip a live pending row to the decided status.
/// `approved_user_id` is set if and only if approving (the table CHECK pins
/// that pairing).
async fn decide_device_code(
    state: &Arc<AdminState>,
    tenant_slug: &str,
    headers: &axum::http::HeaderMap,
    raw_user_code: &str,
    approve: bool,
) -> Result<Json<ActionResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, tenant_slug, headers).await?;
    let user_code = pending_user_code(raw_user_code)?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli device decide: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;
    let (status, approved_user_id) = if approve {
        ("approved", Some(portal.user_id))
    } else {
        ("denied", None)
    };
    // Tenant bind → indexed via UNIQUE(tenant_id, user_code), same as preview.
    let updated: Option<(String,)> = sqlx::query_as(
        r#"UPDATE oauth_device_codes
              SET status = $1, approved_user_id = $2
            WHERE tenant_id = $3 AND user_code = $4
              AND status = 'pending' AND expires_at > NOW()
            RETURNING device_code"#,
    )
    .bind(status)
    .bind(approved_user_id)
    .bind(tenant_id)
    .bind(&user_code)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli device decide: update: {e}");
        ApiError::internal("failed to record the decision")
    })?;
    if updated.is_none() {
        return Err(invalid_user_code());
    }
    let message = if approve {
        "device approved — it signs in within a few seconds"
    } else {
        "device denied"
    };
    Ok(Json(ActionResponse::ok().with_message(message)))
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/device/approve",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_device_approve",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = DeviceConsentRequest,
    responses(
        (status = 200, description = "Approved — the device's next poll mints its tokens", body = ActionResponse),
        (status = 400, description = "Invalid or unknown user code", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_device_approve(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DeviceConsentRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    decide_device_code(&state, &tenant_slug, &headers, &body.user_code, true).await
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/device/deny",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_device_deny",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = DeviceConsentRequest,
    responses(
        (status = 200, description = "Denied — the device's next poll reports access_denied", body = ActionResponse),
        (status = 400, description = "Invalid or unknown user code", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cli_device_deny(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<DeviceConsentRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    decide_device_code(&state, &tenant_slug, &headers, &body.user_code, false).await
}

// ===========================================================================
// /token (PKCE code exchange + rotating refresh)
// ===========================================================================

/// CLI refresh-token claims. Signed with the same per-tenant key as the
/// access token; `typ = "refresh"` keeps the roles apart, and the `jti` row
/// in `oauth_issued_tokens` makes rotation single-use.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CliRefreshClaims {
    pub sub: String,
    pub email: String,
    pub iss: String,
    /// The tenant this token belongs to. Doubles as its audience: unlike the
    /// MCP surface, a CLI token names no per-resource audience.
    pub aud: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
    pub typ: String,
    /// JTI of the access token this refresh was paired with — revoked
    /// together by `/revoke` so logout kills the live pair at once.
    pub original_jti: String,
    #[serde(default)]
    pub device_name: Option<String>,
    pub surface: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

impl super::oauth_common::RefreshClaims for CliRefreshClaims {
    fn surface(&self) -> &str {
        &self.surface
    }
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/token",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_token",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Issued access + refresh token pair", body = TokenResponse),
        (status = 400, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
        (status = 401, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
    ),
)]
pub async fn cli_token_endpoint(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthForm(body): OauthForm<TokenRequest>,
) -> Result<TokenReply, OauthError> {
    let Json(token) = match body.grant_type.as_str() {
        "authorization_code" => cli_token_authorization_code(state, tenant_slug, body).await?,
        "refresh_token" => cli_token_refresh(state, tenant_slug, body).await?,
        DEVICE_CODE_GRANT_TYPE => cli_token_device_code(state, tenant_slug, body).await?,
        other => {
            return Err(OauthError::unsupported_grant_type(format!(
                "unsupported grant_type `{other}`"
            )))
        }
    };
    Ok(token_ok(token))
}

/// RFC 8628 §3.4-3.5 device grant: the device polls with its `device_code`
/// until the user decides on the approval page. No PKCE — the device code
/// itself is the secret, held only by the polling device and carried only
/// over TLS.
async fn cli_token_device_code(
    state: Arc<AdminState>,
    tenant_slug: String,
    body: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let device_code = body.device_code.ok_or_else(|| {
        ApiError::bad_request("device_code grant requires `device_code`")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    if body.client_id != CLI_CLIENT_ID {
        return Err(ApiError::bad_request("client_id mismatch")
            .code(ApiErrorCode::OauthInvalidGrant));
    }
    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli device token: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    // Read the row's state with the expiry and rate-limit checks computed in
    // SQL — one clock (the database's), so admin-api/Postgres skew can't feed
    // a well-behaved client spurious `slow_down`s.
    #[derive(sqlx::FromRow)]
    struct DeviceRow {
        status: String,
        device_name: Option<String>,
        expired: bool,
        too_fast: bool,
        consumed: bool,
    }
    let row: Option<DeviceRow> = sqlx::query_as(
        r#"SELECT status, device_name,
                  expires_at <= NOW() AS expired,
                  (last_polled_at IS NOT NULL
                   AND last_polled_at > NOW() - make_interval(secs => poll_interval_secs))
                      AS too_fast,
                  consumed_at IS NOT NULL AS consumed
             FROM oauth_device_codes
            WHERE device_code = $1 AND tenant_id = $2"#,
    )
    .bind(&device_code)
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli device token: poll: {e}");
        ApiError::internal("failed to look up device code")
    })?;
    let Some(row) = row else {
        return Err(ApiError::bad_request("invalid device code")
            .code(ApiErrorCode::OauthInvalidGrant));
    };
    if row.consumed {
        return Err(ApiError::bad_request("device code already used")
            .code(ApiErrorCode::OauthInvalidGrant));
    }
    if row.expired {
        return Err(ApiError::bad_request(
            "device code expired — run `ssai login` again",
        )
        .code(ApiErrorCode::OauthExpiredToken));
    }
    if row.status == "denied" {
        return Err(ApiError::bad_request("the user denied the authorization request")
            .code(ApiErrorCode::OauthAccessDenied));
    }
    if row.status == "pending" {
        // Stamp the poll only on live pending rows — terminal-state polls
        // stay read-only (no dead tuples from a stuck client re-polling a
        // decided code). Two racing polls may both read the same previous
        // stamp and both get `pending`; the only cost is one missed
        // `slow_down` hint against a device racing itself.
        let _ = sqlx::query(
            "UPDATE oauth_device_codes SET last_polled_at = NOW() WHERE device_code = $1",
        )
        .bind(&device_code)
        .execute(db.conn())
        .await
        .map_err(|e| tracing::warn!("cli device token: stamp poll: {e}"));
        if row.too_fast {
            return Err(ApiError::bad_request(
                "polling too fast — add 5 seconds to the polling interval",
            )
            .code(ApiErrorCode::OauthSlowDown));
        }
        return Err(ApiError::bad_request("authorization pending — keep polling")
            .code(ApiErrorCode::OauthAuthorizationPending));
    }

    // Single-use consume: of two racing polls on a just-approved code, only
    // the one that lands this UPDATE mints tokens. The status predicate keeps
    // the row's CHECK honest — `approved` guarantees a non-null
    // `approved_user_id`, so the tuple decode below can't hit NULL.
    let consumed: Option<(Uuid,)> = sqlx::query_as(
        r#"UPDATE oauth_device_codes
              SET consumed_at = NOW()
            WHERE device_code = $1 AND status = 'approved' AND consumed_at IS NULL
            RETURNING approved_user_id"#,
    )
    .bind(&device_code)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli device token: consume: {e}");
        ApiError::internal("failed to consume device code")
    })?;
    let Some((user_id,)) = consumed else {
        return Err(ApiError::bad_request("device code already used")
            .code(ApiErrorCode::OauthInvalidGrant));
    };

    let email = require_active_user(db.conn(), user_id).await?;
    let pair = mint_cli_token_pair(
        db.conn(),
        tenant_id,
        user_id,
        &email,
        row.device_name.as_deref(),
        // A fresh login is a new machine as far as revocation is concerned.
        Uuid::new_v4(),
    )
    .await?;
    Ok(Json(pair))
}

async fn cli_token_authorization_code(
    state: Arc<AdminState>,
    tenant_slug: String,
    body: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let code = body.code.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `code`")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    let body_redirect_uri = body.redirect_uri.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `redirect_uri`")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    let code_verifier = body.code_verifier.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `code_verifier`")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    if body.client_id != CLI_CLIENT_ID {
        return Err(ApiError::bad_request("client_id mismatch")
            .code(ApiErrorCode::OauthInvalidGrant));
    }
    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli token: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    // Atomically consume the code (same race-safety pattern as the MCP path).
    #[derive(sqlx::FromRow)]
    struct CliCodeRow {
        client_id: String,
        user_id: Uuid,
        device_name: Option<String>,
        code_challenge: String,
        redirect_uri: String,
    }
    let row: Option<CliCodeRow> = sqlx::query_as(
        r#"UPDATE oauth_authorization_codes
              SET consumed_at = NOW()
            WHERE code = $1
              AND surface = 'cli'
              AND consumed_at IS NULL
              AND expires_at > NOW()
            RETURNING client_id, user_id, device_name, code_challenge, redirect_uri"#,
    )
    .bind(&code)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli token: consume code: {e}");
        ApiError::internal("failed to consume authorization code")
    })?;
    let Some(row) = row else {
        return Err(
            ApiError::bad_request("invalid, expired, or already-used authorization code")
                .code(ApiErrorCode::OauthInvalidGrant),
        );
    };
    if row.client_id != body.client_id {
        return Err(ApiError::bad_request("client_id mismatch")
            .code(ApiErrorCode::OauthInvalidGrant));
    }
    if row.redirect_uri != body_redirect_uri {
        return Err(ApiError::bad_request("redirect_uri mismatch")
            .code(ApiErrorCode::OauthRedirectUriMismatch));
    }
    if !verify_s256_challenge(&code_verifier, &row.code_challenge) {
        return Err(ApiError::bad_request("PKCE verification failed")
            .code(ApiErrorCode::OauthInvalidVerifier));
    }

    let email = require_active_user(db.conn(), row.user_id).await?;
    let pair = mint_cli_token_pair(
        db.conn(),
        tenant_id,
        row.user_id,
        &email,
        row.device_name.as_deref(),
        // A fresh login is a new machine as far as revocation is concerned.
        Uuid::new_v4(),
    )
    .await?;
    Ok(Json(pair))
}

/// Refresh-token grant: validate the presented refresh JWT, atomically revoke
/// its `jti` (single-use), then issue a fresh access + refresh pair.
async fn cli_token_refresh(
    state: Arc<AdminState>,
    tenant_slug: String,
    body: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let presented = body.refresh_token.ok_or_else(|| {
        ApiError::bad_request("refresh_token grant requires `refresh_token`")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    let ring = keyring().ok_or_else(|| {
        tracing::error!("cli token: AUTH_SECRET unavailable");
        crate::routes::no_signing_key()
    })?;
    let claims = decode_cli_refresh_claims(&presented, &ring).map_err(|_| {
        ApiError::bad_request("invalid or expired refresh token")
            .code(ApiErrorCode::OauthInvalidGrant)
    })?;
    if claims.typ != REFRESH_TOKEN_TYP
        || claims.client_id != CLI_CLIENT_ID
        || body.client_id != CLI_CLIENT_ID
    {
        return Err(ApiError::bad_request("not a CLI refresh token")
            .code(ApiErrorCode::OauthInvalidGrant));
    }

    let url_tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    let token_tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| {
        ApiError::bad_request("invalid refresh token").code(ApiErrorCode::OauthInvalidGrant)
    })?;
    if token_tenant_id != url_tenant_id {
        return Err(
            ApiError::bad_request("refresh token does not belong to this tenant")
                .code(ApiErrorCode::OauthInvalidGrant),
        );
    }
    let mut db = TenantConn::acquire(&state.db, TenantId::from_credential(token_tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("cli refresh: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    let presented_jti = Uuid::parse_str(&claims.jti).map_err(|_| {
        ApiError::bad_request("invalid refresh token").code(ApiErrorCode::OauthInvalidGrant)
    })?;
    // Rotation and an operator revoke both rewrite this chain, and they MUST NOT
    // interleave. A rotation is retire-then-mint; a revoke is "retire everything
    // live". Run them concurrently and the revoke can land in the gap — retiring
    // only rows the rotation had already retired, while the pair the rotation is
    // about to insert is invisible to it. The revoke would answer 200 having
    // freed nothing, and the device would walk away with a working credential:
    // the exact outcome this endpoint exists to prevent. Serialize per chain.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("cli refresh: begin: {e}");
        ApiError::internal("failed to rotate refresh token")
    })?;

    // The chain is only recorded on the row, so it has to be read before it can
    // be locked. Nothing is decided here — the authoritative check is the UPDATE
    // below, which runs while holding the lock.
    //
    // `login_chain` is read back NOT-NULL because the column is: every row on
    // every surface belongs to a chain. Quietly starting a new one here would
    // leave the device's earlier rows unreachable from a revoke, which is
    // precisely the bug the chain exists to prevent.
    let chain_row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT login_chain FROM oauth_issued_tokens WHERE jti = $1 AND surface = 'cli'",
    )
    .bind(presented_jti)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("cli refresh: resolve chain: {e}");
        ApiError::internal("failed to rotate refresh token")
    })?;
    let Some((login_chain,)) = chain_row else {
        return Err(
            ApiError::bad_request("refresh token revoked, expired, or not recognised")
                .code(ApiErrorCode::OauthInvalidGrant),
        );
    };
    lock_login_chain(&mut tx, login_chain, "cli refresh").await?;

    // Authoritative, and now race-free: an operator revoke that committed while
    // we waited for the lock leaves nothing here to rotate.
    let revoke_row: Option<(Uuid, Option<String>)> = sqlx::query_as(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW()
            WHERE jti = $1
              AND surface = 'cli'
              AND revoked_at IS NULL
              AND expires_at > NOW()
            RETURNING user_id, device_name"#,
    )
    .bind(presented_jti)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("cli refresh: revoke old jti: {e}");
        ApiError::internal("failed to revoke refresh token")
    })?;
    let Some((user_id, device_name)) = revoke_row else {
        // RFC 9700 §4.14.2. The row exists — the SELECT above found its chain —
        // so this is not an unknown token. Either it expired, or it already
        // rotated and a second holder is presenting it. Only the latter is
        // evidence of theft, and only the latter costs the device its chain.
        retire_chain_on_reuse(&mut tx, token_tenant_id, presented_jti, SURFACE_CLI).await?;
        // Commit before returning the error. The retirement is a write inside
        // this transaction, and returning `Err` drops the transaction — which
        // rolls it back. The replay would be refused and the lineage left alive,
        // which is precisely the half-measure the retirement exists to avoid.
        tx.commit().await.map_err(|e| {
            tracing::error!("cli refresh: commit reuse retirement: {e}");
            ApiError::internal("failed to revoke refresh token")
        })?;
        return Err(
            ApiError::bad_request("refresh token revoked, expired, or not recognised")
                .code(ApiErrorCode::OauthInvalidGrant),
        );
    };

    // Retire the paired access token alongside the rotated refresh — without
    // this, every rotation would leave the previous access jti live for the
    // rest of its 1h TTL, and `logout` (which kills only the CURRENT pair)
    // could never catch up with older generations. Propagated, not warned: a
    // failed statement has already aborted the transaction, so swallowing it
    // would let the commit below roll back while reporting success.
    if let Ok(original_jti) = Uuid::parse_str(&claims.original_jti) {
        sqlx::query(
            r#"UPDATE oauth_issued_tokens
                  SET revoked_at = NOW()
                WHERE jti = $1 AND surface = 'cli' AND revoked_at IS NULL"#,
        )
        .bind(original_jti)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("cli refresh: retire paired access jti: {e}");
            ApiError::internal("failed to rotate refresh token")
        })?;
    }

    let email = require_active_user(&mut tx, user_id).await?;
    let pair = mint_cli_token_pair(
        &mut tx,
        token_tenant_id,
        user_id,
        &email,
        device_name.as_deref(),
        // A rotation is the SAME machine — carry its chain so an operator
        // revoking that device still reaches the pair minted here.
        login_chain,
    )
    .await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("cli refresh: commit: {e}");
        ApiError::internal("failed to rotate refresh token")
    })?;
    Ok(Json(pair))
}

/// Take the per-chain lock that makes a rotation and an operator revoke
/// mutually exclusive. Transaction-scoped, so it releases on commit or rollback
/// with nothing to remember to unlock.
///
/// Both writers MUST take it, and both MUST re-read the rows they act on
/// afterwards — the lock orders them, it does not make a stale read fresh.
async fn lock_login_chain(
    tx: &mut crate::db::tenant::TenantTx<'_>,
    login_chain: Uuid,
    context: &str,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 0))")
        .bind(login_chain)
        .execute(&mut **tx)
        .await
        .map_err(|e| {
            tracing::error!("{context}: lock login chain: {e}");
            ApiError::internal("failed to lock the CLI session")
        })?;
    Ok(())
}

/// Re-check the subject still exists and is active before minting — a
/// disabled or deleted user's CLI must die at the next exchange, not at
/// refresh-token expiry.
async fn require_active_user(
    conn: &mut Scoped,
    user_id: Uuid,
) -> Result<String, ApiError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT email, is_active FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("cli token: user lookup: {e}");
                ApiError::internal("failed to resolve user")
            })?;
    match row {
        Some((email, true)) => Ok(email),
        _ => Err(ApiError::forbidden("account disabled")
            .code(ApiErrorCode::PermissionDenied)),
    }
}

/// Mint a provision-scoped access token (a [`PortalClaims`] JWT with a
/// revocable `jti`) plus its rotating refresh token, persisting both jtis as
/// `surface = 'cli'` rows on `login_chain`.
///
/// **A fresh login passes a new chain id; a rotation passes the chain of the
/// token it is rotating** — that continuity is what makes a device revocable as
/// one thing, so a new call site must decide deliberately which it is.
async fn mint_cli_token_pair(
    conn: &mut Scoped,
    tenant_id: Uuid,
    user_id: Uuid,
    email: &str,
    device_name: Option<&str>,
    login_chain: Uuid,
) -> Result<TokenResponse, ApiError> {
    let ring = keyring().ok_or_else(|| {
        tracing::error!("cli token: AUTH_SECRET unavailable");
        crate::routes::no_signing_key()
    })?;
    let now = Utc::now();
    let access_expires = now + Duration::seconds(ACCESS_TOKEN_TTL_SECS);
    let access_jti = new_jti();
    let access_claims = PortalClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: "user".to_string(),
        tenant_id: tenant_id.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: tenant_id.to_string(),
        scope: SCOPE_PROVISION.to_string(),
        jti: Some(access_jti.clone()),
        iat: now.timestamp() as usize,
        nbf: now.timestamp() as usize,
        exp: access_expires.timestamp() as usize,
    };
    let (header, signing_key) = ring.signing_header(&access_claims.tenant_id);
    let access_token = jsonwebtoken::encode(
        &header,
        &access_claims,
        &jsonwebtoken::EncodingKey::from_secret(&signing_key),
    )
    .map_err(|e| {
        tracing::error!("cli token: encode access: {e}");
        ApiError::internal("failed to issue token")
    })?;

    let refresh_jti = new_jti();
    let refresh_expires = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);
    let refresh_claims = CliRefreshClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: tenant_id.to_string(),
        tenant_id: tenant_id.to_string(),
        client_id: CLI_CLIENT_ID.to_string(),
        scope: SCOPE_PROVISION.to_string(),
        jti: refresh_jti.clone(),
        typ: REFRESH_TOKEN_TYP.to_string(),
        original_jti: access_jti.clone(),
        device_name: device_name.map(str::to_string),
        surface: SURFACE_CLI.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: refresh_expires.timestamp(),
    };
    let refresh_token = encode_cli_refresh_claims(&refresh_claims, &ring).map_err(|e| {
        tracing::error!("cli token: encode refresh: {e}");
        ApiError::internal("failed to issue refresh token")
    })?;

    // Persist both jtis (one statement — the pair is issued atomically).
    let access_jti_uuid = Uuid::parse_str(&access_jti).map_err(|e| {
        tracing::error!("cli token: parse access jti: {e}");
        ApiError::internal("internal error")
    })?;
    let refresh_jti_uuid = Uuid::parse_str(&refresh_jti).map_err(|e| {
        tracing::error!("cli token: parse refresh jti: {e}");
        ApiError::internal("internal error")
    })?;
    sqlx::query(
        r#"INSERT INTO oauth_issued_tokens
               (jti, tenant_id, surface, user_id, client_id, device_name, scope, expires_at, login_chain)
           VALUES ($1, $3, 'cli', $4, $5, $6, $7, $8, $10),
                  ($2, $3, 'cli', $4, $5, $6, $7, $9, $10)"#,
    )
    .bind(access_jti_uuid)
    .bind(refresh_jti_uuid)
    .bind(tenant_id)
    .bind(user_id)
    .bind(CLI_CLIENT_ID)
    .bind(device_name)
    .bind(SCOPE_PROVISION)
    .bind(access_expires)
    .bind(refresh_expires)
    .bind(login_chain)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("cli token: persist jtis: {e}");
        ApiError::internal("failed to record issued tokens")
    })?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope: SCOPE_PROVISION.to_string(),
        refresh_token,
        refresh_token_expires_in: REFRESH_TOKEN_TTL_SECS,
    })
}

fn encode_cli_refresh_claims(
    claims: &CliRefreshClaims,
    ring: &Keyring,
) -> Result<String, jsonwebtoken::errors::Error> {
    encode_refresh_jwt(claims, &claims.tenant_id, ring)
}

fn decode_cli_refresh_claims(
    token: &str,
    ring: &Keyring,
) -> Result<CliRefreshClaims, jsonwebtoken::errors::Error> {
    decode_refresh_jwt(token, ring, SURFACE_CLI)
}

// ===========================================================================
// /revoke (RFC 7009 — backs `ssai logout`)
// ===========================================================================

#[derive(Deserialize, ToSchema)]
pub struct CliRevokeRequest {
    /// The refresh token to revoke. Its paired access token (`original_jti`)
    /// is revoked with it.
    pub token: String,
}

/// RFC 7009 §2.2: revocation answers 200 even for an invalid or already
/// revoked token — the caller's goal ("this token must not work") is met
/// either way, and a distinct error would let an attacker probe token
/// validity.
#[utoipa::path(
    post,
    path = "/api/v1/cli/oauth/{tenant_slug}/revoke",
    tag = "CLI OAuth",
    operation_id = "cli_oauth_revoke",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body(content = CliRevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revoked (idempotent)", body = ActionResponse),
    ),
)]
pub async fn cli_revoke_endpoint(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthForm(body): OauthForm<CliRevokeRequest>,
) -> Result<Json<ActionResponse>, OauthError> {
    let done = Ok(Json(ActionResponse::ok().with_message("token revoked")));

    let Some(ring) = keyring() else {
        return Err(OauthError::server_error("authentication not configured"));
    };
    let Ok(claims) = decode_cli_refresh_claims(&body.token, &ring) else {
        return done;
    };
    if claims.typ != REFRESH_TOKEN_TYP || claims.client_id != CLI_CLIENT_ID {
        return done;
    }
    let Ok(url_tenant_id) = resolve_tenant_id(&state.db, &tenant_slug).await else {
        return done;
    };
    let Ok(token_tenant_id) = Uuid::parse_str(&claims.tenant_id) else {
        return done;
    };
    if token_tenant_id != url_tenant_id {
        return done;
    }
    let (Ok(jti), Ok(original_jti)) = (
        Uuid::parse_str(&claims.jti),
        Uuid::parse_str(&claims.original_jti),
    ) else {
        return done;
    };
    let Ok(mut db) = TenantConn::acquire(&state.db, TenantId::from_credential(token_tenant_id)).await else {
        tracing::error!("cli revoke: failed to acquire tenant connection");
        return Err(OauthError::server_error("failed to revoke token"));
    };
    sqlx::query(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW()
            WHERE jti IN ($1, $2)
              AND surface = 'cli'
              AND revoked_at IS NULL"#,
    )
    .bind(jti)
    .bind(original_jti)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("cli revoke: {e}");
        ApiError::internal("failed to revoke token")
    })?;
    done
}

// ---------------------------------------------------------------------------
// Admin surface — CLI device sessions
// ---------------------------------------------------------------------------
//
// A `ssai login` mints one long-lived credential per machine. Revoking a
// single lost device needs the operator to be able to SEE it first: the
// MCP-shaped issued-tokens view deliberately excludes `surface = 'cli'` rows
// (they carry no virtual server or audience to render), so without this surface
// the only lever is disabling the whole user account.

/// One `ssai login` — the machine, not the token.
///
/// A login is a **chain** of token rows: each pair is access + refresh, and
/// every refresh rotation retires the pair and mints another onto the same
/// chain. This row aggregates one chain, which is why its id is the chain and
/// not a jti — the operator revokes a machine, and the tokens are an
/// implementation detail of how that machine holds its access.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct CliSessionRow {
    /// The login chain. Also the revoke handle.
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_display_name: Option<String>,
    /// Self-reported by the CLI at login (device-grant logins name the host).
    /// Absent for a login that reported none — never treat it as an identifier.
    pub device_name: Option<String>,
    pub scope: String,
    /// When the machine signed in, from the oldest generation still on record.
    /// The sweeper eventually purges long-expired generations, so on a chain
    /// older than the retention window this walks forward rather than pinning
    /// the original login.
    pub signed_in_at: chrono::DateTime<Utc>,
    /// How long the machine can keep refreshing before it must sign in again.
    pub expires_at: chrono::DateTime<Utc>,
    /// When the machine was deliberately cut off — by an operator here, or by
    /// its own `ssai logout`. Read from the chain's NEWEST generation,
    /// never from "some row is revoked": rotation revokes the generation it
    /// replaces, so the latter would report every rotated-then-expired chain as
    /// revoked, stamped with the time of a rotation.
    pub revoked_at: Option<chrono::DateTime<Utc>>,
    /// When the machine last called, across the whole chain — a rotation mints
    /// a new generation, but the last call belongs to the machine rather than
    /// to whichever generation was holding its access at the time.
    ///
    /// `None` means it has not called yet. It is stamped at
    /// roughly one write a minute, so read it as "active around then", never
    /// as an exact last-request time.
    pub last_used_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CliSessionListQuery {
    /// Restrict to one user's devices.
    pub user_id: Option<Uuid>,
    /// Lifecycle filter. Defaults to `active`.
    pub status: Option<super::mcp_oauth::TokenStatusFilter>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/cli/sessions",
    tag = "CLI",
    params(CliSessionListQuery),
    responses(
        (status = 200, description = "CLI device sessions (paginated)", body = OffsetPage<CliSessionRow>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_cli_sessions(
    mut db: TenantConn,
    axum::extract::Query(query): axum::extract::Query<CliSessionListQuery>,
) -> Result<Json<OffsetPage<CliSessionRow>>, ApiError> {
    use super::mcp_oauth::TokenStatusFilter;

    let (limit, offset) = PageQuery {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve();

    // Every fragment spliced here is a compile-time literal; the user filter and
    // the page bounds are bound. The optional filter rides a nullable bind
    // rather than a conditional clause so the statement stays one constant.
    //
    // Status is a property of the CHAIN, and specifically of its NEWEST
    // generation — never of "does any row carry a revoked_at". Rotation stamps
    // `revoked_at` on the pair it replaces, so a chain that rotated normally and
    // then simply expired is full of revoked rows while nobody ever revoked it;
    // counting those would report a revocation that did not happen, at the
    // timestamp of a rotation. The newest generation tells the three cases
    // apart cleanly: rotation always leaves it unrevoked, a deliberate revoke
    // (operator or `ssai logout`) always kills it, and natural expiry
    // leaves it unrevoked but past `expires_at`.
    //
    // Picking that generation needs a TOTAL order. A rotation inserts both of a
    // generation's rows in one statement, so they share `issued_at`, and
    // `expires_at` separates them (refresh outlives access) — but neither alone
    // is total, and `ARRAY_AGG` over a tie returns an arbitrary row, which makes
    // the status non-deterministic rather than merely imprecise. `jti` breaks any
    // remaining tie so the same chain always classifies the same way.
    const NEWEST_FIRST: &str = "ORDER BY t.issued_at DESC, t.expires_at DESC, t.jti DESC";
    let newest_revoked_at = format!("(ARRAY_AGG(t.revoked_at {NEWEST_FIRST}))[1]");
    let status_predicate = match query.status.unwrap_or_default() {
        TokenStatusFilter::Active => {
            " HAVING (ARRAY_AGG(t.revoked_at ORDER BY t.issued_at DESC, t.expires_at DESC, t.jti DESC))[1] IS NULL \
                 AND MAX(t.expires_at) > NOW()"
        }
        TokenStatusFilter::Revoked => {
            " HAVING (ARRAY_AGG(t.revoked_at ORDER BY t.issued_at DESC, t.expires_at DESC, t.jti DESC))[1] IS NOT NULL"
        }
        TokenStatusFilter::Expired => {
            " HAVING (ARRAY_AGG(t.revoked_at ORDER BY t.issued_at DESC, t.expires_at DESC, t.jti DESC))[1] IS NULL \
                 AND MAX(t.expires_at) <= NOW()"
        }
        TokenStatusFilter::All => "",
    };

    let rows = sqlx::query_as::<_, CliSessionRow>(sqlx::AssertSqlSafe(&*format!(
        "SELECT t.login_chain AS id, \
                t.user_id, \
                u.email AS user_email, \
                u.display_name AS user_display_name, \
                MAX(t.device_name) AS device_name, \
                MAX(t.scope) AS scope, \
                MIN(t.issued_at) AS signed_in_at, \
                MAX(t.expires_at) AS expires_at, \
                {newest_revoked_at} AS revoked_at, \
                MAX(t.last_used_at) AS last_used_at \
         FROM oauth_issued_tokens t \
         JOIN users u ON u.id = t.user_id \
         WHERE t.surface = 'cli' \
           AND ($3::uuid IS NULL OR t.user_id = $3) \
         GROUP BY t.login_chain, t.user_id, u.email, u.display_name{status_predicate} \
         ORDER BY MIN(t.issued_at) DESC \
         LIMIT $1 OFFSET $2"
    )))
    .bind(limit + 1)
    .bind(offset)
    .bind(query.user_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list cli sessions: {e}");
        ApiError::internal("failed to list CLI sessions")
    })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/cli/sessions/{id}/actions/revoke",
    tag = "CLI",
    params(("id" = Uuid, Path, description = "Login chain of the CLI session")),
    responses(
        (status = 200, description = "Session revoked", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "No live CLI session with this id", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_cli_session(
    axum::Extension(ctx): axum::Extension<crate::db::tenant::AdminTenantCtx>,
    axum::Extension(diff): axum::Extension<crate::middleware::audit_common::AuditDiffSink>,
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Retire the WHOLE chain, not one token. Killing only the access row leaves
    // the refresh token free to mint a replacement pair on the device's next
    // rotation — the device comes back, and the revoke reads as a no-op.
    // Killing only the refresh row leaves the access token working until it
    // expires. Both rows of every generation must go.
    //
    // Under the same per-chain lock the rotation takes, so a rotation in flight
    // cannot slip a freshly minted pair past this UPDATE's snapshot and hand the
    // device a live credential after we have reported it revoked.
    //
    // No config body involved: `portal_auth` re-reads these rows on every provisioning
    // request, so this lands on the device's next call.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("revoke cli session: begin: {e}");
        ApiError::internal("failed to revoke the CLI session")
    })?;
    lock_login_chain(&mut tx, id, "revoke cli session").await?;
    let result = sqlx::query(
        "UPDATE oauth_issued_tokens \
            SET revoked_at = NOW(), revoked_by_user_id = $2 \
          WHERE login_chain = $1 AND surface = 'cli' AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(ctx.admin_account_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("revoke cli session: {e}");
        ApiError::internal("failed to revoke the CLI session")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("no live CLI session with this id", ApiErrorCode::CliSessionNotFound));
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("revoke cli session: commit: {e}");
        ApiError::internal("failed to revoke the CLI session")
    })?;
    // A summary rather than the generic single-row snapshot: the generic path
    // maps a route to one `(table, id_col)` row, and a chain is many rows, so it
    // would capture an arbitrary one of them and read as if that were the whole
    // change.
    diff.set(
        serde_json::json!({ "login_chain": id, "live_tokens": result.rows_affected() }),
        serde_json::json!({ "login_chain": id, "live_tokens": 0 }),
    );
    Ok(Json(ActionResponse::ok().with_message("CLI session revoked")))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn authorize_body() -> CliAuthorizeRequest {
        CliAuthorizeRequest {
            client_id: CLI_CLIENT_ID.to_string(),
            redirect_uri: "http://127.0.0.1:8731/callback".to_string(),
            state: "st".to_string(),
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            code_challenge_method: "S256".to_string(),
            scope: None,
            device_name: None,
        }
    }

    #[test]
    fn a_well_formed_authorize_request_passes() {
        assert!(validate_cli_authorize(&authorize_body()).is_ok());
    }

    /// RFC 6749 §4.1.2.1: an unidentifiable client or an unvouched-for
    /// redirect URI must be shown to the user, never bounced to. Redirecting
    /// either of these would make the consent page an open redirect that an
    /// attacker reaches by naming any URI they like.
    #[test]
    fn an_unidentified_client_or_uri_renders_rather_than_redirecting() {
        let mut unknown_client = authorize_body();
        unknown_client.client_id = "somebody-elses-client".to_string();
        assert_matches!(
            validate_cli_authorize(&unknown_client),
            Err(AuthorizeRejection::Render(_))
        );

        for bad_uri in [
            "https://attacker.example/cb",
            "http://localhost.attacker.example/cb",
            "http://127.0.0.1.evil.example/cb",
        ] {
            let mut body = authorize_body();
            body.redirect_uri = bad_uri.to_string();
            assert_matches!(
                validate_cli_authorize(&body),
                Err(AuthorizeRejection::Render(_)),
                "{bad_uri} must not be redirected to"
            );
        }
    }

    /// The other half of §4.1.2.1: once the client and its URI check out, the
    /// error belongs at that URI. Rendering these instead leaves a conforming
    /// client waiting on a callback that never arrives.
    #[test]
    fn a_vouched_for_client_gets_its_errors_by_redirect() {
        let mut bad_method = authorize_body();
        bad_method.code_challenge_method = "plain".to_string();
        assert_matches!(
            validate_cli_authorize(&bad_method),
            Err(AuthorizeRejection::Redirect { error: OauthErrorCode::InvalidRequest, .. })
        );

        let mut no_challenge = authorize_body();
        no_challenge.code_challenge = String::new();
        assert_matches!(
            validate_cli_authorize(&no_challenge),
            Err(AuthorizeRejection::Redirect { error: OauthErrorCode::InvalidRequest, .. })
        );

        let mut bad_scope = authorize_body();
        bad_scope.scope = Some("admin".to_string());
        assert_matches!(
            validate_cli_authorize(&bad_scope),
            Err(AuthorizeRejection::Redirect { error: OauthErrorCode::InvalidScope, .. })
        );
    }

    /// The boundary is an *ordering* property, so it only holds if the
    /// identity checks run first. A body that is wrong on both sides of the
    /// line must still render — otherwise an attacker pairs an unregistered
    /// redirect URI with a deliberately broken challenge and gets bounced
    /// anywhere they like.
    #[test]
    fn an_unvouched_uri_wins_over_a_later_redirectable_error() {
        let mut body = authorize_body();
        body.redirect_uri = "https://attacker.example/cb".to_string();
        body.code_challenge_method = "plain".to_string();
        body.scope = Some("admin".to_string());
        assert_matches!(
            validate_cli_authorize(&body),
            Err(AuthorizeRejection::Render(_))
        );
    }

    #[test]
    fn user_codes_are_canonical_and_normalizable() {
        for _ in 0..50 {
            let code = generate_user_code();
            assert_eq!(code.len(), 9);
            assert_eq!(code.as_bytes()[4], b'-');
            assert!(code
                .bytes()
                .all(|b| b == b'-' || USER_CODE_ALPHABET.contains(&b)));
            // A generated code round-trips normalization unchanged.
            assert_eq!(normalize_user_code(&code).as_deref(), Some(code.as_str()));
        }
    }

    #[test]
    fn normalization_forgives_case_dash_and_whitespace() {
        assert_eq!(
            normalize_user_code(" bcdf-ghjk ").as_deref(),
            Some("BCDF-GHJK")
        );
        assert_eq!(normalize_user_code("bcdfghjk").as_deref(), Some("BCDF-GHJK"));
        assert_eq!(
            normalize_user_code("BC DF GH JK").as_deref(),
            Some("BCDF-GHJK")
        );
    }

    #[test]
    fn normalization_rejects_wrong_length_and_charset() {
        assert_eq!(normalize_user_code(""), None);
        assert_eq!(normalize_user_code("BCDF-GHJ"), None); // 7 letters
        assert_eq!(normalize_user_code("BCDF-GHJKL"), None); // 9 letters
        assert_eq!(normalize_user_code("ACDF-GHJK"), None); // 'A' not in alphabet
        assert_eq!(normalize_user_code("BCD1-GHJK"), None); // digits excluded
        assert_eq!(normalize_user_code("device-code"), None);
    }
}
