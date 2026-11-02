//! Spec-compliant OAuth 2.1 (PKCE + RFC 9728/8707/8414).
//!
//! Two route surfaces:
//!
//! 1. **Admin** (under `/api/v1/admin/mcp/oauth-clients` and
//!    `/api/v1/admin/mcp/issued-tokens`) — operator-managed CRUD over
//!    `mcp_oauth_clients` and read+revoke over `oauth_issued_tokens`
//!    (`surface = 'mcp'` rows). Mounted behind `admin_auth` middleware.
//!
//! 2. **Public OAuth flow** (under `/api/v1/mcp/oauth/{tenant_slug}/...`) —
//!    the actual OAuth endpoints clients hit. Mounted PUBLIC (no admin/portal
//!    middleware) because:
//!      * `/.well-known/oauth-authorization-server` is unauthenticated by spec.
//!      * `/token` is unauthenticated — the bearer is what we issue.
//!      * `/authorize` requires user authentication via the portal JWT in the
//!        `Authorization` header (the SvelteKit consent page reads it from
//!        localStorage). The handler validates the JWT inline so it doesn't
//!        depend on middleware.
//!
//! All flows write to the per-tenant database — RLS-enforced via `TenantConn`
//! once the tenant is resolved from the URL slug.

use streamscope_mcp_auth::ssrf::Egress;
use streamscope_mcp_auth::egress::Surface;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use streamscope_mcp_auth::jwt::{
    encode_access_token, new_jti, ACCESS_TOKEN_TYP,
};
use streamscope_mcp_auth::metadata::{
    narrow_requested_scopes, AuthorizationServerMetadata, JsonWebKeySet, SUPPORTED_SCOPES,
};
use streamscope_mcp_auth::{
    audience_for_slug, verify_s256_challenge, Keyring, McpAccessClaims, SURFACE_MCP, TOKEN_ISSUER,
};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::admin_auth::keyring;
use super::oauth_common::{
    authorization_error_redirect, authorization_redirect, generate_authorization_code,
    require_tenant_portal_session, resolve_tenant_id, retire_chain_on_reuse, surface_issuer,
    token_ok, OauthSurface,
    validate_redirect_uri, AuthorizeApproveResponse, AuthorizeRejection, TokenReply, TokenRequest,
    TokenResponse, ACCESS_TOKEN_TTL_SECS, AUTH_CODE_TTL_SECS, REFRESH_TOKEN_TTL_SECS,
    REFRESH_TOKEN_TYP,
};
use super::oauth_error::{OauthError, OauthErrorCode, OauthErrorResponse, OauthForm, OauthJson};
use super::{
    ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery,
};
use crate::db::tenant::{Scoped, TenantConn, TenantId};
use crate::AdminState;


// ===========================================================================
// Admin: OAuth clients CRUD
// ===========================================================================

/// One row in `GET /api/v1/admin/mcp/oauth-clients`.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct OauthClientRow {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    /// Always returned as a JSON array of strings. Empty arrays are rejected
    /// at write time, but a corrupted DB row could surface as `null` — the
    /// handler treats that as `[]` for forward compat.
    #[schema(value_type = Vec<String>)]
    pub redirect_uris: serde_json::Value,
    pub registration_method: String,
    pub client_id_metadata_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateOauthClient {
    pub name: String,
    /// At least one redirect URI required. Each must be `http://localhost*`,
    /// `http://127.0.0.1*`, `https://...`, or an RFC 8252 private-use scheme
    /// for a native app (`com.example.app:/cb`).
    pub redirect_uris: Vec<String>,
    /// When set, also register a CIMD URL for follow-up resolution. Stored
    /// at registration but not fetched here — CIMD resolution happens in the
    /// `/authorize` flow.
    pub client_id_metadata_url: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateOauthClient {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    /// Absent = leave as-is; `null` = clear it and return the client to its
    /// stored redirect URIs; a value = adopt (or rotate) the CIMD document.
    ///
    /// The nesting is what makes CIMD reversible. A plain `Option` cannot tell
    /// "field omitted" from "field explicitly cleared", so clearing it would
    /// silently leave a third party's document authoritative for this client's
    /// redirect URIs — with the UI reporting success.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub client_id_metadata_url: Option<Option<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateOauthClientResponse {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    #[schema(value_type = Vec<String>)]
    pub redirect_uris: serde_json::Value,
    pub registration_method: String,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OauthClientListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/oauth-clients",
    tag = "MCP OAuth",
    params(OauthClientListQuery),
    responses(
        (status = 200, description = "Paginated list", body = OffsetPage<OauthClientRow>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_oauth_clients(
    mut db: TenantConn,
    Query(query): Query<OauthClientListQuery>,
) -> Result<Json<OffsetPage<OauthClientRow>>, ApiError> {
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, OauthClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, registration_method,
                  client_id_metadata_url, created_at, updated_at
           FROM mcp_oauth_clients
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp_oauth_clients: {e}");
        ApiError::internal("failed to list OAuth clients")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/oauth-clients",
    tag = "MCP OAuth",
    request_body = CreateOauthClient,
    responses(
        (status = 201, description = "Created", body = CreateOauthClientResponse),
        (status = 400, description = "Invalid input", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_oauth_client(
    Extension(ctx): Extension<crate::db::tenant::AdminTenantCtx>,
    mut db: TenantConn,
    Json(body): Json<CreateOauthClient>,
) -> Result<(axum::http::StatusCode, Json<CreateOauthClientResponse>), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if body.redirect_uris.is_empty() {
        return Err(ApiError::bad_request("at least one redirect URI required")
            .code(ApiErrorCode::McpOauthRedirectUriInvalid));
    }
    for uri in &body.redirect_uris {
        if !validate_redirect_uri(uri) {
            return Err(ApiError::bad_request(format!(
                "redirect URI {uri:?} must be https://, http://localhost*, or a private-use scheme like com.example.app:/cb"
            ))
            .code(ApiErrorCode::McpOauthRedirectUriInvalid));
        }
    }

    // A row carrying a metadata URL IS a CIMD registration — that column is
    // what `resolve_authorize_client` consults, and storing it while leaving
    // the row `manual` would keep the static `redirect_uris` authoritative and
    // make the operator's URL dead data. Validate it on the same egress
    // posture the fetch will use, so a URL accepted here is one that can
    // actually be resolved.
    let registration_method = if let Some(url) = body.client_id_metadata_url.as_deref() {
        check_cimd_url(url)?;
        "cimd"
    } else {
        "manual"
    };

    // Generate an opaque random client_id. Format: `mco-<base58 24 bytes>`.
    let client_id = generate_client_id();
    let id = Uuid::new_v4();
    let redirect_uris_json = serde_json::Value::Array(
        body.redirect_uris
            .iter()
            .map(|s| serde_json::Value::String(s.clone()))
            .collect(),
    );

    sqlx::query(
        r#"INSERT INTO mcp_oauth_clients
               (id, tenant_id, client_id, name, redirect_uris, registration_method,
                client_id_metadata_url, created_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .bind(&client_id)
    .bind(&body.name)
    .bind(&redirect_uris_json)
    .bind(registration_method)
    .bind(&body.client_id_metadata_url)
    .bind(ctx.admin_account_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("client_id already taken", ApiErrorCode::McpOauthClientIdTaken)
        } else {
            tracing::error!("create mcp_oauth_client: {e}");
            ApiError::internal("failed to create OAuth client")
        }
    })?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateOauthClientResponse {
            id,
            client_id,
            name: body.name,
            redirect_uris: redirect_uris_json,
            registration_method: registration_method.to_string(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/oauth-clients/{id}",
    tag = "MCP OAuth",
    params(("id" = Uuid, Path, description = "OAuth client UUID")),
    responses(
        (status = 200, description = "OAuth client", body = OauthClientRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_oauth_client(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<OauthClientRow>, ApiError> {
    let row = sqlx::query_as::<_, OauthClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, registration_method,
                  client_id_metadata_url, created_at, updated_at
           FROM mcp_oauth_clients WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get mcp_oauth_client: {e}");
        ApiError::internal("failed to fetch OAuth client")
    })?
    .ok_or_else(|| {
        ApiError::not_found("OAuth client not found", ApiErrorCode::McpOauthClientNotFound)
    })?;
    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/oauth-clients/{id}",
    tag = "MCP OAuth",
    params(("id" = Uuid, Path, description = "OAuth client UUID")),
    request_body = UpdateOauthClient,
    responses(
        (status = 200, description = "Updated", body = OauthClientRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_oauth_client(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOauthClient>,
) -> Result<Json<OauthClientRow>, ApiError> {
    if let Some(uris) = &body.redirect_uris {
        if uris.is_empty() {
            return Err(ApiError::bad_request("at least one redirect URI required")
                .code(ApiErrorCode::McpOauthRedirectUriInvalid));
        }
        for uri in uris {
            if !validate_redirect_uri(uri) {
                return Err(ApiError::bad_request(format!(
                    "redirect URI {uri:?} must be https://, http://localhost*, or a private-use scheme like com.example.app:/cb"
                ))
                .code(ApiErrorCode::McpOauthRedirectUriInvalid));
            }
        }
    }
    // Setting a metadata URL turns the row into a CIMD registration and
    // clearing it turns the row back — the column alone is inert unless
    // `registration_method` says so, and leaving the row `cimd` with no URL
    // would strand it as a corrupted row the authorize path refuses. Validated
    // on the egress posture the fetch will use, exactly as on create.
    if let Some(Some(url)) = body.client_id_metadata_url.as_ref() {
        check_cimd_url(url)?;
    }
    // `None` = absent (leave both columns); `Some(None)` = clear.
    let (cimd_url_change, clear_cimd) = match &body.client_id_metadata_url {
        None => (None, false),
        Some(None) => (None, true),
        Some(Some(url)) => (Some(url.as_str()), false),
    };
    let redirect_uris_json: Option<serde_json::Value> = body.redirect_uris.as_ref().map(|uris| {
        serde_json::Value::Array(
            uris.iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        )
    });
    let row = sqlx::query_as::<_, OauthClientRow>(
        r#"UPDATE mcp_oauth_clients SET
               name = COALESCE($2, name),
               redirect_uris = COALESCE($3, redirect_uris),
               client_id_metadata_url = CASE
                   WHEN $5 THEN NULL
                   WHEN $4::text IS NULL THEN client_id_metadata_url
                   ELSE $4 END,
               registration_method = CASE
                   WHEN $5 THEN 'manual'
                   WHEN $4::text IS NULL THEN registration_method
                   ELSE 'cimd' END,
               updated_at = NOW()
           WHERE id = $1
           RETURNING id, client_id, name, redirect_uris, registration_method,
                     client_id_metadata_url, created_at, updated_at"#,
    )
    .bind(id)
    .bind(body.name.as_deref())
    .bind(redirect_uris_json.as_ref())
    .bind(cimd_url_change)
    .bind(clear_cimd)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update mcp_oauth_client: {e}");
        ApiError::internal("failed to update OAuth client")
    })?
    .ok_or_else(|| {
        ApiError::not_found("OAuth client not found", ApiErrorCode::McpOauthClientNotFound)
    })?;
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/oauth-clients/{id}",
    tag = "MCP OAuth",
    params(("id" = Uuid, Path, description = "OAuth client UUID")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_oauth_client(
    Extension(ctx): Extension<crate::db::tenant::AdminTenantCtx>,
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Revoke the client's issued tokens before deleting the client row. The
    // proxy rejects a token only when its `jti` is in the tenant's
    // revoked-jti set — so without this a deleted client keeps working until
    // natural token expiry (up to 30 days for a refresh token). Revoke first:
    // if the DELETE below fails, the worst case is an over-revoked client the
    // operator can retry — never a deleted client with live tokens.
    //
    // A CIMD row's tokens can carry EITHER identity: the client may present
    // its `mco-` id or, since a published metadata URL is a `client_id` in its
    // own right, that URL. Revoking only the former would leave the client
    // running on tokens the operator believes they just killed.
    sqlx::query(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW(), revoked_by_user_id = $2
            WHERE client_id IN (
                    SELECT client_id FROM mcp_oauth_clients WHERE id = $1
                    UNION ALL
                    SELECT client_id_metadata_url FROM mcp_oauth_clients
                     WHERE id = $1 AND client_id_metadata_url IS NOT NULL
                  )
              AND surface = 'mcp'
              AND revoked_at IS NULL"#,
    )
    .bind(id)
    .bind(ctx.admin_account_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete mcp_oauth_client: revoke issued tokens: {e}");
        ApiError::internal("failed to revoke the client's issued tokens")
    })?;

    let result = sqlx::query("DELETE FROM mcp_oauth_clients WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete mcp_oauth_client: {e}");
            ApiError::internal("failed to delete OAuth client")
        })?;
    if result.rows_affected() == 0 {
        return Err(
            ApiError::not_found("OAuth client not found", ApiErrorCode::McpOauthClientNotFound)
        );
    }
    Ok(Json(ActionResponse::ok()))
}

// ===========================================================================
// Admin: CIMD client inventory
// ===========================================================================

/// One CIMD client observed holding tokens in this tenant.
///
/// A client that identifies itself by a published metadata URL never registers,
/// so it has **no `mcp_oauth_clients` row** — it is absent from the OAuth-client
/// list and out of reach of that list's revoke. This inventory is derived from
/// the tokens themselves, which is the only record such a client leaves.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct CimdClientRow {
    /// The metadata-document URL the client presented as its `client_id`.
    pub client_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_issued: DateTime<Utc>,
    /// Every token ever minted for this client, revoked and expired included.
    pub tokens_issued: i64,
    /// Tokens that would still be honoured right now.
    pub tokens_active: i64,
    /// Distinct grants — one per consent, however many rotations it has been
    /// through.
    ///
    /// Counted by login chain rather than by user **deliberately**: a token row
    /// outlives its subject (`user_id` is `ON DELETE SET NULL`, so a revocation
    /// survives the account), and counting users would silently drop exactly
    /// the orphaned rows an operator most needs to see here.
    pub grants: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/cimd-clients",
    tag = "MCP OAuth",
    params(OauthClientListQuery),
    responses(
        (status = 200, description = "Observed CIMD clients", body = OffsetPage<CimdClientRow>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_cimd_clients(
    mut db: TenantConn,
    Query(query): Query<OauthClientListQuery>,
) -> Result<Json<OffsetPage<CimdClientRow>>, ApiError> {
    let (limit, offset) = PageQuery {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve();
    // Registered clients are excluded: they already appear in the OAuth-client
    // list and its delete revokes their tokens under both identities. Listing
    // them here too would make one client look like two, and leave it ambiguous
    // which surface actually governs it.
    //
    // No join to `users` anywhere in this statement — see `grants`.
    let rows = sqlx::query_as::<_, CimdClientRow>(
        r#"SELECT t.client_id,
                  MIN(t.issued_at)                                          AS first_seen,
                  MAX(t.issued_at)                                          AS last_issued,
                  COUNT(*)::bigint                                          AS tokens_issued,
                  COUNT(*) FILTER (
                      WHERE t.revoked_at IS NULL AND t.expires_at > NOW()
                  )::bigint                                                 AS tokens_active,
                  COUNT(DISTINCT t.login_chain)::bigint                     AS grants
             FROM oauth_issued_tokens t
            WHERE t.surface = 'mcp'
              AND t.client_id LIKE 'https://%'
              AND NOT EXISTS (
                    SELECT 1 FROM mcp_oauth_clients c
                     WHERE c.client_id = t.client_id
                        OR c.client_id_metadata_url = t.client_id
                  )
            GROUP BY t.client_id
            ORDER BY MAX(t.issued_at) DESC
            LIMIT $1 OFFSET $2"#,
    )
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list cimd clients: {e}");
        ApiError::internal("failed to list CIMD clients")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Deserialize, ToSchema)]
pub struct RevokeCimdClientRequest {
    /// The `client_id` exactly as it appears in the inventory.
    pub client_id: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/cimd-clients/actions/revoke",
    tag = "MCP OAuth",
    request_body = RevokeCimdClientRequest,
    responses(
        (status = 200, description = "Revoked", body = ActionResponse),
        (status = 400, description = "Invalid input", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_cimd_client(
    Extension(ctx): Extension<crate::db::tenant::AdminTenantCtx>,
    Extension(diff): Extension<crate::middleware::audit_common::AuditDiffSink>,
    mut db: TenantConn,
    Json(body): Json<RevokeCimdClientRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    if !body.client_id.starts_with("https://") {
        return Err(ApiError::bad_request(
            "a CIMD client_id is the https:// URL of its metadata document",
        )
        .code(ApiErrorCode::McpOauthClientNotFound));
    }
    // Retire every row of every chain this client holds, not just the live
    // access tokens: leaving a refresh token alive lets the client mint a fresh
    // pair on its next rotation and the revoke would appear to have done
    // nothing. `retire_chain_on_reuse` handles one chain; this is the same
    // reasoning applied to the whole client at once.
    let revoked = sqlx::query(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW(), revoked_by_user_id = $2
            WHERE surface = 'mcp'
              AND client_id = $1
              AND revoked_at IS NULL"#,
    )
    .bind(&body.client_id)
    .bind(ctx.admin_account_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("revoke cimd client: {e}");
        ApiError::internal("failed to revoke the client's tokens")
    })?
    .rows_affected();

    // An authorization code the client has not yet exchanged is a live claim on
    // a fresh token pair. Leaving one behind bounds the revoke by the code TTL
    // rather than making it immediate — the client redeems it seconds later and
    // is back, having been reported cut off.
    sqlx::query(
        "DELETE FROM oauth_authorization_codes WHERE client_id = $1 AND surface = 'mcp'",
    )
    .bind(&body.client_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("revoke cimd client: purge codes: {e}");
        ApiError::internal("failed to revoke the client's tokens")
    })?;


    // A summary, not the generic single-row snapshot: this client has no row of
    // its own — that absence is the whole reason this surface exists — so there
    // is nothing for the registry-driven diff to read.
    diff.set(
        serde_json::json!({ "client_id": body.client_id, "live_tokens": revoked }),
        serde_json::json!({ "client_id": body.client_id, "live_tokens": 0 }),
    );

    Ok(Json(ActionResponse::ok()
        .with_message(format!("revoked {revoked} token(s)"))))
}

// ===========================================================================
// Admin: issued tokens list/revoke
// ===========================================================================

/// One row in the `/mcp/issued-tokens` list. Joins display fields (user
/// email + display_name, client name, endpoint slug) so the UI can render
/// without secondary lookups.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct IssuedTokenRow {
    pub jti: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_display_name: Option<String>,
    pub client_id: String,
    pub client_name: Option<String>,
    pub virtual_server_id: Uuid,
    pub virtual_server_slug: Option<String>,
    pub audience: String,
    pub scope: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Status filter for the issued-tokens list.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatusFilter {
    /// Default: revoked_at IS NULL AND expires_at > NOW().
    #[default]
    Active,
    /// revoked_at IS NOT NULL.
    Revoked,
    /// revoked_at IS NULL AND expires_at <= NOW().
    Expired,
    /// No status filter.
    All,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct IssuedTokenListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub client_id: Option<String>,
    pub audience: Option<String>,
    pub virtual_server_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    /// Status filter. Default `active`.
    pub status: Option<TokenStatusFilter>,
    /// Filter `issued_at >= start` when present.
    pub start: Option<DateTime<Utc>>,
    /// Filter `issued_at < end` when present.
    pub end: Option<DateTime<Utc>>,
    /// Substring match on jti (UUID text) or scope.
    pub q: Option<String>,
}

/// Counts of tokens by status, scoped to the same filters as the list
/// (excluding the `status` filter itself). Powers the Tokens-tab header.
#[derive(Serialize, ToSchema)]
pub struct TokenStatusBreakdown {
    /// Total tokens in scope (active + revoked + expired).
    pub issued: i64,
    pub active: i64,
    pub revoked: i64,
    pub expired: i64,
}

/// Tokens-tab list payload: page of rows + the same-scope status counts
/// rendered above the table. One round trip for both.
#[derive(Serialize, ToSchema)]
pub struct IssuedTokensListResponse {
    pub items: Vec<IssuedTokenRow>,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
    pub total_breakdown: TokenStatusBreakdown,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/issued-tokens",
    tag = "MCP OAuth",
    params(IssuedTokenListQuery),
    responses(
        (status = 200, description = "Issued tokens (paginated) + same-scope status counts", body = IssuedTokensListResponse),
        (status = 400, description = "`start` is not before `end`", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_issued_tokens(
    mut db: TenantConn,
    Query(query): Query<IssuedTokenListQuery>,
) -> Result<Json<IssuedTokensListResponse>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();
    let status = query.status.unwrap_or_default();
    // The free-text term as every list search binds it: trimmed, escaped, and
    // absent when blank.
    let search = crate::sql_pattern::search_pattern(query.q.as_deref());

    // Build common WHERE clause for filters that scope BOTH the list and the
    // status breakdown (status is intentionally excluded from the breakdown
    // filter — the breakdown counts each status under the same other filters).
    let mut where_clauses: Vec<String> = Vec::new();
    let mut next_idx: u32 = 3; // $1 = limit+1, $2 = offset
    if query.client_id.is_some() {
        where_clauses.push(format!("t.client_id = ${next_idx}"));
        next_idx += 1;
    }
    if query.audience.is_some() {
        where_clauses.push(format!("t.audience = ${next_idx}"));
        next_idx += 1;
    }
    if query.virtual_server_id.is_some() {
        where_clauses.push(format!("t.virtual_server_id = ${next_idx}"));
        next_idx += 1;
    }
    if query.user_id.is_some() {
        where_clauses.push(format!("t.user_id = ${next_idx}"));
        next_idx += 1;
    }
    if query.start.is_some() {
        where_clauses.push(format!("t.issued_at >= ${next_idx}"));
        next_idx += 1;
    }
    if query.end.is_some() {
        where_clauses.push(format!("t.issued_at < ${next_idx}"));
        next_idx += 1;
    }
    if search.is_some() {
        where_clauses.push(format!(
            "(t.jti::TEXT ILIKE ${next_idx} OR t.scope ILIKE ${next_idx})"
        ));
        // q is the last conditional bind — no further increment needed.
    }
    let _ = next_idx;
    let scope_where = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", where_clauses.join(" AND "))
    };

    // Status predicate for the LIST query only. The breakdown query
    // computes all three statuses inline via FILTER (WHERE …).
    let status_predicate = match status {
        TokenStatusFilter::Active => " AND t.revoked_at IS NULL AND t.expires_at > NOW()",
        TokenStatusFilter::Revoked => " AND t.revoked_at IS NOT NULL",
        TokenStatusFilter::Expired => " AND t.revoked_at IS NULL AND t.expires_at <= NOW()",
        TokenStatusFilter::All => "",
    };

    // List query — JOIN display fields. RLS scopes oauth_issued_tokens,
    // mcp_oauth_clients, mcp_virtual_servers, and users to the tenant. The
    // surface predicate keeps CLI-provisioning rows (NULL virtual_server_id /
    // audience) out of this MCP-shaped view.
    let list_sql = format!(
        "SELECT t.jti, \
                t.user_id, \
                u.email AS user_email, \
                u.display_name AS user_display_name, \
                t.client_id, \
                c.name AS client_name, \
                t.virtual_server_id, \
                vs.slug AS virtual_server_slug, \
                t.audience, \
                t.scope, \
                t.issued_at, \
                t.expires_at, \
                t.revoked_at \
         FROM oauth_issued_tokens t \
         /* INNER JOIN, deliberately: `user_id` is ON DELETE SET NULL, so a row */ \
         /* whose subject was deleted has none and drops out. That is the right */ \
         /* rendering for a listing of who holds what — but it means this view */ \
         /* is NOT a complete inventory of rows. Every such row is revoked (the */ \
         /* delete revokes under a subject lock), so nothing live is hidden.    */ \
         JOIN users u ON u.id = t.user_id \
         LEFT JOIN mcp_oauth_clients c ON c.client_id = t.client_id \
         LEFT JOIN mcp_virtual_servers vs ON vs.id = t.virtual_server_id \
         WHERE t.surface = 'mcp'{scope_where}{status_predicate} \
         ORDER BY t.issued_at DESC \
         LIMIT $1 OFFSET $2"
    );
    let mut q = sqlx::query_as::<_, IssuedTokenRow>(sqlx::AssertSqlSafe(&*list_sql))
        .bind(limit + 1)
        .bind(offset);
    if let Some(client_id) = &query.client_id {
        q = q.bind(client_id);
    }
    if let Some(audience) = &query.audience {
        q = q.bind(audience);
    }
    if let Some(vs_id) = query.virtual_server_id {
        q = q.bind(vs_id);
    }
    if let Some(uid) = query.user_id {
        q = q.bind(uid);
    }
    if let Some(start) = query.start {
        q = q.bind(start);
    }
    if let Some(end) = query.end {
        q = q.bind(end);
    }
    if let Some(pattern) = &search {
        q = q.bind(pattern.clone());
    }
    let rows = q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list mcp_issued_tokens: {e}");
        ApiError::internal("failed to list issued tokens")
    })?;

    // Breakdown query — same filters minus status, three FILTER aggregates.
    //
    // Carries the list's `JOIN users` too, so the counts describe exactly the
    // rows the list can display. Without it a row whose subject was deleted
    // (revoked, `user_id` NULL) would inflate `revoked` above anything the
    // operator can see, and a count that disagrees with its own list reads as a
    // bug in the filter rather than as rows deliberately withheld.
    let breakdown_sql = format!(
        "SELECT \
            COUNT(*) FILTER (WHERE t.revoked_at IS NULL AND t.expires_at > NOW())::BIGINT AS active, \
            COUNT(*) FILTER (WHERE t.revoked_at IS NOT NULL)::BIGINT AS revoked, \
            COUNT(*) FILTER (WHERE t.revoked_at IS NULL AND t.expires_at <= NOW())::BIGINT AS expired \
         FROM oauth_issued_tokens t \
         JOIN users u ON u.id = t.user_id \
         WHERE t.surface = 'mcp'{scope_where_unindexed}",
        scope_where_unindexed = {
            // Re-emit clauses with bind indices starting at $1 (no limit/offset
            // for breakdown).
            let mut clauses: Vec<String> = Vec::new();
            let mut idx: u32 = 1;
            if query.client_id.is_some() { clauses.push(format!("t.client_id = ${idx}")); idx += 1; }
            if query.audience.is_some() { clauses.push(format!("t.audience = ${idx}")); idx += 1; }
            if query.virtual_server_id.is_some() { clauses.push(format!("t.virtual_server_id = ${idx}")); idx += 1; }
            if query.user_id.is_some() { clauses.push(format!("t.user_id = ${idx}")); idx += 1; }
            if query.start.is_some() { clauses.push(format!("t.issued_at >= ${idx}")); idx += 1; }
            if query.end.is_some() { clauses.push(format!("t.issued_at < ${idx}")); idx += 1; }
            if search.is_some() {
                clauses.push(format!("(t.jti::TEXT ILIKE ${idx} OR t.scope ILIKE ${idx})"));
            }
            if clauses.is_empty() { String::new() } else { format!(" AND {}", clauses.join(" AND ")) }
        }
    );
    let mut bq = sqlx::query_as::<_, (i64, i64, i64)>(sqlx::AssertSqlSafe(&*breakdown_sql));
    if let Some(client_id) = &query.client_id {
        bq = bq.bind(client_id);
    }
    if let Some(audience) = &query.audience {
        bq = bq.bind(audience);
    }
    if let Some(vs_id) = query.virtual_server_id {
        bq = bq.bind(vs_id);
    }
    if let Some(uid) = query.user_id {
        bq = bq.bind(uid);
    }
    if let Some(start) = query.start {
        bq = bq.bind(start);
    }
    if let Some(end) = query.end {
        bq = bq.bind(end);
    }
    if let Some(pattern) = &search {
        bq = bq.bind(pattern.clone());
    }
    let (active, revoked, expired) = bq.fetch_one(db.conn()).await.map_err(|e| {
        tracing::error!("list mcp_issued_tokens (breakdown): {e}");
        ApiError::internal("failed to compute token status breakdown")
    })?;

    let has_more = rows.len() as i64 > limit;
    let mut items = rows;
    if has_more {
        items.truncate(limit as usize);
    }
    Ok(Json(IssuedTokensListResponse {
        items,
        limit,
        offset,
        has_more,
        total_breakdown: TokenStatusBreakdown {
            issued: active + revoked + expired,
            active,
            revoked,
            expired,
        },
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/issued-tokens/{jti}/actions/revoke",
    tag = "MCP OAuth",
    params(("jti" = Uuid, Path, description = "Token JTI")),
    responses(
        (status = 200, description = "Revoked", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_issued_token(
    Extension(ctx): Extension<crate::db::tenant::AdminTenantCtx>,
    mut db: TenantConn,
    Path(jti): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // `surface = 'mcp'`: this endpoint owns the MCP-shaped tokens it lists, and
    // nothing else. A CLI login is revoked through its own surface, which knows
    // that revocation needs no config body change.
    let result = sqlx::query(
        r#"UPDATE oauth_issued_tokens
           SET revoked_at = NOW(), revoked_by_user_id = $2
           WHERE jti = $1 AND surface = 'mcp' AND revoked_at IS NULL"#,
    )
    .bind(jti)
    .bind(ctx.admin_account_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("revoke mcp_issued_token: {e}");
        ApiError::internal("failed to revoke token")
    })?;
    if result.rows_affected() == 0 {
        return Err(
            ApiError::not_found("token not found or already revoked", ApiErrorCode::McpOauthTokenNotFound),
        );
    }
    Ok(Json(ActionResponse::ok().with_message("token revoked")))
}

// ===========================================================================
// Public: RFC 8414 metadata
// ===========================================================================

#[utoipa::path(
    get,
    path = "/api/v1/mcp/oauth/{tenant_slug}/.well-known/oauth-authorization-server",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Authorization server metadata", body = AuthorizationServerMetadata),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
    ),
)]
pub async fn authorization_server_metadata(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
) -> Result<Json<AuthorizationServerMetadata>, ApiError> {
    let metadata = build_authorization_server_metadata(&state, &tenant_slug).await?;
    Ok(Json(metadata))
}

/// The public half of this tenant's MCP token-signing keys (RFC 7517).
///
/// Unauthenticated by design — this is a *public* key set, and a client that
/// has to authenticate to fetch one gains nothing from local verification.
///
/// The document is derived, never stored: the keys come from the same ring that
/// signs, so there is no state that could drift out of step with the tokens in
/// circulation, and rotating `AUTH_SECRET` changes what is published here on
/// the next request with no migration or key-distribution step.
#[utoipa::path(
    get,
    path = "/api/v1/mcp/oauth/{tenant_slug}/jwks.json",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "JSON Web Key Set", body = JsonWebKeySet),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 503, description = "Signing keys unavailable", body = ApiErrorResponse),
    ),
)]
pub async fn jwks_document(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let tenant_id = resolve_active_tenant_id(&state, &tenant_slug).await?;
    let Some(ring) = keyring() else {
        tracing::error!("jwks: AUTH_SECRET unavailable");
        return Err(ApiError::server_misconfigured("signing keys unavailable"));
    };
    let keys = ring.public_jwks(&tenant_id.to_string());
    Ok((
        // Cacheable, but briefly: a client that cached this across a rotation
        // would keep failing signatures until the entry aged out, and the
        // predecessor overlap is measured in hours rather than minutes.
        [(axum::http::header::CACHE_CONTROL, "public, max-age=300")],
        Json(JsonWebKeySet { keys }),
    ))
}

/// Resolve a tenant slug to its id, 404ing identically for unknown and
/// inactive slugs (never leak tenant existence via a different status).
/// Reads only the `tenants` registry (no RLS policy); callers expose public metadata.
async fn resolve_active_tenant_id(
    state: &AdminState,
    tenant_slug: &str,
) -> Result<Uuid, ApiError> {
    // A lookup the database could not answer is a 503, never "no such tenant".
    let Some((tenant_id, is_active)) = super::admin_auth::lookup_tenant_slug(&state.db, tenant_slug).await? else {
        return Err(ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound));
    };
    if !is_active {
        return Err(ApiError::not_found("tenant inactive", ApiErrorCode::TenantInactive));
    }
    Ok(tenant_id)
}

/// endpoint so the two documents stay byte-identical on overlapping fields.
async fn build_authorization_server_metadata(
    state: &AdminState,
    tenant_slug: &str,
) -> Result<AuthorizationServerMetadata, ApiError> {
    let tenant_id = resolve_active_tenant_id(state, tenant_slug).await?;

    // Machine-facing endpoints (issuer/token/register/jwks) live on the
    // API origin; only the browser-facing consent page stays on the admin
    // (UI) origin — `resolve_oauth_discovery_origins` owns the split-vhost
    // fallback rule.
    let origins =
        crate::tenant_public_url::resolve_oauth_discovery_origins(&state.db, tenant_id)
            .await?;
    let issuer = surface_issuer(&state.db, tenant_id, tenant_slug, OauthSurface::Mcp).await?;

    Ok(AuthorizationServerMetadata {
        issuer: issuer.clone(),
        // The consent UI is the SvelteKit `/portal/t/<tenant_slug>/mcp/authorize`
        // page. It lives under the per-tenant URL prefix so the path-scoped
        // portal_session cookie reaches it after the user authenticates; the
        // slug in the path also lets the page resolve which tenant's
        // `/authorize/{preview,approve}` backend to call without re-deriving it
        // from the resource URI (which is slug-only on the proxy origin and would
        // require a DB round-trip).
        authorization_endpoint: format!(
            "{}/portal/t/{tenant_slug}/mcp/authorize",
            origins.admin
        ),
        // RFC 7591 dynamic client registration. Operators can leave `manual`
        // as the only path (admin UI registers clients) by gating the
        // endpoint at the reverse proxy; we always advertise the endpoint
        // so spec-conforming clients can discover it.
        registration_endpoint: Some(format!("{issuer}/register")),
        token_endpoint: format!("{issuer}/token"),
        revocation_endpoint: Some(format!("{issuer}/revoke")),
        device_authorization_endpoint: None,
        // Access tokens on this surface are ES256-signed, so a holder can
        // verify one locally against the keys published here.
        jwks_uri: Some(format!("{issuer}/jwks.json")),
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        scopes_supported: SUPPORTED_SCOPES.iter().map(|s| s.to_string()).collect(),
        resource_parameter_supported: true,
        // CIMD: an `https://` URL presented as `client_id` is resolved to the
        // metadata document it serves, so a client that publishes one never
        // registers at all. `/token` compares the `client_id` recorded on the
        // authorization code, which is that same URL. Per-tenant, and the
        // advertisement must track the enforcement: a document promising CIMD
        // to a tenant that refuses it sends every conforming client down a path
        // that ends in "unknown client".
        client_id_metadata_document_supported: cimd_enabled(&state.db, tenant_id).await?,
        // CLI-surface extension — not part of the MCP discovery contract.
        api_origin: None,
        authorization_response_iss_parameter_supported: true,
    })
}

// ===========================================================================
// Public: /authorize (consent backend — called by SvelteKit consent page)
// ===========================================================================

/// Query (or body) shape used by `preview` and `approve`.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    /// PKCE — fixed `S256`.
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// RFC 8707 `resource` parameter — the canonical URI of the virtual server
    /// the client wants to access. We bind the issued JWT's `aud` to this.
    pub resource: String,
    pub scope: Option<String>,
}

/// Payload returned by `POST /authorize/preview`.
///
/// Two dispositions, because RFC 6749 §4.1.2.1 gives an invalid authorization
/// request two different destinations: the consent page renders `ok`, and
/// hands `redirect` straight back to the client. The consent page cannot make
/// that call itself — only the server knows whether the redirect URI was
/// vouched for by a registration — so the decision is carried, not inferred.
#[derive(Serialize, ToSchema)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum AuthorizePreviewResponse {
    /// The request validated. Render the "X wants to access Y" copy.
    Ok {
        client_name: String,
        virtual_server_name: String,
        virtual_server_slug: String,
        virtual_server_id: Uuid,
        scope: String,
    },
    /// The request is invalid, but the client and its redirect URI are
    /// registered — so the error belongs at that URI, not on our page.
    Redirect {
        /// The fully-built error redirect, so the encoding and the byte-exact
        /// RFC 9207 `iss` stay owned by the server that has to match its own
        /// metadata.
        redirect_to: String,
    },
}

/// The client an `/authorize` call names, however it identified itself.
///
/// Registration is not the only way in: a CIMD client publishes its metadata
/// at a stable URL and presents that URL as its `client_id`, so there is no row
/// to read. Both arrive here as the same three facts the rest of the flow needs.
struct AuthorizeClient {
    /// Recorded on the authorization code and compared at `/token`. For a CIMD
    /// client this is the metadata URL itself.
    client_id: String,
    /// Human-readable name for the consent copy.
    name: String,
    /// The URIs this client may be redirected to, as of this call.
    redirect_uris: Vec<String>,
}

/// Identify the client an `/authorize` call names — **before any connection is
/// checked out**.
///
/// Both ways in can end in an HTTP fetch: a `client_id` that is itself an
/// `https` URL, and a registered row whose `client_id_metadata_url` is
/// resolved live. Neither host is ours, and neither caller is trusted —
/// `/register` is unauthenticated per RFC 7591, so an anonymous caller can
/// register a URL and then present the `mco-` id it was handed. Holding a
/// `TenantConn` across either fetch would let a handful of slow authorizations
/// occupy the connection pool and stall the API for every tenant, so the row
/// read releases its connection before the fetch begins.
///
/// **Invariant to preserve:** nothing on this path may hold a connection
/// across `resolve_cimd_document`. A registry lookup that keeps its handle
/// open reintroduces the stall through the sibling door.
async fn resolve_authorize_client(
    db: &crate::db::Db,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<AuthorizeClient, ApiError> {
    // A `client_id` that is an `https://` URL **is** a CIMD client id — that
    // is the whole convention — so it is resolved against the document it
    // points at rather than looked up. Registered ids are opaque and
    // `mco-`-prefixed, so the two namespaces cannot collide.
    if looks_like_cimd_client_id(client_id) {
        if !cimd_enabled(db, tenant_id).await? {
            tracing::info!(%tenant_id, "authorize: CIMD client refused — disabled for this tenant");
            return Err(cimd_disabled_error());
        }
        let doc = fetch_cimd(db, client_id).await?;
        return Ok(AuthorizeClient {
            client_id: client_id.to_string(),
            name: doc.client_name.unwrap_or_else(|| client_id.to_string()),
            redirect_uris: doc.redirect_uris,
        });
    }

    let mut conn = TenantConn::acquire(db, TenantId::from_row(tenant_id)).await.map_err(|e| {
        tracing::error!("authorize: tdb: {e}");
        super::db_read_error(&e, "the database did not answer")
    })?;
    let client = sqlx::query_as::<_, OauthClientRow>(
        r#"SELECT id, client_id, name, redirect_uris, registration_method,
                  client_id_metadata_url, created_at, updated_at
           FROM mcp_oauth_clients WHERE client_id = $1"#,
    )
    .bind(client_id)
    .fetch_optional(conn.conn())
    .await
    .map_err(|e| {
        tracing::error!("authorize: client lookup: {e}");
        ApiError::internal("failed to load OAuth client")
    })?
    .ok_or_else(|| {
        ApiError::not_found("OAuth client not found", ApiErrorCode::McpOauthClientNotFound)
    })?;
    drop(conn);

    // A registered CIMD client gets its authoritative URI list from the live
    // document on each call, so an operator rotating published URIs doesn't
    // have to re-register. Manual and DCR clients use the row's stored array.
    let redirect_uris: Vec<String> = if client.registration_method == "cimd" {
        // The row is registered, but resolving it still means fetching a
        // document the client publishes — the exact thing the switch turns off.
        if !cimd_enabled(db, tenant_id).await? {
            tracing::info!(%tenant_id, "authorize: registered CIMD client refused — disabled for this tenant");
            return Err(cimd_disabled_error());
        }
        let url = client.client_id_metadata_url.as_deref().ok_or_else(|| {
            tracing::error!(
                client_id = %client.client_id,
                "CIMD client has null client_id_metadata_url — corrupted row"
            );
            ApiError::internal("CIMD client metadata URL missing")
        })?;
        fetch_cimd(db, url).await?.redirect_uris
    } else {
        client
            .redirect_uris
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(AuthorizeClient {
        client_id: client.client_id,
        name: client.name,
        redirect_uris,
    })
}

/// Fetch a CIMD document with the trusted-CA set read fresh first.
///
/// The fetch rides TLS against a host the client chose, and the CA cache is
/// process-local — only the replica that handled an import refreshes it on its
/// own. Without this a just-imported (or just-cleared) CA leaves sibling
/// replicas resolving against a stale trust set, so the same authorization
/// succeeds or fails depending on which one the load balancer picked.
async fn fetch_cimd(db: &crate::db::Db, url: &str) -> Result<CimdDocument, ApiError> {
    crate::custom_ca::refresh_from_db(db).await;
    resolve_cimd_document(url).await
}

/// Validate the /authorize request body and pull out the client + virtual
/// server. Used by both `preview` and `approve` so the validation stays in one
/// place.
///
/// **The order of these checks is the RFC 6749 §4.1.2.1 contract**, not a
/// stylistic choice — see [`AuthorizeRejection`]. Everything above the marked
/// boundary renders; everything below it redirects. Moving a check across that
/// line changes an observable protocol behaviour in one direction (a client
/// waiting forever on a callback we never sent) or opens an open redirect in
/// the other.
async fn validate_authorize_request(
    db: &mut TenantConn,
    public_origin: &str,
    body: &AuthorizeRequest,
    client: AuthorizeClient,
) -> Result<(AuthorizeClient, McpVirtualServerStub, String), AuthorizeRejection> {

    // Exact-match redirect URI.
    if !client.redirect_uris.iter().any(|u| u == &body.redirect_uri) {
        return Err(AuthorizeRejection::Render(
            ApiError::bad_request("redirect_uri does not match a registered URI")
                .code(ApiErrorCode::McpOauthRedirectUriMismatch),
        ));
    }

    // ---- Redirect boundary: the client and its URI are now vouched for. ----

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

    // RFC 6749 §3.3: an authorization server may issue less than was asked for
    // as long as it reports what it issued — which the token response does. So
    // a request naming scopes we grant plus some we don't is narrowed rather
    // than refused, and a request naming nothing gets full access, which is what
    // keeps every client written before per-method scopes working unchanged.
    //
    // A request naming ONLY scopes this server does not grant is a different
    // thing: there is nothing to narrow to, and issuing a token for something
    // else entirely leaves the client holding a credential it will misread.
    // That is §4.1.2.1 `invalid_scope`.
    let Some(granted_scope) = narrow_requested_scopes(body.scope.as_deref()) else {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidScope,
            "none of the requested scopes are granted by this server",
        ));
    };

    // Resolve resource to a virtual server in this tenant.
    let prefix = format!("{}/mcp/", public_origin.trim_end_matches('/'));
    let Some(slug) = body.resource.strip_prefix(prefix.as_str()) else {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidTarget,
            "resource is not on this proxy origin",
        ));
    };
    let vs = sqlx::query_as::<_, McpVirtualServerStub>(
        r#"SELECT id, slug, name, oauth_enabled
           FROM mcp_virtual_servers WHERE slug = $1"#,
    )
    .bind(slug)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("authorize: VS lookup: {e}");
        AuthorizeRejection::redirect(
            OauthErrorCode::ServerError,
            "failed to resolve virtual server",
        )
    })?
    .ok_or_else(|| {
        AuthorizeRejection::redirect(OauthErrorCode::InvalidTarget, "virtual server not found")
    })?;
    if !vs.oauth_enabled {
        return Err(AuthorizeRejection::redirect(
            OauthErrorCode::InvalidTarget,
            "virtual server has not opted into spec-OAuth",
        ));
    }
    Ok((client, vs, granted_scope))
}

/// What fetching a CIMD metadata document may reach: an internal address only
/// when the platform's `cimd` egress list lists it.
///
/// Its own list, deliberately not the MCP one: a CIMD URL arrives as a
/// `client_id` on the unauthenticated registration endpoint, so it is the
/// lowest-trust URL on the MCP surface. **Every** CIMD URL check must go through here, at write time and at fetch
/// time alike: a stricter gate on registration than on the fetch would refuse a
/// URL an unregistered `client_id` then reaches anyway.
const CIMD_EGRESS: Egress = Egress::Surface(Surface::Cimd);

/// The scheme a CIMD metadata URL must use, wherever one is accepted.
///
/// The document is the client's entire identity — its redirect URIs come from
/// it, and `resolve_authorize_client` re-fetches it on *every* authorize — so
/// plaintext would let anyone on the path substitute a redirect URI and collect
/// the authorization code, live, on each login rather than once at
/// registration.
const CIMD_SCHEME: &str = "https://";

/// Whether a `client_id` is a CIMD metadata URL rather than a registered id.
///
/// An `http://` client_id is not a CIMD client id at all; it falls through to
/// the registry and fails there as an unknown client.
fn looks_like_cimd_client_id(client_id: &str) -> bool {
    client_id.starts_with(CIMD_SCHEME)
}

/// Has this tenant left CIMD registration enabled?
///
/// Defaults to true — including for a tenant with no `tenant_auth_configs` row
/// at all — so the answer matches what the tenant's own RFC 8414 document
/// advertises. **Every** path that would fetch a client-published metadata
/// document consults this: the unregistered URL-as-`client_id` arrival, the
/// registered row whose `client_id_metadata_url` is resolved live, and
/// `/register` accepting one in the first place. A gate on fewer than all three
/// would leave the fetch reachable through the doors it did not cover.
///
/// Reads on its own short-lived connection and releases it before returning —
/// callers must not hold one across the CIMD fetch that follows.
async fn cimd_enabled(db: &crate::db::Db, tenant_id: Uuid) -> Result<bool, ApiError> {
    let mut conn = TenantConn::acquire(db, TenantId::from_row(tenant_id)).await.map_err(|e| {
        tracing::error!("cimd_enabled: tdb: {e}");
        super::db_read_error(&e, "the database did not answer")
    })?;
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT mcp_oauth_cimd_enabled FROM tenant_auth_configs \
         WHERE tenant_id = current_tenant_id()",
    )
    .fetch_optional(conn.conn())
    .await
    .map_err(|e| {
        tracing::error!("cimd_enabled: {e}");
        ApiError::internal("failed to read tenant auth config")
    })?;
    Ok(enabled.unwrap_or(true))
}

/// The refusal a tenant with CIMD off returns. Deliberately the
/// unknown-client answer rather than a "CIMD is disabled" one: whether a
/// deployment accepts client-published metadata is visible in its discovery
/// document, and nothing else about the tenant's configuration should be
/// readable from an unauthenticated probe.
fn cimd_disabled_error() -> ApiError {
    ApiError::not_found("OAuth client not found", ApiErrorCode::McpOauthClientNotFound)
}

/// Validate a CIMD metadata URL an operator or a DCR caller supplied.
///
/// **Every** write path that stores one goes through here. A registration guard
/// weaker than [`looks_like_cimd_client_id`] would be worse than none: the
/// stored `http://` URL is fetched on every authorize, so a stricter rule for
/// the unregistered form would only mean the plaintext fetch happens on the
/// registered path instead.
fn check_cimd_url(url: &str) -> Result<url::Url, ApiError> {
    if !url.starts_with(CIMD_SCHEME) {
        return Err(ApiError::bad_request(
            "client_id_metadata_url must be an https URL",
        )
        .code(ApiErrorCode::McpOauthDcrInvalidRequest));
    }
    streamscope_mcp_auth::ssrf::check_url_for(url, CIMD_EGRESS).map_err(
        |e| {
            ApiError::bad_request(format!("invalid client_id_metadata_url: {e}"))
                .code(ApiErrorCode::McpOauthDcrInvalidRequest)
        },
    )
}

#[derive(sqlx::FromRow)]
struct McpVirtualServerStub {
    id: Uuid,
    slug: String,
    name: String,
    oauth_enabled: bool,
}

/// Revoke every live MCP OAuth token whose access path no longer exists.
///
/// Removing a workspace member, or a workspace's grant on a virtual server,
/// cuts that member's `sk-` keys the moment config resync lands — but an OAuth
/// bearer is not a key. It lives until `exp`, and its refresh token renews for
/// thirty days. Revocation is the only thing that withdraws one, so every path
/// that takes access away must call this: the revoked jtis reach the proxy in
/// the tenant's config body.
///
/// **The predicate mirrors [`resolve_mcp_workspace`] deliberately** — a token
/// survives exactly while some workspace both contains its subject and grants
/// its virtual server, which is the same question asked at mint time. Sweeping
/// the whole tenant rather than the pair that changed is what makes it
/// impossible to miss a case; the table holds only live grants.
pub(crate) async fn revoke_orphaned_mcp_tokens(
    db: &mut TenantConn,
) -> Result<u64, ApiError> {
    let tenant_id = db.tenant_uuid();
    revoke_orphaned_mcp_tokens_conn(db.conn(), tenant_id).await
}

/// [`revoke_orphaned_mcp_tokens`] on a connection the caller holds — for a path
/// that removes access inside its own transaction, so the revocation commits
/// or rolls back with the removal. The connection must be tenant-scoped.
pub(crate) async fn revoke_orphaned_mcp_tokens_conn(
    conn: &mut Scoped,
    tenant_id: Uuid,
) -> Result<u64, ApiError> {
    let result = sqlx::query(
        r#"UPDATE oauth_issued_tokens t
              SET revoked_at = NOW()
            WHERE t.tenant_id = $1
              AND t.surface = 'mcp'
              AND t.revoked_at IS NULL
              AND t.expires_at > NOW()
              AND NOT EXISTS (
                    SELECT 1
                      FROM workspaces w
                      JOIN workspace_members m
                        ON m.workspace_id = w.id AND m.user_id = t.user_id
                     WHERE w.tenant_id = t.tenant_id
                       AND EXISTS (
                             SELECT 1 FROM workspace_mcp_access a
                              WHERE a.workspace_id = w.id
                                AND a.virtual_server_id = t.virtual_server_id
                           )
                  )"#,
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("revoke_orphaned_mcp_tokens: {e}");
        ApiError::internal("failed to revoke MCP tokens")
    })?;
    let revoked = result.rows_affected();
    if revoked > 0 {
        tracing::info!(tenant_id = %tenant_id, revoked, "revoked MCP tokens whose access was removed");
    }
    Ok(revoked)
}

/// The row a successful rotation retires, and everything the replacement pair
/// is rebuilt from. Named rather than a tuple because the fields are five
/// identifiers of four different kinds — positional destructuring of that is
/// how a `virtual_server_id` ends up bound where an `audience` belongs.
#[derive(sqlx::FromRow)]
struct RotatedRow {
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: String,
    virtual_server_id: Uuid,
    audience: String,
    scope: String,
    login_chain: Uuid,
}

/// Resolve the workspace through which `user_id` reaches virtual server
/// `vs_id`, or `None` when no workspace grants access. Binding requires one of
/// the user's workspaces to explicitly allowlist the server (`workspace_mcp_access`)
/// — the Default workspace included, with no implicit pass — matching the
/// per-request enforcement, so a token is never minted that would 403 on first
/// use. Among multiple matching workspaces, prefers the Default, then by name,
/// so MCP usage counts against a stable budget / rate bucket. The result is
/// embedded in the token's `workspace_id` claim — the OAuth flow has no
/// per-workspace consent step, so this is the single point where the binding is
/// decided.
///
/// Tenant-scoped explicitly via `w.tenant_id` (FK validation alone would bypass
/// RLS on a superuser connection).
async fn resolve_mcp_workspace(
    db: &mut TenantConn,
    user_id: Uuid,
    vs_id: Uuid,
) -> Result<Option<Uuid>, ApiError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        r#"SELECT w.id
             FROM workspaces w
             JOIN workspace_members m
               ON m.workspace_id = w.id AND m.user_id = $1
            WHERE w.tenant_id = $2
              AND EXISTS (
                    SELECT 1 FROM workspace_mcp_access a
                     WHERE a.workspace_id = w.id
                       AND a.virtual_server_id = $3
                  )
            ORDER BY (w.role = 'default') DESC, w.name
            LIMIT 1"#,
    )
    .bind(user_id)
    .bind(db.tenant_uuid())
    .bind(vs_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("resolve_mcp_workspace: {e}");
        ApiError::internal("failed to resolve workspace access")
    })?;
    Ok(row.map(|(id,)| id))
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)] // expires_at + consumed_at returned for symmetry, ignored.
struct AuthorizationCodeRow {
    client_id: String,
    user_id: Uuid,
    virtual_server_id: Uuid,
    audience: String,
    code_challenge: String,
    redirect_uri: String,
    scope: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    post,
    path = "/api/v1/mcp/oauth/{tenant_slug}/authorize/preview",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Preview", body = AuthorizePreviewResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn authorize_preview(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizePreviewResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    // Resolved before any connection is held — see `resolve_authorize_client`.
    let client = resolve_authorize_client(&state.db, tenant_id, &body.client_id).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("authorize_preview: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;
    let proxy_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Mcp).await?;
    let (client, vs, granted_scope) =
        match validate_authorize_request(&mut db, &proxy_origin, &body, client).await {
            Ok(resolved) => resolved,
            Err(AuthorizeRejection::Render(e)) => return Err(e),
            Err(AuthorizeRejection::Redirect { error, description }) => {
                return Ok(Json(AuthorizePreviewResponse::Redirect {
                    redirect_to: authorization_error_redirect(
                        &body.redirect_uri,
                        error,
                        &description,
                        &body.state,
                        &issuer,
                    ),
                }));
            }
        };
    // The subject must reach this server through a workspace they belong to.
    // Checked here as well as on approve so a non-member is told before being
    // shown an Approve button that cannot work — rendered, not redirected, for
    // the reason spelled out at the approve site.
    if resolve_mcp_workspace(&mut db, portal.user_id, vs.id)
        .await?
        .is_none()
    {
        return Err(ApiError::forbidden(
            "no workspace grants you access to this MCP server",
        )
        .code(ApiErrorCode::PermissionDenied));
    }

    Ok(Json(AuthorizePreviewResponse::Ok {
        client_name: client.name,
        virtual_server_name: vs.name,
        virtual_server_slug: vs.slug,
        virtual_server_id: vs.id,
        scope: granted_scope,
    }))
}

/// The subject refused the grant (RFC 6749 §4.1.2.1 `access_denied`).
///
/// A denial is an authorization *response*, so this server builds it — the same
/// function that builds every other error redirect, carrying the same
/// byte-exact RFC 9207 `iss` an approval would. Assembling it in the browser
/// tier instead meant a second implementation of one wire format, kept in step
/// by nothing, and the consent page needing to be told this server's identity
/// so it could quote it back.
///
/// The full parameter bundle is re-validated first, and that is not ceremony:
/// without it an attacker could craft an authorize URL naming a real client
/// with an attacker-controlled `redirect_uri`, bait a Deny click, and bounce the
/// visitor anywhere from a page wearing the tenant's own branding. No token
/// leaks — but the bounce itself is the phishing primitive. A bundle that fails
/// to validate is refused inline rather than redirected.
#[utoipa::path(
    post,
    path = "/api/v1/mcp/oauth/{tenant_slug}/authorize/deny",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Where to send the user-agent", body = AuthorizeApproveResponse),
        (status = 400, description = "Parameters did not validate", body = ApiErrorResponse),
        (status = 401, description = "No portal session", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn authorize_deny(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeApproveResponse>, ApiError> {
    let (_portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    let client = resolve_authorize_client(&state.db, tenant_id, &body.client_id).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("authorize_deny: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;
    let proxy_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Mcp).await?;

    // Either outcome of validation proves the redirect URI belongs to this
    // client's registration — a `Redirect` rejection is this server saying
    // "deliver that error there" — so both are safe to bounce to. Only a
    // `Render` rejection, which means the client or its URI could not be
    // vouched for at all, stays on our page.
    match validate_authorize_request(&mut db, &proxy_origin, &body, client).await {
        Ok(_) => {}
        Err(AuthorizeRejection::Render(e)) => return Err(e),
        Err(AuthorizeRejection::Redirect { error, description }) => {
            return Ok(Json(AuthorizeApproveResponse {
                redirect_to: authorization_error_redirect(
                    &body.redirect_uri,
                    error,
                    &description,
                    &body.state,
                    &issuer,
                ),
            }));
        }
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
    path = "/api/v1/mcp/oauth/{tenant_slug}/authorize/approve",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Approved — redirect to client", body = AuthorizeApproveResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 401, description = "Portal session required", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn authorize_approve(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeApproveResponse>, ApiError> {
    let (portal, tenant_id) =
        require_tenant_portal_session(&state.db, &tenant_slug, &headers).await?;
    // Resolved before any connection is held — see `resolve_authorize_client`.
    let client = resolve_authorize_client(&state.db, tenant_id, &body.client_id).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("authorize_approve: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;
    let proxy_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;
    // RFC 9207: name the server that answered. A client holding grants from
    // several authorization servers uses this to tell which one this code came
    // from, which is what closes the mix-up attack where a compromised server
    // returns a code minted by a different one. Resolved up front because an
    // error redirect has to carry the same `iss` a success would.
    let issuer = surface_issuer(&state.db, tenant_id, &tenant_slug, OauthSurface::Mcp).await?;

    // A request that validated at preview can stop validating before the user
    // clicks Approve — a virtual server flipped out of spec-OAuth, a CIMD
    // document rotated. RFC 6749 §4.1.2.1 still applies: deliver it to the
    // client rather than stranding it.
    let (client, vs, granted_scope) =
        match validate_authorize_request(&mut db, &proxy_origin, &body, client).await {
            Ok(resolved) => resolved,
            Err(AuthorizeRejection::Render(e)) => return Err(e),
            Err(AuthorizeRejection::Redirect { error, description }) => {
                return Ok(Json(AuthorizeApproveResponse {
                    redirect_to: authorization_error_redirect(
                        &body.redirect_uri,
                        error,
                        &description,
                        &body.state,
                        &issuer,
                    ),
                }));
            }
        };

    // The subject must reach this server through a workspace they belong to —
    // fail at consent rather than after the redirect. The token mint re-resolves
    // (membership may change before /token), so this is fast-feedback, not the
    // sole gate.
    //
    // Deliberately rendered, not redirected, unlike the validation failures
    // above. This is not a malformed request — it is a statement about *this
    // user*, and only they (or their admin) can act on it. A redirect would
    // hand the client an `access_denied` whose reason the person standing at
    // the consent page never sees.
    if resolve_mcp_workspace(&mut db, portal.user_id, vs.id)
        .await?
        .is_none()
    {
        return Err(ApiError::forbidden(
            "no workspace grants you access to this MCP server",
        )
        .code(ApiErrorCode::PermissionDenied));
    }

    let scope = granted_scope;
    let audience = audience_for_slug(&proxy_origin, &vs.slug);
    let code = generate_authorization_code();
    let expires_at = Utc::now() + Duration::seconds(AUTH_CODE_TTL_SECS);

    sqlx::query(
        r#"INSERT INTO oauth_authorization_codes
               (code, tenant_id, surface, client_id, user_id, virtual_server_id,
                audience, code_challenge, redirect_uri, scope, expires_at)
           VALUES ($1, $2, 'mcp', $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(&code)
    .bind(db.tenant_uuid())
    .bind(&client.client_id)
    .bind(portal.user_id)
    .bind(vs.id)
    .bind(&audience)
    .bind(&body.code_challenge)
    .bind(&body.redirect_uri)
    .bind(&scope)
    .bind(expires_at)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("authorize_approve: insert code: {e}");
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
// Public: /register (RFC 7591 dynamic client registration)
// ===========================================================================
//
// Spec-conforming MCP clients (Claude Desktop, Cursor, ...) prefer to register
// themselves rather than ask the operator to copy a client_id by hand. RFC 7591
// gives them a self-service path: POST a JSON body with their `client_name`
// and `redirect_uris[]`, get back an opaque `client_id` they can use against
// `/authorize` and `/token`.
//
// We implement the *open* variant — no initial bearer required. This is
// the easiest end-to-end story for native MCP clients but means anyone who can
// reach the endpoint can register a client. Operators who don't want that can
// gate the endpoint at the reverse proxy and rely on manual client management
// via the admin UI. A future iteration can wire `initial_access_token` from
// RFC 7591 §3 if a tenant wants stricter control without the proxy gate.
//
// CIMD (Client ID Metadata Document) extends DCR by letting the *client*
// publish its metadata at a stable HTTPS URL and pass that URL as the
// `client_id`. Two ways in, both resolving the live document on each
// /authorize call so a client can rotate its redirect URIs without telling us:
// a client that simply presents the URL (no registration at all — see
// `resolve_authorize_client`), and a row registered here with
// `client_id_metadata_url` set, which an operator uses to pin a CIMD client to
// a name and an audit trail.

#[derive(Deserialize, ToSchema)]
pub struct DynamicRegistrationRequest {
    /// Optional human-readable client name. RFC 7591 calls this optional;
    /// we substitute `"unnamed-dcr-client"` when absent so the admin UI has
    /// something to render.
    pub client_name: Option<String>,

    /// Required. At least one URI; each must be `https://` or
    /// `http://localhost*` per the existing redirect-URI policy.
    pub redirect_uris: Vec<String>,

    /// CIMD opt-in. When present, we ignore `redirect_uris` for storage,
    /// stash the URL on the row, and resolve fresh on each /authorize call.
    /// The URL is SSRF-validated immediately (rejects loopback/RFC1918/IMDS).
    pub client_id_metadata_url: Option<String>,

    /// Spec fields we accept but don't act on yet — present to keep RFC 7591
    /// compliant clients happy. `grant_types` MUST contain
    /// `authorization_code` (the only grant we support) when present;
    /// `response_types` MUST contain `code`.
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DynamicRegistrationResponse {
    pub client_id: String,
    pub client_name: String,
    #[schema(value_type = Vec<String>)]
    pub redirect_uris: serde_json::Value,
    pub registration_method: String,
    pub client_id_metadata_url: Option<String>,
    /// `client_secret` is omitted for public clients (RFC 7591 §3.2.1 lets
    /// us return only the fields we set) — our token endpoint uses
    /// `none` auth (PKCE-only).
    pub token_endpoint_auth_method: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/mcp/oauth/{tenant_slug}/register",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body = DynamicRegistrationRequest,
    responses(
        (status = 201, description = "Registered", body = DynamicRegistrationResponse),
        (status = 400, description = "Invalid client metadata, or no such tenant (RFC 7591 §3.2.2 gives registration errors one status)", body = OauthErrorResponse),
        (status = 429, description = "Per-tenant client cap reached", body = OauthErrorResponse),
    ),
)]
pub async fn register_dynamic_client(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthJson(body): OauthJson<DynamicRegistrationRequest>,
) -> Result<(axum::http::StatusCode, Json<DynamicRegistrationResponse>), OauthError> {
    // RFC 7591 spec compliance — only authorization_code + code response_type
    // make sense here. Anything else is an explicit error so spec-aware
    // clients fail fast rather than discovering it at /token time.
    if let Some(grants) = &body.grant_types
        && !grants.is_empty()
        && !grants.iter().any(|g| g == "authorization_code")
    {
        return Err(OauthError::invalid_client_metadata(
            "grant_types must include 'authorization_code'",
        ));
    }
    if let Some(responses) = &body.response_types
        && !responses.is_empty()
        && !responses.iter().any(|r| r == "code")
    {
        return Err(OauthError::invalid_client_metadata(
            "response_types must include 'code'",
        ));
    }
    if let Some(method) = &body.token_endpoint_auth_method
        && method != "none"
    {
        return Err(OauthError::invalid_client_metadata(
            "only token_endpoint_auth_method=none is supported (PKCE-only public clients)",
        ));
    }

    let registration_method = if body.client_id_metadata_url.is_some() {
        "cimd"
    } else {
        "dcr"
    };

    // Validate inputs depending on registration mode. Nothing here reaches the
    // network — the CIMD document is fetched further down, after the tenant
    // exists and the abuse gates have passed, so an anonymous POST naming a
    // tenant that does not exist cannot make this deployment issue an outbound
    // request to a host of the caller's choosing.
    let cimd_candidate = match body.client_id_metadata_url.as_deref() {
        Some(url) => Some(check_cimd_url(url)?),
        None => {
            if body.redirect_uris.is_empty() {
                return Err(OauthError::new(
                    OauthErrorCode::InvalidRedirectUri,
                    "redirect_uris required (or use client_id_metadata_url)",
                ));
            }
            for uri in &body.redirect_uris {
                if !validate_redirect_uri(uri) {
                    return Err(OauthError::new(
                        OauthErrorCode::InvalidRedirectUri,
                        format!("redirect URI {uri:?} must be https://, http://localhost*, or a private-use scheme like com.example.app:/cb"),
                    ));
                }
            }
            None
        }
    };

    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;

    // Ahead of the abuse gates below: it is the cheapest refusal, it is the
    // specific one, and it discloses nothing the tenant's own discovery
    // document does not already state.
    if cimd_candidate.is_some() && !cimd_enabled(&state.db, tenant_id).await? {
        return Err(OauthError::invalid_client_metadata(
            "client_id_metadata_url is not accepted by this tenant",
        ));
    }

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("register_dynamic_client: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    // Abuse controls. Public DCR is convenient for spec-conforming MCP clients
    // (they self-register without operator hand-off) but the endpoint is
    // unauthenticated by RFC 7591, so anyone who can reach it can fill the
    // table. Two cheap mitigations:
    //   1. Require the tenant to have at least one OAuth-enabled virtual
    //      server. If they haven't opted any VS into spec-OAuth, DCR is
    //      pointless anyway — registered clients have nowhere to authenticate.
    //   2. Cap the per-tenant `mcp_oauth_clients` row count. Generous default
    //      (1000) but operator-tunable via `MCP_OAUTH_DCR_PER_TENANT_CAP` for
    //      large tenants who legitimately register many spec-OAuth clients.
    let oauth_enabled_vs: Option<i64> = sqlx::query_scalar(
        "SELECT 1::bigint FROM mcp_virtual_servers \
         WHERE oauth_enabled = true LIMIT 1",
    )
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("register_dynamic_client: vs probe: {e}");
        ApiError::internal("failed to check OAuth-enabled virtual servers")
    })?;
    if oauth_enabled_vs.is_none() {
        // Not a defect in the client's metadata — the server is refusing. RFC
        // 7591 names no code for that, so this borrows RFC 6749's
        // `access_denied` rather than mislabelling good metadata as bad.
        return Err(OauthError::new(
            OauthErrorCode::AccessDenied,
            "this tenant has no OAuth-enabled virtual servers — \
             enable spec OAuth on at least one VS before registering clients",
        ));
    }

    let per_tenant_client_cap = crate::settings::admin_settings().mcp_oauth_dcr_per_tenant_cap;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM mcp_oauth_clients")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("register_dynamic_client: count: {e}");
            ApiError::internal("failed to count OAuth clients")
        })?;
    if existing >= per_tenant_client_cap {
        // 429, but a stored-resource quota — NOT a request-rate throttle, hence
        // the explicit status: RFC 7591 §3.2.2 fixes 400 only for the errors it
        // names, and this is not one of them.
        //
        // It stays audited because `security_audit_mw` skips only a body whose
        // `error.code` reads `rate_limit_exceeded`, and an RFC error body has no
        // `error.code` at all — `error` is a bare string. That is the whole
        // mechanism now; do NOT "restore" an `ApiErrorCode` here on the belief
        // that a distinct code is what keeps the row, because reintroducing the
        // `ApiErrorResponse` shape is what would put it back in range of the
        // skip.
        return Err(OauthError::new(
            OauthErrorCode::AccessDenied,
            format!(
                "per-tenant cap of {per_tenant_client_cap} OAuth clients reached — \
                 prune unused clients via the admin UI"
            ),
        )
        .with_status(axum::http::StatusCode::TOO_MANY_REQUESTS));
    }

    // Only now, with a real tenant that has opted into spec OAuth and room
    // under its cap, is it worth going to the network. Resolving eagerly still
    // means a registration fails here rather than at the first /authorize —
    // it just no longer happens on behalf of a caller who cleared no gate.
    let cimd_url = match cimd_candidate {
        Some(validated) => {
            // Freshen the trusted-CA cache first, for the same per-replica
            // reason `resolve_authorize_client` does.
            crate::custom_ca::refresh_from_db(&state.db).await;
            let resolved = resolve_cimd_document(validated.as_str()).await?.redirect_uris;
            if resolved.is_empty() {
                return Err(OauthError::new(
                    OauthErrorCode::InvalidClientMetadata,
                    "CIMD document had no redirect_uris",
                ));
            }
            Some(validated.to_string())
        }
        None => None,
    };

    let client_id = generate_client_id();
    let id = Uuid::new_v4();
    let name = body
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        // Caller-chosen text in a `text` column, which refuses U+0000.
        .map(|s| streamscope_core::pg_text::storable_str(s).into_owned())
        .unwrap_or_else(|| "unnamed-dcr-client".to_string());
    // CIMD rows still need a non-null redirect_uris column. Store an empty
    // array — `validate_authorize_request` consults the CIMD document instead
    // when `client_id_metadata_url` is set.
    let redirect_uris_for_storage = if cimd_url.is_some() {
        serde_json::Value::Array(vec![])
    } else {
        serde_json::Value::Array(
            body.redirect_uris
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        )
    };

    sqlx::query(
        r#"INSERT INTO mcp_oauth_clients
               (id, tenant_id, client_id, name, redirect_uris, registration_method,
                client_id_metadata_url, created_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)"#,
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .bind(&client_id)
    .bind(&name)
    .bind(&redirect_uris_for_storage)
    .bind(registration_method)
    .bind(&cimd_url)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("register_dynamic_client insert: {e}");
        ApiError::internal("failed to register client")
    })?;


    Ok((
        axum::http::StatusCode::CREATED,
        Json(DynamicRegistrationResponse {
            client_id,
            client_name: name,
            redirect_uris: redirect_uris_for_storage,
            registration_method: registration_method.to_string(),
            client_id_metadata_url: cimd_url,
            token_endpoint_auth_method: "none".to_string(),
        }),
    ))
}

/// The fields we read out of a client's published metadata document.
struct CimdDocument {
    /// Shown on the consent page. Absent in many real documents, so the caller
    /// falls back to the URL rather than treating it as required.
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

/// Fetch a CIMD document. Used by /register (to fail fast when the URL is
/// unreachable), by /authorize/{preview,approve} for a registered CIMD client
/// (to honor URI rotations on each call), and to resolve a bare URL presented
/// as a `client_id`.
///
/// We fetch with a 5s timeout, cap the body at 64 KiB, parse as JSON, and
/// require a top-level `redirect_uris: [string]` field. When the document
/// declares its own `client_id` it must equal the URL it was served from —
/// otherwise a document could claim to speak for a client it does not own.
/// Documents that omit the field are accepted; the URL is the identity either
/// way.
///
/// **DNS-rebinding defense.** Delegates to
/// [`streamscope_mcp_auth::ssrf::resolve_and_pin_addrs`], which scheme-checks
/// the URL, DNS-resolves it, refuses if any resolved record is internal,
/// and returns the verified [`SocketAddr`] list. We then pin reqwest to that
/// list via `resolve_to_addrs` so the connection cannot be redirected to a
/// different IP between the SSRF check and the connect.
///
/// **Redirects are refused** (`Policy::none()`): `resolve_to_addrs` pins only
/// the *initial* host, so a 3xx hop to a different host would resolve through
/// the OS resolver unguarded — letting a public CIMD URL bounce the fetch into
/// an internal address. A CIMD document is served at a stable URL; a redirect
/// is treated as a fetch failure.
async fn resolve_cimd_document(url: &str) -> Result<CimdDocument, ApiError> {
    // One deadline over the whole resolve-and-fetch. The per-hop reqwest
    // timeouts do not cover the DNS lookup, which has none of its own, so
    // without this an unresolvable host bounds the call only by the resolver's
    // own patience — and the registered-CIMD path runs this while a pool
    // connection is held.
    match tokio::time::timeout(std::time::Duration::from_secs(10), resolve_cimd_inner(url)).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(url = %url, "CIMD fetch timed out");
            Err(ApiError::bad_request("CIMD fetch failed")
                .code(ApiErrorCode::McpOauthCimdFetchFailed))
        }
    }
}

async fn resolve_cimd_inner(url: &str) -> Result<CimdDocument, ApiError> {
    use streamscope_mcp_auth::ssrf::resolve_and_pin_addrs_for;

    // A CIMD URL is the lowest-trust URL on the MCP surface — it arrives as a
    // `client_id`, and `/register` is unauthenticated by RFC 7591 — so it gets
    // its own egress list rather than riding the MCP one. Reusing the `mcp`
    // list here would turn "I trust my own MCP upstreams" into "anonymous
    // callers may probe my private network".
    let egress = CIMD_EGRESS;
    let (parsed, host, addrs) = resolve_and_pin_addrs_for(url, egress)
        .await
        .map_err(|e| {
            tracing::warn!(url = %url, "CIMD pre-fetch SSRF check failed: {e}");
            ApiError::bad_request("CIMD URL rejected by SSRF guard")
                .code(ApiErrorCode::McpOauthCimdFetchFailed)
        })?;

    let client = streamscope_core::tls::add_custom_roots(
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .resolve_to_addrs(host.as_str(), &addrs)
            // No redirects: the addr pin covers only `host`, so a 3xx to another
            // host would escape the SSRF check. A 3xx response falls through to
            // the non-success branch below and surfaces as a fetch failure.
            .redirect(reqwest::redirect::Policy::none()),
        crate::custom_ca::current().as_deref(),
    )
    .build()
        .map_err(|e| {
            tracing::error!("CIMD client build: {e}");
            ApiError::internal("failed to build CIMD HTTP client")
        })?;

    let resp = client.get(parsed.as_str()).send().await.map_err(|e| {
        tracing::warn!(url = %url, "CIMD fetch failed: {e}");
        ApiError::bad_request("CIMD fetch failed").code(ApiErrorCode::McpOauthCimdFetchFailed)
    })?;

    if !resp.status().is_success() {
        // The status is logged, not returned: `/register` is unauthenticated,
        // so echoing it back would make this endpoint a port/host scanner that
        // reports what it found.
        tracing::warn!(url = %url, status = %resp.status(), "CIMD URL returned a non-success status");
        return Err(
            ApiError::bad_request("CIMD fetch failed").code(ApiErrorCode::McpOauthCimdFetchFailed)
        );
    }

    // Cap at strictly less than 64 KiB. Real CIMD docs are typically 1-2 KB.
    //
    // **Read streaming and abort at the cap** — buffering the whole body first
    // and measuring after would let a hostile document host push unbounded
    // bytes into memory before the check ever ran, on an endpoint that needs no
    // credential to reach.
    const CIMD_BODY_CAP: usize = 64 * 1024; // 65 536 bytes
    let mut bytes: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        tracing::warn!("CIMD body read: {e}");
        ApiError::bad_request("CIMD body unreadable").code(ApiErrorCode::McpOauthCimdFetchFailed)
    })? {
        if bytes.len() + chunk.len() >= CIMD_BODY_CAP {
            return Err(ApiError::bad_request("CIMD body exceeds 64 KiB cap")
                .code(ApiErrorCode::McpOauthCimdFetchFailed));
        }
        bytes.extend_from_slice(&chunk);
    }

    let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        tracing::warn!("CIMD parse: {e}");
        ApiError::bad_request("CIMD body is not valid JSON")
            .code(ApiErrorCode::McpOauthCimdInvalidMetadata)
    })?;

    // A document that names a `client_id` must name the URL it was served
    // from. Without this a document hosted anywhere could assert someone
    // else's identity, and the consent page would render that borrowed name.
    //
    // Compared against the URL we actually fetched, which `Url::parse`
    // normalized (empty path → `/`, host lowercased). A document correctly
    // declaring its own canonical URL would otherwise read as an impostor
    // whenever the client spelled its `client_id` any other way.
    if let Some(declared) = doc.get("client_id").and_then(|v| v.as_str())
        && declared != parsed.as_str()
    {
        tracing::warn!(url = %url, "CIMD document declares a different client_id");
        return Err(
            ApiError::bad_request("CIMD document's client_id does not match its URL")
                .code(ApiErrorCode::McpOauthCimdInvalidMetadata),
        );
    }

    let arr = doc
        .get("redirect_uris")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ApiError::bad_request("CIMD document missing redirect_uris array")
                .code(ApiErrorCode::McpOauthCimdInvalidMetadata)
        })?;

    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v.as_str().ok_or_else(|| {
            ApiError::bad_request("CIMD redirect_uris contains non-string entry")
                .code(ApiErrorCode::McpOauthCimdInvalidMetadata)
        })?;
        if !validate_redirect_uri(s) {
            return Err(ApiError::bad_request(format!(
                "CIMD redirect URI {s:?} must be https://, http://localhost*, or a private-use scheme like com.example.app:/cb"
            ))
            .code(ApiErrorCode::McpOauthRedirectUriInvalid));
        }
        out.push(s.to_string());
    }
    Ok(CimdDocument {
        client_name: doc
            .get("client_name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.trim().is_empty()),
        redirect_uris: out,
    })
}

// ===========================================================================
// Public: /token (PKCE-protected exchange)
// ===========================================================================

/// Refresh-token claims. Mirrors `McpAccessClaims` so we can sign with the
/// same per-tenant key, but carries `typ = "refresh"` so the /token handler
/// refuses to swap roles. `original_jti` ties the refresh token back to a
/// row in `mcp_issued_tokens`; rotating issues a new pair and revokes
/// `original_jti` so the old refresh can never be reused.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpRefreshClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
    pub typ: String,
    /// JTI of the access token this refresh token was first paired with.
    ///
    /// Rotation ignores it — that path looks up the refresh token's own `jti`.
    /// Revocation does not: RFC 7009 takes the pair down together, so revoking
    /// a refresh token without this would leave its live access bearer behind.
    pub original_jti: String,
    pub surface: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

impl super::oauth_common::RefreshClaims for McpRefreshClaims {
    fn surface(&self) -> &str {
        &self.surface
    }
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/mcp/oauth/{tenant_slug}/token",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body(content = TokenRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Issued access token", body = TokenResponse),
        (status = 400, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
        (status = 401, description = "RFC 6749 §5.2 error", body = OauthErrorResponse),
    ),
)]
pub async fn token_endpoint(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthForm(body): OauthForm<TokenRequest>,
) -> Result<TokenReply, OauthError> {
    let Json(token) = match body.grant_type.as_str() {
        "authorization_code" => token_authorization_code(state, tenant_slug, body).await?,
        "refresh_token" => token_refresh(state, tenant_slug, body).await?,
        other => {
            return Err(OauthError::unsupported_grant_type(format!(
                "unsupported grant_type `{other}`"
            )))
        }
    };
    Ok(token_ok(token))
}

/// RFC 8707 §2.2: honour a `resource` the client asked for, or refuse.
///
/// The metadata advertises `resource_parameter_supported`, so a client that
/// sends one is entitled to have it mean something. Dropping it silently would
/// hand back a token scoped to a different server than the client believes it
/// asked for — and being wrong about which resource holds your token is exactly
/// what audience binding exists to prevent.
///
/// Applies to **every** grant that mints an access token, refresh included: a
/// client that sends `resource` on refresh (the MCP TypeScript SDK does) would
/// otherwise get the check on its first token and not on any that follow.
fn verify_requested_resource(requested: Option<&str>, audience: &str) -> Result<(), ApiError> {
    if let Some(requested) = requested
        && requested != audience
    {
        tracing::warn!(
            %requested, %audience,
            "mcp oauth: token requested for a resource the grant does not cover"
        );
        return Err(ApiError::bad_request(
            "the requested `resource` is not the one this grant was issued for",
        )
        .code(ApiErrorCode::McpOauthInvalidResource));
    }
    Ok(())
}

async fn token_authorization_code(
    state: Arc<AdminState>,
    tenant_slug: String,
    body: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let code = body.code.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `code`")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    let body_redirect_uri = body.redirect_uri.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `redirect_uri`")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    let code_verifier = body.code_verifier.ok_or_else(|| {
        ApiError::bad_request("authorization_code grant requires `code_verifier`")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    let tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("token: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    // Atomically consume the code in one statement so concurrent /token calls
    // can't both pass the "not yet consumed" check. The RETURNING clause
    // gives us back exactly the row we marked, or no row if some other
    // request already won the race (or the code was never valid).
    let row: Option<AuthorizationCodeRow> = sqlx::query_as(
        r#"UPDATE oauth_authorization_codes
              SET consumed_at = NOW()
            WHERE code = $1
              AND surface = 'mcp'
              AND consumed_at IS NULL
              AND expires_at > NOW()
            RETURNING client_id, user_id, virtual_server_id, audience,
                      code_challenge, redirect_uri, scope,
                      expires_at, consumed_at"#,
    )
    .bind(&code)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("token: consume code: {e}");
        ApiError::internal("failed to consume authorization code")
    })?;

    let Some(AuthorizationCodeRow {
        client_id: stored_client_id,
        user_id,
        virtual_server_id,
        audience,
        code_challenge,
        redirect_uri,
        scope,
        expires_at: _,
        consumed_at: _,
    }) = row
    else {
        return Err(
            ApiError::bad_request("invalid, expired, or already-used authorization code")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    };
    if stored_client_id != body.client_id {
        return Err(
            ApiError::bad_request("client_id mismatch")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    }
    if redirect_uri != body_redirect_uri {
        return Err(
            ApiError::bad_request("redirect_uri mismatch")
                .code(ApiErrorCode::McpOauthRedirectUriMismatch),
        );
    }
    verify_requested_resource(body.resource.as_deref(), &audience)?;
    if !verify_s256_challenge(&code_verifier, &code_challenge) {
        return Err(
            ApiError::bad_request("PKCE verification failed")
                .code(ApiErrorCode::McpOauthInvalidVerifier),
        );
    }

    // Re-resolve the access-granting workspace (membership may have changed
    // since the code was issued); reject if the subject no longer has a path.
    let workspace_id = resolve_mcp_workspace(&mut db, user_id, virtual_server_id)
        .await?
        .ok_or_else(|| {
            ApiError::forbidden("no workspace grants access to this MCP server")
                .code(ApiErrorCode::PermissionDenied)
        })?;

    // A fresh consent opens a new chain; every pair rotated from it carries the
    // same id. That is what lets a replayed refresh token retire the whole
    // lineage rather than the single row presented.
    let login_chain = Uuid::new_v4();

    // Mint the JWT.
    let ring = keyring().ok_or_else(|| {
        tracing::error!("token: AUTH_SECRET unavailable");
        crate::routes::no_signing_key()
    })?;
    let now = Utc::now();
    let expires_at = now + Duration::seconds(ACCESS_TOKEN_TTL_SECS);
    let jti = new_jti();
    let claims = McpAccessClaims {
        sub: user_id.to_string(),
        aud: audience.clone(),
        iss: TOKEN_ISSUER.to_string(),
        tenant_id: tenant_id.to_string(),
        workspace_id: workspace_id.to_string(),
        virtual_server_id: virtual_server_id.to_string(),
        client_id: stored_client_id.clone(),
        scope: scope.clone(),
        jti: jti.clone(),
        typ: ACCESS_TOKEN_TYP.to_string(),
        surface: SURFACE_MCP.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: expires_at.timestamp(),
    };
    let token = encode_access_token(&claims, &ring).map_err(|e| {
        tracing::error!("token: encode JWT: {e}");
        ApiError::internal("failed to issue token")
    })?;

    let jti_uuid = Uuid::parse_str(&jti).map_err(|e| {
        tracing::error!("token: parse jti uuid: {e}");
        ApiError::internal("internal error")
    })?;
    sqlx::query(
        r#"INSERT INTO oauth_issued_tokens
               (jti, tenant_id, surface, user_id, client_id, virtual_server_id,
                audience, scope, expires_at, login_chain)
           VALUES ($1, $2, 'mcp', $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(jti_uuid)
    .bind(db.tenant_uuid())
    .bind(user_id)
    .bind(&stored_client_id)
    .bind(virtual_server_id)
    .bind(&audience)
    .bind(&scope)
    .bind(expires_at)
    .bind(login_chain)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("token: persist issued: {e}");
        ApiError::internal("failed to record issued token")
    })?;

    let (refresh_token, refresh_expires_in) = mint_refresh_token(
        &mut db,
        &ring,
        &claims,
        &jti,
        virtual_server_id,
        login_chain,
        now,
    )
    .await?;


    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope,
        refresh_token,
        refresh_token_expires_in: refresh_expires_in,
    }))
}

/// Refresh-token grant: validate the presented refresh JWT, look up its
/// `jti` row, refuse if revoked / expired, then rotate (issue a new
/// access + refresh pair, revoke the old refresh).
async fn token_refresh(
    state: Arc<AdminState>,
    tenant_slug: String,
    body: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let presented = body.refresh_token.ok_or_else(|| {
        ApiError::bad_request("refresh_token grant requires `refresh_token`")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;

    let ring = keyring().ok_or_else(|| {
        tracing::error!("token: AUTH_SECRET unavailable");
        crate::routes::no_signing_key()
    })?;
    let presented_claims = decode_refresh_claims(&presented, &ring).map_err(|_| {
        ApiError::bad_request("invalid or expired refresh token")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    if presented_claims.typ != REFRESH_TOKEN_TYP {
        return Err(
            ApiError::bad_request("not a refresh token")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    }
    if presented_claims.client_id != body.client_id {
        return Err(
            ApiError::bad_request("client_id mismatch")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    }

    // Resolve the URL-path tenant slug separately, then refuse the request
    // if the JWT's tenant_id doesn't match — the slug-only metadata
    // endpoint is unauthenticated, so we treat the JWT's tenant_id as the
    // load-bearing identifier and use the slug only as a sanity check.
    let url_tenant_id = resolve_tenant_id(&state.db, &tenant_slug).await?;
    let token_tenant_id = Uuid::parse_str(&presented_claims.tenant_id).map_err(|_| {
        ApiError::bad_request("invalid refresh token")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    if token_tenant_id != url_tenant_id {
        return Err(
            ApiError::bad_request("refresh token does not belong to this tenant")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    }
    let mut db = TenantConn::acquire(&state.db, TenantId::from_credential(token_tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("refresh: tdb: {e}");
            super::db_read_error(&e, "the database did not answer")
        })?;

    let presented_jti = Uuid::parse_str(&presented_claims.jti).map_err(|_| {
        ApiError::bad_request("invalid refresh token")
            .code(ApiErrorCode::McpOauthInvalidGrant)
    })?;
    // Atomically revoke the presented refresh-jti — same race-safety pattern
    // as the authorization-code consume path. If RETURNING is empty, the
    // refresh was already used / revoked / never issued.
    let revoke_row: Option<RotatedRow> = sqlx::query_as(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW()
            WHERE jti = $1
              AND surface = 'mcp'
              AND revoked_at IS NULL
              AND expires_at > NOW()
            RETURNING tenant_id, user_id, client_id, virtual_server_id, audience, scope, login_chain"#,
    )
    .bind(presented_jti)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("refresh: revoke old jti: {e}");
        ApiError::internal("failed to revoke refresh token")
    })?;

    let Some(RotatedRow {
        tenant_id: stored_tenant_id,
        user_id,
        client_id: stored_client_id,
        virtual_server_id,
        audience,
        scope,
        login_chain: chain,
    }) = revoke_row
    else {
        // RFC 9700 §4.14.2. Nothing rotated — but the reason matters. A token
        // that was *already rotated* and has not yet expired means two parties
        // hold it: whoever rotated it first, and whoever is presenting it now.
        // Refusing this one request leaves the winner's descendants alive, and
        // the loser's client simply re-consents onto a fresh chain and reports
        // itself healthy — so the theft ends with the attacker holding the only
        // working credential and nobody alerted. Retire the whole lineage.
        let tenant = db.tenant_uuid();
        retire_chain_on_reuse(db.conn(), tenant, presented_jti, SURFACE_MCP).await?;
        return Err(
            ApiError::bad_request("refresh token revoked, expired, or not recognised")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    };
    if stored_tenant_id != token_tenant_id || stored_client_id != body.client_id {
        return Err(
            ApiError::bad_request("refresh token claims mismatch")
                .code(ApiErrorCode::McpOauthInvalidGrant),
        );
    }
    verify_requested_resource(body.resource.as_deref(), &audience)?;

    // Continue the presented token's lineage — every row has one, so a rotation
    // never starts a fresh chain. Starting one here would silently orphan the
    // grant from the revoke that reaches it.
    let login_chain = chain;

    // The subject must still be somebody. Rotation is what makes an MCP grant
    // outlive its access token — present a refresh token and you get another
    // hour, plus another 30 days of refresh — so without this a disabled user
    // renews forever.
    let subject_active: Option<bool> = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("refresh: subject lookup: {e}");
            ApiError::internal("failed to verify account")
        })?;
    if subject_active != Some(true) {
        return Err(ApiError::forbidden("account disabled").code(ApiErrorCode::PermissionDenied));
    }

    // Re-resolve the workspace on rotation so a member moved between workspaces
    // (or stripped of access) gets a token reflecting current state.
    let workspace_id = resolve_mcp_workspace(&mut db, user_id, virtual_server_id)
        .await?
        .ok_or_else(|| {
            ApiError::forbidden("no workspace grants access to this MCP server")
                .code(ApiErrorCode::PermissionDenied)
        })?;

    // Issue a fresh access JWT.
    let now = Utc::now();
    let access_expires = now + Duration::seconds(ACCESS_TOKEN_TTL_SECS);
    let new_access_jti = new_jti();
    let access_claims = McpAccessClaims {
        sub: user_id.to_string(),
        aud: audience.clone(),
        iss: TOKEN_ISSUER.to_string(),
        tenant_id: token_tenant_id.to_string(),
        workspace_id: workspace_id.to_string(),
        virtual_server_id: virtual_server_id.to_string(),
        client_id: stored_client_id.clone(),
        scope: scope.clone(),
        jti: new_access_jti.clone(),
        typ: ACCESS_TOKEN_TYP.to_string(),
        surface: SURFACE_MCP.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: access_expires.timestamp(),
    };
    let access_token = encode_access_token(&access_claims, &ring).map_err(|e| {
        tracing::error!("refresh: encode access: {e}");
        ApiError::internal("failed to issue token")
    })?;

    let new_access_jti_uuid = Uuid::parse_str(&new_access_jti).map_err(|e| {
        tracing::error!("refresh: parse new jti: {e}");
        ApiError::internal("internal error")
    })?;
    sqlx::query(
        r#"INSERT INTO oauth_issued_tokens
               (jti, tenant_id, surface, user_id, client_id, virtual_server_id,
                audience, scope, expires_at, login_chain)
           VALUES ($1, $2, 'mcp', $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(new_access_jti_uuid)
    .bind(token_tenant_id)
    .bind(user_id)
    .bind(&stored_client_id)
    .bind(virtual_server_id)
    .bind(&audience)
    .bind(&scope)
    .bind(access_expires)
    .bind(login_chain)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("refresh: persist new access: {e}");
        ApiError::internal("failed to record issued token")
    })?;

    let (new_refresh_token, refresh_expires_in) = mint_refresh_token(
        &mut db,
        &ring,
        &access_claims,
        &new_access_jti,
        virtual_server_id,
        login_chain,
        now,
    )
    .await?;


    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        scope,
        refresh_token: new_refresh_token,
        refresh_token_expires_in: refresh_expires_in,
    }))
}

/// Issue a refresh-token JWT and persist its `jti` in `oauth_issued_tokens`
/// so it can be revoked. Returns the encoded JWT and its TTL in seconds.
/// `virtual_server_id` is required for `surface = 'mcp'` rows; pass the
/// same one bound to the access token this refresh is paired with.
///
/// `login_chain` threads every pair a single consent produced. A fresh grant
/// starts a chain; a rotation continues the one it is rotating. That continuity
/// is what lets a replayed refresh token retire everything descended from the
/// same consent instead of only itself — see
/// [`super::oauth_common::retire_chain_on_reuse`].
async fn mint_refresh_token(
    db: &mut TenantConn,
    ring: &Keyring,
    access_claims: &McpAccessClaims,
    access_jti: &str,
    virtual_server_id: Uuid,
    login_chain: Uuid,
    now: DateTime<Utc>,
) -> Result<(String, i64), ApiError> {
    let refresh_jti = new_jti();
    let refresh_expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECS);
    let refresh_claims = McpRefreshClaims {
        sub: access_claims.sub.clone(),
        aud: access_claims.aud.clone(),
        iss: TOKEN_ISSUER.to_string(),
        tenant_id: access_claims.tenant_id.clone(),
        workspace_id: access_claims.workspace_id.clone(),
        client_id: access_claims.client_id.clone(),
        scope: access_claims.scope.clone(),
        jti: refresh_jti.clone(),
        typ: REFRESH_TOKEN_TYP.to_string(),
        original_jti: access_jti.to_string(),
        surface: SURFACE_MCP.to_string(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
        exp: refresh_expires_at.timestamp(),
    };
    let refresh_token = encode_refresh_claims(&refresh_claims, ring).map_err(|e| {
        tracing::error!("refresh: encode jwt: {e}");
        ApiError::internal("failed to issue refresh token")
    })?;
    let refresh_jti_uuid = Uuid::parse_str(&refresh_jti).map_err(|e| {
        tracing::error!("refresh: parse jti: {e}");
        ApiError::internal("internal error")
    })?;
    sqlx::query(
        r#"INSERT INTO oauth_issued_tokens
               (jti, tenant_id, surface, user_id, client_id, virtual_server_id,
                audience, scope, expires_at, login_chain)
           VALUES ($1, $2, 'mcp', $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(refresh_jti_uuid)
    .bind(db.tenant_uuid())
    .bind(Uuid::parse_str(&access_claims.sub).unwrap_or(Uuid::nil()))
    .bind(&access_claims.client_id)
    .bind(virtual_server_id)
    .bind(&access_claims.aud)
    .bind(&access_claims.scope)
    .bind(refresh_expires_at)
    .bind(login_chain)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("refresh: persist refresh jti: {e}");
        ApiError::internal("failed to record refresh token")
    })?;
    Ok((refresh_token, REFRESH_TOKEN_TTL_SECS))
}

fn encode_refresh_claims(
    claims: &McpRefreshClaims,
    ring: &Keyring,
) -> Result<String, jsonwebtoken::errors::Error> {
    super::oauth_common::encode_refresh_jwt(claims, &claims.tenant_id, ring)
}

fn decode_refresh_claims(
    token: &str,
    ring: &Keyring,
) -> Result<McpRefreshClaims, jsonwebtoken::errors::Error> {
    super::oauth_common::decode_refresh_jwt(token, ring, SURFACE_MCP)
}

// ===========================================================================
// Public: RFC 7009 token revocation
// ===========================================================================

#[derive(Deserialize, ToSchema)]
pub struct McpRevokeRequest {
    /// The token to revoke — either an access token or a refresh token. A
    /// refresh token takes its paired access token down with it.
    pub token: String,
}

/// The subset of claims revocation needs, common to both token types.
///
/// Access and refresh tokens are signed with the same per-tenant key and differ
/// only in `typ` and the refresh token's `original_jti`, so one shape decodes
/// either and the caller does not have to say which it holds — RFC 7009 §2.1
/// makes `token_type_hint` optional precisely because a client may not know.
#[derive(serde::Deserialize)]
struct RevocableClaims {
    tenant_id: String,
    jti: String,
    typ: String,
    surface: String,
    #[serde(default)]
    original_jti: Option<String>,
}

impl super::oauth_common::RefreshClaims for RevocableClaims {
    fn surface(&self) -> &str {
        &self.surface
    }
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// Decode either kind of token RFC 7009 may be handed on this surface.
///
/// **Two decoders because there are two signature algorithms, not two formats.**
/// An MCP *access* token is ES256 (its public key is published so a resource
/// server can verify it); a *refresh* token stays HS256, because only we ever
/// verify one. `token_type_hint` is optional per RFC 7009 §2.1 and a client may
/// not know which it holds, so the endpoint must try both — trying only one
/// makes the other silently un-revocable, and RFC 7009 §2.2's mandatory 200
/// for an unrecognised token means that failure reports success.
fn decode_revocable_mcp_token(token: &str, ring: &Keyring) -> Option<RevocableClaims> {
    if let Ok(access) = streamscope_mcp_auth::jwt::decode_and_verify(token, ring) {
        // `decode_and_verify` already pins `typ`, `surface` and the
        // kid-vs-payload tenant agreement.
        return Some(RevocableClaims {
            tenant_id: access.tenant_id,
            jti: access.jti,
            typ: access.typ,
            surface: access.surface,
            original_jti: None,
        });
    }
    let claims =
        super::oauth_common::decode_refresh_jwt::<RevocableClaims>(token, ring, SURFACE_MCP)
            .ok()?;
    // The refresh decoder is shape-agnostic, so the type claim is checked here.
    if claims.typ != REFRESH_TOKEN_TYP {
        return None;
    }
    Some(claims)
}

/// RFC 7009 §2.2: revocation answers 200 even for a token that is invalid,
/// expired, already revoked, or belongs to someone else. Reporting the
/// difference would turn this endpoint into an oracle for whether a token is
/// live, and the caller's goal — "this token must not work" — is satisfied
/// either way.
#[utoipa::path(
    post,
    path = "/api/v1/mcp/oauth/{tenant_slug}/revoke",
    tag = "MCP OAuth",
    params(("tenant_slug" = String, Path, description = "Tenant slug")),
    request_body(content = McpRevokeRequest, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Revoked (idempotent)", body = ActionResponse),
    ),
)]
pub async fn revoke_endpoint(
    State(state): State<Arc<AdminState>>,
    Path(tenant_slug): Path<String>,
    OauthForm(body): OauthForm<McpRevokeRequest>,
) -> Result<Json<ActionResponse>, OauthError> {
    let done = Ok(Json(ActionResponse::ok().with_message("token revoked")));

    let Some(ring) = keyring() else {
        return Err(OauthError::server_error("authentication not configured"));
    };
    let Some(claims) = decode_revocable_mcp_token(&body.token, &ring) else {
        return done;
    };
    let (Ok(url_tenant_id), Ok(token_tenant_id)) = (
        resolve_tenant_id(&state.db, &tenant_slug).await,
        Uuid::parse_str(&claims.tenant_id),
    ) else {
        return done;
    };
    if token_tenant_id != url_tenant_id {
        return done;
    }
    let Ok(jti) = Uuid::parse_str(&claims.jti) else {
        return done;
    };
    // A refresh token names the access token it was paired with; revoking one
    // without the other would leave a live bearer behind.
    let paired = claims
        .original_jti
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(jti);

    let Ok(mut db) = TenantConn::acquire(&state.db, TenantId::from_credential(token_tenant_id)).await else {
        tracing::error!("mcp revoke: failed to acquire tenant connection");
        return Err(OauthError::server_error("failed to revoke token"));
    };
    sqlx::query(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW()
            WHERE jti IN ($1, $2)
              AND surface = 'mcp'
              AND revoked_at IS NULL"#,
    )
    .bind(jti)
    .bind(paired)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("mcp revoke: {e}");
        OauthError::server_error("failed to revoke token")
    })?;

    done
}

// ===========================================================================
// Helpers
// ===========================================================================

fn generate_client_id() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "mco-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A CIMD client_id is a URL and a registered one is opaque, so the two
    /// namespaces must not overlap: a generated id that read as a URL would
    /// send `/authorize` off to fetch a document instead of reading the row.
    #[test]
    fn a_generated_client_id_is_never_mistaken_for_a_cimd_url() {
        for _ in 0..64 {
            assert!(!looks_like_cimd_client_id(&generate_client_id()));
        }
        assert!(!looks_like_cimd_client_id(
            crate::routes::cli_oauth::CLI_CLIENT_ID
        ));
    }

    /// Plaintext is refused because the document *is* the client's identity —
    /// anyone on the path could swap in their own redirect URI and collect the
    /// authorization code. An `http://` id falls through to the registry and
    /// fails there as an unknown client.
    #[test]
    fn only_an_https_url_counts_as_a_cimd_client_id() {
        assert!(looks_like_cimd_client_id(
            "https://app.example/.well-known/oauth-client"
        ));
        for not_cimd in [
            "http://app.example/.well-known/oauth-client",
            "HTTPS://app.example/doc",
            "ftp://app.example/doc",
            "app.example/doc",
            "",
        ] {
            assert!(
                !looks_like_cimd_client_id(not_cimd),
                "{not_cimd:?} must not be treated as a CIMD client id"
            );
        }
    }

    /// The `mco-` prefix is how a DCR-registered client is told apart from the
    /// static CLI client, and the identifier must stay URL-safe: it travels in
    /// an `/authorize` query string and is compared verbatim at `/token`.
    #[test]
    fn client_id_is_prefixed_and_url_safe() {
        let id = generate_client_id();
        let body = id.strip_prefix("mco-").expect("mco- prefix");
        // 24 random bytes → 32 base64url chars, unpadded.
        assert_eq!(body.len(), 32, "{id}");
        assert!(
            body.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "must be base64url with no padding: {id}"
        );
    }

    #[test]
    fn client_ids_do_not_repeat() {
        let ids: std::collections::HashSet<String> =
            (0..64).map(|_| generate_client_id()).collect();
        assert_eq!(ids.len(), 64);
    }
}
