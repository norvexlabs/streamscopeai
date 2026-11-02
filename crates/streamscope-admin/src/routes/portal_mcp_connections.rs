//! Portal — per-user OAuth connections.
//!
//! Endpoints for the portal user to manage their OAuth connections to
//! `auth_mode = per_user_oauth` upstream MCP servers:
//!
//! - `GET  /portal/mcp/connections` — list per-(virtual server, upstream)
//!   connection status (visible upstreams the user has RBAC for).
//! - `POST /portal/mcp/connections/{upstream_id}/actions/connect` — generate
//!   a PKCE-protected authorization URL + persist a `mcp_pending_authorizations`
//!   row.
//! - `GET  /portal/mcp/connections/oauth/callback` — exchange the OAuth `code`
//!   for tokens, encrypt + UPSERT into `mcp_user_credentials`, redirect back
//!   to the tenant-prefixed portal connections page.
//! - `POST /portal/mcp/connections/{upstream_id}/actions/revoke` — delete
//!   the user's stored credential (best-effort revocation_endpoint call).
//!
//! A credential change reaches every proxy in the tenant's config body (the
//! change triggers on `mcp_user_credentials`). There is no dedicated per-user
//! event channel.

use crate::db::Global;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum::{Extension, Json};
use base64::Engine;
use oauth2::{AuthorizationCode, PkceCodeVerifier, RedirectUrl};
use rand::Rng;
use serde::{Deserialize, Serialize};
use streamscope_core::mcp::oauth_client;
use streamscope_core::mcp::oauth_http::GuardedOauthHttpClient;
use utoipa::ToSchema;
use uuid::Uuid;

use super::portal_auth::PortalUser;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse};
use super::oauth_common::urlencode;
use crate::AdminState;
use crate::db::tenant::TenantConn;

#[derive(Serialize, ToSchema)]
pub struct PortalConnectionItem {
    pub upstream_server_id: Uuid,
    pub upstream_name: String,
    pub upstream_description: Option<String>,
    /// One of: `connected` (credential present, not expired), `expired`
    /// (credential present but `expires_at < now`), `not_connected` (no
    /// credential row).
    pub status: String,
    pub scope: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Virtual servers this upstream is reachable through (the agent calls
    /// `/mcp/<slug>` per virtual server). Useful for the portal to show
    /// "this connection unlocks tools on N virtual servers".
    pub virtual_servers: Vec<PortalConnectionVirtualServer>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalConnectionVirtualServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PortalConnectionsList {
    pub items: Vec<PortalConnectionItem>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalConnectInitResponse {
    pub authorization_url: String,
    /// `mcp_pending_authorizations.id` — the portal can poll status by this id.
    pub pending_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OauthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    /// RFC 9207 authorization-server issuer identifier.
    ///
    /// Optional on the wire because not every authorization server sends it,
    /// but when one does it MUST be checked before the code is redeemed —
    /// that check is what closes the mix-up attack the parameter exists for.
    /// An attacker-controlled authorization server otherwise hands us a code
    /// we carry to an honest server's token endpoint, redeeming its
    /// credential on the attacker's behalf.
    pub iss: Option<String>,
}

#[derive(Deserialize)]
pub struct ConnectInitQuery {
    /// Optional virtual server id — surfaces in the portal "you're
    /// connecting to <vs>" copy. The connection itself is per-(user,
    /// upstream), so the binding is informational only.
    pub virtual_server_id: Option<Uuid>,
}

// ===========================================================================
// LIST
// ===========================================================================

#[utoipa::path(
    get,
    path = "/api/v1/portal/mcp/connections",
    tag = "Portal MCP",
    operation_id = "portal_list_mcp_connections",
    responses(
        (status = 200, description = "The caller's per-user upstream connections", body = PortalConnectionsList),
        (status = 401, description = "No valid portal session", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_connections(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
) -> Result<Json<PortalConnectionsList>, ApiError> {
    // The tenant's per-user-OAuth upstreams that route through any virtual
    // server the user has RBAC access to. Include both connected and
    // not-connected so the portal can show the full setup state.
    let rows: Vec<UpstreamRow> = sqlx::query_as::<_, UpstreamRow>(
        r#"
        SELECT DISTINCT u.id, u.name, u.description
        FROM mcp_upstream_servers u
        JOIN mcp_virtual_routes r ON r.upstream_server_id = u.id AND r.enabled
        JOIN mcp_virtual_servers vs ON vs.id = r.virtual_server_id AND vs.enabled
        WHERE u.auth_mode = 'per_user_oauth'
          AND u.enabled
          AND EXISTS (
                SELECT 1 FROM workspace_members wm
                JOIN workspace_mcp_access wma ON wma.workspace_id = wm.workspace_id
                WHERE wm.user_id = $1 AND wma.virtual_server_id = vs.id
                  AND ($2::uuid IS NULL OR wm.workspace_id = $2)
              )
        ORDER BY u.name
        "#,
    )
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list portal mcp connections: {e}");
        ApiError::internal("failed to list connections")
    })?;

    let mut items = Vec::with_capacity(rows.len());
    for u in rows {
        let creds: Option<CredRow> = sqlx::query_as::<_, CredRow>(
            r#"SELECT scope, expires_at, last_used_at
               FROM mcp_user_credentials
               WHERE tenant_id = $1 AND user_id = $2 AND upstream_server_id = $3"#,
        )
        .bind(db.tenant_uuid())
        .bind(user.user_id)
        .bind(u.id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("portal mcp creds lookup: {e}");
            ApiError::internal("failed to load credential state")
        })?;

        let status = match creds.as_ref() {
            None => "not_connected",
            Some(c) => match c.expires_at {
                Some(at) if at <= chrono::Utc::now() => "expired",
                _ => "connected",
            },
        }
        .to_string();

        let vs_list: Vec<PortalConnectionVirtualServer> = sqlx::query_as::<_, VirtualServerRow>(
            r#"
            SELECT vs.id, vs.slug, vs.name
            FROM mcp_virtual_servers vs
            JOIN mcp_virtual_routes r ON r.virtual_server_id = vs.id AND r.enabled
            WHERE r.upstream_server_id = $1 AND vs.enabled
              AND EXISTS (
                    SELECT 1 FROM workspace_members wm
                    JOIN workspace_mcp_access wma ON wma.workspace_id = wm.workspace_id
                    WHERE wm.user_id = $2 AND wma.virtual_server_id = vs.id
                      AND ($3::uuid IS NULL OR wm.workspace_id = $3)
                  )
            ORDER BY vs.slug
            "#,
        )
        .bind(u.id)
        .bind(user.user_id)
        .bind(user.key_workspace_id)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list virtual servers for upstream: {e}");
            ApiError::internal("failed to list virtual servers")
        })?
        .into_iter()
        .map(|v| PortalConnectionVirtualServer { id: v.id, slug: v.slug, name: v.name })
        .collect();

        items.push(PortalConnectionItem {
            upstream_server_id: u.id,
            upstream_name: u.name,
            upstream_description: u.description,
            status,
            scope: creds.as_ref().and_then(|c| c.scope.clone()),
            expires_at: creds.as_ref().and_then(|c| c.expires_at),
            last_used_at: creds.as_ref().and_then(|c| c.last_used_at),
            virtual_servers: vs_list,
        });
    }
    Ok(Json(PortalConnectionsList { items }))
}

#[derive(sqlx::FromRow)]
struct UpstreamRow {
    id: Uuid,
    name: String,
    description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct CredRow {
    scope: Option<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(sqlx::FromRow)]
struct VirtualServerRow {
    id: Uuid,
    slug: String,
    name: String,
}

// ===========================================================================
// CONNECT — generate authorization URL
// ===========================================================================

#[utoipa::path(
    post,
    path = "/api/v1/portal/mcp/connections/{upstream_id}/actions/connect",
    tag = "Portal MCP",
    operation_id = "portal_connect_mcp_upstream",
    params(("upstream_id" = Uuid, Path, description = "Upstream MCP server id")),
    responses(
        (status = 200, description = "Where to send the browser to authorize the connection", body = PortalConnectInitResponse),
        (status = 400, description = "The upstream is disabled, does not use per-user OAuth, or has no OAuth client configured", body = ApiErrorResponse),
        (status = 403, description = "No virtual server the caller's workspaces reach routes through this upstream", body = ApiErrorResponse),
        (status = 404, description = "No such upstream", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn connect_init(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(upstream_id): Path<Uuid>,
    Query(q): Query<ConnectInitQuery>,
) -> Result<Json<PortalConnectInitResponse>, ApiError> {
    // Resolve the upstream + verify it's per_user_oauth and the operator has
    // configured the OAuth client.
    let row: Option<UpstreamConnectRow> = sqlx::query_as::<_, UpstreamConnectRow>(
        r#"SELECT id, name, auth_mode, enabled,
                  oauth_authorization_url, oauth_token_url,
                  oauth_client_id,
                  COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes
           FROM mcp_upstream_servers
           WHERE id = $1"#,
    )
    .bind(upstream_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal connect_init lookup: {e}");
        ApiError::internal("failed to load upstream")
    })?;
    let row = row.ok_or_else(|| {
        ApiError::not_found("upstream not found", ApiErrorCode::McpUpstreamServerNotFound)
    })?;

    if !row.enabled {
        return Err(ApiError::bad_request("upstream is disabled")
            .code(ApiErrorCode::McpUpstreamServerNotFound));
    }
    if row.auth_mode != "per_user_oauth" {
        return Err(ApiError::bad_request("upstream is not per_user_oauth")
            .code(ApiErrorCode::McpUpstreamNotPerUserOauth));
    }
    // The OAuth client is set by an administrator on the upstream; a portal
    // user can't fix it, so every missing-field path surfaces the same
    // friendly message under one code (the UI branches on the code, not text).
    let not_configured = || {
        ApiError::bad_request(
            "This server isn't fully set up yet — ask your administrator to finish its OAuth configuration.",
        )
        .code(ApiErrorCode::McpUpstreamOauthClientIncomplete)
    };
    let auth_url = row.oauth_authorization_url.filter(|s| !s.is_empty()).ok_or_else(not_configured)?;
    let _token_url_required_for_callback =
        row.oauth_token_url.as_deref().filter(|s| !s.is_empty()).ok_or_else(not_configured)?;
    let client_id = row.oauth_client_id.filter(|s| !s.is_empty()).ok_or_else(not_configured)?;

    // Access — confirm the user reaches at least one virtual server routing
    // through this upstream via one of their workspaces' allowlists.
    let has_access: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM mcp_virtual_routes r
            JOIN mcp_virtual_servers vs ON vs.id = r.virtual_server_id AND vs.enabled
            WHERE r.upstream_server_id = $1 AND r.enabled
              AND EXISTS (
                    SELECT 1 FROM workspace_members wm
                    JOIN workspace_mcp_access wma ON wma.workspace_id = wm.workspace_id
                    WHERE wm.user_id = $2 AND wma.virtual_server_id = vs.id
                      AND ($3::uuid IS NULL OR wm.workspace_id = $3)
                  )
        )
        "#,
    )
    .bind(upstream_id)
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal connect_init access check: {e}");
        ApiError::internal("failed to check access")
    })?;
    if !has_access {
        return Err(ApiError::forbidden("you do not have access to this upstream")
            .code(ApiErrorCode::PermissionDenied));
    }

    // PKCE — single source of truth in the shared crate; we just call the
    // helpers so both per-user OAuth (here) and spec-OAuth (`mcp_oauth.rs`)
    // share verifier/challenge derivation.
    let code_verifier = streamscope_mcp_auth::pkce::generate_code_verifier();
    let code_challenge = streamscope_mcp_auth::pkce::derive_s256_challenge(&code_verifier);

    // The OAuth `state` parameter doubles as the lookup key for the
    // pending-authorization row at callback time. Embedding the tenant_id
    // (as a hex prefix) lets the OAuth callback (which runs without a
    // tenant-bound DB session) set app.tenant_id BEFORE the SELECT,
    // satisfying RLS without iterating every tenant. The remainder is a
    // random nonce so the state is still unguessable from the outside.
    let mut nonce_bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
    let oauth_state = format!("{}.{}", db.tenant_uuid().simple(), nonce);

    let scope_str = if row.oauth_default_scopes.is_empty() {
        None
    } else {
        Some(row.oauth_default_scopes.join(" "))
    };

    // The callback is a machine-shaped `/api/v1/*` endpoint (no portal
    // session — tenant context rides the `state` parameter), so the
    // registered redirect URI MUST live on the API origin: on split-vhost
    // deploys the UI origin never routes `/api/v1/*`.
    let origins = crate::tenant_public_url::resolve_oauth_discovery_origins(
        &state.db,
        db.tenant_uuid(),
    )
    .await?;
    let redirect_uri = oauth_callback_uri(&origins.api);
    let pending_id = Uuid::new_v4();
    let settings = crate::settings::admin_settings();
    let ttl = chrono::Duration::seconds(settings.mcp_oauth_pending_ttl_secs);
    let expires_at = chrono::Utc::now() + ttl;

    sqlx::query(
        r#"INSERT INTO mcp_pending_authorizations
               (id, tenant_id, user_id, upstream_server_id, virtual_server_id,
                state, code_verifier, scope, redirect_uri, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(pending_id)
    .bind(db.tenant_uuid())
    .bind(user.user_id)
    .bind(upstream_id)
    .bind(q.virtual_server_id)
    .bind(&oauth_state)
    .bind(&code_verifier)
    .bind(&scope_str)
    .bind(&redirect_uri)
    .bind(expires_at)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal connect_init insert pending: {e}");
        ApiError::internal("failed to create pending authorization")
    })?;

    let url = build_authorize_url(
        &auth_url,
        &client_id,
        &redirect_uri,
        &oauth_state,
        &code_challenge,
        scope_str.as_deref(),
    )?;

    Ok(Json(PortalConnectInitResponse {
        authorization_url: url,
        pending_id,
        expires_at,
    }))
}

#[derive(sqlx::FromRow)]
struct UpstreamConnectRow {
    #[allow(dead_code)] // kept for symmetry with other upstream rows
    id: Uuid,
    #[allow(dead_code)]
    name: String,
    auth_mode: String,
    enabled: bool,
    oauth_authorization_url: Option<String>,
    oauth_token_url: Option<String>,
    oauth_client_id: Option<String>,
    oauth_default_scopes: Vec<String>,
}

// ===========================================================================
// CALLBACK — exchange code, store credential, redirect
// ===========================================================================

/// OAuth provider redirects here after user consent. The handler:
///   1. validates the `state` (binds to the requesting user + upstream),
///   2. exchanges the `code` at the IdP token endpoint with the PKCE verifier,
///   3. encrypts + UPSERTs into `mcp_user_credentials`,
///   4. deletes the pending row,
///   5. redirects the browser to `/portal/t/<slug>/mcp/connections?connected=...`.
///
/// On any failure, the user is redirected to the connections page with
/// `?error=<short-code>` so the portal UI can show a toast.
#[utoipa::path(
    get,
    path = "/api/v1/portal/mcp/connections/oauth/callback",
    tag = "Portal MCP",
    params(OauthCallbackQuery),
    responses(
        (status = 302, description = "Redirect to /portal/t/<slug>/mcp/connections with success or error code"),
        (status = 400, description = "Invalid state / missing code", body = ApiErrorResponse),
    ),
    // Public — IdP redirects the browser here without a portal session;
    // tenant scoping is decoded from the state nonce.
)]
pub async fn oauth_callback(
    State(state): State<Arc<AdminState>>,
    Query(q): Query<OauthCallbackQuery>,
) -> Result<Redirect, ApiError> {
    // The state encodes tenant_id (hex simple-form, 32 chars, no dashes)
    // followed by `.` and a random nonce. Decode the prefix first so the
    // post-callback redirect resolves through the tenant's `admin_public_url`
    // (per-tenant override or SYSTEM default). Without `state` we have no
    // tenant context — return a hard 400 instead of redirecting blindly.
    //
    // Security model: `state` is an opaque join key into
    // `mcp_pending_authorizations`. The `<tenant_simple>.<nonce>` prefix is a
    // tenant disambiguator (so we can pick the right `TenantConn` without first
    // doing a global lookup), NOT a security boundary — forging the prefix
    // alone is harmless because the join requires the unguessable nonce.
    //
    // Single use is enforced by the atomic claim below (`UPDATE … WHERE
    // consumed_at IS NULL … RETURNING`), which runs before the row is used for
    // anything — so a leaked `state` (e.g. via referer from the IdP page) is
    // spendable at most once, and only inside its `mcp_oauth_pending_ttl_secs`
    // window. Treat the full `state` as a single-use credential: do not log it
    // and do not expose it in error redirects.
    let oauth_state = q
        .state
        .clone()
        .ok_or_else(|| ApiError::bad_request("missing state").code(ApiErrorCode::ValidationFailed))?;
    let (tenant_prefix, _) = oauth_state.split_once('.').ok_or_else(|| {
        ApiError::bad_request("invalid state format")
            .code(ApiErrorCode::McpPendingAuthorizationInvalid)
    })?;
    let tenant_id = Uuid::parse_str(tenant_prefix).map_err(|_| {
        ApiError::bad_request("invalid tenant in state")
            .code(ApiErrorCode::McpPendingAuthorizationInvalid)
    })?;
    let admin_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Admin,
    )
    .await?;
    // The browser redirect must land under the tenant-prefixed portal path —
    // the path-scoped `portal_session` cookie only travels under
    // `/portal/t/<slug>`. The browser arrives here without a session.
    let tenant_slug: String =
        sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1 AND is_active = true")
            .bind(tenant_id)
            .fetch_optional(state.db.global(Global::PreAuth))
            .await
            .map_err(|e| {
                tracing::error!("oauth_callback tenant slug lookup: {e}");
                ApiError::internal("internal error")
            })?
            .ok_or_else(|| {
                ApiError::bad_request("invalid tenant in state")
                    .code(ApiErrorCode::McpPendingAuthorizationInvalid)
            })?;
    let portal_url = format!("{admin_origin}/portal/t/{tenant_slug}/mcp/connections");

    if let Some(err) = q.error {
        let detail = q.error_description.unwrap_or(err);
        return Ok(Redirect::to(&format!(
            "{portal_url}?error={}",
            urlencode(&detail.chars().take(120).collect::<String>())
        )));
    }
    let code = q
        .code
        .ok_or_else(|| ApiError::bad_request("missing code").code(ApiErrorCode::ValidationFailed))?;

    // Use a tenant-scoped DB session — the callback isn't bound to a portal
    // session yet (the browser arrived via IdP redirect), so we acquire one
    // with the tenant_id we just decoded from the state token.
    let mut db = crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_credential(tenant_id),
    )
    .await
    .map_err(|e| {
        tracing::error!("oauth_callback acquire tenant db: {e}");
        ApiError::internal("failed to scope tenant")
    })?;
    // CLAIM the row rather than read it: one statement marks it consumed and
    // hands back its contents, so a `state` is spendable exactly once. Two
    // concurrent callbacks race on the same UPDATE and only one sees a row —
    // and because the claim happens here rather than on the success path, an
    // exchange that FAILS below cannot be replayed for the rest of the TTL.
    // Expiry is folded into the predicate, so a stale row simply doesn't match.
    let pending: PendingRow = sqlx::query_as::<_, PendingRow>(
        r#"UPDATE mcp_pending_authorizations
              SET consumed_at = NOW()
            WHERE state = $1
              AND consumed_at IS NULL
              AND expires_at > NOW()
        RETURNING id, tenant_id, user_id, upstream_server_id, code_verifier, redirect_uri"#,
    )
    .bind(&oauth_state)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("oauth_callback claim pending: {e}");
        ApiError::internal("failed to validate state")
    })?
    .ok_or_else(|| {
        ApiError::bad_request("invalid or expired state")
            .code(ApiErrorCode::McpPendingAuthorizationInvalid)
    })?;

    // Resolve upstream config so we can call the IdP token endpoint.
    let upstream: UpstreamConnectRowWithSecret = sqlx::query_as::<_, UpstreamConnectRowWithSecret>(
        r#"SELECT id, oauth_issuer_url, oauth_token_url, oauth_client_id,
                  convert_from(encrypted_oauth_client_secret, 'UTF8') AS encrypted_oauth_client_secret,
                  COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes
           FROM mcp_upstream_servers
           WHERE id = $1 AND auth_mode = 'per_user_oauth' AND enabled"#,
    )
    .bind(pending.upstream_server_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("oauth_callback upstream lookup: {e}");
        ApiError::internal("failed to load upstream")
    })?
    .ok_or_else(|| {
        ApiError::bad_request("upstream is no longer available")
            .code(ApiErrorCode::McpUpstreamServerNotFound)
    })?;

    // RFC 9207 § 2.4 / MCP 2026-07-28 (SEP-2468): a *present* `iss` MUST be
    // validated against the recorded issuer before the code is redeemed.
    //
    // Absent is not a failure — the parameter is a SHOULD on the server side
    // and plenty of authorization servers omit it. What must never happen is
    // accepting a present one without looking, which is indistinguishable
    // from having no defence at all.
    //
    // Compared with the trailing slash normalised away: an issuer identifier
    // is a URL, and `https://idp.example.com` and `https://idp.example.com/`
    // are the same authorization server written two ways. Anything beyond
    // that is a genuine difference and is refused.
    if let Some(returned) = q.iss.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let recorded = upstream
            .oauth_issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match recorded {
            // Nothing on file to validate against, so there is no comparison
            // to make — the requirement is conditioned on having a recorded
            // issuer. Refusing here would break every connection an operator
            // configured by hand before this field mattered, so this warns and
            // proceeds, naming the upstream so the gap can be closed.
            // Discovery fills the field in automatically.
            None => tracing::warn!(
                upstream_id = %pending.upstream_server_id,
                "oauth_callback: authorization server returned an iss but this upstream records no issuer URL; cannot validate it"
            ),
            Some(recorded)
                if recorded.trim_end_matches('/') != returned.trim_end_matches('/') =>
            {
                tracing::warn!(
                    upstream_id = %pending.upstream_server_id,
                    returned_iss = %returned,
                    "oauth_callback: authorization response iss does not match the recorded issuer; refusing to redeem"
                );
                return Ok(Redirect::to(&format!(
                    "{portal_url}?error={}",
                    urlencode("the authorization server's identity did not match the one configured for this connection")
                )));
            }
            Some(_) => {}
        }
    }

    let token_url = upstream
        .oauth_token_url
        .as_deref()
        .ok_or_else(|| {
            ApiError::bad_request("oauth_token_url not configured")
                .code(ApiErrorCode::McpUpstreamOauthClientIncomplete)
        })?;
    let client_id = upstream
        .oauth_client_id
        .as_deref()
        .ok_or_else(|| {
            ApiError::bad_request("oauth_client_id not configured")
                .code(ApiErrorCode::McpUpstreamOauthClientIncomplete)
        })?;
    let client_secret = match upstream.encrypted_oauth_client_secret.as_deref() {
        Some(ct) => {
            let key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
                ApiError::server_misconfigured("ENCRYPTION_KEY not configured")
            })?;
            Some(streamscope_core::crypto::decrypt(ct, &key).map_err(|e| {
                tracing::error!("decrypt oauth_client_secret: {e}");
                ApiError::internal("failed to decrypt client secret")
            })?)
        }
        None => None,
    };

    // The exchange rides TLS to an operator-configured IdP that may sit behind
    // a private CA. The trusted-CA cache is per-replica and only the replica
    // that handled the import refreshes it, so read it fresh here or the same
    // connect succeeds or fails depending on which replica the LB picked.
    crate::custom_ca::refresh_from_conn(db.conn()).await;

    // Token exchange.
    let exchange = exchange_code_for_tokens(
        token_url,
        client_id,
        client_secret.as_deref(),
        &code,
        &pending.code_verifier,
        &pending.redirect_uri,
    )
    .await;
    let tokens = match exchange {
        Ok(t) => t,
        Err(detail) => {
            tracing::warn!(error = %detail, "oauth_callback token exchange failed");
            return Ok(Redirect::to(&format!(
                "{portal_url}?error={}",
                urlencode(&detail.chars().take(160).collect::<String>())
            )));
        }
    };

    // Encrypt + UPSERT.
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or_else(|| ApiError::server_misconfigured("ENCRYPTION_KEY not configured"))?;
    let encrypted_access = streamscope_core::crypto::encrypt(&tokens.access_token, &key)
        .map_err(|e| {
            tracing::error!("encrypt access_token: {e}");
            ApiError::internal("failed to encrypt token")
        })?;
    let encrypted_refresh = match tokens.refresh_token.as_deref() {
        Some(rt) => Some(
            streamscope_core::crypto::encrypt(rt, &key)
                .map_err(|e| {
                    tracing::error!("encrypt refresh_token: {e}");
                    ApiError::internal("failed to encrypt refresh token")
                })?
                .into_bytes(),
        ),
        None => None,
    };
    // The upstream's token response is its own text; Postgres refuses U+0000.
    let scope = tokens
        .scope
        .as_deref()
        .map(|s| streamscope_core::pg_text::storable_str(s).into_owned())
        .or(if upstream.oauth_default_scopes.is_empty() {
            None
        } else {
            Some(upstream.oauth_default_scopes.join(" "))
        });

    sqlx::query(
        r#"INSERT INTO mcp_user_credentials
               (tenant_id, user_id, upstream_server_id,
                encrypted_access_token, encrypted_refresh_token, expires_at, scope, last_used_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
           ON CONFLICT (tenant_id, user_id, upstream_server_id) DO UPDATE SET
               encrypted_access_token = EXCLUDED.encrypted_access_token,
               encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
               expires_at = EXCLUDED.expires_at,
               scope = EXCLUDED.scope,
               updated_at = NOW(),
               last_used_at = NOW()"#,
    )
    .bind(pending.tenant_id)
    .bind(pending.user_id)
    .bind(pending.upstream_server_id)
    .bind(encrypted_access.into_bytes())
    .bind(encrypted_refresh)
    .bind(tokens.expires_at)
    .bind(scope)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("oauth_callback upsert credential: {e}");
        ApiError::internal("failed to store credential")
    })?;

    // Tidy-up only — the claim above already made this row unusable. Best
    // effort: the expiry sweeper reaps anything left behind.
    let _ = sqlx::query("DELETE FROM mcp_pending_authorizations WHERE id = $1")
        .bind(pending.id)
        .execute(db.conn())
        .await;


    Ok(Redirect::to(&format!(
        "{portal_url}?connected={}",
        pending.upstream_server_id
    )))
}

/// Build the upstream authorization URL for the code flow.
///
/// The parameters are *appended* to whatever query `auth_url` already carries
/// rather than joined with a bare `?`. That matters because `auth_url` is
/// operator-supplied and several IdPs legitimately ship one with a query
/// already on it — Azure AD B2C's `?p=<policy>` is the canonical case, and a
/// `?` join would produce a second question mark and a URL the IdP rejects.
///
/// The IdP receives the public redirect URI; it MUST be exactly registered at
/// the IdP for the code dance to succeed.
fn build_authorize_url(
    auth_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
    scope: Option<&str>,
) -> Result<String, ApiError> {
    let mut parsed = url::Url::parse(auth_url).map_err(|e| {
        tracing::error!("connect_init: unparsable oauth_authorization_url: {e}");
        ApiError::bad_request("upstream oauth_authorization_url is not a valid URL")
            .code(ApiErrorCode::ValidationFailed)
    })?;
    {
        let mut params = parsed.query_pairs_mut();
        params.append_pair("response_type", "code");
        params.append_pair("client_id", client_id);
        params.append_pair("redirect_uri", redirect_uri);
        params.append_pair("state", state);
        params.append_pair("code_challenge", code_challenge);
        params.append_pair("code_challenge_method", "S256");
        if let Some(scope) = scope {
            params.append_pair("scope", scope);
        }
    }
    Ok(parsed.to_string())
}

/// Contents of a pending authorization, as returned by the claiming UPDATE.
/// Carries no `expires_at` — expiry is part of the claim predicate, so a row
/// that comes back is live by construction.
#[derive(sqlx::FromRow)]
struct PendingRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    upstream_server_id: Uuid,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(sqlx::FromRow)]
struct UpstreamConnectRowWithSecret {
    #[allow(dead_code)]
    id: Uuid,
    /// The authorization server this connection was configured against.
    /// Read on the callback to validate a returned RFC 9207 `iss`.
    oauth_issuer_url: Option<String>,
    oauth_token_url: Option<String>,
    oauth_client_id: Option<String>,
    encrypted_oauth_client_secret: Option<String>,
    oauth_default_scopes: Vec<String>,
}

struct ExchangedTokens {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    scope: Option<String>,
}

/// Exchange the authorization code for the user's tokens.
///
/// Every error this returns is surfaced to the user in a redirect query
/// parameter, so it must never carry a live credential —
/// `classify_token_error` redacts the code and the client secret out of
/// anything the IdP echoed back.
async fn exchange_code_for_tokens(
    token_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<ExchangedTokens, String> {
    // SSRF defense-in-depth — see notes on `validate_outbound_urls` in mcp.rs.
    // The token URL is operator-curated on `mcp_upstream_servers` rows; this
    // catches IP-literal regressions if a row was inserted before that
    // validation existed. The transport re-checks and additionally pins the
    // resolved IP at connect time, so neither a DNS rebind nor a redirect can
    // deliver the code + client_secret to an internal target.
    let egress = super::mcp::MCP_EGRESS;
    streamscope_mcp_auth::ssrf::check_url_for(token_url, egress)
        .map_err(|e| format!("token_url refused by SSRF guard: {e}"))?;

    let client = oauth_client::upstream_token_client(client_id, client_secret, token_url)?;
    // Built per call rather than process-cached: this runs once per user per
    // upstream, and a live custom-CA change must take effect without a
    // restart.
    let http = GuardedOauthHttpClient::new(
        // The CA is the platform override (DB, env fallback) — an IdP behind
        // a private CA is the common self-hosted shape.
        streamscope_core::mcp::oauth_http::build_guarded_client(
            egress,
            crate::custom_ca::current().as_deref(),
            None, // the deadline rides the request, below
        )
        .map_err(|e| format!("build guarded oauth client: {e}"))?,
        egress,
        Some(Duration::from_secs(15)),
    );

    // Anything an error message could echo — the IdP sees all of these.
    let secrets = [code, code_verifier, client_secret.unwrap_or("")];
    let to_message = |e| match e {
        oauth_client::UpstreamTokenError::InvalidGrant => {
            "the authorization code was rejected — please try connecting again".to_string()
        }
        oauth_client::UpstreamTokenError::Failed(msg) => msg,
    };

    let response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(code_verifier.to_string()))
        .set_redirect_uri(Cow::Owned(
            RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| format!("invalid redirect_uri: {e}"))?,
        ))
        .request_async(&http)
        .await
        .map_err(|e| to_message(oauth_client::classify_token_error(e, &secrets)))?;

    let tokens = oauth_client::into_tokens(response, &secrets).map_err(to_message)?;
    Ok(ExchangedTokens {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_at,
        scope: tokens.scope,
    })
}

// ===========================================================================
// REVOKE
// ===========================================================================

#[utoipa::path(
    post,
    path = "/api/v1/portal/mcp/connections/{upstream_id}/actions/revoke",
    tag = "Portal MCP",
    operation_id = "portal_revoke_mcp_connection",
    params(("upstream_id" = Uuid, Path, description = "Upstream MCP server id")),
    responses(
        (status = 200, description = "The caller's connection was revoked", body = ActionResponse),
        (status = 404, description = "The caller has no connection to this upstream", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_connection(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(upstream_id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // A portal `ak-` key may only revoke a connection reachable from its bound
    // workspace; a human session (None) is unrestricted here. Confined and
    // unreachable → 404, before any revocation work.
    if let Some(bound) = user.key_workspace_id {
        let reachable: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                SELECT 1 FROM mcp_virtual_routes r
                JOIN mcp_virtual_servers vs ON vs.id = r.virtual_server_id AND vs.enabled
                JOIN workspace_mcp_access wma ON wma.virtual_server_id = vs.id
                JOIN workspace_members wm ON wm.workspace_id = wma.workspace_id
                WHERE r.upstream_server_id = $1 AND r.enabled
                  AND wm.user_id = $2 AND wm.workspace_id = $3
            )"#,
        )
        .bind(upstream_id)
        .bind(user.user_id)
        .bind(bound)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("portal revoke access check: {e}");
            ApiError::internal("internal error")
        })?;
        if !reachable {
            return Err(ApiError::not_found("no credential to revoke", ApiErrorCode::McpUserCredentialNotFound));
        }
    }

    // Best-effort: hit the IdP's revocation endpoint if configured.
    let row: Option<RevokeUpstreamRow> = sqlx::query_as::<_, RevokeUpstreamRow>(
        r#"SELECT
            convert_from(c.encrypted_refresh_token, 'UTF8') AS refresh_ct,
            u.oauth_revocation_url,
            u.oauth_client_id,
            convert_from(u.encrypted_oauth_client_secret, 'UTF8') AS client_secret_ct
           FROM mcp_user_credentials c
           JOIN mcp_upstream_servers u ON u.id = c.upstream_server_id
           WHERE c.tenant_id = $1 AND c.user_id = $2 AND c.upstream_server_id = $3"#,
    )
    .bind(db.tenant_uuid())
    .bind(user.user_id)
    .bind(upstream_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal revoke load creds: {e}");
        ApiError::internal("failed to load credential")
    })?;

    if let Some(r) = row.as_ref()
        && let Some(url) = r.oauth_revocation_url.as_deref()
        && let (Some(rt_ct), Some(cid)) = (&r.refresh_ct, &r.oauth_client_id)
    {
        let key = streamscope_core::crypto::get_encryption_key();
        if let Some(key) = key
            && let Ok(refresh_token) = streamscope_core::crypto::decrypt(rt_ct, &key)
        {
            let secret = r
                .client_secret_ct
                .as_deref()
                .and_then(|ct| streamscope_core::crypto::decrypt(ct, &key).ok());
            // Fresh CA read for the same per-replica reason as the exchange.
            crate::custom_ca::refresh_from_conn(db.conn()).await;
            // Best-effort, fire-and-forget — RFC 7009 says servers MAY ignore.
            let _ = call_revoke(url, cid, secret.as_deref(), &refresh_token).await;
        }
    }

    let deleted = sqlx::query(
        r#"DELETE FROM mcp_user_credentials
           WHERE tenant_id = $1 AND user_id = $2 AND upstream_server_id = $3"#,
    )
    .bind(db.tenant_uuid())
    .bind(user.user_id)
    .bind(upstream_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal revoke delete: {e}");
        ApiError::internal("failed to revoke credential")
    })?;

    if deleted.rows_affected() == 0 {
        return Err(ApiError::not_found("no credential to revoke", ApiErrorCode::McpUserCredentialNotFound));
    }
    Ok(Json(ActionResponse::ok().with_message("Connection disconnected.")))
}

#[derive(sqlx::FromRow)]
struct RevokeUpstreamRow {
    refresh_ct: Option<String>,
    oauth_revocation_url: Option<String>,
    oauth_client_id: Option<String>,
    client_secret_ct: Option<String>,
}

/// RFC 7009 revocation.
///
/// Deliberately hand-rolled rather than routed through `oauth2`: the response
/// is discarded (servers MAY ignore a revocation), so the crate would
/// contribute only an https-only check that is wrong for an operator whose IdP
/// sits on a private network it listed on the `mcp` egress list.
/// It still runs over the same guarded transport as the exchange, because it
/// ships the refresh token and the client secret.
async fn call_revoke(
    url: &str,
    client_id: &str,
    client_secret: Option<&str>,
    token: &str,
) -> Result<(), String> {
    // SSRF defense-in-depth (see exchange_code_for_tokens above).
    let egress = super::mcp::MCP_EGRESS;
    streamscope_mcp_auth::ssrf::check_url_for(url, egress)
        .map_err(|e| format!("revocation_url refused by SSRF guard: {e}"))?;
    let http = streamscope_core::mcp::oauth_http::build_guarded_client(
        egress,
        crate::custom_ca::current().as_deref(),
        Some(Duration::from_secs(10)),
    )
    .map_err(|e| format!("build guarded revoke client: {e}"))?;
    let mut form = vec![
        ("token", token.to_string()),
        ("token_type_hint", "refresh_token".to_string()),
        ("client_id", client_id.to_string()),
    ];
    if let Some(s) = client_secret {
        form.push(("client_secret", s.to_string()));
    }
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let _ = http
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

/// The redirect URI registered at external IdPs for per-user upstream OAuth.
/// `api_origin` MUST be the resolved API origin
/// (`OauthDiscoveryOrigins::api`) — it's an `/api/v1/*` endpoint, which the
/// UI origin never routes on split-vhost deploys. Also surfaced read-only on
/// the settings GET so the admin UI shows the exact string to register.
pub(crate) fn oauth_callback_uri(api_origin: &str) -> String {
    format!(
        "{}/api/v1/portal/mcp/connections/oauth/callback",
        api_origin.trim_end_matches('/')
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    fn params_of(url: &str) -> std::collections::HashMap<String, String> {
        url::Url::parse(url)
            .expect("built URL parses")
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn build(auth_url: &str) -> String {
        build_authorize_url(
            auth_url,
            "client-abc",
            "https://gw.example.test/api/v1/portal/mcp/connections/oauth/callback",
            "acme.nonce-xyz",
            "challenge-123",
            Some("openid email"),
        )
        .expect("well-formed authorize URL")
    }

    #[test]
    fn carries_every_code_flow_parameter() {
        let p = params_of(&build("https://idp.example.test/oauth2/authorize"));
        assert_eq!(p["response_type"], "code");
        assert_eq!(p["client_id"], "client-abc");
        assert_eq!(
            p["redirect_uri"],
            "https://gw.example.test/api/v1/portal/mcp/connections/oauth/callback"
        );
        assert_eq!(p["state"], "acme.nonce-xyz");
        assert_eq!(p["code_challenge"], "challenge-123");
        assert_eq!(p["code_challenge_method"], "S256");
        assert_eq!(p["scope"], "openid email");
    }

    /// The case a bare `?` join corrupts: an operator-supplied authorize URL
    /// that already carries a query. Azure AD B2C pins the user flow this way,
    /// and losing it sends the user to a policy-less endpoint that errors.
    #[test]
    fn preserves_a_query_the_operator_already_supplied() {
        let built = build(
            "https://tenant.b2clogin.com/tenant.onmicrosoft.com/oauth2/v2.0/authorize?p=B2C_1_signin",
        );
        assert!(
            !built.contains("??") && built.matches('?').count() == 1,
            "must not produce a second question mark: {built}"
        );
        let p = params_of(&built);
        assert_eq!(p["p"], "B2C_1_signin", "operator's own parameter survived");
        assert_eq!(p["response_type"], "code", "ours were appended alongside");
    }

    /// Multiple pre-existing parameters, and one whose value needs escaping.
    #[test]
    fn preserves_several_existing_parameters() {
        let p = params_of(&build(
            "https://idp.example.test/authorize?p=B2C_1_signin&ui_locales=fr-FR",
        ));
        assert_eq!(p["p"], "B2C_1_signin");
        assert_eq!(p["ui_locales"], "fr-FR");
        assert_eq!(p["code_challenge_method"], "S256");
    }

    /// A scopeless upstream must simply omit the parameter rather than send an
    /// empty one, which some IdPs reject.
    #[test]
    fn omits_scope_when_absent() {
        let url = build_authorize_url(
            "https://idp.example.test/authorize",
            "c",
            "https://gw.example.test/cb",
            "s",
            "cc",
            None,
        )
        .expect("URL builds");
        assert!(!params_of(&url).contains_key("scope"), "{url}");
    }

    #[test]
    fn rejects_an_unparsable_authorize_url() {
        assert!(build_authorize_url("not a url", "c", "r", "s", "cc", None).is_err());
    }

    /// Values carrying reserved characters must round-trip through the query
    /// intact — the redirect URI is compared byte-for-byte at the IdP.
    #[test]
    fn escapes_reserved_characters_in_values() {
        let url = build_authorize_url(
            "https://idp.example.test/authorize",
            "client&id=weird",
            "https://gw.example.test/cb?x=1&y=2",
            "acme.a+b/c",
            "cc",
            Some("a b"),
        )
        .expect("URL builds");
        let p = params_of(&url);
        assert_eq!(p["client_id"], "client&id=weird");
        assert_eq!(p["redirect_uri"], "https://gw.example.test/cb?x=1&y=2");
        assert_eq!(p["state"], "acme.a+b/c");
        assert_eq!(p["scope"], "a b");
    }
}
