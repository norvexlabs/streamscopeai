//! Portal authentication — OIDC-based and credential-based login for end users.
//!
//! Separate from admin auth: portal users are service `users` (not `admin_accounts`).
//! Supports OIDC token exchange (auto-provisions users on first login) and
//! password-based login. JWT tokens are signed with a per-tenant key derived
//! from `AUTH_SECRET`. Portal middleware extracts [`PortalUser`] for route handlers.

use crate::db::Global;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;


use crate::AdminState;

use super::{bearer_token, no_signing_key, rejected_credential, ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse};
use super::admin_auth::{
    decode_session_jwt, dummy_password_verify, keyring, lookup_tenant_slug, SessionTenant,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Authorization scope of an interactive portal session token. Full
/// portal-plane reach (per the user's own memberships/role); the only scope
/// that may approve OAuth consent grants.
pub const SCOPE_PORTAL: &str = "portal";

/// Authorization scope of a CLI-provisioning access token (minted by the
/// `cli_oauth` surface). Fenced in [`portal_auth`] to the provisioning
/// allowlist ([`PROVISION_ALLOWED`]) and revocable per-token via its `jti`
/// row in `oauth_issued_tokens`.
pub const SCOPE_PROVISION: &str = "provision";

/// JWT claims for portal user session tokens.
/// Distinguished from admin claims by `role: "user"`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PortalClaims {
    pub sub: String,  // user UUID (from `users` table)
    pub email: String,
    pub role: String, // always "user"
    /// Tenant UUID for multi-tenant scoping.
    pub tenant_id: String,
    /// Token issuer — always `"streamscope"`.
    pub iss: String,
    /// Token audience — the tenant UUID, binding the token to one tenant.
    pub aud: String,
    /// Authorization scope — [`SCOPE_PORTAL`] for interactive sessions,
    /// [`SCOPE_PROVISION`] for CLI-provisioning tokens. Required: a token
    /// without it fails decode and the bearer re-authenticates.
    pub scope: String,
    /// Revocation id — set on provision tokens (their row in
    /// `oauth_issued_tokens` is checked per request); absent on interactive
    /// sessions, which live and die with their `exp` alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub exp: usize,
    pub iat: usize,
    /// Equal to `iat`. Required and validated — see `streamscope_jwt_validation`.
    pub nbf: usize,
}

impl SessionTenant for PortalClaims {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// Extracted portal user identity, attached to request extensions by middleware.
///
/// A human portal session (JWT) leaves `key_id`/`key_workspace_id` `None`. An
/// `ak-` portal **automation key** sets them: `user_id`/`email` are then the
/// owning service account, and `key_workspace_id` is the single workspace the
/// key is confined to — the manager gate ([`verify_workspace_manager`]) rejects
/// any attempt to act outside it, so the key carries only that one workspace's
/// manager authority.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortalUser {
    pub user_id: Uuid,
    pub email: String,
    pub tenant_id: Uuid,
    /// `automation_keys.id` (plane=portal) when authenticated via an `ak-` portal key; `None`
    /// for a human session.
    pub key_id: Option<Uuid>,
    /// The workspace an `ak-` portal key is confined to; `None` for a human
    /// session (which acts per its own memberships).
    pub key_workspace_id: Option<Uuid>,
    /// The `iat` of the session JWT this identity came from, for comparison
    /// against the account's sign-out watermark. `None` for an `ak-` key, which
    /// is not a session and is revoked through its own `revoked_at` column.
    ///
    /// Carried here because the consent surface authenticates *outside* the
    /// portal middleware — it has to, since `/authorize/*` is reached with a
    /// token in a header rather than through the portal router — so it cannot
    /// inherit that middleware's watermark check and needs the claim itself.
    pub session_iat: Option<usize>,
}

/// Present on a request authenticated with a CLI-provisioning token
/// ([`SCOPE_PROVISION`]): the caller is `ssai`, not the portal in a browser.
#[derive(Clone, Copy)]
pub struct ProvisionToken;

impl PortalUser {
    /// Whether the caller is the CLI — a provisioning token, or an `ak-` key
    /// (what `ssai` runs with unattended) — rather than a member's browser
    /// session. Decides nothing about access: only which of a client's
    /// configs the caller can write (the CLI writes a project's own file).
    pub fn is_cli(&self, provision: Option<&ProvisionToken>) -> bool {
        provision.is_some() || self.key_id.is_some()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct PortalLoginRequest {
    pub email: String,
    pub password: String,
    /// The tenant these credentials belong to.
    ///
    /// Required, and the only thing that decides which `users` row is
    /// consulted. An email is unique within a tenant and nowhere else, so
    /// without it a login can only guess — and a guess authenticates the
    /// password against one tenant's hash while the caller believes it signed
    /// in to another.
    pub tenant_slug: String,
}

#[derive(Serialize, ToSchema)]
pub struct PortalLoginResponse {
    pub token: String,
    pub user: PortalUserResponse,
    /// The organization the session is for. Under header auth the gateway
    /// decides it, so the console follows this rather than its own URL.
    pub tenant_slug: String,
}

#[derive(Serialize, ToSchema)]
pub struct PortalUserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// Portal auth middleware
// ---------------------------------------------------------------------------

/// Middleware that validates portal user JWT tokens.
/// Attaches `PortalUser` to request extensions if valid, and beside it what
/// the portal hides for that caller (`HiddenPages`) — resolved here, once per
/// request, for the page fences and the handlers that read it.
/// Rejects admin JWTs (role != "user").
pub async fn portal_auth(
    State(state): State<Arc<AdminState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer_token(req.headers())?;

    // `ak-` portal automation key → resolve to the owning service account
    // (fail-closed). Tried before the JWT path; an `ak-` is never a valid JWT.
    if token.starts_with("ak-") {
        // Per-key ceiling first — a flooding key must not reach the cross-tenant
        // scan behind `authenticate_portal_key`.
        if super::admin_auth::automation_key_rate_limited(
            &state.automation_key_rate_limiter,
            req.headers(),
        ) {
            return Err(ApiError::too_many_requests("automation key rate limit exceeded"));
        }
        // A database that does not answer is a 503, never a 401: automation
        // reading a 401 treats a live key as revoked.
        let portal_user = match authenticate_portal_key(req.headers(), &state.db).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err(rejected_credential()),
            Err(e) => return Ok(crate::middleware::AutomationKeyUnverified::response(e)),
        };
        super::admin_auth::record_automation_key_use(
            &state.automation_key_rate_limiter,
            req.headers(),
        );
        // The key is checked: from here a database that does not answer is
        // this request's own 503, not an unverified key's. The key scan holds
        // no connection once it returns, so this takes one — released before
        // the handler takes its own.
        let hidden = {
            let unanswered = |e: sqlx::Error| {
                tracing::warn!(tenant_id = %portal_user.tenant_id, "portal key: hidden pages read failed: {e}");
                super::db_read_error(&e, "session could not be checked")
            };
            let tenant = crate::db::tenant::TenantId::from_credential(portal_user.tenant_id);
            let mut db = crate::db::tenant::TenantConn::acquire(&state.db, tenant).await.map_err(unanswered)?;
            super::client_access_profiles::hidden_pages(db.conn(), &portal_user).await.map_err(unanswered)?
        };
        req.extensions_mut().insert(hidden);
        req.extensions_mut().insert(portal_user);
        return Ok(next.run(req).await);
    }

    let Some(ring) = keyring() else {
        return Err(no_signing_key());
    };

    // The `kid` header names the signing generation and the tenant. Both are
    // unverified here — they pick the key; `decode_session_jwt` binds the
    // verified token's `aud` AND `tenant_id` to that tenant, which matters on
    // this path because `tenant_id` below selects the RLS database context.
    let Some((claims, _tid)) = decode_session_jwt::<PortalClaims>(&ring, token) else {
        return Err(rejected_credential());
    };

    // Only accept portal user tokens (role = "user"), reject admin tokens.
    if claims.role != "user" {
        return Err(ApiError::forbidden("a console session cannot use the portal"));
    }

    let user_id: Uuid = claims.sub.parse().map_err(|_| rejected_credential())?;

    let tid_uuid: Uuid = claims.tenant_id.parse().map_err(|_| rejected_credential())?;
    // From here a database that does not answer is a 503, never a 401: the
    // portal ends its session on a 401, and an outage proves nothing about it.
    let lookup_failed = |what: &str, e: &dyn std::fmt::Display| {
        use axum::response::IntoResponse;
        tracing::warn!(tenant_id = %tid_uuid, "portal session check: {what} failed: {e}");
        ApiError::from(super::admin_auth::SessionLookupFailed).into_response()
    };
    let mut db = match crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_credential(tid_uuid),
    )
    .await
    {
        Ok(db) => db,
        Err(e) => return Ok(lookup_failed("connection", &e)),
    };

    // Verify user exists and is active.
    type UserRow = (Uuid, bool, Option<chrono::DateTime<chrono::Utc>>);
    let user_row: Result<Option<UserRow>, sqlx::Error> = sqlx::query_as(
        "SELECT tenant_id, is_active, sessions_valid_after FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db.conn())
    .await;
    let user_row = match user_row {
        Ok(row) => row,
        Err(e) => return Ok(lookup_failed("user read", &e)),
    };

    let (tenant_id, is_active, sessions_valid_after) = user_row.ok_or_else(rejected_credential)?;
    if !is_active {
        return Err(ApiError::forbidden("this account is disabled").code(ApiErrorCode::UserInactive));
    }

    // A signed-out session is over even though its `exp` has not arrived. Only
    // interactive sessions are governed by the watermark — a provision token
    // carries a `jti` and is revoked through its own row below, so signing out
    // of the browser must not silently kill a running `ssai` CLI.
    if claims.scope == SCOPE_PORTAL
        && super::admin_auth::session_is_revoked(claims.iat, sessions_valid_after)
    {
        return Err(rejected_credential());
    }

    // Scope fence. Interactive sessions pass through; provision-scoped CLI
    // tokens are confined to the provisioning allowlist AND must present a
    // live (non-revoked, non-expired) jti row — the DB row is what makes
    // `ssai logout` / admin revocation take effect instantly instead
    // of at access-token expiry.
    match claims.scope.as_str() {
        SCOPE_PORTAL => {}
        SCOPE_PROVISION => {
            // This middleware runs inside the `/api/v1/portal` nest, where
            // axum has already stripped the prefix from `req.uri()` — read
            // the full path from `OriginalUri` (same as the audit middlewares).
            let full_path = req
                .extensions()
                .get::<axum::extract::OriginalUri>()
                .map(|u| u.path().to_string())
                .unwrap_or_else(|| req.uri().path().to_string());
            if !provision_scope_allows(req.method(), &full_path) {
                use axum::response::IntoResponse;
                return Ok(ApiError::forbidden(
                    "this endpoint is outside the CLI provisioning scope",
                )
                .code(ApiErrorCode::ProvisionScopeForbidden)
                .into_response());
            }
            let jti: Uuid = claims
                .jti
                .as_deref()
                .and_then(|j| j.parse().ok())
                .ok_or_else(rejected_credential)?;
            // Fail-closed: the row must exist and be live. Every provision
            // access token gets a `surface = 'cli'` row at mint time.
            let live: Result<Option<bool>, sqlx::Error> = sqlx::query_scalar(
                "SELECT true FROM oauth_issued_tokens \
                 WHERE jti = $1 AND surface = 'cli' \
                   AND revoked_at IS NULL AND expires_at > NOW()",
            )
            .bind(jti)
            .fetch_optional(db.conn())
            .await;
            let live = match live {
                Ok(live) => live,
                Err(e) => return Ok(lookup_failed("token read", &e)),
            };
            if live != Some(true) {
                return Err(rejected_credential());
            }
            // Best-effort last-used stamp, throttled to ~1/min per token — the
            // shape `automation_keys` already uses, for the same reason: a CLI
            // polls, and this sits on the auth hot path, so 59 of every 60
            // checks must cost a no-op UPDATE rather than a write.
            //
            // Deliberately a second statement rather than folded into the
            // liveness check above. An `UPDATE ... RETURNING` carrying the
            // throttle in its WHERE returns no row whenever the throttle
            // suppresses the write, which this caller reads as "not live" —
            // turning a stamp nobody needs into a 401 on a good token.
            //
            // The same write records what the CLI says it is (its version,
            // OS and host, from the `User-Agent`), for the portal Home's
            // "out of date" notice. A changed report is written at once, so
            // the notice clears on the first call after `ssai update`; an
            // unchanged one rides the throttle; a request without one keeps
            // what was recorded.
            let agent = req
                .headers()
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_cli_agent);
            let _ = sqlx::query(
                "UPDATE oauth_issued_tokens SET last_used_at = NOW(), \
                        cli_version = COALESCE($2, cli_version), cli_os = COALESCE($3, cli_os), \
                        cli_host = COALESCE($4, cli_host) \
                 WHERE jti = $1 AND surface = 'cli' \
                   AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '60 seconds' \
                        OR ($2::text IS NOT NULL \
                            AND (cli_version, cli_os, cli_host) IS DISTINCT FROM ($2::text, $3::text, $4::text)))",
            )
            .bind(jti)
            .bind(agent.as_ref().map(|a| a.version))
            .bind(agent.as_ref().map(|a| a.os))
            .bind(agent.as_ref().map(|a| a.host))
            .execute(db.conn())
            .await;
        }
        _ => return Err(rejected_credential()),
    }

    if claims.scope == SCOPE_PROVISION {
        req.extensions_mut().insert(ProvisionToken);
    }
    let user = PortalUser {
        user_id,
        session_iat: Some(claims.iat),
        email: claims.email,
        tenant_id,
        key_id: None,
        key_workspace_id: None,
    };
    // What the portal hides for the caller, on the connection the session
    // check already holds: one statement per request, read by every fence and
    // handler after it instead of a connection of their own.
    let hidden = match super::client_access_profiles::hidden_pages(db.conn(), &user).await {
        Ok(hidden) => hidden,
        Err(e) => return Ok(lookup_failed("hidden pages read", &e)),
    };

    // Release the pool connection BEFORE running the handler — handlers
    // acquire their own `TenantConn`, and holding this one across `next.run`
    // would pin two connections per in-flight portal request.
    drop(db);

    // Attach portal user context.
    req.extensions_mut().insert(user);
    req.extensions_mut().insert(hidden);

    Ok(next.run(req).await)
}

// ---------------------------------------------------------------------------
// The CLI's self-description
// ---------------------------------------------------------------------------

/// What an `ssai` CLI says about itself in its `User-Agent`:
/// `ssai/<version> (<os>; <host>)`. Self-reported and never an authorisation
/// input — it only names a host in the caller's own portal Home.
pub(crate) struct CliAgent<'a> {
    pub version: &'a str,
    pub os: &'a str,
    pub host: &'a str,
}

/// The longest version, OS and host name recorded (a DNS label is 63).
const CLI_VERSION_MAX: usize = 32;
const CLI_OS_MAX: usize = 16;
const CLI_HOST_MAX: usize = 63;

/// Parses an `ssai` `User-Agent`, or `None` for any other client and for one
/// whose parts are empty, too long or carry a character outside their set
/// (version: ASCII alphanumerics and `.+-`; OS: lowercase alphanumerics and
/// `_`; host: ASCII alphanumerics and `.-_`) — nothing unexpected is stored.
pub(crate) fn parse_cli_agent(ua: &str) -> Option<CliAgent<'_>> {
    let rest = ua.strip_prefix("ssai/")?;
    let (version, rest) = rest.split_once(" (")?;
    let inner = rest.strip_suffix(')')?;
    let (os, host) = inner.split_once("; ")?;
    let ok = |s: &str, max: usize, allowed: fn(char) -> bool| !s.is_empty() && s.len() <= max && s.chars().all(allowed);
    (ok(version, CLI_VERSION_MAX, |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        && ok(os, CLI_OS_MAX, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && ok(host, CLI_HOST_MAX, |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    .then_some(CliAgent { version, os, host })
}

// ---------------------------------------------------------------------------
// Provision-scope allowlist
// ---------------------------------------------------------------------------

/// Portal routes a provision-scoped CLI token may call — the surface the CLI
/// needs to discover, mint a gateway key, and pull a provisioning bundle, and
/// nothing else (no team/manager/automation/MCP-connection reach). Paths are
/// templates relative to `/api/v1/portal`; `{}` matches one non-empty
/// segment. Everything not listed 403s with `ProvisionScopeForbidden`.
const PROVISION_ALLOWED: &[(&str, &str)] = &[
    ("GET", "/auth/me"),
    ("GET", "/mcp/virtual-servers"),
    ("GET", "/mcp/local-servers"),
    ("GET", "/keys"),
    ("POST", "/keys"),
    ("POST", "/keys/{}/actions/revoke"),
    ("GET", "/quickstart/clients"),
    ("GET", "/quickstart/clients/{}"),
    ("GET", "/quickstart/routes"),
    ("GET", "/quickstart/keys"),
    ("POST", "/provision/actions/bundle"),
    ("GET", "/client-access"),
];

fn provision_scope_allows(method: &axum::http::Method, path: &str) -> bool {
    let Some(rel) = path.strip_prefix("/api/v1/portal") else {
        return false;
    };
    PROVISION_ALLOWED
        .iter()
        .any(|(m, tmpl)| method.as_str() == *m && template_matches(tmpl, rel))
}

/// Segment-wise template match: `{}` matches exactly one non-empty segment.
/// Keep [`PROVISION_ALLOWED`] in lockstep with `portal_router()` in
/// `routes/mod.rs` — a renamed portal route silently 403s every shipped CLI.
fn template_matches(tmpl: &str, path: &str) -> bool {
    let mut t = tmpl.split('/');
    let mut p = path.split('/');
    loop {
        match (t.next(), p.next()) {
            (None, None) => return true,
            (Some(ts), Some(ps)) => {
                if ts == "{}" {
                    if ps.is_empty() {
                        return false;
                    }
                } else if ts != ps {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Resolve a `Bearer ak-...` **portal automation key** to a [`PortalUser`].
/// `Ok(None)` is a refusal (→ 401); `Err` means the database did not answer
/// (→ 503). **Fail-closed at every branch** — the same scan as
/// [`authenticate_admin_key`](super::admin_auth::authenticate_admin_key)
/// ([`scan_automation_key`](super::admin_auth::scan_automation_key)) over ONLY
/// `plane='portal'` rows of `automation_keys` (never `api_keys` or admin-plane
/// rows), so a portal key is confined to the portal control plane.
///
/// The resolved `PortalUser` is the owning service account, carrying the key's
/// bound workspace in `key_workspace_id`; manager authority is then enforced
/// per request by [`verify_workspace_manager`](super::portal_manager::verify_workspace_manager).
pub async fn authenticate_portal_key(
    headers: &axum::http::HeaderMap,
    pool: &crate::db::Db,
) -> Result<Option<PortalUser>, ApiError> {
    use super::admin_auth::{scan_automation_key, KeyGrant, KeyPlane};
    let Some(key) = scan_automation_key(headers, pool, KeyPlane::Portal).await? else {
        return Ok(None);
    };
    let KeyGrant::Portal { workspace_id } = key.grant else {
        return Ok(None);
    };
    Ok(Some(PortalUser {
        session_iat: None,
        user_id: key.service_account_id,
        email: key.email,
        tenant_id: key.tenant_id.as_uuid(),
        key_id: Some(key.key_id),
        key_workspace_id: Some(workspace_id),
    }))
}

// ---------------------------------------------------------------------------
// Login endpoint
// ---------------------------------------------------------------------------

/// Portal login: verify email + password against `users` table, return JWT.
#[utoipa::path(
    post,
    path = "/api/v1/portal/auth/login",
    tag = "Portal Auth",
    request_body = PortalLoginRequest,
    responses(
        (status = 200, description = "Login successful, returns JWT and user info", body = PortalLoginResponse),
        (status = 401, description = "Invalid credentials", body = ApiErrorResponse),
        (status = 429, description = "Too many login attempts", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
)]
#[allow(clippy::type_complexity)]
pub async fn portal_login(
    State(state): State<Arc<AdminState>>,
    Json(mut req): Json<PortalLoginRequest>,
) -> Result<Json<PortalLoginResponse>, ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = crate::routes::normalize_email(&req.email);
    // Rate limit per (tenant, account) — only failed attempts count. Keyed on
    // the email ALONE this would be a cross-tenant denial of service: failed
    // attempts against one tenant would lock that address out of every other
    // tenant on the deployment, and the address is not a secret.
    // Keyed on the normalized address, so a change of case cannot reset it.
    let rate_key = format!("portal:{}:{}", req.tenant_slug, req.email);
    if state.login_rate_limiter.is_limited(&rate_key) {
        tracing::warn!(email = %req.email, tenant = %req.tenant_slug, "portal login rate limited");
        return Err(ApiError::too_many_requests("too many login attempts — try again later"));
    }

    // Fail before touching the database rather than after — the mint at the end
    // would fail anyway. Asked of the ring, so `keys.rs` stays the only reader
    // of the signing environment.
    if keyring().is_none() {
        return Err(crate::routes::no_signing_key());
    }

    // The named tenant decides which `users` row these credentials are checked
    // against, and it is the caller's to state. An email is unique within a
    // tenant and nowhere else, so a lookup that searches for the address
    // instead verifies the password against whichever tenant it happens to
    // find first — authenticating someone into a tenant they did not ask for.
    //
    // An unknown slug answers as bad credentials rather than "no such tenant":
    // this endpoint is public, and separating the two makes it a directory of
    // which organisations exist here.
    // A lookup that failed is a 503 (`?`): telling a user their password is
    // wrong during an outage is a claim nothing checked.
    let (found_tenant_id, tenant_active) = lookup_tenant_slug(&state.db, &req.tenant_slug)
        .await?
        .ok_or_else(|| {
            // Answered as an unknown email in a known tenant is: the same
            // Argon2 verify and the same limiter charge.
            dummy_password_verify(&req.password);
            state.login_rate_limiter.record_failure(&rate_key);
            ApiError::unauthorized("invalid credentials")
        })?;

    // A suspended tenant's credentials stop authenticating immediately.
    if !tenant_active {
        return Err(ApiError::forbidden("tenant suspended").code(ApiErrorCode::TenantInactive));
    }

    let mut db = crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_row(found_tenant_id),
    )
    .await
    .map_err(|e| {
        tracing::error!("portal login TenantConn acquire: {e}");
        // A database that could not be asked says nothing about the
        // credentials (503); any other failure is a fault (500).
        super::db_read_error(&e, "sign-in could not be checked")
    })?;

    // Reject password login when this tenant signs its users in through OIDC.
    let tenant_auth_mode: Option<String> = sqlx::query_scalar(
        "SELECT auth_mode FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(found_tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal login auth_mode query: {e}");
        // A database that could not be asked says nothing about the
        // credentials (503); any other failure is a fault (500).
        super::db_read_error(&e, "sign-in could not be checked")
    })?;

    if tenant_auth_mode.as_deref() == Some("oidc") {
        return Err(ApiError::bad_request("password login disabled for this tenant — use SSO")
            .code(ApiErrorCode::PasswordLoginDisabled));
    }

    // Service accounts are login-less principals — never authenticate one via
    // password, even if a password hash somehow landed on the row.
    let row: Option<(Uuid, String, Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT id, email, display_name, password_hash, is_active \
         FROM users WHERE email = $1 AND auth_source IS DISTINCT FROM 'service'",
    )
    .bind(&req.email)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal login user query: {e}");
        // A database that could not be asked says nothing about the
        // credentials (503); any other failure is a fault (500).
        super::db_read_error(&e, "sign-in could not be checked")
    })?;

    let Some((id, email, display_name, password_hash, is_active)) = row else {
        // Unknown email — run one Argon2 verify so timing matches a wrong
        // password (no user enumeration).
        dummy_password_verify(&req.password);
        state.login_rate_limiter.record_failure(&rate_key);
        return Err(ApiError::unauthorized("invalid credentials"));
    };

    // Verify the password and collapse every failure mode (no password set,
    // wrong password, disabled account) to one generic error — no message or
    // timing leak.
    let password_ok = match &password_hash {
        Some(h) => super::admin_auth::verify_password(&req.password, h),
        None => {
            dummy_password_verify(&req.password);
            false
        }
    };
    if !password_ok || !is_active {
        state.login_rate_limiter.record_failure(&rate_key);
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    // Successful login — reset rate limiter.
    state.login_rate_limiter.reset(&rate_key);

    // Generate portal JWT (includes tenant_id for efficient middleware lookup).
    let token = generate_portal_jwt(&id, &email, found_tenant_id)?;

    // Update last_login using a tenant-scoped connection to satisfy RLS.
    if let Ok(mut tdb) = crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_row(found_tenant_id),
    ).await {
        let _ = sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(tdb.conn())
            .await;
    }

    tracing::info!(email = %email, "portal login successful");

    Ok(Json(PortalLoginResponse {
        token,
        user: PortalUserResponse {
            id,
            email,
            display_name,
            is_active,
        },
        tenant_slug: req.tenant_slug,
    }))
}

/// End every interactive portal session for the calling user.
///
/// The mirror of the console's sign-out, and it stops at interactive sessions:
/// a `provision`-scoped CLI token is revoked through its own `oauth_issued_tokens`
/// row by `ssai logout`, so closing a browser tab must not also stop a
/// running CLI the person never touched.
#[utoipa::path(
    post,
    path = "/api/v1/portal/auth/logout",
    tag = "Portal Auth",
    responses(
        (status = 200, description = "Sessions ended", body = ActionResponse),
        (status = 401, description = "No valid session presented", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn portal_logout(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ActionResponse>, ApiError> {
    let token = bearer_token(&headers)?;
    let ring = keyring().ok_or_else(no_signing_key)?;

    let (claims, tenant_id_str) = decode_session_jwt::<PortalClaims>(&ring, token)
        .ok_or_else(rejected_credential)?;
    if claims.scope != SCOPE_PORTAL {
        return Err(rejected_credential());
    }

    let tenant_uuid: Uuid = tenant_id_str
        .parse()
        .map_err(|_| rejected_credential())?;
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| rejected_credential())?;

    let mut db = crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_credential(tenant_uuid),
    )
    .await
    .map_err(|e| {
        tracing::error!("portal logout TenantConn acquire: {e}");
        ApiError::service_unavailable("internal error")
    })?;

    // An already-signed-out token may not sign out again. Without this a stolen
    // token becomes a lockout weapon rather than merely a stale one: every call
    // re-stamps the watermark to now, and because the comparison is inclusive,
    // that also kills whatever session the victim has established since. The
    // holder could keep the account signed out for the token's whole remaining
    // life. The console twin gets this for free from `validate_session_token`;
    // this endpoint authenticates by hand and so must ask.
    let sessions_valid_after: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT sessions_valid_after FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("portal logout watermark read: {e}");
                ApiError::internal("internal error")
            })?
            .flatten();
    if super::admin_auth::session_is_revoked(claims.iat, sessions_valid_after) {
        return Err(rejected_credential());
    }

    // Stamped from this process's clock, not the database's. `iat` is minted
    // here too, so comparing the two against one clock is what keeps the check
    // meaningful when the database is on a different machine — a database clock
    // running ahead would otherwise revoke every *new* login on sight.
    sqlx::query("UPDATE users SET sessions_valid_after = $2 WHERE id = $1")
        .bind(user_id)
        .bind(Utc::now())
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("portal logout revoke: {e}");
            ApiError::internal("internal error")
        })?;

    tracing::info!(email = %claims.email, "portal sessions ended");
    Ok(Json(ActionResponse::ok().with_message("Signed out.")))
}

// ---------------------------------------------------------------------------
// Header-mode portal login
// ---------------------------------------------------------------------------

/// Header-mode portal login: exchanges X-Auth-Request-* headers for a portal JWT.
/// Auto-provisions or links user accounts. Triggers OIDC group sync.
///
/// SECURITY: reachable only under the deployment-wide `AUTH_MODE=header`, or —
/// when `ALLOW_OIDC_CLAIM_EXCHANGE` is on — to a caller presenting
/// `INTERNAL_SERVICE_SECRET`. Anything else gets a 404, so an exposed admin-api
/// port cannot be driven by forged headers.
///
/// The secret is *caller* authentication everywhere else in this deployment; on
/// this endpoint it is also *identity* proof, because past it the caller names
/// the user and the tenant and gets a session for them. That is the same
/// authority the admin plane's `oidc_exchange` grants, so it stands behind the
/// same operator opt-in and is likewise absent by default. Header mode is
/// unaffected: there the reverse proxy is the authentication and no secret is
/// involved.
#[utoipa::path(
    get,
    path = "/api/v1/portal/auth/header-me",
    tag = "Portal Auth",
    responses(
        (status = 200, description = "Header-mode login successful, returns JWT and user info", body = PortalLoginResponse),
        (status = 401, description = "Missing required headers", body = ApiErrorResponse),
        (status = 404, description = "Not available in standard auth mode", body = ApiErrorResponse),
    ),
)]
pub async fn portal_header_me(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<PortalLoginResponse>, ApiError> {
    // Security gate: header auth mode, OR — only where an operator has opted in
    // — an INTERNAL_SERVICE_SECRET bearer.
    //
    // In header mode a reverse proxy (Authelia, Authentik, oauth2-proxy) has
    // already authenticated the request and admin-api is not directly exposed,
    // so the headers ARE the credential — that deployment shape is the whole
    // reason this endpoint exists.
    //
    // The secret branch is different in kind: past it the caller *names* the
    // user and the tenant, so the secret is standing in for a proof of identity
    // rather than merely identifying the calling service. Anything holding it —
    // the browser tier among them — could otherwise mint a session for any user
    // in any tenant. It is therefore gated on the same operator setting as the
    // admin plane's `oidc_exchange`, and off unless a deployment provisions
    // portal users from its own already-verified identity source.
    //
    // Note this is the DEPLOYMENT-wide `AUTH_MODE` (standard | header), not the
    // per-tenant `tenant_auth_configs.auth_mode` (internal | oidc). The two are
    // spelled the same and mean different things; a tenant using OIDC runs under
    // `AUTH_MODE=standard` and so cannot reach this at all unless the operator
    // opted in — its identity comes from a verified ID token, and accepting a
    // bare header instead would make the signature optional.
    let is_trusted = matches!(
        super::admin_auth::auth_mode(),
        super::admin_auth::AuthMode::Header
    ) || (crate::settings::admin_settings().allow_oidc_claim_exchange
        && super::oidc_rp::require_internal_service_secret(&headers).is_ok());

    if !is_trusted {
        return Err(ApiError::route_not_found());
    }
    // Checked before provisioning writes anything a retry would repeat.
    keyring().ok_or_else(no_signing_key)?;

    let email = headers
        .get("x-auth-request-email")
        .and_then(|v| v.to_str().ok())
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::unauthorized("X-Auth-Request-Email header required").code(ApiErrorCode::MissingAuthHeader))?;

    let display_name = headers
        .get("x-auth-request-user")
        .and_then(|v| v.to_str().ok())
        .filter(|u| !u.is_empty());

    // Parse IdP groups from header (comma-separated).
    let groups: Vec<String> = headers
        .get("x-auth-request-groups")
        .and_then(|v| v.to_str().ok())
        .map(|g| {
            g.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let tenant_slug = crate::routes::admin_auth::header_auth_tenant_slug(&headers);

    let tenant_id: uuid::Uuid = sqlx::query_scalar(
        "SELECT id FROM tenants WHERE slug = $1 AND is_active = true",
    )
    .bind(&tenant_slug)
    .fetch_optional(state.db.global(Global::PreAuth))
    .await
    .map_err(|e| {
        tracing::error!("portal header-me tenant lookup: {e}");
        super::db_read_error(&e, "the tenant could not be looked up")
    })?
    .ok_or_else(|| ApiError::bad_request("unknown or inactive tenant").code(ApiErrorCode::TenantNotFound))?;

    // Acquire a tenant-scoped connection to pass RLS.
    let mut db = crate::db::tenant::TenantConn::acquire(
        &state.db,
        crate::db::tenant::TenantId::from_row(tenant_id),
    )
    .await
    .map_err(|e| {
        tracing::error!("portal header-me TenantConn acquire: {e}");
        ApiError::service_unavailable("internal error")
    })?;

    // The proxy's group header is published as the `groups` claim AND under the
    // tenant's configured groups claim (`group` on an AD FS tenant), so a
    // workspace rule written for the tenant's IdP keeps matching when sign-in
    // moves behind a proxy.
    let groups_claim: Option<String> = sqlx::query_scalar(
        "SELECT oidc_groups_claim FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal header-me groups claim: {e}");
        super::db_read_error(&e, "account could not be checked")
    })?;
    let mut claims = std::collections::BTreeMap::from([("groups".to_string(), groups.clone())]);
    if let Some(name) = groups_claim {
        claims.insert(name, groups);
    }

    // A reverse proxy authenticated this request before it arrived, so there is
    // no `email_verified` claim to inspect and nothing here to verify — see
    // `EmailAssurance`. The OIDC path states its assurance from the ID token.
    let user = crate::oidc::identity::provision_portal_user(
        &mut db,
        tenant_id,
        email,
        display_name,
        &claims,
        crate::oidc::identity::EmailAssurance::ProxyAuthenticated,
    )
    .await?;

    // Generate portal JWT (includes tenant_id for efficient middleware lookup).
    let token = generate_portal_jwt(&user.id, &user.email, tenant_id)?;

    Ok(Json(PortalLoginResponse {
        token,
        user: PortalUserResponse {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            is_active: user.is_active,
        },
        tenant_slug,
    }))
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

pub(crate) fn generate_portal_jwt(
    id: &Uuid,
    email: &str,
    tenant_id: Uuid,
) -> Result<String, ApiError> {
    let ring =
        keyring().ok_or_else(crate::routes::no_signing_key)?;

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let claims = PortalClaims {
        sub: id.to_string(),
        email: email.to_string(),
        role: "user".to_string(),
        tenant_id: tenant_id.to_string(),
        iss: streamscope_mcp_auth::TOKEN_ISSUER.to_string(),
        aud: tenant_id.to_string(),
        scope: SCOPE_PORTAL.to_string(),
        jti: None,
        iat,
        nbf: iat,
        exp: (now + chrono::Duration::hours(crate::settings::admin_settings().jwt_expiry_hours)).timestamp() as usize,
    };

    let (header, signing_key) = ring.signing_header(&claims.tenant_id);
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&signing_key)).map_err(|e| {
        tracing::error!("portal JWT encode: {e}");
        ApiError::internal("internal error")
    })
}

#[cfg(test)]
mod provision_fence_tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn allowlist_matches_full_original_paths_only() {
        // The fence receives the ORIGINAL (un-stripped) URI path.
        assert!(provision_scope_allows(&Method::GET, "/api/v1/portal/auth/me"));
        assert!(provision_scope_allows(&Method::POST, "/api/v1/portal/provision/actions/bundle"));
        assert!(provision_scope_allows(&Method::GET, "/api/v1/portal/quickstart/clients/claude-code"));
        assert!(provision_scope_allows(
            &Method::POST,
            "/api/v1/portal/keys/3f8b6e2a-0000-0000-0000-000000000000/actions/revoke"
        ));
        // Nest-stripped paths must NOT match (regression guard for the
        // OriginalUri requirement).
        assert!(!provision_scope_allows(&Method::GET, "/auth/me"));
    }

    fn parts(ua: &str) -> Option<(&str, &str, &str)> {
        parse_cli_agent(ua).map(|a| (a.version, a.os, a.host))
    }

    #[test]
    fn a_cli_user_agent_names_its_version_os_and_host() {
        assert_eq!(
            parts("ssai/2026.11.9 (linux; build-01)"),
            Some(("2026.11.9", "linux", "build-01"))
        );
        assert_eq!(
            parts("ssai/2026.11.30 (macos; Dev-MacBook_Pro.lan)"),
            Some(("2026.11.30", "macos", "Dev-MacBook_Pro.lan"))
        );
        // The longest parts still recorded.
        let host = "h".repeat(CLI_HOST_MAX);
        let ua = format!("ssai/{} ({}; {host})", "1".repeat(CLI_VERSION_MAX), "o".repeat(CLI_OS_MAX));
        assert!(parse_cli_agent(&ua).is_some());
    }

    #[test]
    fn anything_but_a_well_formed_cli_user_agent_records_nothing() {
        for ua in [
            "",
            "curl/8.5.0",
            "reqwest/0.12",
            "ssai/2026.11.9",
            "ssai/2026.11.9 (linux)",
            "ssai/2026.11.9 (linux; )",
            "ssai/ (linux; box)",
            "ssai/2026.11.9 (; box)",
            "ssai/2026.11.9 (linux; box",
            "ssai/2026.11.9 (linux; box) extra",
            "ssai/2026.11.9 (Linux; box)",
            "ssai/2026.11.9 (linux; my box)",
            "ssai/2026.11.9 (linux; box<script>)",
            "ssai/2026 11 (linux; box)",
            "ssai/2026.11.9 (linux; bôx)",
        ] {
            assert_eq!(parts(ua), None, "{ua:?}");
        }
        // One past each length.
        let too_long_host = format!("ssai/1 (linux; {})", "h".repeat(CLI_HOST_MAX + 1));
        let too_long_os = format!("ssai/1 ({}; box)", "o".repeat(CLI_OS_MAX + 1));
        let too_long_version = format!("ssai/{} (linux; box)", "1".repeat(CLI_VERSION_MAX + 1));
        for ua in [too_long_host, too_long_os, too_long_version] {
            assert_eq!(parts(&ua), None, "{ua:?}");
        }
    }

    #[test]
    fn allowlist_fences_everything_else() {
        assert!(!provision_scope_allows(&Method::GET, "/api/v1/portal/stats"));
        assert!(!provision_scope_allows(&Method::GET, "/api/v1/portal/mcp/connections"));
        assert!(!provision_scope_allows(&Method::POST, "/api/v1/portal/quickstart/actions/render"));
        assert!(!provision_scope_allows(
            &Method::GET,
            "/api/v1/portal/workspaces/x/members"
        ));
        // Method matters.
        assert!(!provision_scope_allows(&Method::DELETE, "/api/v1/portal/keys"));
        // `{}` matches exactly one segment — no traversal.
        assert!(!provision_scope_allows(
            &Method::POST,
            "/api/v1/portal/keys/a/b/actions/revoke"
        ));
        assert!(!provision_scope_allows(&Method::POST, "/api/v1/portal/keys//actions/revoke"));
    }
}
