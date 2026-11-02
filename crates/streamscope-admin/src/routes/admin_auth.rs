//! Admin authentication — credential login, JWT sessions, OIDC exchange, and proxy header auth.
//!
//! Admin accounts are separate from service users (`admin_accounts` vs `users` table).
//! Passwords use Argon2 hashing. Sessions are JWT (HMAC-SHA256, 8h expiry) signed
//! with a per-tenant key derived from `AUTH_SECRET`. Supports OIDC token exchange
//! and trusted proxy header auth via `x-auth-request-email` (sole identity carrier),
//! `x-auth-request-groups` (comma-separated IdP groups), and `x-tenant-slug` (default: system).

use std::sync::Arc;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation};
use streamscope_mcp_auth::keys::{self, Keyring};
use streamscope_mcp_auth::TOKEN_ISSUER;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AdminState;
use crate::authz::AdminRole;
use crate::db::tenant::{AdminTenantCtx, Scoped, TenantConn, TenantId};
use crate::db::Global;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};

/// Reserved tenant slugs that cannot be used for new tenants.
const RESERVED_SLUGS: &[&str] = &[
    "system", "admin", "api", "auth", "portal", "internal", "health",
    "login", "setup", "invite", "static", "assets", "fwd", "edge",
];

// ---------------------------------------------------------------------------
// Auth mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Standard mode: per-tenant auth (internal password or OIDC, configured in DB).
    Standard,
    /// Header mode: instance-wide reverse proxy auth (Authelia, Authentik, etc.).
    Header,
}

pub fn auth_mode() -> AuthMode {
    match crate::settings::admin_settings().auth_mode.as_str() {
        "header" => AuthMode::Header,
        _ => AuthMode::Standard,
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateAdminAccountRequest {
    pub email: String,
    /// Optional display name (kept in sync with a sibling gateway user row).
    pub display_name: Option<String>,
    pub password: Option<String>,
    /// Console role: `admin` (default) or `read_only`. Ignored on the SYSTEM
    /// tenant, where admins are always full super-admins.
    pub role: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateAdminAccountRequest {
    pub email: Option<String>,
    /// New display name. Absent = unchanged; explicit `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub display_name: Option<Option<String>>,
    pub password: Option<String>,
    pub is_active: Option<bool>,
    /// Console role: `admin` or `read_only`. `is_super_admin` stays excluded —
    /// it can never be set via the API.
    pub role: Option<String>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct AdminAccountResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_super_admin: bool,
    pub is_active: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub last_login: Option<chrono::DateTime<Utc>>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// Tenant slug (default: "system"). Routes login to the correct tenant.
    #[serde(default = "default_system_slug")]
    pub tenant_slug: String,
}

fn default_system_slug() -> String {
    "system".to_string()
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub user: AdminAccountResponse,
    /// True when the admin has not yet seen the changelog for the current version.
    pub changelog_pending: bool,
}

/// JWT claims for admin session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,       // account UUID
    pub email: String,
    pub role: String,
    pub iss: String,       // "streamscope"
    pub aud: String,       // tenant UUID — determines signing key
    #[serde(rename = "type")]
    pub token_type: String, // "admin"
    pub is_super_admin: bool,
    pub tenant_id: String, // tenant UUID (kept for clarity alongside aud)
    pub exp: usize,
    pub iat: usize,
    /// Equal to `iat`. Required and validated — see [`streamscope_jwt_validation`].
    pub nbf: usize,
}

impl SessionTenant for AdminClaims {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// Setup wizard request body.
#[derive(Deserialize, ToSchema)]
pub struct SetupRequest {
    pub email: String,
    pub password: String,
}

/// Setup wizard response.
#[derive(Serialize, ToSchema)]
pub struct SetupResponse {
    pub token: String,
    pub user: AdminAccountResponse,
    /// Always true for new accounts.
    pub changelog_pending: bool,
}

/// Setup status response.
#[derive(Serialize, ToSchema)]
pub struct SetupStatusResponse {
    pub needs_setup: bool,
    /// Slug of the only active organisation (a tenant other than `system`)
    /// when exactly one exists, else null. Lets the landings and login pages
    /// skip the unanswerable "organization" prompt on a single-organisation
    /// install.
    pub single_tenant_slug: Option<String>,
}

// ---------------------------------------------------------------------------
// Tenant slug validation
// ---------------------------------------------------------------------------

/// Compiled slug regex — cached for process lifetime.
static SLUG_REGEX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$").unwrap());

/// Validate a tenant slug: lowercase alnum + hyphens, 2-50 chars, no reserved words.
pub fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.len() < 2 {
        return Err("slug must be at least 2 characters".to_string());
    }
    if !SLUG_REGEX.is_match(slug) {
        return Err("slug must be lowercase alphanumeric with hyphens, 2-50 chars".to_string());
    }
    if RESERVED_SLUGS.contains(&slug) {
        return Err(format!("slug '{slug}' is reserved"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-tenant JWT signing keys
// ---------------------------------------------------------------------------

/// The signing keys this process mints and verifies with. `None` when
/// `AUTH_SECRET` is unset or empty — every caller turns that into a 503, since
/// no session can be issued or checked without it.
///
/// Read fresh rather than memoised; see [`Keyring::from_env`].
pub fn keyring() -> Option<Keyring> {
    Keyring::from_env()
}

/// The key that verifies `token`, plus the tenant its `kid` names. `None` for a
/// token with no `kid`, a malformed one, or one naming a retired generation.
///
/// **A primitive, not an entry point.** The tenant it returns is
/// attacker-supplied and only *selects* a key; nothing here binds the token to
/// it. The two doors that do are [`decode_session_jwt`] (console + portal) and
/// `oauth_common::decode_refresh_jwt` (both OAuth surfaces), each of which
/// pins every tenant claim its callers read. A new caller that decodes a
/// streamscope JWT belongs behind one of those, not here.
pub(crate) fn session_verification_key(
    ring: &Keyring,
    token: &str,
) -> Option<(String, Vec<u8>)> {
    keys::verification_key_for(token, ring).ok()
}

/// The tenant a session JWT names in its `tenant_id` claim.
///
/// `aud` is bound by [`streamscope_jwt_validation`]; this is the *other* tenant
/// claim, and the two are read by different callers — the console reads `aud`,
/// the portal reads `tenant_id` to pick a tenant's RLS database context and to
/// populate the `PortalUser` every portal authorization check runs against.
/// Pinning only one would leave the other free to name a different tenant than
/// the key that signed the token. [`decode_session_jwt`] binds this one, and
/// the trait bound is what makes a new session-decode site unable to skip it.
pub(crate) trait SessionTenant {
    fn tenant_id(&self) -> &str;
}

/// Decode + verify a session JWT against the key its `kid` names, binding both
/// tenant claims to that key. Returns the claims and the tenant they are bound
/// to.
///
/// `None` for an absent / malformed / retired-generation `kid`, a bad
/// signature or expiry, or a payload whose `tenant_id` disagrees with the key
/// that signed it.
pub(crate) fn decode_session_jwt<T>(ring: &Keyring, token: &str) -> Option<(T, String)>
where
    T: serde::de::DeserializeOwned + SessionTenant,
{
    let (kid_tenant, key) = session_verification_key(ring, token)?;
    let data = jsonwebtoken::decode::<T>(
        token,
        &DecodingKey::from_secret(&key),
        &streamscope_jwt_validation(&kid_tenant),
    )
    .ok()?;
    if data.claims.tenant_id() != kid_tenant {
        return None;
    }
    Some((data.claims, kid_tenant))
}

/// `Validation` for a streamscope-issued JWT: requires `exp`/`nbf`/`iss`/`aud`,
/// pins the issuer to [`TOKEN_ISSUER`], and binds the audience to one tenant.
/// Shared by admin, portal, and MCP-OAuth token verification.
///
/// `nbf` is both required and validated: `validate_nbf` alone silently passes a
/// token that simply omits the claim, so dropping either half makes the check
/// cosmetic.
pub(crate) fn streamscope_jwt_validation(audience: &str) -> Validation {
    let mut validation = Validation { validate_nbf: true, ..Validation::default() };
    validation.set_required_spec_claims::<&str>(&["exp", "nbf", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[audience]);
    validation
}

/// Which tenant a header-authenticated request belongs to.
///
/// In `AUTH_MODE=header` a reverse proxy proves *identity* and this decides
/// which tenant that identity is provisioned into — so it decides the
/// permissions too, and a caller who picks it picks their own. `X-Tenant-Slug`
/// is therefore ignored unless an operator states that their proxy sets it,
/// because nothing here can distinguish a header the proxy overwrote from one
/// the client wrote. A pin always beats the header: a deployment that named its
/// tenant must not be steerable away from it.
///
/// Both planes MUST route through this — the console gate and the portal gate
/// reading the header independently is how one of them ends up trusting it.
pub fn header_auth_tenant_slug(headers: &axum::http::HeaderMap) -> String {
    let s = crate::settings::admin_settings();
    resolve_header_auth_tenant(
        &s.header_auth_tenant_slug,
        s.header_auth_trust_tenant_header,
        headers
            .get("x-tenant-slug")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty()),
    )
    .to_string()
}

/// The decision itself, with no ambient state — so every branch is testable and
/// the "off by default" property is proven rather than asserted.
pub(crate) fn resolve_header_auth_tenant<'a>(
    pinned: &'a str,
    trust_header: bool,
    header: Option<&'a str>,
) -> &'a str {
    match (pinned, trust_header, header) {
        ("", true, Some(slug)) => slug,
        ("", _, _) => "system",
        (pinned, _, _) => pinned,
    }
}

// ---------------------------------------------------------------------------
// Resolve tenant from slug (no RLS — tenants table is the root)
// ---------------------------------------------------------------------------

/// Resolve a tenant slug to (tenant_id, is_active). Reads the `tenants` registry.
/// A missing tenant is 404 `TenantNotFound`; a lookup that failed is 503.
pub async fn resolve_tenant_slug(
    pool: &crate::db::Db,
    slug: &str,
) -> Result<(Uuid, bool), ApiError> {
    lookup_tenant_slug(pool, slug)
        .await?
        .ok_or_else(|| ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound))
}

/// [`resolve_tenant_slug`] for a caller that answers a missing tenant its own
/// way (a sign-in path answering "invalid credentials" so it is not a directory
/// of tenants): `Ok(None)` is "no such tenant", `Err` is a 503 to propagate.
pub async fn lookup_tenant_slug(
    pool: &crate::db::Db,
    slug: &str,
) -> Result<Option<(Uuid, bool)>, ApiError> {
    sqlx::query_as(
        "SELECT id, is_active FROM tenants WHERE slug = $1",
    )
    .bind(slug)
    .fetch_optional(pool.global(Global::TenantRegistry))
    .await
    .map_err(|e| {
        tracing::warn!("lookup_tenant_slug: {e}");
        // A lookup that failed says nothing about the tenant: never the "no
        // such tenant" answer a caller gives `Ok(None)` — 503 when the database
        // could not be asked, 500 for any other fault.
        super::db_read_error(&e, "the tenant could not be looked up")
    })
}

// ---------------------------------------------------------------------------
// Admin automation key (ak-) authentication
// ---------------------------------------------------------------------------

/// The presented `ak-` token's limiter key, or `None` when this request is not
/// automation traffic (no bearer, or a JWT session — which is limited elsewhere
/// and must never draw on an automation budget) or the limiter is disabled.
///
/// A cap of 0 means disabled: counting against it would reject every request.
fn automation_key_bucket(
    limiter: &streamscope_core::middleware::ip_rate_limit::RateLimiter,
    headers: &axum::http::HeaderMap,
) -> Option<String> {
    if limiter.max_attempts() == 0 {
        return None;
    }
    super::bearer_token(headers)
        .ok()
        .filter(|v| v.starts_with("ak-"))
        .map(streamscope_core::auth::virtual_key::hash_key)
}

/// Is the `ak-` automation key on this request already over its per-key window
/// cap? Called before authenticating, so a key known to be flooding is rejected
/// on a hash and a map lookup with no tenant scan behind it.
///
/// **This bounds repetition of ONE key — it is not brute-force protection.** A
/// prober varying the token gets a distinct bucket every time and is not slowed
/// at all; bounding that needs a per-source limiter, which the authenticated
/// routers do not carry.
///
/// Pairs with [`record_automation_key_use`], which is what actually fills the
/// bucket. Checking here and counting there is deliberate: only a key that
/// authenticated is ever tracked, so a spray of junk `ak-`-shaped tokens cannot
/// grow the limiter's map with attacker-chosen entries.
pub fn automation_key_rate_limited(
    limiter: &streamscope_core::middleware::ip_rate_limit::RateLimiter,
    headers: &axum::http::HeaderMap,
) -> bool {
    automation_key_bucket(limiter, headers).is_some_and(|bucket| limiter.is_limited(&bucket))
}

/// Charge one request to the presented `ak-` key's budget. Call only once the
/// key has authenticated — see [`automation_key_rate_limited`] for why.
pub fn record_automation_key_use(limiter: &streamscope_core::middleware::ip_rate_limit::RateLimiter, headers: &axum::http::HeaderMap) {
    if let Some(bucket) = automation_key_bucket(limiter, headers) {
        limiter.record_failure(&bucket);
    }
}

/// How an `ak-` tenant scan fails when no tenant that answered held the key.
///
/// A tenant that could not be asked (503, retry) outranks one that faulted
/// (500): either way the key was not found, and the retryable answer is the one
/// automation can act on. Only the first failure is logged, so an outage does
/// not write one line per tenant per request. Shared by both planes' scans so
/// they cannot answer one outage differently.
#[derive(Default)]
pub(crate) struct ScanFailure(Option<ApiError>);

impl ScanFailure {
    pub(crate) fn record(&mut self, scan: &str, what: &str, e: &sqlx::Error) {
        let failed = super::db_read_error(e, "credentials could not be checked");
        let held_503 = self.0.as_ref().is_some_and(|held| held.status == StatusCode::SERVICE_UNAVAILABLE);
        // Logged when it becomes the answer, so the line names the cause the
        // caller is given: the first failure, and a 503 replacing a held 500.
        if self.0.is_none() || (!held_503 && failed.status == StatusCode::SERVICE_UNAVAILABLE) {
            tracing::warn!("{scan}: {what} failed: {e}");
        }
        if !held_503 {
            self.0 = Some(failed);
        }
    }

    /// A pool that timed out or closed fails every acquire after it, so the
    /// scan stops there rather than wait out the acquire timeout once per
    /// remaining tenant. A failed READ is one tenant's, and the scan goes on.
    pub(crate) fn ends_the_scan(e: &sqlx::Error) -> bool {
        matches!(e, sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed)
    }

    pub(crate) fn into_result<T>(self) -> Result<Option<T>, ApiError> {
        self.0.map_or(Ok(None), Err)
    }
}

/// The control plane an `ak-` key belongs to (`automation_keys.plane`) — and
/// what a key of that plane grants. The table's CHECK holds the shape: an
/// admin-plane row carries a scope and no workspace, a portal-plane row the
/// reverse.
#[derive(Clone, Copy)]
pub(crate) enum KeyPlane {
    Admin,
    Portal,
}

impl KeyPlane {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Portal => "portal",
        }
    }

    fn scan_label(self) -> &'static str {
        match self {
            Self::Admin => "automation key check",
            Self::Portal => "portal automation key check",
        }
    }
}

/// What a resolved key grants, by its plane.
pub(crate) enum KeyGrant {
    /// An admin-plane key's `admin_scope`.
    Admin { scope: String },
    /// A portal-plane key's confining workspace.
    Portal { workspace_id: Uuid },
}

/// A live `ak-` key the scan resolved, with the account that owns it.
pub(crate) struct ScannedKey {
    pub tenant_id: TenantId,
    pub key_id: Uuid,
    pub service_account_id: Uuid,
    pub email: String,
    pub grant: KeyGrant,
}

/// Resolve a `Bearer ak-...` key of `plane` — the one scan both planes'
/// authenticators share.
///
/// `automation_keys` is FORCE-RLS, so a key resolves only inside its own
/// tenant's RLS context: iterate the tenants and look the globally unique hash
/// up within each — it resolves in exactly one, and the RLS-scoped read is the
/// authoritative verify. O(tenants) on the control plane. Inactive tenants are
/// skipped, so a suspended tenant's keys stop authenticating.
///
/// `Ok(None)` is a refusal (→ 401), **fail-closed at every branch**: a
/// missing/garbage header, a key of another family or plane, an unknown,
/// revoked or expired key, an inactive owner. `Err` means the database did not
/// answer, which proves nothing about the key (→ 503): a key found in a tenant
/// that answered wins over one that did not, and "no such key" needs every
/// tenant to have answered.
pub(crate) async fn scan_automation_key(
    headers: &axum::http::HeaderMap,
    pool: &crate::db::Db,
    plane: KeyPlane,
) -> Result<Option<ScannedKey>, ApiError> {
    let Ok(bearer) = super::bearer_token(headers) else {
        return Ok(None);
    };
    // Only the ak- family enters this path; sk-/vk- are proxy data-plane keys and
    // a JWT was already tried by the caller.
    if !bearer.starts_with("ak-") {
        return Ok(None);
    }
    let key_hash = streamscope_core::auth::virtual_key::hash_key(bearer);
    let label = plane.scan_label();

    // The key names its tenant by its hash alone (`resolve_automation_key`:
    // the hash is unique across tenants); the key itself is then read under
    // that tenant's scope.
    let tenants: Vec<(Uuid, bool)> =
        sqlx::query_as("SELECT t.id, t.is_active FROM tenants t WHERE t.id = (SELECT resolve_automation_key($1))")
        .bind(&key_hash)
        .fetch_all(pool.global(Global::PreAuth))
        .await
        .map_err(|e| {
            tracing::warn!("{label}: tenant list failed: {e}");
            super::db_read_error(&e, "credentials could not be checked")
        })?;

    let mut failures = ScanFailure::default();
    for (tenant_uuid, tenant_active) in tenants {
        if !tenant_active {
            continue;
        }
        let tenant_id = TenantId::from_row(tenant_uuid);
        let mut db = match TenantConn::acquire(pool, tenant_id).await {
            Ok(db) => db,
            Err(e) => {
                failures.record(label, "connection", &e);
                if ScanFailure::ends_the_scan(&e) {
                    return failures.into_result();
                }
                continue;
            }
        };

        // Authoritative RLS-scoped read of `automation_keys` — control-plane keys
        // live in their own table, never `api_keys`, so they can never be confused
        // with a gateway key, and the plane filter keeps each plane's keys on
        // their own plane. `revoked_at IS NULL` lives in the WHERE so the partial
        // live-key index serves it.
        #[allow(clippy::type_complexity)]
        let row: Result<
            Option<(Uuid, Uuid, Option<String>, Option<Uuid>, String, Option<chrono::DateTime<Utc>>)>,
            sqlx::Error,
        > = sqlx::query_as(
            "SELECT k.id, k.service_account_id, k.admin_scope, k.workspace_id, u.email, k.expires_at \
             FROM automation_keys k JOIN users u ON u.id = k.service_account_id \
             WHERE k.key_hash = $1 AND k.plane = $2 AND k.revoked_at IS NULL \
               AND u.is_active = true",
        )
        .bind(&key_hash)
        .bind(plane.as_str())
        .fetch_optional(db.conn())
        .await;

        let Some((key_id, service_account_id, scope, workspace_id, email, expires_at)) = (match row {
            Ok(row) => row,
            Err(e) => {
                failures.record(label, "key read", &e);
                continue;
            }
        }) else {
            continue;
        };

        // Lifecycle — fail closed. The hash is unique, so a found-but-expired key
        // is terminal: stop, don't keep scanning other tenants.
        if let Some(exp) = expires_at
            && exp < Utc::now()
        {
            return Ok(None);
        }
        // The table's CHECK holds this shape; a row without it grants nothing.
        let grant = match (plane, scope, workspace_id) {
            (KeyPlane::Admin, Some(scope), None) => KeyGrant::Admin { scope },
            (KeyPlane::Portal, None, Some(workspace_id)) => KeyGrant::Portal { workspace_id },
            _ => return Ok(None),
        };

        // Best-effort last-used stamp, throttled to ~1/min per key — automation
        // keys are high-frequency callers and this sits on the auth hot path.
        let _ = sqlx::query(
            "UPDATE automation_keys SET last_used_at = NOW() \
             WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '60 seconds')",
        )
        .bind(key_id)
        .execute(db.conn())
        .await;

        return Ok(Some(ScannedKey { tenant_id, key_id, service_account_id, email, grant }));
    }

    failures.into_result()
}

/// Resolve a `Bearer ak-...` admin automation key to an [`AdminTenantCtx`].
/// `Ok(None)` is a refusal (→ 401). **Fail-closed at every branch**: a
/// missing/garbage header, unknown / revoked / expired key, inactive owner, or
/// wrong tenant returns `Ok(None)` — never a privilege fallback.
///
/// `Err` means the database did not answer, which proves nothing about the key
/// (→ 503, as for a console session): automation that rotates or alerts on a
/// 401 must not read a Postgres restart as a revoked key. A key found in a
/// tenant that answered wins over a tenant that did not; "no such key" needs
/// every tenant to have answered. The 503 is marked `AutomationKeyUnverified`,
/// so the per-source throttle charges it as it would the refusal — a probe
/// costs a full scan either way, and an uncharged one would be unthrottled.
///
/// The key self-identifies its tenant — no `X-Tenant-Slug` header is consulted;
/// [`scan_automation_key`] finds it.
pub async fn authenticate_admin_key(
    headers: &axum::http::HeaderMap,
    pool: &crate::db::Db,
) -> Result<Option<AdminTenantCtx>, ApiError> {
    let Some(key) = scan_automation_key(headers, pool, KeyPlane::Admin).await? else {
        return Ok(None);
    };
    let KeyGrant::Admin { scope } = key.grant else {
        return Ok(None);
    };
    let role = AdminRole::from_admin_scope(&scope);
    // `super_admin` grants cross-tenant super-admin ONLY for a SYSTEM-tenant
    // key. Defense in depth alongside the create-time validation: even a
    // mis-stamped non-SYSTEM `super_admin` row can never resolve true.
    let is_super_admin =
        scope == crate::authz::admin_scope::SUPER_ADMIN && key.tenant_id == TenantId::SYSTEM;
    Ok(Some(AdminTenantCtx {
        tenant_id: key.tenant_id,
        admin_account_id: key.service_account_id,
        is_super_admin,
        role,
        actor_key_id: Some(key.key_id),
        key_scope: Some(scope),
    }))
}

// ---------------------------------------------------------------------------
// Admin account CRUD (protected by admin_auth middleware)
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/admin-accounts",
    tag = "Admin Accounts",
    request_body = CreateAdminAccountRequest,
    responses(
        (status = 201, description = "Admin account created", body = AdminAccountResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Email already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_admin_account(
    mut db: TenantConn,
    Json(mut req): Json<CreateAdminAccountRequest>,
) -> Result<(StatusCode, Json<AdminAccountResponse>), ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = crate::routes::normalize_email(&req.email);
    crate::routes::require_address(&req.email)?;
    let tenant_id = db.tenant_uuid();
    let password_hash: Option<String> = match &req.password {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw).map_err(|e| {
            tracing::error!("password hashing failed: {e}");
            ApiError::internal("internal error")
        })?),
        // No password supplied: inherit the one already set on a sibling gateway
        // user row for this email, so a console grant added to an existing
        // identity stays password-loginable (NULL otherwise).
        _ => existing_password_hash_for_email(db.conn(), tenant_id, &req.email).await?,
    };

    // System tenant admins are automatically super-admins (always full Admin).
    let is_system = db.tenant_uuid() == crate::db::tenant::TenantId::SYSTEM.as_uuid();

    // Resolve the requested console role. System tenant ignores it (super-admin
    // ⇒ full Admin); elsewhere default to Admin, reject an unknown string.
    let role = if is_system {
        AdminRole::Admin
    } else {
        match req.role.as_deref() {
            None => AdminRole::Admin,
            Some(s) => AdminRole::parse_strict(s).ok_or_else(|| {
                ApiError::bad_request("role must be 'admin' or 'read_only'")
                    .code(ApiErrorCode::ValidationFailed)
            })?,
        }
    };

    let row = sqlx::query_as::<_, AdminAccountResponse>(
        "INSERT INTO admin_accounts (email, display_name, password_hash, tenant_id, is_super_admin, role) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
    )
    .bind(&req.email)
    .bind(req.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(&password_hash)
    .bind(tenant_id)
    .bind(is_system)
    .bind(role.as_str())
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("email already exists", ApiErrorCode::AccountEmailTaken)
        } else {
            tracing::error!("create admin account: {e}");
            ApiError::internal("internal error")
        }
    })?;

    // One identity, one password: propagate to a sibling gateway user row if one
    // exists for this email (no-op otherwise).
    if let Some(hash) = &password_hash {
        sync_password_for_email(db.conn(), tenant_id, &req.email, hash).await?;
    }
    // Same for the display name.
    if let Some(name) = req.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        sync_display_name_for_email(db.conn(), tenant_id, &req.email, Some(name)).await?;
    }

    tracing::info!(email = %req.email, "admin account created");
    Ok((StatusCode::CREATED, Json(row)))
}

/// One identity per `(tenant_id, email)` shares a single internal-mode password.
/// Writes `hash` to both the `admin_accounts` and `users` rows for the email
/// (whichever exist). Login still verifies against each plane's own row; the
/// hashes are simply kept identical. OIDC accounts have NULL hashes and are
/// untouched in practice because this only runs when a password is being set.
pub async fn sync_password_for_email(
    conn: &mut Scoped,
    tenant_id: Uuid,
    email: &str,
    hash: &str,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE admin_accounts SET password_hash = $3 WHERE tenant_id = $1 AND email = $2")
        .bind(tenant_id)
        .bind(email)
        .bind(hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("sync password (admin_accounts): {e}");
            ApiError::internal("internal error")
        })?;
    // Never stamp a password onto a service-account row — it is a login-less
    // principal; a credential there would make it portal-loginable on an email
    // collision with a human account.
    sqlx::query(
        "UPDATE users SET password_hash = $3 \
         WHERE tenant_id = $1 AND email = $2 AND auth_source IS DISTINCT FROM 'service'",
    )
        .bind(tenant_id)
        .bind(email)
        .bind(hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("sync password (users): {e}");
            ApiError::internal("internal error")
        })?;
    Ok(())
}

/// Resolve an already-set internal password hash for `email` from whichever
/// plane row carries one. Creating the *second* plane of an existing identity
/// (e.g. granting gateway access to a console admin, or vice versa) must inherit
/// the one credential rather than landing a NULL hash — a NULL hash silently
/// breaks login on the newly-created plane. Service-account `users` rows are
/// excluded: they are login-less principals and never lend a credential.
pub async fn existing_password_hash_for_email(
    conn: &mut Scoped,
    tenant_id: Uuid,
    email: &str,
) -> Result<Option<String>, ApiError> {
    let hash: Option<Option<String>> = sqlx::query_scalar(
        "SELECT password_hash FROM admin_accounts \
           WHERE tenant_id = $1 AND email = $2 AND password_hash IS NOT NULL \
         UNION ALL \
         SELECT password_hash FROM users \
           WHERE tenant_id = $1 AND email = $2 AND password_hash IS NOT NULL \
             AND auth_source IS DISTINCT FROM 'service' \
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("lookup existing password hash: {e}");
        ApiError::internal("internal error")
    })?;
    Ok(hash.flatten())
}

/// One identity, one display name: write `name` to both the `admin_accounts`
/// and `users` rows for the email (whichever exist). Service-account rows are
/// skipped like the password sync — their name is their own.
pub async fn sync_display_name_for_email(
    conn: &mut Scoped,
    tenant_id: Uuid,
    email: &str,
    name: Option<&str>,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE admin_accounts SET display_name = $3 WHERE tenant_id = $1 AND email = $2")
        .bind(tenant_id)
        .bind(email)
        .bind(name)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("sync display name (admin_accounts): {e}");
            ApiError::internal("internal error")
        })?;
    sqlx::query(
        "UPDATE users SET display_name = $3 \
         WHERE tenant_id = $1 AND email = $2 AND auth_source IS DISTINCT FROM 'service'",
    )
    .bind(tenant_id)
    .bind(email)
    .bind(name)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("sync display name (users): {e}");
        ApiError::internal("internal error")
    })?;
    Ok(())
}

/// Keep the two planes correlated when an email is renamed: point both the
/// `admin_accounts` and `users` rows for `old_email` at `new_email`. The caller's
/// own table row is already at `new_email`, so its `WHERE email = old_email` is a
/// no-op there; only the sibling row is moved. A genuine collision (another
/// account already owns `new_email` in the sibling table) surfaces as an error.
pub async fn sync_email_rename(
    conn: &mut Scoped,
    tenant_id: Uuid,
    old_email: &str,
    new_email: &str,
) -> Result<(), ApiError> {
    for table in ["admin_accounts", "users"] {
        sqlx::query(sqlx::AssertSqlSafe(&*format!(
            "UPDATE {table} SET email = $3 WHERE tenant_id = $1 AND email = $2"
        )))
        .bind(tenant_id)
        .bind(old_email)
        .bind(new_email)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            if super::is_unique_violation(&e) {
                // The collision is in the sibling table: name whose address it is.
                let code = if table == "users" {
                    ApiErrorCode::UserEmailTaken
                } else {
                    ApiErrorCode::AccountEmailTaken
                };
                ApiError::conflict("email already in use", code)
            } else {
                tracing::error!("sync email rename ({table}): {e}");
                ApiError::internal("internal error")
            }
        })?;
    }
    Ok(())
}

/// Map a user's IdP `groups` claim to a console role (OIDC mode). Membership in
/// `admin_group` → [`AdminRole::Admin`] (wins if both match); else membership in
/// `readonly_group` → [`AdminRole::ReadOnly`]; else `None` (no console access).
/// Empty/unset group config never matches. Recomputed on every login so the
/// console role tracks IdP group membership authoritatively.
pub(crate) fn derive_console_role(
    groups: &[String],
    admin_group: Option<&str>,
    readonly_group: Option<&str>,
) -> Option<AdminRole> {
    let in_group = |g: Option<&str>| {
        matches!(g, Some(v) if !v.is_empty() && groups.iter().any(|c| c == v))
    };
    if in_group(admin_group) {
        Some(AdminRole::Admin)
    } else if in_group(readonly_group) {
        Some(AdminRole::ReadOnly)
    } else {
        None
    }
}

/// Number of *other* active full-Admin console accounts in the tenant — the
/// lockout guard for delete / demote / disable. Excludes `exclude_id` (the row
/// being changed) and read-only accounts. On the platform tenant a full Admin is
/// one holding the super-admin grant — every platform page needs it — so an
/// Admin without it does not count. Used to refuse the last-admin removal.
pub(crate) async fn other_active_admins(
    conn: &mut Scoped,
    tenant_id: Uuid,
    exclude_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM admin_accounts \
         WHERE tenant_id = $1 AND id <> $2 AND is_active = true AND role = 'admin' \
           AND (is_super_admin OR tenant_id <> $3)",
    )
    .bind(tenant_id)
    .bind(exclude_id)
    .bind(crate::db::tenant::TenantId::SYSTEM.as_uuid())
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("count active admins: {e}");
        super::db_read_error(&e, "account could not be checked")
    })
}

/// Whether `acct` is one of the accounts [`other_active_admins`] counts: an active
/// full Admin, and on the platform tenant one holding the super-admin grant. Every
/// last-admin guard asks it of its target, so a guard never protects (nor is
/// blocked by) an account the count leaves out.
pub(crate) fn counts_as_console_admin(acct: &AdminAccountResponse, tenant_id: Uuid) -> bool {
    acct.is_active
        && acct.role == AdminRole::Admin.as_str()
        && (acct.is_super_admin || tenant_id != crate::db::tenant::TenantId::SYSTEM.as_uuid())
}

/// Lock every console account of the tenant for the rest of the transaction.
/// A change guarded by [`other_active_admins`] takes it first, so two concurrent
/// demotions, disables or deletes are serialised and the second one counts the
/// first one's result — check-then-act without it lets both pass and leaves the
/// tenant with no active admin.
pub(crate) async fn lock_tenant_admins(
    conn: &mut Scoped,
    tenant_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("SELECT id FROM admin_accounts WHERE tenant_id = $1 ORDER BY id FOR UPDATE")
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("lock tenant admin accounts: {e}");
            super::db_read_error(&e, "account could not be updated")
        })?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/admin-accounts",
    tag = "Admin Accounts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of admin accounts", body = TotalPage<AdminAccountResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_admin_accounts(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<AdminAccountResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_accounts")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count admin accounts: {e}");
            ApiError::internal("internal error")
        })?;
    let rows = sqlx::query_as::<_, AdminAccountResponse>(
        "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
         FROM admin_accounts ORDER BY created_at LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list admin accounts: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/admin-accounts/{id}",
    tag = "Admin Accounts",
    params(("id" = Uuid, Path, description = "Admin account ID")),
    responses(
        (status = 200, description = "Admin account details", body = AdminAccountResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_admin_account(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminAccountResponse>, ApiError> {
    let row = sqlx::query_as::<_, AdminAccountResponse>(
        "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
         FROM admin_accounts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get admin account: {e}");
        ApiError::internal("internal error")
    })?
    .ok_or_else(|| ApiError::not_found("account not found", ApiErrorCode::AccountNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/admin-accounts/{id}",
    tag = "Admin Accounts",
    params(("id" = Uuid, Path, description = "Admin account ID")),
    request_body = UpdateAdminAccountRequest,
    responses(
        (status = 200, description = "Admin account updated", body = AdminAccountResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Account not found", body = ApiErrorResponse),
        (status = 409, description = "The address is taken by another console account (`account_email_taken`) or gateway user (`user_email_taken`)", body = ApiErrorResponse),
        (status = 503, description = "The database could not be reached", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_admin_account(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(mut req): Json<UpdateAdminAccountRequest>,
) -> Result<Json<AdminAccountResponse>, ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = req.email.as_deref().map(crate::routes::normalize_email);
    if let Some(email) = req.email.as_deref() {
        crate::routes::require_address(email)?;
    }
    let tenant_id = db.tenant_uuid();
    let password_hash = match req.password.as_deref().filter(|p| !p.is_empty()) {
        Some(pw) => Some(hash_password(pw).map_err(|e| {
            tracing::error!("password hashing failed: {e}");
            ApiError::internal("internal error")
        })?),
        None => None,
    };

    // One transaction: the account row and its sibling gateway user move
    // together (a rename refused on the sibling leaves the account as it was),
    // and the last-admin guard reads under the tenant's admin-row lock, so two
    // concurrent demotions cannot both pass it.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update admin account (begin): {e}");
        super::db_read_error(&e, "account could not be updated")
    })?;
    lock_tenant_admins(&mut tx, tenant_id).await?;

    let current = sqlx::query_as::<_, AdminAccountResponse>(
        "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
         FROM admin_accounts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("fetch admin account: {e}");
        super::db_read_error(&e, "account could not be updated")
    })?
    .ok_or_else(|| {
        ApiError::not_found("account not found", ApiErrorCode::AccountNotFound)
    })?;

    let new_email = req.email.as_deref().unwrap_or(&current.email).to_string();
    let is_active = req.is_active.unwrap_or(current.is_active);

    // Resolve the new console role. Super-admins stay full Admin (their role is
    // not operator-editable); otherwise take the requested role or keep current.
    let new_role = if current.is_super_admin {
        AdminRole::Admin
    } else if let Some(s) = req.role.as_deref() {
        AdminRole::parse_strict(s).ok_or_else(|| {
            ApiError::bad_request("role must be 'admin' or 'read_only'")
                .code(ApiErrorCode::ValidationFailed)
        })?
    } else {
        AdminRole::parse(&current.role)
    };

    // Lockout guard: refuse a change that would leave the tenant with zero
    // active full-Admin console accounts (demote-to-ReadOnly, disable, etc.) —
    // only for a target that counts as one now (`other_active_admins`' rule), so
    // an edit to a read-only or disabled account is never refused by it.
    let target_stays_active_admin = is_active && new_role == AdminRole::Admin;
    if counts_as_console_admin(&current, tenant_id)
        && !target_stays_active_admin
        && other_active_admins(&mut tx, tenant_id, id).await? == 0
    {
        return Err(ApiError::bad_request(
            "cannot demote or disable the last active admin",
        )
        .code(ApiErrorCode::LastAdminAccount));
    }

    // An admin's enable/disable — even one that repeats the current state — is
    // the account's state from here on: it clears `revoked_by_group`, so a
    // disable holds against the next OIDC or header sign-in (only the group
    // sync's own revoke is undone by a sign-in).
    let row = sqlx::query_as::<_, AdminAccountResponse>(
        "UPDATE admin_accounts SET email = $2, is_active = $3, role = $4, \
         revoked_by_group = CASE WHEN $7 THEN false ELSE revoked_by_group END, \
         display_name = CASE WHEN $5 THEN $6 ELSE display_name END WHERE id = $1 \
         RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
    )
        .bind(id)
        .bind(&new_email)
        .bind(is_active)
        .bind(new_role.as_str())
        .bind(req.display_name.is_some())
        .bind(req.display_name.clone().flatten())
        .bind(req.is_active.is_some())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if super::is_unique_violation(&e) {
                ApiError::conflict("email already exists", ApiErrorCode::AccountEmailTaken)
            } else {
                tracing::error!("update admin account: {e}");
                super::db_read_error(&e, "account could not be updated")
            }
        })?;

    // Email is the identity key: propagate a rename to the sibling gateway user
    // row so the two planes stay correlated (one email, one identity).
    if new_email != current.email {
        sync_email_rename(&mut tx, tenant_id, &current.email, &new_email).await?;
    }

    // Synced password (one identity ⇒ one credential): write to both planes.
    if let Some(hash) = &password_hash {
        sync_password_for_email(&mut tx, tenant_id, &new_email, hash).await?;
    }

    // Synced display name (one identity ⇒ one name).
    if let Some(name) = &req.display_name {
        sync_display_name_for_email(&mut tx, tenant_id, &new_email, name.as_deref()).await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("update admin account (commit): {e}");
        super::db_read_error(&e, "account could not be updated")
    })?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/admin-accounts/{id}",
    tag = "Admin Accounts",
    params(("id" = Uuid, Path, description = "Admin account ID")),
    responses(
        (status = 200, description = "Admin account deleted", body = ActionResponse),
        (status = 400, description = "Cannot delete self or last admin", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Account not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_admin_account(
    axum::Extension(ctx): axum::Extension<AdminTenantCtx>,
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Guard: never delete the account you're signed in as (lockout + audit-trail
    // self-erasure). Use `Disable` to suspend yourself instead.
    if id == ctx.admin_account_id {
        return Err(ApiError::bad_request("cannot delete your own account")
            .code(ApiErrorCode::CannotDeleteSelf));
    }

    let tenant_id = db.tenant_uuid();
    // The last-admin guard reads under the tenant's admin-row lock — see
    // `lock_tenant_admins`.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete admin account (begin): {e}");
        super::db_read_error(&e, "account could not be deleted")
    })?;
    lock_tenant_admins(&mut tx, tenant_id).await?;
    let current = sqlx::query_as::<_, AdminAccountResponse>(
        "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
         FROM admin_accounts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("fetch admin account for delete: {e}");
        super::db_read_error(&e, "account could not be deleted")
    })?
    .ok_or_else(|| ApiError::not_found("account not found", ApiErrorCode::AccountNotFound))?;

    // Lockout guard: refuse deleting the last active full-Admin account.
    if counts_as_console_admin(&current, tenant_id)
        && other_active_admins(&mut tx, tenant_id, id).await? == 0
    {
        return Err(ApiError::bad_request("cannot delete the last active admin")
            .code(ApiErrorCode::LastAdminAccount));
    }

    sqlx::query("DELETE FROM admin_accounts WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete admin account: {e}");
            super::db_read_error(&e, "account could not be deleted")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("delete admin account (commit): {e}");
        super::db_read_error(&e, "account could not be deleted")
    })?;

    Ok(Json(ActionResponse::ok()))
}

// ---------------------------------------------------------------------------
// Setup wizard (first-run, no auth required)
// ---------------------------------------------------------------------------

/// Check if setup is needed (no admin accounts exist).
#[utoipa::path(
    get,
    path = "/api/v1/auth/setup/status",
    tag = "Authentication",
    responses(
        (status = 200, description = "Setup status", body = SetupStatusResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn setup_status(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<SetupStatusResponse>, ApiError> {
    // Use SYSTEM tenant context to check admin_accounts through RLS.
    let mut db = TenantConn::acquire(&state.db, TenantId::SYSTEM)
        .await
        .map_err(|e| {
            tracing::error!("setup_status TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM admin_accounts WHERE email NOT LIKE '%@streamscope.internal')")
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("setup_status query: {e}");
                ApiError::internal("internal error")
            })?;

    // Reveal a slug only when there is exactly one active organisation — a
    // tenant other than SYSTEM, which every install carries — so the landings
    // can route straight to it instead of prompting for an unknowable
    // identifier (nothing to enumerate).
    let slugs: Vec<String> =
        sqlx::query_scalar("SELECT slug FROM tenants WHERE is_active = true AND id <> $1 LIMIT 2")
            .bind(TenantId::SYSTEM.as_uuid())
            .fetch_all(state.db.global(Global::TenantRegistry))
            .await
            .map_err(|e| {
                tracing::error!("setup_status tenant query: {e}");
                ApiError::internal("internal error")
            })?;
    let single_tenant_slug = match slugs.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    };

    Ok(Json(SetupStatusResponse {
        needs_setup: !exists,
        single_tenant_slug,
    }))
}

/// First-run setup: create super-admin account. Atomic, race-condition-free.
/// After first use, always returns 409 Conflict.
#[utoipa::path(
    post,
    path = "/api/v1/auth/setup",
    tag = "Authentication",
    request_body = SetupRequest,
    responses(
        (status = 201, description = "Super-admin account created", body = SetupResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 409, description = "Setup already completed", body = ApiErrorResponse),
        (status = 503, description = "AUTH_SECRET not configured", body = ApiErrorResponse),
    ),
)]
pub async fn setup(
    State(state): State<Arc<AdminState>>,
    Json(mut req): Json<SetupRequest>,
) -> Result<(StatusCode, Json<SetupResponse>), ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = crate::routes::normalize_email(&req.email);
    crate::routes::require_address(&req.email)?;
    let ring = keyring().ok_or_else(|| {
        tracing::error!("AUTH_SECRET not set — setup disabled");
        ApiError::server_misconfigured("AUTH_SECRET not configured")
    })?;

    if req.email.is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request("email and password are required"));
    }

    if req.password.len() < 8 {
        return Err(ApiError::bad_request("password must be at least 8 characters")
            .code(ApiErrorCode::PasswordTooShort));
    }

    let password_hash = hash_password(&req.password).map_err(|e| {
        tracing::error!("setup password hash: {e}");
        ApiError::internal("internal error")
    })?;

    // SYSTEM-scoped transaction: RLS lets the account read/insert below see the
    // SYSTEM tenant's `admin_accounts` rows.
    let mut tx = state.db.begin_tenant(TenantId::SYSTEM).await.map_err(|e| {
        tracing::error!("setup begin tx: {e}");
        crate::routes::db_read_error(&e, "database unavailable")
    })?;

    // Advisory lock prevents concurrent setup attempts.
    sqlx::query("SELECT pg_advisory_xact_lock(1)")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("setup advisory lock: {e}");
            ApiError::internal("internal error")
        })?;

    // Check inside transaction — after lock acquired.
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM admin_accounts WHERE email NOT LIKE '%@streamscope.internal')")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("setup exists check: {e}");
                ApiError::internal("internal error")
            })?;

    if exists {
        return Err(ApiError::conflict("setup already completed", ApiErrorCode::SetupAlreadyCompleted));
    }

    // Create super-admin account in SYSTEM tenant.
    let row = sqlx::query_as::<_, AdminAccountResponse>(
        "INSERT INTO admin_accounts (email, password_hash, role, is_super_admin, tenant_id, last_login) \
         VALUES ($1, $2, 'admin', true, $3, NOW()) \
         RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
    )
    .bind(&req.email)
    .bind(&password_hash)
    .bind(TenantId::SYSTEM.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("setup insert: {e}");
        ApiError::internal("internal error")
    })?;

    // Ensure SYSTEM tenant auth config exists.
    sqlx::query(
        "INSERT INTO tenant_auth_configs (tenant_id, auth_mode) \
         VALUES ($1, 'internal') ON CONFLICT DO NOTHING",
    )
    .bind(TenantId::SYSTEM.as_uuid())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("setup auth config: {e}");
        ApiError::internal("internal error")
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("setup commit: {e}");
        ApiError::internal("internal error")
    })?;

    // Generate JWT with per-tenant key.
    let tenant_str = TenantId::SYSTEM.as_uuid().to_string();
    let token = generate_jwt(&ring, &row.id, &row.email, "admin", &tenant_str, true)?;

    tracing::info!(email = %req.email, "setup wizard: super-admin account created");

    Ok((StatusCode::CREATED, Json(SetupResponse { token, user: row, changelog_pending: true })))
}

// ---------------------------------------------------------------------------
// Session endpoints (no admin auth required)
// ---------------------------------------------------------------------------

/// Login: verify credentials, return JWT. Tenant-scoped via `tenant_slug`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "Authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Bad request (password login disabled)", body = ApiErrorResponse),
        (status = 401, description = "Invalid credentials", body = ApiErrorResponse),
        (status = 429, description = "Too many login attempts", body = ApiErrorResponse),
        (status = 503, description = "AUTH_SECRET not configured, or the database did not answer", body = ApiErrorResponse),
    ),
)]
pub async fn login(
    State(state): State<Arc<AdminState>>,
    Json(mut req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = crate::routes::normalize_email(&req.email);
    // Rate limit by account (tenant_slug:email) — only failed attempts count.
    // Keyed on the normalized address, so a change of case cannot reset it.
    let rate_key = format!("admin:{}:{}", req.tenant_slug, req.email);
    if state.login_rate_limiter.is_limited(&rate_key) {
        tracing::warn!(email = %req.email, tenant = %req.tenant_slug, "login rate limited");
        return Err(ApiError::too_many_requests("too many login attempts — try again later"));
    }

    // Header mode disables password login.
    if matches!(auth_mode(), AuthMode::Header) {
        return Err(ApiError::bad_request("password login disabled — use external authentication")
            .code(ApiErrorCode::PasswordLoginDisabled));
    }

    let ring = keyring().ok_or_else(|| {
        tracing::error!("AUTH_SECRET not set — login disabled");
        crate::routes::no_signing_key()
    })?;

    // Resolve tenant from slug (no RLS — tenants table is root).
    // An unknown slug answers as bad credentials (not a directory of tenants);
    // a lookup that failed is a 503 (`?`), never a claim about the password.
    let (tenant_id, is_active) = lookup_tenant_slug(&state.db, &req.tenant_slug)
        .await?
        .ok_or_else(|| {
            // Answered as an unknown email in a known tenant is: the same
            // Argon2 verify and the same limiter charge, so neither the
            // response time nor a 429 says which tenants exist.
            dummy_password_verify(&req.password);
            state.login_rate_limiter.record_failure(&rate_key);
            ApiError::unauthorized("invalid credentials")
        })?;

    // A suspended tenant's credentials stop authenticating immediately.
    if !is_active {
        return Err(ApiError::forbidden("tenant suspended").code(ApiErrorCode::TenantInactive));
    }

    // Resolve tenant auth config to check auth_mode.
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("login TenantConn acquire: {e}");
            // A database that could not be asked says nothing about the
            // credentials (503); any other failure is a fault (500).
            super::db_read_error(&e, "sign-in could not be checked")
        })?;

    let tenant_auth_mode: Option<String> = sqlx::query_scalar(
        "SELECT auth_mode FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("login auth_mode query: {e}");
        // A database that could not be asked says nothing about the
        // credentials (503); any other failure is a fault (500).
        super::db_read_error(&e, "sign-in could not be checked")
    })?;

    if tenant_auth_mode.as_deref() == Some("oidc") {
        return Err(ApiError::bad_request("password login disabled for this tenant — use SSO")
            .code(ApiErrorCode::PasswordLoginDisabled));
    }

    // Fetch account by email (RLS-scoped to tenant).
    type LoginRow = (Uuid, String, Option<String>, Option<String>, String, bool, bool, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>, Option<String>);
    let row: Option<LoginRow> =
        sqlx::query_as(
            "SELECT id, email, display_name, password_hash, role, is_super_admin, is_active, created_at, last_login, last_seen_version \
             FROM admin_accounts WHERE email = $1",
        )
        .bind(&req.email)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("login query: {e}");
            // A database that could not be asked says nothing about the
            // credentials (503); any other failure is a fault (500).
            super::db_read_error(&e, "sign-in could not be checked")
        })?;

    let Some((id, email, display_name, password_hash, role, is_super_admin, account_active, created_at, _last_login, last_seen_version)) = row
    else {
        // Unknown email — still run one Argon2 verify so the response time is
        // indistinguishable from a wrong-password attempt (no user enumeration).
        dummy_password_verify(&req.password);
        state.login_rate_limiter.record_failure(&rate_key);
        return Err(ApiError::unauthorized("invalid credentials"));
    };

    // Verify the password BEFORE the active check, and collapse every failure
    // mode (unknown email, no password set, wrong password, disabled account)
    // to one generic error — so neither the message nor the timing reveals
    // which one it was.
    let password_ok = match &password_hash {
        Some(h) => verify_password(&req.password, h),
        None => {
            dummy_password_verify(&req.password);
            false
        }
    };
    if !password_ok || !account_active {
        state.login_rate_limiter.record_failure(&rate_key);
        return Err(ApiError::unauthorized("invalid credentials"));
    }

    // Successful login — reset rate limiter for this account.
    state.login_rate_limiter.reset(&rate_key);

    // Generate per-tenant JWT.
    let tenant_str = tenant_id.to_string();
    let token = generate_jwt(&ring, &id, &email, &role, &tenant_str, is_super_admin)?;

    // Update last_login.
    let _ = sqlx::query("UPDATE admin_accounts SET last_login = NOW() WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await;

    tracing::info!(email = %email, tenant = %req.tenant_slug, "admin login successful");

    let now = Utc::now();
    let changelog_pending = super::changelog::is_changelog_pending(last_seen_version.as_deref());
    Ok(Json(LoginResponse {
        token,
        changelog_pending,
        user: AdminAccountResponse {
            id,
            email,
            display_name,
            role,
            is_super_admin,
            is_active: account_active,
            created_at,
            last_login: Some(now),
        },
    }))
}

/// Response for /auth/me — includes optional JWT when using header auth.
#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    #[serde(flatten)]
    #[schema(inline)]
    pub user: AdminAccountResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
    /// True when this deployment is the Kairos VM appliance (the host daemon is
    /// configured) — gates the super-admin Appliance surface in the UI. Always
    /// false on Kubernetes / dev.
    pub appliance: bool,
}

/// Get current session info. In header mode, exchanges X-Auth-Request-User
/// for a JWT. In standard mode, validates the existing JWT.
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "Authentication",
    operation_id = "admin_me",
    responses(
        (status = 200, description = "Current session info", body = MeResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Forbidden (tenant suspended or not in admin group)", body = ApiErrorResponse),
        (status = 503, description = "The session could not be checked (database unavailable); it is not ended", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn me(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    match auth_mode() {
        AuthMode::Header => {
            // Checked before provisioning writes anything a retry would repeat.
            let ring = keyring().ok_or_else(super::no_signing_key)?;
            let email = headers
                .get("x-auth-request-email")
                .and_then(|v| v.to_str().ok())
                .filter(|e| !e.is_empty())
                .ok_or_else(|| ApiError::unauthorized("missing auth header").code(ApiErrorCode::MissingAuthHeader))?;

            // Parse IdP groups from header (comma-separated).
            let groups: Vec<String> = headers
                .get("x-auth-request-groups")
                .and_then(|v| v.to_str().ok())
                .map(|g| g.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
                .unwrap_or_default();

            let tenant_slug = header_auth_tenant_slug(&headers);

            // A database that does not answer is a 503, never the 404 for a
            // missing tenant: a 404 is an answer about the tenant, an outage
            // is not.
            let (tenant_uuid, tenant_active) = resolve_tenant_slug(&state.db, &tenant_slug).await?;

            // Fetch tenant name for the response.
            let tenant_name: Option<String> = sqlx::query_scalar(
                "SELECT name FROM tenants WHERE id = $1",
            )
            .bind(tenant_uuid)
            .fetch_optional(state.db.global(Global::TenantRegistry))
            .await
            .map_err(|e| {
                tracing::warn!("me tenant name read: {e}");
                ApiError::from(SessionLookupFailed)
            })?;

            if !tenant_active {
                return Err(ApiError::forbidden("tenant suspended").code(ApiErrorCode::TenantInactive));
            }

            let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_uuid))
                .await
                .map_err(|e| {
                    tracing::error!("me TenantConn acquire: {e}");
                    ApiError::service_unavailable("internal error")
                })?;

            // Group-derived role, both lockout guards, the revoke-on-no-matching
            // group rule and the domain restriction are the same decisions the
            // OIDC plane makes, so they are made in the same place. Anything
            // added to console provisioning belongs in `oidc::identity`, never
            // in a branch here — a second copy of these rules drifts silently,
            // and the drift is an admin who keeps access they should have lost.
            let account = crate::oidc::identity::provision_admin(
                &mut db,
                tenant_uuid,
                &tenant_slug,
                &crate::oidc::identity::ConsoleIdentity {
                    email,
                    groups: &groups,
                    source: crate::oidc::identity::IdentitySource::ProxyHeader,
                    // The proxy in front of us performed the authentication;
                    // there is no claim to inspect and nothing here could verify
                    // one.
                    assurance: crate::oidc::identity::EmailAssurance::ProxyAuthenticated,
                },
            )
            .await?;

            let tenant_str = tenant_uuid.to_string();
            let token = generate_jwt(&ring, &account.id, &account.email, &account.role, &tenant_str, account.is_super_admin)?;

            Ok(Json(MeResponse {
                user: account,
                token: Some(token),
                tenant_slug: Some(tenant_slug.to_string()),
                tenant_name,
                appliance: crate::settings::admin_settings().is_appliance(),
            }))
        }
        AuthMode::Standard => {
            super::bearer_token(&headers)?;
            keyring().ok_or_else(super::no_signing_key)?;
            let claims = validate_session_token(&headers, &state.db)
                .await?
                .ok_or_else(super::rejected_credential)?;
            let id: Uuid = claims.sub.parse().map_err(|_| super::rejected_credential())?;

            let tenant_uuid = claims.aud.parse::<Uuid>()
                .map_err(|_| super::rejected_credential())?;
            let tenant_id = TenantId::from_credential(tenant_uuid);

            // Fetch tenant slug + name for the response. The browser tier binds
            // the session to the URL's tenant by this slug, so a failed read is
            // a 503 — never a slugless 200 it could not check.
            let tenant_info: Option<(String, String)> = sqlx::query_as(
                "SELECT slug, name FROM tenants WHERE id = $1",
            )
            .bind(tenant_uuid)
            .fetch_optional(state.db.global(Global::TenantRegistry))
            .await
            .map_err(|e| {
                tracing::warn!("me tenant read: {e}");
                ApiError::from(SessionLookupFailed)
            })?;
            // The session's tenant is gone: refused, never a slugless answer.
            let Some(tenant_info) = tenant_info else {
                return Err(super::rejected_credential());
            };

            let mut db = TenantConn::acquire(&state.db, tenant_id)
                .await
                .map_err(|e| {
                    tracing::error!("me TenantConn acquire: {e}");
                    ApiError::service_unavailable("internal error")
                })?;

            let row = sqlx::query_as::<_, AdminAccountResponse>(
                "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
                 FROM admin_accounts WHERE id = $1 AND is_active = true",
            )
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::warn!("me query: {e}");
                ApiError::from(SessionLookupFailed)
            })?
            .ok_or_else(|| ApiError::unauthorized("account not found or disabled"))?;

            Ok(Json(MeResponse {
                user: row,
                token: None,
                tenant_slug: Some(tenant_info.0),
                tenant_name: Some(tenant_info.1),
                appliance: crate::settings::admin_settings().is_appliance(),
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// JWT validation (used by dual auth middleware)
// ---------------------------------------------------------------------------

/// A session the database could not be asked about — a pool timeout, a
/// restarting Postgres. Kept apart from a refused session (`Ok(None)`) so the
/// caller answers 503 and the console keeps its session through the outage,
/// instead of answering 401 and signing every open console out.
#[derive(Debug)]
pub struct SessionLookupFailed;

impl From<SessionLookupFailed> for ApiError {
    fn from(_: SessionLookupFailed) -> Self {
        ApiError::service_unavailable("session could not be checked")
    }
}

/// Validate a JWT session token from Authorization header.
/// Performs per-tenant key derivation and tenant active check.
///
/// `Ok(None)` is a refusal — no token, a bad one, or a session the database
/// says is over. `Err` means the database did not answer, which proves nothing
/// about the session.
pub async fn validate_session_token(
    headers: &axum::http::HeaderMap,
    pool: &crate::db::Db,
) -> Result<Option<AdminClaims>, SessionLookupFailed> {
    let Some(ring) = keyring() else { return Ok(None) };

    let Ok(token) = super::bearer_token(headers) else {
        return Ok(None);
    };

    // The `kid` header names the signing generation and the tenant. Both are
    // unverified at this point — they select a key; `decode_session_jwt` is
    // what binds the verified token's `aud` and `tenant_id` to that tenant.
    let Some((claims, tenant_id_str)) = decode_session_jwt::<AdminClaims>(&ring, token) else {
        return Ok(None);
    };
    check_session_against_db(claims, &tenant_id_str, pool).await
}

/// The database half of [`validate_session_token`], for a token whose
/// signature already verified.
async fn check_session_against_db(
    claims: AdminClaims,
    tenant_id_str: &str,
    pool: &crate::db::Db,
) -> Result<Option<AdminClaims>, SessionLookupFailed> {
    let lookup_failed = |what: &str, e: &dyn std::fmt::Display| {
        tracing::warn!(tenant_id = %tenant_id_str, "session check: {what} failed: {e}");
        SessionLookupFailed
    };

    // Reject portal user tokens — only admin JWTs are valid here. The `type`
    // claim is the discriminator (portal tokens carry `type != "admin"`, and a
    // portal JWT can't even deserialize into `AdminClaims`). Do NOT gate on
    // `role` here — `role` now carries the account's authorization role
    // (`admin` / `read_only`) and is enforced downstream in `authz_mw`; gating
    // on it here would lock read-only accounts out of even their allowed GETs.
    if claims.token_type != "admin" {
        return Ok(None);
    }

    // Everything below re-derives authority from the database rather than
    // trusting the token to still describe reality. One tenant-scoped
    // connection serves both reads: `tenants` carries no RLS policy, so it is
    // readable here, while `admin_accounts` is FORCE-RLS and needs the GUC.
    let Ok(tenant_uuid) = tenant_id_str.parse::<Uuid>() else { return Ok(None) };
    let mut db = TenantConn::acquire(pool, TenantId::from_credential(tenant_uuid))
        .await
        .map_err(|e| lookup_failed("connection", &e))?;

    // A suspended tenant's sessions stop authenticating immediately.
    let tenant_active: bool = sqlx::query_scalar("SELECT is_active FROM tenants WHERE id = $1")
        .bind(tenant_uuid)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| lookup_failed("tenant read", &e))?
        .unwrap_or(false);
    if !tenant_active {
        tracing::warn!(tenant_id = %tenant_id_str, "JWT rejected — tenant deactivated");
        return Ok(None);
    }

    // **The account, not the claim, is the authority.** A JWT is a bearer with
    // an 8h life; disabling an admin, deleting them, or demoting them to
    // read-only must take effect on the next request, not at expiry. Every
    // other credential family already re-reads its subject per request — the
    // portal checks `users.is_active`, an `ak-` joins it, the CLI calls
    // `require_active_user` — so a console session that trusted its own claims
    // was the one gap, and it was the most privileged one.
    let Ok(account_id) = claims.sub.parse::<Uuid>() else { return Ok(None) };
    let account: Option<(bool, String, bool, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(
            "SELECT is_active, role, is_super_admin, sessions_valid_after \
             FROM admin_accounts WHERE id = $1",
        )
        .bind(account_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| lookup_failed("account read", &e))?;

    let Some((account_active, role, is_super_admin, sessions_valid_after)) = account else {
        tracing::warn!(
            tenant_id = %tenant_id_str,
            "JWT rejected — admin account no longer exists"
        );
        return Ok(None);
    };
    if !account_active {
        tracing::warn!(tenant_id = %tenant_id_str, "JWT rejected — admin account disabled");
        return Ok(None);
    }

    // Sessions issued before the watermark are over. Signing out sets it, which
    // is what makes sign-out mean something for a token someone else already
    // copied: the cookie is gone from this browser either way, but the token
    // itself stops being accepted here.
    //
    // Compared against `iat`, and `iat` is in whole seconds, so a token minted
    // in the same second as the watermark must still be refused — a `>=`, not a
    // `>`, or a login racing a sign-out survives it.
    if session_is_revoked(claims.iat, sessions_valid_after) {
        tracing::info!(tenant_id = %tenant_id_str, "JWT rejected — session signed out");
        return Ok(None);
    }

    // Overwrite rather than compare: these two decide what the request may do,
    // and the row is the current answer. `authz_mw` parses `role` fail-closed,
    // so a value it does not recognise lands on least privilege.
    let mut claims = claims;
    claims.role = role;
    claims.is_super_admin = is_super_admin;

    Ok(Some(claims))
}

/// End every console session for the calling account.
///
/// Deleting the cookie is the browser's half and the gateway cannot see it; this
/// is the half that makes the token stop working. Without it a session someone
/// copied outlives sign-out by up to `JWT_EXPIRY_HOURS`, and the only remedy is
/// disabling the account.
///
/// The grain is the account within its tenant, not the one browser that asked —
/// so signing out on a shared machine also ends the session on the laptop that
/// was left logged in, which is the behaviour someone reaching for "sign out"
/// after losing a device needs. Other tenants' sessions for the same person live
/// in their own `admin_accounts` rows and are untouched.
///
/// Requires a live session: `validate_session_token` refuses a token that a
/// previous sign-out already revoked, so a repeat call answers 401 rather than
/// re-stamping the watermark. That refusal is the point — a re-stamp moves the
/// watermark forward and would take out any session established since, turning
/// a copied token into a way to keep someone signed out. The browser tier
/// ignores the status: its cookies go either way.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "Auth",
    responses(
        (status = 200, description = "Sessions ended", body = ActionResponse),
        (status = 401, description = "No valid session presented", body = ApiErrorResponse),
        (status = 503, description = "The session could not be checked (database unavailable)", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn logout(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ActionResponse>, ApiError> {
    super::bearer_token(&headers)?;
    keyring().ok_or_else(super::no_signing_key)?;
    let claims = validate_session_token(&headers, &state.db)
        .await?
        .ok_or_else(super::rejected_credential)?;

    let tenant_uuid: Uuid = claims
        .tenant_id
        .parse()
        .map_err(|_| super::rejected_credential())?;
    let account_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| super::rejected_credential())?;

    let mut db = TenantConn::acquire(&state.db, TenantId::from_credential(tenant_uuid))
        .await
        .map_err(|e| {
            tracing::error!("logout TenantConn acquire: {e}");
            ApiError::service_unavailable("internal error")
        })?;

    // Stamped from this process's clock, not the database's — `iat` is minted
    // here too, and comparing the two against one clock is what keeps the check
    // meaningful when the database runs on a different machine. A database clock
    // running ahead would otherwise revoke every new login on sight.
    sqlx::query("UPDATE admin_accounts SET sessions_valid_after = $2 WHERE id = $1")
        .bind(account_id)
        .bind(chrono::Utc::now())
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("logout revoke: {e}");
            ApiError::internal("internal error")
        })?;

    tracing::info!(email = %claims.email, "console sessions ended");
    Ok(Json(ActionResponse::ok().with_message("Signed out.")))
}

/// Whether a session minted at `iat` falls before an account's sign-out
/// watermark.
///
/// `None` — the column's value for every account that has never signed out —
/// revokes nothing.
///
/// The comparison is `iat <= watermark`, deliberately inclusive. `iat` is whole
/// seconds, so an exclusive test would keep alive a token minted in the same
/// second the watermark was written, which is exactly the race a sign-out is
/// supposed to settle. Re-authenticating a second later is the cost, and it is
/// only paid by someone who logged in and out in the same second.
pub(crate) fn session_is_revoked(
    iat: usize,
    sessions_valid_after: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    let Some(watermark) = sessions_valid_after else {
        return false;
    };
    i64::try_from(iat).is_ok_and(|issued| issued <= watermark.timestamp())
}

// ---------------------------------------------------------------------------
// Header auth helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/// Generate a console-session JWT for the given admin account, signed with the
/// ring's active per-tenant key and labelled with its `kid`.
///
/// **The one place a console session is minted.** Every path that hands a
/// browser an admin token comes through here, so the lifetime, the claim shape,
/// and the key that signs it are stated once.
pub(crate) fn generate_jwt(
    ring: &Keyring,
    id: &Uuid,
    email: &str,
    role: &str,
    tenant_id: &str,
    is_super_admin: bool,
) -> Result<String, ApiError> {
    let (header, signing_key) = ring.signing_header(tenant_id);

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let claims = AdminClaims {
        sub: id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: tenant_id.to_string(),
        token_type: "admin".to_string(),
        is_super_admin,
        tenant_id: tenant_id.to_string(),
        iat,
        nbf: iat,
        exp: (now + chrono::Duration::hours(crate::settings::admin_settings().jwt_expiry_hours)).timestamp() as usize,
    };

    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&signing_key)).map_err(|e| {
        tracing::error!("JWT encode: {e}");
        ApiError::internal("internal error")
    })
}

/// Mint a console session for an account that has just been provisioned.
pub(crate) fn generate_session_jwt(
    account: &AdminAccountResponse,
    tenant_id: Uuid,
) -> Result<String, ApiError> {
    let ring =
        keyring().ok_or_else(crate::routes::no_signing_key)?;
    generate_jwt(
        &ring,
        &account.id,
        &account.email,
        &account.role,
        &tenant_id.to_string(),
        account.is_super_admin,
    )
}

// ---------------------------------------------------------------------------
// Internal OIDC exchange endpoint (INTERNAL_SERVICE_SECRET only, for SvelteKit OIDC callback)
// ---------------------------------------------------------------------------

/// Request body for the internal OIDC exchange.
#[derive(Deserialize, ToSchema)]
pub struct OidcExchangeRequest {
    pub email: String,
    pub email_verified: Option<bool>,
    pub oidc_sub: String,
    pub oidc_issuer: String,
    pub groups: Option<Vec<String>>,
    pub tenant_slug: String,
}

/// Exchange asserted OIDC claims for a session JWT. Disabled by default.
///
/// This endpoint takes an identity on a caller's word: the bearer secret proves
/// *which service* is asking, never *who the user is*. The gateway's own login
/// path no longer uses it — it verifies the provider's signature in-process —
/// so it is off unless an operator turns it on for a deployment that drives
/// provisioning from its own already-verified identity source.
#[utoipa::path(
    post,
    path = "/api/v1/auth/oidc-exchange",
    tag = "Authentication",
    request_body = OidcExchangeRequest,
    responses(
        (status = 200, description = "OIDC exchange successful", body = MeResponse),
        (status = 401, description = "Missing or invalid service secret", body = ApiErrorResponse),
        (status = 403, description = "Forbidden (tenant suspended, issuer mismatch, not in admin group, or the account is bound to another identity)", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found, or claim exchange is disabled", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer, or the deployment lacks the service secret or signing key", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn oidc_exchange(
    State(state): State<Arc<AdminState>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<OidcExchangeRequest>,
) -> Result<Json<MeResponse>, ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = crate::routes::normalize_email(&req.email);
    // Mounted only when a deployment turns it on, behind the service-secret
    // layer (`claim_exchange_router`); checked again so the handler is safe
    // wherever it is mounted.
    super::oidc_rp::require_internal_service_secret(&headers)?;
    // Checked before provisioning writes anything a retry would repeat.
    let ring = keyring().ok_or_else(super::no_signing_key)?;

    // Resolve tenant.
    let (tenant_uuid, tenant_active) = resolve_tenant_slug(&state.db, &req.tenant_slug).await?;

    if !tenant_active {
        return Err(ApiError::forbidden("tenant suspended").code(ApiErrorCode::TenantInactive));
    }

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_uuid))
        .await
        .map_err(|e| {
            tracing::error!("oidc_exchange TenantConn: {e}");
            ApiError::service_unavailable("internal error")
        })?;

    // Provisioning — account linking, group-derived role, lockout guards and
    // domain restrictions — lives in `oidc::identity` so this plane and the
    // portal cannot drift apart on who gets an account.
    // The caller asserts `email_verified`; this endpoint has no token to read it
    // from. That is precisely why it is off by default. The asserted value meets
    // the tenant's opt-in through the same decision the ID-token path uses, so
    // the two doors cannot disagree about one identity.
    // `email_verified` describes the standard `email` claim, so a tenant keyed
    // on another claim treats the asserted address as unstated here too.
    let (email_claim, allow_unverified): (String, bool) = sqlx::query_as(
        "SELECT oidc_email_claim, oidc_allow_unverified_email \
         FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_uuid)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("oidc_exchange auth config: {e}");
        super::db_read_error(&e, "account could not be checked")
    })?
    .unwrap_or_else(|| (crate::oidc::identity::STANDARD_EMAIL_CLAIM.to_string(), false));
    let identity = crate::oidc::identity::VerifiedOidcIdentity {
        email: req.email.clone(),
        assurance: crate::oidc::identity::oidc_email_assurance(
            &email_claim,
            req.email_verified,
            allow_unverified,
        ),
        subject: req.oidc_sub.clone(),
        issuer: req.oidc_issuer.clone(),
        groups: req.groups.clone().unwrap_or_default(),
    };
    let account =
        crate::oidc::identity::provision_admin(&mut db, tenant_uuid, &req.tenant_slug, &identity.console())
            .await?;

    let tenant_str = tenant_uuid.to_string();
    let jwt = generate_jwt(&ring, &account.id, &account.email, &account.role, &tenant_str, account.is_super_admin)?;

    // Fetch tenant name.
    let tenant_name: Option<String> = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant_uuid)
        .fetch_optional(state.db.global(Global::TenantRegistry))
        .await
        .ok()
        .flatten();

    tracing::info!(email = %req.email, tenant = %req.tenant_slug, "OIDC exchange: admin login");

    Ok(Json(MeResponse {
        user: account,
        token: Some(jwt),
        tenant_slug: Some(req.tenant_slug.clone()),
        tenant_name,
        appliance: crate::settings::admin_settings().is_appliance(),
    }))
}

// ---------------------------------------------------------------------------
// Password helpers (public for use by other modules)
// ---------------------------------------------------------------------------

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    Ok(Argon2::default().hash_password(password.as_bytes())?.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A fixed Argon2 hash, computed once with the real params, used only to
/// equalize login timing. On a no-account / no-password path we still run one
/// verify against this so an attacker can't distinguish "unknown email" from
/// "wrong password" by response time.
static DUMMY_PASSWORD_HASH: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| hash_password("streamscope-timing-equalizer").unwrap_or_default());

/// Burn one Argon2 verify and discard the result — keeps failed-lookup login
/// paths timing-indistinguishable from a wrong-password attempt.
pub fn dummy_password_verify(password: &str) {
    let _ = verify_password(password, &DUMMY_PASSWORD_HASH);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored password hash outlives the library that wrote it: one the
    /// previous Argon2 implementation produced still verifies, and only for
    /// its own password; a fresh hash round-trips.
    #[test]
    fn a_password_hash_from_the_previous_library_still_verifies() {
        let stored = "$argon2id$v=19$m=19456,t=2,p=1$7+uqFy+kfxge97hUSwfOoA$5UuRDBzYjr7yzw2500VUZP6dfKkQdbUcXw1/sY2tntg";
        assert!(verify_password("known-answer-password", stored));
        assert!(!verify_password("another-password", stored));
        let fresh = hash_password("known-answer-password").unwrap();
        assert!(fresh.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{fresh}");
        assert!(verify_password("known-answer-password", &fresh));
    }

    /// In header mode a reverse proxy proves *identity*; the tenant decides
    /// what that identity may reach. A caller who names it names their own
    /// permissions, so the header is inert unless an operator says their proxy
    /// sets it.
    #[test]
    fn the_tenant_header_is_ignored_unless_the_operator_trusts_it() {
        // The shipped default: nothing configured, header present anyway.
        assert_eq!(
            resolve_header_auth_tenant("", false, Some("victim-tenant")),
            "system",
            "an untrusted X-Tenant-Slug must not choose the tenant"
        );
        assert_eq!(resolve_header_auth_tenant("", false, None), "system");

        // The opt-in, for a proxy that sets the header per vhost.
        assert_eq!(
            resolve_header_auth_tenant("", true, Some("acme")),
            "acme",
            "the opt-in must actually take effect, or it is decoration"
        );
        // Trusted but absent still lands somewhere definite.
        assert_eq!(resolve_header_auth_tenant("", true, None), "system");
    }

    /// A deployment that named its tenant must not be steerable away from it,
    /// even by an operator who also turned the header on.
    #[test]
    fn a_pinned_tenant_outranks_the_header() {
        assert_eq!(resolve_header_auth_tenant("acme", false, Some("evil")), "acme");
        assert_eq!(resolve_header_auth_tenant("acme", true, Some("evil")), "acme");
        assert_eq!(resolve_header_auth_tenant("acme", true, None), "acme");
    }

    const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";
    const TENANT_B: &str = "22222222-2222-4222-8222-222222222222";

    const SECRET: &str = "test-secret-at-least-32-characters-long";
    const OTHER_SECRET: &str = "other-secret-at-least-32-characters-x";

    fn ring(secret: &str) -> Keyring {
        Keyring::new(secret, None).expect("ring")
    }

    /// Mint a token with fully caller-controlled `iss` / `aud`, so the
    /// validation tests can drive claim combinations `generate_jwt` never
    /// produces.
    fn mint(secret: &str, signing_tenant: &str, iss: &str, aud: &str) -> String {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: iss.to_string(),
            aud: aud.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: aud.to_string(),
            iat,
            nbf: iat,
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
        };
        sign(secret, signing_tenant, &claims)
    }

    /// Sign an arbitrary claim payload under one tenant's active key, labelled
    /// with the `kid` a verifier will resolve it by.
    fn sign<T: Serialize>(secret: &str, signing_tenant: &str, claims: &T) -> String {
        let (header, key) = ring(secret).signing_header(signing_tenant);
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_secret(&key)).unwrap()
    }

    /// Decode a token this module just minted, resolving its key the way the
    /// middleware does. Panics on anything the middleware would reject.
    fn decode_minted(token: &str) -> AdminClaims {
        let ring = ring(SECRET);
        let (tenant, key) = session_verification_key(&ring, token).expect("kid resolves");
        jsonwebtoken::decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(&key),
            &streamscope_jwt_validation(&tenant),
        )
        .expect("decode")
        .claims
    }

    /// Verify the way `validate_session_token` does: resolve the key from the
    /// token's own `kid`, then validate against the tenant that `kid` named.
    fn verify(token: &str, secret: &str) -> bool {
        let ring = ring(secret);
        let Some((tenant, key)) = session_verification_key(&ring, token) else {
            return false;
        };
        jsonwebtoken::decode::<AdminClaims>(
            token,
            &DecodingKey::from_secret(&key),
            &streamscope_jwt_validation(&tenant),
        )
        .is_ok()
    }

    #[test]
    fn validation_accepts_matching_issuer_and_audience() {
        assert!(verify(
            &mint(SECRET, TENANT_A, TOKEN_ISSUER, TENANT_A),
            SECRET
        ));
    }

    /// The audience binds a token to one tenant. A token minted for tenant B
    /// must not validate against tenant A even before the key difference is
    /// considered — so mint it under A's own key to isolate the `aud` check.
    #[test]
    fn validation_rejects_foreign_audience() {
        assert!(!verify(
            &mint(SECRET, TENANT_A, TOKEN_ISSUER, TENANT_B),
            SECRET
        ));
    }

    #[test]
    fn validation_rejects_foreign_issuer() {
        assert!(!verify(&mint(SECRET, TENANT_A, "evil", TENANT_A), SECRET));
    }

    /// Cross-tenant forgery, in the shape the `kid` makes possible: take a
    /// genuine token for tenant B and relabel its header to name tenant A, so
    /// it would be read under A's context. The relabelled `kid` selects A's
    /// key, which never signed this token, so the signature refuses it.
    #[test]
    fn validation_rejects_a_token_relabelled_for_another_tenant() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let token = mint(SECRET, TENANT_B, TOKEN_ISSUER, TENANT_B);
        assert!(verify(&token, SECRET), "genuine tenant-B token should verify");

        let parts: Vec<&str> = token.split('.').collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        let generation = header["kid"]
            .as_str()
            .and_then(|k| k.split_once('.'))
            .map(|(g, _)| g.to_string())
            .expect("kid names a generation");
        header["kid"] = serde_json::Value::String(format!("{generation}.{TENANT_A}"));
        let relabelled = format!(
            "{}.{}.{}",
            b64.encode(serde_json::to_vec(&header).unwrap()),
            parts[1],
            parts[2]
        );

        assert!(!verify(&relabelled, SECRET));
    }

    #[test]
    fn validation_rejects_wrong_secret() {
        assert!(!verify(
            &mint(SECRET, TENANT_A, TOKEN_ISSUER, TENANT_A),
            OTHER_SECRET
        ));
    }

    /// `exp` is a required spec claim, so a token that omits it entirely is
    /// rejected rather than treated as non-expiring.
    #[test]
    fn validation_rejects_token_without_exp() {
        #[derive(Serialize)]
        struct NoExp {
            sub: String,
            email: String,
            role: String,
            iss: String,
            aud: String,
            #[serde(rename = "type")]
            token_type: String,
            is_super_admin: bool,
            tenant_id: String,
            iat: usize,
            nbf: usize,
        }
        let iat = Utc::now().timestamp() as usize;
        let token = sign(
            SECRET,
            TENANT_A,
            &NoExp {
                sub: Uuid::nil().to_string(),
                email: "a@example.com".to_string(),
                role: "admin".to_string(),
                iss: TOKEN_ISSUER.to_string(),
                aud: TENANT_A.to_string(),
                token_type: "admin".to_string(),
                is_super_admin: false,
                tenant_id: TENANT_A.to_string(),
                iat,
                nbf: iat,
            },
        );
        assert!(!verify(&token, SECRET));
    }

    /// A console session with no `nbf` is refused. Two independent mechanisms
    /// reach that outcome — `AdminClaims.nbf` is a mandatory serde field, and
    /// `nbf` is in the required spec claims — and this asserts the outcome, not
    /// either mechanism. `the_required_claims_refuse_a_session_without_nbf`
    /// isolates the second, on this validation's own required set. (Each of the
    /// three validation builders in the workspace keeps its own list, so
    /// isolating one says nothing about the others.)
    #[test]
    fn validation_rejects_token_without_nbf() {
        let mut payload = serde_json::to_value(AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat: Utc::now().timestamp() as usize,
            nbf: Utc::now().timestamp() as usize,
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        })
        .expect("claims");
        payload.as_object_mut().expect("object").remove("nbf");
        assert!(!verify(&sign(SECRET, TENANT_A, &payload), SECRET));
    }

    /// A claim shape that names only what this test reads, so a missing `nbf`
    /// deserializes cleanly — which is what makes it the honest test of
    /// `streamscope_jwt_validation`'s required set rather than of serde.
    #[derive(Deserialize)]
    struct SubsetSessionClaims {
        tenant_id: String,
    }

    /// `validate_nbf` is a no-op on a token that omits the claim, so the
    /// requirement is what makes the not-yet-valid check real on the session
    /// path too. Drive the validation directly with a shape that would
    /// otherwise tolerate the missing field.
    #[test]
    fn the_required_claims_refuse_a_session_without_nbf() {
        let (_, key) = ring(SECRET).signing_key(TENANT_A);
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat,
            nbf: iat,
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
        };

        let check = |token: &str| {
            jsonwebtoken::decode::<SubsetSessionClaims>(
                token,
                &DecodingKey::from_secret(&key),
                &streamscope_jwt_validation(TENANT_A),
            )
        };

        // Control: with `nbf` present the same subset shape decodes, so the
        // refusal below is about the missing claim and not the shape.
        let intact = sign(SECRET, TENANT_A, &claims);
        assert_eq!(
            check(&intact).expect("intact decodes").claims.tenant_id,
            TENANT_A
        );

        let mut payload = serde_json::to_value(&claims).expect("claims");
        payload.as_object_mut().expect("object").remove("nbf");
        assert!(check(&sign(SECRET, TENANT_A, &payload)).is_err());
    }

    /// A session that has not started yet must not authenticate.
    #[test]
    fn validation_rejects_token_not_yet_valid() {
        let now = Utc::now();
        let claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat: now.timestamp() as usize,
            // Well outside the 60s default leeway.
            nbf: (now + chrono::Duration::hours(1)).timestamp() as usize,
            exp: (now + chrono::Duration::hours(2)).timestamp() as usize,
        };
        assert!(!verify(&sign(SECRET, TENANT_A, &claims), SECRET));
    }

    /// A session JWT carries the tenant twice — `aud` and `tenant_id` — and
    /// different callers read different ones: the console reads `aud`, the
    /// portal reads `tenant_id` to pick a tenant's RLS database context. Both
    /// must be pinned to the key that signed the token, so a payload where they
    /// disagree is refused outright.
    #[test]
    fn validation_rejects_a_tenant_id_that_disagrees_with_the_audience() {
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let mut claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat,
            nbf: iat,
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
        };

        // Control: signed under A's key, `kid` names A, both tenant claims say
        // A — accepted, so the refusal below is about the disagreement alone.
        assert!(
            decode_session_jwt::<AdminClaims>(&ring(SECRET), &sign(SECRET, TENANT_A, &claims))
                .is_some()
        );

        claims.tenant_id = TENANT_B.to_string();
        assert!(
            decode_session_jwt::<AdminClaims>(&ring(SECRET), &sign(SECRET, TENANT_A, &claims))
                .is_none()
        );
    }

    /// A token with no `kid` names no key, so nothing can verify it. Every
    /// session minted before the keyring landed is in exactly this shape — the
    /// mass logout this rejection causes is the point.
    #[test]
    fn validation_rejects_token_without_kid() {
        let (_, key) = ring(SECRET).signing_key(TENANT_A);
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat,
            nbf: iat,
            exp: (now + chrono::Duration::hours(1)).timestamp() as usize,
        };
        let token =
            jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &claims,
                &EncodingKey::from_secret(&key),
            )
                .unwrap();
        assert!(!verify(&token, SECRET));
    }

    /// A session signed under the outgoing `AUTH_SECRET_SECONDARY` keeps working
    /// through the overlap window, and stops the moment that secret is dropped.
    /// This is what makes rotating `AUTH_SECRET` a non-event for logged-in users.
    #[test]
    fn validation_accepts_the_previous_generation() {
        let token = mint(OTHER_SECRET, TENANT_A, TOKEN_ISSUER, TENANT_A);
        let rotated = Keyring::new(SECRET, Some(OTHER_SECRET)).expect("ring");
        let (tenant, key) = session_verification_key(&rotated, &token).expect("resolves");
        assert!(jsonwebtoken::decode::<AdminClaims>(
            &token,
            &DecodingKey::from_secret(&key),
            &streamscope_jwt_validation(&tenant),
        )
        .is_ok());

        assert!(!verify(&token, SECRET));
    }

    #[test]
    fn validation_rejects_expired_token() {
        let past = Utc::now() - chrono::Duration::hours(2);
        let claims = AdminClaims {
            sub: Uuid::nil().to_string(),
            email: "a@example.com".to_string(),
            role: "admin".to_string(),
            iss: TOKEN_ISSUER.to_string(),
            aud: TENANT_A.to_string(),
            token_type: "admin".to_string(),
            is_super_admin: false,
            tenant_id: TENANT_A.to_string(),
            iat: past.timestamp() as usize,
            nbf: past.timestamp() as usize,
            // Well outside the 60s default leeway.
            exp: (past + chrono::Duration::minutes(1)).timestamp() as usize,
        };
        assert!(!verify(&sign(SECRET, TENANT_A, &claims), SECRET));
    }

    /// `generate_jwt` must stamp the claim shape the middleware relies on:
    /// `iss` pinned, `aud` == `tenant_id`, and `type` == "admin" (the
    /// discriminator `validate_session_token` uses to refuse portal tokens).
    #[test]
    fn generate_jwt_stamps_the_expected_claims() {
        let id = Uuid::new_v4();
        let token = generate_jwt(&ring(SECRET), &id, "a@example.com", "read_only", TENANT_A, false)
            .expect("generate_jwt");
        let claims = decode_minted(&token);

        assert_eq!(claims.sub, id.to_string());
        assert_eq!(claims.email, "a@example.com");
        assert_eq!(claims.role, "read_only");
        assert_eq!(claims.iss, TOKEN_ISSUER);
        assert_eq!(claims.nbf, claims.iat);
        assert_eq!(claims.aud, TENANT_A);
        assert_eq!(claims.tenant_id, TENANT_A);
        assert_eq!(claims.token_type, "admin");
        assert!(!claims.is_super_admin);
    }

    /// The session lifetime is `jwt_expiry_hours`, read from the same setting
    /// rather than a literal so the assertion states the invariant.
    ///
    /// Limit worth knowing: because both sides read the setting, this cannot
    /// catch a mint site that hardcodes the *current default*. What it does
    /// catch is one that hardcodes a different lifetime — and `generate_jwt`
    /// being the sole console minter is what makes covering it here enough.
    #[test]
    fn generate_jwt_lifetime_follows_the_configured_expiry() {
        let token = generate_jwt(&ring(SECRET), &Uuid::new_v4(), "a@example.com", "admin", TENANT_A, true)
            .expect("generate_jwt");
        let claims = decode_minted(&token);

        let expected = crate::settings::admin_settings().jwt_expiry_hours * 3600;
        assert_eq!(claims.exp as i64 - claims.iat as i64, expected);
    }

    #[test]
    fn generate_jwt_carries_super_admin() {
        let token = generate_jwt(&ring(SECRET), &Uuid::new_v4(), "a@example.com", "admin", TENANT_A, true)
            .expect("generate_jwt");
        let claims = decode_minted(&token);
        assert!(claims.is_super_admin);
    }
}

