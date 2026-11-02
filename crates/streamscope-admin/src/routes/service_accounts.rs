//! Service-account management — the principal-first surface for automation.
//!
//! A service account is a non-human `users` row (`auth_source='service'`) that
//! owns long-lived keys. The principal is the resource; keys are a sub-resource.
//! Because it never logs in and isn't tied to a person, its keys are the standing
//! automation credentials — auditable, person-independent, revocable.
//!
//! Two key families live in two tables, deliberately:
//!   - **automation keys** (`ak-…`, `automation_keys`) — the control planes.
//!     `plane='admin'` (`/api/v1/admin/*`; no workspace; authority is
//!     `admin_scope`) or `plane='portal'` (`/api/v1/portal/*`; confined to one
//!     workspace via the owning account's manager role there).
//!   - **gateway keys** (`sk-`/`vk-`, `api_keys`) — data plane; workspace-bound
//!     (allowlist + budget). The proxy edge only ever reads `api_keys`, so an
//!     automation key can never be presented to the proxy.
//!
//! Lifecycle: **disable** (reversible — `is_active=false`, keys kept but stop
//! authenticating on every plane), **enable** (reactivate — non-revoked keys
//! resume), **revoke** (terminal — disable + revoke ALL keys atomically). The
//! built-in agent is the canonical service account and is guarded against all
//! three; its key is replaced via the rotate action instead.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_core::auth::virtual_key::{
    generate_admin_key, generate_forward_key, generate_virtual_key, hash_key,
};

use super::keys::KeyBudget;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, TotalPage};
use crate::agent::AGENT_EMAIL;
use crate::authz::admin_scope;
use crate::db::tenant::{AdminTenantCtx, TenantConn, TenantId};
use crate::service_account::{create_service_account, ensure_workspace_membership, slugify};
use crate::AdminState;

// ---------------------------------------------------------------------------
// Create service account
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateServiceAccountRequest {
    /// Human-facing display name (e.g. "CI bot").
    pub name: String,
    /// Stable login-less identity. When omitted, auto-derived as
    /// `svc-<slug>@<tenant>.service`. Must be unique within the tenant.
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts",
    tag = "Service Accounts",
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, description = "Service account created", body = ServiceAccountResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Email already taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_service_account_handler(
    mut db: TenantConn,
    Json(req): Json<CreateServiceAccountRequest>,
) -> Result<(StatusCode, Json<ServiceAccountResponse>), ApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required").code(ApiErrorCode::ValidationFailed));
    }

    // Resolve the email: explicit, or auto-derived from name + tenant slug.
    let email = match req.email.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        // Stored normalized, like every address (`routes::normalize_email`).
        Some(e) => {
            let email = super::normalize_email(e);
            super::require_address(&email)?;
            email
        }
        None => {
            let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
                .bind(db.tenant_uuid())
                .fetch_optional(db.conn())
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "tenant".to_string());
            let local = slugify(&name);
            let local = if local.is_empty() { "account".to_string() } else { local };
            format!("svc-{local}@{slug}.service")
        }
    };

    // Reject a collision with an existing account (service or human).
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = $2)",
    )
    .bind(&email)
    .bind(db.tenant_uuid())
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create service account email check: {e}");
        ApiError::internal("failed to validate email")
    })?;
    if taken {
        return Err(ApiError::conflict("an account with that email already exists", ApiErrorCode::UserEmailTaken));
    }

    let tenant_uuid = db.tenant_uuid();
    let user_id = create_service_account(db.conn(), tenant_uuid, &email, &name)
        .await
        .map_err(|e| {
            // A concurrent create can pass the check above and lose here.
            if super::is_unique_violation(&e) {
                return ApiError::conflict("an account with that email already exists", ApiErrorCode::UserEmailTaken);
            }
            tracing::error!("create service account: {e}");
            ApiError::internal("failed to create service account")
        })?;

    Ok((
        StatusCode::CREATED,
        Json(ServiceAccountResponse { id: user_id, email, name }),
    ))
}

// ---------------------------------------------------------------------------
// List / get service accounts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct ServiceAccountListItem {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    /// True for the built-in agent service account (read-only in the UI).
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
    /// Count of live (non-revoked, non-expired) keys the account owns, across
    /// both the admin and gateway key tables.
    pub active_keys: i64,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/service-accounts",
    tag = "Service Accounts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of service accounts", body = OffsetPage<ServiceAccountListItem>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_service_accounts(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<ServiceAccountListItem>>, ApiError> {
    let (limit, offset) = page.resolve();
    // Live-key count + last-used fold across both key tables.
    let rows = sqlx::query_as::<_, ServiceAccountListItem>(
        "SELECT u.id, u.email, u.display_name, u.is_active, \
                (u.email = $1 OR u.email = $4) AS is_builtin, u.created_at, \
                (COALESCE(g.cnt, 0) + COALESCE(a.cnt, 0))::bigint AS active_keys, \
                GREATEST(g.last_used, a.last_used) AS last_used_at \
         FROM users u \
         LEFT JOIN ( \
            SELECT user_id, COUNT(*) FILTER (WHERE revoked_at IS NULL \
                AND (expires_at IS NULL OR expires_at > NOW())) AS cnt, \
                MAX(last_used_at) AS last_used \
            FROM api_keys GROUP BY user_id \
         ) g ON g.user_id = u.id \
         LEFT JOIN ( \
            SELECT service_account_id, COUNT(*) FILTER (WHERE revoked_at IS NULL \
                AND (expires_at IS NULL OR expires_at > NOW())) AS cnt, \
                MAX(last_used_at) AS last_used \
            FROM automation_keys GROUP BY service_account_id \
         ) a ON a.service_account_id = u.id \
         WHERE u.auth_source = 'service' \
         ORDER BY u.created_at DESC \
         LIMIT $2 OFFSET $3",
    )
    .bind(AGENT_EMAIL)
    .bind(limit + 1)
    .bind(offset)
    .bind(crate::service_account::INLINE_AI_EMAIL)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list service accounts: {e}");
        ApiError::internal("failed to list service accounts")
    })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

/// A key owned by a service account — unified across the automation (`ak-`) and
/// gateway (`sk-`/`vk-`) tables. `plane` discriminates; the per-plane fields are
/// populated only where they apply.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct ServiceAccountKeyItem {
    pub id: Uuid,
    pub name: Option<String>,
    pub key_prefix: Option<String>,
    /// `admin` (ak-, admin control plane) | `portal` (ak-, portal control plane)
    /// | `gateway` (sk-/vk-, data plane).
    pub plane: String,
    /// `read_only` | `admin` | `super_admin` — admin-plane keys only.
    pub admin_scope: Option<String>,
    /// BYOK (`vk-`) flag — gateway keys only.
    pub forward_auth: Option<bool>,
    pub workspace_id: Option<Uuid>,
    pub workspace_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    pub budget_mode: Option<String>,
}

/// Both key tables as one row set: automation keys (`admin` / `portal` plane)
/// and gateway keys (`gateway` plane), each column filled only where it applies.
const SA_KEYS_UNION: &str = "\
    SELECT k.id, k.name, k.key_prefix, k.plane, k.admin_scope, NULL::boolean AS forward_auth, \
           k.workspace_id, w.name AS workspace_name, k.created_at, k.expires_at, k.revoked_at, \
           k.last_used_at, NULL::double precision AS daily_budget, \
           NULL::double precision AS monthly_budget, NULL::text AS budget_mode \
      FROM automation_keys k LEFT JOIN workspaces w ON w.id = k.workspace_id \
     WHERE k.service_account_id = $1 \
    UNION ALL \
    SELECT k.id, k.name, COALESCE(k.key_prefix, LEFT(k.key_hash, 8)), 'gateway', NULL, \
           k.forward_auth, k.workspace_id, w.name, k.created_at, k.expires_at, k.revoked_at, \
           k.last_used_at, k.daily_budget, k.monthly_budget, k.budget_mode \
      FROM api_keys k JOIN workspaces w ON w.id = k.workspace_id \
     WHERE k.user_id = $1";

/// The service account's keys from both tables, newest first. `limit = None`
/// reads them all.
async fn fetch_sa_keys(
    db: &mut TenantConn,
    sa_id: Uuid,
    limit: Option<i64>,
    offset: i64,
) -> Result<Vec<ServiceAccountKeyItem>, sqlx::Error> {
    sqlx::query_as::<_, ServiceAccountKeyItem>(sqlx::AssertSqlSafe(format!(
        "SELECT * FROM ({SA_KEYS_UNION}) keys ORDER BY created_at DESC, id LIMIT $2 OFFSET $3"
    )))
    .bind(sa_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
}

async fn count_sa_keys(db: &mut TenantConn, sa_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM automation_keys WHERE service_account_id = $1) \
              + (SELECT COUNT(*) FROM api_keys WHERE user_id = $1)",
    )
    .bind(sa_id)
    .fetch_one(db.conn())
    .await
}

#[derive(Serialize, ToSchema)]
pub struct ServiceAccountDetail {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
    pub keys: Vec<ServiceAccountKeyItem>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/service-accounts/{id}",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account with its keys", body = ServiceAccountDetail),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_service_account(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceAccountDetail>, ApiError> {
    #[allow(clippy::type_complexity)]
    let account: Option<(Uuid, String, Option<String>, bool, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, email, display_name, is_active, created_at \
         FROM users WHERE id = $1 AND auth_source = 'service'",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get service account: {e}");
        ApiError::internal("failed to load service account")
    })?;

    let Some((sa_id, email, display_name, is_active, created_at)) = account else {
        return Err(ApiError::not_found("service account not found", ApiErrorCode::UserNotFound));
    };

    let keys = fetch_sa_keys(&mut db, sa_id, None, 0).await.map_err(|e| {
        tracing::error!("get service account keys: {e}");
        ApiError::internal("failed to load service account keys")
    })?;

    Ok(Json(ServiceAccountDetail {
        id: sa_id,
        is_builtin: email == AGENT_EMAIL || email == crate::service_account::INLINE_AI_EMAIL,
        email,
        display_name,
        is_active,
        created_at,
        keys,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/service-accounts/{id}/keys",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID"), PageQuery),
    responses(
        (status = 200, description = "The service account's keys, newest first", body = TotalPage<ServiceAccountKeyItem>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_service_account_keys(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<ServiceAccountKeyItem>>, ApiError> {
    let (limit, offset) = page.resolve();
    let failed = |e: sqlx::Error| {
        tracing::error!("list service account keys: {e}");
        ApiError::internal("failed to list keys")
    };
    let total = count_sa_keys(&mut db, id).await.map_err(failed)?;
    let keys = fetch_sa_keys(&mut db, id, Some(limit), offset).await.map_err(failed)?;
    Ok(Json(TotalPage::new(keys, limit, offset, total)))
}

// ---------------------------------------------------------------------------
// Lifecycle: disable / enable / revoke
// ---------------------------------------------------------------------------

/// Resolve the email of an existing service account, 404 otherwise; reject the
/// built-in agent (`verb` only flavours the error message).
async fn require_non_agent_sa(
    db: &mut TenantConn,
    id: Uuid,
    verb: &str,
) -> Result<String, ApiError> {
    let email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE id = $1 AND auth_source = 'service'",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("{verb} service account lookup: {e}");
        ApiError::internal("failed to load service account")
    })?;
    let Some(email) = email else {
        return Err(ApiError::not_found("service account not found", ApiErrorCode::UserNotFound));
    };
    if email == AGENT_EMAIL {
        return Err(ApiError::bad_request(format!(
            "the built-in agent service account cannot be {verb}d"
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    if email == crate::service_account::INLINE_AI_EMAIL {
        return Err(ApiError::bad_request(format!(
            "the built-in inline-AI service account cannot be {verb}d"
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    Ok(email)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/actions/disable",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account disabled; keys kept but stop authenticating", body = ActionResponse),
        (status = 400, description = "Cannot disable the built-in agent", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_service_account(
    db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    set_sa_active(db, id, false).await
}

/// Shared body of the reversible disable/enable pair: flip `users.is_active`,
/// keys untouched. Every key auth path gates on `is_active` (ak- live at lookup;
/// sk-/vk- via the edge snapshot, which excludes inactive owners).
async fn set_sa_active(
    mut db: TenantConn,
    id: Uuid,
    active: bool,
) -> Result<Json<ActionResponse>, ApiError> {
    let verb = if active { "enable" } else { "disable" };
    require_non_agent_sa(&mut db, id, verb).await?;

    sqlx::query("UPDATE users SET is_active = $2 WHERE id = $1")
        .bind(id)
        .bind(active)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("{verb} service account: {e}");
            ApiError::internal("failed to update service account")
        })?;


    Ok(Json(ActionResponse::ok().with_message(if active {
        "Service account enabled. All its non-revoked keys authenticate again."
    } else {
        "Service account disabled. Its keys stop authenticating but are kept; enable the account to restore them."
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/actions/enable",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account re-enabled; non-revoked keys resume working", body = ActionResponse),
        (status = 400, description = "Cannot enable the built-in agent", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_service_account(
    db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    set_sa_active(db, id, true).await
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/actions/revoke",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account revoked: disabled and ALL its keys revoked", body = ActionResponse),
        (status = 400, description = "Cannot revoke the built-in agent", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_service_account(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    require_non_agent_sa(&mut db, id, "revoke").await?;

    // Terminal, fail-closed: disable the principal AND revoke its live keys in
    // BOTH tables, atomically — a partial failure must never leave a "revoked"
    // account still holding usable keys.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("revoke service account begin tx: {e}");
        ApiError::internal("failed to revoke service account")
    })?;
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("revoke service account disable: {e}");
            ApiError::internal("failed to revoke service account")
        })?;
    let gw = sqlx::query("UPDATE api_keys SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("revoke service account gateway keys: {e}");
            ApiError::internal("failed to revoke service account keys")
        })?
        .rows_affected();
    let ak = sqlx::query("UPDATE automation_keys SET revoked_at = NOW() WHERE service_account_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("revoke service account automation keys: {e}");
            ApiError::internal("failed to revoke service account keys")
        })?
        .rows_affected();
    tx.commit().await.map_err(|e| {
        tracing::error!("revoke service account commit: {e}");
        ApiError::internal("failed to revoke service account")
    })?;


    Ok(Json(ActionResponse::ok().with_message(format!(
        "Service account revoked; {} key(s) revoked.",
        gw + ak
    ))))
}

// ---------------------------------------------------------------------------
// Mint a key under a service account
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct MintServiceAccountKeyRequest {
    /// `admin` (ak- automation key) | `gateway` (sk-/vk- data-plane key).
    #[serde(rename = "type")]
    pub key_type: String,
    pub name: String,
    /// Required when `type=admin`: `read_only` | `admin` | `super_admin`.
    #[serde(default)]
    pub admin_scope: Option<String>,
    /// Required when `type=gateway`: the workspace the key binds to.
    #[serde(default)]
    pub workspace_id: Option<Uuid>,
    /// When `type=gateway` and true, mint a `vk-` BYOK key; else `sk-`.
    #[serde(default)]
    pub forward_auth: Option<bool>,
    /// Optional per-key budget (gateway keys only).
    #[serde(default)]
    pub budget: Option<KeyBudget>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
pub struct MintServiceAccountKeyResponse {
    pub id: Uuid,
    /// The plaintext key — returned ONCE, never again.
    pub key: String,
    pub name: Option<String>,
    /// `admin` | `gateway`.
    pub plane: String,
    pub admin_scope: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Gateway BYOK (`vk-`) connection origin; `None` for admin/portal keys.
    pub proxy_base_url: Option<String>,
    /// Admin/portal `ak-` scripting origin (`api_public_url`) — the FQDN the
    /// admin-API is served on, which the reveal-once example targets. `None`
    /// for gateway keys or when the API origin isn't configured (the UI then
    /// falls back to the console origin, correct for co-resident installs).
    pub api_base_url: Option<String>,
}

/// API origin to surface in an admin/portal `ak-` key's reveal-once snippet:
/// those keys are scripted against the admin-API at `api_public_url`. `None`
/// when unset — the UI falls back to the console origin (co-resident
/// single-domain installs / e2e serve the API same-origin).
async fn admin_key_api_base_url(
    state: &AdminState,
    tenant_uuid: Uuid,
) -> Result<Option<String>, ApiError> {
    crate::tenant_public_url::try_resolve_public_url(
        &state.db,
        tenant_uuid,
        crate::tenant_public_url::PublicUrlKey::Api,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/keys",
    tag = "Service Accounts",
    request_body = MintServiceAccountKeyRequest,
    params(("id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 201, description = "Key minted (plaintext returned once)", body = MintServiceAccountKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "Insufficient privilege for the requested scope", body = ApiErrorResponse),
        (status = 404, description = "Service account not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mint_service_account_key(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AdminTenantCtx>,
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<MintServiceAccountKeyRequest>,
) -> Result<(StatusCode, Json<MintServiceAccountKeyResponse>), ApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("key name is required").code(ApiErrorCode::ValidationFailed));
    }

    // The service account must exist and be a real service principal.
    let sa_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND auth_source = 'service')",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("mint key validate service account: {e}");
        ApiError::internal("failed to validate service account")
    })?;
    if !sa_exists {
        return Err(ApiError::not_found("service account not found", ApiErrorCode::UserNotFound));
    }

    let now = Utc::now();
    let key_id = Uuid::new_v4();

    // The SYSTEM tenant runs no workloads (auth + platform audit only): it mints
    // only Operator (`super_admin`) automation keys — no gateway keys, no
    // tenant-level scopes.
    if db.tenant_id() == TenantId::SYSTEM
        && (req.key_type != "admin" || req.admin_scope.as_deref() != Some(admin_scope::SUPER_ADMIN))
    {
        return Err(ApiError::bad_request(
            "the SYSTEM tenant mints only Operator (super_admin) automation keys",
        )
        .code(ApiErrorCode::ValidationFailed));
    }

    match req.key_type.as_str() {
        "admin" => {
            let scope = req
                .admin_scope
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ApiError::bad_request("admin_scope is required for an admin key")
                        .code(ApiErrorCode::ValidationFailed)
                })?;
            if !admin_scope::is_valid(scope) {
                return Err(ApiError::bad_request(
                    "admin_scope must be read_only, admin, or super_admin",
                )
                .code(ApiErrorCode::ValidationFailed));
            }
            // `super_admin` is the cross-tenant operator key — mintable ONLY by a
            // super-admin caller in the SYSTEM tenant. Double-enforced with the
            // auth-time check that only SYSTEM keys ever resolve is_super_admin.
            if scope == admin_scope::SUPER_ADMIN
                && !(ctx.is_super_admin && db.tenant_id() == TenantId::SYSTEM)
            {
                return Err(ApiError::forbidden(
                    "super_admin keys can only be minted by a super-admin in the SYSTEM tenant",
                )
                .code(ApiErrorCode::PermissionDenied));
            }

            let plaintext = generate_admin_key();
            let key_hash = hash_key(&plaintext);
            let key_prefix = &plaintext[..plaintext.len().min(12)];
            sqlx::query(
                "INSERT INTO automation_keys (id, tenant_id, plane, service_account_id, key_hash, key_prefix, name, admin_scope, expires_at, created_at) \
                 VALUES ($1, $2, 'admin', $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(key_id)
            .bind(db.tenant_uuid())
            .bind(id)
            .bind(&key_hash)
            .bind(key_prefix)
            .bind(&name)
            .bind(scope)
            .bind(req.expires_at)
            .bind(now)
            .execute(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("mint admin key: {e}");
                ApiError::internal("failed to mint key")
            })?;

            let api_base_url = admin_key_api_base_url(&state, db.tenant_uuid()).await?;
            Ok((
                StatusCode::CREATED,
                Json(MintServiceAccountKeyResponse {
                    id: key_id,
                    key: plaintext,
                    name: Some(name),
                    plane: "admin".to_string(),
                    admin_scope: Some(scope.to_string()),
                    created_at: now,
                    proxy_base_url: None,
                    api_base_url,
                }),
            ))
        }
        "gateway" => {
            let Some(workspace_id) = req.workspace_id else {
                return Err(ApiError::bad_request("workspace_id is required for a gateway key")
                    .code(ApiErrorCode::ValidationFailed));
            };
            let ws_exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1)")
                    .bind(workspace_id)
                    .fetch_one(db.conn())
                    .await
                    .map_err(|e| {
                        tracing::error!("mint key validate workspace: {e}");
                        ApiError::internal("failed to validate workspace")
                    })?;
            if !ws_exists {
                return Err(
                    ApiError::bad_request("workspace not found").code(ApiErrorCode::WorkspaceNotFound)
                );
            }
            let tenant_uuid = db.tenant_uuid();
            let forward_auth = req.forward_auth.unwrap_or(false);
            let plaintext = if forward_auth { generate_forward_key() } else { generate_virtual_key() };
            let key_hash = hash_key(&plaintext);
            let key_prefix = &plaintext[..plaintext.len().min(12)];
            let (daily, monthly, mode) = match &req.budget {
                Some(b) => (
                    b.daily_budget,
                    b.monthly_budget,
                    crate::routes::workspaces::norm_budget_mode(&b.budget_mode),
                ),
                None => (None, None, crate::routes::workspaces::default_budget_mode()),
            };
            // Membership + key INSERT atomically — never add the SA to a workspace
            // without the key it was added for (or vice versa).
            let mut tx = db.conn().begin().await.map_err(|e| {
                tracing::error!("mint gateway key begin tx: {e}");
                ApiError::internal("failed to mint key")
            })?;
            // The SA must be a member of the target workspace to hold a key in it.
            ensure_workspace_membership(&mut tx, tenant_uuid, id, workspace_id)
                .await
                .map_err(|e| {
                    tracing::error!("mint key ensure membership: {e}");
                    ApiError::internal("failed to add service account to workspace")
                })?;
            // A service account is unattended work by definition, so it takes
            // the tenant's class for automation.
            let qos_class_id = crate::routes::qos_classes::default_class_for_mint(
                &mut tx,
                workspace_id,
                crate::routes::qos_classes::MintPrincipal::Automation,
            )
            .await?;
            sqlx::query(
                "INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, key_hash, key_prefix, name, forward_auth, expires_at, created_at, daily_budget, monthly_budget, budget_mode, qos_class_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(key_id)
            .bind(tenant_uuid)
            .bind(workspace_id)
            .bind(id)
            .bind(&key_hash)
            .bind(key_prefix)
            .bind(&name)
            .bind(forward_auth)
            .bind(req.expires_at)
            .bind(now)
            .bind(daily)
            .bind(monthly)
            .bind(&mode)
            .bind(qos_class_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("mint gateway key: {e}");
                ApiError::internal("failed to mint key")
            })?;
            tx.commit().await.map_err(|e| {
                tracing::error!("mint gateway key commit: {e}");
                ApiError::internal("failed to mint key")
            })?;

            // Every gateway key is exercised against the proxy origin — standard on
            // `/v1/...`, BYOK on `/fwd/{key}/v1/...` — so always carry the origin.
            let proxy_base_url = crate::tenant_public_url::try_resolve_public_url(
                &state.db,
                tenant_uuid,
                crate::tenant_public_url::PublicUrlKey::Proxy,
            )
            .await?;

            Ok((
                StatusCode::CREATED,
                Json(MintServiceAccountKeyResponse {
                    id: key_id,
                    key: plaintext,
                    name: Some(name),
                    plane: "gateway".to_string(),
                    admin_scope: None,
                    created_at: now,
                    proxy_base_url,
                    api_base_url: None,
                }),
            ))
        }
        _ => Err(ApiError::bad_request("type must be 'admin' or 'gateway'")
            .code(ApiErrorCode::ValidationFailed)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/keys/{key_id}/actions/revoke",
    tag = "Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID"),
        ("key_id" = Uuid, Path, description = "Key ID"),
    ),
    responses(
        (status = 200, description = "Key revoked (row retained for audit linkage)", body = ActionResponse),
        (status = 404, description = "Key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_service_account_key(
    mut db: TenantConn,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Automation key first (either plane), then gateway — the id is unique to one
    // table.
    let admin = sqlx::query(
        "UPDATE automation_keys SET revoked_at = NOW() \
         WHERE id = $1 AND service_account_id = $2 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("revoke admin key: {e}");
        ApiError::internal("failed to revoke key")
    })?
    .rows_affected();

    let gw = if admin == 0 {
        sqlx::query(
            "UPDATE api_keys SET revoked_at = NOW() \
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("revoke gateway key: {e}");
            ApiError::internal("failed to revoke key")
        })?
        .rows_affected()
    } else {
        0
    };

    if admin == 0 && gw == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }

    Ok(Json(ActionResponse::ok().with_message("Key revoked.")))
}

// ---------------------------------------------------------------------------
// Rotate a service-account key (mint replacement + revoke old, one transaction)
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/keys/{key_id}/actions/rotate",
    tag = "Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID"),
        ("key_id" = Uuid, Path, description = "Key ID to rotate"),
    ),
    responses(
        (status = 200, description = "Key rotated: same-shape replacement minted (plaintext returned once), old key revoked — atomically", body = MintServiceAccountKeyResponse),
        (status = 400, description = "The built-in agent's key rotates via its dedicated action", body = ApiErrorResponse),
        (status = 404, description = "Live key not found for that account", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_service_account_key(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<MintServiceAccountKeyResponse>), ApiError> {
    // The agent's key has a stored plaintext the agent reads — rotating it here
    // would orphan that; its dedicated action handles the storage too.
    let is_agent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2)",
    )
    .bind(id)
    .bind(AGENT_EMAIL)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("rotate key agent check: {e}");
        ApiError::internal("failed to rotate key")
    })?;
    if is_agent {
        return Err(ApiError::bad_request(
            "the built-in agent's key rotates via the rotate-agent-key action",
        )
        .code(ApiErrorCode::ValidationFailed));
    }
    // Same exclusion for the inline-AI managed key: its dedicated action owns
    // the stored plaintext (and the reveal); a generic rotate would orphan it.
    let is_inline_ai: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2)")
            .bind(id)
            .bind(crate::service_account::INLINE_AI_EMAIL)
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("rotate key inline-ai check: {e}");
                ApiError::internal("failed to rotate key")
            })?;
    if is_inline_ai {
        return Err(ApiError::bad_request(
            "the built-in inline-AI key rotates via the rotate-inline-ai-key action",
        )
        .code(ApiErrorCode::ValidationFailed));
    }

    let tenant_uuid = db.tenant_uuid();
    let now = Utc::now();
    let new_id = Uuid::new_v4();

    // Locate the LIVE key in either family. Rotation restarts the key's
    // LIFETIME: the replacement expires `created→expiry` from NOW, not at the
    // old absolute timestamp — rotating near expiry must extend, never mint a
    // key that is born (nearly) dead.
    #[allow(clippy::type_complexity)]
    let ak_row: Option<(String, Option<String>, Option<Uuid>, Option<String>, DateTime<Utc>, Option<DateTime<Utc>>)> =
        sqlx::query_as(
            "SELECT plane, admin_scope, workspace_id, name, created_at, expires_at \
             FROM automation_keys \
             WHERE id = $1 AND service_account_id = $2 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("rotate key load automation: {e}");
            ApiError::internal("failed to rotate key")
        })?;

    let restart_lifetime = |created: DateTime<Utc>, expires: Option<DateTime<Utc>>| {
        expires.map(|exp| now + (exp - created))
    };

    if let Some((plane, admin_scope_val, workspace_id, name, created_at, expires_at)) = ak_row {
        let plaintext = generate_admin_key();
        let key_hash = hash_key(&plaintext);
        let key_prefix = &plaintext[..plaintext.len().min(12)];
        let new_expiry = restart_lifetime(created_at, expires_at);

        let mut tx = db.conn().begin().await.map_err(|e| {
            tracing::error!("rotate automation key begin tx: {e}");
            ApiError::internal("failed to rotate key")
        })?;
        sqlx::query(
            "INSERT INTO automation_keys (id, tenant_id, plane, service_account_id, key_hash, key_prefix, name, admin_scope, workspace_id, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(new_id)
        .bind(tenant_uuid)
        .bind(&plane)
        .bind(id)
        .bind(&key_hash)
        .bind(key_prefix)
        .bind(&name)
        .bind(&admin_scope_val)
        .bind(workspace_id)
        .bind(new_expiry)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("rotate automation key insert: {e}");
            ApiError::internal("failed to rotate key")
        })?;
        sqlx::query("UPDATE automation_keys SET revoked_at = NOW() WHERE id = $1")
            .bind(key_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("rotate automation key revoke: {e}");
                ApiError::internal("failed to rotate key")
            })?;
        tx.commit().await.map_err(|e| {
            tracing::error!("rotate automation key commit: {e}");
            ApiError::internal("failed to rotate key")
        })?;

        // Both rotated planes here are `ak-` (admin or portal) — scripted
        // against the admin-API.
        let api_base_url = admin_key_api_base_url(&state, tenant_uuid).await?;
        return Ok((
            StatusCode::OK,
            Json(MintServiceAccountKeyResponse {
                id: new_id,
                key: plaintext,
                name,
                plane,
                admin_scope: admin_scope_val,
                created_at: now,
                proxy_base_url: None,
                api_base_url,
            }),
        ));
    }

    // Gateway family.
    #[allow(clippy::type_complexity)]
    let gw_row: Option<(Uuid, Option<String>, bool, Option<f64>, Option<f64>, String, DateTime<Utc>, Option<DateTime<Utc>>, Option<Uuid>, bool)> =
        sqlx::query_as(
            "SELECT workspace_id, name, forward_auth, daily_budget, monthly_budget, budget_mode, created_at, expires_at, \
                    qos_class_id, qos_class_elevated \
             FROM api_keys WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("rotate key load gateway: {e}");
            ApiError::internal("failed to rotate key")
        })?;

    let Some((
        workspace_id,
        name,
        forward_auth,
        daily,
        monthly,
        mode,
        created_at,
        expires_at,
        qos_class_id,
        qos_class_elevated,
    )) = gw_row
    else {
        return Err(ApiError::not_found("live key not found", ApiErrorCode::KeyNotFound));
    };

    let plaintext = if forward_auth { generate_forward_key() } else { generate_virtual_key() };
    let key_hash = hash_key(&plaintext);
    let key_prefix = &plaintext[..plaintext.len().min(12)];
    let new_expiry = restart_lifetime(created_at, expires_at);

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("rotate gateway key begin tx: {e}");
        ApiError::internal("failed to rotate key")
    })?;
    // A rotation replaces a credential, it does not re-decide what the key is:
    // an admin may have set its class deliberately, so it travels with it.
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, key_hash, key_prefix, name, forward_auth, expires_at, created_at, daily_budget, monthly_budget, budget_mode, qos_class_id, qos_class_elevated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(new_id)
    .bind(tenant_uuid)
    .bind(workspace_id)
    .bind(id)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(&name)
    .bind(forward_auth)
    .bind(new_expiry)
    .bind(now)
    .bind(daily)
    .bind(monthly)
    .bind(&mode)
    .bind(qos_class_id)
    .bind(qos_class_elevated)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("rotate gateway key insert: {e}");
        ApiError::internal("failed to rotate key")
    })?;
    sqlx::query("UPDATE api_keys SET revoked_at = NOW() WHERE id = $1")
        .bind(key_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("rotate gateway key revoke: {e}");
            ApiError::internal("failed to rotate key")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("rotate gateway key commit: {e}");
        ApiError::internal("failed to rotate key")
    })?;

    // Every gateway key is exercised against the proxy origin — standard on
    // `/v1/...`, BYOK on `/fwd/{key}/v1/...` — so always carry the origin.
    let proxy_base_url = crate::tenant_public_url::try_resolve_public_url(
        &state.db,
        tenant_uuid,
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;

    Ok((
        StatusCode::OK,
        Json(MintServiceAccountKeyResponse {
            id: new_id,
            key: plaintext,
            name,
            plane: "gateway".to_string(),
            admin_scope: None,
            created_at: now,
            proxy_base_url,
            api_base_url: None,
        }),
    ))
}

// ---------------------------------------------------------------------------
// Rotate the built-in agent's key
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/actions/rotate-agent-key",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID (must be the built-in agent)")),
    responses(
        (status = 200, description = "Agent key rotated: old key revoked, new key minted and stored", body = ActionResponse),
        (status = 404, description = "Not the built-in agent service account", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_agent_key(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Only the built-in agent has a managed key with a stored plaintext; any
    // other account rotates by minting a new key and revoking the old one.
    let is_agent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2 AND auth_source = 'service')",
    )
    .bind(id)
    .bind(AGENT_EMAIL)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("rotate agent key lookup: {e}");
        ApiError::internal("failed to load service account")
    })?;
    if !is_agent {
        return Err(ApiError::not_found("only the built-in agent service account has a rotatable key", ApiErrorCode::UserNotFound));
    }

    // One transaction: revoke the live key, then re-provision (mint + encrypt +
    // store the plaintext in system_settings). A mid-way failure rolls back to
    // the still-working old key — the agent is never left keyless.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("rotate agent key begin tx: {e}");
        ApiError::internal("failed to rotate agent key")
    })?;
    sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() \
         WHERE user_id = $1 AND name = 'agent-key' AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("rotate agent key revoke: {e}");
        ApiError::internal("failed to rotate agent key")
    })?;
    crate::agent::provision_agent_key(&mut tx).await.map_err(|e| {
        tracing::error!("rotate agent key re-provision: {e}");
        ApiError::internal("failed to rotate agent key")
    })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("rotate agent key commit: {e}");
        ApiError::internal("failed to rotate agent key")
    })?;


    Ok(Json(ActionResponse::ok().with_message(
        "Agent key rotated. The old key is revoked; edges receive the new key on the next config sync.",
    )))
}

// ---------------------------------------------------------------------------
// Rotate the built-in inline-AI key
// ---------------------------------------------------------------------------

/// The rotated inline-AI key, revealed ONCE so the operator can configure the
/// external analyzer (the mint-key reveal contract).
#[derive(Serialize, ToSchema)]
pub struct RotateInlineAiKeyResponse {
    /// The new plaintext key — returned ONCE, never again (rotate again for a
    /// fresh one).
    pub key: String,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/service-accounts/{id}/actions/rotate-inline-ai-key",
    tag = "Service Accounts",
    params(("id" = Uuid, Path, description = "Service account ID (must be the built-in inline-AI account)")),
    responses(
        (status = 200, description = "Inline-AI key rotated: old key revoked, new key minted, stored, and revealed once", body = RotateInlineAiKeyResponse),
        (status = 404, description = "Not the built-in inline-AI service account", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_inline_ai_key(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<RotateInlineAiKeyResponse>, ApiError> {
    // Only the built-in inline-AI account has this managed key. Unlike the
    // agent (whose plaintext only the gateway itself consumes), the rotated key
    // is returned once — it is the credential the operator pastes into the
    // external analyzer.
    let is_inline_ai: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2 AND auth_source = 'service')",
    )
    .bind(id)
    .bind(crate::service_account::INLINE_AI_EMAIL)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("rotate inline-ai key lookup: {e}");
        ApiError::internal("failed to load service account")
    })?;
    if !is_inline_ai {
        return Err(ApiError::not_found(
            "only the built-in inline-AI service account has a rotatable managed key",
            ApiErrorCode::UserNotFound,
        ));
    }

    // One transaction: revoke the live key, then re-provision (mint + encrypt +
    // store the plaintext in system_settings). A mid-way failure rolls back to
    // the still-working old key — the analyzer is never left keyless.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("rotate inline-ai key begin tx: {e}");
        ApiError::internal("failed to rotate inline-ai key")
    })?;
    sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() \
         WHERE user_id = $1 AND name = 'inline-ai-key' AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("rotate inline-ai key revoke: {e}");
        ApiError::internal("failed to rotate inline-ai key")
    })?;
    crate::inline_ai::provision_inline_ai_key(&mut tx)
        .await
        .map_err(|e| {
            tracing::error!("rotate inline-ai key re-provision: {e}");
            ApiError::internal("failed to rotate inline-ai key")
        })?;
    let key = crate::inline_ai::stored_inline_ai_key(&mut tx)
        .await
        .ok_or_else(|| {
            tracing::error!("rotate inline-ai key: stored key unreadable after provision");
            ApiError::internal("failed to rotate inline-ai key")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("rotate inline-ai key commit: {e}");
        ApiError::internal("failed to rotate inline-ai key")
    })?;


    Ok(Json(RotateInlineAiKeyResponse {
        key,
        message: "Inline-AI key rotated. The old key is revoked; edges accept the new key after the next config sync. Store it now — it is not shown again."
            .to_string(),
    }))
}
