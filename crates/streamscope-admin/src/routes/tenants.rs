//! Tenant management, plus the public invite-acceptance routes.
//!
//! CRUD for tenants (organizations) is super-admin only. Creating a tenant seeds
//! default data (upstream providers, transform programs, experts, catalog) and
//! optionally creates an initial admin account; deleting one cascades to all
//! child data. Accepting an invite is unauthenticated by construction — the
//! invite token IS the credential — and mounted here beside the routes that
//! issue those invites.
//!
//! These operations read the `tenants` registry through `Db::global`, whose
//! connections run as `streamscope_global`: it reads `tenants` (which carries
//! no policy) and is refused every tenant-scoped table, so it is **not** an RLS
//! bypass. A write that must land in a tenant's own context uses
//! `begin_tenant`.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::AdminState;
use crate::db::tenant::{TenantConn, TenantId};
use crate::db::Global;
use crate::routes::admin_auth::{hash_password, validate_slug, AdminAccountResponse};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct TenantResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub is_active: bool,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct TenantDetailResponse {
    #[serde(flatten)]
    #[schema(inline)]
    pub tenant: TenantResponse,
    pub admin_count: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateInviteRequest {
    pub role: Option<String>,
    pub email: Option<String>,
    /// Expiry in hours (default: 168 = 7 days, max: 168)
    pub expires_in_hours: Option<i64>,
    /// Emergency recovery invite — resets tenant auth_mode to internal.
    #[serde(default)]
    pub emergency: bool,
}

#[derive(Serialize, ToSchema)]
pub struct InviteResponse {
    pub id: Uuid,
    pub role: String,
    pub email: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
    pub used: bool,
}

#[derive(Serialize, ToSchema)]
pub struct InviteCreatedResponse {
    pub id: Uuid,
    /// Plaintext token — shown once, never stored.
    pub token: String,
    pub invite_url: String,
    pub role: String,
    pub email: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct InviteInfoResponse {
    pub valid: bool,
    pub tenant_name: Option<String>,
    pub tenant_slug: Option<String>,
    pub role: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct AcceptInviteRequest {
    pub email: String,
    pub password: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn tenant_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", post(create_tenant).get(list_tenants))
        .route("/{slug}", get(get_tenant).patch(update_tenant).delete(delete_tenant))
        .route("/{slug}/invites", post(create_invite).get(list_invites))
        .route("/{slug}/invites/{id}", delete(revoke_invite))
        .route("/{slug}/admins", get(list_tenant_admins))
}

/// Public invite routes (no auth required).
pub fn invite_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/{token}", get(get_invite_info))
        .route("/{token}/accept", post(accept_invite))
}

// ---------------------------------------------------------------------------
// Tenant CRUD (super-admin only — guard applied at route layer)
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/tenants",
    tag = "Tenants",
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = TenantResponse),
        (status = 400, description = "Bad request (invalid slug or name)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Tenant slug already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn create_tenant(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<(StatusCode, Json<TenantResponse>), ApiError> {
    // Validate slug.
    validate_slug(&req.slug).map_err(|msg| ApiError::bad_request(msg).code(ApiErrorCode::TenantSlugInvalid))?;

    if req.name.is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }

    // The tenant row and its auth config are provisioned together: a tenant
    // with no `tenant_auth_configs` row cannot be logged into. Both writes
    // commit atomically — a failure on either rolls the tenant back rather
    // than leaving an orphan row that a 201 would falsely report as created.
    //
    // The id is generated here so the transaction can be scoped to the new
    // tenant before its row exists — that scoping is what lets the RLS WITH
    // CHECK on `tenant_auth_configs` accept the child insert below.
    let new_tenant = TenantId::mint();
    let new_id = new_tenant.as_uuid();
    let mut tx = state.db.begin_tenant(new_tenant).await.map_err(|e| {
        tracing::error!("create tenant begin tx: {e}");
        ApiError::internal("internal error")
    })?;

    // Insert tenant (no RLS on tenants table).
    let tenant = sqlx::query_as::<_, TenantResponse>(
        "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) \
         RETURNING id, name, slug, is_active, created_at, updated_at",
    )
    .bind(new_id)
    .bind(&req.name)
    .bind(&req.slug)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("tenant slug already exists", ApiErrorCode::TenantSlugTaken)
        } else {
            tracing::error!("create tenant: {e}");
            ApiError::internal("internal error")
        }
    })?;

    // Default auth config. A swallowed failure here would strand the tenant
    // unloggable — propagate it so the whole transaction rolls back.
    sqlx::query(
        "INSERT INTO tenant_auth_configs (tenant_id, auth_mode) VALUES ($1, 'internal') ON CONFLICT DO NOTHING",
    )
    .bind(tenant.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(tenant_id = %tenant.id, "failed to create tenant auth config: {e}");
        ApiError::internal("internal error")
    })?;

    // Every seed type (scripts, experts, catalogs, rules, workspaces and the
    // Default profiles) in the same transaction: a tenant is created seeded or
    // not at all, with one commit.
    crate::seed_scripts::seed_new_tenant(&mut tx, new_tenant).await.map_err(|_| {
        ApiError::internal("internal error")
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("create tenant commit: {e}");
        ApiError::internal("internal error")
    })?;

    // The steps the startup passes repeat (expert colours, the agent and
    // inline-AI accounts, built-in Web), best-effort: a failure is logged and
    // retried on the next boot.
    // A caller that hangs up does not stop it half-way: a mutating request
    // runs to completion (`run_to_completion_mw`).
    crate::seed_scripts::finish_new_tenant(&state.db, new_tenant).await;


    tracing::info!(slug = %req.slug, tenant_id = %tenant.id, "tenant created");
    Ok((StatusCode::CREATED, Json(tenant)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants",
    tag = "Tenants",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of tenants", body = TotalPage<TenantResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn list_tenants(
    State(state): State<Arc<AdminState>>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<TenantResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(state.db.global(Global::TenantRegistry))
        .await
        .map_err(|e| {
            tracing::error!("count tenants: {e}");
            ApiError::internal("internal error")
        })?;
    let rows = sqlx::query_as::<_, TenantResponse>(
        "SELECT id, name, slug, is_active, created_at, updated_at FROM tenants \
         ORDER BY created_at LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.global(Global::TenantRegistry))
    .await
    .map_err(|e| {
        tracing::error!("list tenants: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants/{slug}",
    tag = "Tenants",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Tenant details", body = TenantDetailResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn get_tenant(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<TenantDetailResponse>, ApiError> {
    let tenant = sqlx::query_as::<_, TenantResponse>(
        "SELECT id, name, slug, is_active, created_at, updated_at FROM tenants WHERE slug = $1",
    )
    .bind(&slug)
    .fetch_optional(state.db.global(Global::TenantRegistry))
    .await
    .map_err(|e| {
        tracing::error!("get tenant: {e}");
        ApiError::internal("internal error")
    })?
    .ok_or_else(|| ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound))?;

    // Count admins in this tenant.
    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant.id))
        .await
        .map_err(|e| {
            tracing::error!("get tenant admin count TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

    let admin_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM admin_accounts WHERE is_active = true",
    )
    .fetch_one(db.conn())
    .await
    .unwrap_or((0,));

    Ok(Json(TenantDetailResponse {
        tenant,
        admin_count: admin_count.0,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/tenants/{slug}",
    tag = "Tenants",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = UpdateTenantRequest,
    responses(
        (status = 200, description = "Tenant updated", body = TenantResponse),
        (status = 400, description = "Bad request (cannot deactivate system tenant)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn update_tenant(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    // Cannot deactivate SYSTEM tenant.
    if slug == "system" && req.is_active == Some(false) {
        return Err(ApiError::bad_request("cannot deactivate the system tenant")
            .code(ApiErrorCode::TenantSystemImmutable));
    }

    let row = sqlx::query_as::<_, TenantResponse>(
        "UPDATE tenants SET \
            name = COALESCE($2, name), \
            is_active = COALESCE($3, is_active), \
            updated_at = NOW() \
         WHERE slug = $1 \
         RETURNING id, name, slug, is_active, created_at, updated_at",
    )
    .bind(&slug)
    .bind(&req.name)
    .bind(req.is_active)
    .fetch_optional(state.db.global(Global::TenantRegistry))
    .await
    .map_err(|e| {
        tracing::error!("update tenant: {e}");
        ApiError::internal("internal error")
    })?
    .ok_or_else(|| ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound))?;

    tracing::info!(slug = %slug, "tenant updated");
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/tenants/{slug}",
    tag = "Tenants",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Tenant deleted", body = ActionResponse),
        (status = 400, description = "Bad request (cannot delete system tenant)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn delete_tenant(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<ActionResponse>, ApiError> {
    if slug == "system" {
        return Err(ApiError::bad_request("cannot delete the system tenant")
            .code(ApiErrorCode::TenantSystemImmutable));
    }

    let db_err = |e: sqlx::Error| {
        tracing::error!("delete tenant: {e}");
        ApiError::internal("internal error")
    };

    // Resolve slug to tenant_id (needed for explicit deletes on partitioned tables).
    let tenant_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE slug = $1")
            .bind(&slug)
            .fetch_optional(state.db.global(Global::TenantRegistry))
            .await
            .map_err(db_err)?;

    let Some(tenant_id) = tenant_id else {
        return Err(ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound));
    };

    let mut tx = state.db.begin_tenant(TenantId::from_row(tenant_id)).await.map_err(db_err)?;

    // Partitioned tables aren't pulled in by the tenants CASCADE — delete
    // explicitly, before the tenant row.
    crate::audit_store::purge::delete_tenant_facts(&mut tx, tenant_id)
        .await
        .map_err(db_err)?;

    // Delete tenant row — cascades to all FK-constrained tables.
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

    tx.commit().await.map_err(db_err)?;


    tracing::info!(slug = %slug, "tenant deleted");
    Ok(Json(ActionResponse::ok()))
}

// ---------------------------------------------------------------------------
// Invite management (super-admin only)
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/tenants/{slug}/invites",
    tag = "Invites",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = CreateInviteRequest,
    responses(
        (status = 201, description = "Invite created (token shown once)", body = InviteCreatedResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn create_invite(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(mut req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<InviteCreatedResponse>), ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    // A blank restriction is no restriction, never an invite for the empty address.
    req.email = req.email.as_deref().map(super::normalize_email).filter(|e| !e.is_empty());
    if let Some(email) = req.email.as_deref() {
        super::require_address(email)?;
    }
    let (tenant_id, _) = crate::routes::admin_auth::resolve_tenant_slug(&state.db, &slug).await?;

    // Validate the requested role against the closed set (reject unknown so a
    // typo can't silently mint an unintended account), then store the canonical
    // string. Defaults to a full `admin` invite when omitted.
    let role = crate::authz::AdminRole::parse_strict(req.role.as_deref().unwrap_or(crate::authz::AdminRole::ADMIN))
        .ok_or_else(|| ApiError::bad_request("invalid invite role").code(ApiErrorCode::ValidationFailed))?
        .as_str();
    let expires_hours = req.expires_in_hours.unwrap_or(168).clamp(1, 168);

    // Generate random token (32 bytes, URL-safe base64).
    let token_bytes: [u8; 32] = rand::random();
    let token = base64_url_encode(&token_bytes);

    // Store SHA-256 hash of token (plaintext never stored).
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("create invite TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

    // Emergency invite handling.
    if req.emergency {
        // Guard: reject emergency invite for system tenant.
        if slug == "system" {
            return Err(ApiError::bad_request("cannot create emergency invite for system tenant")
                .code(ApiErrorCode::TenantSystemImmutable));
        }
        // Enforce max 1 active emergency invite per tenant.
        let active_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_invites \
             WHERE tenant_id = $1 AND is_emergency = true AND used_by IS NULL AND expires_at > NOW()",
        )
        .bind(tenant_id)
        .fetch_one(db.conn())
        .await
        .unwrap_or(0);

        if active_count > 0 {
            return Err(ApiError::conflict("an active emergency invite already exists for this tenant", ApiErrorCode::EmergencyInviteActive));
        }

        // Reset tenant auth_mode to 'internal' (preserve OIDC config).
        sqlx::query("UPDATE tenant_auth_configs SET auth_mode = 'internal', updated_at = NOW() WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("emergency invite: failed to reset auth mode: {e}");
                ApiError::internal("internal error")
            })?;
        tracing::warn!(slug = %slug, "emergency invite: tenant auth mode reset to internal");
    }

    let row: (Uuid, String, Option<String>, chrono::DateTime<Utc>, chrono::DateTime<Utc>) =
        sqlx::query_as(
            "INSERT INTO tenant_invites (tenant_id, token_hash, role, email, is_emergency, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NOW() + make_interval(hours => $6)) \
             RETURNING id, role, email, expires_at, created_at",
        )
        .bind(tenant_id)
        .bind(&token_hash)
        .bind(role)
        .bind(&req.email)
        .bind(req.emergency)
        .bind(expires_hours as i32)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("create invite: {e}");
            ApiError::internal("internal error")
        })?;

    let origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_id,
        crate::tenant_public_url::PublicUrlKey::Admin,
    )
    .await?;
    let invite_url = format!("{origin}/invite/{token}");

    tracing::info!(slug = %slug, role, "invite created");
    Ok((
        StatusCode::CREATED,
        Json(InviteCreatedResponse {
            id: row.0,
            token,
            invite_url,
            role: row.1,
            email: row.2,
            expires_at: row.3,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants/{slug}/invites",
    tag = "Invites",
    params(("slug" = String, Path, description = "Tenant slug"), PageQuery),
    responses(
        (status = 200, description = "Paginated list of invites", body = TotalPage<InviteResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn list_invites(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<InviteResponse>>, ApiError> {
    let (tenant_id, _) = crate::routes::admin_auth::resolve_tenant_slug(&state.db, &slug).await?;

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("list invites TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_invites")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count invites: {e}");
            ApiError::internal("internal error")
        })?;
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, chrono::DateTime<Utc>, chrono::DateTime<Utc>, Option<Uuid>)>(
        "SELECT id, role, email, expires_at, created_at, used_by FROM tenant_invites \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list invites: {e}");
        ApiError::internal("internal error")
    })?;

    let invites: Vec<InviteResponse> = rows.into_iter().map(|(id, role, email, expires_at, created_at, used_by)| {
        InviteResponse {
            id,
            role,
            email,
            expires_at,
            created_at,
            used: used_by.is_some(),
        }
    }).collect();

    Ok(Json(TotalPage::new(invites, limit, offset, total)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/tenants/{slug}/invites/{id}",
    tag = "Invites",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = Uuid, Path, description = "Invite ID"),
    ),
    responses(
        (status = 200, description = "Invite revoked", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Invite not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn revoke_invite(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    let (tenant_id, _) = crate::routes::admin_auth::resolve_tenant_slug(&state.db, &slug).await?;

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("revoke invite TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

    let result = sqlx::query("DELETE FROM tenant_invites WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("revoke invite: {e}");
            ApiError::internal("internal error")
        })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("invite not found", ApiErrorCode::InviteNotFound));
    }

    Ok(Json(ActionResponse::ok()))
}

// ---------------------------------------------------------------------------
// Tenant admins list (super-admin only)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/tenants/{slug}/admins",
    tag = "Tenants",
    params(("slug" = String, Path, description = "Tenant slug"), PageQuery),
    responses(
        (status = 200, description = "Paginated list of tenant admin accounts", body = TotalPage<AdminAccountResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Tenant not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub(crate) async fn list_tenant_admins(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<AdminAccountResponse>>, ApiError> {
    let (tenant_id, _) = crate::routes::admin_auth::resolve_tenant_slug(&state.db, &slug).await?;

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("list tenant admins TenantConn: {e}");
            ApiError::internal("internal error")
        })?;

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
        tracing::error!("list tenant admins: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

// ---------------------------------------------------------------------------
// Public invite endpoints (no auth required)
// ---------------------------------------------------------------------------

/// Get invite info (minimal, no secrets). Same response for invalid tokens.
#[utoipa::path(
    get,
    path = "/api/v1/invites/{token}",
    tag = "Invites",
    params(("token" = String, Path, description = "Invite token")),
    responses(
        (status = 200, description = "Invite info (valid or invalid)", body = InviteInfoResponse),
    ),
)]
pub(crate) async fn get_invite_info(
    State(state): State<Arc<AdminState>>,
    Path(token): Path<String>,
) -> Json<InviteInfoResponse> {
    let token_hash = hash_token(&token);

    // Two-step lookup to work around RLS on tenant_invites:
    // 1. Find tenant_id from token_hash using a raw connection with explicit SET
    // 2. Use tenants (no RLS) to get the name/slug
    #[derive(sqlx::FromRow)]
    struct InviteInfoRow {
        tenant_name: String,
        tenant_slug: String,
        role: String,
        email: Option<String>,
        expires_at: chrono::DateTime<Utc>,
        used_by: Option<Uuid>,
    }

    // The invite names its tenant by its token alone (`resolve_invite`: the
    // hash is unique across tenants); it is then read under that tenant's scope.
    let tenants: Vec<(Uuid,)> = sqlx::query_as("SELECT t.id FROM tenants t WHERE t.id = (SELECT resolve_invite($1))")
        .bind(&token_hash)
        .fetch_all(state.db.global(Global::PreAuth))
        .await
        .unwrap_or_default();

    let mut row: Option<InviteInfoRow> = None;
    for (tid,) in &tenants {
        if let Ok(mut db) = TenantConn::acquire(&state.db, TenantId::from_row(*tid)).await
            && let Ok(Some(r)) = sqlx::query_as::<_, InviteInfoRow>(
                "SELECT t.name AS tenant_name, t.slug AS tenant_slug, i.role, i.email, i.expires_at, i.used_by \
                 FROM tenant_invites i JOIN tenants t ON t.id = i.tenant_id \
                 WHERE i.token_hash = $1",
            )
            .bind(&token_hash)
            .fetch_optional(db.conn())
            .await
        {
            row = Some(r);
            break;
        }
    }

    match row {
        Some(r) if r.used_by.is_none() && r.expires_at > Utc::now() => {
            Json(InviteInfoResponse {
                valid: true,
                tenant_name: Some(r.tenant_name),
                tenant_slug: Some(r.tenant_slug),
                role: Some(r.role),
                email: r.email,
            })
        }
        _ => Json(InviteInfoResponse {
            valid: false,
            tenant_name: None,
            tenant_slug: None,
            role: None,
            email: None,
        }),
    }
}

/// Accept an invite: create admin account atomically.
#[utoipa::path(
    post,
    path = "/api/v1/invites/{token}/accept",
    tag = "Invites",
    params(("token" = String, Path, description = "Invite token")),
    request_body = AcceptInviteRequest,
    responses(
        (status = 201, description = "Invite accepted, admin account created", body = AcceptInviteResponse),
        (status = 400, description = "Bad request (email/password validation)", body = ApiErrorResponse),
        (status = 409, description = "Invite invalid, expired, or already used", body = ApiErrorResponse),
        (status = 429, description = "Too many attempts", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub(crate) async fn accept_invite(
    State(state): State<Arc<AdminState>>,
    Path(token): Path<String>,
    Json(mut req): Json<AcceptInviteRequest>,
) -> Result<(StatusCode, Json<AcceptInviteResponse>), ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = super::normalize_email(&req.email);
    super::require_address(&req.email)?;
    let rate_key = format!("invite:{token}");
    if state.invite_rate_limiter.check_rate_limit(&rate_key) {
        return Err(ApiError::too_many_requests("too many attempts — try again later"));
    }

    if req.email.is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request("email and password are required"));
    }

    if req.password.len() < 8 {
        return Err(ApiError::bad_request("password must be at least 8 characters")
            .code(ApiErrorCode::PasswordTooShort));
    }

    let token_hash = hash_token(&token);

    // The invite's tenant, from its token alone (`resolve_invite`).
    let tenants: Vec<(Uuid,)> =
        sqlx::query_as("SELECT t.id FROM tenants t WHERE t.is_active AND t.id = (SELECT resolve_invite($1))")
        .bind(&token_hash)
        .fetch_all(state.db.global(Global::PreAuth))
        .await
        .map_err(|e| {
            tracing::error!("accept invite tenant list: {e}");
            ApiError::internal("internal error")
        })?;

    let mut invite_row: Option<(Uuid, Uuid, String, Option<String>)> = None;
    for (tid,) in &tenants {
        let Ok(mut db) = TenantConn::acquire(&state.db, TenantId::from_row(*tid)).await else {
            continue;
        };
        match sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
            "SELECT id, tenant_id, role, email FROM tenant_invites \
             WHERE token_hash = $1 AND used_by IS NULL AND expires_at > NOW()",
        )
        .bind(&token_hash)
        .fetch_optional(db.conn())
        .await
        {
            Ok(Some(r)) => {
                invite_row = Some(r);
                break;
            }
            Ok(None) => continue,
            Err(_) => continue,
        }
    }

    let Some((invite_id, tenant_id, role, invite_email)) = invite_row else {
        return Err(ApiError::conflict("invite is invalid, expired, or already used", ApiErrorCode::InviteUnusable));
    };

    // If invite has an email restriction, verify it matches — exactly, on the
    // normalized forms: a Unicode lower-casing would fold a look-alike
    // (KELVIN SIGN to `k`) onto the address the invite names.
    if let Some(expected_email) = &invite_email
        && super::normalize_email(expected_email) != req.email
    {
        return Err(ApiError::bad_request("email does not match the invite")
            .code(ApiErrorCode::InviteEmailMismatch));
    }

    let password_hash = hash_password(&req.password).map_err(|e| {
        tracing::error!("accept invite password hash: {e}");
        ApiError::internal("internal error")
    })?;

    // One tenant-scoped transaction for atomic invite claim + account creation:
    // concurrent accepts of the same invite cannot leave an orphaned account.
    let mut tx = state.db.begin_tenant(TenantId::from_row(tenant_id)).await.map_err(|e| {
        tracing::error!("accept invite begin tx: {e}");
        ApiError::internal("internal error")
    })?;

    // Step 1: Atomically claim the invite (SELECT FOR UPDATE + UPDATE in one shot).
    let claimed = sqlx::query_as::<_, (Uuid,)>(
        "UPDATE tenant_invites SET used_at = NOW() \
         WHERE id = $1 AND used_by IS NULL AND expires_at > NOW() \
         RETURNING id",
    )
    .bind(invite_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("accept invite claim: {e}");
        ApiError::internal("internal error")
    })?;

    if claimed.is_none() {
        return Err(ApiError::conflict("invite was already claimed", ApiErrorCode::InviteAlreadyUsed));
    }

    // Step 2: Create admin account inside the same transaction.
    let account = sqlx::query_as::<_, AdminAccountResponse>(
        "INSERT INTO admin_accounts (email, password_hash, role, auth_source, tenant_id, last_login) \
         VALUES ($1, $2, $3, 'local', $4, NOW()) \
         RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
    )
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&role)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("an account with this email already exists", ApiErrorCode::AccountEmailTaken)
        } else {
            tracing::error!("accept invite create account: {e}");
            ApiError::internal("internal error")
        }
    })?;

    // Step 3: Link the invite to the account.
    sqlx::query("UPDATE tenant_invites SET used_by = $1 WHERE id = $2")
        .bind(account.id)
        .bind(invite_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("accept invite link: {e}");
            ApiError::internal("internal error")
        })?;

    // Commit — all three steps succeed or none do.
    tx.commit().await.map_err(|e| {
        tracing::error!("accept invite commit: {e}");
        ApiError::internal("internal error")
    })?;

    // Generate JWT for the new admin.
    let ring = super::admin_auth::keyring()
        .ok_or_else(crate::routes::no_signing_key)?;
    let token = super::admin_auth::generate_jwt(
        &ring,
        &account.id,
        &account.email,
        &account.role,
        &tenant_id.to_string(),
        false,
    )?;

    // The tenant slug lets the frontend scope the session cookie to /t/<slug>.
    let tenant_slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_one(state.db.global(Global::TenantRegistry))
        .await
        .map_err(|e| {
            tracing::error!("accept invite slug lookup: {e}");
            ApiError::internal("internal error")
        })?;

    tracing::info!(email = %req.email, tenant_id = %tenant_id, "invite accepted, admin account created");

    Ok((
        StatusCode::CREATED,
        Json(AcceptInviteResponse {
            token,
            user: account,
            tenant_slug,
        }),
    ))
}

#[derive(Serialize, ToSchema)]
pub struct AcceptInviteResponse {
    pub token: String,
    pub user: super::admin_auth::AdminAccountResponse,
    pub tenant_slug: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
