//! Portal **workspace-manager** automation surface.
//!
//! A workspace manager provisions long-lived `ak-` automation keys for the
//! workspace they manage — credentials that survive employee offboarding because
//! they hang off a non-human **service account**, not a person. Each key
//! authenticates to the PORTAL control plane (`/api/v1/portal/*`) AS that service
//! account and carries exactly **one** workspace's manager authority: the owning
//! account is a `manager` member of the workspace and the key is bound to it, so
//! [`verify_workspace_manager`](super::portal_manager::verify_workspace_manager)
//! confines it there and nowhere else.
//!
//! Principal-first, mirroring the admin Service Accounts surface: the automation
//! account is the resource, keys are a sub-resource. The accounts created here are
//! ordinary service accounts (`auth_source='service'`) — they appear on the admin
//! Service Accounts page too — but a manager can only ever see/manage the ones
//! that are managers of a workspace they manage.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_core::auth::virtual_key::{generate_admin_key, hash_key};

use super::portal_auth::PortalUser;
use super::portal_manager::verify_workspace_manager;
use super::service_accounts::ServiceAccountResponse;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::agent::AGENT_EMAIL;
use crate::db::tenant::TenantConn;
use crate::service_account::{create_service_account, ensure_workspace_membership_role, slugify};
use crate::AdminState;

/// Confirm `sa_id` is a service account that is a member of `workspace_id` — the
/// manager may only act on automation accounts scoped to the workspace they
/// manage. 404 otherwise.
async fn require_sa_in_workspace(
    db: &mut TenantConn,
    workspace_id: Uuid,
    sa_id: Uuid,
) -> Result<(), ApiError> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users u \
         JOIN workspace_members m ON m.user_id = u.id \
         WHERE u.id = $1 AND u.auth_source = 'service' AND m.workspace_id = $2)",
    )
    .bind(sa_id)
    .bind(workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("require sa in workspace: {e}");
        ApiError::internal("internal error")
    })?;
    if !ok {
        return Err(ApiError::not_found("automation account not found in this workspace", ApiErrorCode::UserNotFound));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// List / create automation accounts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct WsAutomationAccount {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    /// Live (non-revoked, non-expired) portal keys this account holds in THIS
    /// workspace.
    pub active_keys: i64,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts",
    tag = "Portal",
    operation_id = "portal_list_automation_accounts",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Automation accounts managing this workspace", body = OffsetPage<WsAutomationAccount>),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_automation_accounts(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WsAutomationAccount>>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, WsAutomationAccount>(
        "SELECT u.id, u.email, u.display_name, u.is_active, u.created_at, \
                COALESCE(COUNT(k.id) FILTER (WHERE k.revoked_at IS NULL \
                    AND (k.expires_at IS NULL OR k.expires_at > NOW())), 0)::bigint AS active_keys, \
                MAX(k.last_used_at) AS last_used_at \
         FROM users u \
         JOIN workspace_members m ON m.user_id = u.id AND m.workspace_id = $1 AND m.role = 'manager' \
         LEFT JOIN automation_keys k ON k.service_account_id = u.id \
             AND k.plane = 'portal' AND k.workspace_id = $1 \
         WHERE u.auth_source = 'service' AND u.email <> $4 \
         GROUP BY u.tenant_id, u.id, u.email, u.display_name, u.is_active, u.created_at \
         ORDER BY u.created_at DESC \
         LIMIT $2 OFFSET $3",
    )
    .bind(workspace_id)
    .bind(limit + 1)
    .bind(offset)
    .bind(AGENT_EMAIL)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list automation accounts: {e}");
        ApiError::internal("failed to list automation accounts")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateWsAutomationAccountRequest {
    /// Human-facing display name (e.g. "CI bot").
    pub name: String,
    /// Stable login-less identity. Auto-derived from the name + workspace when
    /// omitted. Must be unique within the tenant.
    #[serde(default)]
    pub email: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts",
    tag = "Portal",
    operation_id = "portal_create_automation_account",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = CreateWsAutomationAccountRequest,
    responses(
        (status = 201, description = "Automation account created (manager of this workspace)", body = ServiceAccountResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 409, description = "Email already taken", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_automation_account(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
    Json(req): Json<CreateWsAutomationAccountRequest>,
) -> Result<(StatusCode, Json<ServiceAccountResponse>), ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required").code(ApiErrorCode::ValidationFailed));
    }

    // Auto-derive a workspace-namespaced email when none is given, so a manager's
    // account can't collide with an unrelated tenant account of the same name.
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
            let ws_short = workspace_id.simple().to_string();
            format!("svc-{local}-{}@{slug}.service", &ws_short[..8])
        }
    };

    let taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND tenant_id = $2)")
            .bind(&email)
            .bind(db.tenant_uuid())
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("create automation account email check: {e}");
                ApiError::internal("failed to validate email")
            })?;
    if taken {
        return Err(ApiError::conflict("an account with that email already exists", ApiErrorCode::UserEmailTaken));
    }

    // Create the principal and make it a MANAGER of this workspace, atomically.
    let tenant_uuid = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create automation account begin tx: {e}");
        ApiError::internal("failed to create automation account")
    })?;
    let user_id = create_service_account(&mut tx, tenant_uuid, &email, &name)
        .await
        .map_err(|e| {
            // A concurrent create can pass the check above and lose here.
            if super::is_unique_violation(&e) {
                return ApiError::conflict("an account with that email already exists", ApiErrorCode::UserEmailTaken);
            }
            tracing::error!("create automation account: {e}");
            ApiError::internal("failed to create automation account")
        })?;
    ensure_workspace_membership_role(&mut tx, tenant_uuid, user_id, workspace_id, "manager")
        .await
        .map_err(|e| {
            tracing::error!("create automation account membership: {e}");
            ApiError::internal("failed to grant workspace authority")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("create automation account commit: {e}");
        ApiError::internal("failed to create automation account")
    })?;

    Ok((
        StatusCode::CREATED,
        Json(ServiceAccountResponse { id: user_id, email, name }),
    ))
}

// ---------------------------------------------------------------------------
// Automation keys (ak-, portal control plane)
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct WsAutomationKeyItem {
    pub id: Uuid,
    pub name: Option<String>,
    pub key_prefix: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys",
    tag = "Portal",
    operation_id = "portal_list_automation_keys",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("said" = Uuid, Path, description = "Automation account id"),
    ),
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("said" = Uuid, Path, description = "Automation account id"),
        PageQuery,
    ),
    responses(
        (status = 200, description = "The account's portal keys in this workspace", body = OffsetPage<WsAutomationKeyItem>),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Account not found in this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_automation_keys(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, sa_id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WsAutomationKeyItem>>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_sa_in_workspace(&mut db, workspace_id, sa_id).await?;
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, WsAutomationKeyItem>(
        "SELECT id, name, key_prefix, created_at, expires_at, revoked_at, last_used_at \
         FROM automation_keys \
         WHERE plane = 'portal' AND service_account_id = $1 AND workspace_id = $2 \
         ORDER BY created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(sa_id)
    .bind(workspace_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list automation keys: {e}");
        ApiError::internal("failed to list keys")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Deserialize, ToSchema)]
pub struct MintWsAutomationKeyRequest {
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
pub struct MintWsAutomationKeyResponse {
    pub id: Uuid,
    /// The plaintext `ak-` key — returned ONCE, never again.
    pub key: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Portal `ak-` scripting origin (`api_public_url`) — the FQDN the
    /// admin-API is served on, which the reveal-once example targets. `None`
    /// when the API origin isn't configured (the UI then falls back to the
    /// console origin, correct for co-resident installs).
    pub api_base_url: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys",
    tag = "Portal",
    operation_id = "portal_mint_automation_key",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("said" = Uuid, Path, description = "Automation account id"),
    ),
    request_body = MintWsAutomationKeyRequest,
    responses(
        (status = 201, description = "Portal key minted (plaintext returned once)", body = MintWsAutomationKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Account not found in this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mint_automation_key(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, sa_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<MintWsAutomationKeyRequest>,
) -> Result<(StatusCode, Json<MintWsAutomationKeyResponse>), ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_sa_in_workspace(&mut db, workspace_id, sa_id).await?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("key name is required").code(ApiErrorCode::ValidationFailed));
    }

    let now = Utc::now();
    let key_id = Uuid::new_v4();
    let plaintext = generate_admin_key();
    let key_hash = hash_key(&plaintext);
    let key_prefix = &plaintext[..plaintext.len().min(12)];

    // Portal keys are CONTROL-plane only — never in the proxy config snapshot, so
    // no config-dirty mark.
    sqlx::query(
        "INSERT INTO automation_keys \
            (id, tenant_id, plane, workspace_id, service_account_id, key_hash, key_prefix, name, expires_at, created_at) \
         VALUES ($1, $2, 'portal', $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(key_id)
    .bind(db.tenant_uuid())
    .bind(workspace_id)
    .bind(sa_id)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(&name)
    .bind(req.expires_at)
    .bind(now)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("mint automation key: {e}");
        ApiError::internal("failed to mint key")
    })?;

    let api_base_url = crate::tenant_public_url::try_resolve_public_url(
        &state.db,
        db.tenant_uuid(),
        crate::tenant_public_url::PublicUrlKey::Api,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(MintWsAutomationKeyResponse {
            id: key_id,
            key: plaintext,
            name: Some(name),
            created_at: now,
            api_base_url,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys/{key_id}/actions/revoke",
    tag = "Portal",
    operation_id = "portal_revoke_automation_key",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("said" = Uuid, Path, description = "Automation account id"),
        ("key_id" = Uuid, Path, description = "Portal key id"),
    ),
    responses(
        (status = 200, description = "Key revoked (row retained for audit linkage)", body = ActionResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Key not found in this workspace for that account", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_automation_key(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, sa_id, key_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    // Scope the revoke to a key the account holds in THIS workspace — a manager
    // cannot touch keys outside the workspace they manage.
    let result = sqlx::query(
        "UPDATE automation_keys SET revoked_at = NOW() \
         WHERE id = $1 AND plane = 'portal' AND service_account_id = $2 \
           AND workspace_id = $3 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(sa_id)
    .bind(workspace_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("revoke automation key: {e}");
        ApiError::internal("failed to revoke key")
    })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }
    Ok(Json(ActionResponse::ok().with_message("Key revoked.")))
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/automation-accounts/{said}/actions/revoke",
    tag = "Portal",
    operation_id = "portal_revoke_automation_account",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("said" = Uuid, Path, description = "Automation account id"),
    ),
    responses(
        (status = 200, description = "Account removed from this workspace; its portal keys here revoked", body = ActionResponse),
        (status = 400, description = "Cannot revoke the built-in agent", body = ApiErrorResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Account not found in this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_automation_account(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, sa_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_sa_in_workspace(&mut db, workspace_id, sa_id).await?;

    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(sa_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("revoke automation account lookup: {e}");
            ApiError::internal("internal error")
        })?;
    if email.as_deref() == Some(AGENT_EMAIL) {
        return Err(ApiError::bad_request("the built-in agent cannot be revoked")
            .code(ApiErrorCode::ValidationFailed));
    }

    // Workspace-scoped retire: revoke the account's portal keys HERE and drop its
    // manager membership of THIS workspace — never touch the principal globally
    // (it may, in principle, be granted elsewhere by an admin). The key auth still
    // resolves but the manager gate then denies it, and its keys are revoked.
    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("revoke automation account begin tx: {e}");
        ApiError::internal("failed to revoke automation account")
    })?;
    let revoked = sqlx::query(
        "UPDATE automation_keys SET revoked_at = NOW() \
         WHERE plane = 'portal' AND service_account_id = $1 AND workspace_id = $2 \
           AND revoked_at IS NULL",
    )
    .bind(sa_id)
    .bind(workspace_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("revoke automation account revoke keys: {e}");
        ApiError::internal("failed to revoke keys")
    })?
    .rows_affected();
    // Ending the membership ends everything it carried in this workspace, the
    // same way an administrator's removal does.
    let (gateway_keys, _) =
        super::workspaces::remove_membership(&mut tx, tenant_id, workspace_id, sa_id).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("revoke automation account commit: {e}");
        ApiError::internal("failed to revoke automation account")
    })?;

    Ok(Json(ActionResponse::ok().with_message(format!(
        "Automation account removed from this workspace; {} key(s) revoked.",
        revoked + gateway_keys
    ))))
}
