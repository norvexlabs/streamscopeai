//! Portal **workspace-manager** surface.
//!
//! A workspace `manager` (the elevated `workspace_members.role`) operates on the
//! members of the workspaces they manage — **always as themselves**, never by
//! impersonation. They can see the roster + per-member usage, and mint / revoke
//! a member's key in that workspace. Every mutation is audited with the manager
//! as the actor and the member as `portal_audit.target_user_id`.
//!
//! Hard boundaries (NOT a manager's to do — admin-only or member-only):
//! - membership changes (add/remove members, role changes) — admin-only;
//! - per-user MCP OAuth connect/authorize for a member — only the member, since
//!   it is them authenticating to a third-party IdP with their own credential.
//!
//! Enforcement is re-checked per request via [`verify_workspace_manager`] (no
//! session caching), so a role/membership change takes effect immediately.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_core::auth::virtual_key::{generate_forward_key, generate_virtual_key, hash_key};

use crate::agent::AGENT_EMAIL;
// A manager op's target must be on this workspace's roster (404 otherwise).
use crate::routes::workspaces::require_member;

use super::portal::{CreatePortalKeyResponse, PortalKeyInfo, StatsQuery};
use super::portal_auth::PortalUser;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::TenantConn;
use crate::middleware::PortalAuditTarget;
use crate::AdminState;

// ---------------------------------------------------------------------------
// Manager gate
// ---------------------------------------------------------------------------

/// Require the caller to be a `manager` of `workspace_id`. Re-evaluated per
/// request: `manager` → Ok; a `member` → 403 `WorkspaceManagerRequired`; a
/// non-member → 403 `WorkspaceMembershipRequired`.
pub(crate) async fn verify_workspace_manager(
    db: &mut TenantConn,
    user: &PortalUser,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    // A portal automation (`ak-`) key is confined to one workspace — reject any
    // attempt to act on a different one, regardless of what other workspaces the
    // owning service account may manage. A human session leaves this `None` and
    // is checked purely on its membership role below.
    if let Some(bound) = user.key_workspace_id
        && bound != workspace_id
    {
        return Err(ApiError::forbidden("this key is scoped to a different workspace")
            .code(ApiErrorCode::WorkspaceManagerRequired));
    }
    let role = crate::routes::workspaces::member_role(db, workspace_id, user.user_id).await?;
    match role.as_deref() {
        Some("manager") => Ok(()),
        Some(_) => Err(ApiError::forbidden("you are not a manager of this workspace")
            .code(ApiErrorCode::WorkspaceManagerRequired)),
        None => Err(ApiError::forbidden("you are not a member of this workspace")
            .code(ApiErrorCode::WorkspaceMembershipRequired)),
    }
}

/// Reject an `ak-` portal key acting on a workspace other than the one it is
/// bound to. A human session (`key_workspace_id == None`) always passes — it is
/// gated purely on its memberships. This is the confinement guard for the
/// self-service portal routes that take an explicit `workspace_id` but are NOT
/// manager-gated; routes that *enumerate* the caller's resources confine instead
/// by filtering each query on `key_workspace_id` (the `($N IS NULL OR …)` idiom).
pub(crate) fn confine_to_key_workspace(
    user: &PortalUser,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    if let Some(bound) = user.key_workspace_id
        && bound != workspace_id
    {
        return Err(ApiError::forbidden("this key is scoped to a different workspace")
            .code(ApiErrorCode::WorkspaceManagerRequired));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /workspaces/{id}/members — roster (manager only)
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceMemberInfo {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    /// The member's non-revoked, non-expired keys **in this workspace**.
    pub active_keys: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/members",
    tag = "Portal",
    operation_id = "portal_manager_list_members",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Workspace roster", body = OffsetPage<WorkspaceMemberInfo>),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_members(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceMemberInfo>>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, WorkspaceMemberInfo>(
        r#"SELECT u.id AS user_id, u.email, u.display_name, m.role,
                  COALESCE(COUNT(k.id) FILTER (
                      WHERE k.revoked_at IS NULL
                        AND (k.expires_at IS NULL OR k.expires_at > NOW())
                  ), 0)::bigint AS active_keys
           FROM workspace_members m
           JOIN users u ON u.id = m.user_id
           LEFT JOIN api_keys k ON k.user_id = m.user_id AND k.workspace_id = m.workspace_id
           WHERE m.workspace_id = $1 AND u.email <> $4
           GROUP BY u.tenant_id, u.id, u.email, u.display_name, m.role
           ORDER BY u.email
           LIMIT $2 OFFSET $3"#,
    )
    .bind(workspace_id)
    .bind(limit + 1)
    .bind(offset)
    .bind(AGENT_EMAIL)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("manager list members: {e}");
        ApiError::internal("internal error")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

// ---------------------------------------------------------------------------
// GET /workspaces/{id}/members/{uid}/keys — a member's keys here (manager only)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/keys",
    tag = "Portal",
    operation_id = "portal_manager_list_member_keys",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
        PageQuery,
    ),
    responses(
        (status = 200, description = "The member's keys in this workspace", body = OffsetPage<PortalKeyInfo>),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "User is not a member of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_member_keys(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<PortalKeyInfo>>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_member(&mut db, workspace_id, member_id).await?;
    let (limit, offset) = page.resolve();
    let mut rows = sqlx::query_as::<_, PortalKeyInfo>(
        r#"SELECT k.id, k.name, k.key_prefix, k.workspace_id,
                  w.name AS workspace_name, k.forward_auth,
                  k.created_at, k.expires_at, k.revoked_at,
                  k.daily_budget, k.monthly_budget, k.budget_mode, k.qos_class_id
           FROM api_keys k
           JOIN workspaces w ON w.id = k.workspace_id
           WHERE k.user_id = $1 AND k.workspace_id = $2
           ORDER BY k.created_at DESC
           LIMIT $3 OFFSET $4"#,
    )
    .bind(member_id)
    .bind(workspace_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("manager list member keys: {e}");
        ApiError::internal("internal error")
    })?;
    // Fill current per-key spend, in the tenant's accounting currency, so a
    // budgeted key shows spend-vs-cap.
    let tenant = db.tenant_uuid();
    let spend = crate::routes::analytics::current_budget_spend(db.conn(), tenant, "key")
        .await
        .unwrap_or_default();
    for r in &mut rows {
        if let Some((daily, monthly)) = spend.get(&r.id) {
            r.daily_spent = *daily;
            r.monthly_spent = *monthly;
        }
    }
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

// ---------------------------------------------------------------------------
// GET /workspaces/{id}/stats — per-member usage in this workspace (manager only)
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct WorkspaceMemberUsage {
    pub user_id: Uuid,
    pub email: String,
    pub requests: i64,
    pub tokens: i64,
    /// What the member spent in this workspace, and in which currency. `null`
    /// when the window straddles a change of the tenant's accounting currency.
    pub spend: Option<super::SpendTotal>,
}

#[derive(Serialize, ToSchema)]
pub struct WorkspaceTeamStats {
    pub members: Vec<WorkspaceMemberUsage>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/stats",
    tag = "Portal",
    operation_id = "portal_manager_stats",
    params(("id" = Uuid, Path, description = "Workspace id"), StatsQuery),
    responses(
        (status = 200, description = "Per-member usage for this workspace", body = WorkspaceTeamStats),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn member_stats(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<WorkspaceTeamStats>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let (start_ts, end_ts) = query.time_window().resolve(30)?;

    // Usage counts each member's LLM requests stamped with **this workspace**
    // only (the population of every portal usage figure) — a member
    // who also belongs to other workspaces is never cross-counted here. The
    // internal agent account is left out by its email, should it ever be made a
    // member of a team's workspace.
    let rows = crate::audit_store::usage::workspace_member_usage(db.conn(), workspace_id, (start_ts, end_ts), AGENT_EMAIL)
        .await
        .map_err(|e| {
            tracing::error!("manager member stats: {e}");
            ApiError::internal("internal error")
        })?;
    // A member with no traffic reports a zero, in the tenant's current
    // accounting currency — read only when some member needs it.
    let fallback = if rows.iter().any(|r| r.usage.currency_count == 0) {
        super::pricing::accounting_currency(db.conn()).await
    } else {
        streamscope_core::pricing::Currency::USD
    };
    let members = rows
        .into_iter()
        .map(|r| WorkspaceMemberUsage {
            user_id: r.user_id,
            email: r.email,
            requests: r.usage.requests,
            tokens: r.usage.tokens,
            spend: super::spend_total(r.usage.currency_count, r.usage.currency, r.usage.amount, fallback),
        })
        .collect();
    Ok(Json(WorkspaceTeamStats { members }))
}

// ---------------------------------------------------------------------------
// POST /workspaces/{id}/members/{uid}/keys — mint a key for a member
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct MintForMemberRequest {
    pub name: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When true, mint a `vk-` BYOK (forward-auth) key.
    pub forward_auth: Option<bool>,
    /// Optional BYOK downstream binding for a `vk-` key (LLM pass-through). Must
    /// be a `byok` downstream granted to this workspace; ignored for a standard
    /// key. Mirrors the self-service key path.
    #[serde(default)]
    pub downstream_provider_id: Option<Uuid>,
    /// Optional per-key budget ceiling (omitted ⇒ no per-key cap). A manager may
    /// cap the keys they provision for a member.
    #[serde(default)]
    pub budget: Option<crate::routes::keys::KeyBudget>,
    /// The key's priority class under load. Omitted takes the workspace's own
    /// default for a person's tool; a class more important than the workspace's
    /// is refused — a manager cannot hand out what the workspace does not have.
    #[serde(default)]
    pub qos_class_id: Option<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/keys",
    tag = "Portal",
    operation_id = "portal_manager_mint_member_key",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
    ),
    request_body = MintForMemberRequest,
    responses(
        (status = 201, description = "Key minted for the member (plaintext once)", body = CreatePortalKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "User is not a member of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mint_member_key(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(audit_target): Extension<PortalAuditTarget>,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<MintForMemberRequest>,
) -> Result<(StatusCode, Json<CreatePortalKeyResponse>), ApiError> {
    // Gate first: an unauthorized caller always gets a 403, never a 400 that
    // would confirm the route shape.
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_member(&mut db, workspace_id, member_id).await?;
    // Audit this as a manager-on-member action regardless of outcome below.
    audit_target.set(member_id);

    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("key name is required"));
    }

    let id = Uuid::new_v4();
    let forward_auth = body.forward_auth.unwrap_or(false);

    // BYOK binding (optional): a forward-auth (`vk-`) key MAY bind to one BYOK
    // downstream for LLM pass-through — it must be a `byok` downstream granted to
    // this workspace (mirror the self-service key path). Discarded for a standard
    // key so a picked provider can never silently no-op.
    let bound_downstream_id = if forward_auth {
        body.downstream_provider_id
    } else {
        None
    };
    if let Some(dp) = bound_downstream_id {
        let ok: bool = crate::routes::byok_downstream_bindable(db.conn(), dp, workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("manager mint member key validate byok downstream: {e}");
            ApiError::internal("internal error")
        })?;
        if !ok {
            return Err(crate::routes::byok_binding_refused());
        }
    }

    let plaintext_key = if forward_auth {
        generate_forward_key()
    } else {
        generate_virtual_key()
    };
    let key_hash = hash_key(&plaintext_key);
    let key_prefix = &plaintext_key[..plaintext_key.len().min(12)];
    let now = chrono::Utc::now();

    // The key is OWNED by the member (`user_id`); `minted_by_user_id` records the
    // manager who provisioned it. Workspace-bound, so it reaches nothing the
    // member couldn't already reach in this workspace — no escalation.
    let (daily_budget, monthly_budget, budget_mode) = match &body.budget {
        Some(b) => (
            b.daily_budget,
            b.monthly_budget,
            crate::routes::workspaces::norm_budget_mode(&b.budget_mode),
        ),
        None => (None, None, crate::routes::workspaces::default_budget_mode()),
    };

    // Minted for a member to use on their own machine: the interactive default,
    // clamped to the workspace. A manager cannot hand out a better class than
    // the workspace has — that is a tenant admin's decision.
    let qos_class_id = match body.qos_class_id {
        Some(_) => {
            crate::routes::qos_classes::resolve_key_class(
                db.conn(),
                workspace_id,
                body.qos_class_id,
                crate::routes::qos_classes::ClassAuthority::Delegated,
            )
            .await?
            .0
        }
        None => {
            crate::routes::qos_classes::default_class_for_mint(
                db.conn(),
                workspace_id,
                crate::routes::qos_classes::MintPrincipal::Person,
            )
            .await?
        }
    };

    sqlx::query(
        r#"INSERT INTO api_keys
               (id, tenant_id, workspace_id, user_id, minted_by_user_id,
                key_hash, key_prefix, name, forward_auth, downstream_provider_id, expires_at, created_at,
                daily_budget, monthly_budget, budget_mode, qos_class_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"#,
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .bind(workspace_id)
    .bind(member_id)
    .bind(user.user_id)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(&body.name)
    .bind(forward_auth)
    .bind(bound_downstream_id)
    .bind(body.expires_at)
    .bind(now)
    .bind(daily_budget)
    .bind(monthly_budget)
    .bind(budget_mode)
    .bind(qos_class_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        if crate::routes::bound_passthrough_gone(&e) {
            return crate::routes::byok_binding_refused();
        }
        tracing::error!("manager mint member key: {e}");
        ApiError::internal("internal error")
    })?;

    tracing::info!(
        manager_id = %user.user_id, member_id = %member_id, workspace_id = %workspace_id,
        "manager minted key for member"
    );

    // Every gateway key is exercised against the proxy origin — a standard key on
    // `/v1/...`, a BYOK key on `/fwd/{key}/v1/...`. Carry the configured public
    // URL so the reveal-card curl never falls back to the console origin.
    let proxy_base_url = crate::tenant_public_url::try_resolve_public_url(
        &state.db,
        db.tenant_uuid(),
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePortalKeyResponse {
            id,
            key: plaintext_key,
            name: Some(body.name),
            created_at: now,
            proxy_base_url,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /workspaces/{id}/members/{uid}/keys/{key_id}/actions/revoke
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/keys/{key_id}/actions/revoke",
    tag = "Portal",
    operation_id = "portal_manager_revoke_member_key",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
        ("key_id" = Uuid, Path, description = "API key id"),
    ),
    responses(
        (status = 200, description = "Member key revoked", body = ActionResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Key not found in this workspace for that member", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_member_key(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(audit_target): Extension<PortalAuditTarget>,
    Path((workspace_id, member_id, key_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    audit_target.set(member_id);

    // Scope the revoke to a key the member actually holds in THIS workspace — a
    // manager cannot touch keys outside the workspace they manage.
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() \
         WHERE id = $1 AND user_id = $2 AND workspace_id = $3 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .bind(member_id)
    .bind(workspace_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("manager revoke member key: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }

    tracing::info!(
        manager_id = %user.user_id, member_id = %member_id, workspace_id = %workspace_id,
        "manager revoked key for member"
    );
    Ok(Json(ActionResponse::ok().with_message("Member key revoked.")))
}

// ---------------------------------------------------------------------------
// PUT /workspaces/{id}/members/{uid}/keys/{key_id}/budget
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct SetMemberKeyBudgetRequest {
    /// New per-key budget. Null caps clear the cap; omitted budget clears it too.
    #[serde(default)]
    pub budget: Option<crate::routes::keys::KeyBudget>,
}

#[utoipa::path(
    put,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/keys/{key_id}/budget",
    tag = "Portal",
    operation_id = "portal_manager_set_member_key_budget",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
        ("key_id" = Uuid, Path, description = "API key id"),
    ),
    request_body = SetMemberKeyBudgetRequest,
    responses(
        (status = 200, description = "Member key budget updated", body = ActionResponse),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "Key not found in this workspace for that member", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_member_key_budget(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(audit_target): Extension<PortalAuditTarget>,
    Path((workspace_id, member_id, key_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(body): Json<SetMemberKeyBudgetRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_member(&mut db, workspace_id, member_id).await?;
    audit_target.set(member_id);

    let (daily, monthly, mode) = match &body.budget {
        Some(b) => (
            b.daily_budget,
            b.monthly_budget,
            crate::routes::workspaces::norm_budget_mode(&b.budget_mode),
        ),
        None => (None, None, crate::routes::workspaces::default_budget_mode()),
    };

    // Scope the update to a key the member holds in THIS workspace — a manager
    // cannot touch keys outside the workspace they manage.
    let result = sqlx::query(
        "UPDATE api_keys SET daily_budget = $4, monthly_budget = $5, budget_mode = $6 \
         WHERE id = $1 AND user_id = $2 AND workspace_id = $3",
    )
    .bind(key_id)
    .bind(member_id)
    .bind(workspace_id)
    .bind(daily)
    .bind(monthly)
    .bind(mode)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("manager set member key budget: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }

    Ok(Json(ActionResponse::ok().with_message("Member key budget updated.")))
}

// ---------------------------------------------------------------------------
// Member limits — read the workspace's limits, edit member EXCEPTIONS.
//
// A manager may raise or lower one member's limit inside the pool the
// administrator set; the pool and the member default stay admin-only. A manager
// never edits their OWN exception (separation of duties) — refused here, not
// only hidden in the UI.
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/limits",
    tag = "Portal",
    operation_id = "portal_manager_limits_overview",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "The workspace pool, inherited default and member default (read-only here)", body = crate::routes::workspaces::WorkspaceLimitsOverview),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn limits_overview(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
) -> Result<Json<crate::routes::workspaces::WorkspaceLimitsOverview>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let role = crate::routes::workspaces::workspace_role(&mut db, workspace_id).await?;
    Ok(Json(crate::routes::workspaces::limits_overview(&mut db, workspace_id, role).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/member-exceptions",
    tag = "Portal",
    operation_id = "portal_manager_list_member_exceptions",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Member exceptions in this workspace", body = OffsetPage<crate::routes::workspaces::UserRateLimitOverride>),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_member_exceptions(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<crate::routes::workspaces::UserRateLimitOverride>>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    let mut listed = crate::routes::workspaces::list_member_exceptions(&mut db, workspace_id, page).await?;
    // An administrator's address belongs to the console, not the portal: the
    // manager sees THAT an administrator set an exception, not who.
    for o in &mut listed.items {
        if o.set_via.as_deref() == Some("admin") {
            o.set_by_email = None;
        }
    }
    Ok(Json(listed))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/limits",
    tag = "Portal",
    operation_id = "portal_manager_member_limits",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
    ),
    responses(
        (status = 200, description = "Every limit that applies to this member, widest first", body = crate::limits::EffectiveLimitStack),
        (status = 403, description = "Not a manager of this workspace", body = ApiErrorResponse),
        (status = 404, description = "User is not a member of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn member_limits(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<crate::limits::EffectiveLimitStack>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    require_member(&mut db, workspace_id, member_id).await?;
    let tenant_id = db.tenant_uuid();
    crate::limits::effective_stack(db.conn(), tenant_id, workspace_id, member_id, crate::limits::StackViewer::Manager)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("manager member limits: {e}");
            ApiError::internal("internal error")
        })
}

/// A manager may change a plain member's exception only: their own, and any
/// other manager's, is an administrator's — or two managers could each raise
/// the other's, the outcome the self-edit refusal exists to prevent.
async fn refuse_manager_target(
    db: &mut TenantConn,
    user: &PortalUser,
    workspace_id: Uuid,
    member_id: Uuid,
) -> Result<(), ApiError> {
    if user.user_id == member_id {
        return Err(ApiError::forbidden("your own limit can only be changed by an administrator")
            .code(ApiErrorCode::MemberLimitSelfEditForbidden));
    }
    let role = crate::routes::workspaces::member_role(db, workspace_id, member_id).await?;
    if role.as_deref() == Some("manager") {
        return Err(ApiError::forbidden("a manager's limit can only be changed by an administrator")
            .code(ApiErrorCode::MemberLimitManagerEditForbidden));
    }
    Ok(())
}

#[utoipa::path(
    put,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/limits",
    tag = "Portal",
    operation_id = "portal_manager_set_member_exception",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
    ),
    request_body = crate::routes::workspaces::PutRateLimitOverrideRequest,
    responses(
        (status = 200, description = "Member exception set", body = crate::routes::workspaces::UserRateLimitOverride),
        (status = 400, description = "Invalid value", body = ApiErrorResponse),
        (status = 403, description = "Not a manager of this workspace, or the caller's own exception", body = ApiErrorResponse),
        (status = 404, description = "User is not a member of this workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_member_exception(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(audit_target): Extension<PortalAuditTarget>,
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<crate::routes::workspaces::PutRateLimitOverrideRequest>,
) -> Result<Json<crate::routes::workspaces::UserRateLimitOverride>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    refuse_manager_target(&mut db, &user, workspace_id, member_id).await?;
    audit_target.set(member_id);
    let setter = crate::routes::workspaces::ExceptionSetter { via: "manager", email: Some(user.email.clone()) };
    let (before, row) =
        crate::routes::workspaces::upsert_member_exception(&mut db, workspace_id, member_id, &req, setter).await?;
    audit_sink.record(before.as_ref(), Some(&row));
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/portal/workspaces/{id}/members/{uid}/limits",
    tag = "Portal",
    operation_id = "portal_manager_remove_member_exception",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("uid" = Uuid, Path, description = "Member user id"),
    ),
    responses(
        (status = 200, description = "Member exception removed — the member is back on the workspace default", body = ActionResponse),
        (status = 403, description = "Not a manager of this workspace, or the caller's own exception", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_member_exception(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(audit_target): Extension<PortalAuditTarget>,
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    Path((workspace_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    verify_workspace_manager(&mut db, &user, workspace_id).await?;
    refuse_manager_target(&mut db, &user, workspace_id, member_id).await?;
    audit_target.set(member_id);
    let removed = crate::routes::workspaces::delete_member_exception(&mut db, workspace_id, member_id).await?;
    audit_sink.record(removed.as_ref(), None::<&crate::routes::workspaces::UserRateLimitOverride>);
    Ok(Json(ActionResponse::ok().with_message("Member exception removed.")))
}
