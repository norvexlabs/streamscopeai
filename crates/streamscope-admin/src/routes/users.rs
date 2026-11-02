//! User CRUD, status management, usage tracking, and rate limit configuration.
//!
//! Service users (distinct from admin accounts) represent API consumers.
//! Each user has per-user rate limits (RPM, TPM) and budget caps (daily,
//! monthly). Users are assigned to groups which control downstream access.
//! Status can be active, suspended, or disabled. Usage stats are aggregated
//! from audit records.

use std::collections::HashMap;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::analytics::DEFAULT_USAGE_DAYS;
use super::key_lifecycle::{self, DeletionResponse, DryRunQuery};
use super::workspaces::WorkspaceRole;
use super::{
    ApiError, ApiErrorCode, ApiErrorResponse, PageQuery,
    SpendTotal, TotalPage, WindowWorkspacesQuery,
};
use crate::db::tenant::TenantConn;

#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// User email address (unique per tenant).
    pub email: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional password for portal login.
    pub password: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    /// New email address.
    pub email: Option<String>,
    /// New display name. Absent = unchanged; explicit `null` clears it (the
    /// `double_option` deserializer keeps the two distinguishable).
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub display_name: Option<Option<String>>,
    /// New password (empty string or null = no change).
    pub password: Option<String>,
    /// Activate/deactivate the user account. Folded from the former
    /// `PATCH /users/{id}/status` endpoint — present for partial updates.
    pub is_active: Option<bool>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub tenant_id: Uuid,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Workspaces this user belongs to, with their per-workspace role. Populated
    /// by the list endpoint (one batched query, not per-row); empty on the
    /// single-row create/update responses. Lets the unified Accounts view render
    /// the gateway side inline without an N+1 fetch. Not a DB column — skipped by
    /// `FromRow` and filled after the query.
    #[sqlx(skip)]
    #[serde(default)]
    pub workspaces: Vec<WorkspaceMembershipInfo>,
}

/// One workspace the user belongs to, with their role in it. Surfaced on the
/// user-detail endpoint so admins can see (and reason about) a user's
/// workspace footprint without a second round-trip.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct WorkspaceMembershipInfo {
    pub workspace_id: Uuid,
    pub workspace_name: String,
    /// The user's **membership** role in this workspace (`member`/`manager`),
    /// distinct from `workspace_role` below.
    pub role: String,
    /// The **workspace's** role — its `default`/`agent`/`inline`/`standard` axis.
    pub workspace_role: WorkspaceRole,
}

/// User detail = the user row plus the workspaces they're a member of.
#[derive(Serialize, ToSchema)]
pub struct UserDetailResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub tenant_id: Uuid,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub workspace_memberships: Vec<WorkspaceMembershipInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct UserUsageSummary {
    pub total_requests: i64,
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_cache_creation_tokens: i64,
    pub total_cache_read_tokens: i64,
    pub total_reasoning_tokens: i64,
    /// What this user spent over the window, and in which currency. `null`
    /// when the window straddles a change of the tenant's accounting currency
    /// — the rows are then in different denominations and no single figure
    /// states them.
    pub spend: Option<SpendTotal>,
    pub avg_latency_ms: f64,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users",
    tag = "Users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Email already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_user(
    mut db: TenantConn,
    Json(mut req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = super::normalize_email(&req.email);
    super::require_address(&req.email)?;
    if req.email.trim().is_empty() {
        return Err(ApiError::bad_request("email is required").code(ApiErrorCode::ValidationFailed));
    }

    let id = Uuid::new_v4();
    let tenant_id = db.tenant_uuid();
    let now = chrono::Utc::now();

    // Hash password if provided; otherwise inherit the one already set on a
    // sibling console admin row for this email. Granting gateway access to an
    // existing console identity rarely re-types the password (it is already set
    // on the console side), so without this inheritance the new user row lands a
    // NULL hash and portal login fails with "invalid credentials".
    let password_hash: Option<String> = match &req.password {
        Some(pw) if !pw.is_empty() => Some(
            super::admin_auth::hash_password(pw).map_err(|e| {
                tracing::error!("hash password: {e}");
                ApiError::internal("failed to hash password")
            })?,
        ),
        _ => super::admin_auth::existing_password_hash_for_email(db.conn(), tenant_id, &req.email).await?,
    };

    // A new user joins NO workspace automatically — membership is always an
    // explicit grant (admin adds them to a workspace, or OIDC group-sync does on
    // login), consistent with the portal auto-provision path. Until then the user
    // exists but can't mint a key (key issuance requires workspace membership).
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create user begin tx: {e}");
        ApiError::internal("failed to create user")
    })?;

    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, display_name, password_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&req.display_name)
    .bind(&password_hash)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            return ApiError::conflict("a user with this email already exists", ApiErrorCode::UserEmailTaken);
        }
        tracing::error!("create user: {e}");
        ApiError::internal("failed to create user")
    })?;

    // One identity, one password: propagate to a sibling console admin row if
    // one exists for this email (no-op otherwise).
    if let Some(hash) = &password_hash {
        super::admin_auth::sync_password_for_email(&mut tx, tenant_id, &req.email, hash).await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("create user commit: {e}");
        ApiError::internal("failed to create user")
    })?;


    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id,
            email: req.email,
            display_name: req.display_name,
            tenant_id,
            is_active: true,
            created_at: now,
            workspaces: Vec::new(),
        }),
    ))
}

/// Query for `GET /users` — pagination plus an optional case-insensitive
/// substring search over email / display name (drives the member picker).
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Case-insensitive substring on email or display name. Omit for all.
    pub q: Option<String>,
    /// `human` (default — accounts surfaces and the member picker never want
    /// service principals) | `service` | `all`.
    pub kind: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "Users",
    params(UserListQuery),
    responses(
        (status = 200, description = "Paginated list of users", body = TotalPage<UserResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_users(
    mut db: TenantConn,
    Query(query): Query<UserListQuery>,
) -> Result<Json<TotalPage<UserResponse>>, ApiError> {
    let (limit, offset) = PageQuery {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve();
    let tenant_id = db.tenant_uuid();
    // Trimmed search term as a NULL-tolerant ILIKE pattern: a NULL `$2`
    // matches every row.
    let pattern = crate::sql_pattern::search_pattern(query.q.as_deref());
    // Default to HUMANS: every existing consumer (Accounts table, workspace
    // member picker) wants people; service principals have their own surfaces.
    // NULL = no kind filter (`all`).
    let service_only: Option<bool> = match query.kind.as_deref() {
        Some("service") => Some(true),
        Some("all") => None,
        _ => Some(false),
    };

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users \
         WHERE tenant_id = $1 \
           AND ($2::text IS NULL OR email ILIKE $2 OR display_name ILIKE $2) \
           AND ($3::bool IS NULL OR (auth_source IS NOT DISTINCT FROM 'service') = $3)",
    )
    .bind(tenant_id)
    .bind(&pattern)
    .bind(service_only)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("count users: {e}");
        ApiError::internal("failed to list users")
    })?;

    let mut rows = sqlx::query_as::<_, UserResponse>(
        "SELECT id, email, display_name, tenant_id, is_active, created_at \
         FROM users \
         WHERE tenant_id = $1 \
           AND ($2::text IS NULL OR email ILIKE $2 OR display_name ILIKE $2) \
           AND ($5::bool IS NULL OR (auth_source IS NOT DISTINCT FROM 'service') = $5) \
         ORDER BY created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(tenant_id)
    .bind(&pattern)
    .bind(limit)
    .bind(offset)
    .bind(service_only)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list users: {e}");
        ApiError::internal("failed to list users")
    })?;

    // Batch-load workspace memberships for the page (one query, grouped by user)
    // so the Accounts view renders each user's gateway role list without N+1.
    let user_ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    if !user_ids.is_empty() {
        #[derive(sqlx::FromRow)]
        struct MembershipRow {
            user_id: Uuid,
            workspace_id: Uuid,
            workspace_name: String,
            role: String,
            workspace_role: WorkspaceRole,
        }
        let memberships = sqlx::query_as::<_, MembershipRow>(
            "SELECT m.user_id, w.id as workspace_id, \
                    w.name as workspace_name, m.role, w.role AS workspace_role \
             FROM workspace_members m \
             JOIN workspaces w ON w.id = m.workspace_id \
             WHERE m.tenant_id = $1 AND m.user_id = ANY($2) \
             ORDER BY (w.role = 'default') DESC, w.name",
        )
        .bind(tenant_id)
        .bind(&user_ids)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list user memberships: {e}");
            ApiError::internal("failed to list users")
        })?;

        let mut by_user: HashMap<Uuid, Vec<WorkspaceMembershipInfo>> = HashMap::new();
        for m in memberships {
            by_user.entry(m.user_id).or_default().push(WorkspaceMembershipInfo {
                workspace_id: m.workspace_id,
                workspace_name: m.workspace_name,
                role: m.role,
                workspace_role: m.workspace_role,
            });
        }
        for r in &mut rows {
            if let Some(ws) = by_user.remove(&r.id) {
                r.workspaces = ws;
            }
        }
    }

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users/{id}",
    tag = "Users",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User details", body = UserDetailResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<UserDetailResponse>, ApiError> {
    let row = sqlx::query_as::<_, UserResponse>(
        "SELECT id, email, display_name, tenant_id, is_active, created_at FROM users WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get user: {e}");
        ApiError::internal("failed to get user")
    })?
    .ok_or_else(|| ApiError::not_found("user not found", ApiErrorCode::UserNotFound))?;

    let workspace_memberships = sqlx::query_as::<_, WorkspaceMembershipInfo>(
        "SELECT w.id as workspace_id, w.name as workspace_name, \
                m.role, w.role AS workspace_role \
         FROM workspace_members m \
         JOIN workspaces w ON w.id = m.workspace_id \
         WHERE m.user_id = $1 \
         ORDER BY (w.role = 'default') DESC, w.name",
    )
    .bind(id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get user memberships: {e}");
        ApiError::internal("failed to get user")
    })?;

    Ok(Json(UserDetailResponse {
        id: row.id,
        email: row.email,
        display_name: row.display_name,
        tenant_id: row.tenant_id,
        is_active: row.is_active,
        created_at: row.created_at,
        workspace_memberships,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/users/{id}",
    tag = "Users",
    params(("id" = Uuid, Path, description = "User ID")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "Updated user", body = UserResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Email already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_user(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(mut req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    // Addresses are stored and compared normalized (`routes::normalize_email`).
    req.email = req.email.as_deref().map(super::normalize_email);
    if let Some(email) = req.email.as_deref() {
        super::require_address(email)?;
    }
    // Hash password if provided.
    let password_hash: Option<String> = match &req.password {
        Some(pw) if !pw.is_empty() => Some(
            super::admin_auth::hash_password(pw).map_err(|e| {
                tracing::error!("hash password: {e}");
                ApiError::internal("failed to hash password")
            })?,
        ),
        _ => None,
    };

    // Service accounts have their own lifecycle (disable/enable/revoke on
    // /service-accounts, agent guarded there) — this generic PATCH must not
    // bypass those guards.
    if req.is_active.is_some() {
        let is_service: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND auth_source = 'service')",
        )
        .bind(id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update user service check: {e}");
            ApiError::internal("failed to update user")
        })?;
        if is_service {
            return Err(ApiError::bad_request(
                "service accounts are enabled/disabled via the service-account lifecycle actions",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
    }

    // Atomic partial update + cross-plane sync (email rename / password /
    // display name propagate to the sibling console-admin row) in one
    // transaction so the two planes can't diverge on a partial failure.
    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update user begin tx: {e}");
        ApiError::internal("failed to update user")
    })?;
    // An edit that reaches the console sibling (address, password, name) takes
    // the console-account rows before the user row: the console's account
    // update takes them in that order, and the opposite order deadlocks an edit
    // of one identity from both planes at once. All of the tenant's, not the
    // sibling's by address: the address is read below, under this lock, so a
    // concurrent rename cannot leave the lock on a row that no longer matches.
    if req.email.is_some() || password_hash.is_some() || req.display_name.is_some() {
        super::admin_auth::lock_tenant_admins(&mut tx, tenant_id).await?;
    }

    // Snapshot the prior email inside the transaction so a rename can be
    // propagated to the sibling console-admin row. The audit before/after diff
    // is captured generically by the audit middleware.
    let before = sqlx::query_as::<_, UserResponse>(
        "SELECT id, email, display_name, tenant_id, is_active, created_at \
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update user load before: {e}");
        ApiError::internal("failed to update user")
    })?;


    let row = sqlx::query_as::<_, UserResponse>(
        r#"UPDATE users SET
            email = COALESCE($2, email),
            display_name = CASE WHEN $3 THEN $4 ELSE display_name END,
            password_hash = COALESCE($5, password_hash),
            is_active = COALESCE($6, is_active)
        WHERE id = $1
        RETURNING id, email, display_name, tenant_id, is_active, created_at"#,
    )
    .bind(id)
    .bind(req.email.as_deref())
    .bind(req.display_name.is_some()) // flag: was display_name provided (value OR explicit null)?
    .bind(req.display_name.clone().flatten())
    .bind(password_hash.as_deref())
    .bind(req.is_active)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update user: {e}");
        if super::is_unique_violation(&e) {
            ApiError::conflict("a user with this email already exists", ApiErrorCode::UserEmailTaken)
        } else {
            ApiError::internal("failed to update user")
        }
    })?
    .ok_or_else(|| ApiError::not_found("user not found", ApiErrorCode::UserNotFound))?;

    // Email is the identity key: propagate a rename to the sibling console admin
    // row so the two planes stay correlated.
    if let Some(b) = &before
        && b.email != row.email
    {
        super::admin_auth::sync_email_rename(&mut tx, row.tenant_id, &b.email, &row.email).await?;
    }

    // Synced password (one identity ⇒ one credential): write to the sibling
    // console admin row too. Uses the updated email so a same-call rename stays
    // consistent.
    if let Some(hash) = &password_hash {
        super::admin_auth::sync_password_for_email(&mut tx, row.tenant_id, &row.email, hash).await?;
    }

    // Synced display name: keep the sibling console-admin row equal so the one
    // identity reads the same everywhere.
    if let Some(name) = &req.display_name {
        super::admin_auth::sync_display_name_for_email(
            &mut tx,
            row.tenant_id,
            &row.email,
            name.as_deref(),
        )
        .await?;
    }

    // Disable is REVERSIBLE: keys are kept but stop authenticating everywhere —
    // ak- lookups gate on `users.is_active` live, and the edge config body
    // excludes inactive owners' keys. Only the per-user
    // OAuth MCP credentials are dropped: they proxy a third-party grant that
    // should be re-consented after a suspension, not silently resumed.
    if req.is_active == Some(false) {
        let creds = sqlx::query(
            "DELETE FROM mcp_user_credentials WHERE user_id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("cascade delete mcp_user_credentials on user disable: {e}");
            ApiError::internal("failed to drop user MCP credentials")
        })?
        .rows_affected();

        if creds > 0 {
            tracing::info!(user_id = %id, dropped_credentials = creds, "user disable cascade");
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("update user commit: {e}");
        ApiError::internal("failed to update user")
    })?;


    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}",
    tag = "Users",
    params(("id" = Uuid, Path, description = "User ID"), DryRunQuery),
    responses(
        (status = 200, description = "User deleted (or dry-run impact)", body = DeletionResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_user(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(q): Query<DryRunQuery>,
) -> Result<Json<DeletionResponse>, ApiError> {
    // The built-in agent is guarded against every lifecycle verb — the generic
    // DELETE must not be the one path that can destroy it (cascade would drop
    // its keys and silently stop agent analysis fleet-wide).
    let is_agent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2)",
    )
    .bind(id)
    .bind(crate::agent::AGENT_EMAIL)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete user agent check: {e}");
        ApiError::internal("failed to delete user")
    })?;
    if is_agent {
        return Err(ApiError::bad_request("the built-in agent service account cannot be deleted")
            .code(ApiErrorCode::ValidationFailed));
    }
    // Same guard for the built-in inline-AI account — deleting it would cascade
    // its managed key and silently sever the external analyzer.
    let is_inline_ai: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND email = $2)")
            .bind(id)
            .bind(crate::service_account::INLINE_AI_EMAIL)
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("delete user inline-ai check: {e}");
                ApiError::internal("failed to delete user")
            })?;
    if is_inline_ai {
        return Err(ApiError::bad_request(
            "the built-in inline-AI service account cannot be deleted",
        )
        .code(ApiErrorCode::ValidationFailed));
    }

    // Live OAuth grants: MCP client authorizations and signed-in CLI machines.
    // Counted per login rather than per row, because one login is a chain of
    // rotating pairs and reporting "6 sessions" for three machines would not
    // help anybody decide.
    let oauth_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT login_chain)::bigint \
           FROM oauth_issued_tokens \
          WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("count oauth sessions for user: {e}");
        ApiError::internal("failed to count sessions")
    })?;

    if q.dry_run.unwrap_or(false) {
        let impact = key_lifecycle::count_keys_for_user(db.conn(), id)
            .await
            .map_err(|e| {
                tracing::error!("dry run count keys for user: {e}");
                ApiError::internal("failed to count keys")
            })?;
        return Ok(Json(DeletionResponse {
            dry_run: true,
            affected_keys: impact.affected_keys,
            affected_users: 1,
            affected_oauth_sessions: oauth_sessions,
        }));
    }

    // One transaction: revoking the user's credentials and removing the user are
    // halves of one operation. Split across autocommits, a failure between them
    // leaves a user with no credentials but still present, and a retry looks
    // like it deleted nothing.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete user begin: {e}");
        ApiError::internal("failed to delete user")
    })?;

    // Lock the subject FIRST, and do not remove this.
    //
    // Every revoke below is snapshot-bound: it cannot see a row a concurrent
    // token rotation commits after it runs. Because `oauth_issued_tokens.user_id`
    // is `ON DELETE SET NULL`, such a row is not blocked by the delete — it is
    // orphaned, keeps `revoked_at IS NULL`, and therefore stays OUT of the
    // revoked-jti set the proxy enforces. The deleted user's access token would
    // go on working for the rest of its hour, and the operator could not even see
    // it: every listing joins `users`, so an orphan is invisible.
    //
    // `FOR UPDATE` closes the window because inserting an FK child takes
    // `FOR KEY SHARE` on the parent row, which conflicts with it. A rotation that
    // starts mid-delete blocks here, then fails its foreign key once this commits
    // — the loud, fail-closed outcome. Nothing else in this transaction enforces
    // that: `SET NULL` is what lets a token row outlive its subject, so this lock
    // is the only thing standing between a mid-delete rotation and a live token
    // belonging to nobody.
    let subject: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete user lock: {e}");
            ApiError::internal("failed to delete user")
        })?;
    if subject.is_none() {
        return Err(ApiError::not_found("user not found", ApiErrorCode::UserNotFound));
    }

    // Revoke all keys for this user.
    let revoke_result = sqlx::query("UPDATE api_keys SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("revoke user keys: {e}");
            ApiError::internal("failed to revoke user keys")
        })?;
    let revoked = revoke_result.rows_affected() as i64;

    // Revoke the issued tokens — do NOT delete them. The proxy verifies MCP
    // bearers without touching the database; what refuses a revoked one is the
    // config snapshot's revoked-jti set, and that set is *derived* from rows
    // still present with `revoked_at` set. Deleting the rows would therefore
    // withdraw the revocation at the same instant the subject stopped existing,
    // and the next config body would carry that shrunken set out —
    // handing a deleted user's access token back for the rest of its hour.
    // `user_id` is nullable with ON DELETE SET NULL, so the rows survive the
    // user and keep carrying their jtis until they expire.
    sqlx::query(
        "UPDATE oauth_issued_tokens SET revoked_at = NOW() \
          WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("revoke user oauth tokens: {e}");
        ApiError::internal("failed to delete user")
    })?;

    // Pending authorization codes are deleted rather than revoked: they live 60
    // seconds, feed no revocation set, and are consumed by an atomic claim that
    // a missing row already refuses.
    sqlx::query("DELETE FROM oauth_authorization_codes WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete user authorization codes: {e}");
            ApiError::internal("failed to delete user")
        })?;

    // Workspace memberships and per-(workspace, user) rate-limit overrides drop
    // via `ON DELETE CASCADE` on `user_id` when the user row is deleted below.

    // Delete user.
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete user: {e}");
            ApiError::internal("failed to delete user")
        })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("user not found", ApiErrorCode::UserNotFound));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("delete user commit: {e}");
        ApiError::internal("failed to delete user")
    })?;


    Ok(Json(DeletionResponse {
        dry_run: false,
        affected_keys: revoked,
        affected_users: 1,
        affected_oauth_sessions: oauth_sessions,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users/{id}/usage",
    tag = "Users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        WindowWorkspacesQuery,
    ),
    responses(
        (status = 200, description = "Usage summary", body = UserUsageSummary),
        (status = 400, description = "Invalid time window", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_usage(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(params): Query<WindowWorkspacesQuery>,
) -> Result<Json<UserUsageSummary>, ApiError> {
    let window = params.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let row = crate::audit_store::usage::user_usage(db.conn(), id, window, params.workspace_ids().as_deref())
        .await
        .map_err(|e| {
            tracing::error!("failed to query user usage: {e}");
            ApiError::internal("failed to query user usage")
        })?;

    let spend = super::denominated_spend(db.conn(), row.currency_count, row.currency, row.amount).await;
    let summary = UserUsageSummary {
        total_requests: row.requests,
        total_prompt_tokens: row.prompt_tokens,
        total_completion_tokens: row.completion_tokens,
        total_cache_creation_tokens: row.cache_creation_tokens,
        total_cache_read_tokens: row.cache_read_tokens,
        total_reasoning_tokens: row.reasoning_tokens,
        spend,
        avg_latency_ms: row.avg_latency_ms,
    };

    Ok(Json(summary))
}

