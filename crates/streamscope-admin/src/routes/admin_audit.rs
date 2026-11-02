//! Admin-action audit read API.
//!
//! Read surface over the `admin_audit` table populated by
//! `crate::middleware::admin_audit_mw`. Two endpoints:
//!
//! - `GET /api/v1/admin/admin-audit` (tenant-scoped) — `TenantConn`, RLS enforces
//!   the filter. Visible to every admin.
//! - `GET /api/v1/admin/global/admin-audit` (super-admin) — iterates every
//!   non-SYSTEM tenant with its own `TenantConn` and merges the rows. Each row
//!   carries `tenant_slug` so the UI can render the tenant column without a
//!   client-side join.
//!
//! The global handler iterates tenants rather than running one cross-tenant
//! SELECT because `streamscope_app` does not have `BYPASSRLS` and the
//! `admin_audit` policy is `FORCE`. Admin-mutation volume is low (10-50 rows
//! per tenant per day); a 30-day window across hundreds of tenants stays well
//! within an in-memory sort.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{ApiError, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{TenantConn, TenantId};
use crate::db::Global;
use crate::AdminState;

/// One row in `GET /api/v1/admin/admin-audit`.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct AdminAuditRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub tenant_id: Uuid,
    /// `human` (an admin session) or `admin_key` (an `ak-` automation key).
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    /// The `ak-` key id when `actor_kind='admin_key'`; `null` for humans.
    /// Answers "which automation did this?" independently of the owning account.
    pub actor_key_id: Option<Uuid>,
    pub actor_ip: Option<String>,
    pub is_super_admin: bool,
    pub method: String,
    pub path: String,
    pub route_template: Option<String>,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    /// Redacted request body. `null` when the inbound body was empty or
    /// non-JSON. The middleware redacts known secret-shaped keys (password,
    /// api_key, token, …) before insert.
    #[schema(value_type = Object)]
    pub request_body: Option<serde_json::Value>,
    /// Structured before/after snapshot stamped by handlers that pre-load
    /// the row they're about to mutate. Shape: `{ "before": <row>, "after":
    /// <row> }`, or `{ "_truncated": true, "_bytes": <n> }` when it was too
    /// large to keep. NULL for handlers that haven't opted in (most creates /
    /// deletes) or when nothing actually changed.
    #[schema(value_type = Object)]
    pub change_diff: Option<serde_json::Value>,
    /// Typed error body (`{code, message}`) the handler returned on a non-2xx
    /// status. NULL on success. Lets the log show WHY a call failed, not just
    /// its status_code.
    #[schema(value_type = Object)]
    pub response_error: Option<serde_json::Value>,
    pub status_code: i16,
    pub request_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AdminAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter to actions performed by this admin account.
    pub actor_id: Option<Uuid>,
    /// Filter to actions performed by this `ak-` automation key.
    pub actor_key_id: Option<Uuid>,
    /// Filter by canonical verb (e.g. `users.create`, `keys.revoke`).
    pub action: Option<String>,
    /// Filter by `resource_kind` (e.g. `users`, `keys`, `tool_rules`).
    pub resource_kind: Option<String>,
    /// Lower bound on `at` (inclusive, RFC 3339).
    pub start: Option<DateTime<Utc>>,
    /// Upper bound on `at` (exclusive, RFC 3339).
    pub end: Option<DateTime<Utc>>,
    /// Filter to a specific request_id (for log correlation).
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/admin-audit",
    tag = "Admin Audit",
    params(AdminAuditListQuery),
    responses(
        (status = 200, description = "Paginated list of admin actions", body = OffsetPage<AdminAuditRow>),
        (status = 400, description = "`start` is not before `end`", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_admin_audit(
    mut db: TenantConn,
    Query(query): Query<AdminAuditListQuery>,
) -> Result<Json<OffsetPage<AdminAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();

    // Build the WHERE clause dynamically — RLS already filters to the current
    // tenant, so each predicate below is purely a user-facing refinement.
    let mut sql = String::from(
        "SELECT id, at, tenant_id, actor_kind, actor_id, actor_email, actor_key_id, actor_ip, \
                is_super_admin, method, path, route_template, action, \
                resource_kind, resource_id, request_body, change_diff, \
                response_error, status_code, request_id \
         FROM admin_audit WHERE 1=1",
    );
    let mut idx = 1;
    if query.actor_id.is_some() {
        sql.push_str(&format!(" AND actor_id = ${idx}"));
        idx += 1;
    }
    if query.actor_key_id.is_some() {
        sql.push_str(&format!(" AND actor_key_id = ${idx}"));
        idx += 1;
    }
    if query.action.is_some() {
        sql.push_str(&format!(" AND action = ${idx}"));
        idx += 1;
    }
    if query.resource_kind.is_some() {
        sql.push_str(&format!(" AND resource_kind = ${idx}"));
        idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&format!(" AND at >= ${idx}"));
        idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&format!(" AND at < ${idx}"));
        idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND request_id = ${idx}"));
        idx += 1;
    }
    sql.push_str(&format!(
        " ORDER BY at DESC, id DESC LIMIT ${idx} OFFSET ${}",
        idx + 1
    ));

    let mut q = sqlx::query_as::<_, AdminAuditRow>(sqlx::AssertSqlSafe(&*sql));
    if let Some(actor_id) = query.actor_id {
        q = q.bind(actor_id);
    }
    if let Some(actor_key_id) = query.actor_key_id {
        q = q.bind(actor_key_id);
    }
    if let Some(action) = query.action {
        q = q.bind(action);
    }
    if let Some(resource_kind) = query.resource_kind {
        q = q.bind(resource_kind);
    }
    if let Some(start) = query.start {
        q = q.bind(start);
    }
    if let Some(end) = query.end {
        q = q.bind(end);
    }
    if let Some(request_id) = query.request_id {
        q = q.bind(request_id);
    }
    q = q.bind(limit + 1).bind(offset);

    let rows = q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list admin_audit: {e}");
        ApiError::internal("failed to list admin audit")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

/// One row in `GET /api/v1/admin/global/admin-audit`. Same shape as the
/// tenant-scoped row plus `tenant_slug` for the UI's tenant column / filter.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct GlobalAdminAuditRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub actor_kind: String,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_key_id: Option<Uuid>,
    pub actor_ip: Option<String>,
    pub is_super_admin: bool,
    pub method: String,
    pub path: String,
    pub route_template: Option<String>,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    /// Redacted request body (secret-shaped keys removed); `null` when the body was empty or not JSON; `{ "_truncated": true, "_bytes": <n>, …identity fields }` when it was too large to keep.
    #[schema(value_type = Object)]
    pub request_body: Option<serde_json::Value>,
    /// `{ "before": <row>, "after": <row> }` for the resource the call changed, or `{ "_truncated": true, "_bytes": <n> }` when it was too large to keep; `null` when nothing was captured or nothing changed.
    #[schema(value_type = Object)]
    pub change_diff: Option<serde_json::Value>,
    /// The error body the call answered with (`{code, message}` for a current release, any stored JSON for an older one); `null` on success.
    #[schema(value_type = Object)]
    pub response_error: Option<serde_json::Value>,
    pub status_code: i16,
    pub request_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GlobalAdminAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Restrict to a single tenant (by UUID). Omit for a merged cross-tenant feed.
    pub tenant_id: Option<Uuid>,
    /// Restrict to a single tenant (by slug). Alternative to `tenant_id`; ignored when both are set.
    pub tenant_slug: Option<String>,
    pub actor_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_kind: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/admin-audit",
    tag = "Admin Audit",
    params(GlobalAdminAuditListQuery),
    responses(
        (status = 200, description = "Paginated cross-tenant list of admin actions", body = OffsetPage<GlobalAdminAuditRow>),
        (status = 400, description = "`start` is not before `end`, or the page is too deep", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_global_admin_audit(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<GlobalAdminAuditListQuery>,
) -> Result<Json<OffsetPage<GlobalAdminAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();
    // The page is merged in memory from every tenant's first
    // `limit + offset + 1` rows.
    super::check_merged_offset(offset)?;

    // Resolve the tenant scope. `tenant_id` and `tenant_slug` are alternative
    // ways to name the same tenant; supplying both is ambiguous and almost
    // always indicates a UI bug — reject explicitly so the operator doesn't
    // silently see results filtered by the one we happened to prefer.
    if query.tenant_id.is_some() && query.tenant_slug.is_some() {
        return Err(ApiError::bad_request(
            "supply at most one of tenant_id / tenant_slug",
        ));
    }
    let target_tenant_id = if let Some(tid) = query.tenant_id {
        Some(tid)
    } else if let Some(slug) = query.tenant_slug.as_deref() {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM tenants WHERE slug = $1")
            .bind(slug)
            .fetch_optional(state.db.global(Global::TenantRegistry))
            .await
            .map_err(|e| {
                tracing::error!("list global admin_audit tenant lookup: {e}");
                ApiError::internal("failed to list admin audit")
            })?
    } else {
        None
    };

    // List of (tenant_id, tenant_slug) to scan. Single-tenant when filtered;
    // otherwise every non-SYSTEM tenant.
    let tenants: Vec<(Uuid, String)> = if let Some(tid) = target_tenant_id {
        let slug: Option<String> =
            sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1 AND slug != 'system'")
                .bind(tid)
                .fetch_optional(state.db.global(Global::TenantRegistry))
                .await
                .map_err(|e| {
                    tracing::error!("list global admin_audit slug: {e}");
                    ApiError::internal("failed to list admin audit")
                })?;
        match slug {
            Some(s) => vec![(tid, s)],
            None => Vec::new(),
        }
    } else {
        sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, slug FROM tenants WHERE slug != 'system' ORDER BY slug",
        )
        .fetch_all(state.db.global(Global::TenantIteration))
        .await
        .map_err(|e| {
            tracing::error!("list global admin_audit list tenants: {e}");
            ApiError::internal("failed to list admin audit")
        })?
    };

    // Per-tenant overfetch ceiling: at most we ever need (limit + offset + 1)
    // rows in time order from any single tenant to render this page after the
    // merge-sort. Bound the per-tenant fetch so a noisy tenant doesn't dominate.
    //
    // Each tenant contributes its first `limit + offset + 1` rows, so the
    // merged page and its `has_more` are exact; the offset is bounded above.
    let per_tenant_cap = limit + offset + 1;

    let mut sql_filters = String::new();
    let mut idx = 1;
    if query.actor_id.is_some() {
        sql_filters.push_str(&format!(" AND actor_id = ${idx}"));
        idx += 1;
    }
    if query.action.is_some() {
        sql_filters.push_str(&format!(" AND action = ${idx}"));
        idx += 1;
    }
    if query.resource_kind.is_some() {
        sql_filters.push_str(&format!(" AND resource_kind = ${idx}"));
        idx += 1;
    }
    if query.start.is_some() {
        sql_filters.push_str(&format!(" AND at >= ${idx}"));
        idx += 1;
    }
    if query.end.is_some() {
        sql_filters.push_str(&format!(" AND at < ${idx}"));
        idx += 1;
    }
    if query.request_id.is_some() {
        sql_filters.push_str(&format!(" AND request_id = ${idx}"));
        idx += 1;
    }
    let limit_idx = idx;

    let select_cols = "id, at, tenant_id, actor_kind, actor_id, actor_email, actor_key_id, actor_ip, \
                       is_super_admin, method, path, route_template, action, \
                       resource_kind, resource_id, request_body, change_diff, \
                       response_error, status_code, request_id";
    let sql = format!(
        "SELECT {select_cols} FROM admin_audit WHERE 1=1{sql_filters} \
         ORDER BY at DESC, id DESC LIMIT ${limit_idx}"
    );

    let mut merged: Vec<GlobalAdminAuditRow> = Vec::new();
    for (tid, slug) in &tenants {
        let mut db = TenantConn::acquire(&state.db, TenantId::from_row(*tid))
            .await
            .map_err(|e| {
                tracing::error!("list global admin_audit acquire {tid}: {e}");
                ApiError::internal("failed to list admin audit")
            })?;
        let mut q = sqlx::query_as::<_, AdminAuditRow>(sqlx::AssertSqlSafe(&*sql));
        if let Some(actor_id) = query.actor_id {
            q = q.bind(actor_id);
        }
        if let Some(ref action) = query.action {
            q = q.bind(action);
        }
        if let Some(ref resource_kind) = query.resource_kind {
            q = q.bind(resource_kind);
        }
        if let Some(start) = query.start {
            q = q.bind(start);
        }
        if let Some(end) = query.end {
            q = q.bind(end);
        }
        if let Some(request_id) = query.request_id {
            q = q.bind(request_id);
        }
        q = q.bind(per_tenant_cap);
        let rows = q.fetch_all(db.conn()).await.map_err(|e| {
            tracing::error!("list global admin_audit fetch {tid}: {e}");
            ApiError::internal("failed to list admin audit")
        })?;
        for r in rows {
            merged.push(GlobalAdminAuditRow {
                id: r.id,
                at: r.at,
                tenant_id: r.tenant_id,
                tenant_slug: slug.clone(),
                actor_kind: r.actor_kind,
                actor_id: r.actor_id,
                actor_email: r.actor_email,
                actor_key_id: r.actor_key_id,
                actor_ip: r.actor_ip,
                is_super_admin: r.is_super_admin,
                method: r.method,
                path: r.path,
                route_template: r.route_template,
                action: r.action,
                resource_kind: r.resource_kind,
                resource_id: r.resource_id,
                request_body: r.request_body,
                change_diff: r.change_diff,
                response_error: r.response_error,
                status_code: r.status_code,
                request_id: r.request_id,
            });
        }
        // Keep only the rows the page can still need: memory stays at about
        // twice the page whatever the number of tenants.
        merged.sort_by_key(|r| std::cmp::Reverse((r.at, r.id)));
        merged.truncate(per_tenant_cap as usize);
    }

    // `merged` is already in the per-tenant queries' own order (newest first,
    // then id), kept to the page's first `per_tenant_cap` rows.
    let start_idx = offset.max(0) as usize;
    let end_idx = (start_idx + (limit as usize) + 1).min(merged.len());
    let slice: Vec<GlobalAdminAuditRow> = if start_idx >= merged.len() {
        Vec::new()
    } else {
        merged.drain(start_idx..end_idx).collect()
    };
    Ok(Json(OffsetPage::from_overfetched(slice, limit, offset)))
}

// ---------------------------------------------------------------------------
// Portal audit (end-user mutations on /api/v1/portal/*)
// ---------------------------------------------------------------------------

/// One row in `GET /api/v1/admin/portal-audit`.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct PortalAuditRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub tenant_id: Uuid,
    /// Portal user (the `users` row) that performed the action. For a
    /// `portal_key` actor this is the owning service account.
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_ip: Option<String>,
    /// `human` (portal session) | `portal_key` (an `ak-` portal automation key).
    pub actor_kind: String,
    /// The `automation_keys.id` (plane='portal') when `actor_kind='portal_key'`; `null` for humans.
    pub actor_key_id: Option<Uuid>,
    /// Workspace the mutation acted within, when one was in scope (key
    /// creation, quickstart render carry it). NULL otherwise.
    pub workspace_id: Option<Uuid>,
    /// The member a manager operated on (mint/revoke a key for someone else).
    /// NULL for self-service mutations.
    pub target_user_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub route_template: Option<String>,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    /// Redacted request body (secret-shaped keys removed); `null` when the body was empty or not JSON; `{ "_truncated": true, "_bytes": <n>, …identity fields }` when it was too large to keep.
    #[schema(value_type = Object)]
    pub request_body: Option<serde_json::Value>,
    /// `{ "before": <row>, "after": <row> }` for the resource the call changed, or `{ "_truncated": true, "_bytes": <n> }` when it was too large to keep; `null` when nothing was captured or nothing changed.
    #[schema(value_type = Object)]
    pub change_diff: Option<serde_json::Value>,
    /// The error body the call answered with (`{code, message}` for a current release, any stored JSON for an older one); `null` on success.
    #[schema(value_type = Object)]
    pub response_error: Option<serde_json::Value>,
    pub status_code: i16,
    pub request_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter to actions performed by this portal user.
    pub actor_id: Option<Uuid>,
    /// Filter to actions performed by this portal automation (`ak-`) key.
    pub actor_key_id: Option<Uuid>,
    /// Filter to actions scoped to this workspace.
    pub workspace_id: Option<Uuid>,
    /// Filter by canonical verb (e.g. `portal_key.create`, `quickstart.render`).
    pub action: Option<String>,
    pub resource_kind: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/portal-audit",
    tag = "Admin Audit",
    params(PortalAuditListQuery),
    responses(
        (status = 200, description = "Paginated list of portal user actions", body = OffsetPage<PortalAuditRow>),
        (status = 400, description = "`start` is not before `end`", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_portal_audit(
    mut db: TenantConn,
    Query(query): Query<PortalAuditListQuery>,
) -> Result<Json<OffsetPage<PortalAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();

    // RLS scopes to the caller's tenant; each predicate is a user refinement.
    let mut sql = String::from(
        "SELECT id, at, tenant_id, actor_id, actor_email, actor_ip, actor_kind, actor_key_id, \
                workspace_id, target_user_id, method, path, route_template, \
                action, resource_kind, resource_id, request_body, change_diff, \
                response_error, status_code, request_id \
         FROM portal_audit WHERE 1=1",
    );
    let mut idx = 1;
    if query.actor_id.is_some() {
        sql.push_str(&format!(" AND actor_id = ${idx}"));
        idx += 1;
    }
    if query.actor_key_id.is_some() {
        sql.push_str(&format!(" AND actor_key_id = ${idx}"));
        idx += 1;
    }
    if query.workspace_id.is_some() {
        sql.push_str(&format!(" AND workspace_id = ${idx}"));
        idx += 1;
    }
    if query.action.is_some() {
        sql.push_str(&format!(" AND action = ${idx}"));
        idx += 1;
    }
    if query.resource_kind.is_some() {
        sql.push_str(&format!(" AND resource_kind = ${idx}"));
        idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&format!(" AND at >= ${idx}"));
        idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&format!(" AND at < ${idx}"));
        idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND request_id = ${idx}"));
        idx += 1;
    }
    sql.push_str(&format!(" ORDER BY at DESC, id DESC LIMIT ${idx} OFFSET ${}", idx + 1));

    let mut q = sqlx::query_as::<_, PortalAuditRow>(sqlx::AssertSqlSafe(&*sql));
    if let Some(actor_id) = query.actor_id {
        q = q.bind(actor_id);
    }
    if let Some(actor_key_id) = query.actor_key_id {
        q = q.bind(actor_key_id);
    }
    if let Some(workspace_id) = query.workspace_id {
        q = q.bind(workspace_id);
    }
    if let Some(action) = query.action {
        q = q.bind(action);
    }
    if let Some(resource_kind) = query.resource_kind {
        q = q.bind(resource_kind);
    }
    if let Some(start) = query.start {
        q = q.bind(start);
    }
    if let Some(end) = query.end {
        q = q.bind(end);
    }
    if let Some(request_id) = query.request_id {
        q = q.bind(request_id);
    }
    q = q.bind(limit + 1).bind(offset);

    let rows = q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list portal_audit: {e}");
        ApiError::internal("failed to list portal audit")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

// ---------------------------------------------------------------------------
// Security audit (pre-auth / public security events)
// ---------------------------------------------------------------------------

/// One row in `GET /api/v1/admin/security-audit`.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct SecurityAuditRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub tenant_id: Option<Uuid>,
    pub tenant_slug: Option<String>,
    /// Attempted identity — the login email or OAuth client_id. NULL when the
    /// request carried none (e.g. the body-less OAuth callback).
    pub actor_identity: Option<String>,
    pub actor_ip: Option<String>,
    pub method: String,
    pub path: String,
    pub route_template: Option<String>,
    pub action: String,
    pub succeeded: bool,
    pub status_code: i16,
    /// Redacted request body (secret-shaped keys removed); `null` when the body was empty or not JSON; `{ "_truncated": true, "_bytes": <n>, …identity fields }` when it was too large to keep.
    #[schema(value_type = Object)]
    pub request_body: Option<serde_json::Value>,
    /// The error body the call answered with (`{code, message}` for a current release, any stored JSON for an older one); `null` on success.
    #[schema(value_type = Object)]
    pub response_error: Option<serde_json::Value>,
    pub request_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SecurityAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by canonical verb (e.g. `auth.login`, `invite.accept`).
    pub action: Option<String>,
    /// Filter to only failed (`false`) or only successful (`true`) attempts.
    pub succeeded: Option<bool>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/security-audit",
    tag = "Admin Audit",
    params(SecurityAuditListQuery),
    responses(
        (status = 200, description = "Paginated list of pre-auth security events for this tenant", body = OffsetPage<SecurityAuditRow>),
        (status = 400, description = "`start` is not before `end`", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_security_audit(
    mut db: TenantConn,
    Query(query): Query<SecurityAuditListQuery>,
) -> Result<Json<OffsetPage<SecurityAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();

    // `security_audit` is a global, non-RLS table (pre-auth events have no
    // reliable tenant). A tenant admin sees only events tagged with THEIR
    // slug — the slug a login/exchange attempt named in its request. Events
    // with no resolvable tenant (failed login to an unknown slug, the
    // body-less callback) are platform-level and never surface here.
    let tenant_uuid = db.tenant_uuid();
    let slug: Option<String> =
        sqlx::query_scalar::<_, String>("SELECT slug FROM tenants WHERE id = $1")
            .bind(tenant_uuid)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("list security_audit slug lookup: {e}");
                ApiError::internal("failed to list security audit")
            })?;
    let Some(slug) = slug else {
        return Ok(Json(OffsetPage::from_overfetched(Vec::new(), limit, offset)));
    };

    let mut sql = String::from(
        "SELECT id, at, tenant_id, tenant_slug, actor_identity, actor_ip, \
                method, path, route_template, action, succeeded, status_code, \
                request_body, response_error, request_id \
         FROM security_audit WHERE tenant_slug = $1",
    );
    let mut idx = 2;
    if query.action.is_some() {
        sql.push_str(&format!(" AND action = ${idx}"));
        idx += 1;
    }
    if query.succeeded.is_some() {
        sql.push_str(&format!(" AND succeeded = ${idx}"));
        idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&format!(" AND at >= ${idx}"));
        idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&format!(" AND at < ${idx}"));
        idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND request_id = ${idx}"));
        idx += 1;
    }
    sql.push_str(&format!(" ORDER BY at DESC, id DESC LIMIT ${idx} OFFSET ${}", idx + 1));

    let mut q = sqlx::query_as::<_, SecurityAuditRow>(sqlx::AssertSqlSafe(&*sql)).bind(&slug);
    if let Some(action) = query.action {
        q = q.bind(action);
    }
    if let Some(succeeded) = query.succeeded {
        q = q.bind(succeeded);
    }
    if let Some(start) = query.start {
        q = q.bind(start);
    }
    if let Some(end) = query.end {
        q = q.bind(end);
    }
    if let Some(request_id) = query.request_id {
        q = q.bind(request_id);
    }
    q = q.bind(limit + 1).bind(offset);

    let rows = q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list security_audit: {e}");
        ApiError::internal("failed to list security audit")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

// ---------------------------------------------------------------------------
// Super-admin cross-tenant feeds (mounted under /api/v1/admin/global/*)
// ---------------------------------------------------------------------------

/// One row in `GET /api/v1/admin/global/portal-audit` — `PortalAuditRow` plus
/// `tenant_slug` for the UI's tenant column.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct GlobalPortalAuditRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub actor_id: Option<Uuid>,
    pub actor_email: Option<String>,
    pub actor_ip: Option<String>,
    pub actor_kind: String,
    pub actor_key_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub target_user_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub route_template: Option<String>,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    /// Redacted request body (secret-shaped keys removed); `null` when the body was empty or not JSON; `{ "_truncated": true, "_bytes": <n>, …identity fields }` when it was too large to keep.
    #[schema(value_type = Object)]
    pub request_body: Option<serde_json::Value>,
    /// `{ "before": <row>, "after": <row> }` for the resource the call changed, or `{ "_truncated": true, "_bytes": <n> }` when it was too large to keep; `null` when nothing was captured or nothing changed.
    #[schema(value_type = Object)]
    pub change_diff: Option<serde_json::Value>,
    /// The error body the call answered with (`{code, message}` for a current release, any stored JSON for an older one); `null` on success.
    #[schema(value_type = Object)]
    pub response_error: Option<serde_json::Value>,
    pub status_code: i16,
    pub request_id: Uuid,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GlobalPortalAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Restrict to a single tenant (by slug).
    pub tenant_slug: Option<String>,
    pub actor_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_kind: Option<String>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/portal-audit",
    tag = "Admin Audit",
    params(GlobalPortalAuditListQuery),
    responses(
        (status = 200, description = "Paginated cross-tenant list of portal user actions", body = OffsetPage<GlobalPortalAuditRow>),
        (status = 400, description = "`start` is not before `end`, or the page is too deep", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_global_portal_audit(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<GlobalPortalAuditListQuery>,
) -> Result<Json<OffsetPage<GlobalPortalAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    // The page is merged in memory from every tenant's first
    // `limit + offset + 1` rows.
    super::check_merged_offset(offset)?;

    // Tenant scope: a single tenant when filtered, else every non-SYSTEM
    // tenant (iterated under its own RLS connection — `streamscope_app` has no
    // BYPASSRLS and `portal_audit` is FORCE RLS).
    let tenants: Vec<(Uuid, String)> = if let Some(slug) = query.tenant_slug.as_deref() {
        sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, slug FROM tenants WHERE slug = $1 AND slug != 'system'",
        )
        .bind(slug)
        .fetch_all(state.db.global(Global::TenantIteration))
        .await
        .map_err(|e| {
            tracing::error!("list global portal_audit tenant lookup: {e}");
            ApiError::internal("failed to list portal audit")
        })?
    } else {
        sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, slug FROM tenants WHERE slug != 'system' ORDER BY slug",
        )
        .fetch_all(state.db.global(Global::TenantIteration))
        .await
        .map_err(|e| {
            tracing::error!("list global portal_audit list tenants: {e}");
            ApiError::internal("failed to list portal audit")
        })?
    };

    let per_tenant_cap = limit + offset + 1;
    let mut sql_filters = String::new();
    let mut idx = 1;
    if query.actor_id.is_some() { sql_filters.push_str(&format!(" AND actor_id = ${idx}")); idx += 1; }
    if query.workspace_id.is_some() { sql_filters.push_str(&format!(" AND workspace_id = ${idx}")); idx += 1; }
    if query.action.is_some() { sql_filters.push_str(&format!(" AND action = ${idx}")); idx += 1; }
    if query.resource_kind.is_some() { sql_filters.push_str(&format!(" AND resource_kind = ${idx}")); idx += 1; }
    if query.start.is_some() { sql_filters.push_str(&format!(" AND at >= ${idx}")); idx += 1; }
    if query.end.is_some() { sql_filters.push_str(&format!(" AND at < ${idx}")); idx += 1; }
    if query.request_id.is_some() { sql_filters.push_str(&format!(" AND request_id = ${idx}")); idx += 1; }
    let limit_idx = idx;

    let select_cols = "id, at, tenant_id, actor_id, actor_email, actor_ip, actor_kind, actor_key_id, \
                       workspace_id, target_user_id, method, path, route_template, \
                       action, resource_kind, resource_id, request_body, change_diff, \
                       response_error, status_code, request_id";
    let sql = format!(
        "SELECT {select_cols} FROM portal_audit WHERE 1=1{sql_filters} \
         ORDER BY at DESC, id DESC LIMIT ${limit_idx}"
    );

    let mut merged: Vec<GlobalPortalAuditRow> = Vec::new();
    for (tid, slug) in &tenants {
        let mut db = TenantConn::acquire(&state.db, TenantId::from_row(*tid)).await.map_err(|e| {
            tracing::error!("list global portal_audit acquire {tid}: {e}");
            ApiError::internal("failed to list portal audit")
        })?;
        let mut q = sqlx::query_as::<_, PortalAuditRow>(sqlx::AssertSqlSafe(&*sql));
        if let Some(actor_id) = query.actor_id { q = q.bind(actor_id); }
        if let Some(workspace_id) = query.workspace_id { q = q.bind(workspace_id); }
        if let Some(ref action) = query.action { q = q.bind(action); }
        if let Some(ref resource_kind) = query.resource_kind { q = q.bind(resource_kind); }
        if let Some(start) = query.start { q = q.bind(start); }
        if let Some(end) = query.end { q = q.bind(end); }
        if let Some(request_id) = query.request_id { q = q.bind(request_id); }
        q = q.bind(per_tenant_cap);
        let rows = q.fetch_all(db.conn()).await.map_err(|e| {
            tracing::error!("list global portal_audit fetch {tid}: {e}");
            ApiError::internal("failed to list portal audit")
        })?;
        for r in rows {
            merged.push(GlobalPortalAuditRow {
                id: r.id, at: r.at, tenant_id: r.tenant_id, tenant_slug: slug.clone(),
                actor_id: r.actor_id, actor_email: r.actor_email, actor_ip: r.actor_ip,
                actor_kind: r.actor_kind, actor_key_id: r.actor_key_id,
                workspace_id: r.workspace_id, target_user_id: r.target_user_id,
                method: r.method, path: r.path, route_template: r.route_template,
                action: r.action, resource_kind: r.resource_kind, resource_id: r.resource_id,
                request_body: r.request_body, change_diff: r.change_diff,
                response_error: r.response_error, status_code: r.status_code, request_id: r.request_id,
            });
        }
        // Keep only the rows the page can still need: memory stays at about
        // twice the page whatever the number of tenants.
        merged.sort_by_key(|r| std::cmp::Reverse((r.at, r.id)));
        merged.truncate(per_tenant_cap as usize);
    }

    // `merged` is already in the per-tenant queries' own order (newest first,
    // then id), kept to the page's first `per_tenant_cap` rows.
    let start_idx = offset.max(0) as usize;
    let end_idx = (start_idx + (limit as usize) + 1).min(merged.len());
    let slice: Vec<GlobalPortalAuditRow> = if start_idx >= merged.len() {
        Vec::new()
    } else {
        merged.drain(start_idx..end_idx).collect()
    };
    Ok(Json(OffsetPage::from_overfetched(slice, limit, offset)))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GlobalSecurityAuditListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Restrict to events whose attempted `tenant_slug` matches (best-effort).
    pub tenant_slug: Option<String>,
    pub action: Option<String>,
    pub succeeded: Option<bool>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub request_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/security-audit",
    tag = "Admin Audit",
    params(GlobalSecurityAuditListQuery),
    responses(
        (status = 200, description = "Paginated cross-tenant list of pre-auth security events, including platform-level events with no resolvable tenant", body = OffsetPage<SecurityAuditRow>),
        (status = 400, description = "`start` is not before `end`", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_global_security_audit(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<GlobalSecurityAuditListQuery>,
) -> Result<Json<OffsetPage<SecurityAuditRow>>, ApiError> {
    super::check_bounds(query.start, query.end)?;
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();

    // security_audit is a global, no-RLS table — a super-admin sees ALL rows,
    // including events with NULL tenant_slug (failed login to an unknown
    // tenant, portal-login attempts) that no tenant-scoped read can surface.
    let mut sql = String::from(
        "SELECT id, at, tenant_id, tenant_slug, actor_identity, actor_ip, \
                method, path, route_template, action, succeeded, status_code, \
                request_body, response_error, request_id \
         FROM security_audit WHERE 1=1",
    );
    let mut idx = 1;
    if query.tenant_slug.is_some() { sql.push_str(&format!(" AND tenant_slug = ${idx}")); idx += 1; }
    if query.action.is_some() { sql.push_str(&format!(" AND action = ${idx}")); idx += 1; }
    if query.succeeded.is_some() { sql.push_str(&format!(" AND succeeded = ${idx}")); idx += 1; }
    if query.start.is_some() { sql.push_str(&format!(" AND at >= ${idx}")); idx += 1; }
    if query.end.is_some() { sql.push_str(&format!(" AND at < ${idx}")); idx += 1; }
    if query.request_id.is_some() { sql.push_str(&format!(" AND request_id = ${idx}")); idx += 1; }
    sql.push_str(&format!(" ORDER BY at DESC, id DESC LIMIT ${idx} OFFSET ${}", idx + 1));

    let mut q = sqlx::query_as::<_, SecurityAuditRow>(sqlx::AssertSqlSafe(&*sql));
    if let Some(ref slug) = query.tenant_slug { q = q.bind(slug); }
    if let Some(ref action) = query.action { q = q.bind(action); }
    if let Some(succeeded) = query.succeeded { q = q.bind(succeeded); }
    if let Some(start) = query.start { q = q.bind(start); }
    if let Some(end) = query.end { q = q.bind(end); }
    if let Some(request_id) = query.request_id { q = q.bind(request_id); }
    q = q.bind(limit + 1).bind(offset);

    let rows = q.fetch_all(state.db.global(Global::Infra)).await.map_err(|e| {
        tracing::error!("list global security_audit: {e}");
        ApiError::internal("failed to list security audit")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}
