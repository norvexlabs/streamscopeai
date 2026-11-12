//! Read surface for the operator [`crate::notifications`] feed — the Dashboard
//! Overview's notifications panel. List-only; producers + the dispatcher write
//! the rows (see [`crate::alerts`]). Tenant-scoped via `TenantConn` (RLS); an
//! optional `workspace_id` narrows to one workspace (the dashboard's global
//! workspace selector).

use axum::extract::Query;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{ApiError, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::TenantConn;

/// One notification row for the feed.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct NotificationItem {
    pub id: Uuid,
    /// `budget_breach` | `budget_approaching` | `session_major_alert` |
    /// `credential_expiring` | `guardrail_detection` | `upstream_unhealthy` |
    /// `upstream_recovered` | `appliance_upgrade_available` |
    /// `agent_analysis_failing` | `edge_sync_rows_dropped` |
    /// `mcp_upstream_unusable`.
    pub kind: String,
    /// 0 info, 1 warning, 2 critical.
    pub severity: i16,
    pub title: String,
    pub summary: String,
    /// `workspace` | `user` | `session` | `api_key` | `guardrail` |
    /// `upstream_server` | `mcp_upstream_server` — drives the UI deep-link.
    pub target_kind: Option<String>,
    pub target_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct NotificationListQuery {
    /// Narrow to one workspace (the dashboard's workspace selector). Rows with
    /// no workspace (e.g. session alerts) are excluded when this is set.
    pub workspace_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/notifications",
    tag = "Analytics",
    params(NotificationListQuery),
    responses(
        (status = 200, description = "Recent operator notifications, newest first.", body = OffsetPage<NotificationItem>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_notifications(
    mut db: TenantConn,
    Query(query): Query<NotificationListQuery>,
) -> Result<Json<OffsetPage<NotificationItem>>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let page = PageQuery {
        limit: query.limit,
        offset: query.offset,
    };
    let (limit, offset) = page.resolve();

    let ws_filter = if query.workspace_id.is_some() {
        " AND workspace_id = $4"
    } else {
        ""
    };
    let sql = format!(
        "SELECT id, kind, severity, title, summary, target_kind, target_id, workspace_id, created_at \
           FROM notifications \
          WHERE tenant_id = $1{ws_filter} \
          ORDER BY created_at DESC \
          LIMIT $2 OFFSET $3"
    );
    let mut q = sqlx::query_as::<_, NotificationItem>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(limit + 1) // overfetch to detect has_more
        .bind(offset);
    if let Some(ws) = query.workspace_id {
        q = q.bind(ws);
    }
    let rows = q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list notifications: {e}");
        ApiError::internal("database query failed")
    })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}
