//! Changelog endpoints — "What's New" notification per admin.
//!
//! Content is embedded at compile time from `CHANGELOG.md` at the repo root.
//! Per-admin tracking uses `admin_accounts.last_seen_version`.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::db::tenant::{AdminTenantCtx, TenantConn};
use crate::AdminState;
use super::{ActionResponse, ApiError};

/// Embedded changelog content (compiled from repo root).
const CHANGELOG_CONTENT: &str = include_str!("../../../../CHANGELOG.md");

/// Current application version.
const APP_VERSION: &str = streamscope_core::VERSION;

/// Changelog response with markdown content and current version.
#[derive(Serialize, ToSchema)]
pub struct ChangelogResponse {
    /// Markdown content of the full changelog.
    pub content: String,
    /// Current application version.
    pub current_version: String,
}

/// GET /api/v1/admin/changelog — return changelog content.
#[utoipa::path(
    get,
    path = "/api/v1/admin/changelog",
    tag = "Changelog",
    responses(
        (status = 200, description = "Changelog content", body = ChangelogResponse),
        (status = 401, description = "Unauthorized", body = super::ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_changelog() -> Json<ChangelogResponse> {
    Json(ChangelogResponse {
        content: CHANGELOG_CONTENT.to_string(),
        current_version: APP_VERSION.to_string(),
    })
}

/// POST /api/v1/admin/changelog/actions/dismiss — mark changelog as seen for this admin.
#[utoipa::path(
    post,
    path = "/api/v1/admin/changelog/actions/dismiss",
    tag = "Changelog",
    responses(
        (status = 200, description = "Changelog dismissed", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = super::ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn dismiss_changelog(
    State(state): State<Arc<AdminState>>,
    ctx: axum::extract::Extension<AdminTenantCtx>,
) -> Result<Json<ActionResponse>, ApiError> {
    let mut db = TenantConn::acquire(&state.db, ctx.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("changelog dismiss db: {e}");
            ApiError::internal("internal error")
        })?;

    sqlx::query("UPDATE admin_accounts SET last_seen_version = $1 WHERE id = $2")
        .bind(APP_VERSION)
        .bind(ctx.admin_account_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("changelog dismiss update: {e}");
            ApiError::internal("internal error")
        })?;

    Ok(Json(ActionResponse::ok()))
}

/// Check whether this admin has pending changelog entries.
pub fn is_changelog_pending(last_seen_version: Option<&str>) -> bool {
    match last_seen_version {
        None => true,
        Some(v) => v != APP_VERSION,
    }
}
