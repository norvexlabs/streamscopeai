//! Internal platform-host callbacks — host daemon → admin-api.
//!
//! Gated by `INTERNAL_SERVICE_SECRET` (same shared secret the OIDC internal
//! endpoints use). Called by the Kairos VM's host daemon:
//!
//! - `POST /api/v1/internal/maintenance/platform-purge` — the daemon's disk
//!   watch reports soft or hard pressure; admin-api decides the retention it
//!   enforces across every tenant for this purge ([`pressure_retention_days`]),
//!   never below `admin_settings().db_size_min_retention_days`.
//!
//! No `TenantConn` extractor for the purge response — platform-level under the
//! SYSTEM tenant. Pattern mirrors `auth_config::get_tenant_oidc_config`.

use std::sync::Arc;

use axum::Extension;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ApiError, ApiErrorResponse};
use crate::AdminState;
use crate::db::tenant::{TenantConn, TenantId};
use crate::middleware::request_id::RequestId;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Internal platform-host endpoints. Mounted at `/api/v1/internal`.
///
/// The service-secret check is a **layer**, not a line in each handler, and the
/// difference is load-bearing: axum runs a handler's extractors before its body
/// executes, so an inline check happens only after `Json<_>` has already read
/// and parsed the request. That lets an unauthenticated caller on the public
/// vhost make this process buffer and deserialize arbitrary bodies. Out here the
/// refusal lands before anything is read — the same reason the sibling OIDC
/// router puts its copy outermost.
pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/maintenance/platform-purge", post(post_platform_purge))
        .route_layer(axum::middleware::from_fn(
            super::oidc_rp::internal_service_secret_mw,
        ))
}

// ---------------------------------------------------------------------------
// platform-purge
// ---------------------------------------------------------------------------

/// How full the disk is, as the host daemon's disk watch classifies it. It
/// reports only the two levels that call for a purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskPressureLevel {
    /// At `soft_pct` or past it.
    Soft,
    /// At `hard_pct` or past it.
    Hard,
}

/// The host daemon's disk-pressure report.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PlatformPurgeRequest {
    pub level: DiskPressureLevel,
    /// Percent of the persistent partition in use.
    pub used_pct: f64,
    pub soft_pct: i64,
    pub hard_pct: i64,
}

/// Retention (days) a soft-pressure purge keeps when the floor is lower.
pub const SOFT_PRESSURE_RETENTION_DAYS: i64 = 15;

/// The retention a purge under `level` enforces: soft keeps
/// [`SOFT_PRESSURE_RETENTION_DAYS`], hard goes down to the floor — and neither
/// goes below the floor, itself never below one day (a floor of 0 would purge
/// everything).
pub fn pressure_retention_days(level: DiskPressureLevel, floor: i64) -> i64 {
    let floor = floor.max(1);
    match level {
        DiskPressureLevel::Soft => floor.max(SOFT_PRESSURE_RETENTION_DAYS),
        DiskPressureLevel::Hard => floor,
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformPurgeResponse {
    pub status: String,
    pub effective_retention_days: i64,
    pub summary: crate::retention::PurgeSummary,
}

#[utoipa::path(
    post,
    path = "/api/v1/internal/maintenance/platform-purge",
    tag = "Platform",
    request_body = PlatformPurgeRequest,
    responses(
        (status = 200, description = "Purge complete", body = PlatformPurgeResponse),
        (status = 401, description = "Missing or invalid service secret", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "A disk-pressure purge is already running", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn post_platform_purge(
    State(state): State<Arc<AdminState>>,
    Extension(RequestId(req_id)): Extension<RequestId>,
    Json(req): Json<PlatformPurgeRequest>,
) -> Result<Json<PlatformPurgeResponse>, ApiError> {
    // Single-flight: the daemon retries a report it got no answer to a minute
    // later, so a purge longer than its deadline must not start a second one.
    let Ok(guard) = PURGE_RUNNING.clone().try_lock_owned() else {
        return Err(ApiError::service_unavailable("a disk-pressure purge is already running"));
    };
    let floor = crate::settings::admin_settings().db_size_min_retention_days;
    let effective = pressure_retention_days(req.level, floor);

    tracing::info!(
        level = ?req.level,
        used_pct = req.used_pct,
        retention_days = effective,
        "platform-purge: starting cross-tenant purge under disk pressure"
    );

    // The purge and its audit row run in their own task: a caller that stops
    // waiting (the daemon's deadline is shorter than a large purge) drops this
    // handler, never the purge — its last step is the one that frees the disk.
    let task = tokio::spawn(async move {
        let _guard = guard;
        let summary = crate::retention::run_purge_with_override(&state.db, Some(effective))
            .await
            .map_err(|e| {
                tracing::error!("platform-purge run_purge_with_override: {e}");
                ApiError::internal("platform purge failed")
            })?;
        audit_platform_purge(&state, req_id, &req, effective, &summary).await;
        Ok::<_, ApiError>(summary)
    });
    let summary = task.await.map_err(|e| {
        tracing::error!("platform-purge task: {e}");
        ApiError::internal("platform purge failed")
    })??;

    Ok(Json(PlatformPurgeResponse {
        status: "ok".into(),
        effective_retention_days: effective,
        summary,
    }))
}

/// Held while a disk-pressure purge runs.
static PURGE_RUNNING: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

/// The SYSTEM-tenant admin_audit row of a purge, so operators can see what
/// fired and why. A failure is logged, never returned: the purge already ran.
async fn audit_platform_purge(
    state: &AdminState,
    req_id: uuid::Uuid,
    req: &PlatformPurgeRequest,
    effective: i64,
    summary: &crate::retention::PurgeSummary,
) {
    let mut db = match TenantConn::acquire(&state.db, TenantId::SYSTEM).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("platform-purge admin_audit TenantConn (purge already ran): {e}");
            return;
        }
    };

    let body_json = serde_json::json!({
        "level": req.level,
        "used_pct": req.used_pct,
        "soft_pct": req.soft_pct,
        "hard_pct": req.hard_pct,
        "effective_retention_days": effective,
    });
    let summary_json = serde_json::to_value(summary).unwrap_or(serde_json::Value::Null);

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO admin_audit
          (tenant_id, actor_id, actor_email, actor_ip, is_super_admin,
           method, path, route_template, action, resource_kind, resource_id,
           request_body, change_diff, status_code, request_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
    )
    .bind(TenantId::SYSTEM.as_uuid())
    .bind(uuid::Uuid::nil())
    .bind(None::<String>)
    .bind(None::<String>)
    .bind(false)
    .bind("POST")
    .bind("/api/v1/internal/maintenance/platform-purge")
    .bind(Some("/maintenance/platform-purge"))
    .bind("maintenance.platform_purge")
    .bind("maintenance")
    .bind(None::<String>)
    .bind(Some(&body_json))
    .bind(Some(&summary_json))
    .bind(200i16)
    .bind(req_id)
    .execute(db.conn())
    .await
    {
        tracing::error!("platform-purge admin_audit insert failed (purge already ran): {e}");
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_pressure_keeps_fifteen_days_unless_the_floor_is_higher() {
        assert_eq!(pressure_retention_days(DiskPressureLevel::Soft, 7), 15);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Soft, 14), 15);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Soft, 15), 15);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Soft, 16), 16);
    }

    #[test]
    fn hard_pressure_goes_down_to_the_floor_and_no_further() {
        assert_eq!(pressure_retention_days(DiskPressureLevel::Hard, 7), 7);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Hard, 30), 30);
    }

    #[test]
    fn a_floor_below_one_day_reads_as_one_day() {
        assert_eq!(pressure_retention_days(DiskPressureLevel::Hard, 1), 1);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Hard, 0), 1);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Hard, -5), 1);
        assert_eq!(pressure_retention_days(DiskPressureLevel::Soft, 0), 15);
    }

    #[test]
    fn the_daemons_report_decodes_and_a_level_without_pressure_is_refused() {
        let req: PlatformPurgeRequest =
            serde_json::from_str(r#"{"level":"hard","used_pct":91.5,"soft_pct":75,"hard_pct":90}"#).expect("decodes");
        assert_eq!(req.level, DiskPressureLevel::Hard);
        for level in ["none", "unknown", "Soft"] {
            let body = format!(r#"{{"level":"{level}","used_pct":1,"soft_pct":75,"hard_pct":90}}"#);
            assert!(serde_json::from_str::<PlatformPurgeRequest>(&body).is_err(), "{level} accepted");
        }
    }
}
