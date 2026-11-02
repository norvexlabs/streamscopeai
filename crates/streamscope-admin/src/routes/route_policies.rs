//! Route policy CRUD — per-downstream path-level controls for catch-all proxy forwarding.
//!
//! Route policies define which `/v1/*` paths are forwarded as-is to the upstream,
//! with per-path rate limiting, body size limits, and audit controls.


use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::TenantConn;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct RoutePolicyRow {
    pub id: Uuid,
    pub downstream_id: Uuid,
    pub path_pattern: String,
    pub enabled: bool,
    pub rate_limit_rpm: Option<i32>,
    pub max_body_bytes: i64,
    pub audit_body: bool,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateRoutePolicy {
    pub downstream_id: Uuid,
    pub path_pattern: String,
    pub enabled: Option<bool>,
    pub rate_limit_rpm: Option<i32>,
    pub max_body_bytes: Option<i64>,
    pub audit_body: Option<bool>,
    pub description: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateRoutePolicy {
    pub enabled: Option<bool>,
    /// Absent leaves it; `null` removes the limit.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub rate_limit_rpm: Option<Option<i32>>,
    /// Not clearable: `0` falls back to the deployment-wide body limit.
    pub max_body_bytes: Option<i64>,
    pub audit_body: Option<bool>,
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RoutePolicyListQuery {
    pub downstream_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/route-policies",
    tag = "Route Policies",
    params(RoutePolicyListQuery),
    responses(
        (status = 200, description = "Paginated list of route policies", body = TotalPage<RoutePolicyRow>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_route_policies(
    mut db: TenantConn,
    Query(query): Query<RoutePolicyListQuery>,
) -> Result<Json<TotalPage<RoutePolicyRow>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    let tenant_id = db.tenant_uuid();

    let (total, rows) = if let Some(downstream_id) = query.downstream_id {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM route_policies WHERE tenant_id = $1 AND downstream_id = $2",
        )
        .bind(tenant_id)
        .bind(downstream_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count route policies: {e}");
            ApiError::internal("failed to list route policies")
        })?;
        let rows = sqlx::query_as::<_, RoutePolicyRow>(
            r#"SELECT id, downstream_id, path_pattern, enabled, rate_limit_rpm,
                      max_body_bytes, audit_body, description, created_at, updated_at
               FROM route_policies
               WHERE tenant_id = $1 AND downstream_id = $2
               ORDER BY path_pattern LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(downstream_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list route policies: {e}");
            ApiError::internal("failed to list route policies")
        })?;
        (total, rows)
    } else {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM route_policies WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count route policies: {e}");
            ApiError::internal("failed to list route policies")
        })?;
        let rows = sqlx::query_as::<_, RoutePolicyRow>(
            r#"SELECT id, downstream_id, path_pattern, enabled, rate_limit_rpm,
                      max_body_bytes, audit_body, description, created_at, updated_at
               FROM route_policies
               WHERE tenant_id = $1
               ORDER BY downstream_id, path_pattern LIMIT $2 OFFSET $3"#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list route policies: {e}");
            ApiError::internal("failed to list route policies")
        })?;
        (total, rows)
    };

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/route-policies",
    tag = "Route Policies",
    request_body = CreateRoutePolicy,
    responses(
        (status = 201, description = "Route policy created", body = RoutePolicyRow),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "Duplicate path pattern for downstream", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_route_policy(
    mut db: TenantConn,
    Json(body): Json<CreateRoutePolicy>,
) -> Result<(StatusCode, Json<RoutePolicyRow>), ApiError> {
    // Validate path_pattern starts with /
    if !body.path_pattern.starts_with('/') {
        return Err(ApiError::bad_request("path_pattern must start with '/'")
            .code(ApiErrorCode::RoutePathPatternInvalid));
    }

    // Verify downstream provider exists and belongs to tenant.
    let downstream_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM downstream_providers WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(body.downstream_id)
    .bind(db.tenant_uuid())
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create route policy check downstream: {e}");
        ApiError::internal("failed to verify downstream provider")
    })?;

    if !downstream_exists {
        return Err(ApiError::bad_request("downstream provider not found")
            .code(ApiErrorCode::DownstreamNotFound));
    }

    let enabled = body.enabled.unwrap_or(false);
    let max_body_bytes = body.max_body_bytes.unwrap_or(10_485_760); // 10 MiB default
    let audit_body = body.audit_body.unwrap_or(false);

    let row = sqlx::query_as::<_, RoutePolicyRow>(
        r#"INSERT INTO route_policies (tenant_id, downstream_id, path_pattern, enabled, rate_limit_rpm, max_body_bytes, audit_body, description)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, downstream_id, path_pattern, enabled, rate_limit_rpm, max_body_bytes, audit_body, description, created_at, updated_at"#,
    )
    .bind(db.tenant_uuid())
    .bind(body.downstream_id)
    .bind(&body.path_pattern)
    .bind(enabled)
    .bind(body.rate_limit_rpm)
    .bind(max_body_bytes)
    .bind(audit_body)
    .bind(&body.description)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("route policy already exists for this downstream + path pattern", ApiErrorCode::RoutePolicyTaken)
        } else {
            tracing::error!("create route policy: {e}");
            ApiError::internal("failed to create route policy")
        }
    })?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/route-policies/{id}",
    tag = "Route Policies",
    params(("id" = Uuid, Path, description = "Route policy ID")),
    request_body = UpdateRoutePolicy,
    responses(
        (status = 200, description = "Updated route policy", body = RoutePolicyRow),
        (status = 404, description = "Route policy not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_route_policy(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRoutePolicy>,
) -> Result<Json<RoutePolicyRow>, ApiError> {
    let row = sqlx::query_as::<_, RoutePolicyRow>(
        r#"UPDATE route_policies SET
               enabled = COALESCE($2, enabled),
               rate_limit_rpm = CASE WHEN $8 THEN $3::integer ELSE rate_limit_rpm END,
               max_body_bytes = COALESCE($4, max_body_bytes),
               audit_body = COALESCE($5, audit_body),
               description = CASE WHEN $9 THEN $6::text ELSE description END,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $7
           RETURNING id, downstream_id, path_pattern, enabled, rate_limit_rpm, max_body_bytes, audit_body, description, created_at, updated_at"#,
    )
    .bind(id)
    .bind(body.enabled)
    .bind(body.rate_limit_rpm.flatten())
    .bind(body.max_body_bytes)
    .bind(body.audit_body)
    .bind(body.description.as_ref().and_then(|d| d.as_deref()))
    .bind(db.tenant_uuid())
    .bind(body.rate_limit_rpm.is_some()) // $8
    .bind(body.description.is_some()) // $9
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update route policy: {e}");
        ApiError::internal("failed to update route policy")
    })?
    .ok_or_else(|| ApiError::not_found("route policy not found", ApiErrorCode::RoutePolicyNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/route-policies/{id}",
    tag = "Route Policies",
    params(("id" = Uuid, Path, description = "Route policy ID")),
    responses(
        (status = 200, description = "Route policy deleted", body = ActionResponse),
        (status = 404, description = "Route policy not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_route_policy(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let result = sqlx::query(
        "DELETE FROM route_policies WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete route policy: {e}");
        ApiError::internal("failed to delete route policy")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("route policy not found", ApiErrorCode::RoutePolicyNotFound));
    }

    Ok(Json(ActionResponse::ok()))
}
