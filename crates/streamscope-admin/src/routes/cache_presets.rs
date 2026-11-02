//! Cache-preset CRUD — named, reusable response-cache policies.
//!
//! A preset holds the knobs (mode, TTL, similarity threshold, sharing scope);
//! a `downstream_routes` row references one via `cache_preset_id`, and a NULL
//! reference means the alias is uncached. The mirror emits one route per
//! (model × invocation preset), so per-route cache columns would not scale —
//! a tenant defines a handful of presets and tunes them in one place, exactly
//! the relationship `model_presets` has with invocation settings.
//!
//! Deleting a preset sets every referencing route back to NULL (uncached).
//! That direction is deliberate: the fail-safe outcome of losing a policy is
//! *less* caching, never a wrongly-served answer.

use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionImpact, ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::TenantConn;
use crate::AdminState;

const MODES: [&str; 3] = ["exact", "semantic", "observe"];
const SHARE_SCOPES: [&str; 3] = ["workspace", "user", "tenant"];
/// Matches the schema's `cache_presets_ttl_check` upper bound (30 days).
const MAX_TTL_SECONDS: i32 = 2_592_000;

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct CachePreset {
    pub id: Uuid,
    pub name: String,
    /// `exact` | `semantic` | `observe`.
    pub mode: String,
    pub ttl_seconds: i32,
    /// Cosine-similarity floor for a semantic hit. Ignored in the other modes.
    pub threshold: f32,
    /// `workspace` | `user` | `tenant`.
    pub share_scope: String,
    /// How many aliases reference this preset. Drives the delete-impact warning.
    pub route_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCachePresetRequest {
    pub name: String,
    /// Defaults to `observe` — a new preset records before it serves, which is
    /// the tuning path the admin flow is built around.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i32>,
    #[serde(default)]
    pub threshold: Option<f32>,
    #[serde(default)]
    pub share_scope: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCachePresetRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i32>,
    #[serde(default)]
    pub threshold: Option<f32>,
    #[serde(default)]
    pub share_scope: Option<String>,
}

const PRESET_SELECT: &str = "SELECT p.id, p.name, p.mode, p.ttl_seconds, p.threshold, \
     p.share_scope, p.created_at, \
     (SELECT count(*) FROM downstream_routes r WHERE r.cache_preset_id = p.id) AS route_count \
     FROM cache_presets p";

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate(
    name: Option<&str>,
    mode: Option<&str>,
    ttl_seconds: Option<i32>,
    threshold: Option<f32>,
    share_scope: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(n) = name
        && n.trim().is_empty()
    {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if let Some(m) = mode
        && !MODES.contains(&m)
    {
        return Err(ApiError::bad_request(format!(
            "mode must be one of {}",
            MODES.join(", ")
        )));
    }
    if let Some(s) = share_scope
        && !SHARE_SCOPES.contains(&s)
    {
        return Err(ApiError::bad_request(format!(
            "share_scope must be one of {}",
            SHARE_SCOPES.join(", ")
        )));
    }
    if let Some(t) = ttl_seconds
        && !(1..=MAX_TTL_SECONDS).contains(&t)
    {
        return Err(ApiError::bad_request(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )));
    }
    if let Some(t) = threshold
        && !(0.0 < t && t <= 1.0)
    {
        return Err(ApiError::bad_request(
            "threshold must be greater than 0 and at most 1",
        ));
    }
    Ok(())
}

/// Map a unique-name violation onto the typed conflict code; everything else is
/// an internal error.
fn map_write_error(e: sqlx::Error, what: &str) -> ApiError {
    // `idx_cache_presets_name` is the only unique index on the table, so the
    // SQLSTATE alone identifies the collision — reading the index name out of the
    // driver's error text would make a migration rename silently downgrade this
    // 409 to a 500, on the one path no happy-path test exercises.
    if super::is_unique_violation(&e) {
        return ApiError::conflict("a cache preset with that name already exists", ApiErrorCode::CachePresetNameTaken);
    }
    tracing::error!("{what}: {e}");
    ApiError::internal("internal error")
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/cache-presets",
    tag = "Cache Presets",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated cache-preset list", body = OffsetPage<CachePreset>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_cache_presets(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<CachePreset>>, ApiError> {
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, CachePreset>(sqlx::AssertSqlSafe(&*format!(
        "{PRESET_SELECT} ORDER BY p.name ASC LIMIT $1 OFFSET $2"
    )))
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list cache presets: {e}");
        ApiError::internal("failed to list cache presets")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/cache-presets/{id}",
    tag = "Cache Presets",
    params(("id" = Uuid, Path, description = "Cache preset ID")),
    responses(
        (status = 200, description = "Cache preset", body = CachePreset),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_cache_preset(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<CachePreset>, ApiError> {
    let row = sqlx::query_as::<_, CachePreset>(sqlx::AssertSqlSafe(&*format!(
        "{PRESET_SELECT} WHERE p.id = $1"
    )))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("get cache preset: {e}");
            ApiError::internal("failed to load cache preset")
        })?
        .ok_or_else(|| {
            ApiError::not_found("cache preset not found", ApiErrorCode::CachePresetNotFound)
        })?;
    Ok(Json(row))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/cache-presets",
    tag = "Cache Presets",
    request_body = CreateCachePresetRequest,
    responses(
        (status = 201, description = "Cache preset created", body = CachePreset),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_cache_preset(
    mut db: TenantConn,
    Json(body): Json<CreateCachePresetRequest>,
) -> Result<(StatusCode, Json<CachePreset>), ApiError> {
    validate(
        Some(&body.name),
        body.mode.as_deref(),
        body.ttl_seconds,
        body.threshold,
        body.share_scope.as_deref(),
    )?;
    let tenant_id = db.tenant_uuid();

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO cache_presets (tenant_id, name, mode, ttl_seconds, threshold, share_scope) \
         VALUES ($1, $2, COALESCE($3, 'observe'), COALESCE($4, 3600), \
                 COALESCE($5, 0.9), COALESCE($6, 'workspace')) \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(body.name.trim())
    .bind(body.mode.as_deref())
    .bind(body.ttl_seconds)
    .bind(body.threshold)
    .bind(body.share_scope.as_deref())
    .fetch_one(db.conn())
    .await
    .map_err(|e| map_write_error(e, "create cache preset"))?;

    let row = sqlx::query_as::<_, CachePreset>(sqlx::AssertSqlSafe(&*format!(
        "{PRESET_SELECT} WHERE p.id = $1"
    )))
        .bind(id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("reload created cache preset: {e}");
            ApiError::internal("failed to create cache preset")
        })?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/cache-presets/{id}",
    tag = "Cache Presets",
    params(("id" = Uuid, Path, description = "Cache preset ID")),
    request_body = UpdateCachePresetRequest,
    responses(
        (status = 200, description = "Updated cache preset", body = CachePreset),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_cache_preset(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateCachePresetRequest>,
) -> Result<Json<CachePreset>, ApiError> {
    validate(
        body.name.as_deref(),
        body.mode.as_deref(),
        body.ttl_seconds,
        body.threshold,
        body.share_scope.as_deref(),
    )?;

    let updated: Option<Uuid> = sqlx::query_scalar(
        "UPDATE cache_presets SET \
             name = COALESCE($2, name), \
             mode = COALESCE($3, mode), \
             ttl_seconds = COALESCE($4, ttl_seconds), \
             threshold = COALESCE($5, threshold), \
             share_scope = COALESCE($6, share_scope) \
         WHERE id = $1 RETURNING id",
    )
    .bind(id)
    .bind(body.name.as_deref().map(str::trim))
    .bind(body.mode.as_deref())
    .bind(body.ttl_seconds)
    .bind(body.threshold)
    .bind(body.share_scope.as_deref())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| map_write_error(e, "update cache preset"))?;

    if updated.is_none() {
        return Err(
            ApiError::not_found("cache preset not found", ApiErrorCode::CachePresetNotFound)
        );
    }

    let row = sqlx::query_as::<_, CachePreset>(sqlx::AssertSqlSafe(&*format!(
        "{PRESET_SELECT} WHERE p.id = $1"
    )))
        .bind(id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("reload updated cache preset: {e}");
            ApiError::internal("failed to update cache preset")
        })?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/cache-presets/{id}",
    tag = "Cache Presets",
    params(("id" = Uuid, Path, description = "Cache preset ID")),
    responses(
        (status = 200, description = "Cache preset deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_cache_preset(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {

    // Count referencing aliases before the delete so the response can state the
    // impact; the FK's ON DELETE SET NULL does the actual unbinding.
    let routes_uncached: i64 =
        sqlx::query_scalar("SELECT count(*) FROM downstream_routes WHERE cache_preset_id = $1")
            .bind(id)
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("count routes referencing cache preset: {e}");
                ApiError::internal("failed to delete cache preset")
            })?;

    let deleted = sqlx::query("DELETE FROM cache_presets WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete cache preset: {e}");
            ApiError::internal("failed to delete cache preset")
        })?;

    if deleted.rows_affected() == 0 {
        return Err(
            ApiError::not_found("cache preset not found", ApiErrorCode::CachePresetNotFound)
        );
    }

    Ok(Json(
        ActionResponse::ok()
            .with_message("cache preset deleted")
            .with_impact(ActionImpact { routes_uncached: Some(routes_uncached), ..ActionImpact::default() }),
    ))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn cache_presets_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::get;

    axum::Router::new()
        .route("/", get(list_cache_presets).post(create_cache_preset))
        .route(
            "/{id}",
            get(get_cache_preset)
                .patch(update_cache_preset)
                .delete(delete_cache_preset),
        )
}
