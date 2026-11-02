//! QoS classes — the tenant's priority bands under load.
//!
//! A class is a name, a `rank` (lower is more important) and how it behaves when
//! no upstream has headroom: held until capacity or its TTL expires, or — when it
//! is `sheddable` — refused at once. The rank is abstract and reaches no wire on
//! its own; the target server's scheduling dialect decides how it is expressed.
//!
//! A workspace picks the class its keys default to, a key may override it within
//! what its holder is entitled to, and a route target may accept only some
//! classes. Every one of those is a reference this module refuses to break: a
//! class in use is deleted only after its references are moved somewhere else.
//!
//! Builtins follow the seed-sync pattern — an edit flips `is_builtin` false and
//! is never overwritten, a delete is a `suppressed` row. The proxy resolves a
//! request's class from its config body, which the change triggers keep current.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};
use crate::AdminState;

/// The longest hold a class may ask for. The operator's own maximum is applied
/// again when the value is resolved, so this only bounds what can be stored.
// The schema's own bound (`qos_classes`' CHECK). A deployment's
// `QOS_QUEUE_TTL_MAX_MS` defaults below it, under the clients' own timeouts.
const MAX_QUEUE_TTL_MS: i32 = 600_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct QosClassRow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// Lower is served first. Ties are broken by the fairness order between
    /// users, never by arrival.
    pub rank: i32,
    /// Refused at once at saturation instead of being held.
    pub sheddable: bool,
    /// How long a request of this class may be held, in milliseconds. `null`
    /// uses the deployment's default hold.
    pub queue_ttl_ms: Option<i32>,
    /// The class every workspace without one of its own resolves to.
    pub is_default: bool,
    /// `interactive` or `automation`: the class a key minted by that kind of
    /// principal gets. `null` on every other class.
    pub mint_default_for: Option<String>,
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A class plus what currently points at it — the counts the delete flow needs.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct QosClass {
    #[serde(flatten)]
    #[sqlx(flatten)]
    pub class: QosClassRow,
    /// Workspaces whose keys default to this class.
    pub workspace_count: i64,
    /// Live keys that name this class themselves.
    pub key_count: i64,
    /// Route targets that accept this class explicitly.
    pub route_target_count: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateQosClassRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rank: i32,
    #[serde(default)]
    pub sheddable: bool,
    #[serde(default)]
    pub queue_ttl_ms: Option<i32>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateQosClassRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rank: Option<i32>,
    #[serde(default)]
    pub sheddable: Option<bool>,
    /// Present and `null` clears the class's own TTL (back to the deployment's
    /// default); absent leaves it as it is.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub queue_ttl_ms: Option<Option<i32>>,
}

#[derive(Deserialize, ToSchema)]
pub struct SetMintDefaultRequest {
    /// `interactive`, `automation`, or `null` to take the star off this class.
    pub kind: Option<String>,
}

/// A deployment setting as the gateways run it.
#[derive(Serialize, ToSchema)]
pub struct DeploymentMs {
    /// The lowest and highest value among the connected gateways, in
    /// milliseconds — equal when they agree.
    pub low_ms: u64,
    pub high_ms: u64,
    /// `true` when read from what connected gateways report running; `false`
    /// when none has reported yet, and the value is what they start with.
    pub reported: bool,
}

/// The operator's hold limits every class resolves against. Read-only here:
/// they bound a gateway's memory and shutdown, so only the operator sets them.
#[derive(Serialize, ToSchema)]
pub struct QosDeploymentLimits {
    /// How long a request is held when its class names no wait of its own.
    /// `null` (as are the two below) when no gateway states a readable
    /// number: a value it could not parse is not a limit to state as zero.
    pub default_wait: Option<DeploymentMs>,
    /// The longest hold any class gets: a class asking for more is held this long.
    pub max_wait: Option<DeploymentMs>,
    /// What a class that names no wait of its own is held for: the default,
    /// capped by the maximum, per gateway.
    pub default_hold: Option<DeploymentMs>,
    /// Gateway replicas connected now. Holds, and a server's in-flight limit,
    /// apply per replica.
    pub gateway_replicas: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeleteQosClassQuery {
    /// Move every workspace, key and route target on this class to that class
    /// first. Without it, a class in use is refused.
    #[serde(default)]
    pub reassign_to: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CLASS_COLUMNS: &str = "id, name, description, rank, sheddable, queue_ttl_ms, \
                             is_default, mint_default_for, is_builtin, created_at, updated_at";

fn validate_ttl(ttl: Option<i32>) -> Result<(), ApiError> {
    match ttl {
        Some(ms) if !(1..=MAX_QUEUE_TTL_MS).contains(&ms) => Err(ApiError::bad_request(format!(
            "queue_ttl_ms must be between 1 and {MAX_QUEUE_TTL_MS}"
        ))
        .code(ApiErrorCode::ValidationFailed)),
        _ => Ok(()),
    }
}

fn validate_name(name: &str) -> Result<&str, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("name is required").code(ApiErrorCode::ValidationFailed));
    }
    Ok(trimmed)
}

fn name_taken(e: &sqlx::Error) -> ApiError {
    if super::is_unique_violation(e) {
        ApiError::conflict("a QoS class with this name already exists", ApiErrorCode::QosClassNameTaken)
    } else {
        tracing::error!("qos class write: {e}");
        ApiError::internal("failed to write QoS class")
    }
}

/// How many workspaces, live keys and route targets name this class.
async fn reference_counts(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<(i64, i64, i64), ApiError> {
    sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT (SELECT count(*) FROM workspaces w WHERE w.qos_class_id = $1), \
                (SELECT count(*) FROM api_keys k WHERE k.qos_class_id = $1 AND k.revoked_at IS NULL), \
                (SELECT count(*) FROM route_qos_classes r WHERE r.qos_class_id = $1)",
    )
    .bind(id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("qos class references: {e}");
        ApiError::internal("failed to count QoS class references")
    })
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/qos-classes",
    tag = "QoS",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated class list, most important first", body = OffsetPage<QosClass>),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_qos_classes(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<QosClass>>, ApiError> {
    let (limit, offset) = page.resolve();
    let items = sqlx::query_as::<_, QosClass>(sqlx::AssertSqlSafe(format!(
        "SELECT {CLASS_COLUMNS}, \
                (SELECT count(*) FROM workspaces w WHERE w.qos_class_id = q.id) AS workspace_count, \
                (SELECT count(*) FROM api_keys k WHERE k.qos_class_id = q.id AND k.revoked_at IS NULL) AS key_count, \
                (SELECT count(*) FROM route_qos_classes r WHERE r.qos_class_id = q.id) AS route_target_count \
         FROM qos_classes q WHERE NOT suppressed \
         ORDER BY rank ASC, name ASC LIMIT $1 OFFSET $2"
    )))
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list qos classes: {e}");
        ApiError::internal("failed to list QoS classes")
    })?;

    Ok(Json(OffsetPage::from_overfetched(items, limit, offset)))
}

/// The lowest and highest of a figure computed per gateway.
fn span(values: impl Iterator<Item = u64> + Clone, reported: bool) -> Option<DeploymentMs> {
    Some(DeploymentMs { low_ms: values.clone().min()?, high_ms: values.max()?, reported })
}

/// The deployment's hold limits, each figure taken per gateway first. The
/// default hold a class without its own gets is `min(default, max)` on ONE
/// gateway — combining the fleet's lowest default with its lowest maximum
/// would state a hold no gateway gives.
pub(crate) fn deployment_limits(
    fleet: &super::runtime_config::FleetSettings,
    gateway_replicas: i64,
) -> QosDeploymentLimits {
    let per_gateway: Vec<(u64, u64)> = fleet
        .gateways
        .iter()
        .filter_map(|g| {
            let default = g.get("QOS_QUEUE_TTL_MS")?.trim().parse::<u64>().ok()?;
            let max = g.get("QOS_QUEUE_TTL_MAX_MS")?.trim().parse::<u64>().ok()?;
            Some((default, max))
        })
        .collect();
    QosDeploymentLimits {
        default_wait: span(per_gateway.iter().map(|(d, _)| *d), fleet.reported),
        max_wait: span(per_gateway.iter().map(|(_, m)| *m), fleet.reported),
        default_hold: span(per_gateway.iter().map(|(d, m)| (*d).min(*m)), fleet.reported),
        gateway_replicas,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/qos-classes/deployment-limits",
    tag = "QoS",
    responses(
        (status = 200, description = "The hold limits the gateways apply to every class", body = QosDeploymentLimits),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_qos_deployment_limits(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<QosDeploymentLimits>, ApiError> {
    let fleet = super::runtime_config::fleet_settings(&state.db, &["QOS_QUEUE_TTL_MS", "QOS_QUEUE_TTL_MAX_MS"])
        .await
        .map_err(|e| {
            tracing::error!("qos deployment limits: {e}");
            ApiError::internal("failed to read the deployment limits")
        })?;
    let replicas = super::upstream_endpoints::connected_gateway_replicas(&state.db).await?;
    Ok(Json(deployment_limits(&fleet, replicas)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/qos-classes",
    tag = "QoS",
    request_body = CreateQosClassRequest,
    responses(
        (status = 201, description = "Class created", body = QosClassRow),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_qos_class(
    mut db: TenantConn,
    Json(req): Json<CreateQosClassRequest>,
) -> Result<(StatusCode, Json<QosClassRow>), ApiError> {
    let name = validate_name(&req.name)?;
    validate_ttl(req.queue_ttl_ms)?;
    let tenant_id = db.tenant_uuid();

    // `class_key` is the seed identity; a hand-made class gets its own id there
    // so it can never collide with a builtin the seed ships later.
    let row = sqlx::query_as::<_, QosClassRow>(sqlx::AssertSqlSafe(format!(
        "INSERT INTO qos_classes \
           (tenant_id, class_key, name, description, rank, sheddable, queue_ttl_ms, is_builtin) \
         VALUES ($1, gen_random_uuid()::text, $2, $3, $4, $5, $6, false) \
         RETURNING {CLASS_COLUMNS}"
    )))
    .bind(tenant_id)
    .bind(name)
    .bind(&req.description)
    .bind(req.rank)
    .bind(req.sheddable)
    .bind(req.queue_ttl_ms)
    .fetch_one(db.conn())
    .await
    .map_err(|e| name_taken(&e))?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/qos-classes/{id}",
    tag = "QoS",
    params(("id" = Uuid, Path, description = "QoS class id")),
    responses(
        (status = 200, description = "The class and what points at it", body = QosClass),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_qos_class(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<QosClass>, ApiError> {
    let row = sqlx::query_as::<_, QosClassRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {CLASS_COLUMNS} FROM qos_classes WHERE id = $1 AND NOT suppressed"
    )))
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("load qos class: {e}");
        ApiError::internal("failed to load QoS class")
    })?
    .ok_or_else(|| {
        ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
    })?;

    let (workspace_count, key_count, route_target_count) =
        reference_counts(db.conn(), id).await?;
    Ok(Json(QosClass { class: row, workspace_count, key_count, route_target_count }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/qos-classes/{id}",
    tag = "QoS",
    params(("id" = Uuid, Path, description = "QoS class id")),
    request_body = UpdateQosClassRequest,
    responses(
        (status = 200, description = "Class updated", body = QosClassRow),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_qos_class(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateQosClassRequest>,
) -> Result<Json<QosClassRow>, ApiError> {
    let name = req.name.as_deref().map(validate_name).transpose()?;
    if let Some(ttl) = req.queue_ttl_ms {
        validate_ttl(ttl)?;
    }

    // An edited builtin stops being seed-owned, exactly as every other seeded
    // collection: the seed must not overwrite what an admin has changed.
    let row = sqlx::query_as::<_, QosClassRow>(sqlx::AssertSqlSafe(format!(
        "UPDATE qos_classes SET \
           name = COALESCE($2, name), \
           description = COALESCE($3, description), \
           rank = COALESCE($4, rank), \
           sheddable = COALESCE($5, sheddable), \
           queue_ttl_ms = CASE WHEN $6 THEN $7 ELSE queue_ttl_ms END, \
           is_builtin = false, \
           updated_at = now() \
         WHERE id = $1 AND NOT suppressed \
         RETURNING {CLASS_COLUMNS}"
    )))
    .bind(id)
    .bind(name)
    .bind(req.description.as_deref())
    .bind(req.rank)
    .bind(req.sheddable)
    .bind(req.queue_ttl_ms.is_some())
    .bind(req.queue_ttl_ms.flatten())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| name_taken(&e))?
    .ok_or_else(|| {
        ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
    })?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/qos-classes/{id}",
    tag = "QoS",
    params(("id" = Uuid, Path, description = "QoS class id"), DeleteQosClassQuery),
    responses(
        (status = 200, description = "Class deleted", body = ActionResponse),
        (status = 400, description = "Invalid reassignment target", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Default class, or still in use", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_qos_class(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(q): Query<DeleteQosClassQuery>,
) -> Result<Json<ActionResponse>, ApiError> {

    let row: Option<(bool, bool)> =
        sqlx::query_as("SELECT is_default, seeded FROM qos_classes WHERE id = $1 AND NOT suppressed")
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("load qos class: {e}");
                ApiError::internal("failed to load QoS class")
            })?;
    let Some((is_default, seeded)) = row else {
        return Err(
            ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
        );
    };
    if is_default {
        return Err(ApiError::conflict(
            "the default class cannot be deleted — make another class the default first",
            ApiErrorCode::QosClassDefaultProtected,
        ));
    }

    if let Some(target) = q.reassign_to {
        if target == id {
            return Err(ApiError::bad_request("reassign_to must name another class")
                .code(ApiErrorCode::ValidationFailed));
        }
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM qos_classes WHERE id = $1 AND NOT suppressed")
                .bind(target)
                .fetch_optional(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!("load reassign target: {e}");
                    ApiError::internal("failed to load QoS class")
                })?;
        if exists.is_none() {
            return Err(ApiError::bad_request("reassign_to does not name a class of this tenant")
                .code(ApiErrorCode::QosClassNotFound));
        }
    }

    let (workspaces, keys, targets) = reference_counts(db.conn(), id).await?;
    let referenced = workspaces + keys + targets;
    if referenced > 0 && q.reassign_to.is_none() {
        return Err(ApiError::conflict(format!(
            "still in use by {workspaces} workspace(s), {keys} key(s) and {targets} route target(s)"
        ), ApiErrorCode::QosClassInUse));
    }

    // One transaction: move every reference, then remove the class. A builtin is
    // suppressed rather than deleted (the seed would bring it back), and loses
    // its mint star — a suppressed row still occupies the partial unique index,
    // so leaving the star would block moving it to another class.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete qos class (begin): {e}");
        ApiError::internal("failed to delete QoS class")
    })?;
    // Asked again, on the row, inside the transaction that removes it. The
    // partial unique index forbids a SECOND default and says nothing about
    // none, so a `set-default` landing between the check above and this
    // transaction would otherwise leave the tenant with no default class at all
    // — and every workspace with no class to resolve.
    let still_default: Option<bool> =
        sqlx::query_scalar("SELECT is_default FROM qos_classes WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("re-read qos class default: {e}");
                ApiError::internal("failed to delete QoS class")
            })?;
    if still_default.unwrap_or(false) {
        return Err(ApiError::conflict(
            "the default class cannot be deleted — make another class the default first",
            ApiErrorCode::QosClassDefaultProtected,
        ));
    }
    // And whether anything points at it, counted again under that lock: a
    // reference written since the count above would otherwise be left on a
    // hidden class, which no read resolves — a seeded class is hidden, not
    // removed, so no foreign key refuses it.
    if q.reassign_to.is_none() {
        let (workspaces, keys, targets) = reference_counts(&mut tx, id).await?;
        if workspaces + keys + targets > 0 {
            return Err(ApiError::conflict(format!(
                "still in use by {workspaces} workspace(s), {keys} key(s) and {targets} route target(s)"
            ), ApiErrorCode::QosClassInUse));
        }
    }
    // A revoked key's class describes traffic that can no longer happen, so it
    // is not counted as a reference — but the foreign key still is one, and it
    // would refuse this delete for ever with nothing an admin could move.
    sqlx::query("UPDATE api_keys SET qos_class_id = NULL WHERE qos_class_id = $1 AND revoked_at IS NOT NULL")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clear qos class from revoked keys: {e}");
            ApiError::internal("failed to delete QoS class")
        })?;
    if let Some(target) = q.reassign_to {
        for stmt in [
            "UPDATE workspaces SET qos_class_id = $2 WHERE qos_class_id = $1",
            // The elevation bit goes with the class it was granted for: nobody
            // elevated these keys to the class they are being moved to, and
            // leaving the bit set would let them outrank their workspace later
            // with no admin decision behind it.
            "UPDATE api_keys SET qos_class_id = $2, qos_class_elevated = false WHERE qos_class_id = $1",
        ] {
            sqlx::query(stmt)
                .bind(id)
                .bind(target)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("reassign qos class: {e}");
                    ApiError::internal("failed to reassign QoS class")
                })?;
        }
        // A target already accepting the destination class keeps one row, not two.
        sqlx::query(
            "INSERT INTO route_qos_classes (route_id, qos_class_id, tenant_id) \
             SELECT route_id, $2, tenant_id FROM route_qos_classes WHERE qos_class_id = $1 \
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("reassign route classes: {e}");
            ApiError::internal("failed to reassign QoS class")
        })?;
        sqlx::query("DELETE FROM route_qos_classes WHERE qos_class_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("clear route classes: {e}");
                ApiError::internal("failed to reassign QoS class")
            })?;
    }
    let stmt = if seeded {
        "UPDATE qos_classes SET suppressed = true, mint_default_for = NULL, updated_at = now() \
         WHERE id = $1"
    } else {
        "DELETE FROM qos_classes WHERE id = $1"
    };
    sqlx::query(stmt)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            // Something started pointing at the class between the count above
            // and this statement. The foreign key is the backstop, and this is
            // the same answer the count would have given: still in use.
            if super::is_still_referenced(&e) {
                return ApiError::conflict(
                    "something started using this class while it was being deleted — try again",
                    ApiErrorCode::QosClassInUse,
                );
            }
            tracing::error!("delete qos class: {e}");
            ApiError::internal("failed to delete QoS class")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("delete qos class (commit): {e}");
        ApiError::internal("failed to delete QoS class")
    })?;

    let mut resp = ActionResponse::ok().with_message("QoS class deleted");
    if referenced > 0 {
        resp = resp.with_impact(super::ActionImpact {
            workspaces_moved: Some(workspaces),
            keys_moved: Some(keys),
            route_targets_moved: Some(targets),
            ..Default::default()
        });
    }
    Ok(Json(resp))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/qos-classes/{id}/actions/set-default",
    tag = "QoS",
    params(("id" = Uuid, Path, description = "QoS class id")),
    responses(
        (status = 200, description = "Default class set", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default_qos_class(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Clear then set, in one transaction: the partial unique index forbids two
    // defaults at once, so the clear has to land first.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("set default qos class (begin): {e}");
        ApiError::internal("failed to set the default class")
    })?;
    sqlx::query(
        "UPDATE qos_classes SET is_default = false, updated_at = now() \
         WHERE tenant_id = $1 AND is_default AND id <> $2",
    )
    .bind(tenant_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("clear default qos class: {e}");
        ApiError::internal("failed to set the default class")
    })?;
    let updated = sqlx::query(
        "UPDATE qos_classes SET is_default = true, updated_at = now() \
         WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            return ApiError::conflict("another class became the default — reload and try again", ApiErrorCode::QosClassStarTaken);
        }
        tracing::error!("set default qos class: {e}");
        ApiError::internal("failed to set the default class")
    })?
    .rows_affected();
    if updated == 0 {
        return Err(
            ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
        );
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("set default qos class (commit): {e}");
        ApiError::internal("failed to set the default class")
    })?;

    Ok(Json(ActionResponse::ok().with_message("default class set")))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/qos-classes/{id}/actions/set-mint-default",
    tag = "QoS",
    params(("id" = Uuid, Path, description = "QoS class id")),
    request_body = SetMintDefaultRequest,
    responses(
        (status = 200, description = "Mint default set", body = ActionResponse),
        (status = 400, description = "Unknown kind", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_mint_default_qos_class(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<SetMintDefaultRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let kind = match req.kind.as_deref() {
        None => None,
        Some(k @ ("interactive" | "automation")) => Some(k.to_string()),
        Some(_) => {
            return Err(ApiError::bad_request(
                "kind must be \"interactive\", \"automation\" or null",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
    };

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("set mint default (begin): {e}");
        ApiError::internal("failed to set the mint default")
    })?;
    // Either way this class ends up holding exactly the star asked for; when one
    // is given, the class that held it loses it first (one star per kind).
    if let Some(kind) = &kind {
        sqlx::query(
            "UPDATE qos_classes SET mint_default_for = NULL, updated_at = now() \
             WHERE tenant_id = $1 AND mint_default_for = $2 AND id <> $3",
        )
        .bind(tenant_id)
        .bind(kind)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clear mint default: {e}");
            ApiError::internal("failed to set the mint default")
        })?;
    }
    let updated = sqlx::query(
        "UPDATE qos_classes SET mint_default_for = $2, updated_at = now() \
         WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .bind(kind.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        // Two admins moving the same star at once: the partial unique index
        // catches the loser, and that is an ordinary conflict the UI can retry,
        // not a fault.
        if super::is_unique_violation(&e) {
            return ApiError::conflict("another class took that star — reload and try again", ApiErrorCode::QosClassStarTaken);
        }
        tracing::error!("set mint default: {e}");
        ApiError::internal("failed to set the mint default")
    })?
    .rows_affected();
    if updated == 0 {
        return Err(
            ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
        );
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("set mint default (commit): {e}");
        ApiError::internal("failed to set the mint default")
    })?;

    // Minting is admin-side: which class a NEW key gets changes no edge config,
    // so this is the one class mutation that does not mark the tenant dirty.
    Ok(Json(ActionResponse::ok().with_message("mint default set")))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn qos_classes_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/", get(list_qos_classes).post(create_qos_class))
        .route("/deployment-limits", get(get_qos_deployment_limits))
        .route(
            "/{id}",
            get(get_qos_class).patch(update_qos_class).delete(delete_qos_class),
        )
        .route("/{id}/actions/set-default", post(set_default_qos_class))
        .route("/{id}/actions/set-mint-default", post(set_mint_default_qos_class))
}

// ---------------------------------------------------------------------------
// Shared resolution — used by every path that writes a class onto a key
// ---------------------------------------------------------------------------

/// Who is asking for a class. A tenant admin may put a key above its
/// workspace; nobody else may, and the difference is audited as an elevation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClassAuthority {
    TenantAdmin,
    /// A workspace manager, or a member minting their own key.
    Delegated,
}

/// What kind of principal a key is being minted for, which is what decides the
/// class it gets when nobody asked for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MintPrincipal {
    /// A person's own tool, on their own machine.
    Person,
    /// Unattended work: CI, a service account.
    Automation,
}

impl MintPrincipal {
    fn star(self) -> &'static str {
        match self {
            Self::Person => "interactive",
            Self::Automation => "automation",
        }
    }
}

/// The rank of the class a workspace's traffic runs as — its own, else the
/// tenant's default. A workspace that inherits the default is NOT "unranked":
/// comparing against nothing would let any key name any class.
pub(crate) async fn effective_workspace_rank(
    conn: &mut Scoped,
    workspace_id: Uuid,
) -> Result<Option<i32>, ApiError> {
    sqlx::query_scalar::<_, i32>(
        "SELECT q.rank FROM qos_classes q \
         WHERE NOT q.suppressed \
           AND q.id = COALESCE( \
                 (SELECT w.qos_class_id FROM workspaces w WHERE w.id = $1), \
                 (SELECT d.id FROM qos_classes d WHERE d.is_default AND NOT d.suppressed LIMIT 1))",
    )
    .bind(workspace_id)
    .fetch_optional(conn)
    .await
    .map_err(|e| {
        tracing::error!("workspace qos rank: {e}");
        ApiError::internal("failed to resolve the workspace's QoS class")
    })
}

/// What to store on a key for a requested class: the class itself, and whether
/// it sits above the workspace deliberately.
///
/// `None` asked for means inherit. A class more important than the workspace's
/// is an elevation only a tenant admin may make; for anyone else it is refused
/// rather than quietly downgraded, so the caller learns their key is not what
/// they asked for.
pub(crate) async fn resolve_key_class(
    conn: &mut Scoped,
    workspace_id: Uuid,
    requested: Option<Uuid>,
    authority: ClassAuthority,
) -> Result<(Option<Uuid>, bool), ApiError> {
    let Some(requested) = requested else {
        return Ok((None, false));
    };
    let rank: Option<i32> =
        sqlx::query_scalar("SELECT rank FROM qos_classes WHERE id = $1 AND NOT suppressed")
            .bind(requested)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("load qos class for key: {e}");
                ApiError::internal("failed to load the QoS class")
            })?;
    let Some(rank) = rank else {
        return Err(
            ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound)
        );
    };
    let workspace_rank = effective_workspace_rank(&mut *conn, workspace_id).await?;
    match (workspace_rank, authority) {
        // At most as important as the workspace: anyone who may mint here may ask for it.
        (Some(ws), _) if rank >= ws => Ok((Some(requested), false)),
        // Above the workspace — or the workspace runs as nothing we can compare
        // against, which is the same question with no answer. Both are the tenant
        // admin's call; an unanswerable one is not a grant.
        (_, ClassAuthority::TenantAdmin) => Ok((Some(requested), workspace_rank.is_some())),
        (_, ClassAuthority::Delegated) => Err(ApiError::forbidden(
            "that priority class is more important than this workspace's; only a tenant admin can grant it",
        )
        .code(ApiErrorCode::QosClassNotEntitled)),
    }
}

/// The class a NEW key gets when the caller named none: the tenant's star for
/// that kind of principal, clamped to what the workspace itself runs as.
///
/// Clamping to inherit rather than to the workspace's class id is deliberate: a
/// key that inherits follows the workspace if it is promoted later, which is
/// what someone who never chose a class would expect.
pub(crate) async fn default_class_for_mint(
    conn: &mut Scoped,
    workspace_id: Uuid,
    principal: MintPrincipal,
) -> Result<Option<Uuid>, ApiError> {
    let star: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT id, rank FROM qos_classes \
         WHERE mint_default_for = $1 AND NOT suppressed",
    )
    .bind(principal.star())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load mint default class: {e}");
        ApiError::internal("failed to resolve the default QoS class")
    })?;
    let Some((id, rank)) = star else {
        return Ok(None);
    };
    let workspace_rank = effective_workspace_rank(&mut *conn, workspace_id).await?;
    // No comparable workspace rank means the clamp cannot be evaluated, so the
    // key inherits rather than taking a star nobody asked for.
    Ok(match workspace_rank {
        Some(ws) if rank >= ws => Some(id),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn fleet(pairs: &[(&str, &str)]) -> super::super::runtime_config::FleetSettings {
        super::super::runtime_config::FleetSettings {
            gateways: pairs
                .iter()
                .map(|(d, m)| HashMap::from([("QOS_QUEUE_TTL_MS", d.to_string()), ("QOS_QUEUE_TTL_MAX_MS", m.to_string())]))
                .collect(),
            reported: true,
        }
    }

    #[test]
    fn the_default_hold_pairs_each_gateways_own_default_and_maximum() {
        // Gateway A holds 10 s (default 10, max 60); gateway B holds 20 s
        // (default 30, capped at 20). Mixing the ends would claim 10–30 s.
        let limits = deployment_limits(&fleet(&[("10000", "60000"), ("30000", "20000")]), 2);
        let (hold, def, max) = (limits.default_hold.expect("hold"), limits.default_wait.expect("default"), limits.max_wait.expect("max"));
        assert_eq!((hold.low_ms, hold.high_ms), (10000, 20000));
        assert_eq!((def.low_ms, def.high_ms), (10000, 30000));
        assert_eq!((max.low_ms, max.high_ms), (20000, 60000));
    }

    #[test]
    fn a_fleet_that_agrees_states_one_value_and_nothing_readable_states_none() {
        let one = deployment_limits(&fleet(&[("10000", "20000"), ("10000", "20000")]), 2).default_hold.expect("hold");
        assert_eq!((one.low_ms, one.high_ms), (10000, 10000));
        let unreadable = deployment_limits(&fleet(&[("ten", "20000")]), 3);
        assert!(unreadable.max_wait.is_none(), "not a number is not a zero");
        assert_eq!(unreadable.gateway_replicas, 3, "and the replica count survives it");
    }
}
