//! Edge node registry: the logical edges an admin creates, each with the token
//! its proxy replicas authenticate with. What each replica holds and ships is
//! read from `edge_instances` (`edge_v2`).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::AdminState;
use crate::db::Global;
use crate::edge_v2::status::NodeSync;
use crate::routes::{ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};

type NodeRow = (uuid::Uuid, String, String, String, chrono::DateTime<chrono::Utc>, Option<serde_json::Value>);

async fn node_sync(db: &crate::db::Db) -> Result<HashMap<uuid::Uuid, NodeSync>, ApiError> {
    crate::edge_v2::status::node_sync(db).await.map_err(|e| {
        tracing::error!("edge nodes: read instance sync state: {e}");
        ApiError::internal("internal error")
    })
}

fn node_response(
    (id, name, endpoint, status, created_at, metadata): NodeRow,
    sync: &mut HashMap<uuid::Uuid, NodeSync>,
) -> EdgeNodeResponse {
    let s = sync.remove(&id).unwrap_or_default();
    EdgeNodeResponse {
        id,
        name,
        endpoint,
        status,
        is_connected: s.live_instances > 0,
        last_sync_at: s.last_sync_at,
        synced: s.synced,
        connected_instances: s.live_instances,
        created_at,
        // Read loosely: a row written before a field existed still lists.
        metadata: metadata.and_then(|v| serde_json::from_value::<EdgeNodeMetadata>(v).ok()),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateEdgeNodeRequest {
    pub name: String,
    pub endpoint: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateEdgeNodeResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub token: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct EdgeNodeResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub endpoint: String,
    /// `active` admits the edge's token; any other value refuses it.
    pub status: String,
    /// Some proxy replica of this edge has synced recently.
    pub is_connected: bool,
    /// The most recent sync by any of its replicas.
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Every live replica holds the current config, as the answering admin
    /// replica's cache has it (at most one `EDGE_SYNC_REFRESH_MS` behind).
    pub synced: bool,
    /// Proxy replicas (edge instances) syncing recently: 1 for a single-proxy
    /// VM appliance, N for a horizontally-scaled (e.g. Kubernetes) Deployment.
    pub connected_instances: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: Option<EdgeNodeMetadata>,
}

/// Typed metadata bag stored on each edge node. Populated from the proxy
/// heartbeat payload (`stats`, `runtime`) and a server-assigned timestamp.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct EdgeNodeMetadata {
    /// Live runtime stats from the proxy (most recent heartbeat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<EdgeProxyStats>,
    /// RFC3339 timestamp when the stats block was most recently written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_updated_at: Option<String>,
    /// Runtime-config state reported by the proxy (effective settings + the
    /// central-override subset it booted with) — the *actual* half of the
    /// desired-vs-actual runtime-config model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<EdgeRuntimeReport>,
}

pub use streamscope_edge_api::ingest::{EdgeCacheStats, EdgeProxyStats, EdgeRuntimeReport};

/// Create a new edge node, returning a one-time plaintext token.
/// Edge nodes are global infrastructure — uses raw pool (no TenantConn).
#[utoipa::path(
    post,
    path = "/api/v1/admin/edge-nodes",
    tag = "Edge Nodes",
    request_body = CreateEdgeNodeRequest,
    responses(
        (status = 201, description = "Edge node created with one-time token", body = CreateEdgeNodeResponse),
        (status = 400, description = "Empty name", body = ApiErrorResponse),
        (status = 409, description = "Another edge node has that name", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_edge_node(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<CreateEdgeNodeRequest>,
) -> Result<(StatusCode, Json<CreateEdgeNodeResponse>), ApiError> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("an edge node's name cannot be empty"));
    }
    // Generate token: edge-<base58(16 random bytes)>
    let mut token_bytes = [0u8; 16];
    use rand::Rng;
    rand::rng().fill_bytes(&mut token_bytes);
    let token = format!("edge-{}", bs58::encode(&token_bytes).into_string());

    // Hash for storage.
    let hash = hex_sha256(&token);
    let endpoint = req.endpoint.unwrap_or_default();

    let row = sqlx::query_as::<_, (uuid::Uuid, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO edge_nodes (name, endpoint, token_hash) VALUES ($1, $2, $3) RETURNING id, created_at",
    )
    .bind(&name)
    .bind(&endpoint)
    .bind(&hash)
    .fetch_one(state.db.global(Global::Infra))
    .await
    .map_err(|e| name_conflict_or_internal(e, "create edge node"))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateEdgeNodeResponse {
            id: row.0,
            name,
            token,
            created_at: row.1,
        }),
    ))
}

/// List all edge nodes (token_hash excluded).
/// Edge nodes are global infrastructure — uses raw pool (no TenantConn).
#[utoipa::path(
    get,
    path = "/api/v1/admin/edge-nodes",
    tag = "Edge Nodes",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of all edge nodes", body = TotalPage<EdgeNodeResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_edge_nodes(
    State(state): State<Arc<AdminState>>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<EdgeNodeResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edge_nodes")
        .fetch_one(state.db.global(Global::Infra))
        .await
        .map_err(|e| {
            tracing::error!("count edge nodes: {e}");
            ApiError::internal("internal error")
        })?;
    let rows = sqlx::query_as::<_, NodeRow>(
        "SELECT id, name, endpoint, status, created_at, metadata FROM edge_nodes ORDER BY created_at LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(state.db.global(Global::Infra))
    .await
    .map_err(|e| {
        tracing::error!("list edge nodes: {e}");
        ApiError::internal("internal error")
    })?;
    let mut sync = node_sync(&state.db).await?;
    let nodes = rows.into_iter().map(|row| node_response(row, &mut sync)).collect();

    Ok(Json(TotalPage::new(nodes, limit, offset, total)))
}

/// Delete an edge node.
/// Edge nodes are global infrastructure — uses raw pool (no TenantConn).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/edge-nodes/{id}",
    tag = "Edge Nodes",
    params(("id" = Uuid, Path, description = "Edge node ID")),
    responses(
        (status = 200, description = "Edge node deleted", body = crate::routes::ActionResponse),
        (status = 404, description = "Edge node not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_edge_node(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::routes::ActionResponse>, ApiError> {
    let result = sqlx::query("DELETE FROM edge_nodes WHERE id = $1")
        .bind(id)
        .execute(state.db.global(Global::Infra))
        .await
        .map_err(|e| {
            tracing::error!("delete edge node: {e}");
            ApiError::internal("internal error")
        })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("edge node not found", ApiErrorCode::EdgeNodeNotFound));
    }
    Ok(Json(crate::routes::ActionResponse::ok()))
}

// ---------------------------------------------------------------------------
// Update edge node
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct UpdateEdgeNodeRequest {
    pub name: Option<String>,
    /// The node's endpoint; an empty string clears it.
    pub endpoint: Option<String>,
}

/// Update an edge node: each field given replaces its value, an absent one is
/// left as it is.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/edge-nodes/{id}",
    tag = "Edge Nodes",
    params(("id" = uuid::Uuid, Path, description = "Edge node ID")),
    request_body = UpdateEdgeNodeRequest,
    responses(
        (status = 200, description = "Edge node updated", body = EdgeNodeResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 400, description = "Empty name", body = ApiErrorResponse),
        (status = 409, description = "Another edge node has that name", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_edge_node(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<UpdateEdgeNodeRequest>,
) -> Result<Json<EdgeNodeResponse>, ApiError> {
    let name = req.name.as_deref().map(str::trim);
    if name.is_some_and(str::is_empty) {
        return Err(ApiError::bad_request("an edge node's name cannot be empty"));
    }
    let result = sqlx::query(
        "UPDATE edge_nodes SET \
         name = COALESCE($2, name), \
         endpoint = COALESCE($3, endpoint) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(&req.endpoint)
    .execute(state.db.global(Global::Infra))
    .await
    .map_err(|e| name_conflict_or_internal(e, "update edge node"))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("edge node not found", ApiErrorCode::EdgeNodeNotFound));
    }

    let row = sqlx::query_as::<_, NodeRow>(
        "SELECT id, name, endpoint, status, created_at, metadata FROM edge_nodes WHERE id = $1",
    )
    .bind(id)
    .fetch_one(state.db.global(Global::Infra))
    .await
    .map_err(|e| {
        tracing::error!("fetch updated edge node: {e}");
        ApiError::internal("internal error")
    })?;
    let mut sync = node_sync(&state.db).await?;
    Ok(Json(node_response(row, &mut sync)))
}


/// A write that hit the unique node name is a 409; anything else a 500.
fn name_conflict_or_internal(e: sqlx::Error, what: &str) -> ApiError {
    if crate::routes::is_unique_violation(&e) {
        return ApiError::conflict("an edge node with this name already exists", ApiErrorCode::EdgeNodeNameTaken);
    }
    tracing::error!("{what}: {e}");
    ApiError::internal("internal error")
}

/// Compute hex-encoded SHA-256 hash of a string.
fn hex_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
