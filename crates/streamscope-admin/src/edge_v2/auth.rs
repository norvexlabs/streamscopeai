//! Edge identity for the v2 endpoints: the edge token on every request, and
//! the instance it names.

// An edge request is refused with the finished response its handler returns
// as it is: the refusal is the cold path, so its size costs nothing.
#![allow(clippy::result_large_err)]

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::db::{Db, Global};
use crate::routes::{ApiError, ApiErrorCode};

/// The active edge node `Authorization: Bearer <edge token>` names: the
/// token's sha256 in `edge_nodes.token_hash`. 401 when the header is absent or
/// names no active node.
pub async fn authenticate_edge_node(headers: &HeaderMap, db: &Db) -> Result<uuid::Uuid, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if token.is_empty() {
        return Err(ApiError::unauthorized("missing edge token").code(ApiErrorCode::EdgeTokenInvalid).into_response());
    }
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let found: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM edge_nodes WHERE token_hash = $1 AND status = 'active'")
            .bind(&hash)
            .fetch_optional(db.global(Global::Infra))
            .await
            .map_err(|e| {
                tracing::error!("edge v2 auth: reading edge_nodes failed: {e}");
                ApiError::internal("Failed to authenticate the edge").into_response()
            })?;
    found.ok_or_else(|| ApiError::unauthorized("invalid edge token").code(ApiErrorCode::EdgeTokenInvalid).into_response())
}

/// The `edge_instances.id` of `instance` on `edge_node_id`, created on first
/// sight. The instance id is the edge's own, persisted with its store.
pub async fn instance_id(db: &Db, edge_node_id: uuid::Uuid, instance: uuid::Uuid) -> Result<uuid::Uuid, sqlx::Error> {
    // Read first: every poll names an instance that already exists.
    let known: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM edge_instances WHERE edge_node_id = $1 AND instance_key = $2")
            .bind(edge_node_id)
            .bind(instance.to_string())
            .fetch_optional(db.global(Global::Infra))
            .await?;
    if let Some(id) = known {
        return Ok(id);
    }
    sqlx::query_scalar(
        "INSERT INTO edge_instances (edge_node_id, instance_key) VALUES ($1, $2) \
         ON CONFLICT (edge_node_id, instance_key) DO UPDATE SET instance_key = EXCLUDED.instance_key \
         RETURNING id",
    )
    .bind(edge_node_id)
    .bind(instance.to_string())
    .fetch_one(db.global(Global::Infra))
    .await
}

/// Authenticate an edge request from its headers alone, and only then read its
/// body, under `limit` bytes. An unauthenticated caller is answered before a
/// byte of its body is read; an authenticated one past the limit gets 413.
pub async fn authenticated_body(
    req: axum::extract::Request,
    db: &Db,
    limit: usize,
) -> Result<(uuid::Uuid, axum::body::Bytes), Response> {
    let (parts, body) = req.into_parts();
    let node = authenticate_edge_node(&parts.headers, db).await?;
    Ok((node, read_body(body, limit).await?))
}

/// Read an authenticated edge request's body under `limit` bytes; past it,
/// 413; one that fails to arrive, 400.
async fn read_body(body: axum::body::Body, limit: usize) -> Result<axum::body::Bytes, Response> {
    match crate::body_read::read_capped(&mut body.into_data_stream(), limit, 0).await {
        Ok(Some(data)) => Ok(data.into()),
        Ok(None) => Err(too_large(limit)),
        Err(_) => Err(ApiError::bad_request("The request body did not arrive whole").into_response()),
    }
}

/// The 413 a body past `limit` is answered.
pub fn too_large(limit: usize) -> Response {
    ApiError::payload_too_large(format!("Request body larger than {limit} bytes, or unreadable")).into_response()
}

