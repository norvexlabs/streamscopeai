//! `PUT /api/v2/edge/blobs/{tenant}/{blob_type}/{content_hash}`: one media
//! blob, its raw bytes as the body and its media type as `Content-Type`.
//!
//! A blob too large to travel inside an ingest share goes up this way, ahead
//! of the records that reference it, which then leave it out. Storing it again
//! is harmless: a blob already stored keeps its bytes, and either way it is
//! stamped (`last_referenced_at`), which holds off the stamp purge while those
//! records are on their way.
//!
//! The body is read whole, under the platform's blob cap
//! (`EDGE_BLOB_MAX_MB`) — the same bytes the serving endpoints read back
//! whole — and the bodies one replica reads at once are held to
//! [`UPLOAD_BYTES_AT_ONCE`] in all, so the memory they take is bounded.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use streamscope_core::audit::BlobType;

use crate::content_store::media_blobs;
use crate::db::tenant::{TenantConn, TenantId};
use crate::routes::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse};
use crate::AdminState;

/// The bytes of blob bodies one replica reads at once, by their declared
/// length (the cap when none is declared); a further upload waits its turn,
/// and a blob larger than this reads alone. Each body is held about three
/// times over while it is written (the body, the bound parameter, the
/// socket buffer).
const UPLOAD_BYTES_AT_ONCE: usize = 64 * 1024 * 1024;
static UPLOADS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(UPLOAD_BYTES_AT_ONCE);

/// How long a body of `bytes` may take to arrive.
fn read_deadline(bytes: usize) -> std::time::Duration {
    READ_BASE + std::time::Duration::from_secs(bytes as u64 / READ_FLOOR_BYTES_PER_SEC)
}

/// The longest an upload waits for its turn.
const TURN_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A body is read within `READ_BASE` plus its size at `READ_FLOOR_BYTES_PER_SEC`.
const READ_BASE: std::time::Duration = std::time::Duration::from_secs(30);
const READ_FLOOR_BYTES_PER_SEC: u64 = 128 * 1024;

#[utoipa::path(
    put,
    path = "/api/v2/edge/blobs/{tenant}/{blob_type}/{content_hash}",
    params(
        ("tenant" = uuid::Uuid, Path, description = "The tenant the blob belongs to"),
        ("blob_type" = String, Path, description = "The blob's type"),
        ("content_hash" = String, Path, description = "The blob's content hash, as its records reference it"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The blob's bytes; `Content-Type` is its media type"),
    responses(
        (status = 200, description = "Stored, or already stored", body = ActionResponse),
        (status = 400, description = "Unknown blob type, or no media type", body = ApiErrorResponse),
        (status = 401, description = "Missing or unknown edge token", body = ApiErrorResponse),
        (status = 410, description = "The tenant no longer exists", body = ApiErrorResponse),
        (status = 413, description = "Larger than the platform's blob cap", body = ApiErrorResponse),
        (status = 422, description = "Refused for its data; sending it again is refused the same way", body = ApiErrorResponse),
        (status = 503, description = "Busy with other blob uploads; sent again later", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "Edge Nodes"
)]
pub(crate) async fn put_blob_handler(
    State(state): State<Arc<AdminState>>,
    Path((tenant, blob_type, content_hash)): Path<(uuid::Uuid, String, String)>,
    request: axum::extract::Request,
) -> Response {
    // The token first: an unauthenticated caller never waits for, or holds,
    // an upload slot.
    let (parts, body) = request.into_parts();
    let node_id = match super::auth::authenticate_edge_node(&parts.headers, &state.db).await {
        Ok(node) => node,
        Err(refused) => return refused,
    };
    let Ok(blob_type) = blob_type.parse::<BlobType>() else {
        return ApiError::bad_request("Unknown blob type").into_response();
    };
    let media_type = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .filter(|m| !m.is_empty());
    let Some(media_type) = media_type else {
        return ApiError::bad_request("A blob needs its media type as Content-Type").into_response();
    };
    let limit = streamscope_core::settings::core_settings().edge_blob_max_bytes();
    // A declared length decides "too large" before a byte is read; a body
    // that then fails to arrive whole is retried by the edge (500), never
    // settled as too large.
    let declared = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > limit) {
        return super::auth::too_large(limit);
    }
    let internal = |e: sqlx::Error| {
        tracing::error!(%node_id, %tenant, "edge blob upload: {e}");
        ApiError::internal("Failed to store the blob").into_response()
    };
    // Already stored (an answer the edge did not read, a resend after
    // `Retry { missing }`): stamped, and the body is read through without
    // being kept or written — a proxy in front of admin-api still sending it
    // would answer the edge 502 for a body cut off, and the edge would send
    // it again forever. The connection is let go before the body is read.
    let held = async {
        let mut db = TenantConn::acquire(&state.db, TenantId::from_edge(tenant)).await?;
        media_blobs::stamp_held(db.conn(), tenant, &content_hash, blob_type).await
    }
    .await;
    match held {
        Ok(r) if r.rows_affected() > 0 => {
            let deadline = read_deadline(declared.unwrap_or(limit));
            return match tokio::time::timeout(deadline, crate::body_read::read_through(&mut body.into_data_stream(), limit)).await {
                Ok(Ok(())) => Json(ActionResponse { ok: true, message: None, impact: None }).into_response(),
                _ => ApiError::internal("The blob body did not arrive whole").into_response(),
            };
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    let share = declared.unwrap_or(limit).clamp(1, UPLOAD_BYTES_AT_ONCE) as u32;
    // A turn not had within `TURN_WAIT` is answered 503: the edge sends the
    // blob again after its backoff rather than waiting behind slow uploads.
    // Shorter than any edge's upload timeout, so the edge reads the answer.
    let _turn = match tokio::time::timeout(TURN_WAIT, UPLOADS.acquire_many(share)).await {
        Ok(Ok(turn)) => turn,
        Ok(Err(_)) => return ApiError::internal("Blob uploads are closed").into_response(),
        Err(_) => {
            return ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "Busy with other blob uploads; send it again later".into(),
                error_type: "service_unavailable",
                code: ApiErrorCode::EdgeBlobUploadsBusy,
            }
            .into_response();
        }
    };
    // A body that arrives slower than the floor gives its share of the
    // budget back (500: the edge sends it again later).
    let deadline = read_deadline(declared.unwrap_or(limit));
    let data = match tokio::time::timeout(deadline, crate::body_read::read_capped(&mut body.into_data_stream(), limit, declared.unwrap_or(0))).await {
        Ok(Ok(Some(data))) => data,
        Ok(Ok(None)) => return super::auth::too_large(limit),
        Ok(Err(_)) => return ApiError::internal("The blob body did not arrive whole").into_response(),
        Err(_) => return ApiError::internal("The blob body did not arrive in time").into_response(),
    };
    let mut db = match TenantConn::acquire(&state.db, TenantId::from_edge(tenant)).await {
        Ok(db) => db,
        Err(e) => return internal(e),
    };
    // A deleted tenant's blob is undeliverable: nothing is written (the row
    // would FK-violate on every resend) and the edge drops it.
    let stored = media_blobs::insert_uploaded(db.conn(), tenant, &content_hash, blob_type, &media_type, data.as_slice()).await;
    match stored {
        Ok(r) if r.rows_affected() == 0 => ApiError {
            status: StatusCode::GONE,
            message: "The tenant no longer exists".into(),
            error_type: "invalid_request",
            code: ApiErrorCode::TenantNotFound,
        }
        .into_response(),
        Ok(_) => Json(ActionResponse { ok: true, message: None, impact: None }).into_response(),
        // Refused for its data: every resend would be refused the same way.
        Err(e) if super::writers::is_permanent_row_rejection(&e) => {
            tracing::error!(%node_id, %tenant, "edge blob upload refused for its data: {e}");
            ApiError {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                message: "The blob was refused for its data".into(),
                error_type: "invalid_request",
                code: ApiErrorCode::EdgeBlobRefused,
            }
            .into_response()
        }
        Err(e) => internal(e),
    }
}
