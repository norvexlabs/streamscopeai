//! `POST /api/v2/edge/mcp-sse-replay`: a session's MCP SSE events after a
//! sequence, for an edge resuming a `GET /mcp/<slug>` with `Last-Event-ID`.
//!
//! The edge names the tenant (the posture of audit ingest: an edge token is
//! trusted with the tenants it serves); the read runs on that tenant's RLS
//! connection, and every replay is logged with the edge that asked.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use streamscope_edge_api::replay::{REPLAY_MAX_EVENTS, REPLAY_REQUEST_MAX_BYTES, ReplayEvent, ReplayRequest, ReplayResponse};

use crate::AdminState;
use crate::db::tenant::{TenantConn, TenantId};
use crate::routes::{ApiError, ApiErrorResponse};

#[utoipa::path(
    post,
    path = "/api/v2/edge/mcp-sse-replay",
    request_body = streamscope_edge_api::replay::ReplayRequest,
    responses(
        (status = 200, description = "The session's events after the sequence, oldest first", body = streamscope_edge_api::replay::ReplayResponse),
        (status = 400, description = "Malformed request", body = ApiErrorResponse),
        (status = 401, description = "Missing or unknown edge token", body = ApiErrorResponse),
        (status = 413, description = "Request larger than the replay maximum", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "Edge Nodes"
)]
pub(crate) async fn replay_handler(State(state): State<Arc<AdminState>>, request: axum::extract::Request) -> Response {
    let (node_id, body) = match super::auth::authenticated_body(request, &state.db, REPLAY_REQUEST_MAX_BYTES).await {
        Ok(parts) => parts,
        Err(refused) => return refused,
    };
    let req: ReplayRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return ApiError::bad_request("Malformed replay request").into_response(),
    };
    tracing::debug!(
        %node_id, tenant_id = %req.tenant_id, mcp_session_id = %req.mcp_session_id,
        after_sequence = req.after_sequence, "edge mcp sse replay"
    );
    let internal = |what: &str, e: sqlx::Error| {
        tracing::error!(%node_id, tenant_id = %req.tenant_id, "edge sse replay: {what}: {e}");
        ApiError::internal("Failed to read the session's events").into_response()
    };
    let mut db = match TenantConn::acquire(&state.db, TenantId::from_edge(req.tenant_id)).await {
        Ok(db) => db,
        Err(e) => return internal("tenant connection", e),
    };
    let rows: Vec<(String, i64, Vec<u8>)> = match sqlx::query_as(
        "SELECT event_id, sequence, event_data FROM mcp_sse_events \
          WHERE tenant_id = $1 AND mcp_session_id = $2 AND sequence > $3 \
          ORDER BY sequence ASC LIMIT $4",
    )
    .bind(req.tenant_id)
    .bind(&req.mcp_session_id)
    .bind(req.after_sequence)
    .bind(req.limit.clamp(1, REPLAY_MAX_EVENTS))
    .fetch_all(db.conn())
    .await
    {
        Ok(rows) => rows,
        Err(e) => return internal("select", e),
    };
    let events = rows
        .into_iter()
        .map(|(event_id, sequence, data)| ReplayEvent {
            event_id,
            sequence,
            event_data: base64::engine::general_purpose::STANDARD.encode(&data),
        })
        .collect();
    Json(ReplayResponse { events }).into_response()
}
