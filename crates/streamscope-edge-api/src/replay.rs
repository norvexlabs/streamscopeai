//! `POST /api/v2/edge/mcp-sse-replay` — the MCP SSE events of one session
//! after a sequence, for a `GET /mcp/<slug>` that resumes with
//! `Last-Event-ID` on an edge process that did not produce them.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The most events one replay answer carries.
pub const REPLAY_MAX_EVENTS: i64 = 10_000;

/// The largest replay request admin-api reads: a few ids.
pub const REPLAY_REQUEST_MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ReplayRequest {
    pub tenant_id: uuid::Uuid,
    pub mcp_session_id: String,
    pub after_sequence: i64,
    /// Held to `1..=`[`REPLAY_MAX_EVENTS`].
    pub limit: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ReplayEvent {
    pub event_id: String,
    pub sequence: i64,
    /// The SSE wire bytes, standard base64, to forward verbatim.
    pub event_data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ReplayResponse {
    /// Oldest first.
    pub events: Vec<ReplayEvent>,
}
