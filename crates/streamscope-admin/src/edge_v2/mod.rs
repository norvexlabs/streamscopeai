//! The admin side of the edge protocol: endpoints the edge calls, served by
//! any replica, authenticated by the edge token on every request.

use std::sync::Arc;

use axum::Router;
use axum::routing::{post, put};

use crate::AdminState;

pub mod auth;
pub mod blobs;
pub mod events;
pub mod history;
pub mod ingest;
pub mod replay;
pub mod status;
pub mod sync;
pub mod writers;

/// Mounted at `/api/v2/edge`.
pub fn edge_v2_router() -> Router<Arc<AdminState>> {
    // Each handler reads its own body, after the edge token checks out and
    // under its own limit (`auth::authenticated_body`), so no body limit is
    // layered here.
    Router::new()
        // A cold edge's answers are megabytes of repeated rule and profile
        // text: gzipped when the edge asks for it; a steady-state poll (a few
        // hundred bytes) goes plain.
        .route(
            "/sync",
            post(sync::sync_handler).layer(
                tower_http::compression::CompressionLayer::new()
                    .gzip(true)
                    .quality(tower_http::CompressionLevel::Fastest)
                    .compress_when(tower_http::compression::predicate::SizeAbove::new(8 * 1024)),
            ),
        )
        .route("/ingest", post(ingest::ingest_handler))
        .route("/blobs/{tenant}/{blob_type}/{content_hash}", put(blobs::put_blob_handler))
        .route("/mcp-sse-replay", post(replay::replay_handler))
        // Mounted outside the app-wide panic layer (see `run_to_completion_mw`
        // in main.rs), so it carries its own.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(crate::handle_panic))
}
