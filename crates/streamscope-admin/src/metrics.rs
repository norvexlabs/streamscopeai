//! Control-plane `/metrics`: response-class counting layer + the exposition
//! handler for the dedicated `METRICS_PORT` listener (see
//! `streamscope_core::metrics` for why the scrape surface never mounts on the
//! main service port).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use streamscope_core::metrics::{metrics_response, PromBuf};

use crate::AdminState;

const STATUS_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "other"];

/// Process-lifetime admin metrics: uptime anchor + cumulative response counts
/// by HTTP status class (fed by [`count_responses_mw`] on the main router).
pub struct AdminMetrics {
    started: Instant,
    responses_by_class: [AtomicU64; 6],
}

impl Default for AdminMetrics {
    fn default() -> Self {
        Self { started: Instant::now(), responses_by_class: std::array::from_fn(|_| AtomicU64::new(0)) }
    }
}

impl AdminMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    fn record_response(&self, status: u16) {
        let idx = match status / 100 {
            c @ 1..=5 => (c - 1) as usize,
            _ => 5,
        };
        self.responses_by_class[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Counting layer on the main admin router: one relaxed atomic increment per
/// response, keyed by status class.
pub async fn count_responses_mw(
    State(metrics): State<Arc<AdminMetrics>>,
    req: Request,
    next: Next,
) -> Response {
    let resp = next.run(req).await;
    metrics.record_response(resp.status().as_u16());
    resp
}

/// Prometheus exposition for the dedicated `METRICS_PORT` listener.
pub async fn metrics_handler(
    State((state, metrics)): State<(Arc<AdminState>, Arc<AdminMetrics>)>,
) -> Response {
    let mut buf = PromBuf::new();

    buf.family("streamscope_admin_build_info", "gauge", "Build information (constant 1).");
    buf.sample_u64(
        "streamscope_admin_build_info",
        &[("version", streamscope_core::VERSION)],
        1,
    );

    buf.family(
        "streamscope_admin_db_pool_connections",
        "gauge",
        "Open PostgreSQL pool connections.",
    );
    buf.sample_u64("streamscope_admin_db_pool_connections", &[], u64::from(state.db.open_connections()));
    buf.family(
        "streamscope_admin_db_pool_idle_connections",
        "gauge",
        "Idle PostgreSQL pool connections.",
    );
    buf.sample_u64(
        "streamscope_admin_db_pool_idle_connections",
        &[],
        state.db.idle_connections() as u64,
    );

    buf.family(
        "streamscope_admin_http_responses_total",
        "counter",
        "Responses served on the main API listener, by HTTP status class.",
    );
    for (i, class) in STATUS_CLASSES.iter().enumerate() {
        buf.sample_u64(
            "streamscope_admin_http_responses_total",
            &[("class", class)],
            metrics.responses_by_class[i].load(Ordering::Relaxed),
        );
    }

    buf.family("streamscope_admin_uptime_seconds", "gauge", "Seconds since process start.");
    buf.sample_u64("streamscope_admin_uptime_seconds", &[], metrics.started.elapsed().as_secs());

    metrics_response(buf.finish()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_classes_bucket_correctly() {
        let m = AdminMetrics::new();
        m.record_response(200);
        m.record_response(204);
        m.record_response(404);
        m.record_response(503);
        m.record_response(0); // unknown → other
        let loads: Vec<u64> =
            m.responses_by_class.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        assert_eq!(loads, vec![0, 2, 0, 1, 1, 1]);
    }
}
