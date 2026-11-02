//! A mutating request runs to the end even when its caller hangs up.
//!
//! Hyper drops a request's future when the connection closes, which would stop
//! a handler between two of its writes (a tenant committed, its seeding not
//! done) and drop the audit middleware before it records what already
//! happened. A request whose method may change state therefore runs in its
//! own task: the caller can leave, the work and its audit row still complete.
//! Safe methods stay inline — cancelling a read loses nothing. Graceful
//! shutdown waits for these tasks (`DETACHED`) as it waits for its workers.

use std::sync::LazyLock;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Every mutating request in flight, so shutdown can wait for those whose
/// caller is gone.
pub static DETACHED: LazyLock<tokio_util::task::TaskTracker> = LazyLock::new(tokio_util::task::TaskTracker::new);

/// Past this many in flight, a mutating request runs inline again (a hang-up
/// cancels it): callers that time out and retry cannot pile up work nobody
/// waits for. Each request holds at most a pool connection or two, and the
/// pool is far smaller than this, so it bounds only the backlog.
const DETACHED_MAX: usize = 256;

pub async fn run_to_completion_mw(req: Request, next: Next) -> Response {
    let changes_state = !req.method().is_safe()
        || super::security_audit::is_side_effect_get(
            req.method(),
            req.uri().path(),
            req.extensions().get::<axum::extract::MatchedPath>().map(|m| m.as_str()),
        );
    if !changes_state {
        return next.run(req).await;
    }
    if DETACHED.len() >= DETACHED_MAX {
        tracing::warn!("{DETACHED_MAX} abandoned or running writes in flight: this one runs inline, cancelled if its caller hangs up");
        return next.run(req).await;
    }
    match DETACHED.spawn(next.run(req)).await {
        Ok(resp) => resp,
        // Panics are answered inside the task by `CatchPanicLayer`; reaching
        // here means the task itself failed.
        Err(e) => {
            tracing::error!("a mutating request's task failed: {e}");
            crate::routes::ApiError::internal("internal error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tower::ServiceExt;

    fn app(done: Arc<AtomicBool>) -> Router {
        let slow = move || {
            let done = done.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                done.store(true, Ordering::SeqCst);
                "ok"
            }
        };
        Router::new()
            .route("/w", post(slow.clone()))
            .route("/r", get(slow))
            .layer(axum::middleware::from_fn(run_to_completion_mw))
    }

    async fn abandon(app: Router, method: &str, uri: &str) {
        let req = Request::builder().method(method).uri(uri).body(Body::empty()).unwrap();
        // The caller gives up before the handler finishes.
        let _ = tokio::time::timeout(Duration::from_millis(5), app.oneshot(req)).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn an_abandoned_write_still_completes() {
        let done = Arc::new(AtomicBool::new(false));
        abandon(app(done.clone()), "POST", "/w").await;
        assert!(done.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn an_abandoned_read_is_dropped() {
        let done = Arc::new(AtomicBool::new(false));
        abandon(app(done.clone()), "GET", "/r").await;
        assert!(!done.load(Ordering::SeqCst), "a read is not worth finishing for nobody");
    }
}
