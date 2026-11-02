//! A whole-transfer deadline on an inbound request body.
//!
//! A per-read timeout restarts on every frame, so a client sending one byte at
//! a time holds a connection and a body buffer for as long as it likes. This
//! layer bounds the body in total time instead: the body must have arrived in
//! full within the surface's deadline, counted from its first read, so the
//! server's own
//! work before that (authentication, a database read) is not the client's
//! time; past it, the next read fails with [`BodyDeadlineExceeded`] and the
//! reader refuses the request through its own read-error path, in its own
//! error envelope.
//!
//! It applies to inbound request bodies only — never to a response, whose
//! length on a streamed model answer is the model's.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Frame, SizeHint};

/// The read error a body yields once its deadline has passed.
#[derive(Debug, thiserror::Error)]
#[error("request body not received in full within {}s", .0.as_secs())]
pub struct BodyDeadlineExceeded(Duration);

/// `inner`, failing any read still waiting once `limit` has elapsed since the
/// first read.
///
/// A frame already received is always handed on, so a body whose last bytes
/// arrive in time is read whole; only a read that would have to wait past the
/// deadline fails.
pub struct DeadlineBody {
    inner: Body,
    limit: Duration,
    /// Armed by the first read.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl DeadlineBody {
    pub fn new(inner: Body, limit: Duration) -> Self {
        Self { inner, limit, deadline: None }
    }
}

impl http_body::Body for DeadlineBody {
    type Data = Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        let limit = this.limit;
        let deadline = this.deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        if let Poll::Ready(frame) = Pin::new(&mut this.inner).poll_frame(cx) {
            return Poll::Ready(frame.map(|f| f.map_err(Into::into)));
        }
        match deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Some(Err(BodyDeadlineExceeded(this.limit).into()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Middleware: give the request's body the deadline `limit`, counted from its
/// first read (zero: none; a request with no body is left as it is). Mount it with
/// `from_fn_with_state(limit, bound_request_body)` — per route group where
/// surfaces need different deadlines, else router-wide; a body wrapped twice
/// keeps the shorter one.
pub async fn bound_request_body(State(limit): State<Duration>, req: Request, next: Next) -> Response {
    use http_body::Body as _;
    if limit.is_zero() || req.body().is_end_stream() {
        return next.run(req).await;
    }
    next.run(req.map(|body| Body::new(DeadlineBody::new(body, limit)))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    const LIMIT: Duration = Duration::from_secs(10);

    /// A body sending `first`, then — `gap` later — `last`, then ending,
    /// bounded by the deadline [`LIMIT`].
    fn trickled(gap: Duration) -> Body {
        Body::new(DeadlineBody::new(slow_parts(gap), LIMIT))
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_finishing_inside_the_deadline_is_read_whole() {
        let gap = LIMIT - Duration::from_millis(1);
        let bytes = axum::body::to_bytes(trickled(gap), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"firstlast");
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_still_arriving_past_the_deadline_is_refused() {
        let gap = LIMIT + Duration::from_millis(1);
        let err = axum::body::to_bytes(trickled(gap), usize::MAX).await.unwrap_err();
        assert_eq!(err.to_string(), "request body not received in full within 10s");
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_is_the_whole_transfer_not_the_gap_between_frames() {
        // Every frame comes well inside the limit of the one before it; the
        // body as a whole does not.
        let frames = futures::stream::iter(0..20).then(|_| async {
            tokio::time::sleep(LIMIT / 4).await;
            Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
        });
        let body = Body::new(DeadlineBody::new(Body::from_stream(frames), LIMIT));
        let err = axum::body::to_bytes(body, usize::MAX).await.unwrap_err();
        assert_eq!(err.to_string(), "request body not received in full within 10s");
    }

    #[tokio::test(start_paused = true)]
    async fn the_clock_starts_at_the_first_read() {
        let body = Body::new(DeadlineBody::new(slow_parts(Duration::from_millis(1)), LIMIT));
        // The server is busy past the deadline before it reads a byte; the
        // body then takes a moment to arrive.
        tokio::time::sleep(LIMIT * 2).await;
        assert_eq!(&axum::body::to_bytes(body, usize::MAX).await.unwrap()[..], b"firstlast");
    }

    /// A route that reads its body whole, behind the middleware with `limit`.
    fn reading_route(limit: Duration) -> axum::Router {
        axum::Router::new()
            .route(
                "/",
                axum::routing::post(|body: Body| async move {
                    match axum::body::to_bytes(body, usize::MAX).await {
                        Ok(bytes) => (axum::http::StatusCode::OK, bytes.len().to_string()),
                        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e.to_string()),
                    }
                }),
            )
            .route_layer(axum::middleware::from_fn_with_state(limit, bound_request_body))
    }

    async fn post(route: axum::Router, body: Body) -> (axum::http::StatusCode, String) {
        use tower::ServiceExt;
        let req = axum::http::Request::post("/").body(body).unwrap();
        let resp = route.oneshot(req).await.unwrap();
        let status = resp.status();
        let text = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&text).into_owned())
    }

    /// `first`, then — `gap` later — `last`, then the end, with no deadline.
    fn slow_parts(gap: Duration) -> Body {
        let parts = futures::stream::iter([("first", Duration::ZERO), ("last", gap)]).then(
            |(chunk, wait)| async move {
                tokio::time::sleep(wait).await;
                Ok::<_, std::io::Error>(Bytes::from(chunk))
            },
        );
        Body::from_stream(parts)
    }

    #[tokio::test(start_paused = true)]
    async fn the_middleware_refuses_a_late_body_and_passes_a_timely_one() {
        let late = post(reading_route(LIMIT), slow_parts(LIMIT * 2)).await;
        assert_eq!(late, (axum::http::StatusCode::BAD_REQUEST, "request body not received in full within 10s".into()));
        let timely = post(reading_route(LIMIT), slow_parts(LIMIT / 2)).await;
        assert_eq!(timely, (axum::http::StatusCode::OK, "9".into()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_deadline_bounds_nothing() {
        let got = post(reading_route(Duration::ZERO), slow_parts(LIMIT * 100)).await;
        assert_eq!(got, (axum::http::StatusCode::OK, "9".into()));
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_body_ends_at_once() {
        let body = Body::new(DeadlineBody::new(Body::empty(), LIMIT));
        assert!(axum::body::to_bytes(body, usize::MAX).await.unwrap().is_empty());
    }
}
