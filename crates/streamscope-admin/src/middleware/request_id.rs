//! Request-ID middleware.
//!
//! Reads `X-Request-Id` from the incoming request (or mints a UUIDv7),
//! stores it on request extensions, and echoes it on the response. Downstream
//! middleware and handlers read it via the `RequestId` extractor; the audit
//! middleware uses it to correlate admin actions with HTTP access logs.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

/// Per-request correlation ID. Stored on request extensions by `request_id_mw`.
#[derive(Debug, Clone, Copy)]
pub struct RequestId(pub Uuid);

pub async fn request_id_mw(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(streamscope_core::ids::mint_request_id);
    req.extensions_mut().insert(RequestId(id));
    let mut resp = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id.to_string()) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(request_id_mw))
    }

    async fn echoed(req: Request) -> Uuid {
        let resp = app().oneshot(req).await.expect("router responds");
        let header = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("the id is echoed");
        Uuid::parse_str(header).expect("the echoed id is a UUID")
    }

    #[tokio::test]
    async fn a_request_without_an_id_gets_a_minted_v7() {
        let first = echoed(Request::new(Body::empty())).await;
        let second = echoed(Request::new(Body::empty())).await;
        assert_eq!(first.get_version_num(), 7);
        assert_eq!(second.get_version_num(), 7);
        assert!(first < second, "ids minted in sequence increase");
    }

    #[tokio::test]
    async fn a_callers_id_of_any_version_is_kept() {
        let v4 = Uuid::new_v4();
        let mut req = Request::new(Body::empty());
        req.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&v4.to_string()).expect("a UUID is a valid header value"),
        );
        assert_eq!(echoed(req).await, v4);
    }
}
