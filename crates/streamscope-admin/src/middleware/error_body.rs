//! One error shape for every response: an error that leaves this service
//! without a JSON body — an axum extractor rejection (malformed JSON, a bad
//! query or path parameter, a wrong `Content-Type`), the router's own 404 and
//! 405, or a bare status from any layer — is rewritten here into the
//! `ApiErrorResponse` envelope with an `ApiErrorCode`, so a client can branch
//! on `error.code` for every failure the API can produce.
//!
//! A JSON error passes through untouched: handlers already answer with
//! `ApiError`, and the OAuth surfaces answer RFC-shaped JSON of their own.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::routes::{ApiError, ApiErrorCode};

/// Rejection bodies are a sentence; anything longer is not one and is not echoed.
const MAX_ECHOED_BODY: usize = 1024;

pub async fn json_error_body_mw(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let status = resp.status();
    if !(status.is_client_error() || status.is_server_error()) || is_json(&resp) {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    // A server error's text is never echoed: it may carry internals.
    let text = if status.is_client_error() {
        axum::body::to_bytes(body, MAX_ECHOED_BODY)
            .await
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let message = if text.is_empty() {
        status.canonical_reason().unwrap_or("error").to_string()
    } else {
        text
    };
    let rewritten = error_for_status(status, message).into_response();
    // Keep only what the original answer said beyond its body (`Allow` on a
    // 405, `WWW-Authenticate`, `Retry-After`, `Vary`); every other header may
    // describe the old body, and the new one is plain, uncompressed JSON.
    // Layers outside this one (CORS, the request id) add theirs afterwards.
    const KEPT: [header::HeaderName; 4] =
        [header::ALLOW, header::WWW_AUTHENTICATE, header::RETRY_AFTER, header::VARY];
    let mut kept = axum::http::HeaderMap::new();
    for name in KEPT {
        for value in parts.headers.get_all(&name) {
            kept.append(name.clone(), value.clone());
        }
    }
    parts.headers = kept;
    for (name, value) in rewritten.headers() {
        parts.headers.insert(name.clone(), value.clone());
    }
    let body: Body = rewritten.into_body();
    Response::from_parts(parts, body)
}

fn is_json(resp: &Response) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let essence = ct.split(';').next().unwrap_or("").trim();
            essence == "application/json" || essence.ends_with("+json")
        })
}

/// The envelope for a status no handler shaped. Every arm keeps the status.
fn error_for_status(status: StatusCode, message: String) -> ApiError {
    let (error_type, code) = match status {
        StatusCode::NOT_FOUND => ("not_found", ApiErrorCode::ApiRouteNotFound),
        StatusCode::METHOD_NOT_ALLOWED => ("invalid_request", ApiErrorCode::MethodNotAllowed),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ("invalid_request", ApiErrorCode::UnsupportedMediaType),
        StatusCode::PAYLOAD_TOO_LARGE => ("invalid_request", ApiErrorCode::PayloadTooLarge),
        StatusCode::UNAUTHORIZED => ("auth_error", ApiErrorCode::InvalidCredentials),
        StatusCode::FORBIDDEN => ("auth_error", ApiErrorCode::PermissionDenied),
        StatusCode::TOO_MANY_REQUESTS => ("rate_limit_error", ApiErrorCode::RateLimitExceeded),
        StatusCode::SERVICE_UNAVAILABLE => ("service_unavailable", ApiErrorCode::MaintenanceInProgress),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            ("invalid_request", ApiErrorCode::ValidationFailed)
        }
        s if s.is_server_error() => ("internal_error", ApiErrorCode::InternalError),
        // Any other bare 4xx names no cause; inventing one would mislead.
        _ => ("invalid_request", ApiErrorCode::RequestRefused),
    };
    ApiError { status, message, error_type, code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    #[derive(serde::Deserialize)]
    struct Named {
        #[allow(dead_code)]
        name: String,
    }

    fn app() -> Router {
        Router::new()
            .route("/thing", post(|axum::Json(_): axum::Json<Named>| async { "ok" }))
            .route("/plain", get(|| async { (StatusCode::BAD_GATEWAY, "upstream secret detail") }))
            .route("/shaped", get(|| async { ApiError::conflict("taken", ApiErrorCode::KeyNameTaken) }))
            .route("/gone", get(|| async { StatusCode::GONE }))
            .route("/gzipped", get(|| async {
                (StatusCode::BAD_REQUEST, [(header::CONTENT_ENCODING, "gzip"), (header::ETAG, "\"x\"")], "bad")
            }))
            .layer(axum::middleware::from_fn(json_error_body_mw))
    }

    async fn send(req: axum::http::Request<Body>) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let resp = app().oneshot(req).await.expect("router responds");
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16).await.expect("body");
        (status, headers, serde_json::from_slice(&bytes).expect("a JSON body"))
    }

    fn req(method: &str, uri: &str, ct: Option<&str>, body: &str) -> axum::http::Request<Body> {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        if let Some(ct) = ct {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        b.body(Body::from(body.to_string())).expect("request")
    }

    #[tokio::test]
    async fn a_rejection_gets_the_envelope_and_a_code() {
        for (r, status, code) in [
            (req("POST", "/thing", Some("application/json"), "{"), StatusCode::BAD_REQUEST, "validation_failed"),
            (req("POST", "/thing", Some("application/json"), "{}"), StatusCode::UNPROCESSABLE_ENTITY, "validation_failed"),
            (req("POST", "/thing", Some("text/plain"), "{}"), StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"),
            (req("GET", "/nowhere", None, ""), StatusCode::NOT_FOUND, "api_route_not_found"),
            (req("DELETE", "/thing", None, ""), StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
        ] {
            let (got, headers, body) = send(r).await;
            assert_eq!(got, status);
            assert_eq!(body["error"]["code"], code, "{body}");
            assert!(body["error"]["message"].as_str().is_some_and(|m| !m.is_empty()), "{body}");
            if got == StatusCode::METHOD_NOT_ALLOWED {
                assert!(headers.contains_key(header::ALLOW), "the 405 keeps its Allow header");
            }
        }
    }

    #[tokio::test]
    async fn a_bare_refusal_with_no_known_cause_is_not_given_one() {
        let (status, _, body) = send(req("GET", "/gone", None, "")).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(body["error"]["code"], "request_refused", "{body}");
    }

    #[tokio::test]
    async fn no_header_describing_the_old_body_survives_the_rewrite() {
        let (status, headers, body) = send(req("GET", "/gzipped", None, "")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "validation_failed", "{body}");
        assert!(!headers.contains_key(header::CONTENT_ENCODING), "the new body is not compressed");
        assert!(!headers.contains_key(header::ETAG), "the tag named the old body");
    }

    #[tokio::test]
    async fn a_server_errors_text_is_never_echoed() {
        let (status, _, body) = send(req("GET", "/plain", None, "")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"]["code"], "internal_error");
        assert!(!body.to_string().contains("secret"), "{body}");
    }

    #[tokio::test]
    async fn a_shaped_error_and_a_success_pass_untouched() {
        let (status, _, body) = send(req("GET", "/shaped", None, "")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "key_name_taken");
        let ok = app()
            .oneshot(req("POST", "/thing", Some("application/json"), r#"{"name":"x"}"#))
            .await
            .expect("router responds");
        assert_eq!(ok.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(ok.into_body(), 64).await.expect("body");
        assert_eq!(&bytes[..], b"ok");
    }
}
