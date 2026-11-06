//! Typed error hierarchy with security-aware client responses.
//!
//! [`AppError`] is the top-level request error; [`AuthError`] covers authentication
//! failures. [`AppError::client_error`] enforces a security boundary: of an
//! upstream's error body a client is shown only its `error.message` (the whole
//! body is logged at warn level, and the audit keeps the fullest detail via
//! [`envelope::upstream_error_detail`]). Internal errors return a generic
//! message. Auth errors include a truncated key prefix for log correlation
//! without leaking the full credential. [`envelope`] renders the result in the
//! client protocol's own grammar.

pub mod envelope;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::api::sse::ApiVersion;
use envelope::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),

    /// A rate limit refused the request. `bucket` names which limit — `None`
    /// for a limit outside the four limit buckets (the pre-auth IP throttle).
    #[error("rate limit exceeded: {message}")]
    RateLimited { message: String, bucket: Option<crate::middleware::rate_limit::LimitBucket> },

    /// A budget refused the request; `bucket` names which one.
    #[error("budget exceeded: {message}")]
    BudgetExceeded { message: String, bucket: crate::middleware::rate_limit::LimitBucket },

    /// No upstream had capacity in time. Distinct from a rate limit: nothing the
    /// caller did wrong and no quota was reached — the model is busy — so it
    /// carries how long to wait and is audited under its own category. The
    /// reason names which way capacity ran out (held past its deadline, shed as
    /// a low-priority request, or refused because this replica is already
    /// holding as much as it may).
    #[error("no capacity: {message}")]
    Saturated { message: String, reason: &'static str, retry_after_secs: u64 },

    #[error("invalid request: {0}")]
    BadRequest(String),

    /// An upstream answered with an error status. `model` is the alias the
    /// client asked for, attached by [`AppError::for_model`] once the request
    /// has given up on every target, so the client is told which of its
    /// models failed. Build one with [`AppError::upstream`].
    #[error("upstream error (status {status})")]
    Upstream { status: u16, body: String, model: Option<String> },

    /// An upstream answered with a success status and a body that is not
    /// JSON, on a leg that must TRANSLATE it: there is nothing to render in
    /// the client's protocol, and it is not a refusal either, so it is neither
    /// an [`AppError::Upstream`] nor handed to the client as a success. The
    /// client is refused with 502. `excerpt` is the body's start, for the audit
    /// only; `model` as on [`AppError::Upstream`]. Build one with
    /// [`AppError::upstream_unreadable`].
    #[error("unreadable upstream answer (status {status})")]
    UpstreamUnreadable { status: u16, excerpt: String, model: Option<String> },

    /// No answer came back from an upstream: the connection failed, or it did
    /// not respond in time. A fact about the path to the upstream, not the
    /// gateway's own fault, so the client is refused as by a gateway — 502, or
    /// 504 when the upstream timed out — and the row is audited as `upstream`.
    /// The only upstream failure without an HTTP answer, which is what the
    /// circuit breaker counts. `model` as on [`AppError::Upstream`]. Build one
    /// with [`AppError::upstream_send_error`].
    #[error("upstream unreachable ({kind}): {detail}")]
    UpstreamUnreachable { kind: &'static str, detail: String, model: Option<String> },

    /// The gateway has nowhere it may send the request — its own routing
    /// state, not an upstream's answer: a server with no URL, a provider with
    /// no enabled target, a model no enabled endpoint serves. Nothing was
    /// contacted, so it is never worded as a provider's failure. `model` as on
    /// [`AppError::Upstream`].
    #[error("no upstream to send to: {reason}")]
    Unroutable { reason: &'static str, model: Option<String> },

    #[error("model not found: {0}")]
    ModelNotFound(String),

    /// The request to an upstream could not be BUILT — a stored credential
    /// with a character no header may carry, a malformed URL. It never left
    /// the gateway and fails identically on every attempt and every replica of
    /// the server, so it is neither retried nor moved to a sibling replica —
    /// the only failure that is not. Reported like [`AppError::Internal`]: it
    /// is the gateway's own configuration fault. Build one with
    /// [`AppError::upstream_send_error`].
    #[error("upstream request could not be built: {0}")]
    UpstreamUnbuildable(String),

    /// The upstream's address is private and the platform's egress list for
    /// its surface does not list it (or it is the cloud metadata endpoint), or
    /// it redirected from https down to plain http. A policy refusal, decided before anything is sent: never retried and
    /// never a strike against the replica, but another replica — at another
    /// address — may be listed, so it is moved on from like a failed send.
    /// The detail names the refusal for the log and the audit row; what a
    /// client is told (`Display`, `client_error`) stays generic.
    #[error("upstream refused by the platform's egress policy")]
    EgressRefused(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        if e.is_data() || e.is_syntax() || e.is_eof() {
            AppError::BadRequest(format!("JSON error: {e}"))
        } else {
            AppError::Internal(format!("JSON serialization error: {e}"))
        }
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::Internal(format!("HTTP client error: {e}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingHeader,

    #[error("invalid API key ({0}…)")]
    InvalidKey(String),

    #[error("key revoked ({0}…)")]
    KeyRevoked(String),

    #[error("key expired ({0}…)")]
    KeyExpired(String),

    #[error("unrecognized credential format ({0}…)")]
    UnrecognizedFormat(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("cache error: {0}")]
    Cache(String),

    /// The key's workspace does not allow the resolved MCP virtual server.
    /// Surfaces as 403.
    #[error("workspace {workspace_id} does not permit MCP server {virtual_server_id}")]
    WorkspaceMcpAccessDenied {
        workspace_id: uuid::Uuid,
        virtual_server_id: uuid::Uuid,
    },

    /// The key's workspace does not allow the resolved A2A upstream agent.
    /// Surfaces as 403.
    #[error("workspace {workspace_id} does not permit A2A agent {agent_id}")]
    WorkspaceA2aAccessDenied {
        workspace_id: uuid::Uuid,
        agent_id: uuid::Uuid,
    },

    /// Operator misconfiguration — the resource is reachable but the
    /// tenant has no `proxy_public_url` configured, so MCP spec-OAuth
    /// validation can't compute the expected audience. Renders 503 so
    /// clients (and ops dashboards) can distinguish this from a client-
    /// side credential problem (which renders 401).
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl IntoResponse for AppError {
    /// The OpenAI grammar. A route that speaks another protocol re-renders the
    /// error through `envelope::render_errors_in`, which reads the
    /// [`envelope::ClientError`] this response carries.
    fn into_response(self) -> Response {
        // Log server errors at error level, client errors at warn level
        match &self {
            AppError::Internal(_) | AppError::UpstreamUnbuildable(_) | AppError::Anyhow(_) => {
                tracing::error!(error = %self, "request error");
            }
            AppError::Upstream { status, body, .. } => {
                // Include truncated upstream body at WARN level for diagnosis
                let excerpt: String = body.chars().take(500).collect();
                tracing::warn!(
                    upstream_status = status,
                    upstream_body = excerpt.as_str(),
                    "request error"
                );
            }
            _ => {
                tracing::warn!(error = %self, "request error");
            }
        }

        let error = self.client_error();

        // A capacity refusal is the one error here that can say WHEN to come
        // back, and a client that retries immediately makes a busy pool worse.
        let retry_after = match &self {
            AppError::Saturated { retry_after_secs, .. } => {
                axum::http::HeaderValue::from_str(&retry_after_secs.to_string()).ok()
            }
            _ => None,
        };
        let mut response = error.into_response(ApiVersion::ChatCompletions);
        if let Some(value) = retry_after {
            response.headers_mut().insert(axum::http::header::RETRY_AFTER, value);
        }
        response
    }
}

impl AppError {
    /// What the client is told: status, category and message, decided here for
    /// every protocol. An upstream refusal reaches the client only as the
    /// gateway's reading of its status plus the upstream's own `error.message`
    /// — never the rest of its body.
    pub fn client_error(&self) -> ClientError {
        let (status, kind, message) = match self {
            AppError::Auth(AuthError::MissingHeader) => {
                (StatusCode::UNAUTHORIZED, "auth_error", self.to_string())
            }
            AppError::Auth(AuthError::InvalidKey(_) | AuthError::KeyRevoked(_) | AuthError::KeyExpired(_)) => {
                (StatusCode::UNAUTHORIZED, "auth_error", self.to_string())
            }
            AppError::Auth(AuthError::Forbidden(_)) => {
                (StatusCode::FORBIDDEN, "auth_error", self.to_string())
            }
            AppError::Auth(AuthError::UnrecognizedFormat(_)) => {
                (StatusCode::UNAUTHORIZED, "auth_error", self.to_string())
            }
            // The `Display` names the workspace and the resource by UUID, which
            // is right for the log line and wrong for the wire: the caller
            // presented a key and learns from the refusal both which workspace
            // it belongs to and the id of a resource it was told it cannot
            // reach. The MCP surface already answers a bare "forbidden"; this
            // matches it. The detail is not lost — the variant is logged with
            // its full `Display` where the decision is made.
            AppError::Auth(
                AuthError::WorkspaceMcpAccessDenied { .. }
                | AuthError::WorkspaceA2aAccessDenied { .. },
            ) => (
                StatusCode::FORBIDDEN,
                "auth_error",
                "this key's workspace does not permit the requested resource".to_string(),
            ),
            AppError::Auth(AuthError::Cache(_)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "authentication service unavailable".to_string(),
            ),
            AppError::Auth(AuthError::ServiceUnavailable(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                self.to_string(),
            ),
            AppError::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                self.to_string(),
            ),
            AppError::BudgetExceeded { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "budget_exceeded",
                self.to_string(),
            ),
            AppError::Saturated { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exceeded",
                self.to_string(),
            ),
            AppError::BadRequest(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request", self.to_string())
            }
            AppError::Upstream { status, body, model } => {
                // The message keeps the status the upstream sent — or, for an
                // error inside a 2xx, the one that error names; the client is
                // refused with `upstream_client_status`.
                let upstream = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
                (
                    Self::upstream_client_status(*status),
                    "upstream_error",
                    envelope::upstream_refusal_message(upstream, body, model.as_deref()),
                )
            }
            AppError::UpstreamUnreadable { status, model, .. } => {
                let reason = format!(
                    "upstream provider returned a response the gateway could not read (HTTP {status})"
                );
                (
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    match model {
                        Some(m) => format!("{m}: {reason}"),
                        None => reason,
                    },
                )
            }
            AppError::UpstreamUnreachable { model, .. } => {
                let reason = if self.upstream_timed_out() {
                    "upstream provider did not respond in time"
                } else {
                    "upstream provider could not be reached"
                };
                (
                    self.unreachable_status(),
                    "upstream_error",
                    match model {
                        Some(m) => format!("{m}: {reason}"),
                        None => reason.to_string(),
                    },
                )
            }
            AppError::Unroutable { reason, model } => (
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                match model {
                    Some(m) => format!("{m}: {reason}"),
                    None => (*reason).to_string(),
                },
            ),
            AppError::ModelNotFound(_) => {
                (StatusCode::NOT_FOUND, "model_not_found", self.to_string())
            }
            AppError::EgressRefused(_) => (
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "the upstream was refused by the platform's egress policy".to_string(),
            ),
            AppError::Internal(_) | AppError::UpstreamUnbuildable(_) | AppError::Anyhow(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal server error".to_string(),
            ),
        };
        ClientError { status, kind, message, bucket: self.limit_bucket().map(|b| b.as_str()) }
    }
}

/// Truncate a string to at most `max_bytes` on a valid UTF-8 char boundary.
pub fn truncate_error_detail(s: &str, max_bytes: usize) -> String {
    let boundary = s.floor_char_boundary(max_bytes);
    s[..boundary].to_string()
}

impl AppError {
    /// An upstream's error answer: its status and body, not yet attributed to
    /// a model.
    pub fn upstream(status: u16, body: impl Into<String>) -> Self {
        AppError::Upstream { status, body: body.into(), model: None }
    }

    /// A success answer whose `body` could not be read, not yet attributed to
    /// a model. Keeps only the body's start.
    pub fn upstream_unreadable(status: u16, body: &[u8]) -> Self {
        let text = String::from_utf8_lossy(body);
        AppError::UpstreamUnreadable {
            status,
            excerpt: truncate_error_detail(text.trim(), 200),
            model: None,
        }
    }

    /// Attribute an upstream refusal, an answer it could not read, or the
    /// gateway having no upstream to send to, to the alias the client asked
    /// for. Every other error passes through unchanged.
    pub fn for_model(self, alias: &str) -> Self {
        match self {
            AppError::Upstream { status, body, .. } => {
                AppError::Upstream { status, body, model: Some(alias.to_string()) }
            }
            AppError::UpstreamUnreadable { status, excerpt, .. } => {
                AppError::UpstreamUnreadable { status, excerpt, model: Some(alias.to_string()) }
            }
            AppError::Unroutable { reason, .. } => {
                AppError::Unroutable { reason, model: Some(alias.to_string()) }
            }
            AppError::UpstreamUnreachable { kind, detail, .. } => {
                AppError::UpstreamUnreachable { kind, detail, model: Some(alias.to_string()) }
            }
            other => other,
        }
    }

    /// What a failed `send()` to an upstream means. A request that could not
    /// be BUILT — a stored credential with a character no header may carry, a
    /// malformed URL — never left the gateway: that is the gateway's own
    /// configuration fault, reported as internal and never counted against the
    /// replica. Anything else is an upstream that did not answer.
    pub fn upstream_send_error(e: &reqwest::Error) -> Self {
        if e.is_builder() {
            return AppError::UpstreamUnbuildable(format!("{e:#}"));
        }
        // The guard refused the address a host name resolved to, or a redirect
        // hop: it says so with a typed error inside the failure.
        match streamscope_mcp_auth::ssrf::refusal(e) {
            Some(streamscope_mcp_auth::ssrf::Refusal::Address) => {
                return AppError::EgressRefused(
                    "the provider's address is not on the platform's llm egress list".to_string(),
                );
            }
            Some(streamscope_mcp_auth::ssrf::Refusal::Downgrade) => {
                return AppError::EgressRefused(
                    "the provider redirected from https down to plain http, which is never followed".to_string(),
                );
            }
            None => {}
        }
        let kind = if e.is_timeout() {
            "timeout"
        } else if e.is_connect() {
            "connection"
        } else if e.is_request() {
            "request"
        } else {
            "other"
        };
        AppError::UpstreamUnreachable { kind, detail: format!("{e:#}"), model: None }
    }

    fn upstream_timed_out(&self) -> bool {
        matches!(self, AppError::UpstreamUnreachable { kind: "timeout", .. })
    }

    /// 504 for an upstream that did not answer in time, 502 for one that could
    /// not be reached at all.
    fn unreachable_status(&self) -> StatusCode {
        if self.upstream_timed_out() { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY }
    }

    /// The status a client is refused with for an upstream's answer `status`:
    /// that status itself, except that an error payload inside a success
    /// answer is refused with 400 — the client is never handed a 2xx for it.
    fn upstream_client_status(status: u16) -> StatusCode {
        match StatusCode::from_u16(status) {
            Ok(s) if s.is_success() => StatusCode::BAD_REQUEST,
            Ok(s) => s,
            Err(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// A limit refusal without a bucket — for a throttle outside the four limit
    /// buckets (the pre-auth IP limiter).
    pub fn rate_limited(message: impl Into<String>) -> Self {
        AppError::RateLimited { message: message.into(), bucket: None }
    }

    /// Which limit bucket refused the request, on a limit refusal.
    pub fn limit_bucket(&self) -> Option<crate::middleware::rate_limit::LimitBucket> {
        match self {
            AppError::RateLimited { bucket, .. } => *bucket,
            AppError::BudgetExceeded { bucket, .. } => Some(*bucket),
            _ => None,
        }
    }

    /// Why the dispatch gate gave no capacity, on a gate refusal.
    pub fn gate_refusal(&self) -> Option<&'static str> {
        match self {
            AppError::Saturated { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// Extract error metadata for audit recording: (status_code, category, detail).
    pub fn audit_error_info(&self) -> (u16, &'static str, String) {
        match self {
            AppError::Auth(e) => (
                if matches!(e, AuthError::Cache(_)) { 503 }
                else if matches!(
                    e,
                    AuthError::Forbidden(_)
                        | AuthError::WorkspaceMcpAccessDenied { .. }
                        | AuthError::WorkspaceA2aAccessDenied { .. }
                ) { 403 }
                else { 401 },
                "auth",
                e.to_string(),
            ),
            AppError::RateLimited { message, .. } => (429, "rate_limit", message.clone()),
            AppError::BudgetExceeded { message, .. } => (429, "budget_exceeded", message.clone()),
            AppError::Saturated { message, reason, .. } => {
                (429, "capacity", format!("{reason}: {message}"))
            }
            AppError::BadRequest(msg) => (400, "bad_request", truncate_error_detail(msg, 500)),
            AppError::Upstream { status, body, .. } => {
                let detail = envelope::upstream_error_detail(body).unwrap_or_else(|| {
                    if (200..300).contains(status) {
                        format!("upstream returned {status} with an error payload")
                    } else {
                        format!("upstream status {status}")
                    }
                });
                // The row records what the client was refused with, as for
                // every other category.
                (
                    Self::upstream_client_status(*status).as_u16(),
                    "upstream",
                    truncate_error_detail(&detail, 500),
                )
            }
            AppError::UpstreamUnreadable { status, excerpt, .. } => {
                let detail = if excerpt.is_empty() {
                    format!("upstream returned {status} with an empty body")
                } else {
                    format!("upstream returned {status} with a body that is not JSON: {excerpt}")
                };
                (502, "upstream", truncate_error_detail(&detail, 500))
            }
            AppError::UpstreamUnreachable { kind, detail, .. } => (
                self.unreachable_status().as_u16(),
                "upstream",
                truncate_error_detail(&format!("upstream unreachable ({kind}): {detail}"), 500),
            ),
            AppError::Unroutable { reason, .. } => (502, "upstream", (*reason).to_string()),
            AppError::ModelNotFound(msg) => (404, "model_not_found", msg.clone()),
            AppError::Internal(msg) => (500, "internal", truncate_error_detail(msg, 500)),
            AppError::UpstreamUnbuildable(msg) => (
                500,
                "internal",
                truncate_error_detail(&format!("upstream request could not be built: {msg}"), 500),
            ),
            AppError::EgressRefused(msg) => (502, "egress_refused", truncate_error_detail(msg, 500)),
            AppError::Anyhow(e) => (500, "internal", truncate_error_detail(&e.to_string(), 500)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn auth_missing_header_returns_401() {
        let err = AppError::Auth(AuthError::MissingHeader);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_invalid_key_returns_401() {
        let err = AppError::Auth(AuthError::InvalidKey("sk-abc12345".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_key_revoked_returns_401() {
        let err = AppError::Auth(AuthError::KeyRevoked("sk-abc12345".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_key_expired_returns_401() {
        let err = AppError::Auth(AuthError::KeyExpired("sk-abc12345".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_unrecognized_format_returns_401() {
        let err = AppError::Auth(AuthError::UnrecognizedFormat("not-a-valid-".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_cache_error_returns_500() {
        let err = AppError::Auth(AuthError::Cache("lookup failed".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn rate_limited_returns_429() {
        let err = AppError::rate_limited("requests per minute limit exceeded");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn budget_exceeded_returns_429() {
        let err = AppError::BudgetExceeded {
            message: "daily budget exceeded".into(),
            bucket: crate::middleware::rate_limit::LimitBucket::Member,
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn bad_request_returns_400() {
        let err = AppError::BadRequest("invalid JSON".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn internal_error_returns_500() {
        let err = AppError::Internal("something broke".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn model_not_found_returns_404() {
        let err = AppError::ModelNotFound("gpt-5".into());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn upstream_error_preserves_status() {
        let err = AppError::upstream(502, "bad gateway");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn upstream_error_out_of_range_status_returns_502() {
        // StatusCode::from_u16 rejects values < 100
        let err = AppError::upstream(99, "invalid status");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn an_error_inside_a_success_answer_refuses_with_400_and_names_the_real_status() {
        // The client is never handed a 2xx for a refusal — and the message
        // states the status the upstream really sent, not the one it was
        // refused with.
        let e = AppError::upstream(200, r#"{"error":{"message":"bad"}}"#).for_model("m");
        let client = e.client_error();
        assert_eq!(client.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            client.message,
            "m: upstream provider returned an error inside a successful response (HTTP 200): bad"
        );
        // Positive control: an error status is passed through as it came.
        let e = AppError::upstream(404, r#"{"error":{"message":"gone"}}"#);
        assert_eq!(e.client_error().status, StatusCode::NOT_FOUND);
    }

    /// The guard's refusal travels inside reqwest's connect error; found there
    /// it is a policy refusal — not retried, no breaker strike — beside the
    /// positive control: the same name on a surface that lists it, where
    /// nothing listens, is an upstream that did not answer.
    #[tokio::test]
    async fn a_refusal_by_the_egress_guard_is_typed_and_a_dead_upstream_is_not() {
        let client = crate::mcp::oauth_http::guarded_egress_builder(
            streamscope_mcp_auth::ssrf::Egress::PublicOnly,
            0,
            None,
        )
        .connect_timeout(std::time::Duration::from_millis(300))
        .build()
        .unwrap();
        let refused = client.get("http://localhost:9/").send().await.expect_err("localhost is private");
        let e = AppError::upstream_send_error(&refused);
        assert!(matches!(e, AppError::EgressRefused(_)), "{e:?}");
        assert_eq!(e.client_error().status, StatusCode::BAD_GATEWAY);
        assert!(crate::proxy::routing::another_replica_may_answer(&e), "another replica may be listed");
        crate::test_egress::install();
        let listed = crate::mcp::oauth_http::guarded_egress_builder(
            streamscope_mcp_auth::ssrf::Egress::Surface(streamscope_mcp_auth::egress::Surface::Mcp),
            0,
            None,
        )
        .build()
        .unwrap();
        let dead = listed.get("http://localhost:9/").send().await.expect_err("nothing listens on the discard port");
        let e = AppError::upstream_send_error(&dead);
        assert!(matches!(e, AppError::UpstreamUnreachable { .. }), "{e:?}");
    }

    #[tokio::test]
    async fn an_upstream_that_cannot_be_reached_is_a_gateway_failure_not_an_internal_one() {
        // A port nothing listens on: the error the forward path really gets.
        let refused = reqwest::Client::new()
            .get("http://127.0.0.1:9/")
            .send()
            .await
            .expect_err("nothing listens on the discard port");
        let e = AppError::upstream_send_error(&refused).for_model("m");
        assert!(matches!(e, AppError::UpstreamUnreachable { kind: "connection", .. }), "{e:?}");
        let client = e.client_error();
        assert_eq!((client.status, client.kind), (StatusCode::BAD_GATEWAY, "upstream_error"));
        assert_eq!(client.message, "m: upstream provider could not be reached");
        // The transport detail is the operator's, never the client's.
        let (status, category, detail) = e.audit_error_info();
        assert_eq!((status, category), (502, "upstream"));
        assert!(detail.starts_with("upstream unreachable (connection): "), "{detail}");
        assert!(e.gate_refusal().is_none());
    }

    #[tokio::test]
    async fn a_request_that_could_not_be_built_never_reached_the_upstream() {
        // A header value no request may carry — a stored key with a newline —
        // fails inside the client before anything is sent.
        let unbuildable = reqwest::Client::new()
            .get("http://127.0.0.1:9/")
            .header("authorization", "Bearer key\nwith-a-newline")
            .send()
            .await
            .expect_err("the header is refused before sending");
        assert!(unbuildable.is_builder(), "{unbuildable:?}");
        let e = AppError::upstream_send_error(&unbuildable);
        assert!(matches!(e, AppError::UpstreamUnbuildable(_)), "{e:?}");
        let (status, category, detail) = e.audit_error_info();
        assert_eq!((status, category), (500, "internal"));
        assert!(detail.starts_with("upstream request could not be built: "), "{detail}");
        assert_eq!(e.client_error().status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn an_upstream_that_timed_out_is_a_gateway_timeout() {
        let e = AppError::UpstreamUnreachable { kind: "timeout", detail: "deadline".into(), model: None };
        let client = e.client_error();
        assert_eq!((client.status, client.kind), (StatusCode::GATEWAY_TIMEOUT, "upstream_error"));
        assert_eq!(client.message, "upstream provider did not respond in time");
        assert_eq!(e.audit_error_info().0, 504);
    }

    #[test]
    fn only_a_gate_refusal_carries_a_refusal_reason() {
        let refusal = AppError::Saturated {
            message: "busy".into(),
            reason: "queue_timeout",
            retry_after_secs: 3,
        };
        assert_eq!(refusal.gate_refusal(), Some("queue_timeout"));
        // A rate limit is also a 429, and is not a capacity refusal.
        let limited = AppError::RateLimited { message: "slow down".into(), bucket: None };
        assert_eq!(limited.gate_refusal(), None);
    }

    #[test]
    fn a_success_answer_that_cannot_be_read_refuses_with_502_and_keeps_its_body_for_the_audit() {
        let page = "<html>provider maintenance window</html>";
        let e = AppError::upstream_unreadable(200, page.as_bytes()).for_model("m");
        let client = e.client_error();
        assert_eq!(client.status, StatusCode::BAD_GATEWAY);
        assert_eq!(client.kind, "upstream_error");
        assert_eq!(
            client.message,
            "m: upstream provider returned a response the gateway could not read (HTTP 200)"
        );
        // The body is the operator's to read, never the client's.
        assert!(!client.message.contains("maintenance"));
        let (status, category, detail) = e.audit_error_info();
        assert_eq!((status, category), (502, "upstream"));
        assert!(detail.contains(page), "{detail}");
        // An empty body says so rather than quoting nothing.
        let (_, _, empty) = AppError::upstream_unreadable(200, b"").audit_error_info();
        assert_eq!(empty, "upstream returned 200 with an empty body");
        // Only the body's start is kept.
        let long = "x".repeat(10_000);
        let AppError::UpstreamUnreadable { excerpt, .. } = AppError::upstream_unreadable(200, long.as_bytes())
        else {
            unreachable!()
        };
        assert_eq!(excerpt.len(), 200);
    }

    #[test]
    fn serde_json_syntax_error_maps_to_bad_request() {
        let e: Result<serde_json::Value, _> = serde_json::from_str("not valid json");
        let err: AppError = e.unwrap_err().into();
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn reqwest_error_maps_to_internal() {
        // Build a reqwest error with a relative URL (no host)
        let err: AppError = reqwest::Client::new()
            .get("")
            .build()
            .unwrap_err()
            .into();
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── audit_error_info tests ──

    #[test]
    fn audit_info_auth_invalid_key() {
        let err = AppError::Auth(AuthError::InvalidKey("sk-abc12345".into()));
        let (status, cat, detail) = err.audit_error_info();
        assert_eq!(status, 401);
        assert_eq!(cat, "auth");
        assert!(detail.contains("invalid"));
        assert!(detail.contains("sk-abc12345"));
    }

    #[test]
    fn audit_info_auth_cache_returns_503() {
        let err = AppError::Auth(AuthError::Cache("lookup failed".into()));
        let (status, cat, _) = err.audit_error_info();
        assert_eq!(status, 503);
        assert_eq!(cat, "auth");
    }

    #[test]
    fn audit_info_budget_exceeded() {
        let err = AppError::BudgetExceeded {
            message: "daily budget exceeded".into(),
            bucket: crate::middleware::rate_limit::LimitBucket::Workspace,
        };
        let (status, cat, detail) = err.audit_error_info();
        assert_eq!(status, 429);
        assert_eq!(cat, "budget_exceeded");
        assert_eq!(detail, "daily budget exceeded");
    }

    #[test]
    fn audit_info_rate_limit() {
        let err = AppError::rate_limited("RPM exceeded");
        let (status, cat, detail) = err.audit_error_info();
        assert_eq!(status, 429);
        assert_eq!(cat, "rate_limit");
        assert_eq!(detail, "RPM exceeded");
    }

    #[test]
    fn audit_info_upstream_extracts_message() {
        let err = AppError::upstream(429, r#"{"error":{"message":"rate limit exceeded"}}"#);
        let (status, cat, detail) = err.audit_error_info();
        assert_eq!(status, 429);
        assert_eq!(cat, "upstream");
        assert_eq!(detail, "rate limit exceeded");
    }

    #[test]
    fn audit_info_model_not_found() {
        let err = AppError::ModelNotFound("gpt-5".into());
        let (status, cat, _) = err.audit_error_info();
        assert_eq!(status, 404);
        assert_eq!(cat, "model_not_found");
    }

    #[test]
    fn truncate_detail_respects_char_boundary() {
        let long = "a".repeat(600);
        let truncated = truncate_error_detail(&long, 500);
        assert_eq!(truncated.len(), 500);
    }
}
