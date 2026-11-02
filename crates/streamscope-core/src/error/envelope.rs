//! The error body each client protocol's own specification defines.
//!
//! A gateway error is decided ONCE — status, category, message — as a
//! [`ClientError`], and rendered here in the grammar of the protocol the client
//! spoke. A client SDK parses an error only in its own grammar: handed another
//! protocol's body it falls back to the status line and prints the raw JSON,
//! so every error it sees reads as `Not Found: {…}` whatever it said.
//!
//! - Chat Completions / Responses — `{"error":{"message","type","param","code"}}`.
//! - Anthropic Messages — `{"type":"error","error":{"type","message"}}`, the
//!   `type` fixed by the HTTP status.
//! - Gemini `generateContent` — AIP-193, `{"error":{"code","message","status"}}`,
//!   `code` the HTTP status and `status` its `google.rpc.Code` name.
//!
//! Invariant to preserve: every HTTP error body an LLM route returns is shaped
//! here, and so are the mid-stream errors whose grammar these same specs define
//! (Gemini's AIP-193 chunk via [`ClientError::stream_failure`], an Anthropic
//! error's `type` via [`anthropic_stream_error_type`], the Chat Completions
//! error chunk and the Responses `error` event via [`openai_stream_error`]).
//! A handler or pipeline
//! exit that renders its own error JSON drifts from the spec in whichever way it
//! happens to — add a case here instead. The per-target shapes are locked by the
//! tests below.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{Value, json};

use crate::api::sse::ApiVersion;

/// What a client is told about a failed request — decided once, rendered per
/// protocol by [`ClientError::body`].
#[derive(Debug, Clone)]
pub struct ClientError {
    pub status: StatusCode,
    /// The gateway's own category, e.g. `upstream_error`. The OpenAI grammar
    /// carries it as `error.type`; the other two derive their category from the
    /// status, as their specs define it.
    pub kind: &'static str,
    pub message: String,
    /// On a limit refusal: which limit refused it.
    pub bucket: Option<&'static str>,
}

impl ClientError {
    /// An upstream failure reported mid-stream: the status line is already
    /// sent, so it is stated as the server fault it is.
    pub fn stream_failure(message: &str) -> Self {
        ClientError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            kind: "upstream_error",
            message: message.to_string(),
            bucket: None,
        }
    }

    /// This error's body in `protocol`'s grammar.
    pub fn body(&self, protocol: ApiVersion) -> Value {
        match protocol {
            ApiVersion::ChatCompletions | ApiVersion::Responses => {
                let mut error = json!({
                    "message": self.message,
                    "type": self.kind,
                    "param": null,
                    "code": null,
                });
                if let Some(bucket) = self.bucket {
                    error["bucket"] = bucket.into();
                }
                json!({ "error": error })
            }
            ApiVersion::AnthropicMessages => {
                let mut error = json!({
                    "type": anthropic_error_type(self.status),
                    "message": self.message,
                });
                // The spec lets the members of `error` grow; `bucket` is the
                // gateway's own and no Anthropic client reads it.
                if let Some(bucket) = self.bucket {
                    error["bucket"] = bucket.into();
                }
                json!({ "type": "error", "error": error })
            }
            ApiVersion::GoogleGemini => json!({
                "error": {
                    "code": self.status.as_u16(),
                    "message": self.message,
                    "status": google_rpc_status(self.status),
                }
            }),
        }
    }

    /// The full HTTP response in `protocol`'s grammar. `self` rides along as a
    /// response extension so [`render_errors_in`] can re-render it for a route
    /// that speaks another protocol.
    pub fn into_response(self, protocol: ApiVersion) -> Response {
        let mut response = Response::new(Body::from(self.body(protocol).to_string()));
        *response.status_mut() = self.status;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        response.extensions_mut().insert(self);
        response
    }
}

/// Route layer: re-render every gateway error a handler under it returns in
/// `protocol`'s grammar. Mounted per protocol on the routes that speak it, so
/// the protocol comes from the route and nothing is read off the request.
/// Status and every other header (a `Retry-After` included) are kept; only the
/// body is replaced. A response that is not a gateway error passes untouched.
pub async fn render_errors_in(
    State(protocol): State<ApiVersion>,
    req: Request,
    next: Next,
) -> Response {
    render_as(protocol, next.run(req).await)
}

/// Re-render `response` in `protocol`'s grammar when it is a gateway error.
pub fn render_as(protocol: ApiVersion, response: Response) -> Response {
    let Some(error) = response.extensions().get::<ClientError>().cloned() else {
        return response;
    };
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(error.body(protocol).to_string()))
}

/// The Anthropic error `type` for an HTTP status, per the Messages API's
/// error table. An unlisted 4xx is `invalid_request_error` (the spec says that
/// type "may also be used for other 4XX status codes"); an unlisted 5xx is
/// `api_error`.
pub fn anthropic_error_type(status: StatusCode) -> &'static str {
    match status.as_u16() {
        401 => "authentication_error",
        402 => "billing_error",
        403 => "permission_error",
        404 => "not_found_error",
        409 => "conflict_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        504 => "timeout_error",
        529 => "overloaded_error",
        s if (400..500).contains(&s) => "invalid_request_error",
        _ => "api_error",
    }
}

/// Every `type` the Anthropic error table defines.
const ANTHROPIC_ERROR_TYPES: &[&str] = &[
    "invalid_request_error",
    "authentication_error",
    "billing_error",
    "permission_error",
    "not_found_error",
    "conflict_error",
    "request_too_large",
    "rate_limit_error",
    "api_error",
    "timeout_error",
    "overloaded_error",
];

/// The Anthropic error `type` for a mid-stream error that carries no HTTP
/// status — only whatever code the upstream attached, in the upstream's own
/// vocabulary. A code already in Anthropic's table is kept; any other (an
/// OpenAI `server_error`, a Gemini status name) is `api_error`, never passed
/// through as a type no Anthropic client knows.
pub fn anthropic_stream_error_type(code: Option<&str>) -> &'static str {
    code.and_then(|c| ANTHROPIC_ERROR_TYPES.iter().copied().find(|t| *t == c))
        .unwrap_or("api_error")
}

/// Every name in `google/rpc/code.proto` — the closed vocabulary a Gemini
/// upstream's error `status` is written in.
const GOOGLE_RPC_CODES: &[&str] = &[
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// A mid-stream error's `code` for an OpenAI-protocol client, from whatever the
/// upstream called it. The two FOREIGN vocabularies are closed, so a code in
/// one is recognised and translated by what it means for a retry: a rate limit
/// — Anthropic's `rate_limit_error`, Gemini's `RESOURCE_EXHAUSTED` — is
/// `rate_limit_exceeded`; a request rejected as sent, which no retry can make
/// succeed — Anthropic's `invalid_request_error` / `request_too_large`,
/// Gemini's `INVALID_ARGUMENT` / `FAILED_PRECONDITION` / `OUT_OF_RANGE` — is
/// `invalid_prompt`; every other code of theirs the server fault
/// `server_error`. Anything else came from an OpenAI or OpenAI-compatible
/// upstream and is already in the client's vocabulary, so it passes as sent: a
/// code such as `context_length_exceeded` is what a client acts on (Codex
/// compacts on it), and flattening it would turn a request that can never
/// succeed into one it retries. No code at all is `server_error`.
pub fn openai_stream_error_code(code: Option<&str>) -> String {
    match code {
        Some("rate_limit_error" | "RESOURCE_EXHAUSTED") => "rate_limit_exceeded".to_string(),
        Some(
            "invalid_request_error" | "request_too_large" | "INVALID_ARGUMENT" | "FAILED_PRECONDITION"
            | "OUT_OF_RANGE",
        ) => "invalid_prompt".to_string(),
        Some(c) if ANTHROPIC_ERROR_TYPES.contains(&c) || GOOGLE_RPC_CODES.contains(&c) => {
            "server_error".to_string()
        }
        Some(c) if !c.is_empty() => c.to_string(),
        _ => "server_error".to_string(),
    }
}

/// An upstream failure reported mid-stream to an OpenAI-protocol client, as
/// that protocol streams it. Chat Completions defines no stream error of its
/// own: the SDKs raise on a chunk carrying the HTTP error object, so the chunk
/// IS that object (`{"error":{message,type,param,code}}`). Responses defines
/// the `error` event, whose members sit beside its `type`, not under an
/// `error` key. `code` is the upstream's, translated by
/// [`openai_stream_error_code`].
pub fn openai_stream_error(protocol: ApiVersion, message: &str, code: Option<&str>) -> Value {
    let code = openai_stream_error_code(code);
    match protocol {
        ApiVersion::Responses => json!({
            "type": "error",
            "code": code,
            "message": message,
            "param": null,
        }),
        _ => {
            let mut body = ClientError::stream_failure(message).body(ApiVersion::ChatCompletions);
            body["error"]["code"] = code.into();
            body
        }
    }
}

/// The `google.rpc.Code` name AIP-193 pairs with an HTTP status, per the HTTP
/// mappings in `google/rpc/code.proto`. Where a status maps to several codes
/// the general one is used; an unlisted 4xx is `FAILED_PRECONDITION`, an
/// unlisted 5xx `INTERNAL`, except 502 — a failure of the service behind the
/// gateway — which is the transient `UNAVAILABLE`.
pub fn google_rpc_status(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 | 413 => "INVALID_ARGUMENT",
        401 => "UNAUTHENTICATED",
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        408 | 504 => "DEADLINE_EXCEEDED",
        409 => "ABORTED",
        416 => "OUT_OF_RANGE",
        429 => "RESOURCE_EXHAUSTED",
        499 => "CANCELLED",
        501 => "UNIMPLEMENTED",
        502 | 503 => "UNAVAILABLE",
        s if (400..500).contains(&s) => "FAILED_PRECONDITION",
        _ => "INTERNAL",
    }
}

/// The upstream's own message, when its body carries one where every protocol
/// we speak puts it: `error.message` (OpenAI, Anthropic, Gemini), or a bare
/// `error` string. This is the only part of an upstream body a client is ever
/// shown; the rest (an RFC 7807 `detail`, a vendor `metadata` object) is for
/// [`upstream_error_detail`]. It is passed on as the upstream wrote it, so it
/// is not scrubbed: a provider can name its own account in it (Anthropic's
/// rate-limit message carries the organisation id).
pub fn upstream_error_message(body: &str) -> Option<String> {
    message_in(&serde_json::from_str(body).ok()?)
}

/// The error a parsed upstream body carries. The protocols' own place comes
/// first: a top-level `error` — every protocol's error body, and what an
/// OpenAI-compatible server answers with a success status (vLLM; OpenRouter
/// when generation fails before any output). Only a body without one is read
/// for OpenRouter's extension of the Chat Completions wire: the first choice
/// carrying an `error`, beside its partial content and `finish_reason:
/// "error"`, when generation failed after some output — one failed choice
/// makes the whole answer an error, as a top-level one does. Only an object
/// with members or a non-blank message is an error.
pub fn error_in(v: &Value) -> Option<&Value> {
    let present = |e: &&Value| is_error(e);
    v.get("error").filter(present).or_else(|| {
        v.get("choices")?
            .as_array()?
            .iter()
            .find_map(|choice| choice.get("error").filter(present))
    })
}

/// Whether an `error` member says anything: an object with members or a
/// non-blank message is an error; `null`, `false`, `""` or `{}` is none. The
/// one reading of it, for whole answers ([`error_in`]) and stream chunks alike.
pub fn is_error(error: &Value) -> bool {
    match error {
        Value::Object(o) => !o.is_empty(),
        Value::String(s) => !s.trim().is_empty(),
        _ => false,
    }
}

/// The HTTP status an error object names in its `code`, where that is a
/// number in the error range (OpenRouter's errors; vLLM's): `None` for
/// OpenAI's and Anthropic's string codes, or a number that is no error status.
pub fn error_http_status(error: &Value) -> Option<u16> {
    error
        .get("code")?
        .as_u64()
        .and_then(|c| u16::try_from(c).ok())
        .filter(|c| (400..=599).contains(c))
}

/// `error.message`, or a bare `error` string, of a parsed upstream body —
/// read from [`error_in`].
fn message_in(v: &Value) -> Option<String> {
    let error = error_in(v)?;
    error
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| error.as_str())
        .filter(|m| !m.trim().is_empty())
        .map(String::from)
}

/// The fullest account of an upstream refusal its body gives, for the audit
/// row and the operator — never for the client. Adds what the client-safe
/// [`upstream_error_message`] leaves out: an aggregator's `error.metadata.raw`
/// (the refusal of the provider behind it — OpenRouter's "…is temporarily
/// rate-limited upstream") and an RFC 7807 problem body's `title` / `detail`
/// (NVIDIA's "Function '…': Not found for account '…'").
pub fn upstream_error_detail(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let text = |p: &str| v.pointer(p).and_then(Value::as_str).filter(|s| !s.trim().is_empty());
    let message = message_in(&v);
    let raw = error_in(&v)
        .and_then(|e| e.pointer("/metadata/raw"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty());
    let problem = text("/detail").or_else(|| text("/title"));
    match (message, raw.or(problem)) {
        (Some(m), Some(extra)) if m != extra => Some(format!("{m}: {extra}")),
        (Some(m), _) => Some(m),
        (None, Some(extra)) => Some(extra.to_string()),
        (None, None) => None,
    }
}

/// How the gateway reads an upstream's HTTP status, in words a client can act
/// on. The status alone decides it, so the same refusal reads the same on
/// every protocol.
pub fn upstream_refusal_reason(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 | 422 => "rejected the request",
        // Neutral on whose: the gateway's on a curated route, the client's own
        // on a BYOK pass-through.
        401 => "rejected the credentials it was sent",
        402 => "refused the request for billing reasons",
        403 => "refused access",
        // Not "the model is missing": a wrong base URL or a proxy's own 404
        // page answers the same status.
        404 => "answered not found",
        408 | 504 => "timed out",
        409 => "reported a conflict",
        413 => "rejected the request as too large",
        429 => "is rate-limiting requests; retry later",
        s if (200..300).contains(&s) => "returned an error inside a successful response",
        s if s >= 500 => "failed",
        _ => "returned an error",
    }
}

/// The client message for an upstream refusal: the model the client asked
/// for, the gateway's reading of the status, the status itself, then the
/// upstream's own message when it sent one.
pub fn upstream_refusal_message(status: StatusCode, body: &str, model: Option<&str>) -> String {
    let reason = upstream_refusal_reason(status);
    let code = status.as_u16();
    let mut msg = match model {
        Some(m) => format!("{m}: upstream provider {reason} (HTTP {code})"),
        None => format!("upstream provider {reason} (HTTP {code})"),
    };
    if let Some(upstream) = upstream_error_message(body) {
        msg.push_str(": ");
        msg.push_str(&upstream);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(status: u16) -> ClientError {
        ClientError {
            status: StatusCode::from_u16(status).unwrap(),
            kind: "upstream_error",
            message: "boom".into(),
            bucket: None,
        }
    }

    #[test]
    fn openai_grammar_carries_the_four_error_members() {
        for protocol in [ApiVersion::ChatCompletions, ApiVersion::Responses] {
            let body = err(404).body(protocol);
            assert_eq!(
                body,
                json!({"error": {"message": "boom", "type": "upstream_error", "param": null, "code": null}})
            );
        }
    }

    #[test]
    fn anthropic_grammar_is_a_typed_error_object() {
        let body = err(404).body(ApiVersion::AnthropicMessages);
        assert_eq!(
            body,
            json!({"type": "error", "error": {"type": "not_found_error", "message": "boom"}})
        );
    }

    #[test]
    fn gemini_grammar_is_aip_193() {
        let body = err(429).body(ApiVersion::GoogleGemini);
        assert_eq!(
            body,
            json!({"error": {"code": 429, "message": "boom", "status": "RESOURCE_EXHAUSTED"}})
        );
    }

    #[test]
    fn a_limit_bucket_rides_inside_the_error_object_where_the_grammar_allows() {
        let mut e = err(429);
        e.bucket = Some("workspace");
        assert_eq!(e.body(ApiVersion::ChatCompletions)["error"]["bucket"], "workspace");
        assert_eq!(e.body(ApiVersion::AnthropicMessages)["error"]["bucket"], "workspace");
        // AIP-193 defines no free-form member; the bucket is not invented into it.
        assert!(e.body(ApiVersion::GoogleGemini)["error"].get("bucket").is_none());
    }

    #[test]
    fn anthropic_type_follows_the_status_table_on_both_sides_of_each_range() {
        let cases = [
            (400, "invalid_request_error"),
            (401, "authentication_error"),
            (402, "billing_error"),
            (403, "permission_error"),
            (404, "not_found_error"),
            (409, "conflict_error"),
            (413, "request_too_large"),
            (422, "invalid_request_error"),
            (429, "rate_limit_error"),
            (499, "invalid_request_error"),
            (500, "api_error"),
            (502, "api_error"),
            (503, "api_error"),
            (504, "timeout_error"),
            (529, "overloaded_error"),
        ];
        for (status, want) in cases {
            assert_eq!(anthropic_error_type(StatusCode::from_u16(status).unwrap()), want, "{status}");
        }
    }

    #[test]
    fn a_stream_error_type_is_always_one_the_anthropic_table_defines() {
        assert_eq!(anthropic_stream_error_type(Some("overloaded_error")), "overloaded_error");
        assert_eq!(anthropic_stream_error_type(Some("rate_limit_error")), "rate_limit_error");
        assert_eq!(anthropic_stream_error_type(Some("server_error")), "api_error");
        assert_eq!(anthropic_stream_error_type(Some("RESOURCE_EXHAUSTED")), "api_error");
        assert_eq!(anthropic_stream_error_type(None), "api_error");
    }

    /// One case per vocabulary a stream error's code arrives in, plus none.
    #[test]
    fn a_stream_error_code_is_translated_only_out_of_a_foreign_vocabulary() {
        let cases = [
            (Some("rate_limit_exceeded"), "rate_limit_exceeded"), // OpenAI's own
            (Some("context_length_exceeded"), "context_length_exceeded"),
            (Some("insufficient_quota"), "insufficient_quota"),
            (Some("rate_limit_error"), "rate_limit_exceeded"), // Anthropic
            (Some("overloaded_error"), "server_error"),
            (Some("invalid_request_error"), "invalid_prompt"),
            (Some("request_too_large"), "invalid_prompt"),
            (Some("INVALID_ARGUMENT"), "invalid_prompt"),
            (Some("OUT_OF_RANGE"), "invalid_prompt"),
            (Some("RESOURCE_EXHAUSTED"), "rate_limit_exceeded"), // Gemini
            (Some("INTERNAL"), "server_error"),
            (Some("UNAVAILABLE"), "server_error"),
            (Some(""), "server_error"),
            (None, "server_error"),
        ];
        for (code, want) in cases {
            assert_eq!(openai_stream_error_code(code), want, "{code:?}");
        }
    }

    #[test]
    fn a_chat_completions_stream_error_is_the_http_error_object() {
        let chunk = openai_stream_error(ApiVersion::ChatCompletions, "boom", Some("RESOURCE_EXHAUSTED"));
        assert_eq!(
            chunk,
            json!({"error": {
                "message": "boom",
                "type": "upstream_error",
                "param": null,
                "code": "rate_limit_exceeded",
            }})
        );
    }

    /// Responses' `error` event carries its members beside `type` — an `error`
    /// key is what the Chat Completions chunk has, not this event.
    #[test]
    fn a_responses_stream_error_is_the_flat_error_event() {
        let event = openai_stream_error(ApiVersion::Responses, "boom", Some("overloaded_error"));
        assert_eq!(
            event,
            json!({"type": "error", "code": "server_error", "message": "boom", "param": null})
        );
        assert!(event.get("error").is_none());
    }

    #[test]
    fn google_status_follows_the_code_proto_http_mappings() {
        let cases = [
            (400, "INVALID_ARGUMENT"),
            (401, "UNAUTHENTICATED"),
            (402, "FAILED_PRECONDITION"),
            (403, "PERMISSION_DENIED"),
            (404, "NOT_FOUND"),
            (408, "DEADLINE_EXCEEDED"),
            (409, "ABORTED"),
            (413, "INVALID_ARGUMENT"),
            (429, "RESOURCE_EXHAUSTED"),
            (499, "CANCELLED"),
            (500, "INTERNAL"),
            (501, "UNIMPLEMENTED"),
            (502, "UNAVAILABLE"),
            (503, "UNAVAILABLE"),
            (504, "DEADLINE_EXCEEDED"),
            (505, "INTERNAL"),
        ];
        for (status, want) in cases {
            assert_eq!(google_rpc_status(StatusCode::from_u16(status).unwrap()), want, "{status}");
        }
    }

    #[test]
    fn the_client_is_shown_only_the_upstreams_error_message() {
        // OpenRouter: the useful text sits in `metadata.raw`, beside a user id.
        let openrouter = r#"{"error":{"message":"Provider returned error","code":429,"metadata":{"raw":"m:free is temporarily rate-limited upstream"}},"user_id":"user_x"}"#;
        assert_eq!(upstream_error_message(openrouter).as_deref(), Some("Provider returned error"));
        // RFC 7807 (NVIDIA): the detail names the operator's account.
        let nvidia = r#"{"status":404,"title":"Not Found","detail":"Function 'f': Not found for account 'acct'"}"#;
        assert_eq!(upstream_error_message(nvidia), None);
        // Anthropic and a bare string both carry it where the client may see it.
        let anthropic = r#"{"type":"error","error":{"type":"not_found_error","message":"no such model"}}"#;
        assert_eq!(upstream_error_message(anthropic).as_deref(), Some("no such model"));
        assert_eq!(upstream_error_message(r#"{"error":"nope"}"#).as_deref(), Some("nope"));
        assert_eq!(upstream_error_message(r#"{"error":{"message":"  "}}"#), None);
        assert_eq!(upstream_error_message("upstream returned 429"), None);
    }

    #[test]
    fn the_operator_detail_keeps_what_the_client_is_not_shown() {
        let openrouter = r#"{"error":{"message":"Provider returned error","metadata":{"raw":"m:free is temporarily rate-limited upstream"}}}"#;
        assert_eq!(
            upstream_error_detail(openrouter).as_deref(),
            Some("Provider returned error: m:free is temporarily rate-limited upstream")
        );
        let nvidia = r#"{"status":404,"title":"Not Found","detail":"Function 'f': Not found for account 'acct'"}"#;
        assert_eq!(
            upstream_error_detail(nvidia).as_deref(),
            Some("Function 'f': Not found for account 'acct'")
        );
        let title_only = r#"{"status":404,"title":"Not Found"}"#;
        assert_eq!(upstream_error_detail(title_only).as_deref(), Some("Not Found"));
        let plain = r#"{"error":{"message":"bad"}}"#;
        assert_eq!(upstream_error_detail(plain).as_deref(), Some("bad"));
        assert_eq!(upstream_error_detail("not json"), None);
    }

    #[test]
    fn a_choice_error_is_read_only_where_the_body_has_no_top_level_one() {
        // OpenRouter, a generation that failed after some output (its documented
        // non-streaming shape): the error sits on the choice, beside the partial
        // content and `finish_reason: "error"`.
        let on_choice = r#"{"id":"gen-1","choices":[{"index":0,"message":{"role":"assistant","content":"Partial"},"finish_reason":"error","error":{"code":502,"message":"Provider disconnected mid-stream","metadata":{"error_type":"provider_unavailable","raw":"upstream reset"}}}]}"#;
        let v: Value = serde_json::from_str(on_choice).unwrap();
        assert_eq!(error_in(&v).and_then(|e| e.get("code")), Some(&json!(502)));
        assert_eq!(upstream_error_message(on_choice).as_deref(), Some("Provider disconnected mid-stream"));
        assert_eq!(
            upstream_error_detail(on_choice).as_deref(),
            Some("Provider disconnected mid-stream: upstream reset")
        );
        // The first choice carrying one, wherever it is among them.
        let second = json!({"choices": [{"message": {"content": "ok"}}, {"error": {"message": "second failed"}}]});
        assert_eq!(error_in(&second), Some(&json!({"message": "second failed"})));
        // A top-level error is the protocol's place, and comes first.
        let both = json!({"error": {"message": "top"}, "choices": [{"error": {"message": "choice"}}]});
        assert_eq!(error_in(&both), Some(&json!({"message": "top"})));
        // Positive control: an answer is no error, and an `error` that is null
        // is none either, at either place.
        let answer = json!({"choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]});
        assert_eq!(error_in(&answer), None);
        let nulls = json!({"error": null, "choices": [{"message": {"content": "hi"}, "error": null}]});
        assert_eq!(error_in(&nulls), None);
        // Nor are an empty object, an empty message or `false`.
        for none in [json!({}), json!(""), json!("  "), json!(false)] {
            assert_eq!(error_in(&json!({"error": none.clone()})), None, "{none}");
            assert_eq!(error_in(&json!({"choices": [{"error": none.clone()}]})), None, "{none}");
        }
        // A null top-level error does not hide a choice's.
        let null_top = json!({"error": null, "choices": [{"error": {"message": "choice"}}]});
        assert_eq!(error_in(&null_top), Some(&json!({"message": "choice"})));
    }

    #[test]
    fn an_error_names_its_http_status_only_with_a_number_in_the_error_range() {
        assert_eq!(error_http_status(&json!({"code": 502, "message": "m"})), Some(502));
        assert_eq!(error_http_status(&json!({"code": 400})), Some(400));
        assert_eq!(error_http_status(&json!({"code": 599})), Some(599));
        // Both sides of the range, and the codes that name no status.
        for none in [
            json!({"code": 399}),
            json!({"code": 600}),
            json!({"code": 200}),
            json!({"code": -502}),
            json!({"code": 70000}),
            json!({"code": "invalid_api_key"}),
            json!({"code": "502"}),
            json!({"code": null}),
            json!({"message": "m"}),
        ] {
            assert_eq!(error_http_status(&none), None, "{none}");
        }
    }

    #[test]
    fn a_refusal_message_names_the_model_the_reading_and_the_status() {
        let nvidia = r#"{"status":404,"title":"Not Found","detail":"Function 'f': Not found for account 'acct'"}"#;
        let msg = upstream_refusal_message(StatusCode::NOT_FOUND, nvidia, Some("01-ai/yi-large"));
        assert_eq!(msg, "01-ai/yi-large: upstream provider answered not found (HTTP 404)");
        assert!(!msg.contains("acct"), "the operator's account must not reach the client: {msg}");

        let openrouter = r#"{"error":{"message":"Provider returned error"}}"#;
        let msg = upstream_refusal_message(StatusCode::TOO_MANY_REQUESTS, openrouter, None);
        assert_eq!(
            msg,
            "upstream provider is rate-limiting requests; retry later (HTTP 429): Provider returned error"
        );
    }

    async fn body_of(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16).await.expect("body");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    #[tokio::test]
    async fn a_route_layer_rerenders_a_gateway_error_and_passes_anything_else() {
        let e = err(429);
        let mut original = e.clone().into_response(ApiVersion::ChatCompletions);
        original
            .headers_mut()
            .insert(header::RETRY_AFTER, header::HeaderValue::from_static("7"));
        let rendered = render_as(ApiVersion::AnthropicMessages, original);
        assert_eq!(rendered.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rendered.headers()[header::RETRY_AFTER], "7");
        assert_eq!(rendered.headers()[header::CONTENT_TYPE], "application/json");
        assert!(rendered.headers().get(header::CONTENT_LENGTH).is_none());
        assert_eq!(body_of(rendered).await, e.body(ApiVersion::AnthropicMessages));

        // Positive control: a response that is not a gateway error — an
        // upstream's own JSON on a successful call — is not touched.
        let plain = Response::new(Body::from("{\"error\":\"kept verbatim\"}"));
        let passed = render_as(ApiVersion::AnthropicMessages, plain);
        assert_eq!(passed.status(), StatusCode::OK);
        assert_eq!(body_of(passed).await, json!({"error": "kept verbatim"}));
    }
}
