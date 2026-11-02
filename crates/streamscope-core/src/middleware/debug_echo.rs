//! Debug echo — returns the transformed request as an SSE event for introspection.
//!
//! Activated by `X-Debug-Echo: true` header. Emits a single `event: debug` SSE
//! event containing the upstream URL, resolved model, and full transformed body.
//! Useful for verifying transform pipeline behavior without hitting the upstream.

use axum::http::HeaderMap;

/// Check if debug echo is requested via the `X-Debug-Echo: true` header.
pub fn is_debug_echo_requested(headers: &HeaderMap) -> bool {
    headers
        .get("x-debug-echo")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Build a debug echo SSE event showing the transformed upstream request.
pub fn build_debug_event(upstream_url: &str, upstream_model: &str, body: &[u8]) -> String {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);

    let debug_data = serde_json::json!({
        "upstream_url": upstream_url,
        "upstream_model": upstream_model,
        "transformed_body": body_json,
    });

    format!("event: debug\ndata: {debug_data}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    /// The header opts a request into echoing its own transformed body back.
    /// It is read case-insensitively but only for the literal `true`: anything
    /// else — including the truthy spellings a client might reach for — leaves
    /// the request on the ordinary forward path.
    #[test]
    fn debug_echo_is_requested_only_by_a_literal_true() {
        assert!(is_debug_echo_requested(&headers(&[("x-debug-echo", "true")])));
        assert!(is_debug_echo_requested(&headers(&[("x-debug-echo", "TRUE")])));
        assert!(is_debug_echo_requested(&headers(&[("x-debug-echo", "True")])));

        assert!(!is_debug_echo_requested(&headers(&[("x-debug-echo", "false")])));
        assert!(!is_debug_echo_requested(&headers(&[("x-debug-echo", "1")])));
        assert!(!is_debug_echo_requested(&headers(&[("x-debug-echo", "yes")])));
        assert!(!is_debug_echo_requested(&headers(&[("x-debug-echo", "")])));
        assert!(!is_debug_echo_requested(&headers(&[("x-debug-echo", " true")])));
        assert!(!is_debug_echo_requested(&HeaderMap::new()));
        assert!(!is_debug_echo_requested(&headers(&[("x-debug", "true")])));
    }

    /// The event is one SSE frame carrying the body the upstream would have
    /// received. A body that does not parse becomes `null` rather than
    /// collapsing the frame — the point of the surface is to show what was
    /// about to be sent, including when that is malformed.
    #[test]
    fn a_debug_event_is_one_sse_frame_around_the_transformed_body() {
        let event = build_debug_event(
            "https://api.example.test/v1/messages",
            "claude-sonnet-5",
            br#"{"model":"upstream-name","stream":true}"#,
        );
        assert!(event.starts_with("event: debug\ndata: "));
        assert!(event.ends_with("\n\n"));
        assert_eq!(event.matches("\n\n").count(), 1, "exactly one frame");

        let payload: serde_json::Value =
            serde_json::from_str(event.trim_start_matches("event: debug\ndata: ").trim_end())
                .expect("the data line is a single JSON document");
        assert_eq!(payload["upstream_url"], "https://api.example.test/v1/messages");
        assert_eq!(payload["upstream_model"], "claude-sonnet-5");
        assert_eq!(payload["transformed_body"]["model"], "upstream-name");
        assert_eq!(payload["transformed_body"]["stream"], true);

        let broken = build_debug_event("https://x", "m", b"{not json");
        let payload: serde_json::Value =
            serde_json::from_str(broken.trim_start_matches("event: debug\ndata: ").trim_end())
                .expect("a malformed body still yields a well-formed frame");
        assert!(payload["transformed_body"].is_null());
        assert_eq!(payload["upstream_url"], "https://x");
    }
}
