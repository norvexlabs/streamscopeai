//! MCP `sampling/createMessage` intercept.
//!
//! When a virtual server is configured with [`SamplingInterceptConfig`], a
//! server-initiated `sampling/createMessage` event is *not* forwarded to the
//! connected agent. Instead the proxy synthesizes a normal LLM call through
//! its own `/v1/messages` endpoint (HTTP loopback — same trick the agent
//! analyser uses, see `streamscope_admin::agent::analysis`) and answers the
//! upstream with the result. The upstream cannot tell whether the agent or
//! the gateway produced the message.
//!
//! Why loopback rather than an in-process call: the LLM pipeline is
//! HTTP-shaped (auth → routing → transforms → audit) and there is no clean
//! Rust entry point that takes a pre-built `DomainRequest` and runs the
//! full pipeline. Until that exists, the loopback gets us coverage of every
//! surface (audit, budget, Rhai, tool policy) for free.
//!
//! Tight-loop marker (NOT an enforcer yet): the loopback request carries
//! `X-Mcp-Sampling-Depth: 1`. The LLM proxy doesn't yet read this header on
//! inbound, so today the loop is bounded only by the structural fact that
//! the LLM pipeline doesn't recursively call MCP. Inbound enforcement
//! requires a depth-incrementing intercept (read incoming, stamp `+1`)
//! plus a threshold-≥2 inbound check; the simpler "stamp 1, reject ≥1"
//! shape would falsely refuse the legitimate first loopback because the
//! intercept itself stamps 1 on every call.

use std::time::Instant;

use serde_json::{Value, json};
use streamscope_core::audit::mcp::SamplingInterceptOutcome;
use streamscope_core::config::mcp::SamplingInterceptConfig;

use super::handler::McpRouterState;

/// Bound on a loopback *error* body. It is only ever classified and logged, so
/// a cap this small loses nothing a larger one would preserve.
const LOOPBACK_ERROR_BODY_CAP: u64 = 64 * 1024;

/// Outcome returned to the caller. The caller is responsible for posting the
/// `upstream_payload` (a complete JSON-RPC response) back to the upstream
/// MCP server via [`super::upstream::forward_client_response`].
#[derive(Debug)]
pub struct InterceptOutcome {
    /// Full JSON-RPC response — `{ jsonrpc: "2.0", id, result | error }` —
    /// to POST to the upstream so it sees a complete answer to its
    /// `sampling/createMessage`.
    pub upstream_payload: Value,
    /// Typed audit signal for `mcp_audit.transform_diff.sampling_intercept`.
    pub audit_outcome: SamplingInterceptOutcome,
    /// JSON-RPC error code when the intercept failed (e.g. `-32500`,
    /// `-32429`); `None` on success.
    pub rpc_error_code: Option<i32>,
}

/// Try to intercept a server-initiated `sampling/createMessage`.
///
/// Arguments:
/// - `state` — shared proxy state (for the http client + settings)
/// - `intercept` — per-VS sampling configuration (decrypted credential bearer
///   + model alias) resolved from `tenant.mcp.virtual_servers[id].sampling_intercept`
/// - `event_data` — raw JSON-RPC payload of the upstream's
///   `sampling/createMessage` event (post-virtualization rewrite, but
///   `params` is unaffected by ssrid minting)
/// - `original_rpc_id` — upstream's authentic JSON-RPC id (NOT the rewritten
///   `ssrid.…` token); the synthesized response must echo this back so the
///   upstream matches its pending request
/// - `upstream_session_id` — raw `Mcp-Session-Id` (used as `X-Session-Id` on
///   the loopback so `gateway_audit.session_id` collapses with the upstream
///   `mcp_audit` row)
pub async fn try_intercept(
    state: &McpRouterState,
    intercept: &SamplingInterceptConfig,
    event_data: &str,
    original_rpc_id: &Value,
    upstream_session_id: Option<&str>,
) -> InterceptOutcome {
    let started = Instant::now();

    // Decrypt the operator-pasted bearer.
    let bearer = match decrypt_credential(&intercept.encrypted_credential) {
        Ok(b) => b,
        Err(reason) => return failed(original_rpc_id, reason, -32500, started),
    };

    // Pull `params` out of the upstream's JSON-RPC payload.
    let parsed: Value = match serde_json::from_str(event_data) {
        Ok(v) => v,
        Err(_) => return failed(original_rpc_id, "params_unparseable", -32500, started),
    };
    let params = match parsed.get("params") {
        Some(p) => p,
        None => return failed(original_rpc_id, "params_missing", -32500, started),
    };

    let body = build_anthropic_body(params, &intercept.model_alias);
    let port = crate::settings::proxy_settings().port;
    let url = format!("http://127.0.0.1:{port}/v1/messages");

    let mut request = state
        .mcp
        .mcp_client
        .post(&url)
        .header("Authorization", format!("Bearer {bearer}"))
        .header("X-App-Id", "mcp-sampling")
        .header("X-Mcp-Sampling-Depth", "1")
        .header("anthropic-version", streamscope_core::proxy::client::ANTHROPIC_API_VERSION)
        .json(&body);
    if let Some(sid) = upstream_session_id {
        request = request.header("X-Session-Id", sid);
    }

    let resp = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "mcp sampling intercept loopback send failed");
            return failed(original_rpc_id, "loopback_send_failed", -32500, started);
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let raw = streamscope_core::http_body::read_body_capped(resp, LOOPBACK_ERROR_BODY_CAP)
            .await
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let (reason, code) = classify_loopback_error(status, &raw);
        tracing::warn!(
            status = %status,
            reason = %reason,
            "mcp sampling intercept loopback returned error"
        );
        return failed(original_rpc_id, reason, code, started);
    }

    // The loopback body is the LLM pipeline's own response, so the honest
    // ceiling is the one the pipeline itself enforces on an upstream reply —
    // anything larger could not have been produced by the call we just made.
    let cap = streamscope_core::settings::core_settings().max_upstream_body_size as u64;
    let llm_body: Value = match streamscope_core::http_body::read_body_capped(resp, cap).await {
        Ok(raw) => match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "mcp sampling intercept failed to parse loopback body");
                return failed(original_rpc_id, "loopback_decode_failed", -32500, started);
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "mcp sampling intercept failed to read loopback body");
            return failed(original_rpc_id, "loopback_decode_failed", -32500, started);
        }
    };

    let model = llm_body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(&intercept.model_alias)
        .to_string();
    let role = llm_body
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("assistant")
        .to_string();
    let stop_reason = mcp_stop_reason(
        llm_body.get("stop_reason").and_then(Value::as_str).unwrap_or("end_turn"),
    );
    let text = extract_anthropic_text(&llm_body).unwrap_or_default();

    let upstream_payload = json!({
        "jsonrpc": "2.0",
        "id": original_rpc_id,
        "result": {
            "role": role,
            "content": { "type": "text", "text": text },
            "model": model.clone(),
            "stopReason": stop_reason,
        },
    });

    InterceptOutcome {
        upstream_payload,
        audit_outcome: SamplingInterceptOutcome::Served {
            model: Some(model),
            latency_ms: started.elapsed().as_millis() as u64,
        },
        rpc_error_code: None,
    }
}

fn failed(rpc_id: &Value, reason: &str, code: i32, started: Instant) -> InterceptOutcome {
    let _ = started; // latency tracked on the audit outcome
    let upstream_payload = json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": code,
            "message": format!("gateway sampling intercept failed: {reason}"),
        },
    });
    InterceptOutcome {
        upstream_payload,
        audit_outcome: SamplingInterceptOutcome::Failed { reason: reason.to_string() },
        rpc_error_code: Some(code),
    }
}

fn classify_loopback_error(
    status: reqwest::StatusCode,
    body: &str,
) -> (&'static str, i32) {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return ("budget_or_rate_limit", -32429);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return ("auth_failed", -32500);
    }
    if status == reqwest::StatusCode::PAYMENT_REQUIRED {
        return ("budget_exceeded", -32429);
    }
    if status == reqwest::StatusCode::BAD_REQUEST {
        // Capability mismatches and validation errors come back as 400; the
        // body usually carries a typed `code` we could re-map, but for
        // operator-visibility a single bucket is enough. Body can be inspected
        // via the audit row's error_message for forensics.
        let _ = body;
        return ("capability_or_validation", -32500);
    }
    ("loopback_http_error", -32500)
}

fn decrypt_credential(ciphertext: &str) -> Result<String, &'static str> {
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or("encryption_key_unset")?;
    streamscope_core::crypto::decrypt(ciphertext, &key)
        .map_err(|_| "credential_decrypt_failed")
}

/// Convert MCP `sampling/createMessage` `params` into an Anthropic Messages
/// POST body. The MCP shape (per spec, 2025-11-25 § Sampling) is:
///
/// ```json
/// {
///   "messages": [{ "role": "user", "content": { "type": "text", "text": "..." } }, ...],
///   "modelPreferences": { "hints": [{ "name": "claude-3-5-sonnet" }], ... },
///   "systemPrompt": "...",
///   "includeContext": "thisServer" | "allServers" | "none",
///   "temperature": 0.7,
///   "maxTokens": 1024,
///   "stopSequences": ["..."],
///   "metadata": {}
/// }
/// ```
///
/// We pass `messages`, `system`, `temperature`, `max_tokens`, `stop_sequences`
/// straight through; `model` is the operator-configured alias (the Streamscope
/// router resolves it). `modelPreferences.hints[]` is dropped — operators
/// chose the alias deliberately and we don't want upstream-driven model
/// switching defeating audit/budget config. `includeContext` is dropped
/// (we don't have visibility into "this server"'s prior turns from the
/// upstream's perspective; the synthetic call is single-turn).
fn build_anthropic_body(params: &Value, model_alias: &str) -> Value {
    let messages = params
        .get("messages")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let max_tokens = params
        .get("maxTokens")
        .and_then(Value::as_u64)
        .unwrap_or(1024);
    let temperature = params.get("temperature").cloned();
    let system = params.get("systemPrompt").and_then(Value::as_str);
    let stop_sequences = params.get("stopSequences").cloned();

    let mut body = serde_json::Map::new();
    body.insert("model".into(), Value::String(model_alias.to_string()));
    body.insert(
        "messages".into(),
        normalize_messages_for_anthropic(messages),
    );
    body.insert("max_tokens".into(), Value::from(max_tokens));
    if let Some(s) = system {
        body.insert("system".into(), Value::String(s.to_string()));
    }
    if let Some(t) = temperature {
        body.insert("temperature".into(), t);
    }
    if let Some(stop) = stop_sequences {
        body.insert("stop_sequences".into(), stop);
    }
    Value::Object(body)
}

/// MCP messages have content as either an object (single block) or an array
/// of blocks. Anthropic Messages always expects an array. Promote single
/// blocks; pass arrays through.
fn normalize_messages_for_anthropic(messages: Value) -> Value {
    let arr = match messages {
        Value::Array(a) => a,
        _ => return Value::Array(Vec::new()),
    };
    let normalized = arr
        .into_iter()
        .map(|m| {
            let mut obj = match m {
                Value::Object(o) => o,
                _ => return Value::Null,
            };
            if let Some(content) = obj.get("content").cloned() {
                let promoted = match content {
                    Value::Array(_) => content,
                    Value::Object(_) => Value::Array(vec![content]),
                    Value::String(s) => Value::Array(vec![json!({ "type": "text", "text": s })]),
                    other => Value::Array(vec![other]),
                };
                obj.insert("content".into(), promoted);
            }
            Value::Object(obj)
        })
        .filter(|v| !v.is_null())
        .collect();
    Value::Array(normalized)
}

/// Pull the first text block out of an Anthropic Messages response body.
/// Multimodal blocks (`tool_use`, `image`) are skipped — sampling clients
/// are spec-bound to render plain text.
fn extract_anthropic_text(body: &Value) -> Option<String> {
    let content = body.get("content")?.as_array()?;
    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("text")
            && let Some(text) = block.get("text").and_then(Value::as_str)
        {
            return Some(text.to_string());
        }
    }
    None
}

/// Anthropic's `stop_reason` in MCP's `CreateMessageResult.stopReason` grammar.
/// MCP names four standard values in camelCase (`endTurn`, `stopSequence`,
/// `maxTokens`, `toolUse`) and leaves the field an open string "to allow for
/// provider-specific stop reasons" — so the four with an MCP spelling are
/// renamed and any other (`pause_turn`, `refusal`, …) travels as Anthropic
/// said it.
fn mcp_stop_reason(anthropic: &str) -> String {
    match anthropic {
        "end_turn" => "endTurn",
        "stop_sequence" => "stopSequence",
        "max_tokens" => "maxTokens",
        "tool_use" => "toolUse",
        other => other,
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn build_body_default_max_tokens() {
        let params = json!({
            "messages": [{ "role": "user", "content": "hi" }],
        });
        let body = build_anthropic_body(&params, "claude-default");
        assert_eq!(body.get("model").unwrap(), "claude-default");
        assert_eq!(body.get("max_tokens").unwrap().as_u64().unwrap(), 1024);
        // String content should have been promoted to a text block array.
        let messages = body.get("messages").unwrap().as_array().unwrap();
        assert_eq!(messages.len(), 1);
        let content = messages[0].get("content").unwrap().as_array().unwrap();
        assert_eq!(content[0].get("type").unwrap(), "text");
        assert_eq!(content[0].get("text").unwrap(), "hi");
    }

    /// MCP's four standard `stopReason` values are camelCase; Anthropic's are
    /// snake_case. A provider-specific reason (the field is an open string)
    /// keeps Anthropic's own spelling rather than being guessed into one.
    #[test]
    fn stop_reasons_take_mcps_spelling() {
        assert_eq!(mcp_stop_reason("end_turn"), "endTurn");
        assert_eq!(mcp_stop_reason("stop_sequence"), "stopSequence");
        assert_eq!(mcp_stop_reason("max_tokens"), "maxTokens");
        assert_eq!(mcp_stop_reason("tool_use"), "toolUse");
        assert_eq!(mcp_stop_reason("refusal"), "refusal");
        assert_eq!(mcp_stop_reason("pause_turn"), "pause_turn");
    }

    #[test]
    fn build_body_carries_system_and_temperature() {
        let params = json!({
            "messages": [],
            "systemPrompt": "you are helpful",
            "temperature": 0.5,
            "maxTokens": 256,
            "stopSequences": ["END"],
        });
        let body = build_anthropic_body(&params, "claude-default");
        assert_eq!(body.get("system").unwrap(), "you are helpful");
        assert_eq!(body.get("temperature").unwrap().as_f64().unwrap(), 0.5);
        assert_eq!(body.get("max_tokens").unwrap().as_u64().unwrap(), 256);
        assert_eq!(
            body.get("stop_sequences").unwrap().as_array().unwrap()[0],
            "END"
        );
    }

    #[test]
    fn build_body_drops_model_preferences() {
        // Operator-chosen alias wins over upstream `modelPreferences.hints`.
        let params = json!({
            "messages": [],
            "modelPreferences": {
                "hints": [{ "name": "rogue-model" }],
                "intelligencePriority": 1.0,
            },
        });
        let body = build_anthropic_body(&params, "claude-default");
        assert_eq!(body.get("model").unwrap(), "claude-default");
        assert!(
            body.get("modelPreferences").is_none(),
            "modelPreferences must not leak into the upstream body"
        );
    }

    #[test]
    fn extract_text_picks_first_text_block() {
        let body = json!({
            "content": [
                { "type": "tool_use", "id": "tu_1", "name": "x", "input": {} },
                { "type": "text", "text": "hello world" },
                { "type": "text", "text": "second" },
            ],
        });
        assert_eq!(extract_anthropic_text(&body).as_deref(), Some("hello world"));
    }

    #[test]
    fn classify_loopback_status_codes() {
        assert_eq!(
            classify_loopback_error(reqwest::StatusCode::TOO_MANY_REQUESTS, ""),
            ("budget_or_rate_limit", -32429)
        );
        assert_eq!(
            classify_loopback_error(reqwest::StatusCode::UNAUTHORIZED, ""),
            ("auth_failed", -32500)
        );
        assert_eq!(
            classify_loopback_error(reqwest::StatusCode::BAD_REQUEST, ""),
            ("capability_or_validation", -32500)
        );
        assert_eq!(
            classify_loopback_error(reqwest::StatusCode::PAYMENT_REQUIRED, ""),
            ("budget_exceeded", -32429)
        );
        assert_eq!(
            classify_loopback_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, ""),
            ("loopback_http_error", -32500)
        );
    }

    #[test]
    fn failed_outcome_carries_jsonrpc_error_envelope() {
        let outcome = failed(&json!(42), "auth_failed", -32500, Instant::now());
        assert_eq!(outcome.rpc_error_code, Some(-32500));
        let id = outcome.upstream_payload.get("id").unwrap();
        assert_eq!(id.as_i64(), Some(42));
        let err = outcome.upstream_payload.get("error").unwrap();
        assert_eq!(err.get("code").unwrap().as_i64(), Some(-32500));
        assert_matches!(
            outcome.audit_outcome,
            SamplingInterceptOutcome::Failed { ref reason } if reason == "auth_failed"
        );
    }
}
