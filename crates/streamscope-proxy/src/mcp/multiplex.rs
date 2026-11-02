//! Server-initiated MCP primitive passthrough.
//!
//! When an upstream MCP server replies to `tools/call` (or any other client
//! request) with `Content-Type: text/event-stream`, the response stream may
//! interleave:
//!
//! 1. **Server-initiated requests** (`sampling/createMessage`,
//!    `elicitation/create`) — the server asks the agent to invoke its LLM /
//!    prompt the user for input. These have a JSON-RPC `id` the agent must
//!    echo back in its response.
//! 2. **Notifications** (`notifications/message` is the load-bearing one —
//!    log lines from the upstream tool). No `id`; fire-and-forget.
//! 3. **The eventual response** to the agent's original request — has the
//!    same `id` the agent sent and an MCP `result` / `error` field.
//!
//! This module owns the bridge: pumps the upstream SSE stream into a
//! downstream SSE stream that the agent consumes, classifying each event
//! along the way so the audit pipeline records what actually flowed.
//!
//! The reverse direction — the agent's response to a server-initiated request
//! — arrives as a fresh `POST /mcp/<slug>` body of `Response` shape; the
//! handler classifies and forwards it through [`session::McpSessionMap`].
//! Both halves complete the round-trip.

use streamscope_core::api::sse::SseEvent;
use streamscope_core::mcp::tokens::encode_request_id;
use uuid::Uuid;

use super::jsonrpc::{ServerInitiated, classify_server_initiated};

/// What we surface to the audit / log pipeline for one decoded SSE event.
/// The handler converts this into either an info-level audit row (sampling /
/// elicitation), a debug log (notifications/message), or a no-op (everything
/// else, including the eventual final response which the existing audit row
/// for the original request already covers).
#[derive(Debug, Clone)]
pub struct ClassifiedEvent {
    pub kind: EventKind,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    /// Server-initiated `sampling/createMessage`. Audit at info; record the
    /// JSON-RPC id so the operator can correlate with the agent's reply.
    Sampling { rpc_id: serde_json::Value },
    /// Server-initiated `elicitation/create`. Audit at info; record the id.
    Elicitation { rpc_id: serde_json::Value },
    /// `notifications/message` — log line. Debug-log only; no audit row.
    LogNotification {
        level: Option<String>,
        logger: Option<String>,
    },
    /// `notifications/{tools,resources,prompts}/list_changed` — upstream
    /// catalog drift signal. Promoted to a typed audit row so operators see
    /// drift in the admin UI; also fanned out to any GET-channel subscriber
    /// for the same user.
    ListChanged { which: ListChangedKind },
    /// `notifications/resources/updated` — fired by the server when a
    /// previously-subscribed resource changes. `params.uri` carries the
    /// upstream URI; the gateway rewrites it to the `stsmcp://` envelope
    /// before forwarding so agents that subscribed by envelope URI can
    /// correlate the notification.
    ResourceUpdated { uri: Option<String> },
    /// `notifications/elicitation/complete` — server signals that an
    /// out-of-band URL-mode elicitation completed (introduced in MCP
    /// 2025-11-25 § Elicitation). Audit at info; the `elicitationId`
    /// correlates with the original `elicitation/create` request.
    ElicitationComplete { elicitation_id: Option<String> },
    /// Everything else — final response to the agent's original request, or
    /// a notification we don't have a special path for. Forwarded verbatim,
    /// no audit, no log.
    Passthrough,
}

/// Which catalog dimension drifted. `method` returns the canonical wire
/// method name so audit and bus payloads match what the upstream emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListChangedKind {
    Tools,
    Resources,
    Prompts,
}

impl ListChangedKind {
    pub fn method(self) -> &'static str {
        match self {
            ListChangedKind::Tools => "notifications/tools/list_changed",
            ListChangedKind::Resources => "notifications/resources/list_changed",
            ListChangedKind::Prompts => "notifications/prompts/list_changed",
        }
    }
}

/// Inspect a decoded SSE event's `data` payload and decide what audit /
/// log signal to emit. The raw bytes are already attached on the wire; this
/// only classifies for the side-channel.
pub fn classify_sse_event(data: &str) -> ClassifiedEvent {
    let parsed: Option<serde_json::Value> = serde_json::from_str(data).ok();
    let kind = match parsed.as_ref() {
        Some(v) => classify_value(v),
        None => EventKind::Passthrough,
    };
    ClassifiedEvent { kind }
}

pub fn classify_value(v: &serde_json::Value) -> EventKind {
    let method = match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => return EventKind::Passthrough,
    };
    match classify_server_initiated(method) {
        ServerInitiated::SamplingCreateMessage => EventKind::Sampling {
            rpc_id: v.get("id").cloned().unwrap_or(serde_json::Value::Null),
        },
        ServerInitiated::ElicitationCreate => EventKind::Elicitation {
            rpc_id: v.get("id").cloned().unwrap_or(serde_json::Value::Null),
        },
        ServerInitiated::NotificationsMessage => {
            let params = v.get("params");
            EventKind::LogNotification {
                level: params
                    .and_then(|p| p.get("level"))
                    .and_then(|l| l.as_str())
                    .map(str::to_string),
                logger: params
                    .and_then(|p| p.get("logger"))
                    .and_then(|l| l.as_str())
                    .map(str::to_string),
            }
        }
        ServerInitiated::Other => match method {
            "notifications/tools/list_changed" => EventKind::ListChanged {
                which: ListChangedKind::Tools,
            },
            "notifications/resources/list_changed" => EventKind::ListChanged {
                which: ListChangedKind::Resources,
            },
            "notifications/prompts/list_changed" => EventKind::ListChanged {
                which: ListChangedKind::Prompts,
            },
            "notifications/resources/updated" => EventKind::ResourceUpdated {
                uri: v
                    .get("params")
                    .and_then(|p| p.get("uri"))
                    .and_then(|u| u.as_str())
                    .map(str::to_string),
            },
            "notifications/elicitation/complete" => EventKind::ElicitationComplete {
                elicitation_id: v
                    .get("params")
                    .and_then(|p| p.get("elicitationId"))
                    .and_then(|i| i.as_str())
                    .map(str::to_string),
            },
            _ => EventKind::Passthrough,
        },
    }
}

/// One server-initiated request whose JSON-RPC `id` was rewritten to an
/// `ssrid.…` token before forwarding to the agent. The caller forwards
/// `data` (the re-serialized JSON) on the wire and feeds `original_id` to
/// audit emission so cross-row correlation pivots on the upstream's id.
#[derive(Debug, Clone)]
pub struct VirtualizedEvent {
    pub data: String,
    pub original_id: serde_json::Value,
}

/// If `data` is a JSON-RPC `sampling/createMessage` or `elicitation/create`
/// request with an `id`, replace the `id` with a virtualized `ssrid.…` token
/// bound to `(upstream_id, upstream_session_id, tenant_id, user_id)` and
/// return the rewritten payload plus the original id. Returns `None` for
/// non-JSON, notifications, non-server-initiated methods, or events without
/// an `id`.
///
/// Closes the cross-instance reverse-path bug: the agent's POST response
/// quotes the virtualized id verbatim, so any proxy replica decodes it and
/// reaches the originating upstream without consulting `McpSessionMap`.
/// `tenant_id` / `user_id` are folded into the signed payload so the
/// reverse-path handler can refuse a token replayed by a sibling user.
///
/// Wire-bytes wrapper around [`virtualize_server_initiated_id_value`] for
/// the Streamable-HTTP SSE pump (which has bytes, not a parsed Value).
pub fn virtualize_server_initiated_id(
    data: &str,
    upstream_id: Uuid,
    upstream_session_id: &str,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Option<VirtualizedEvent> {
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;
    let original_id = virtualize_server_initiated_id_value(
        &mut value,
        upstream_id,
        upstream_session_id,
        tenant_id,
        user_id,
    )?;
    let rewritten = serde_json::to_string(&value).ok()?;
    Some(VirtualizedEvent {
        data: rewritten,
        original_id,
    })
}

/// Value-level helper. If `value` is a JSON-RPC `sampling/createMessage` or
/// `elicitation/create` request with an `id`, replace the `id` with a
/// virtualized `ssrid.…` token bound to the four-tuple
/// `(upstream_id, upstream_session_id, tenant_id, user_id)` and return the
/// original id. Returns `None` for notifications, non-server-initiated
/// methods, events without an `id`, or non-object values.
///
/// Mutates `value` in place. Used directly by the legacy-SSE bus-publish
/// path (which already has a parsed `serde_json::Value`).
pub fn virtualize_server_initiated_id_value(
    value: &mut serde_json::Value,
    upstream_id: Uuid,
    upstream_session_id: &str,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Option<serde_json::Value> {
    let method = value.get("method").and_then(|m| m.as_str())?;
    match classify_server_initiated(method) {
        ServerInitiated::SamplingCreateMessage | ServerInitiated::ElicitationCreate => {}
        _ => return None,
    }
    let original_id = value.get("id").cloned()?;
    let token = match encode_request_id(
        upstream_id,
        upstream_session_id,
        &original_id,
        tenant_id,
        user_id,
    ) {
        Ok(t) => t,
        Err(err) => {
            tracing::error!(
                error = %err,
                method = method,
                "failed to mint ssrid token (ENCRYPTION_KEY broken?); forwarding non-virtualized id will -32401 on the agent's reverse-path POST"
            );
            return None;
        }
    };
    let obj = value.as_object_mut()?;
    obj.insert("id".to_string(), serde_json::Value::String(token));
    Some(original_id)
}

/// If `data` is a `notifications/resources/updated` notification with a
/// `params.uri`, rewrite the URI through the `stsmcp://<prefix>/<b64>`
/// envelope so agents that subscribed by envelope URI can correlate the
/// notification. Returns the rewritten JSON string, or `None` if the event
/// isn't a resources/updated notification or `params.uri` is missing /
/// already enveloped.
///
/// The agent's `resources/subscribe` carries an envelope URI; the gateway
/// decodes it to (route_prefix, upstream URI) and forwards the upstream URI
/// to the matching upstream. The upstream then emits `params.uri = <upstream
/// URI>` on every change. Without this rewrite the agent receives a URI it
/// never subscribed to and treats the notification as orphaned.
pub fn rewrite_resource_updated_uri(data: &str, prefix: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;
    rewrite_resource_updated_uri_value(&mut value, prefix)?;
    serde_json::to_string(&value).ok()
}

/// Value-level helper. Mutates `value` in place; returns `Some(())` iff a
/// rewrite occurred. Used by the legacy-SSE path which already has a parsed
/// `serde_json::Value`.
pub fn rewrite_resource_updated_uri_value(
    value: &mut serde_json::Value,
    prefix: &str,
) -> Option<()> {
    let method = value.get("method").and_then(|m| m.as_str())?;
    if method != "notifications/resources/updated" {
        return None;
    }
    let params = value.get_mut("params")?.as_object_mut()?;
    let uri = params.get("uri").and_then(|u| u.as_str())?.to_string();
    // Idempotent: an already-enveloped URI round-trips through decode/encode
    // unchanged (route prefix is stable per upstream), so re-running the
    // rewrite is a no-op rather than a double-wrap.
    if streamscope_core::mcp::tokens::decode_resource_uri(&uri).is_ok() {
        return None;
    }
    let envelope = streamscope_core::mcp::tokens::encode_resource_uri(prefix, &uri);
    params.insert("uri".to_string(), serde_json::Value::String(envelope));
    Some(())
}

/// Rewrite every upstream resource URI inside a JSON-RPC `result` payload to
/// the `stsmcp://<prefix>/<b64>` envelope so agents who round-trip URIs (the
/// documented contract — `resources/read` on an unwrapped URI returns
/// `-32001 mcp_route_not_found`) keep correlating responses to the URIs the
/// gateway handed them.
///
/// Three response shapes carry resource URIs:
/// * `result.contents[].uri` — `resources/read` response
/// * `result.content[]` blocks of `type = "resource_link"` (`uri` directly on
///   the block) or `type = "resource"` (`resource.uri` nested) — `tools/call`
///   response
/// * `result.messages[].content` (object or array of blocks) — `prompts/get`
///   response, same `resource` / `resource_link` shapes
///
/// Returns `Some(rewritten_json)` iff at least one URI was rewritten. Already-
/// enveloped URIs are left alone (idempotent on bus replay or pass-through).
pub fn rewrite_response_resource_uris(data: &str, prefix: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(data).ok()?;
    if !rewrite_response_resource_uris_value(&mut value, prefix) {
        return None;
    }
    serde_json::to_string(&value).ok()
}

/// Value-level helper. Mutates `value` in place; returns `true` iff any URI
/// was rewritten. Callers that already hold a parsed `result` (e.g.
/// `JsonRpcResponse.result`) can call [`rewrite_result_resource_uris`].
///
/// A response carries a resource URI in one of two disjoint places, so both
/// are visited: the `result`, and — when the read failed — the error's
/// `data.uri` (see [`rewrite_error_resource_uri`]).
pub fn rewrite_response_resource_uris_value(
    value: &mut serde_json::Value,
    prefix: &str,
) -> bool {
    let mut changed = false;
    if let Some(result) = value.get_mut("result") {
        changed |= rewrite_result_resource_uris(result, prefix);
    }
    if let Some(error) = value.get_mut("error") {
        changed |= rewrite_error_resource_uri(error, prefix);
    }
    changed
}

/// Re-virtualize the URI an error names under `data.uri`.
///
/// MCP § Resources has a server name the resource it could not read there, so
/// a conforming upstream's `resources/read` failure carries the URI **as that
/// upstream spells it**. Every other URI the client sees is virtualized, which
/// is what keeps one route's namespace out of another's and what the client
/// must send back — so relaying this one raw hands the client an address it
/// cannot round-trip (a retry would `-32001` against our own decoder) and
/// discloses the upstream's own addressing, the thing virtualization exists to
/// withhold.
///
/// Only `data.uri` is touched. The rest of an upstream's `data` is its own
/// text and is not a channel the gateway forwards on its behalf.
///
/// **The field name is the whole gate — deliberately, not by omission.**
/// Neither the error code nor the request method is consulted: the spec names
/// `data.uri` in exactly one place and gives it exactly one meaning, so an
/// error carrying that key is making that claim whatever code it rode in on,
/// and a server that picks a different code for the same condition still gets
/// a client address. The cost of being wrong is bounded and symmetric — an
/// upstream misusing the key for something that is not a resource has its
/// value enveloped, which is no worse than the raw leak the other way — while
/// gating on the code would silently reintroduce the leak for every spelling
/// not enumerated, the failure this repo keeps rediscovering.
pub fn rewrite_error_resource_uri(error: &mut serde_json::Value, prefix: &str) -> bool {
    let Some(data) = error.get_mut("data") else {
        return false;
    };
    rewrite_uri_field(data, prefix)
}

/// Re-virtualize every resource URI a parsed JSON-RPC response carries.
///
/// The two halves are disjoint — a response is a result or an error, never
/// both — and this is the seam that keeps them from drifting apart. Call sites
/// that reached only for `result` are why an error's `data.uri` travelled
/// de-virtualized: there was no single place that meant "the response, on its
/// way out".
pub fn rewrite_response_uris(resp: &mut super::jsonrpc::JsonRpcResponse, prefix: &str) -> bool {
    let mut changed = false;
    if let Some(result) = resp.result.as_mut() {
        changed |= rewrite_result_resource_uris(result, prefix);
    }
    if let Some(data) = resp.error.as_mut().and_then(|e| e.data.as_mut()) {
        changed |= rewrite_uri_field(data, prefix);
    }
    changed
}

/// Rewrite resource URIs inside the `result` value of a JSON-RPC response.
/// Used directly by call sites that hold a parsed `JsonRpcResponse` (e.g. the
/// non-streaming `tools/call` and `resources/read` paths).
pub fn rewrite_result_resource_uris(result: &mut serde_json::Value, prefix: &str) -> bool {
    let Some(obj) = result.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    if let Some(arr) = obj.get_mut("contents").and_then(|v| v.as_array_mut()) {
        for item in arr {
            changed |= rewrite_uri_field(item, prefix);
        }
    }
    if let Some(arr) = obj.get_mut("content").and_then(|v| v.as_array_mut()) {
        for block in arr {
            changed |= rewrite_content_block_uris(block, prefix);
        }
    }
    if let Some(arr) = obj.get_mut("messages").and_then(|v| v.as_array_mut()) {
        for msg in arr {
            let Some(content) = msg.get_mut("content") else {
                continue;
            };
            if let Some(blocks) = content.as_array_mut() {
                for block in blocks {
                    changed |= rewrite_content_block_uris(block, prefix);
                }
            } else if content.is_object() {
                changed |= rewrite_content_block_uris(content, prefix);
            }
        }
    }
    changed
}

fn rewrite_content_block_uris(block: &mut serde_json::Value, prefix: &str) -> bool {
    let Some(obj) = block.as_object_mut() else {
        return false;
    };
    let block_type = obj
        .get("type")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());
    match block_type.as_deref() {
        Some("resource_link") => rewrite_uri_field(block, prefix),
        Some("resource") => match obj.get_mut("resource") {
            Some(resource) => rewrite_uri_field(resource, prefix),
            None => false,
        },
        _ => false,
    }
}

fn rewrite_uri_field(value: &mut serde_json::Value, prefix: &str) -> bool {
    let Some(obj) = value.as_object_mut() else {
        return false;
    };
    let Some(uri) = obj.get("uri").and_then(|u| u.as_str()).map(String::from) else {
        return false;
    };
    if streamscope_core::mcp::tokens::decode_resource_uri(&uri).is_ok() {
        return false;
    }
    let envelope = streamscope_core::mcp::tokens::encode_resource_uri(prefix, &uri);
    obj.insert("uri".to_string(), serde_json::Value::String(envelope));
    true
}

/// Re-encode an [`SseEvent`] back to wire bytes so the proxy can forward it
/// to the downstream client. Mirrors the upstream's framing exactly:
///
/// - `event:` line if an event_type was present (otherwise omitted, per the
///   SSE spec's "default event type" rule the upstream relied on).
/// - One `data:` line per `\n`-separated chunk in the data (multi-line
///   payloads round-trip cleanly).
/// - Terminating blank line.
pub fn encode_sse_event(ev: &SseEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(ev.data.len() + 32);
    if let Some(kind) = &ev.event_type {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(kind.as_bytes());
        out.push(b'\n');
    }
    if let Some(id) = &ev.id {
        out.extend_from_slice(b"id: ");
        out.extend_from_slice(id.as_bytes());
        out.push(b'\n');
    }
    for line in ev.data.split('\n') {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// Convenience wrapper that drains every event from a single byte slice
/// using the shared [`streamscope_core::api::sse::SseDecoder`]. Used by tests
/// and small synchronous flows — the production streaming path drives
/// `SseDecoder` directly off the `bytes_stream()` poll loop so it can
/// interleave forwarding with receive.
#[cfg(test)]
pub fn decode_all(buf: &[u8]) -> Vec<SseEvent> {
    use bytes::BytesMut;
    use streamscope_core::api::sse::SseDecoder;
    use tokio_util::codec::Decoder;
    let mut buf = BytesMut::from(buf);
    let mut decoder = SseDecoder::new();
    let mut out = Vec::new();
    while let Ok(Some(ev)) = decoder.decode(&mut buf) {
        out.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn classify_sampling_request() {
        let body = r#"{"jsonrpc":"2.0","id":42,"method":"sampling/createMessage","params":{"messages":[]}}"#;
        let ev = classify_sse_event(body);
        match ev.kind {
            EventKind::Sampling { rpc_id } => assert_eq!(rpc_id, serde_json::json!(42)),
            other => panic!("expected Sampling, got {other:?}"),
        }
    }

    #[test]
    fn classify_elicitation_request() {
        let body = r#"{"jsonrpc":"2.0","id":"abc","method":"elicitation/create","params":{}}"#;
        let ev = classify_sse_event(body);
        assert_matches!(ev.kind, EventKind::Elicitation { .. });
    }

    #[test]
    fn classify_log_notification_with_level() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","logger":"github","data":"ok"}}"#;
        let ev = classify_sse_event(body);
        match ev.kind {
            EventKind::LogNotification { level, logger } => {
                assert_eq!(level.as_deref(), Some("info"));
                assert_eq!(logger.as_deref(), Some("github"));
            }
            other => panic!("expected LogNotification, got {other:?}"),
        }
    }

    #[test]
    fn classify_tools_list_changed() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let ev = classify_sse_event(body);
        assert_matches!(
            ev.kind,
            EventKind::ListChanged { which: ListChangedKind::Tools }
        );
    }

    #[test]
    fn classify_resources_list_changed() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#;
        let ev = classify_sse_event(body);
        assert_matches!(
            ev.kind,
            EventKind::ListChanged { which: ListChangedKind::Resources }
        );
    }

    #[test]
    fn classify_prompts_list_changed() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#;
        let ev = classify_sse_event(body);
        assert_matches!(
            ev.kind,
            EventKind::ListChanged { which: ListChangedKind::Prompts }
        );
    }

    #[test]
    fn classify_resources_updated_extracts_uri() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///x"}}"#;
        let ev = classify_sse_event(body);
        match ev.kind {
            EventKind::ResourceUpdated { uri } => {
                assert_eq!(uri.as_deref(), Some("file:///x"));
            }
            other => panic!("expected ResourceUpdated, got {other:?}"),
        }
    }

    #[test]
    fn classify_unknown_notification_passes_through() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/something/else"}"#;
        let ev = classify_sse_event(body);
        assert_matches!(ev.kind, EventKind::Passthrough);
    }

    #[test]
    fn rewrite_resource_updated_wraps_upstream_uri() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"note://welcome"}}"#;
        let rewritten = rewrite_resource_updated_uri(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let new_uri = parsed["params"]["uri"].as_str().unwrap();
        assert!(new_uri.starts_with("stsmcp://gh/"), "got {new_uri}");
        let (prefix, original) =
            streamscope_core::mcp::tokens::decode_resource_uri(new_uri).unwrap();
        assert_eq!(prefix, "gh");
        assert_eq!(original, "note://welcome");
    }

    #[test]
    fn rewrite_resource_updated_idempotent_on_envelope() {
        let original_envelope =
            streamscope_core::mcp::tokens::encode_resource_uri("gh", "note://welcome");
        let body = format!(
            r#"{{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{{"uri":"{original_envelope}"}}}}"#
        );
        // Already enveloped — rewrite returns None (no double-wrap).
        assert!(rewrite_resource_updated_uri(&body, "gh").is_none());
    }

    #[test]
    fn rewrite_resource_updated_skips_non_resource_updates() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#;
        assert!(rewrite_resource_updated_uri(body, "gh").is_none());
    }

    #[test]
    fn rewrite_resource_updated_skips_missing_uri() {
        let body = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{}}"#;
        assert!(rewrite_resource_updated_uri(body, "gh").is_none());
    }

    #[test]
    fn rewrite_response_uris_resources_read_contents() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"contents":[{"uri":"note://docs","mimeType":"text/plain","text":"hi"}]}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let new_uri = parsed["result"]["contents"][0]["uri"].as_str().unwrap();
        assert!(new_uri.starts_with("stsmcp://gh/"), "got {new_uri}");
        let (prefix, original) =
            streamscope_core::mcp::tokens::decode_resource_uri(new_uri).unwrap();
        assert_eq!(prefix, "gh");
        assert_eq!(original, "note://docs");
    }

    #[test]
    fn rewrite_response_uris_tool_call_resource_link() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"resource_link","uri":"note://welcome","name":"welcome"}]}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let new_uri = parsed["result"]["content"][0]["uri"].as_str().unwrap();
        assert!(new_uri.starts_with("stsmcp://gh/"), "got {new_uri}");
    }

    #[test]
    fn rewrite_response_uris_tool_call_resource_block() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"resource","resource":{"uri":"note://embedded","mimeType":"text/plain","text":"x"}}]}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let new_uri = parsed["result"]["content"][0]["resource"]["uri"]
            .as_str()
            .unwrap();
        assert!(new_uri.starts_with("stsmcp://gh/"), "got {new_uri}");
    }

    #[test]
    fn rewrite_response_uris_prompts_get_messages_array_content() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"messages":[{"role":"user","content":[{"type":"resource_link","uri":"note://x"},{"type":"resource","resource":{"uri":"note://y"}}]}]}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let blocks = &parsed["result"]["messages"][0]["content"];
        assert!(blocks[0]["uri"].as_str().unwrap().starts_with("stsmcp://gh/"));
        assert!(
            blocks[1]["resource"]["uri"]
                .as_str()
                .unwrap()
                .starts_with("stsmcp://gh/")
        );
    }

    #[test]
    fn rewrite_response_uris_prompts_get_messages_object_content() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"messages":[{"role":"assistant","content":{"type":"resource","resource":{"uri":"note://obj"}}}]}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let new_uri = parsed["result"]["messages"][0]["content"]["resource"]["uri"]
            .as_str()
            .unwrap();
        assert!(new_uri.starts_with("stsmcp://gh/"), "got {new_uri}");
    }

    #[test]
    fn rewrite_response_uris_idempotent_on_envelope() {
        let envelope = streamscope_core::mcp::tokens::encode_resource_uri("gh", "note://x");
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":7,"result":{{"contents":[{{"uri":"{envelope}"}}]}}}}"#
        );
        assert!(rewrite_response_resource_uris(&body, "gh").is_none());
    }

    #[test]
    fn rewrite_response_uris_skips_non_resource_blocks() {
        let body = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hello"},{"type":"image","data":"…","mimeType":"image/png"}]}}"#;
        assert!(rewrite_response_resource_uris(body, "gh").is_none());
    }

    #[test]
    fn rewrite_response_uris_skips_an_error_naming_no_resource() {
        let body = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"x"}}"#;
        assert!(rewrite_response_resource_uris(body, "gh").is_none());
    }

    /// MCP § Resources has a server name the resource it could not read under
    /// `error.data.uri`, so a conforming upstream's failure carries the URI as
    /// IT spells it. Relayed raw, the client is handed an address it cannot
    /// round-trip — a retry would `-32001` against our own decoder — and the
    /// upstream's own addressing leaks, which is the thing virtualization
    /// exists to withhold. The result path covers none of this: an error
    /// carries no `contents`.
    #[test]
    fn an_error_naming_a_resource_is_virtualized_like_a_result() {
        let body = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"not found","data":{"uri":"note://missing"}}}"#;
        let rewritten = rewrite_response_resource_uris(body, "gh").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let uri = parsed["error"]["data"]["uri"].as_str().unwrap();
        let (prefix, original) =
            streamscope_core::mcp::tokens::decode_resource_uri(uri).unwrap();
        assert_eq!(prefix, "gh");
        assert_eq!(
            original, "note://missing",
            "the client must be able to round-trip what it is handed"
        );
        assert_eq!(
            parsed["error"]["message"], "not found",
            "only the uri is rewritten; the rest of the error is untouched"
        );
    }

    /// Same idempotence the result path has, and it is load-bearing for the
    /// same reason: a gateway-raised `resource_not_found` already names the
    /// virtualized URI the client sent, so a second pass must not envelope an
    /// envelope.
    #[test]
    fn rewriting_an_error_uri_is_idempotent() {
        let envelope = streamscope_core::mcp::tokens::encode_resource_uri("gh", "note://x");
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":7,"error":{{"code":-32602,"message":"nope","data":{{"uri":"{envelope}"}}}}}}"#
        );
        assert!(rewrite_response_resource_uris(&body, "gh").is_none());
    }

    /// The handler holds a parsed `JsonRpcResponse`, so it reaches the typed
    /// seam rather than the string one. Both must cover the same two places or
    /// the gap simply moves to whichever the tests do not exercise.
    #[test]
    fn the_typed_seam_virtualizes_a_result_and_an_error_alike() {
        use super::super::jsonrpc::{JsonRpcError, JsonRpcResponse, RpcId};

        let mut ok = JsonRpcResponse::ok(
            RpcId::Number(1.into()),
            serde_json::json!({ "contents": [{ "uri": "note://ok" }] }),
        );
        assert!(rewrite_response_uris(&mut ok, "gh"));
        let uri = ok.result.as_ref().unwrap()["contents"][0]["uri"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            streamscope_core::mcp::tokens::decode_resource_uri(&uri).unwrap(),
            ("gh".to_string(), "note://ok".to_string())
        );

        let mut failed = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: RpcId::Number(1.into()),
            result: None,
            error: Some(JsonRpcError {
                code: -32602,
                message: "not found".into(),
                data: Some(serde_json::json!({ "uri": "note://gone" })),
            }),
        };
        assert!(rewrite_response_uris(&mut failed, "gh"));
        let uri = failed.error.as_ref().unwrap().data.as_ref().unwrap()["uri"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            streamscope_core::mcp::tokens::decode_resource_uri(&uri).unwrap(),
            ("gh".to_string(), "note://gone".to_string())
        );

        // Nothing to do is reported as nothing done, so a caller can keep the
        // original bytes.
        let mut untouched = JsonRpcResponse::err(RpcId::Number(1.into()), -32601, "x");
        assert!(!rewrite_response_uris(&mut untouched, "gh"));
    }

    /// An error whose `data` is not an object, or names no `uri`, is left
    /// exactly as it arrived — the gateway rewrites one field, not a payload.
    #[test]
    fn an_errors_other_data_is_never_touched() {
        for body in [
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"x","data":"a string"}}"#,
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"x","data":{"detail":"note://looks-like-one"}}}"#,
            r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"x","data":{"uri":42}}}"#,
        ] {
            assert!(
                rewrite_response_resource_uris(body, "gh").is_none(),
                "{body}"
            );
        }
    }

    #[test]
    fn classify_response_passes_through() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
        let ev = classify_sse_event(body);
        assert_matches!(ev.kind, EventKind::Passthrough);
    }

    #[test]
    fn encode_sse_round_trip() {
        let ev = SseEvent {
            event_type: Some("message".into()),
            data: r#"{"x":1}"#.into(),
            id: None,
        };
        let wire = encode_sse_event(&ev);
        let s = std::str::from_utf8(&wire).unwrap();
        assert!(s.starts_with("event: message\n"));
        assert!(s.contains("data: {\"x\":1}\n"));
        assert!(s.ends_with("\n\n"));
    }

    #[test]
    fn encode_sse_multiline_data() {
        let ev = SseEvent {
            event_type: None,
            data: "line1\nline2".into(),
            id: None,
        };
        let s = String::from_utf8(encode_sse_event(&ev)).unwrap();
        assert!(s.contains("data: line1\n"));
        assert!(s.contains("data: line2\n"));
    }

    #[test]
    fn decode_two_events() {
        let raw = b"event: message\ndata: {\"a\":1}\n\nevent: message\ndata: {\"b\":2}\n\n";
        let evs = decode_all(raw);
        assert_eq!(evs.len(), 2);
        assert!(evs[0].data.contains("a"));
        assert!(evs[1].data.contains("b"));
    }

    fn ensure_token_secret() {
        // SAFETY: the token module reads ENCRYPTION_KEY once via OnceLock; tests
        // run single-threaded by default and the env is private to this process.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-mcp-token-secret-very-long");
        }
    }

    #[test]
    fn virtualize_sampling_request_swaps_id() {
        ensure_token_secret();
        let up_id = Uuid::new_v4();
        let body = r#"{"jsonrpc":"2.0","id":42,"method":"sampling/createMessage","params":{"messages":[]}}"#;
        let out =
            virtualize_server_initiated_id(body, up_id, "upstream-sid", Uuid::new_v4(), Uuid::new_v4())
                .unwrap();
        assert_eq!(out.original_id, serde_json::json!(42));
        let parsed: serde_json::Value = serde_json::from_str(&out.data).unwrap();
        let id = parsed.get("id").and_then(|v| v.as_str()).unwrap();
        assert!(
            id.starts_with("ssrid."),
            "expected virtualized id, got {id}"
        );
        // Method and params must round-trip unchanged.
        assert_eq!(
            parsed.get("method").and_then(|m| m.as_str()),
            Some("sampling/createMessage")
        );
        assert!(parsed.get("params").is_some());
    }

    #[test]
    fn virtualize_elicitation_request_swaps_id() {
        ensure_token_secret();
        let body = r#"{"jsonrpc":"2.0","id":"abc","method":"elicitation/create","params":{}}"#;
        let out = virtualize_server_initiated_id(
            body,
            Uuid::new_v4(),
            "u",
            Uuid::new_v4(),
            Uuid::new_v4(),
        )
        .unwrap();
        assert_eq!(out.original_id, serde_json::json!("abc"));
        assert!(out.data.contains("\"ssrid."));
    }

    #[test]
    fn virtualize_skips_notifications() {
        ensure_token_secret();
        let body = r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}"#;
        assert!(
            virtualize_server_initiated_id(
                body,
                Uuid::new_v4(),
                "u",
                Uuid::new_v4(),
                Uuid::new_v4()
            )
            .is_none()
        );
    }

    #[test]
    fn virtualize_skips_responses() {
        ensure_token_secret();
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#;
        assert!(
            virtualize_server_initiated_id(
                body,
                Uuid::new_v4(),
                "u",
                Uuid::new_v4(),
                Uuid::new_v4()
            )
            .is_none()
        );
    }

    #[test]
    fn virtualize_skips_non_json() {
        ensure_token_secret();
        assert!(
            virtualize_server_initiated_id(
                "not json",
                Uuid::new_v4(),
                "u",
                Uuid::new_v4(),
                Uuid::new_v4()
            )
            .is_none()
        );
    }

    #[test]
    fn virtualize_round_trip_recovers_original_id() {
        ensure_token_secret();
        let up_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let body = r#"{"jsonrpc":"2.0","id":99,"method":"sampling/createMessage","params":{}}"#;
        let out =
            virtualize_server_initiated_id(body, up_id, "upstream-sid", tenant_id, user_id)
                .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out.data).unwrap();
        let token = parsed["id"].as_str().unwrap();
        let decoded = streamscope_core::mcp::tokens::decode_request_id(token, 0).unwrap();
        assert_eq!(decoded.upstream_id, up_id);
        assert_eq!(decoded.upstream_session_id, "upstream-sid");
        assert_eq!(decoded.original_id, serde_json::json!(99));
        assert_eq!(decoded.tenant_id, tenant_id);
        assert_eq!(decoded.user_id, user_id);
    }
}
