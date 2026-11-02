//! JSON-RPC 2.0 framing for the MCP gateway.
//!
//! MCP rides JSON-RPC 2.0 over Streamable HTTP. We don't need a full JSON-RPC
//! implementation — only enough to parse a request, classify the method, and
//! serialize a response or error. Notification semantics (no `id`) are
//! preserved so server-initiated `tools/list_changed` and friends round-trip
//! correctly in later phases.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request id. The spec allows string, number, or null. We
/// preserve whichever form the caller used so responses round-trip with the
/// exact same id type.
///
/// `Number` carries a `serde_json::Number` (rather than `i64`) so upstream
/// ids outside the i64 range — `u64`, large floats minted by exotic clients,
/// or anything that wouldn't fit a signed 64-bit integer — round-trip
/// byte-identically. JSON-RPC requires the response id to equal the request
/// id; collapsing to `Null` for out-of-range numerics would silently drop
/// upstream responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RpcId {
    Number(serde_json::Number),
    String(String),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    /// Notifications have no `id`. Synchronous JSON-RPC sees only requests
    /// with an id; notifications are forwarded by the multiplexer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<RpcId>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RpcId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn ok(id: RpcId, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    pub fn err(id: RpcId, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into(), data: None }),
        }
    }
    /// An error carrying the typed `data` payload a client branches on.
    ///
    /// Kept distinct from [`Self::err`] rather than widening it: `data` is
    /// meaningful on only a handful of errors, and a `None` passed at every
    /// other call site reads as "this error has no payload" when it means
    /// "nobody considered one".
    pub fn err_with_data(
        id: RpcId,
        code: i32,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ── Standard JSON-RPC error codes ────────────────────────────────────────
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// ── MCP-specific gateway errors (server-defined range -32000..=-32099) ───
/// Returned when no virtual server matches the slug or all routes are
/// disabled. Maps to HTTP 404 at the transport layer.
pub const ROUTE_NOT_FOUND: i32 = -32001;
/// Upstream returned a non-200 response or a transport error.
pub const UPSTREAM_ERROR: i32 = -32003;
/// `tools/call` referenced a tool that didn't resolve to any upstream after
/// namespace stripping.
pub const TOOL_NOT_FOUND: i32 = -32004;
/// Unauthenticated / wrong-family / wrong-virtual-server / wrong-forward-auth
/// bearer. Mirrors HTTP 401 in the JSON-RPC body for clients that don't read
/// the HTTP status (per MCP spec recommendation for auth errors).
pub const AUTH_REQUIRED: i32 = -32401;
/// The bearer authenticated, but the scope it was granted does not cover the
/// method it asked for. Mirrors HTTP 403 in the JSON-RPC body.
///
/// Deliberately distinct from [`AUTH_REQUIRED`]: a client that reads the two as
/// one thing re-runs the whole authorization flow and is issued the same narrow
/// token again, which loops. This code says "your credential is fine, ask for
/// more" — and the `WWW-Authenticate` header alongside it names what to ask for.
pub const INSUFFICIENT_SCOPE: i32 = -32403;
/// Per-user RPM/TPM/budget limit exceeded on `/mcp/<slug>` or
/// `/fwd/{key}/mcp/<slug>`. Mirrors HTTP 429.
pub const RATE_LIMITED: i32 = -32429;
/// Service-account upstream is configured but the credential is missing /
/// undecryptable. Operator must (re)set it via the admin UI.
pub const UPSTREAM_CREDENTIAL_UNAVAILABLE: i32 = -32500;
/// Per-user OAuth — the user has not connected this upstream. The agent
/// should direct the user to the portal to authorize.
pub const MCP_USER_CREDENTIAL_MISSING: i32 = -32501;
/// Per-user OAuth — stored credential is past `expires_at` and the refresh
/// attempt failed (refresh token revoked or absent). The user must reconnect
/// via the portal.
pub const MCP_USER_CREDENTIAL_EXPIRED: i32 = -32502;
/// Per-user OAuth — refresh attempt failed for transient reasons (network,
/// IdP 5xx). The agent may retry; the credential is still valid.
pub const MCP_USER_OAUTH_REFRESH_FAILED: i32 = -32503;
/// Admin has not finished configuring the OAuth client (issuer URL,
/// client_id, or token URL missing). Operator must complete the upstream
/// config.
pub const MCP_OAUTH_CLIENT_NOT_CONFIGURED: i32 = -32504;
/// Outbound MCP/upstream URL points at an internal / loopback IP literal.
/// Defense-in-depth — admin write-time validation is the load-bearing
/// guard. Operator must fix the URL.
pub const MCP_UPSTREAM_SSRF_REFUSED: i32 = -32505;
/// A tool-risk rule with `action: block` matched the inbound MCP request
/// (`tools/call`, `resources/read`, or `prompts/get`). The per-rule message
/// describes which rule fired; the rule id rides on the audit row's
/// `transform_diff` so reviewers can backtrack.
pub const MCP_BLOCKED_BY_POLICY: i32 = -32506;
/// The proxy's long-lived `GET /sse` channel to a legacy-SSE upstream
/// terminated while a request was in flight, OR the upstream never emitted
/// a JSON-RPC response for the request id within the per-call timeout. The
/// agent should retry; the proxy will reconnect to the upstream
/// transparently on the next call.
pub const MCP_UPSTREAM_SESSION_LOST: i32 = -32507;
/// The upstream is configured with a transport or auth mode this build cannot
/// dispatch — an operator misconfiguration or a config-snapshot drift, never
/// anything the caller did.
///
/// Distinct from every other code here because it is the only one whose fix is
/// "change the upstream's configuration". It must **not** be spelled `-32002`:
/// that code means *resource not found* in every revision up to `2025-11-25`,
/// and MCP `2026-07-28` retired it outright, so a client reading it learns
/// something false in one era and nothing at all in the other.
pub const MCP_UPSTREAM_CONFIG_UNSUPPORTED: i32 = -32508;
/// The upstream answered a one-shot request by asking the *client* for input
/// (`elicitation/create`, `sampling/createMessage`, `roots/list`) and then
/// closed its stream.
///
/// The gateway bridges that pattern on `tools/call` and `prompts/get`, whose
/// responses it streams and can therefore keep talking on. `resources/read`
/// and the aggregate list methods are read in one shot, so by the time the
/// question is visible there is no stream left to answer it on — the round
/// trip cannot be completed however many times the client retries.
///
/// Reported as its own code rather than folded into a generic upstream error
/// because the two need different responses from an operator: this one is a
/// gateway limitation with a name, not an upstream that is misbehaving.
pub const MCP_UPSTREAM_INPUT_UNSUPPORTED: i32 = -32509;

/// Classification of an inbound POST body. Streamable HTTP allows three
/// shapes on the wire:
///
/// - `Request` — has both `method` and `id`. The dominant shape; every
///   synchronous JSON-RPC method lands here.
/// - `Notification` — has `method` but no `id`. Fire-and-forget client → server.
/// - `Response` — has `id` and (`result` | `error`) but **no** `method`. This
///   is the client's reply to a server-initiated `sampling/createMessage` /
///   `elicitation/create`, posted as a fresh HTTP request with the matching
///   id and the `Mcp-Session-Id` header.
///
/// The handler classifies before dispatch so the response shape can be routed
/// back to the originating upstream via the session map instead of being
/// rejected as a malformed Request.
#[derive(Debug, Clone)]
pub enum InboundMessage {
    Request(JsonRpcRequest),
    Notification(JsonRpcRequest),
    Response(JsonRpcResponse),
}

impl InboundMessage {
    /// Parse a raw body into the appropriate variant. Falls back to a
    /// `JsonRpcRequest` parse error when the body matches none of the three
    /// JSON-RPC envelope shapes.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let has_method = value.get("method").is_some();
        let has_result = value.get("result").is_some();
        let has_error = value.get("error").is_some();
        let has_id = value.get("id").is_some();
        if !has_method && (has_result || has_error) && has_id {
            let resp: JsonRpcResponse = serde_json::from_value(value)?;
            return Ok(InboundMessage::Response(resp));
        }
        let req: JsonRpcRequest = serde_json::from_value(value)?;
        if req.id.is_some() {
            Ok(InboundMessage::Request(req))
        } else {
            Ok(InboundMessage::Notification(req))
        }
    }
}

/// Categorize a method name into its MCP scope. Used by the audit writer to
/// stamp `tool_id` / `prompt_id` / `resource_uri` columns appropriately and
/// by the dispatcher to route methods to the correct upstream(s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpScope {
    Initialize,
    ToolList,
    ToolCall,
    ResourceList,
    ResourceRead,
    /// `resources/subscribe` — single-URI subscription. Routed by decoding
    /// `params.uri` (`stsmcp://prefix/...`) the same way as `resources/read`.
    ResourceSubscribe,
    /// `resources/unsubscribe` — symmetric counterpart. Same routing.
    ResourceUnsubscribe,
    PromptList,
    PromptGet,
    /// `completion/complete` — argument autocompletion against either a
    /// prompt (`ref/prompt`) or a resource template (`ref/resource`). Routing
    /// is per-ref-type: ref/prompt splits `<prefix>__<name>` like prompts/get;
    /// ref/resource decodes `stsmcp://` like resources/read.
    CompletionComplete,
    /// `resources/templates/list` — aggregate fan-out across every enabled
    /// route (mirrors `resources/list`). Each upstream's `uriTemplate` is
    /// re-wrapped under the `stsmcp+<prefix>+<scheme>://` envelope so RFC 6570
    /// placeholder expansion survives the round-trip.
    ResourceTemplatesList,
    /// `logging/setLevel` — fan out to every enabled route. Returns success if
    /// any route accepts; the gateway advertises `logging` in `initialize` so
    /// the agent's call MUST reach all upstreams that declared `logging`.
    LoggingSetLevel,
    Notification,
    Other,
}

pub fn classify_method(method: &str) -> McpScope {
    match method {
        "initialize" => McpScope::Initialize,
        "tools/list" => McpScope::ToolList,
        "tools/call" => McpScope::ToolCall,
        "resources/list" => McpScope::ResourceList,
        "resources/read" => McpScope::ResourceRead,
        "resources/subscribe" => McpScope::ResourceSubscribe,
        "resources/unsubscribe" => McpScope::ResourceUnsubscribe,
        "prompts/list" => McpScope::PromptList,
        "prompts/get" => McpScope::PromptGet,
        "completion/complete" => McpScope::CompletionComplete,
        "resources/templates/list" => McpScope::ResourceTemplatesList,
        "logging/setLevel" => McpScope::LoggingSetLevel,
        m if m.starts_with("notifications/") => McpScope::Notification,
        _ => McpScope::Other,
    }
}

/// Classify an upstream-originated method as the kind of server-initiated
/// MCP primitive. Used by the multiplexer to choose between
/// "info-level audit row" (sampling / elicitation) and "debug log only"
/// (notifications/message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerInitiated {
    /// `sampling/createMessage` — server asks the client to invoke its LLM.
    SamplingCreateMessage,
    /// `elicitation/create` — server asks the client for human input.
    ElicitationCreate,
    /// `notifications/message` — log line. Persist at debug only.
    NotificationsMessage,
    /// Anything else from the upstream — forwarded verbatim, no audit, no
    /// debug log (counted in operator metrics if we ever surface them).
    Other,
}

pub fn classify_server_initiated(method: &str) -> ServerInitiated {
    match method {
        "sampling/createMessage" => ServerInitiated::SamplingCreateMessage,
        "elicitation/create" => ServerInitiated::ElicitationCreate,
        "notifications/message" => ServerInitiated::NotificationsMessage,
        _ => ServerInitiated::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_with_string_id() {
        let raw = r#"{"jsonrpc":"2.0","id":"abc","method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(RpcId::String("abc".into())));
    }

    #[test]
    fn parse_request_with_numeric_id() {
        let raw = r#"{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.id, Some(RpcId::Number(serde_json::Number::from(42))));
        assert!(req.params.is_some());
    }

    #[test]
    fn classify_methods() {
        assert_eq!(classify_method("tools/call"), McpScope::ToolCall);
        assert_eq!(classify_method("notifications/tools/list_changed"), McpScope::Notification);
        assert_eq!(classify_method("resources/read"), McpScope::ResourceRead);
        assert_eq!(classify_method("resources/subscribe"), McpScope::ResourceSubscribe);
        assert_eq!(classify_method("resources/unsubscribe"), McpScope::ResourceUnsubscribe);
        assert_eq!(classify_method("completion/complete"), McpScope::CompletionComplete);
        assert_eq!(
            classify_method("resources/templates/list"),
            McpScope::ResourceTemplatesList
        );
        assert_eq!(classify_method("logging/setLevel"), McpScope::LoggingSetLevel);
        assert_eq!(classify_method("foo/bar"), McpScope::Other);
    }

    #[test]
    fn round_trip_response() {
        let r = JsonRpcResponse::ok(RpcId::Number(serde_json::Number::from(1)), serde_json::json!({"x": 1}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""id":1"#));
        assert!(s.contains(r#""result":{"x":1}"#));
        assert!(!s.contains("error"));
    }

    #[test]
    fn round_trip_response_with_large_unsigned_id() {
        // u64 ids past i64::MAX must round-trip byte-identically. This guards
        // against regressing `RpcId::Number(i64)` where the upstream-side
        // numeric would silently collapse to null on the way back.
        let big = u64::MAX;
        let r = JsonRpcResponse::ok(
            RpcId::Number(serde_json::Number::from(big)),
            serde_json::json!({"ok": true}),
        );
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            s.contains(&format!("\"id\":{big}")),
            "expected literal {big} in body, got {s}"
        );
        let back: JsonRpcResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, RpcId::Number(serde_json::Number::from(big)));
    }

    #[test]
    fn classify_inbound_request() {
        let raw = br#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{}}"#;
        match InboundMessage::parse(raw).unwrap() {
            InboundMessage::Request(req) => assert_eq!(req.method, "tools/call"),
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn classify_inbound_notification() {
        let raw = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        match InboundMessage::parse(raw).unwrap() {
            InboundMessage::Notification(req) => {
                assert_eq!(req.method, "notifications/initialized");
                assert!(req.id.is_none());
            }
            other => panic!("expected Notification, got {other:?}"),
        }
    }

    #[test]
    fn classify_inbound_response() {
        let raw = br#"{"jsonrpc":"2.0","id":7,"result":{"role":"assistant","content":{"type":"text","text":"ok"}}}"#;
        match InboundMessage::parse(raw).unwrap() {
            InboundMessage::Response(resp) => {
                assert_eq!(resp.id, RpcId::Number(serde_json::Number::from(7)));
                assert!(resp.result.is_some());
                assert!(resp.error.is_none());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_inbound_error_response() {
        let raw = br#"{"jsonrpc":"2.0","id":8,"error":{"code":-32603,"message":"nope"}}"#;
        match InboundMessage::parse(raw).unwrap() {
            InboundMessage::Response(resp) => {
                assert!(resp.error.is_some());
                assert!(resp.result.is_none());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn classify_server_initiated_methods() {
        assert_eq!(
            classify_server_initiated("sampling/createMessage"),
            ServerInitiated::SamplingCreateMessage
        );
        assert_eq!(
            classify_server_initiated("elicitation/create"),
            ServerInitiated::ElicitationCreate
        );
        assert_eq!(
            classify_server_initiated("notifications/message"),
            ServerInitiated::NotificationsMessage
        );
        assert_eq!(
            classify_server_initiated("notifications/tools/list_changed"),
            ServerInitiated::Other
        );
    }
}
