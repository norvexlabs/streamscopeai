//! A2A error taxonomy (spec § 3.3.2 / § 5.4) and JSON-RPC 2.0 envelope
//! helpers for the JSON-RPC binding. Every A2A-specific error carries a
//! `google.rpc.ErrorInfo` in `error.data` with `domain: "a2a-protocol.org"`
//! and an UPPER_SNAKE_CASE `reason`.

use serde_json::{json, Value};

pub const A2A_ERROR_DOMAIN: &str = "a2a-protocol.org";
pub const ERROR_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ErrorInfo";

/// Errors the *gateway* raises on its own authority carry this domain, not the
/// protocol's — a policy refusal is Streamscope's verdict, and a client must be
/// able to tell it apart from anything the remote agent said.
pub const GATEWAY_ERROR_DOMAIN: &str = "streamscope.gateway";

/// A2A-specific JSON-RPC error codes (`-32001..-32009`), the JSON-RPC 2.0
/// standard codes the dispatcher emits, and the gateway's own policy refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2aErrorCode {
    TaskNotFound,
    TaskNotCancelable,
    PushNotificationNotSupported,
    UnsupportedOperation,
    ContentTypeNotSupported,
    InvalidAgentResponse,
    ExtendedAgentCardNotConfigured,
    ExtensionSupportRequired,
    VersionNotSupported,
    // JSON-RPC 2.0 standard codes.
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    /// Tool policy refused the call before it left the gateway. Shares its code
    /// with the MCP gateway's block error so a client that speaks both protocols
    /// sees one "blocked by policy" code, not one per protocol.
    BlockedByPolicy,
}

impl A2aErrorCode {
    pub fn code(self) -> i32 {
        match self {
            Self::TaskNotFound => -32001,
            Self::TaskNotCancelable => -32002,
            Self::PushNotificationNotSupported => -32003,
            Self::UnsupportedOperation => -32004,
            Self::ContentTypeNotSupported => -32005,
            Self::InvalidAgentResponse => -32006,
            Self::ExtendedAgentCardNotConfigured => -32007,
            Self::ExtensionSupportRequired => -32008,
            Self::VersionNotSupported => -32009,
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::BlockedByPolicy => -32506,
        }
    }

    /// `google.rpc.ErrorInfo.domain`. A2A's own taxonomy is the protocol's; a
    /// gateway verdict is ours.
    pub fn domain(self) -> &'static str {
        match self {
            Self::BlockedByPolicy => GATEWAY_ERROR_DOMAIN,
            _ => A2A_ERROR_DOMAIN,
        }
    }

    /// `google.rpc.ErrorInfo.reason` — the A2A error type name without the
    /// `Error` suffix, UPPER_SNAKE_CASE. `None` for JSON-RPC standard codes
    /// (they are not A2A-domain errors).
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::BlockedByPolicy => Some("BLOCKED_BY_POLICY"),
            Self::TaskNotFound => Some("TASK_NOT_FOUND"),
            Self::TaskNotCancelable => Some("TASK_NOT_CANCELABLE"),
            Self::PushNotificationNotSupported => Some("PUSH_NOTIFICATION_NOT_SUPPORTED"),
            Self::UnsupportedOperation => Some("UNSUPPORTED_OPERATION"),
            Self::ContentTypeNotSupported => Some("CONTENT_TYPE_NOT_SUPPORTED"),
            Self::InvalidAgentResponse => Some("INVALID_AGENT_RESPONSE"),
            Self::ExtendedAgentCardNotConfigured => Some("EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
            Self::ExtensionSupportRequired => Some("EXTENSION_SUPPORT_REQUIRED"),
            Self::VersionNotSupported => Some("VERSION_NOT_SUPPORTED"),
            _ => None,
        }
    }
}

/// The `google.rpc.ErrorInfo` details object.
pub fn error_info(reason: &str, domain: &str, metadata: Option<Value>) -> Value {
    let mut info = json!({
        "@type": ERROR_INFO_TYPE,
        "reason": reason,
        "domain": domain,
    });
    if let Some(md) = metadata {
        info["metadata"] = md;
    }
    info
}

/// A complete JSON-RPC error response envelope. `rpc_id` is the request's
/// `id` (JSON `null` when the request never parsed far enough to have one).
pub fn jsonrpc_error(rpc_id: &Value, code: A2aErrorCode, message: &str) -> Value {
    let mut error = json!({
        "code": code.code(),
        "message": message,
    });
    if let Some(reason) = code.reason() {
        error["data"] = json!([error_info(reason, code.domain(), None)]);
    }
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": error,
    })
}

/// A complete JSON-RPC success envelope.
pub fn jsonrpc_result(rpc_id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a2a_errors_carry_error_info() {
        let env = jsonrpc_error(&json!(7), A2aErrorCode::VersionNotSupported, "unsupported");
        assert_eq!(env["error"]["code"], -32009);
        assert_eq!(env["id"], 7);
        let info = &env["error"]["data"][0];
        assert_eq!(info["@type"], ERROR_INFO_TYPE);
        assert_eq!(info["reason"], "VERSION_NOT_SUPPORTED");
        assert_eq!(info["domain"], A2A_ERROR_DOMAIN);
    }

    #[test]
    fn jsonrpc_standard_errors_have_no_error_info() {
        let env = jsonrpc_error(&Value::Null, A2aErrorCode::MethodNotFound, "no such method");
        assert_eq!(env["error"]["code"], -32601);
        assert!(env["error"].get("data").is_none());
    }

    #[test]
    fn a_policy_refusal_is_the_gateways_verdict_not_the_protocols() {
        // A client must be able to tell "Streamscope refused this" apart from
        // anything the remote agent said — hence our own ErrorInfo domain.
        let env = jsonrpc_error(&json!(1), A2aErrorCode::BlockedByPolicy, "blocked");
        assert_eq!(env["error"]["code"], -32506);
        let info = &env["error"]["data"][0];
        assert_eq!(info["reason"], "BLOCKED_BY_POLICY");
        assert_eq!(info["domain"], GATEWAY_ERROR_DOMAIN);
        assert_ne!(info["domain"], A2A_ERROR_DOMAIN);
    }
}
