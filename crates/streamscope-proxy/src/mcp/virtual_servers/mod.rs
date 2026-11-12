//! Built-in (gateway-internal) MCP upstreams.
//!
//! When `mcp::handler::call_cached` and `mcp::upstream::call_with_auth_for_streaming`
//! see an upstream whose `upstream_url` starts with the `internal://` scheme,
//! they short-circuit the outbound HTTP call and dispatch here instead. The
//! returned [`super::jsonrpc::JsonRpcResponse`] flows through the rest of the
//! MCP pipeline (capability stamping, audit, etc.) exactly like a real
//! upstream's reply — the rest of the gateway is blind to the origin.
//!
//! Phase 1 ships the `web` virtual server. Future built-ins
//! (`internal://timeseries`, etc.) plug in through [`dispatch`].

pub mod web;

use streamscope_core::config::mcp::McpUpstreamServer;
use streamscope_core::web::{is_internal_upstream_url, BUILTIN_WEB_UPSTREAM_URL};

use super::handler::AuthCtx;
use super::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RpcId};
use super::upstream::UpstreamError;

/// `true` when this upstream is a gateway-internal sentinel (handled by
/// [`dispatch`] rather than by `mcp::upstream::call_with_auth*`). Thin
/// wrapper around [`is_internal_upstream_url`] so callers with an
/// `McpUpstreamServer` in hand don't reach into the URL field directly.
pub fn is_internal(upstream: &McpUpstreamServer) -> bool {
    is_internal_upstream_url(&upstream.upstream_url)
}

/// Dispatch a JSON-RPC request to the matching built-in handler. Returns the
/// `(JsonRpcResponse, response_session_id)` shape that the rest of the MCP
/// pipeline expects from a real upstream — internal upstreams never issue an
/// `Mcp-Session-Id`, so the second tuple element is always `None`.
pub async fn dispatch(
    auth: &AuthCtx,
    upstream: &McpUpstreamServer,
    request: &JsonRpcRequest,
) -> Result<(JsonRpcResponse, Option<String>), UpstreamError> {
    let id = request.id.clone().unwrap_or(RpcId::Null);
    if upstream.upstream_url == BUILTIN_WEB_UPSTREAM_URL {
        return Ok((
            web::handle(auth, upstream, request, id).await,
            None,
        ));
    }
    Ok((
        JsonRpcResponse::err(
            id,
            super::jsonrpc::METHOD_NOT_FOUND,
            format!("unknown built-in upstream: {}", upstream.upstream_url),
        ),
        None,
    ))
}
