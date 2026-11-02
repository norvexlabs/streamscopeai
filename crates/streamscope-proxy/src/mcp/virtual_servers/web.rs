//! Built-in Web virtual MCP server (search + fetch).
//!
//! Exposes two tools to MCP clients mounted on `/mcp/web` (the default
//! tenant slug):
//!
//! - **`web_search`** — query the configured search backend (SearXNG / Brave
//!   / Tavily / Google CSE / Serper). Returns ranked hits with snippets.
//! - **`web_fetch`** — retrieve a URL through the SSRF-guarded fetcher and
//!   return the extracted text. Honours per-tenant URL-filter chain.
//!
//! All other JSON-RPC methods return a typed `MethodNotFound` so the
//! capability cache + virtualize layer keep treating us like a real upstream.

use serde_json::{json, Value};
use streamscope_core::config::mcp::McpUpstreamServer;
use streamscope_core::web::{
    self, FetchRequest, SearchRequest, WebSettings, TOOL_WEB_FETCH, TOOL_WEB_SEARCH,
};

use crate::mcp::handler::AuthCtx;
use crate::mcp::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RpcId};
use crate::settings::MCP_SUPPORTED_PROTOCOL_VERSIONS;


/// Top-level dispatch for the `internal://web` upstream.
pub async fn handle(
    auth: &AuthCtx,
    upstream: &McpUpstreamServer,
    request: &JsonRpcRequest,
    id: RpcId,
) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => handle_initialize(request, id, &auth.web_settings),
        "ping" => JsonRpcResponse::ok(id, json!({})),
        "tools/list" => handle_tools_list(id, &auth.web_settings),
        "tools/call" => handle_tools_call(auth, upstream, request, id).await,
        // Resources / prompts not exposed by the built-in. Return empty
        // arrays so MCP clients that pre-fetch capabilities don't treat
        // these as errors.
        "resources/list" => JsonRpcResponse::ok(id, json!({ "resources": [] })),
        "resources/templates/list" => {
            JsonRpcResponse::ok(id, json!({ "resourceTemplates": [] }))
        }
        "prompts/list" => JsonRpcResponse::ok(id, json!({ "prompts": [] })),
        other => JsonRpcResponse::err(
            id,
            crate::mcp::jsonrpc::METHOD_NOT_FOUND,
            format!("method `{other}` not supported by built-in web upstream"),
        ),
    }
}

fn handle_initialize(request: &JsonRpcRequest, id: RpcId, settings: &WebSettings) -> JsonRpcResponse {
    // Echo the client's requested protocolVersion when it's in the gateway's
    // supported set, otherwise negotiate down to the newest LEGACY revision.
    // The gateway's era resolver (`resolve_protocol_era`) rejects anything
    // outside `MCP_SUPPORTED_PROTOCOL_VERSIONS` on subsequent requests, so
    // returning a version we won't accept here would break every client that
    // honours the negotiated version on later calls.
    //
    // The fallback must be a legacy version and is therefore named explicitly
    // rather than read off the end of the supported list. `initialize` exists
    // only in the legacy era: a client that reached it cannot speak
    // `2026-07-28`, so answering with the newest revision overall would hand
    // it a version it is guaranteed not to understand — and reading the
    // *oldest* off the other end of the list would silently downgrade every
    // unrecognised-version handshake to `2025-03-26`.
    let client_requested = request
        .params
        .as_ref()
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str());
    let negotiated = match client_requested {
        Some(v) if MCP_SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
        _ => crate::settings::MCP_GATEWAY_UPSTREAM_PROTOCOL_VERSION,
    };
    JsonRpcResponse::ok(
        id,
        json!({
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "streamscope-builtin-web",
                "version": streamscope_core::VERSION,
            },
            "instructions": served_instructions(settings),
        }),
    )
}

/// Guidance naming exactly the tools `tools/list` serves for these settings,
/// so a client is never told about a tool it cannot call.
fn served_instructions(settings: &WebSettings) -> String {
    let tools: Vec<&str> = web::served_web_tools(settings).map(|t| t.name).collect();
    let mut text = format!("Gateway web tools: {}.", tools.join(", "));
    if !settings.is_configured() {
        text.push_str(" Web search is not configured on this gateway.");
    }
    text
}

fn handle_tools_list(id: RpcId, settings: &WebSettings) -> JsonRpcResponse {
    // Only the tools these settings can serve: `web_search` needs a search
    // backend, `web_fetch` does not.
    let tools: Vec<Value> = web::served_web_tools(settings)
        .map(|tool| match tool.name {
            TOOL_WEB_SEARCH => tool_schema_web_search(tool, settings),
            TOOL_WEB_FETCH => tool_schema_web_fetch(tool, settings),
            _ => json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": { "type": "object" },
            }),
        })
        .collect();
    JsonRpcResponse::ok(id, json!({ "tools": tools }))
}

fn tool_schema_web_search(tool: &web::BuiltinTool, settings: &WebSettings) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query string."
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum hits to return (1–50).",
                    "minimum": 1,
                    "maximum": WebSettings::MAX_RESULTS_HARD_CAP,
                    "default": settings.max_results,
                },
                "language": {
                    "type": "string",
                    "description": "Optional ISO-639-1 language hint (e.g. \"en\", \"fr\")."
                }
            },
            "required": ["query"]
        }
    })
}

fn tool_schema_web_fetch(tool: &web::BuiltinTool, settings: &WebSettings) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "description": "The URL to fetch."
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Optional cap on response body size; clamped to the tenant's configured maximum.",
                    "default": settings.fetch_max_bytes,
                }
            },
            "required": ["url"]
        }
    })
}

async fn handle_tools_call(
    auth: &AuthCtx,
    upstream: &McpUpstreamServer,
    request: &JsonRpcRequest,
    id: RpcId,
) -> JsonRpcResponse {
    let params = request.params.clone().unwrap_or(Value::Null);
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Decrypt the upstream's stored credential ahead of context construction
    // so its plaintext lifetime is bound to this stack frame; paid backends
    // need it via `ctx.credential`.
    let credential = upstream
        .encrypted_credential
        .as_deref()
        .and_then(web::decrypt_upstream_credential);
    let ctx = build_ctx(auth, upstream, credential.as_deref());

    match name.as_str() {
        // Both arms decode through `parse_audited_args` rather than
        // `serde_json::from_value`: a malformed-arguments call is a web call
        // that happened, so it must leave a `web_audit` row like every other way
        // `search`/`fetch` can fail. The JSON-RPC error the caller sees is
        // unchanged — the `mcp_audit` row for this `tools/call` is a different
        // grain and still records the −32602 on its own.
        TOOL_WEB_SEARCH => {
            let req: SearchRequest =
                match web::service::parse_audited_args(&ctx, "search", &arguments.to_string())
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return JsonRpcResponse::err(
                            id,
                            crate::mcp::jsonrpc::INVALID_PARAMS,
                            format!("invalid web_search arguments: {e}"),
                        );
                    }
                };
            match web::service::search(&ctx, req).await {
                Ok(result) => mcp_text_result(id, &result),
                Err(e) => map_error(id, &e),
            }
        }
        TOOL_WEB_FETCH => {
            let req: FetchRequest =
                match web::service::parse_audited_args(&ctx, "fetch", &arguments.to_string()).await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return JsonRpcResponse::err(
                            id,
                            crate::mcp::jsonrpc::INVALID_PARAMS,
                            format!("invalid web_fetch arguments: {e}"),
                        );
                    }
                };
            match web::service::fetch(&ctx, req).await {
                Ok(result) => mcp_text_result(id, &result),
                Err(e) => map_error(id, &e),
            }
        }
        other => JsonRpcResponse::err(
            id,
            crate::mcp::jsonrpc::TOOL_NOT_FOUND,
            format!("tool `{other}` not exposed by built-in web upstream"),
        ),
    }
}

fn build_ctx<'a>(
    auth: &'a AuthCtx,
    upstream: &McpUpstreamServer,
    credential: Option<&'a str>,
) -> web::service::WebContext<'a> {
    // request_id is distinct per call — retry-dedup at the audit layer would
    // be nice but correctness wins (a retried RPC against a stateful backend
    // genuinely is a separate call from the audit's perspective).
    let request_id = streamscope_core::ids::mint_request_id();

    web::service::WebContext {
        settings: &auth.web_settings,
        credential,
        search_clients: &auth.web_search_clients,
        audit_tx: Some(&auth.web_audit_tx),
        request_id,
        tenant_id: auth.tenant_id,
        workspace_id: auth.workspace_id,
        user_id: auth.user_id,
        upstream_server_id: upstream.id,
        key_id: auth.key_id,
        app_id: None,
        session_id: None,
        user_agent: None,
        detection_method: Some(streamscope_core::middleware::attribution::DETECTION_DIRECT.to_string()),
        ip: None,
        // Direct `/mcp/web` surface: result goes straight to the client, so the
        // service runs an observe-mode scan and badges the `web_audit` row.
        surface: web::service::WebSurface::DirectMcp {
            guardrail: &auth.guardrail,
        },
        parent_request_id: None,
        // Direct MCP traffic carries no intercepted-call id (the guardrail rides
        // the web_audit row's badge, not the LLM turn's guardrail_steps).
        tool_use_id: None,
        // MCP `tools/call` futures are dropped by the JSON-RPC layer when the
        // client disconnects, which already cancels in-flight HTTP via
        // reqwest's connection drop. No explicit token threaded today.
        cancel_token: None,
    }
}

/// Wrap a successful service result as an MCP `content: [{ type: "text", … }]`
/// reply. The model sees the JSON-stringified result; clients that render
/// MCP tool results show it inline.
fn mcp_text_result<T: serde::Serialize>(id: RpcId, result: &T) -> JsonRpcResponse {
    let text = serde_json::to_string_pretty(result)
        .unwrap_or_else(|e| format!("(serialization error: {e})"));
    JsonRpcResponse::ok(
        id,
        json!({
            "content": [
                { "type": "text", "text": text }
            ],
            "isError": false
        }),
    )
}

fn map_error(id: RpcId, e: &web::WebError) -> JsonRpcResponse {
    JsonRpcResponse::err(id, e.rpc_code(), e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::web::types::WebProvider;

    fn names(resp: &JsonRpcResponse) -> Vec<String> {
        resp.result.as_ref().unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    fn initialize(settings: &WebSettings) -> String {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(RpcId::Null),
            method: "initialize".into(),
            params: None,
        };
        let resp = handle_initialize(&req, RpcId::Null, settings);
        resp.result.unwrap()["instructions"].as_str().unwrap().to_string()
    }

    #[test]
    fn without_a_search_backend_only_fetch_is_listed_and_named() {
        let s = WebSettings::default();
        assert_eq!(names(&handle_tools_list(RpcId::Null, &s)), ["web_fetch"]);
        let text = initialize(&s);
        assert!(text.contains("web_fetch") && !text.contains("web_search"), "{text}");
    }

    #[test]
    fn with_a_search_backend_both_tools_are_listed_and_named() {
        let s = WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("https://search.example.com".into()),
            ..WebSettings::default()
        };
        assert_eq!(names(&handle_tools_list(RpcId::Null, &s)), ["web_search", "web_fetch"]);
        let text = initialize(&s);
        assert!(text.contains("web_fetch") && text.contains("web_search"), "{text}");
    }
}
