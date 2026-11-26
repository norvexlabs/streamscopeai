//! Built-in Web virtual MCP server (search + fetch).
//!
//! Exposes two tools to MCP clients mounted on `/mcp/web` (the default
//! tenant slug):
//!
//! - **`web_search`** — query the configured search backend (SearXNG or
//!   Staan). Returns ranked hits with snippets.
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
use crate::mcp::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RpcId, MCP_TOOL_EXECUTION_ERROR};
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

pub(crate) fn handle_tools_list(id: RpcId, settings: &WebSettings) -> JsonRpcResponse {
    // Only the tools these settings can serve: `web_search` needs a search
    // backend, `web_fetch` does not.
    let tools: Vec<Value> = web::served_web_tools(settings)
        .map(|tool| match tool.name {
            TOOL_WEB_SEARCH => tool_schema_web_search(tool, settings),
            TOOL_WEB_FETCH => tool_schema_web_fetch(tool),
            _ => json!({
                "name": tool.name,
                "title": tool.title,
                "description": tool.description,
                "inputSchema": { "type": "object" },
            }),
        })
        .collect();
    JsonRpcResponse::ok(id, json!({ "tools": tools }))
}

/// Both tools only read the public web: nothing they do changes anything, and
/// what they reach is outside this server. MCP `ToolAnnotations` (2026-07-28,
/// as in 2025-11-25 and earlier): `destructiveHint` and `idempotentHint` are
/// "meaningful only when `readOnlyHint == false`", so a read-only tool states
/// neither.
fn read_only_open_world() -> Value {
    json!({
        "readOnlyHint": true,
        "openWorldHint": true,
    })
}

fn tool_schema_web_search(tool: &web::BuiltinTool, settings: &WebSettings) -> Value {
    let cap = WebSettings::MAX_RESULTS_HARD_CAP;
    json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to search for, as you would type it into a search engine."
                },
                "max_results": {
                    "type": "integer",
                    "description": format!("How many results to return (1–{cap}); fewer may come back."),
                    "minimum": 1,
                    "maximum": cap,
                    "default": settings.max_results.clamp(1, cap),
                },
                "language": {
                    "type": "string",
                    "description": "Optional ISO 639-1 language of the results (e.g. \"en\", \"fr\")."
                }
            },
            "required": ["query"]
        },
        // A search result is returned whole as `structuredContent` (and as
        // its JSON in the text block); `snippet` and `published` are absent
        // when the search engine gives none.
        "outputSchema": {
            "type": "object",
            "properties": {
                "hits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": { "type": "string" },
                            "title": { "type": "string" },
                            "snippet": { "type": "string" },
                            "published": { "type": "string" }
                        },
                        "required": ["url", "title"]
                    }
                },
                "total_filtered": {
                    "type": "integer",
                    "description": "Results left out because their address is not allowed."
                },
                "backend": { "type": "string", "description": "The search engine that answered." }
            },
            "required": ["hits", "total_filtered", "backend"]
        },
        "annotations": read_only_open_world(),
    })
}

fn tool_schema_web_fetch(tool: &web::BuiltinTool) -> Value {
    json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "format": "uri",
                    "description": "The absolute http or https URL of the page, e.g. one from a web_search result."
                },
                "max_length": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "The most characters of the page's text to return. Omit for the whole page."
                },
                "start_index": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "The character to start from: the next_start_index a cut result gave."
                }
            },
            "required": ["url"]
        },
        "annotations": read_only_open_world(),
    })
}

async fn handle_tools_call(
    auth: &AuthCtx,
    upstream: &McpUpstreamServer,
    request: &JsonRpcRequest,
    id: RpcId,
) -> JsonRpcResponse {
    use streamscope_core::config::tool_rules::WebInterceptKind;

    let params = request.params.clone().unwrap_or(Value::Null);
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // `arguments` is optional in a CallToolRequest: absent is no arguments.
    let arguments = params
        .get("arguments")
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Decrypt the upstream's stored credential ahead of context construction
    // so its plaintext lifetime is bound to this stack frame; Staan reads it
    // via `ctx.credential`.
    let credential = upstream
        .encrypted_credential
        .as_deref()
        .and_then(web::decrypt_upstream_credential);
    if let Some(unknown) = unserved_tool(&id, &auth.web_settings, &name) {
        return unknown;
    }
    let ctx = build_ctx(auth, upstream, credential.as_deref());

    // Every failure of a call to a tool this server has is a tool execution
    // error (MCP: a result with `isError`, its text one the model can act on);
    // only an unknown tool is a protocol error. Arguments decode through
    // `parse_audited_args`, so a malformed call leaves its `web_audit` row
    // like every other way `search`/`fetch` can fail.
    match name.as_str() {
        TOOL_WEB_SEARCH => {
            let op = WebInterceptKind::Search;
            let req: SearchRequest =
                match web::service::parse_audited_args(&ctx, "search", &arguments.to_string()).await {
                    Ok(r) => r,
                    Err(e) => return tool_error(id, &e, op),
                };
            match web::service::search(&ctx, req).await {
                Ok(result) => tool_result(id, &result, true),
                Err(e) => tool_error(id, &e, op),
            }
        }
        TOOL_WEB_FETCH => {
            let op = WebInterceptKind::Fetch;
            let req: FetchRequest =
                match web::service::parse_audited_args(&ctx, "fetch", &arguments.to_string()).await {
                    Ok(r) => r,
                    Err(e) => return tool_error(id, &e, op),
                };
            // This server's `web_fetch` declares `start_index`. The client is
            // handed the slice; the service scanned the whole page.
            match web::service::fetch(&ctx, req, web::Paging::Offered).await {
                Ok(fetched) => tool_result(id, &fetched.result, false),
                Err(e) => tool_error(id, &e, op),
            }
        }
        other => unknown_tool(id, other),
    }
}

/// The answer to a call naming a tool these settings do not serve — one
/// `tools/list` does not offer (`web_search` without a search backend, or no
/// such tool) — `None` for a served one. A tool the server does not offer is an
/// unknown tool, answered before anything runs, so no `web_audit` row records
/// a call to a tool that does not exist.
fn unserved_tool(id: &RpcId, settings: &WebSettings, name: &str) -> Option<JsonRpcResponse> {
    (!web::served_web_tools(settings).any(|tool| tool.name == name)).then(|| unknown_tool(id.clone(), name))
}

/// An unknown tool is a protocol error, `-32602` (Invalid params), as the MCP
/// tools error handling's own example answers one (2026-07-28, 2025-11-25).
pub(crate) fn unknown_tool(id: RpcId, name: &str) -> JsonRpcResponse {
    JsonRpcResponse::err(id, crate::mcp::jsonrpc::INVALID_PARAMS, format!("Unknown tool: {name}"))
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

/// A successful call as an MCP result: the result's JSON in a text block —
/// what the model reads — and, for a tool declaring an `outputSchema`, the
/// same object as `structuredContent`.
pub(crate) fn tool_result<T: serde::Serialize>(id: RpcId, result: &T, structured: bool) -> JsonRpcResponse {
    let value = serde_json::to_value(result).unwrap_or(Value::Null);
    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
    let mut body = json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": false
    });
    if structured {
        body["structuredContent"] = value;
    }
    JsonRpcResponse::ok(id, body)
}

/// A failed call as an MCP tool execution error: `isError`, and the text the
/// model is told ([`web::WebError::model_text`]; this server's definitions
/// declare every optional argument). The audit row records it as any tool's
/// own failure, [`MCP_TOOL_EXECUTION_ERROR`] (category `tool_error`) — what
/// the client was answered — with the failure's own words as its message;
/// the `web_audit` row keeps its specific category (`WebError::category`).
pub(crate) fn tool_error(
    id: RpcId,
    e: &web::WebError,
    op: streamscope_core::config::tool_rules::WebInterceptKind,
) -> JsonRpcResponse {
    JsonRpcResponse::tool_execution_error(
        id,
        e.model_text(op, web::DeclaredArgs::ALL),
        crate::mcp::jsonrpc::JsonRpcError { code: MCP_TOOL_EXECUTION_ERROR, message: e.to_string(), data: None },
    )
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

    /// A call naming a tool `tools/list` does not offer is an unknown tool,
    /// `-32602` "Unknown tool: <name>" (MCP 2026-07-28 and 2025-11-25 tools
    /// § Error Handling: "Protocol Errors … Unknown tool"): `web_search`
    /// without a search backend; with one, both tools are served and only a
    /// name of neither is unknown.
    #[test]
    fn a_tool_the_settings_do_not_serve_is_an_unknown_tool() {
        let none = WebSettings::default();
        let unknown = unserved_tool(&RpcId::Null, &none, TOOL_WEB_SEARCH).expect("not served");
        let err = unknown.error.as_ref().unwrap();
        assert_eq!((err.code, err.message.as_str()), (crate::mcp::jsonrpc::INVALID_PARAMS, "Unknown tool: web_search"));
        assert!(unknown.result.is_none());
        assert!(unserved_tool(&RpcId::Null, &none, TOOL_WEB_FETCH).is_none());

        let backed = WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("https://search.example.com".into()),
            ..WebSettings::default()
        };
        assert!(unserved_tool(&RpcId::Null, &backed, TOOL_WEB_SEARCH).is_none());
        assert!(unserved_tool(&RpcId::Null, &backed, TOOL_WEB_FETCH).is_none());
        assert!(unserved_tool(&RpcId::Null, &backed, "nope").is_some());
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

    /// Each tool as MCP 2026-07-28 and 2025-11-25 describe one — the one list
    /// every era is served: a name, a display `title`, a description, an
    /// object `inputSchema` whose required keys it declares, read-only
    /// open-world annotations with neither hint the schema calls "meaningful
    /// only when `readOnlyHint == false`", and for web_search an
    /// `outputSchema` its `structuredContent` conforms to, an object at its
    /// root ("Currently restricted to type: \"object\" at the root level" in
    /// 2025-11-25; any schema in 2026-07-28). The stated result range is the
    /// hard cap's, and nothing a model reads names the gateway's own
    /// mechanisms.
    #[test]
    fn the_listed_tools_carry_the_spec_tool_fields() {
        let s = WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("https://search.example.com".into()),
            ..WebSettings::default()
        };
        let resp = handle_tools_list(RpcId::Null, &s);
        let tools = resp.result.as_ref().unwrap()["tools"].as_array().unwrap().clone();
        for tool in &tools {
            let name = tool["name"].as_str().unwrap();
            assert!(tool["title"].as_str().is_some_and(|t| !t.is_empty()), "{name}");
            assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
            let props = tool["inputSchema"]["properties"].as_object().unwrap();
            for key in tool["inputSchema"]["required"].as_array().unwrap() {
                assert!(props.contains_key(key.as_str().unwrap()), "{name}: {key}");
            }
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{name}");
            assert_eq!(tool["annotations"]["openWorldHint"], true, "{name}");
            for meaningless in ["destructiveHint", "idempotentHint"] {
                assert!(tool["annotations"].get(meaningless).is_none(), "{name}: {meaningless}");
            }
            let text = serde_json::to_string(tool).unwrap().to_lowercase();
            for jargon in ["tenant", "gateway", "max_bytes"] {
                assert!(!text.contains(jargon), "{name} says {jargon:?}");
            }
        }
        let search = &tools[0];
        let range = format!("1–{}", WebSettings::MAX_RESULTS_HARD_CAP);
        let max_results = &search["inputSchema"]["properties"]["max_results"];
        assert!(max_results["description"].as_str().unwrap().contains(&range), "{max_results}");
        assert_eq!(max_results["maximum"], WebSettings::MAX_RESULTS_HARD_CAP);
        assert_eq!(search["inputSchema"]["required"], json!(["query"]));
        assert_eq!(search["outputSchema"]["type"], "object");
        assert_eq!(search["outputSchema"]["required"], json!(["hits", "total_filtered", "backend"]));
        assert_eq!(search["outputSchema"]["properties"]["hits"]["items"]["required"], json!(["url", "title"]));
        let fetch = &tools[1];
        assert_eq!(fetch["inputSchema"]["required"], json!(["url"]));
        for key in ["max_length", "start_index"] {
            assert_eq!(fetch["inputSchema"]["properties"][key]["type"], "integer", "{key}");
        }
        // A failed call names every optional argument (`DeclaredArgs::ALL`):
        // these definitions declare each one.
        let declared = |t: &Value| web::DeclaredArgs::of_schema(&t["inputSchema"]);
        assert!(declared(search).max_results, "{search}");
        assert!(declared(fetch).max_length && declared(fetch).start_index, "{fetch}");
        assert!(fetch.get("outputSchema").is_none());

        // `structuredContent` is the search result itself, the same object
        // the text block carries.
        let result = streamscope_core::web::SearchResult {
            hits: vec![streamscope_core::web::SearchHit {
                url: "https://a.test/".into(),
                title: "A".into(),
                snippet: None,
                published: None,
            }],
            total_filtered: 0,
            backend: WebProvider::Searxng,
        };
        let ok = tool_result(RpcId::Null, &result, true);
        let body = ok.result.unwrap();
        assert_eq!(body["isError"], false);
        let text: Value = serde_json::from_str(body["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, body["structuredContent"]);
        assert_eq!(body["structuredContent"]["hits"][0]["url"], "https://a.test/");
        assert!(body["structuredContent"]["hits"][0].get("snippet").is_none(), "absent, never null");
    }

    /// A failed call is a tool execution error the model can act on — a
    /// result with `isError`, its text a code it knows then what to do — and
    /// the audit still records it as the failure it is. A successful call is
    /// the positive control.
    #[test]
    fn a_failed_call_is_an_is_error_result_the_audit_still_counts() {
        use streamscope_core::config::tool_rules::WebInterceptKind;
        let e = web::WebError::InvalidArguments("missing field `url`".into());
        let resp = tool_error(RpcId::Null, &e, WebInterceptKind::Fetch);
        assert!(resp.error.is_none(), "not a protocol error");
        let body = resp.result.as_ref().unwrap();
        assert_eq!(body["isError"], true);
        let text = body["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("invalid_tool_input: ") && text.contains("missing field `url`"), "{text}");
        let audited = resp.audited_error().expect("the audit records the failure");
        assert_eq!((audited.code, audited.message.as_str()), (MCP_TOOL_EXECUTION_ERROR, "invalid arguments: missing field `url`"));
        assert_eq!(crate::mcp::jsonrpc::audit_error_category(audited.code), "tool_error");
        let wire = serde_json::to_value(&resp).unwrap();
        assert!(wire.get("audit_error").is_none(), "never on the wire: {wire}");

        let refused = tool_error(RpcId::Null, &web::WebError::SsrfRefused("internal address".into()), WebInterceptKind::Fetch);
        let text = refused.result.as_ref().unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        assert!(text.starts_with("url_not_allowed: ") && !text.contains("internal address"), "{text}");
        // A tool's own failure whatever its cause, its words kept: never the
        // code of a gateway refusal of an upstream (-32505).
        let audited = refused.audited_error().unwrap();
        assert_eq!((audited.code, audited.message.as_str()), (MCP_TOOL_EXECUTION_ERROR, "URL refused by SSRF guard: internal address"));

        let ok = tool_result(RpcId::Null, &json!({"final_url": "https://a.test/"}), false);
        assert!(ok.audited_error().is_none());
        assert_eq!(ok.result.as_ref().unwrap()["isError"], false);
        assert!(ok.result.as_ref().unwrap().get("structuredContent").is_none());
    }
}
