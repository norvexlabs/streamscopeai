//! Portal — MCP catalog smoke test.
//!
//! `POST /api/v1/portal/mcp/test/{virtual_server_id}` runs `tools/list` /
//! `prompts/list` / `resources/list` against each upstream the chosen virtual
//! server fans into, using the same auth resolution rules the proxy uses, and
//! returns the merged catalog the user's `sk-*` key would see when calling
//! `/mcp/<slug>`.
//!
//! Why this lives in admin-api rather than going through the proxy:
//! - The user already authenticated via the portal session — we don't want
//!   them to paste their `sk-*` plaintext into a textbox to "test it".
//! - The test endpoint has the same auth-mode coverage matrix as the proxy
//!   (no_auth, service_account, per_user_oauth) without dragging in the
//!   proxy's full multiplexer / session-tracking infrastructure.
//!
//! Out of scope:
//! - `byot` upstreams — they only resolve at request time on the `/fwd/{vk-...}`
//!   path; without the agent's bearer in hand, we can't preview them. The
//!   endpoint reports `unsupported_byot` so the UI can explain.
//! - Streaming `tools/call` — this is read-only catalog discovery; the test
//!   page links to a sample curl for actual tool invocation.

use std::time::Duration;

use axum::extract::Path;
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::Value;
use streamscope_core::config::mcp::routes_back_to;
use streamscope_core::web::{
    is_internal_upstream_url, served_web_tools, WebSettings, BUILTIN_WEB_UPSTREAM_NAME,
    BUILTIN_WEB_UPSTREAM_URL,
};
use utoipa::ToSchema;
use uuid::Uuid;

use super::portal_auth::PortalUser;
use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};

#[derive(Serialize, ToSchema)]
pub struct PortalMcpTestResponse {
    pub virtual_server: PortalMcpTestVirtualServer,
    pub routes: Vec<PortalMcpTestRouteResult>,
    /// Aggregated tool count across all reachable routes (post-namespacing).
    pub total_tools: usize,
    pub total_prompts: usize,
    pub total_resources: usize,
}

#[derive(Serialize, ToSchema)]
pub struct PortalMcpTestVirtualServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PortalMcpTestRouteResult {
    pub upstream_id: Uuid,
    pub upstream_name: String,
    pub upstream_url: String,
    pub auth_mode: String,
    pub prefix: String,
    /// One of: `ok`, `needs_connection`, `service_account_unavailable`,
    /// `unsupported_byot`, `http_error`, `jsonrpc_error`, `disabled`.
    pub status: String,
    /// Human-readable detail when `status != ok`. None on success.
    pub error: Option<String>,
    /// Namespaced tool names (`<prefix>__<name>` when prefix is set).
    pub tools: Vec<PortalMcpTestEntry>,
    pub prompts: Vec<PortalMcpTestEntry>,
    pub resources: Vec<PortalMcpTestResource>,
    /// Populated only for gateway-internal upstreams (e.g. `internal://web`).
    /// Exposes admin-side configuration state the portal user can't observe
    /// directly (does the operator have a backend selected? a credential
    /// stored?), so the user can tell whether their agent calls will
    /// actually succeed at runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtin_status: Option<PortalMcpBuiltinStatus>,
}

/// Configuration summary for gateway-internal MCP upstreams (only built-in
/// upstreams populate this — regular HTTP upstreams leave it absent).
#[derive(Serialize, ToSchema, Debug, Clone)]
pub struct PortalMcpBuiltinStatus {
    /// `true` iff the admin has selected a search backend in
    /// `system_settings.web`. False means only `web_fetch` is served;
    /// `web_search` appears once a backend is configured.
    pub has_backend: bool,
    /// `true` iff an encrypted backend credential is stored on the
    /// synthetic `builtin-web` row. False is non-fatal (some backends like
    /// public SearXNG don't need one) but worth surfacing for operators.
    pub has_credential: bool,
}

#[derive(Serialize, ToSchema)]
pub struct PortalMcpTestEntry {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalMcpTestResource {
    pub uri: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(sqlx::FromRow)]
struct VsRow {
    id: Uuid,
    slug: String,
    name: String,
}

#[derive(sqlx::FromRow)]
struct RouteUpstreamRow {
    upstream_id: Uuid,
    upstream_name: String,
    upstream_url: String,
    auth_mode: String,
    enabled: bool,
    /// BYTEA column read as UTF-8 via `convert_from(..., 'UTF8')` — same as
    /// the proxy's snapshot path. Holds base64 ciphertext.
    encrypted_credential: Option<String>,
    prefix: String,
    request_timeout_ms: i32,
}

#[derive(sqlx::FromRow)]
struct UserCredRow {
    encrypted_access_token: String,
    /// NULL = no known expiry. The proxy refreshes an expired token on real
    /// calls; the test path can't, so it reports `token_expired` instead of
    /// making a doomed upstream call with a stale bearer.
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Hard upper bound on per-call upstream timeout for the test path. Operators
/// can set very large request_timeout_ms on production upstreams (multi-minute
/// tool calls), but the test endpoint pings list-shaped read-only methods only,
/// and a portal user shouldn't be able to pin an admin-api worker for minutes.
const TEST_UPSTREAM_TIMEOUT_CAP_MS: u64 = 15_000;

#[utoipa::path(
    post,
    path = "/api/v1/portal/mcp/virtual-servers/{virtual_server_id}/actions/test",
    tag = "Portal MCP",
    operation_id = "portal_test_mcp_virtual_server",
    params(
        ("virtual_server_id" = Uuid, Path, description = "Virtual server to test"),
    ),
    responses(
        (status = 200, description = "What the test call to each upstream returned", body = PortalMcpTestResponse),
        (status = 400, body = ApiErrorResponse, description = "Invalid upstream URL"),
        (status = 403, body = ApiErrorResponse, description = "RBAC forbids this virtual server"),
        (status = 404, description = "No such virtual server", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_virtual_server(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(virtual_server_id): Path<Uuid>,
) -> Result<Json<PortalMcpTestResponse>, ApiError> {
    // Workspace allowlist + lookup.
    let vs: Option<VsRow> = sqlx::query_as::<_, VsRow>(
        r#"SELECT vs.id, vs.slug, vs.name
           FROM mcp_virtual_servers vs
           WHERE vs.id = $1 AND vs.enabled
             AND EXISTS (
                   SELECT 1 FROM workspace_members wm
                   JOIN workspace_mcp_access wma ON wma.workspace_id = wm.workspace_id
                   WHERE wm.user_id = $2 AND wma.virtual_server_id = vs.id
                     AND ($3::uuid IS NULL OR wm.workspace_id = $3)
                 )"#,
    )
    .bind(virtual_server_id)
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal mcp test vs lookup: {e}");
        ApiError::internal("failed to load virtual server")
    })?;
    let vs = vs.ok_or_else(|| {
        ApiError::not_found("virtual server not found or not accessible", ApiErrorCode::McpVirtualServerNotFound)
    })?;

    // The test calls ride TLS to operator-configured upstreams that may sit
    // behind a private CA. The trusted-CA cache is per-replica and only the
    // replica that handled the import refreshes it, so read it fresh here —
    // otherwise the button reports a trust failure a real call would not hit.
    crate::custom_ca::refresh_from_conn(db.conn()).await;

    // Routes + upstream details, ordered so the merge is deterministic.
    let routes: Vec<RouteUpstreamRow> = sqlx::query_as::<_, RouteUpstreamRow>(
        r#"SELECT u.id AS upstream_id,
                  u.name AS upstream_name,
                  u.upstream_url AS upstream_url,
                  u.auth_mode AS auth_mode,
                  u.enabled AS enabled,
                  convert_from(u.encrypted_credential, 'UTF8') AS encrypted_credential,
                  COALESCE(r.prefix, '') AS prefix,
                  u.request_timeout_ms
           FROM mcp_virtual_routes r
           JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
           WHERE r.virtual_server_id = $1 AND r.enabled
           ORDER BY r.position, r.id"#,
    )
    .bind(vs.id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal mcp test routes lookup: {e}");
        ApiError::internal("failed to load routes")
    })?;

    // The prefix of every route the gateway serves (its upstream enabled), so
    // the preview advertises exactly the names the gateway's `tools/list`
    // keeps: those that route back to their upstream.
    let prefixes: Vec<String> =
        routes.iter().filter(|r| r.enabled).map(|r| r.prefix.clone()).collect();
    let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let routable = |entries: &mut Vec<PortalMcpTestEntry>, prefix: &str| {
        entries.retain(|e| routes_back_to(&e.name, &prefixes, prefix));
    };

    let mut results = Vec::with_capacity(routes.len());
    let mut total_tools = 0usize;
    let mut total_prompts = 0usize;
    let mut total_resources = 0usize;

    for route in routes {
        if !route.enabled {
            results.push(PortalMcpTestRouteResult {
                upstream_id: route.upstream_id,
                upstream_name: route.upstream_name,
                upstream_url: route.upstream_url,
                auth_mode: route.auth_mode,
                prefix: route.prefix,
                status: "disabled".into(),
                error: Some("upstream disabled".into()),
                tools: vec![],
                prompts: vec![],
                resources: vec![],
                builtin_status: None,
            });
            continue;
        }

        // Built-in upstreams (`internal://...`) don't go over HTTP, so the
        // SSRF / scheme guards downstream would reject them. Short-circuit
        // here with a hardcoded preview of the tool surface plus a
        // capability summary (does the admin have a backend / credential
        // configured?). No live call — there is nothing dynamic to probe
        // for these.
        if is_internal_upstream_url(&route.upstream_url) {
            // Pull tenant_uuid first — it borrows `db` immutably, and the
            // mutable `db.conn()` borrow on the next line would otherwise
            // conflict (E0502).
            let tenant_uuid = db.tenant_uuid();
            let preview = preview_internal_upstream(
                db.conn(),
                tenant_uuid,
                &route.upstream_url,
                &route.prefix,
            )
            .await?;
            let mut preview = preview;
            routable(&mut preview.tools, &route.prefix);
            routable(&mut preview.prompts, &route.prefix);
            total_tools += preview.tools.len();
            total_prompts += preview.prompts.len();
            total_resources += preview.resources.len();
            results.push(PortalMcpTestRouteResult {
                upstream_id: route.upstream_id,
                upstream_name: route.upstream_name,
                upstream_url: route.upstream_url,
                auth_mode: route.auth_mode,
                prefix: route.prefix,
                status: "ok".into(),
                error: None,
                tools: preview.tools,
                prompts: preview.prompts,
                resources: preview.resources,
                builtin_status: Some(preview.builtin_status),
            });
            continue;
        }
        // Resolve bearer per auth_mode — same matrix as the proxy.
        let bearer = match route.auth_mode.as_str() {
            "no_auth" => Ok(None),
            "service_account" => match (&route.encrypted_credential, streamscope_core::crypto::get_encryption_key()) {
                (Some(cipher), Some(key)) => streamscope_core::crypto::decrypt(cipher.as_str(), &key)
                    .map(Some)
                    .map_err(|_| "service_account_unavailable"),
                _ => Err("service_account_unavailable"),
            },
            "per_user_oauth" => {
                // `encrypted_access_token` is BYTEA holding the UTF-8 ciphertext
                // (the store binds `.into_bytes()`); read it back as text with
                // `convert_from(..., 'UTF8')` — same as the edge-sync forwarder.
                // A raw `SELECT` of the BYTEA column into a Rust `String` fails
                // to decode (sqlx maps BYTEA → Vec<u8>).
                let cred: Option<UserCredRow> = sqlx::query_as::<_, UserCredRow>(
                    r#"SELECT convert_from(encrypted_access_token, 'UTF8') AS encrypted_access_token,
                              expires_at
                       FROM mcp_user_credentials
                       WHERE tenant_id = $1 AND user_id = $2 AND upstream_server_id = $3"#,
                )
                .bind(db.tenant_uuid())
                .bind(user.user_id)
                .bind(route.upstream_id)
                .fetch_optional(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!("portal mcp test cred lookup: {e}");
                    ApiError::internal("failed to look up credential")
                })?;
                match cred {
                    None => Err("needs_connection"),
                    // The proxy refreshes an expired access token transparently
                    // on real calls; the test path doesn't, so a live probe with
                    // a stale bearer would 401. Report `token_expired` — the
                    // connection is fine, it just needs a reconnect to verify here.
                    Some(c) if c.expires_at.is_some_and(|e| e <= chrono::Utc::now()) => {
                        Err("token_expired")
                    }
                    Some(c) => match streamscope_core::crypto::get_encryption_key() {
                        Some(key) => streamscope_core::crypto::decrypt(c.encrypted_access_token.as_str(), &key)
                            .map(Some)
                            .map_err(|_| "needs_connection"),
                        None => Err("needs_connection"),
                    },
                }
            }
            "byot" => Err("unsupported_byot"),
            _ => Err("service_account_unavailable"),
        };
        let bearer = match bearer {
            Ok(b) => b,
            Err(status) => {
                let msg = match status {
                    "needs_connection" => "no stored OAuth credential — connect first",
                    "token_expired" => "OAuth token expired — reconnect to test here (real calls refresh it automatically)",
                    "service_account_unavailable" => "service-account credential is missing or undecryptable",
                    "unsupported_byot" => "byot upstreams cannot be tested from the portal",
                    _ => "auth resolution failed",
                };
                results.push(PortalMcpTestRouteResult {
                    upstream_id: route.upstream_id,
                    upstream_name: route.upstream_name,
                    upstream_url: route.upstream_url,
                    auth_mode: route.auth_mode,
                    prefix: route.prefix,
                    status: status.into(),
                    error: Some(msg.into()),
                    tools: vec![],
                    prompts: vec![],
                    resources: vec![],
                    builtin_status: None,
                });
                continue;
            }
        };

        // Defense-in-depth: reject non-http(s) upstream URLs at the test
        // endpoint. Today only operators write `upstream_url`, but if the
        // self-service surface ever grows, this guard prevents a portal user
        // from steering admin-api into making outbound calls to non-HTTP
        // schemes (file://, gopher://, …) using a server-decrypted bearer.
        // Internal upstreams (`internal://...`) are short-circuited above
        // and never reach this guard.
        if !route.upstream_url.starts_with("http://")
            && !route.upstream_url.starts_with("https://")
        {
            results.push(PortalMcpTestRouteResult {
                upstream_id: route.upstream_id,
                upstream_name: route.upstream_name,
                upstream_url: route.upstream_url,
                auth_mode: route.auth_mode,
                prefix: route.prefix,
                status: "http_error".into(),
                error: Some("upstream_url must be http(s)://...".into()),
                tools: vec![],
                prompts: vec![],
                resources: vec![],
                builtin_status: None,
            });
            continue;
        }

        // Run tools/list, prompts/list, resources/list. Each is a separate
        // JSON-RPC POST so a server that doesn't support one capability still
        // surfaces the others. Cap the per-call timeout so a portal user
        // can't pin an admin-api worker for minutes via a slow upstream.
        let raw_timeout = u64::try_from(route.request_timeout_ms).unwrap_or(60_000);
        let timeout = Duration::from_millis(raw_timeout.min(TEST_UPSTREAM_TIMEOUT_CAP_MS));

        // MCP streamable-HTTP handshake, matching what the proxy (and any real
        // client) does: `initialize` first — capturing any `Mcp-Session-Id` the
        // server assigns — then `notifications/initialized`, then the list
        // calls carrying that session. A stateful server (e.g. GitHub) rejects
        // a bare `tools/list`; a stateless one simply returns no session id and
        // the calls proceed without one. Replies may be JSON or SSE-framed.
        let init_params = serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "streamscope-portal-test", "version": "1" },
        });
        // One guarded client per test run — see `guarded_test_client`. A
        // build failure surfaces on the same path a handshake failure does.
        let (tools_res, prompts_res, resources_res) = match guarded_test_client() {
            Err(e) => (Err(e), Err(String::new()), Err(String::new())),
            Ok(http) => match mcp_rpc(
                &http, &route.upstream_url, &bearer, &None,
                "initialize", init_params, timeout,
            )
            .await
            {
                // Handshake failed — surface it as the primary (tools/list)
                // error; the other two collapse to empty via the
                // `Err(_) => vec![]` arms.
                Err(e) => (Err(e), Err(String::new()), Err(String::new())),
                Ok((_, session_id)) => {
                    if session_id.is_some() {
                        mcp_notify(
                            &http, &route.upstream_url, &bearer, &session_id,
                            "notifications/initialized", timeout,
                        )
                        .await;
                    }
                    let empty = serde_json::json!({});
                    let tools = mcp_rpc(&http, &route.upstream_url, &bearer, &session_id, "tools/list", empty.clone(), timeout).await.map(|(v, _)| v);
                    let prompts = mcp_rpc(&http, &route.upstream_url, &bearer, &session_id, "prompts/list", empty.clone(), timeout).await.map(|(v, _)| v);
                    let resources = mcp_rpc(&http, &route.upstream_url, &bearer, &session_id, "resources/list", empty, timeout).await.map(|(v, _)| v);
                    (tools, prompts, resources)
                }
            },
        };

        // tools/list is the primary signal — if it failed at the HTTP or
        // JSON-RPC layer, surface that even if prompts/resources happen to
        // succeed. prompts/list and resources/list are best-effort: many
        // servers don't implement them.
        let mut status = "ok";
        let mut err_msg: Option<String> = None;
        let (mut tools, tools_err) = match &tools_res {
            Ok(v) => (extract_named(v, "tools", &route.prefix), None),
            Err(e) => (vec![], Some(e.clone())),
        };
        if let Some(msg) = tools_err {
            status = if msg.contains(": HTTP ") {
                "http_error"
            } else {
                "jsonrpc_error"
            };
            err_msg = Some(msg);
        }
        let mut prompts = match &prompts_res {
            Ok(v) => extract_named(v, "prompts", &route.prefix),
            Err(_) => vec![],
        };
        routable(&mut tools, &route.prefix);
        routable(&mut prompts, &route.prefix);
        let resources = match &resources_res {
            Ok(v) => extract_resources(v),
            Err(_) => vec![],
        };

        total_tools += tools.len();
        total_prompts += prompts.len();
        total_resources += resources.len();

        results.push(PortalMcpTestRouteResult {
            upstream_id: route.upstream_id,
            upstream_name: route.upstream_name,
            upstream_url: route.upstream_url,
            auth_mode: route.auth_mode,
            prefix: route.prefix,
            status: status.into(),
            error: err_msg,
            tools,
            prompts,
            resources,
            builtin_status: None,
        });
    }

    Ok(Json(PortalMcpTestResponse {
        virtual_server: PortalMcpTestVirtualServer { id: vs.id, slug: vs.slug, name: vs.name },
        routes: results,
        total_tools,
        total_prompts,
        total_resources,
    }))
}

/// Extract the last SSE `data:` payload from a `text/event-stream` body — the
/// MCP streamable-HTTP transport frames a JSON-RPC reply this way. Mirrors the
/// proxy's upstream parser so the test unwraps exactly what a real call does.
fn parse_last_sse_event(text: &str) -> Option<String> {
    let mut last_data: Option<String> = None;
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            if let Some(payload) = current.take() {
                last_data = Some(payload);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            current = Some(rest.trim_start_matches(' ').to_string());
        }
    }
    if let Some(payload) = current {
        last_data = Some(payload);
    }
    last_data
}

/// POST one JSON-RPC request over MCP streamable HTTP. Returns the parsed
/// response and any `Mcp-Session-Id` the server assigned. Sends the
/// spec-mandated `Accept: application/json, text/event-stream`, forwards the
/// session id when set, and unwraps an SSE-framed reply — the same transport
/// the proxy speaks, so the test sees what a real agent would.
async fn mcp_rpc(
    client: &reqwest::Client,
    upstream_url: &str,
    bearer: &Option<String>,
    session_id: &Option<String>,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<(Value, Option<String>), String> {
    // Defense-in-depth SSRF guard, layer 1: refuse an internal IP *literal*
    // before we connect. Admin write-time validation is the load-bearing layer
    // (see `routes/mcp.rs::validate_outbound_urls`); this catch covers legacy
    // rows + `upstream_url` columns that might bypass the create/update path
    // in future surfaces. Layer 2 — the connect-time resolver that closes DNS
    // rebinding, and redirect re-vetting — rides `client`, which MUST be a
    // guarded one (see `guarded_test_client`). IMDS is refused by both
    // regardless of the operator's egress posture.
    streamscope_mcp_auth::ssrf::check_url_for(upstream_url, super::mcp::MCP_EGRESS)
        .map_err(|e| format!("{method}: upstream URL refused by SSRF guard: {e}"))?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut req = client
        .post(upstream_url)
        .timeout(timeout)
        .header("Accept", "application/json, text/event-stream")
        .json(&body);
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid.as_str());
    }
    let resp = req.send().await.map_err(|e| format!("{method}: {e}"))?;
    let status = resp.status();
    let resp_session = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Bounded like the proxy's own MCP egress, and for the same reason: the
    // server on the other end is operator- or user-named, and an unbounded read
    // lets it OOM this admin-api replica — taking the control plane down for
    // every tenant on it, from a call any portal user can trigger.
    let raw = streamscope_core::http_body::read_body_capped(
        resp,
        streamscope_core::mcp::MCP_MAX_RESPONSE_BYTES,
    )
    .await
    .map_err(|e| format!("{method}: {e}"))?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    if !status.is_success() {
        return Err(format!("{method}: HTTP {status}"));
    }
    let json_str = if content_type.starts_with("text/event-stream") {
        parse_last_sse_event(&text).ok_or_else(|| format!("{method}: empty SSE response"))?
    } else {
        text
    };
    let v: Value =
        serde_json::from_str(&json_str).map_err(|e| format!("{method}: invalid JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("{method}: jsonrpc error: {err}"));
    }
    Ok((v, resp_session))
}

/// The SSRF-guarded client every test call rides.
///
/// The URL is operator-supplied and reached on a portal user's request, so the
/// hostname-only pre-check in [`mcp_rpc`] is not sufficient on its own: only a
/// [`GuardedResolver`](streamscope_mcp_auth::ssrf::GuardedResolver)-backed
/// client validates the address DNS actually returns, at connect time, and
/// re-vets redirect hops.
fn guarded_test_client() -> Result<reqwest::Client, String> {
    streamscope_core::mcp::oauth_http::build_guarded_client(
        super::mcp::MCP_EGRESS,
        crate::custom_ca::current().as_deref(),
        None, // per-call deadlines are applied on each request
    )
    .map_err(|e| format!("build guarded upstream client: {e}"))
}

/// Fire a JSON-RPC notification (no `id`, no reply) — used for
/// `notifications/initialized` after the handshake. Best-effort: any transport
/// error is ignored, since a server that doesn't need the notification still
/// answers the subsequent list calls.
async fn mcp_notify(
    client: &reqwest::Client,
    upstream_url: &str,
    bearer: &Option<String>,
    session_id: &Option<String>,
    method: &str,
    timeout: Duration,
) {
    let body = serde_json::json!({ "jsonrpc": "2.0", "method": method });
    let mut req = client
        .post(upstream_url)
        .timeout(timeout)
        .header("Accept", "application/json, text/event-stream")
        .json(&body);
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid.as_str());
    }
    let _ = req.send().await;
}

fn extract_named(v: &Value, key: &str, prefix: &str) -> Vec<PortalMcpTestEntry> {
    let arr = match v.get("result").and_then(|r| r.get(key)).and_then(|t| t.as_array()) {
        Some(a) => a,
        None => return vec![],
    };
    arr.iter()
        .filter_map(|t| {
            let name = t.get("name").and_then(|n| n.as_str())?;
            let description = t
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            let namespaced = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}__{name}")
            };
            Some(PortalMcpTestEntry { name: namespaced, description })
        })
        .collect()
}

/// Static preview of one gateway-internal upstream's catalog plus the
/// admin-side capability summary the portal user can't observe directly.
///
/// Returned by [`preview_internal_upstream`] to keep the route-loop body
/// from juggling the four output lists.
struct InternalPreview {
    tools: Vec<PortalMcpTestEntry>,
    prompts: Vec<PortalMcpTestEntry>,
    resources: Vec<PortalMcpTestResource>,
    builtin_status: PortalMcpBuiltinStatus,
}

async fn preview_internal_upstream(
    conn: &mut Scoped,
    tenant_id: Uuid,
    upstream_url: &str,
    prefix: &str,
) -> Result<InternalPreview, ApiError> {
    match upstream_url {
        BUILTIN_WEB_UPSTREAM_URL => preview_builtin_web(conn, tenant_id, prefix).await,
        other => {
            // Unknown sentinel — list nothing, but don't 500 since the schema
            // allowed it through. New built-ins should be added here.
            tracing::warn!(upstream_url = %other, "unknown internal upstream in portal MCP test");
            Ok(InternalPreview {
                tools: vec![],
                prompts: vec![],
                resources: vec![],
                builtin_status: PortalMcpBuiltinStatus {
                    has_backend: false,
                    has_credential: false,
                },
            })
        }
    }
}

async fn preview_builtin_web(
    conn: &mut Scoped,
    tenant_id: Uuid,
    prefix: &str,
) -> Result<InternalPreview, ApiError> {
    // Admin-side configuration check. The tool list comes from the same
    // `served_web_tools` predicate the MCP `tools/list` handler uses, so what
    // the portal user sees here matches what the agent gets on a real call.
    let settings = load_web_settings(conn).await?;
    let has_backend = settings.is_configured();
    let has_credential: bool = sqlx::query_scalar(
        "SELECT (encrypted_credential IS NOT NULL)
         FROM mcp_upstream_servers
         WHERE name = $1 AND tenant_id = $2",
    )
    .bind(BUILTIN_WEB_UPSTREAM_NAME)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("portal mcp test builtin-web credential lookup: {e}");
        ApiError::internal("failed to load builtin upstream status")
    })?
    .unwrap_or(false);

    // Exactly the tools the proxy's `tools/list` serves for these settings.
    let tools: Vec<PortalMcpTestEntry> = served_web_tools(&settings)
        .map(|tool| {
            let namespaced = if prefix.is_empty() {
                tool.name.to_string()
            } else {
                format!("{prefix}__{name}", name = tool.name)
            };
            PortalMcpTestEntry {
                name: namespaced,
                description: Some(tool.description.to_string()),
            }
        })
        .collect();

    Ok(InternalPreview {
        tools,
        prompts: vec![],
        resources: vec![],
        builtin_status: PortalMcpBuiltinStatus { has_backend, has_credential },
    })
}

async fn load_web_settings(
    conn: &mut Scoped,
) -> Result<WebSettings, ApiError> {
    let raw: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM system_settings WHERE key = 'web'",
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("portal mcp test load web settings: {e}");
        ApiError::internal("failed to load web settings")
    })?;
    Ok(raw
        .and_then(|v| serde_json::from_value::<WebSettings>(v).ok())
        .unwrap_or_default())
}

fn extract_resources(v: &Value) -> Vec<PortalMcpTestResource> {
    let arr = match v
        .get("result")
        .and_then(|r| r.get("resources"))
        .and_then(|t| t.as_array())
    {
        Some(a) => a,
        None => return vec![],
    };
    arr.iter()
        .filter_map(|r| {
            let uri = r.get("uri").and_then(|u| u.as_str())?;
            let name = r.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());
            let description = r
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            Some(PortalMcpTestResource { uri: uri.to_string(), name, description })
        })
        .collect()
}
