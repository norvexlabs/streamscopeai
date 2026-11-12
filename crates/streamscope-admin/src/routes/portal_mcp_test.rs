//! Portal — MCP catalog smoke test.
//!
//! `POST /api/v1/portal/mcp/virtual-servers/{virtual_server_id}/actions/test`
//! runs `tools/list` / `prompts/list` / `resources/list` against each upstream
//! the chosen virtual server fans into, with the headers the proxy would send
//! for this user (the same resolver,
//! [`streamscope_core::mcp::header_inputs::resolve`]), and returns the merged
//! catalog the user's key would see when calling `/mcp/<slug>`.
//!
//! Why this lives in admin-api rather than going through the proxy:
//! - The user already authenticated via the portal session — we don't want
//!   them to paste their key plaintext into a textbox to "test it".
//! - It needs only the header resolution, not the proxy's multiplexer /
//!   session-tracking infrastructure.
//!
//! Out of scope:
//! - An upstream needing a header the CLIENT sends on each request: the test
//!   has no client, so it reports `needs_client_header` rather than calling.
//! - Streaming `tools/call` — this is read-only catalog discovery.
//!
//! What a result says about a failure is the gateway's own sentence (an HTTP
//! status, a JSON-RPC error code), never text the upstream sent: a portal user
//! must not read what an upstream echoed back of its credentials.

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

use std::collections::HashMap;

use streamscope_core::mcp::header_inputs::{self as hi, InputValues, Remote, ResolveError, UpstreamAuth};

use super::mcp_inputs;
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
    /// One of: `ok`, `needs_connection` (the user's OAuth sign-in or a
    /// required input of theirs is missing), `token_expired`,
    /// `needs_client_header` (the client sends a required header on each
    /// request; not a failure), `unavailable` (the administrator's settings
    /// are incomplete or unreadable), `redirected` (a 3xx, never followed),
    /// `http_error`, `jsonrpc_error`, `disabled`.
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
    remote: sqlx::types::Json<Remote>,
    encrypted_admin_inputs: sqlx::types::Json<HashMap<String, String>>,
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
                  u.remote, u.encrypted_admin_inputs,
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
        // The headers the proxy would send for this user: the same resolver,
        // over the admin's values, the user's own and no client.
        let auth = match resolve_for_user(&mut db, user.user_id, &route).await? {
            Ok(auth) => auth,
            Err((status, msg)) => {
                results.push(PortalMcpTestRouteResult {
                    upstream_id: route.upstream_id,
                    upstream_name: route.upstream_name,
                    upstream_url: route.upstream_url,
                    auth_mode: route.auth_mode,
                    prefix: route.prefix,
                    status: status.into(),
                    error: Some(msg),
                    tools: vec![],
                    prompts: vec![],
                    resources: vec![],
                    builtin_status: None,
                });
                continue;
            }
        };

        let mut probe = probe_upstream(&route.upstream_url, &auth, route.request_timeout_ms, &route.prefix).await;
        routable(&mut probe.tools, &route.prefix);
        routable(&mut probe.prompts, &route.prefix);
        total_tools += probe.tools.len();
        total_prompts += probe.prompts.len();
        total_resources += probe.resources.len();

        results.push(PortalMcpTestRouteResult {
            upstream_id: route.upstream_id,
            upstream_name: route.upstream_name,
            upstream_url: route.upstream_url,
            auth_mode: route.auth_mode,
            prefix: route.prefix,
            status: probe.status.into(),
            error: probe.error,
            tools: probe.tools,
            prompts: probe.prompts,
            resources: probe.resources,
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

/// What one probe of an upstream found: the catalog it lists, or why the call
/// failed (`status` as in [`PortalMcpTestRouteResult::status`]).
pub(crate) struct ProbeOutcome {
    pub status: &'static str,
    pub error: Option<String>,
    pub tools: Vec<PortalMcpTestEntry>,
    pub prompts: Vec<PortalMcpTestEntry>,
    pub resources: Vec<PortalMcpTestResource>,
}

/// Probe one HTTP upstream with `auth`'s headers: the MCP handshake, then
/// `tools/list`, `prompts/list` and `resources/list`, over the guarded,
/// no-redirect client, each call capped at [`TEST_UPSTREAM_TIMEOUT_CAP_MS`].
/// Names are namespaced with `prefix` (`<prefix>__<name>`) when it is set.
/// The shared probe of the portal's and the console's Test buttons.
pub(crate) async fn probe_upstream(
    upstream_url: &str,
    auth: &UpstreamAuth,
    request_timeout_ms: i32,
    prefix: &str,
) -> ProbeOutcome {
    // Defense-in-depth: reject non-http(s) upstream URLs before any call, so
    // a stored URL can never steer admin-api into a non-HTTP scheme with the
    // upstream's resolved headers. Internal upstreams (`internal://...`) are
    // previewed by the callers and never reach this.
    if !upstream_url.starts_with("http://") && !upstream_url.starts_with("https://") {
        return ProbeOutcome {
            status: "http_error",
            error: Some("upstream_url must be http(s)://...".into()),
            tools: vec![],
            prompts: vec![],
            resources: vec![],
        };
    }

    // Each list call is a separate JSON-RPC POST so a server that doesn't
    // support one capability still surfaces the others. The per-call timeout
    // is capped so a caller can't pin an admin-api worker for minutes via a
    // slow upstream.
    let raw_timeout = u64::try_from(request_timeout_ms).unwrap_or(60_000);
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
    // One guarded client per probe — see `guarded_test_client`. A build
    // failure surfaces on the same path a handshake failure does.
    let (tools_res, prompts_res, resources_res) = match guarded_test_client() {
        Err(e) => (Err(e), Err(RpcError::quiet()), Err(RpcError::quiet())),
        Ok(http) => match mcp_rpc(&http, upstream_url, auth, &None, "initialize", init_params, timeout).await {
            // Handshake failed — surface it as the primary (tools/list) error;
            // the other two collapse to empty.
            Err(e) => (Err(e), Err(RpcError::quiet()), Err(RpcError::quiet())),
            Ok((_, session_id)) => {
                if session_id.is_some() {
                    mcp_notify(&http, upstream_url, auth, &session_id, "notifications/initialized", timeout).await;
                }
                let empty = serde_json::json!({});
                let tools = mcp_rpc(&http, upstream_url, auth, &session_id, "tools/list", empty.clone(), timeout).await.map(|(v, _)| v);
                let prompts = mcp_rpc(&http, upstream_url, auth, &session_id, "prompts/list", empty.clone(), timeout).await.map(|(v, _)| v);
                let resources = mcp_rpc(&http, upstream_url, auth, &session_id, "resources/list", empty, timeout).await.map(|(v, _)| v);
                (tools, prompts, resources)
            }
        },
    };

    // tools/list is the primary signal — if it failed at the HTTP or JSON-RPC
    // layer, surface that even if prompts/resources happen to succeed.
    // prompts/list and resources/list are best-effort: many servers don't
    // implement them.
    let (status, error, tools) = match &tools_res {
        Ok(v) => ("ok", None, extract_named(v, "tools", prefix)),
        Err(e) => (e.status(), Some(e.message.clone()), vec![]),
    };
    let prompts = prompts_res.as_ref().map(|v| extract_named(v, "prompts", prefix)).unwrap_or_default();
    let resources = resources_res.as_ref().map(extract_resources).unwrap_or_default();
    ProbeOutcome { status, error, tools, prompts, resources }
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

/// Why a test call failed, in the gateway's own words: an HTTP status or a
/// JSON-RPC error code, never text the upstream sent.
#[derive(Debug, Clone)]
struct RpcError {
    kind: RpcErrorKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcErrorKind {
    Http,
    Redirected,
    JsonRpc,
}

impl RpcError {
    fn http(method: &str, what: &str) -> Self {
        Self { kind: RpcErrorKind::Http, message: format!("{method}: {what}") }
    }
    /// The placeholder for a call never made (the handshake failed first).
    fn quiet() -> Self {
        Self { kind: RpcErrorKind::Http, message: String::new() }
    }
    fn status(&self) -> &'static str {
        match self.kind {
            RpcErrorKind::Http => "http_error",
            RpcErrorKind::Redirected => "redirected",
            RpcErrorKind::JsonRpc => "jsonrpc_error",
        }
    }
}

/// POST one JSON-RPC request over MCP streamable HTTP. Returns the parsed
/// response and any `Mcp-Session-Id` the server assigned. Sends the
/// spec-mandated `Accept: application/json, text/event-stream`, the upstream's
/// resolved headers, forwards the session id when set, and unwraps an
/// SSE-framed reply — the same transport the proxy speaks, so the test sees
/// what a real agent would.
async fn mcp_rpc(
    client: &reqwest::Client,
    upstream_url: &str,
    auth: &UpstreamAuth,
    session_id: &Option<String>,
    method: &str,
    params: Value,
    timeout: Duration,
) -> Result<(Value, Option<String>), RpcError> {
    // Defense-in-depth SSRF guard, layer 1: refuse an internal IP *literal*
    // before we connect. Admin write-time validation is the load-bearing layer
    // (see `routes/mcp.rs::validate_outbound_urls`); this catch covers rows
    // that might bypass the create/update path in future surfaces. Layer 2 —
    // the connect-time resolver that closes DNS rebinding — rides `client`,
    // which MUST be a guarded one (see `guarded_test_client`). IMDS is refused
    // by both regardless of the operator's egress posture.
    if let Err(e) = streamscope_mcp_auth::ssrf::check_url_for(upstream_url, super::mcp::MCP_EGRESS) {
        return Err(RpcError::http(method, &format!("upstream URL refused by SSRF guard: {e}")));
    }
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
    req = auth.apply(req);
    if let Some(sid) = session_id {
        req = req.header("Mcp-Session-Id", sid.as_str());
    }
    let resp = req.send().await.map_err(|e| {
        tracing::info!(%upstream_url, method, "portal mcp test: request failed: {e}");
        let what = if e.is_timeout() {
            "the server did not answer in time"
        } else {
            "could not reach the server"
        };
        RpcError::http(method, what)
    })?;
    let status = resp.status();
    if status.is_redirection() {
        return Err(RpcError {
            kind: RpcErrorKind::Redirected,
            message: format!("{method}: the server answered HTTP {status}, a redirect the gateway does not follow"),
        });
    }
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
    .map_err(|_| RpcError::http(method, "the server's reply could not be read"))?;
    if !status.is_success() {
        return Err(RpcError::http(method, &format!("HTTP {status}")));
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let json_str = if content_type.starts_with("text/event-stream") {
        parse_last_sse_event(&text)
            .ok_or_else(|| RpcError { kind: RpcErrorKind::JsonRpc, message: format!("{method}: empty SSE response") })?
    } else {
        text
    };
    let v: Value = serde_json::from_str(&json_str).map_err(|_| RpcError {
        kind: RpcErrorKind::JsonRpc,
        message: format!("{method}: the reply is not valid JSON"),
    })?;
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(Value::as_i64);
        let message = match code {
            Some(c) => format!("{method}: the server answered JSON-RPC error {c}"),
            None => format!("{method}: the server answered a JSON-RPC error"),
        };
        return Err(RpcError { kind: RpcErrorKind::JsonRpc, message });
    }
    Ok((v, resp_session))
}

/// The SSRF-guarded client every test call rides.
///
/// The URL is operator-supplied and reached on a portal user's request, so the
/// hostname-only pre-check in [`mcp_rpc`] is not sufficient on its own: only a
/// [`GuardedResolver`](streamscope_mcp_auth::ssrf::GuardedResolver)-backed
/// client validates the address DNS actually returns, at connect time.
///
/// It follows NO redirect: the request carries the upstream's declared
/// headers, and reqwest strips only `Authorization` and `Cookie` on a
/// cross-origin hop — a custom credential header would ride along to wherever
/// the 3xx points. A redirect is reported (`redirected`), never followed.
fn guarded_test_client() -> Result<reqwest::Client, RpcError> {
    streamscope_core::mcp::oauth_http::guarded_egress_builder(
        super::mcp::MCP_EGRESS,
        0,
        crate::custom_ca::current().as_deref(),
    )
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .map_err(|e| {
        tracing::error!("build guarded portal test client: {e}");
        RpcError::http("initialize", "the gateway could not prepare the call")
    })
}

/// The headers for one route's upstream, for this user, with no client: the
/// admin's values, the user's own, and the user's OAuth token on a per-user
/// OAuth upstream. `Err((status, message))` is a route result, not a failure
/// of the request.
async fn resolve_for_user(
    db: &mut TenantConn,
    user_id: Uuid,
    route: &RouteUpstreamRow,
) -> Result<Result<UpstreamAuth, (&'static str, String)>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let oauth = mcp_inputs::is_oauth(&route.auth_mode);
    let unavailable = || {
        Err((
            "unavailable",
            "this server is not fully set up — ask your administrator".to_string(),
        ))
    };
    let admin = mcp_inputs::decrypt_values(&route.encrypted_admin_inputs.0);
    if admin.len() != route.encrypted_admin_inputs.0.len() {
        return Ok(unavailable());
    }
    let user_ct: Option<sqlx::types::Json<HashMap<String, String>>> = sqlx::query_scalar(
        r#"SELECT encrypted_values FROM mcp_user_inputs
           WHERE tenant_id = $1 AND user_id = $2 AND upstream_server_id = $3"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(route.upstream_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal mcp test inputs lookup: {e}");
        ApiError::internal("failed to look up inputs")
    })?;
    let user = user_ct.map(|j| mcp_inputs::decrypt_values(&j.0)).unwrap_or_default();

    let values = InputValues { admin: Some(&admin), user: Some(&user), client: None };
    let mut auth = match hi::resolve(&route.remote, oauth, values) {
        Ok(auth) => auth,
        Err(ResolveError::Missing(m)) if !m.user.is_empty() => {
            return Ok(Err((
                "needs_connection",
                "fill in your values for this server under Connections first".to_string(),
            )));
        }
        Err(ResolveError::Missing(m)) if m.admin.is_empty() && !m.client.is_empty() => {
            return Ok(Err((
                "needs_client_header",
                format!("needs the client's header: {}", m.client.join(", ")),
            )));
        }
        Err(e) => {
            tracing::warn!(upstream = %route.upstream_id, "portal mcp test: headers unresolved: {e:?}");
            return Ok(unavailable());
        }
    };

    if oauth {
        // `encrypted_access_token` is BYTEA holding the UTF-8 ciphertext
        // (the store binds `.into_bytes()`); read it back as text with
        // `convert_from(..., 'UTF8')` — same as the edge-sync forwarder.
        let cred: Option<UserCredRow> = sqlx::query_as::<_, UserCredRow>(
            r#"SELECT convert_from(encrypted_access_token, 'UTF8') AS encrypted_access_token,
                      expires_at
               FROM mcp_user_credentials
               WHERE tenant_id = $1 AND user_id = $2 AND upstream_server_id = $3"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(route.upstream_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("portal mcp test cred lookup: {e}");
            ApiError::internal("failed to look up credential")
        })?;
        let connect_first = || {
            Err(("needs_connection", "no stored OAuth credential — connect first".to_string()))
        };
        let token = match cred {
            None => return Ok(connect_first()),
            // The proxy refreshes an expired access token transparently on
            // real calls; the test path doesn't, so a live probe with a stale
            // bearer would 401. Report `token_expired` — the connection is
            // fine, it just needs a reconnect to verify here.
            Some(c) if c.expires_at.is_some_and(|e| e <= chrono::Utc::now()) => {
                return Ok(Err((
                    "token_expired",
                    "OAuth token expired — reconnect to test here (real calls refresh it automatically)"
                        .to_string(),
                )));
            }
            Some(c) => match streamscope_core::crypto::get_encryption_key()
                .and_then(|key| streamscope_core::crypto::decrypt(&c.encrypted_access_token, &key).ok())
            {
                Some(t) => t,
                None => return Ok(connect_first()),
            },
        };
        if auth.push_bearer(&token).is_none() {
            return Ok(connect_first());
        }
    }
    Ok(Ok(auth))
}

/// Fire a JSON-RPC notification (no `id`, no reply) — used for
/// `notifications/initialized` after the handshake. Best-effort: any transport
/// error is ignored, since a server that doesn't need the notification still
/// answers the subsequent list calls.
async fn mcp_notify(
    client: &reqwest::Client,
    upstream_url: &str,
    auth: &UpstreamAuth,
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
    req = auth.apply(req);
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
pub(crate) struct InternalPreview {
    pub(crate) tools: Vec<PortalMcpTestEntry>,
    pub(crate) prompts: Vec<PortalMcpTestEntry>,
    pub(crate) resources: Vec<PortalMcpTestResource>,
    pub(crate) builtin_status: PortalMcpBuiltinStatus,
}

pub(crate) async fn preview_internal_upstream(
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
         WHERE name = $1 AND tenant_id = $2 AND built_in",
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
