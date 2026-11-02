//! Outbound JSON-RPC client to upstream MCP servers.
//!
//! Two transports are supported:
//! - **Streamable HTTP** (`transport='streamable_http'`) — the modern MCP
//!   spec. POST to a single endpoint; responses arrive as either
//!   `application/json` (one-shot) or `text/event-stream` (multiplexed
//!   server-initiated events + final result). Implemented inline below.
//! - **Legacy SSE** (`transport='sse'`) — the pre-Streamable-HTTP
//!   protocol. Long-lived `GET /sse` channel + `POST /messages` correlated
//!   by JSON-RPC `id`. Implemented in [`super::legacy_sse`]; the entry
//!   functions below dispatch on `upstream.transport` and call into the
//!   per-(tenant, upstream, agent_session) `LegacySseSession`.
//!
//! `auth_mode = ServiceAccount` is honoured: the proxy decrypts the
//! per-upstream `encrypted_credential` once per request and stamps it as
//! `Authorization: Bearer <token>`. `PerUserOauth` and `Byot` are also
//! supported by the [`super::handler::call_cached`] dispatcher.
//!
//! The MCP Streamable HTTP spec supports two response shapes:
//! - `Content-Type: application/json` — single-shot JSON body.
//! - `Content-Type: text/event-stream` — SSE stream (used for tools that
//!   stream progress or for server-initiated requests).
//!
//! Non-streaming methods only forward `application/json` responses. SSE streams
//! from upstream are converted to a single combined response using the final
//! `data:` event before the `[DONE]` marker. Streaming pass-through for
//! `tools/call` lives in the multiplex bridge.

use streamscope_mcp_auth::egress::{Cached, Surface, egress_slot};
use streamscope_mcp_auth::ssrf::Egress;
use std::time::Duration;

use streamscope_core::config::mcp::{McpAuthMode, McpUpstreamServer};

use super::jsonrpc::{JsonRpcRequest, JsonRpcResponse};

/// Outcome of a `tools/call`-style upstream invocation that may stream.
/// The proxy decides between the two variants based on the upstream
/// response's `Content-Type`:
///
/// - `application/json` → [`UpstreamReply::Single`] — single JSON-RPC body,
///   identical to today's flow. Forwarded as a one-shot HTTP response.
/// - `text/event-stream` → [`UpstreamReply::Streaming`] — SSE body. The proxy
///   forwards the body to the client as `text/event-stream` and pipes events
///   through the multiplex bridge for per-event audit/log classification.
pub enum UpstreamReply {
    Single(JsonRpcResponse, Option<String>),
    Streaming(reqwest::Response, Option<String>),
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("auth mode {0:?} not yet supported")]
    AuthModeUnsupported(McpAuthMode),
    #[error("transport not supported: {0}")]
    TransportUnsupported(&'static str),
    #[error("upstream HTTP error: {status} body={body}")]
    Http {
        status: u16,
        body: String,
        /// The JSON-RPC `error.code` the upstream put inside that non-2xx
        /// body, when it put one there at all.
        ///
        /// Captured from the raw bytes **before** [`redact_upstream_body`]
        /// caps them, because the era probe classifies an upstream by exactly
        /// this code and the redacted text is a log line, not a data channel:
        /// it truncates at 200 characters on whatever boundary falls there,
        /// so re-parsing it would work until an upstream's `data` grew.
        jsonrpc_code: Option<i32>,
        /// The `error.data.requiredCapabilities` object the upstream named,
        /// when it named one — captured from the same pre-redaction bytes and
        /// for the same reason.
        ///
        /// This is the ONLY part of an upstream's `data` the gateway keeps.
        /// The rest is the upstream's own prose, which is never forwarded to a
        /// client; this field is not prose but the client's own missing
        /// capability declaration handed back, and § Client Capability
        /// Constraints makes it the thing a `-32021` exists to say.
        required_capabilities: Option<serde_json::Value>,
    },
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("upstream returned an empty body")]
    EmptyBody,
    /// Upstream response body crossed the gateway size cap mid-stream.
    /// Surfaces as JSON-RPC `-32003`; protects the proxy from a malicious or
    /// compromised upstream returning an oversized body.
    #[error("upstream response exceeded {limit}-byte cap")]
    ResponseTooLarge { limit: u64 },
    #[error("upstream returned a malformed SSE stream")]
    BadSse,
    /// The upstream answered a one-shot request by asking the *client* for
    /// input (`sampling/createMessage`, `elicitation/create`, `roots/list`)
    /// rather than returning a result.
    ///
    /// It is a distinct variant rather than a `BadSse` because it is not a
    /// broken upstream: it is an upstream politely waiting on a reply this
    /// code path has no stream left to send. The caller decides what that
    /// means — a modern client can be handed the question as an
    /// `InputRequiredResult`; a legacy one gets an honest error instead of an
    /// empty response body.
    #[error("upstream asked the client for input instead of answering")]
    ServerInitiatedRequest(serde_json::Value),
    /// Service-account upstream is missing or has an undecodable credential.
    /// Surfaces as JSON-RPC `-32500` to the client; admin must (re)set it.
    #[error("service-account credential missing or undecryptable")]
    CredentialUnavailable,
    /// Per-user OAuth upstream — the calling user has not yet connected.
    /// Surfaces as JSON-RPC `-32501`; the agent should direct the user to
    /// the portal connections page.
    #[error("per-user oauth: user has not authorized this upstream")]
    UserCredentialMissing,
    /// Per-user OAuth — stored credential expired and refresh failed
    /// (refresh_token revoked, IdP rejected `invalid_grant`, etc.).
    /// Surfaces as JSON-RPC `-32502`; the user must reconnect.
    #[error("per-user oauth: stored credential expired and refresh failed")]
    UserCredentialExpired,
    /// Per-user OAuth — refresh attempt failed for a transient reason
    /// (network, IdP 5xx). Surfaces as JSON-RPC `-32503`; agent may
    /// retry. The stored credential remains usable.
    #[error("per-user oauth: refresh attempt failed: {0}")]
    UserOauthRefreshFailed(String),
    /// Admin hasn't finished configuring the OAuth client (issuer URL,
    /// client_id, token URL or client_secret missing). Surfaces as
    /// JSON-RPC `-32504`; operator must finish configuration.
    #[error("oauth client not fully configured: {0}")]
    OauthClientNotConfigured(&'static str),
    /// Outbound URL points at an internal/loopback range. Defense-in-depth
    /// — admin write-time validation is the load-bearing guard. Surfaces
    /// as JSON-RPC `-32505`; operator must fix the URL.
    #[error("outbound URL refused by SSRF guard: {0}")]
    SsrfRefused(String),
    /// Legacy SSE upstream — the long-lived `GET /sse` channel terminated
    /// while a request was in flight, or the upstream never emitted a
    /// matching JSON-RPC response within the per-call timeout. Surfaces
    /// as JSON-RPC `-32507`; the agent should retry.
    #[error("legacy SSE upstream session lost: {0}")]
    SessionLost(String),
}

// The handler resolves all auth_mode → bearer translations in
// `handler::call_cached` (so cache hits, single-flight refresh, and per-user
// credential lookup live in one place). The standalone `call()` wrapper
// has been folded into `call_with_bearer`.

/// Cap an upstream error body before stuffing it into `UpstreamError::Http`.
/// Two protections, both mandatory under BYOT:
///   1. Strip the literal bearer when the caller knows it — BYOT forwards
///      a per-user PAT verbatim to the upstream, and a misbehaving upstream
///      may echo it back ("invalid token <pat>").
///   2. Strip generic `Bearer <token>` patterns the upstream may quote at us
///      (4xx echo of the request's own auth header is common).
///   3. Cap at 200 chars on a UTF-8 boundary so operator logs don't carry
///      kilobytes of upstream HTML / stack traces.
///
/// Operators still see status code, fragment of body, and method on the
/// `tracing::warn!` line — enough to triage without leaking the secret.
const UPSTREAM_BODY_CAP: usize = 200;

pub(crate) use streamscope_core::mcp::MCP_MAX_RESPONSE_BYTES;

/// Read an upstream response body, aborting with
/// [`UpstreamError::ResponseTooLarge`] the moment the cumulative length
/// crosses `cap` — the gateway never buffers more than `cap` bytes regardless
/// of what the upstream advertises in `Content-Length`.
///
/// Thin adapter over the shared [`read_body_capped`](streamscope_core::http_body::read_body_capped)
/// so the MCP surface's errors stay in [`UpstreamError`]; the bounding itself
/// is the one implementation every egress path uses.
pub(crate) async fn read_capped_response(
    resp: reqwest::Response,
    cap: u64,
) -> Result<bytes::Bytes, UpstreamError> {
    use streamscope_core::http_body::CappedReadError;
    streamscope_core::http_body::read_body_capped(resp, cap)
        .await
        .map_err(|e| match e {
            CappedReadError::Oversized { limit_bytes } => {
                UpstreamError::ResponseTooLarge { limit: limit_bytes }
            }
            CappedReadError::Transport(e) => UpstreamError::Transport(e),
        })
}

/// The JSON-RPC `error.code` inside an upstream's response bytes, if the body
/// is a JSON-RPC error at all.
///
/// Used on the non-2xx path, where the *protocol* answer often rides an HTTP
/// failure status: a modern server refusing a legacy `MCP-Protocol-Version`
/// answers `400` with `-32022` in the body, and that code is the only thing
/// that distinguishes it from a server which simply does not route the URL.
pub(crate) fn jsonrpc_error_code(bytes: &[u8]) -> Option<i32> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("error")?
        .get("code")?
        .as_i64()
        .map(|c| c as i32)
}

/// The `error.data.requiredCapabilities` object inside an upstream's response
/// bytes, if it named one.
///
/// Read from the raw bytes for the same reason as [`jsonrpc_error_code`]: the
/// redacted body is truncated and is a log line, not a data channel.
///
/// Only a JSON **object** is accepted. § Client Capability Constraints defines
/// the field as a `ClientCapabilities` — an object keyed by the missing
/// capability, e.g. `{"sampling": {}}` — so an upstream answering with an
/// array of names is not producing the shape a client can read, and relaying
/// it would put our name on that mistake.
pub(crate) fn jsonrpc_required_capabilities(bytes: &[u8]) -> Option<serde_json::Value> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("error")?
        .get("data")?
        .get("requiredCapabilities")?
        .clone();
    value.is_object().then_some(value)
}

pub(crate) fn redact_upstream_body(raw: &str, bearer: Option<&str>) -> String {
    // Pre-truncate the input to a generous bound BEFORE we allocate. Operator
    // logs don't need a 5 MB upstream HTML page, and `String::replace` would
    // otherwise copy the full body once per redaction pass.
    const PRE_TRUNCATE: usize = 16 * 1024;
    let pre_cut = raw
        .floor_char_boundary(raw.len().min(PRE_TRUNCATE))
        .min(raw.len());
    let mut s = raw[..pre_cut].to_string();
    if let Some(token) = bearer
        && !token.is_empty()
    {
        s = s.replace(token, "<REDACTED>");
    }
    // Strip `Bearer <opaque>` (and the case-flipped sibling). The pattern is
    // simple enough that a regex would be overkill; we walk the string once.
    s = strip_bearer_pattern(&s);
    if s.len() > UPSTREAM_BODY_CAP {
        let cut = s
            .as_str()
            .floor_char_boundary(UPSTREAM_BODY_CAP)
            .min(s.len());
        s.truncate(cut);
        s.push_str("…[truncated]");
    }
    s
}

fn strip_bearer_pattern(input: &str) -> String {
    // We look for the literal "Bearer " (case-insensitive) followed by one or
    // more non-whitespace chars and replace the token with `<REDACTED>`.
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 7 <= bytes.len() && bytes[i..i + 7].eq_ignore_ascii_case(b"Bearer ") {
            out.push_str(&input[i..i + 7]);
            i += 7;
            // Consume the token (non-whitespace, non-quote run).
            let mut j = i;
            while j < bytes.len() {
                let c = bytes[j];
                if c == b' '
                    || c == b'\n'
                    || c == b'\r'
                    || c == b'\t'
                    || c == b'"'
                    || c == b'\''
                {
                    break;
                }
                j += 1;
            }
            if j > i {
                out.push_str("<REDACTED>");
                i = j;
                continue;
            }
        }
        // SAFETY: We only step by char boundaries below; the bearer match is
        // ASCII so byte-stepping is safe through it.
        let ch = input[i..]
            .chars()
            .next()
            .expect("non-empty remaining slice");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Max redirect hops tolerated on an external MCP egress call. MCP transports
/// answer directly, so this absorbs an incidental 3xx rather than enabling a
/// feature; each hop is re-vetted by [`GuardedResolver`](streamscope_mcp_auth::ssrf::GuardedResolver)
/// (hostname targets) and the redirect policy below (IP-literal targets).
const MCP_MAX_REDIRECTS: usize = 3;

/// Build a reqwest client that enforces the SSRF guard on **every** connection:
/// the resolved IP is validated at DNS time (closing the DNS-rebinding window
/// the hostname-only [`check_url_for`](streamscope_mcp_auth::ssrf::check_url_for)
/// pre-check leaves open), IP-literal redirect targets are re-vetted, and IMDS
/// is refused whatever the egress list says. Used for all *external* MCP egress
/// (upstream calls, per-user OAuth token refresh, legacy-SSE POST) and, via
/// [`guarded_stream_client`], for its long-lived streams. The loopback sampling path keeps
/// the unguarded shared client.
///
/// `streaming` selects the deadline shape: a request/response client gets one
/// total timeout, while a client that carries long-lived SSE gets a generous
/// wall-clock ceiling plus an idle read bound — a single short total deadline
/// would kill a legitimately long stream mid-flight.
fn build_guarded_client(egress: Egress, streaming: bool) -> reqwest::Client {
    // The guard itself (resolver + redirect re-vetting + trusted roots) is
    // shared with admin-api's upstream OAuth hop, so there is one definition
    // of what "guarded MCP egress" means. Only the deadline shape and pool
    // sizing are local.
    with_deadlines(
        streamscope_core::mcp::oauth_http::guarded_egress_builder(
            egress,
            MCP_MAX_REDIRECTS,
            streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
        ),
        streaming,
    )
    .build()
    .expect("build guarded mcp http client")
}

/// The pooled client for an https A2A agent: the `a2a` guard's resolver, and
/// no redirect followed — a hop to another host would carry the agent's
/// credential header with it (reqwest strips only its own auth headers across
/// hosts); a 3xx reaches the caller as the agent's answer. Rebuilt when the
/// `a2a` list changes. `streaming` picks the deadline shape.
pub(crate) fn guarded_agent_client(streaming: bool) -> Result<reqwest::Client, reqwest::Error> {
    static SLOTS: [Cached<reqwest::Client>; 2] = [const { Cached::new() }; 2];
    let egress = crate::a2a::upstream::A2A_EGRESS;
    SLOTS[usize::from(streaming)].get_or_try_build(egress, || {
        // The shared guard; a later `redirect` replaces its policy.
        with_deadlines(
            streamscope_core::mcp::oauth_http::guarded_egress_builder(
                egress,
                0,
                streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
            )
            .redirect(reqwest::redirect::Policy::none()),
            streaming,
        )
        .build()
    })
}

/// A one-call client for a plain-http destination, connecting only to the
/// `addrs` the guard vetted for `host` (no lookup of its own, so the name
/// cannot be rebound between the check and the connection) and following no
/// redirect. Built per call; a plain-http destination has no TLS session to
/// pool.
pub(crate) fn pinned_plain_http_client(
    host: &str,
    addrs: &[std::net::SocketAddr],
    streaming: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    with_deadlines(
        // No environment proxy: one would resolve the name itself and undo the pin.
        reqwest::Client::builder()
            .no_proxy()
            .resolve_to_addrs(host, addrs)
            .redirect(reqwest::redirect::Policy::none()),
        streaming,
    )
    .build()
}

/// The deadline shape and pool sizing of a guarded client.
fn with_deadlines(builder: reqwest::ClientBuilder, streaming: bool) -> reqwest::ClientBuilder {
    let s = crate::settings::proxy_settings();
    let mut builder = builder.pool_max_idle_per_host(8);
    if streaming {
        // 0 means "no bound" on either knob. reqwest reads a zero Duration as
        // an immediate deadline, so an operator asking for unlimited would
        // otherwise kill every stream on contact.
        if s.a2a_stream_timeout_secs > 0 {
            builder = builder.timeout(Duration::from_secs(s.a2a_stream_timeout_secs));
        }
        if s.a2a_stream_idle_timeout_secs > 0 {
            builder = builder.read_timeout(Duration::from_secs(s.a2a_stream_idle_timeout_secs));
        }
        builder
    } else {
        builder.timeout(Duration::from_secs(s.mcp_http_client_timeout_secs))
    }
}

/// What MCP egress (upstream calls, per-user OAuth token refresh, legacy-SSE
/// POST, notification listeners) may reach: an internal address only when the
/// platform's `mcp` egress list lists it — a deployment-level decision, never
/// a per-tenant one. IMDS stays refused whatever the list says.
pub(crate) const MCP_EGRESS: Egress = Egress::Surface(Surface::Mcp);

/// One process-cached client per egress (each surface, and public-only), so
/// egress reuses pooled connections instead of rebuilding a client per call.
/// The list is read at resolve time, and a list change rebuilds the client —
/// its pooled connections were opened under the old lists.
type ClientSlots = [Cached<reqwest::Client>; Surface::ALL.len() + 1];

fn cached(slots: &'static ClientSlots, egress: Egress, streaming: bool) -> reqwest::Client {
    slots[egress_slot(egress)].get_or_build(egress, || build_guarded_client(egress, streaming))
}

/// The guarded request/response client for `egress`.
pub(crate) fn guarded_upstream_client(egress: Egress) -> reqwest::Client {
    static SLOTS: ClientSlots = [const { Cached::new() }; Surface::ALL.len() + 1];
    cached(&SLOTS, egress, false)
}

/// The same SSRF-guarded egress, with the deadline shape a long-lived SSE
/// stream needs (ceiling + idle bound instead of one short total timeout).
/// Used by the MCP notification listener and the legacy-SSE drain; a
/// request/response call MUST keep using
/// [`guarded_upstream_client`], whose total timeout is the correct bound there.
pub(crate) fn guarded_stream_client(egress: Egress) -> reqwest::Client {
    static SLOTS: ClientSlots = [const { Cached::new() }; Surface::ALL.len() + 1];
    cached(&SLOTS, egress, true)
}

/// Stamp the MCP transport headers on an outbound upstream request.
///
/// Three headers, each a client-side obligation this gateway owes as the MCP
/// *client* of its upstreams:
///
/// - `MCP-Protocol-Version` — REQUIRED of clients from `2025-06-18` onwards on
///   every request after `initialize`. `None` is passed only for the
///   `initialize` call itself, which by definition precedes negotiation.
/// - `Mcp-Method` / `Mcp-Name` — REQUIRED by `2026-07-28`, and inert to an
///   older upstream, which ignores unrecognised field names per RFC 9110.
///   They are rebuilt from the request we are actually sending, never relayed
///   from the client: virtualization has by now stripped the namespace prefix
///   off `params.name` and decoded `stsmcp://` URIs, so the caller's own
///   header would name something this body does not contain — which a modern
///   upstream MUST reject with `-32020`.
///
/// Sending the mirrored headers cannot be mistaken for speaking the modern
/// era: a dual-era server selects its era from the version header and the
/// modern `_meta` envelope, and this request carries a legacy version and no
/// such envelope.
fn stamp_outbound_mcp_headers(
    mut builder: reqwest::RequestBuilder,
    request: &JsonRpcRequest,
    protocol_version: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(version) = protocol_version.filter(|v| !v.is_empty()) {
        builder = builder.header("MCP-Protocol-Version", version);
    }
    for (name, value) in crate::mcp::modern::outbound_transport_headers(request) {
        builder = builder.header(name, value);
    }
    builder
}

/// One round-trip JSON-RPC call with an explicit bearer token.
///
/// Used by per-user OAuth: the handler resolves a per-(user, upstream)
/// access token (refreshing if needed) and passes it here. The caller is
/// responsible for credential resolution; this function only stamps the
/// header and forwards the body.
///
/// Streamable HTTP only. Legacy SSE upstreams are dispatched through
/// `legacy_sse::LegacySseSessionMap` in [`super::handler::call_cached`];
/// this entry remains transport-checked so an accidental config-drift call
/// fails loudly rather than silently going wrong.
pub async fn call_with_bearer(
    upstream: &McpUpstreamServer,
    bearer: Option<String>,
    request: &JsonRpcRequest,
    mcp_session_id: Option<&str>,
    protocol_version: Option<&str>,
) -> Result<(JsonRpcResponse, Option<String>), UpstreamError> {
    if !matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::StreamableHttp
    ) {
        return Err(UpstreamError::TransportUnsupported(
            "legacy SSE must be dispatched through LegacySseSessionMap",
        ));
    }

    // Fast-fail on an IP-literal internal `upstream_url`; the guarded client
    // additionally pins the resolved IP at DNS time (closing DNS-rebinding) and
    // re-vets redirect hops, so a hostname that resolves internal is refused at
    // connect rather than receiving the (operator- or user-owned) bearer.
    if let Err(e) = streamscope_mcp_auth::ssrf::check_url_for(
        &upstream.upstream_url,
        MCP_EGRESS,
    ) {
        return Err(UpstreamError::SsrfRefused(e.to_string()));
    }
    let client = guarded_upstream_client(MCP_EGRESS);

    let body = serde_json::to_vec(request)?;
    let mut builder = client
        .post(&upstream.upstream_url)
        .header("Content-Type", "application/json")
        // The MCP Streamable HTTP spec mandates Accept: application/json,
        // text/event-stream so the server can choose either shape.
        .header("Accept", "application/json, text/event-stream")
        .timeout(Duration::from_millis(upstream.request_timeout_ms.max(1) as u64))
        .body(body);
    builder = stamp_outbound_mcp_headers(builder, request, protocol_version);
    if let Some(sid) = mcp_session_id {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    if let Some(token) = &bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }

    let resp = builder.send().await?;
    let status = resp.status();
    let response_session_id = resp
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

    if !status.is_success() {
        let raw_bytes = read_capped_response(resp, MCP_MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_default();
        let raw = String::from_utf8_lossy(&raw_bytes);
        let redacted = redact_upstream_body(&raw, bearer.as_deref());
        return Err(UpstreamError::Http {
            status: status.as_u16(),
            body: redacted,
            jsonrpc_code: jsonrpc_error_code(&raw_bytes),
            required_capabilities: jsonrpc_required_capabilities(&raw_bytes),
        });
    }

    let bytes = read_capped_response(resp, MCP_MAX_RESPONSE_BYTES).await?;
    if bytes.is_empty() {
        return Err(UpstreamError::EmptyBody);
    }

    let parsed = if content_type.starts_with("text/event-stream") {
        match parse_sse_outcome(&bytes) {
            SseOutcome::Response(payload) => serde_json::from_str::<JsonRpcResponse>(&payload)?,
            SseOutcome::ServerRequest(v) => {
                return Err(UpstreamError::ServerInitiatedRequest(v));
            }
            SseOutcome::Nothing => return Err(UpstreamError::BadSse),
        }
    } else {
        serde_json::from_slice::<JsonRpcResponse>(&bytes)?
    };

    Ok((parsed, response_session_id))
}

/// Like [`call_with_bearer`] but defers the body read so an
/// `text/event-stream` response can be streamed verbatim to the downstream
/// client without buffering the whole stream in memory.
///
/// Returns either:
/// - [`UpstreamReply::Single`] when the upstream replied with a one-shot
///   JSON body (the non-streaming flow — every method other than `tools/call`).
/// - [`UpstreamReply::Streaming`] when the upstream replied with SSE — the
///   handler attaches the [`reqwest::Response`] to an Axum streaming body,
///   wires the multiplex bridge, and returns it to the client.
pub async fn call_with_bearer_for_streaming(
    upstream: &McpUpstreamServer,
    bearer: Option<String>,
    request: &JsonRpcRequest,
    mcp_session_id: Option<&str>,
    protocol_version: Option<&str>,
) -> Result<UpstreamReply, UpstreamError> {
    if !matches!(
        upstream.transport,
        streamscope_core::config::mcp::McpTransport::StreamableHttp
    ) {
        return Err(UpstreamError::TransportUnsupported(
            "legacy SSE must be dispatched through LegacySseSessionMap",
        ));
    }
    if let Err(e) = streamscope_mcp_auth::ssrf::check_url_for(
        &upstream.upstream_url,
        MCP_EGRESS,
    ) {
        return Err(UpstreamError::SsrfRefused(e.to_string()));
    }
    let client = guarded_upstream_client(MCP_EGRESS);

    let body = serde_json::to_vec(request)?;
    let mut builder = client
        .post(&upstream.upstream_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .timeout(Duration::from_millis(upstream.request_timeout_ms.max(1) as u64))
        .body(body);
    builder = stamp_outbound_mcp_headers(builder, request, protocol_version);
    if let Some(sid) = mcp_session_id {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    if let Some(token) = &bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }

    let resp = builder.send().await?;
    let status = resp.status();
    let response_session_id = resp
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

    if !status.is_success() {
        let raw_bytes = read_capped_response(resp, MCP_MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_default();
        let raw = String::from_utf8_lossy(&raw_bytes);
        let redacted = redact_upstream_body(&raw, bearer.as_deref());
        return Err(UpstreamError::Http {
            status: status.as_u16(),
            body: redacted,
            jsonrpc_code: jsonrpc_error_code(&raw_bytes),
            required_capabilities: jsonrpc_required_capabilities(&raw_bytes),
        });
    }

    if content_type.starts_with("text/event-stream") {
        return Ok(UpstreamReply::Streaming(resp, response_session_id));
    }

    let bytes = read_capped_response(resp, MCP_MAX_RESPONSE_BYTES).await?;
    if bytes.is_empty() {
        return Err(UpstreamError::EmptyBody);
    }
    let parsed: JsonRpcResponse = serde_json::from_slice(&bytes)?;
    Ok(UpstreamReply::Single(parsed, response_session_id))
}

/// Fire-and-forget POST used to forward a client's JSON-RPC
/// **response** (the agent's reply to a server-initiated `sampling` /
/// `elicitation`) back to the upstream that originated the request. Returns
/// the upstream's HTTP status code so the audit row records what happened.
///
/// The body is the raw `JsonRpcResponse` shape the client already sent on
/// the wire — the proxy is a transparent forwarder for the response payload.
pub async fn forward_client_response(
    upstream_url: &str,
    bearer: Option<&str>,
    body: &serde_json::Value,
    mcp_session_id: &str,
    request_timeout_ms: i32,
) -> Result<u16, UpstreamError> {
    if let Err(e) =
        streamscope_mcp_auth::ssrf::check_url_for(upstream_url, MCP_EGRESS)
    {
        return Err(UpstreamError::SsrfRefused(e.to_string()));
    }
    let client = guarded_upstream_client(MCP_EGRESS);
    let serialized = serde_json::to_vec(body)?;
    let mut builder = client
        .post(upstream_url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Session-Id", mcp_session_id)
        .timeout(Duration::from_millis(request_timeout_ms.max(1) as u64))
        .body(serialized);
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let resp = builder.send().await?;
    let status = resp.status();
    if !status.is_success() && status.as_u16() != 202 {
        // The upstream MAY return 4xx if the original request id is unknown
        // or already answered; capture the body so the audit row preserves it.
        let raw_bytes = read_capped_response(resp, MCP_MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_default();
        let raw = String::from_utf8_lossy(&raw_bytes);
        let redacted = redact_upstream_body(&raw, bearer);
        return Err(UpstreamError::Http {
            status: status.as_u16(),
            body: redacted,
            jsonrpc_code: jsonrpc_error_code(&raw_bytes),
            required_capabilities: jsonrpc_required_capabilities(&raw_bytes),
        });
    }
    Ok(status.as_u16())
}

/// What a one-shot read of a Streamable-HTTP SSE body actually found.
pub enum SseOutcome {
    /// The JSON-RPC response to the request we sent.
    Response(String),
    /// The upstream asked the *client* something instead of answering — a
    /// `sampling/createMessage`, `elicitation/create` or `roots/list`. It is
    /// now waiting on a reply that this one-shot code path cannot give it.
    ServerRequest(serde_json::Value),
    /// Nothing usable: no `data:` payload, or only notifications.
    Nothing,
}

/// Pull the JSON-RPC response out of a Streamable-HTTP SSE body.
///
/// **The response is not simply the last event.** An MCP server may interleave
/// `notifications/progress` and `notifications/message` with the result, and
/// nothing requires the result to come last — an upstream that emits its
/// result and then one more log line would otherwise have that log line
/// returned to the caller as the response, silently, with the real answer
/// discarded. So the scan selects the last payload that is *shaped* like a
/// JSON-RPC response: an `id`, and no `method`.
///
/// A server-initiated request is reported separately rather than folded into
/// `Nothing`, because the two need different answers: one is a broken
/// upstream, the other is an upstream politely waiting for input on a stream
/// this code path has already consumed.
fn parse_sse_outcome(bytes: &[u8]) -> SseOutcome {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return SseOutcome::Nothing;
    };
    let mut payloads: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for raw_line in text.lines() {
        if raw_line.is_empty() {
            if let Some(payload) = current.take() {
                payloads.push(payload);
            }
            continue;
        }
        if let Some(rest) = raw_line.strip_prefix("data:") {
            let trimmed = rest.trim_start_matches(' ');
            if trimmed.starts_with('[') && trimmed.contains("DONE") {
                continue;
            }
            current = Some(trimmed.to_string());
        }
    }
    if let Some(payload) = current {
        payloads.push(payload);
    }

    let mut server_request: Option<serde_json::Value> = None;
    for payload in payloads.iter().rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        let has_method = value.get("method").is_some();
        let has_id = value.get("id").is_some();
        if !has_method && has_id {
            return SseOutcome::Response(payload.clone());
        }
        // A server-initiated *request* (method + id). A notification has a
        // method and no id and is simply skipped.
        if has_method && has_id && server_request.is_none() {
            server_request = Some(value);
        }
    }
    match server_request {
        Some(v) => SseOutcome::ServerRequest(v),
        None => SseOutcome::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_of(bytes: &[u8]) -> Option<String> {
        match parse_sse_outcome(bytes) {
            SseOutcome::Response(p) => Some(p),
            _ => None,
        }
    }

    #[test]
    fn parse_sse_returns_the_response_event() {
        let raw = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        assert_eq!(
            response_of(raw).unwrap(),
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
        );
    }

    #[test]
    fn parse_sse_skips_done_marker() {
        let raw = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1}\n\ndata: [DONE]\n\n";
        assert!(response_of(raw).unwrap().contains("\"id\":1"));
    }

    #[test]
    fn parse_sse_returns_nothing_when_empty() {
        assert!(response_of(b"").is_none());
    }

    /// Nothing requires the result to be the LAST event: an upstream may emit
    /// its response and then one more log line. Taking the last payload would
    /// hand that notification back as the response and discard the real
    /// answer — silently, since a notification deserializes into
    /// `JsonRpcResponse` with both `result` and `error` absent.
    #[test]
    fn parse_sse_ignores_notifications_that_trail_the_response() {
        let raw = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[]}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n\n"
        )
        .as_bytes();
        let payload = response_of(raw).expect("the response must survive a trailing notification");
        assert!(payload.contains("\"id\":7"));
        assert!(payload.contains("content"));
    }

    /// A stream carrying only notifications has no response in it. Reporting
    /// `Nothing` is what turns that into a real error rather than a
    /// successful-looking reply with no result and no error.
    #[test]
    fn parse_sse_reports_nothing_when_only_notifications_arrived() {
        let raw = b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n";
        assert!(matches!(parse_sse_outcome(raw), SseOutcome::Nothing));
    }

    /// An upstream that asks the client for input is not a broken upstream,
    /// and must be distinguishable from one: a modern client can be handed
    /// the question, a legacy one gets an honest error.
    #[test]
    fn parse_sse_separates_a_server_initiated_request_from_a_broken_stream() {
        let raw = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"id\":\"e1\",\"method\":\"elicitation/create\",",
            "\"params\":{\"mode\":\"form\",\"message\":\"who?\"}}\n\n"
        )
        .as_bytes();
        match parse_sse_outcome(raw) {
            SseOutcome::ServerRequest(v) => {
                assert_eq!(v["method"], "elicitation/create");
                assert_eq!(v["id"], "e1");
            }
            _ => panic!("a server-initiated request must not read as a broken stream"),
        }
    }

    /// ...but a response present alongside one still wins: the upstream
    /// answered, and the question was incidental.
    #[test]
    fn parse_sse_prefers_a_response_over_a_server_request() {
        let raw = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"id\":\"e1\",\"method\":\"elicitation/create\",\"params\":{}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n"
        )
        .as_bytes();
        assert!(response_of(raw).unwrap().contains("\"id\":9"));
    }

    #[test]
    fn redact_strips_known_bearer() {
        let body = r#"{"error":"invalid_token","detail":"saw Bearer ghp_secrettoken123 reject"}"#;
        let out = redact_upstream_body(body, Some("ghp_secrettoken123"));
        assert!(!out.contains("ghp_secrettoken123"));
        assert!(out.contains("<REDACTED>"));
    }

    #[test]
    fn redact_strips_generic_bearer_pattern() {
        let body = "401: bearer xyz123abc rejected by IdP";
        let out = redact_upstream_body(body, None);
        assert!(!out.contains("xyz123abc"));
        assert!(out.contains("<REDACTED>"));
    }

    #[test]
    fn redact_caps_long_bodies() {
        let body = "x".repeat(5000);
        let out = redact_upstream_body(&body, None);
        // Bound includes the truncation marker; the prefix is the cap.
        assert!(out.starts_with(&"x".repeat(UPSTREAM_BODY_CAP)));
        assert!(out.ends_with("…[truncated]"));
    }

    #[test]
    fn redact_short_body_passes_through() {
        let out = redact_upstream_body("not found", None);
        assert_eq!(out, "not found");
    }

    #[test]
    fn redact_handles_utf8_boundary_at_cap() {
        let mut body = "a".repeat(UPSTREAM_BODY_CAP - 1);
        body.push('é'); // 2-byte char straddling the cap when truncating
        body.push_str("xxxx");
        let out = redact_upstream_body(&body, None);
        // Should not panic; truncation must respect char boundaries.
        assert!(out.ends_with("…[truncated]"));
    }

    /// § Client Capability Constraints defines `requiredCapabilities` as a
    /// `ClientCapabilities` — an object keyed by the missing capability. An
    /// upstream answering with an array of names is not producing the shape a
    /// client reads, and relaying it would put the gateway's name on that
    /// mistake, so only an object is captured.
    #[test]
    fn only_an_object_is_taken_as_required_capabilities() {
        let object = br#"{"error":{"code":-32021,"data":{"requiredCapabilities":{"sampling":{}}}}}"#;
        assert_eq!(
            jsonrpc_required_capabilities(object),
            Some(serde_json::json!({ "sampling": {} }))
        );

        for rejected in [
            // The array the spec text explicitly calls out as wrong.
            &br#"{"error":{"code":-32021,"data":{"requiredCapabilities":["sampling"]}}}"#[..],
            // Named nothing at all.
            &br#"{"error":{"code":-32021,"data":{"detail":"nope"}}}"#[..],
            // No `data`, no `error`, not JSON.
            &br#"{"error":{"code":-32021}}"#[..],
            &br#"{"result":{}}"#[..],
            &b"<html>gateway timeout</html>"[..],
        ] {
            assert_eq!(
                jsonrpc_required_capabilities(rejected),
                None,
                "{}",
                String::from_utf8_lossy(rejected)
            );
        }
    }
}
