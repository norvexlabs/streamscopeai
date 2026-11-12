//! MCP upstream OAuth endpoint discovery.
//!
//! When an operator adds an MCP upstream with `auth_mode = per_user_oauth`,
//! the gateway acts as the OAuth **client** toward that upstream. Per the MCP
//! authorization spec (2025-11-25) the client discovers the upstream's OAuth
//! endpoints rather than asking the operator to paste them: fetch the RFC 9728
//! protected-resource-metadata (PRM), read `authorization_servers`, then fetch
//! that issuer's RFC 8414 / OIDC authorization-server metadata and read the
//! authorization / token / revocation endpoints + scopes.
//!
//! This endpoint runs that chain on demand and returns the discovered values
//! for the operator to **review before saving** — it persists nothing. Servers
//! that expose no OAuth metadata (older, non-conformant) return a generic
//! failure and the operator enters the endpoints manually.
//!
//! **Keep it that way: do not cache a result, and do not refresh one on a
//! schedule.** The probe exists to answer "what does this server advertise
//! *now*", asked by an operator who is about to commit to the answer — so a
//! cache would serve a stale reply to the one click whose whole purpose is a
//! fresh one, and it is a hostile-influenced document, which means a cache is
//! also somewhere an upstream's past answer outlives the upstream's present
//! one. A scheduled refresh is worse: it would rewrite endpoints the operator
//! reviewed and approved, moving where users are sent to log in and where a
//! client secret is presented, with nobody watching. The endpoints are cheap to
//! re-probe on demand, which is the whole reason this can stay stateless.
//!
//! ## Security
//!
//! Discovery is a multi-hop fetch chain driven by **attacker-influenced** data:
//! the `resource_metadata` URL comes from the upstream's 401 header, and the
//! issuer comes from the upstream's PRM body. So every hop is guarded
//! independently — there is no single client that follows redirects across
//! hosts (that would re-open a DNS-rebinding window). Each fetch:
//!
//!   * runs the URL through [`resolve_and_pin_addrs_for`] (DNS
//!     pinned to vetted addresses; private/loopback/IMDS refused),
//!   * pins reqwest to those addresses with `resolve_to_addrs`,
//!   * refuses redirects (`Policy::none()`) — a 3xx is a discovery failure,
//!   * is HTTPS-only with a short per-hop timeout and a 64 KiB body cap.
//!
//! The whole chain runs under an overall deadline and a fixed probe budget, and
//! every failure mode collapses to one generic error code so the endpoint can't
//! be used to probe internal hosts by status/timing. Discovered endpoints are
//! themselves re-checked through the SSRF guard before being returned.

use streamscope_mcp_auth::ssrf::Egress;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::AdminState;
use crate::db::tenant::TenantConn;
use crate::middleware::AuditDiffSink;
use axum::Extension;

/// Per-hop connect + total timeout. Real metadata documents respond in well
/// under a second; the cap bounds a slow-loris upstream.
const HOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Overall budget for the whole discovery chain across all hops.
const OVERALL_DEADLINE: Duration = Duration::from_secs(15);
/// Response-body cap per probe (matches the CIMD fetcher). Metadata docs are a
/// few KB; this bounds parse cost on a hostile target.
const BODY_CAP: usize = 64 * 1024;
/// Upper bound on scopes echoed back from a hostile metadata document.
const MAX_SCOPES: usize = 64;
/// Upper bound on a single scope string echoed back.
const MAX_SCOPE_LEN: usize = 128;

#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscoverOauthRequest {
    /// The MCP upstream server URL (the same value as the upstream row's
    /// `upstream_url`). Discovery POSTs an `initialize` here to learn the
    /// protected-resource-metadata location.
    pub upstream_url: String,
    /// Optional explicit issuer URL. When supplied, the PRM step is skipped
    /// and authorization-server metadata is discovered directly from it — for
    /// servers that don't expose PRM but whose issuer the operator knows.
    #[serde(default)]
    pub issuer_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoverOauthResponse {
    /// The discovered (or operator-supplied) issuer URL.
    pub issuer_url: String,
    pub authorization_url: String,
    pub token_url: String,
    pub revocation_url: Option<String>,
    /// Scopes to request by default — the PRM `scopes_supported` when present,
    /// else the authorization-server `scopes_supported`.
    pub default_scopes: Vec<String>,
    /// Whether the authorization server advertises PKCE S256
    /// (`code_challenge_methods_supported` contains `S256`). The MCP spec
    /// requires clients to refuse a server without it; surfaced so the UI can
    /// warn rather than silently proceed.
    pub pkce_s256_supported: bool,
    /// True when the discovered issuer's registrable domain differs from the
    /// `upstream_url`'s. A conformant server's login lives on the same site;
    /// a mismatch (e.g. a `tools.example.com` server pointing login at
    /// `login.evil.com`) is the confused-deputy shape the MCP spec warns
    /// about, so the UI surfaces it as a prominent "verify this" warning
    /// before the operator saves.
    pub issuer_host_mismatch: bool,
    /// The RFC 7591 dynamic-client-registration endpoint, when the server
    /// advertises one *and* it passes the same guard the endpoints above do.
    ///
    /// `None` means the operator must create a client by hand — which is what
    /// most servers require (GitHub among them). The UI reads this to decide
    /// whether to offer registration at all, because the alternative is a
    /// button whose only possible outcome is an error after a full discovery
    /// round trip.
    ///
    /// The URL rather than a bare capability flag: registration is where a
    /// client secret is handed out, so which host would receive that request
    /// is worth showing the operator next to `issuer_host_mismatch`.
    pub registration_endpoint: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterOauthClientRequest {
    /// The MCP upstream server URL — the same value as the upstream row's
    /// `upstream_url`. Used to discover the authorization server (and thus its
    /// registration endpoint) when `issuer_url` is not supplied.
    pub upstream_url: String,
    /// Optional explicit issuer URL. When supplied, the PRM step is skipped and
    /// the authorization-server metadata is fetched directly from it.
    #[serde(default)]
    pub issuer_url: Option<String>,
    /// Scopes to record on the registered client (RFC 7591 `scope`, space-
    /// delimited). Defaults to none; many servers ignore it at registration.
    #[serde(default)]
    pub default_scopes: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterOauthClientResponse {
    /// The client identifier the authorization server issued — store as the
    /// upstream's OAuth client ID.
    pub client_id: String,
    /// The client secret, when the server issued a confidential client. Absent
    /// for public (PKCE-only) clients. Returned once for the operator to save;
    /// this endpoint persists nothing.
    pub client_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Lenient parse structs for REMOTE documents.
//
// The structs in `streamscope-mcp-auth::metadata` describe the documents we
// *serve* and mark many fields required (`scopes_supported`,
// `resource_signing_alg_values_supported`, …). Real upstream documents omit
// most of them (Notion's PRM carries only `resource` + `authorization_servers`
// + `bearer_methods_supported`), so parsing a remote doc into those structs
// would hard-fail. These mirror only what discovery needs, every field
// defaulted.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RemotePrm {
    #[serde(default)]
    authorization_servers: Vec<serde_json::Value>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteAsMetadata {
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    /// RFC 7591 dynamic client registration endpoint. Present only on servers
    /// that support DCR; absent for the many (e.g. GitHub) that require a
    /// manually-registered OAuth app.
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
}

fn discovery_failed() -> ApiError {
    // One generic error for every failure mode (SSRF refusal, connect refused,
    // timeout, 4xx/5xx, malformed JSON). Distinguishing them would let a caller
    // use this endpoint as an internal port/host scanner; the detail is logged
    // server-side only.
    ApiError::bad_request(
        "could not discover OAuth endpoints for this server — enter them manually",
    )
    .code(ApiErrorCode::McpUpstreamOauthDiscoveryFailed)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/upstream-servers/actions/discover-oauth",
    tag = "MCP Servers",
    request_body = DiscoverOauthRequest,
    responses(
        (status = 200, description = "Discovered OAuth endpoints", body = DiscoverOauthResponse),
        (status = 400, description = "Discovery failed — enter endpoints manually", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn discover_upstream_oauth(
    State(_state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(diff): Extension<AuditDiffSink>,
    Json(body): Json<DiscoverOauthRequest>,
) -> Result<Json<DiscoverOauthResponse>, ApiError> {
    let egress = super::mcp::MCP_EGRESS;
    // Fresh trusted-CA read: the cache is process-local and only the replica
    // that handled the import refreshes it, so an outbound TLS hop on a
    // sibling replica would otherwise use a stale trust set.
    crate::custom_ca::refresh_from_conn(db.conn()).await;

    let result = tokio::time::timeout(
        OVERALL_DEADLINE,
        run_discovery(&body.upstream_url, body.issuer_url.as_deref(), egress),
    )
    .await;

    let resp = match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            tracing::warn!(upstream = %body.upstream_url, "oauth discovery failed: {e}");
            return Err(discovery_failed());
        }
        Err(_elapsed) => {
            tracing::warn!(upstream = %body.upstream_url, "oauth discovery exceeded deadline");
            return Err(discovery_failed());
        }
    };

    // Record what was discovered (the dangerous output, not just the probed
    // URL) on the audit row. These are public OAuth URLs — nothing to redact.
    diff.set(
        serde_json::Value::Null,
        serde_json::json!({
            "upstream_url": body.upstream_url,
            "issuer_url": resp.issuer_url,
            "authorization_url": resp.authorization_url,
            "token_url": resp.token_url,
            "revocation_url": resp.revocation_url,
            "issuer_host_mismatch": resp.issuer_host_mismatch,
        }),
    );

    Ok(Json(resp))
}

/// Discover `upstream_url`'s OAuth endpoints (RFC 9728 → 8414) under the same
/// deadline and with the same single generic refusal as the discover action —
/// for a catalog adopt whose entry carries no OAuth hints. The caller refreshes
/// the trusted-CA cache first.
pub(crate) async fn discover_oauth_endpoints(upstream_url: &str) -> Result<DiscoverOauthResponse, ApiError> {
    match tokio::time::timeout(
        OVERALL_DEADLINE,
        run_discovery(upstream_url, None, super::mcp::MCP_EGRESS),
    )
    .await
    {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => {
            tracing::warn!(upstream = %upstream_url, "oauth discovery failed: {e}");
            Err(discovery_failed())
        }
        Err(_elapsed) => {
            tracing::warn!(upstream = %upstream_url, "oauth discovery exceeded deadline");
            Err(discovery_failed())
        }
    }
}

/// RFC 7591 client name presented to upstream authorization servers.
const DCR_CLIENT_NAME: &str = "Streamscope MCP Gateway";

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/upstream-servers/actions/register-oauth-client",
    tag = "MCP Servers",
    request_body = RegisterOauthClientRequest,
    responses(
        (status = 200, description = "Registered an OAuth client via RFC 7591 DCR", body = RegisterOauthClientResponse),
        (status = 400, description = "Registration unsupported or failed — register the client manually", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn register_upstream_oauth_client(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(diff): Extension<AuditDiffSink>,
    Json(body): Json<RegisterOauthClientRequest>,
) -> Result<Json<RegisterOauthClientResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Fresh trusted-CA read: the cache is process-local and only the replica
    // that handled the import refreshes it, so an outbound TLS hop on a
    // sibling replica would otherwise use a stale trust set.
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    // The redirect URI is server-derived (it rides the tenant's resolved API
    // origin), never taken from the client: it must match the portal OAuth
    // callback, and a split-vhost deploy's API origin differs from the origin
    // the browser sees.
    let redirect_uri = super::settings::load_inherited_defaults(&state.db, tenant_id)
        .await?
        .mcp_oauth_redirect_uri()
        .ok_or_else(|| {
            ApiError::bad_request(
                "configure your tenant's public URLs (Settings → Defaults) before \
                 registering an OAuth client",
            )
            .code(ApiErrorCode::McpUpstreamDcrFailed)
        })?;

    let egress = super::mcp::MCP_EGRESS;

    let result = tokio::time::timeout(
        OVERALL_DEADLINE,
        run_registration(&body, &redirect_uri, egress),
    )
    .await;

    let resp = match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(RegistrationError::Unsupported)) => {
            return Err(ApiError::bad_request(
                "this provider does not support automatic client registration — \
                 register an OAuth app manually and enter the Client ID and Secret",
            )
            .code(ApiErrorCode::McpUpstreamDcrUnsupported));
        }
        Ok(Err(RegistrationError::Failed(e))) => {
            tracing::warn!(upstream = %body.upstream_url, "oauth client registration failed: {e}");
            return Err(registration_failed());
        }
        Err(_elapsed) => {
            tracing::warn!(upstream = %body.upstream_url, "oauth client registration exceeded deadline");
            return Err(registration_failed());
        }
    };

    // Record the registration on the audit row: the issued client_id and the
    // redirect URI (both public values). NEVER the client_secret.
    diff.set(
        serde_json::Value::Null,
        serde_json::json!({
            "upstream_url": body.upstream_url,
            "redirect_uri": redirect_uri,
            "client_id": resp.client_id,
        }),
    );

    Ok(Json(resp))
}

fn registration_failed() -> ApiError {
    ApiError::bad_request(
        "could not register an OAuth client with this server — register one manually \
         and enter the Client ID and Secret",
    )
    .code(ApiErrorCode::McpUpstreamDcrFailed)
}

/// Outcome of a failed registration attempt: a clean "this IdP advertises no
/// registration endpoint" (actionable — register manually) vs every other
/// failure (collapsed to one opaque code, like discovery).
enum RegistrationError {
    Unsupported,
    Failed(String),
}

impl From<DiscoveryError> for RegistrationError {
    fn from(e: DiscoveryError) -> Self {
        RegistrationError::Failed(e.0)
    }
}

/// RFC 7591 registration response — only the two fields we persist; everything
/// else (client_id_issued_at, registration_access_token, …) is ignored.
#[derive(Debug, Deserialize)]
struct DcrResponse {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Discover the upstream's authorization server, read its RFC 7591
/// `registration_endpoint`, and POST a registration request through the SSRF
/// guard. Returns the issued client credentials. The whole path reuses the
/// discovery hops (issuer → AS metadata) and per-hop guard so a hostile target
/// can't pivot to internal hosts.
async fn run_registration(
    req: &RegisterOauthClientRequest,
    redirect_uri: &str,
    egress: Egress,
) -> Result<RegisterOauthClientResponse, RegistrationError> {
    let issuer = match req.issuer_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(explicit) => explicit.trim_end_matches('/').to_string(),
        None => discover_issuer(&req.upstream_url, egress).await?.0,
    };
    let asm = discover_as_metadata(&issuer, egress).await?;
    let registration_endpoint = asm
        .registration_endpoint
        .filter(|s| !s.is_empty())
        .ok_or(RegistrationError::Unsupported)?;

    let scope = req
        .default_scopes
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut reg_body = serde_json::json!({
        "client_name": DCR_CLIENT_NAME,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        // MCP 2026-07-28 (SEP-837) requires clients to state this at
        // registration. `web` is the honest value and the only one that
        // matches our redirect: an OpenID Connect authorization server
        // constrains a `native` client to a custom scheme or loopback, and
        // ours is the gateway's own HTTPS callback. Leaving it to the
        // server's default is what the SEP set out to stop — the default is
        // not the same on every implementation, and the ones that guess
        // `native` reject the registration for a reason the operator cannot
        // see from the error.
        "application_type": "web",
    });
    if !scope.is_empty() {
        reg_body["scope"] = serde_json::Value::String(scope);
    }

    // post_json_capped runs the https gate + SSRF guard on the (attacker-
    // influenced) registration endpoint before connecting.
    let bytes = post_json_capped(&registration_endpoint, &reg_body, egress).await?;
    let reg: DcrResponse = serde_json::from_slice(&bytes)
        .map_err(|e| RegistrationError::Failed(format!("registration response parse: {e}")))?;

    let client_id = reg.client_id.trim().to_string();
    if client_id.is_empty() {
        return Err(RegistrationError::Failed("registration response missing client_id".into()));
    }
    let client_secret =
        reg.client_secret.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    Ok(RegisterOauthClientResponse { client_id, client_secret })
}

/// Internal error type — kept private; the handler maps every variant to the
/// single public [`discovery_failed`] code.
#[derive(Debug)]
pub(crate) struct DiscoveryError(String);

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! derr {
    ($($arg:tt)*) => { DiscoveryError(format!($($arg)*)) };
}

/// Gate one endpoint read out of a remote metadata document before anything
/// downstream — a later fetch, or the operator's own form — can act on it.
///
/// The document is written by the upstream, so every URL in it is
/// attacker-influenced. HTTPS is required in the default posture; an operator
/// may run an http IdP on a private address it listed, so plain http passes
/// only to such an address.
async fn check_discovered_endpoint(ep: &str, egress: Egress) -> Result<(), DiscoveryError> {
    streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(ep, egress)
        .await
        .map_err(|e| match e {
            streamscope_mcp_auth::SsrfError::PlainHttp => derr!("discovered endpoint is not https: {ep}"),
            e => derr!("discovered endpoint rejected by SSRF guard: {e}"),
        })?;
    Ok(())
}

async fn run_discovery(
    upstream_url: &str,
    issuer_url: Option<&str>,
    egress: Egress,
) -> Result<DiscoverOauthResponse, DiscoveryError> {
    // --- Step 1: locate the issuer (RFC 9728 PRM), unless supplied. ---
    let (issuer, prm_scopes) = match issuer_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(explicit) => (explicit.trim_end_matches('/').to_string(), Vec::new()),
        None => discover_issuer(upstream_url, egress).await?,
    };

    // --- Step 2: authorization-server metadata (RFC 8414 / OIDC). ---
    let asm = discover_as_metadata(&issuer, egress).await?;

    let authorization_url = asm
        .authorization_endpoint
        .filter(|s| !s.is_empty())
        .ok_or_else(|| derr!("AS metadata missing authorization_endpoint"))?;
    let token_url = asm
        .token_endpoint
        .filter(|s| !s.is_empty())
        .ok_or_else(|| derr!("AS metadata missing token_endpoint"))?;
    let revocation_url = asm.revocation_endpoint.filter(|s| !s.is_empty());

    // Re-check every discovered endpoint through the SSRF guard so an
    // internal-resolving authorization/token/revocation endpoint never reaches
    // the operator's form, and reject non-https.
    for ep in [Some(&authorization_url), Some(&token_url), revocation_url.as_ref()]
        .into_iter()
        .flatten()
    {
        check_discovered_endpoint(ep, egress).await?;
    }

    // Dynamic registration is optional, so an endpoint we refuse to reach
    // demotes the capability instead of failing the chain: that server is one
    // the operator registers with by hand, which is exactly what `None` tells
    // the UI. Failing outright would withhold the endpoints we *did* discover
    // over a capability they were never going to use.
    let registration_endpoint = match asm.registration_endpoint.filter(|s| !s.is_empty()) {
        Some(ep) => match check_discovered_endpoint(&ep, egress).await {
            Ok(()) => Some(ep),
            Err(e) => {
                tracing::warn!("discovery: ignoring advertised registration_endpoint: {e}");
                None
            }
        },
        None => None,
    };

    let pkce_s256_supported = asm
        .code_challenge_methods_supported
        .iter()
        .any(|m| m.eq_ignore_ascii_case("S256"));

    let default_scopes = clamp_scopes(if !prm_scopes.is_empty() {
        prm_scopes
    } else {
        asm.scopes_supported
    });

    let issuer_host_mismatch = registrable_domain(upstream_url) != registrable_domain(&issuer);

    Ok(DiscoverOauthResponse {
        issuer_url: issuer,
        authorization_url,
        token_url,
        revocation_url,
        default_scopes,
        pkce_s256_supported,
        issuer_host_mismatch,
        registration_endpoint,
    })
}

/// Step 1: POST `initialize` to the upstream, read the 401
/// `WWW-Authenticate: resource_metadata=` pointer, fetch the PRM, and return
/// the first authorization server + its advertised scopes. Falls back to the
/// well-known PRM locations (path-style then root) when no header is present.
async fn discover_issuer(
    upstream_url: &str,
    egress: Egress,
) -> Result<(String, Vec<String>), DiscoveryError> {
    let init_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "streamscope-gateway", "version": "1.0" }
        }
    });

    // Probe the upstream; a 401/403 may carry the resource_metadata pointer.
    let mut prm_candidates: Vec<String> = Vec::new();
    if let Ok(www) = www_authenticate_for(upstream_url, &init_body, egress).await
        && let Some(p) = parse_resource_metadata(&www)
    {
        prm_candidates.push(p);
    }
    // Well-known fallbacks per RFC 9728: path-style then root.
    let parsed = url::Url::parse(upstream_url).map_err(|e| derr!("bad upstream_url: {e}"))?;
    let host = parsed.host_str().ok_or_else(|| derr!("upstream_url has no host"))?;
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let base = format!("{}://{host}{port}", parsed.scheme());
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        prm_candidates.push(format!("{base}/.well-known/oauth-protected-resource{path}"));
    }
    prm_candidates.push(format!("{base}/.well-known/oauth-protected-resource"));

    for cand in prm_candidates {
        let Ok(bytes) = fetch_json(&cand, egress).await else {
            continue;
        };
        let Ok(prm) = serde_json::from_slice::<RemotePrm>(&bytes) else {
            continue;
        };
        if let Some(issuer) = first_authorization_server(&prm.authorization_servers) {
            return Ok((issuer, prm.scopes_supported));
        }
    }
    Err(derr!("no protected-resource-metadata with authorization_servers"))
}

/// Step 2: try the spec-ordered well-known authorization-server metadata URLs
/// for `issuer` (path-aware), returning the first that parses.
async fn discover_as_metadata(
    issuer: &str,
    egress: Egress,
) -> Result<RemoteAsMetadata, DiscoveryError> {
    let parsed = url::Url::parse(issuer).map_err(|e| derr!("bad issuer url: {e}"))?;
    let host = parsed.host_str().ok_or_else(|| derr!("issuer has no host"))?;
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let base = format!("{}://{host}{port}", parsed.scheme());
    let path = parsed.path().trim_end_matches('/');

    // RFC 8414 § 3.1 + OIDC interop ordering. With a path component, the
    // well-known segment is *inserted* before the path; OIDC also allows
    // *appending* it.
    let candidates: Vec<String> = if path.is_empty() {
        vec![
            format!("{base}/.well-known/oauth-authorization-server"),
            format!("{base}/.well-known/openid-configuration"),
        ]
    } else {
        vec![
            format!("{base}/.well-known/oauth-authorization-server{path}"),
            format!("{base}/.well-known/openid-configuration{path}"),
            format!("{base}{path}/.well-known/openid-configuration"),
        ]
    };

    for cand in candidates {
        let Ok(bytes) = fetch_json(&cand, egress).await else {
            continue;
        };
        if let Ok(asm) = serde_json::from_slice::<RemoteAsMetadata>(&bytes)
            && asm.authorization_endpoint.is_some()
            && asm.token_endpoint.is_some()
        {
            return Ok(asm);
        }
    }
    Err(derr!("no authorization-server metadata at issuer"))
}

/// POST `body` to `url` (SSRF-guarded, no redirects) and return the
/// `WWW-Authenticate` header value if the response is a 401/403 carrying one.
async fn www_authenticate_for(
    url: &str,
    body: &serde_json::Value,
    egress: Egress,
) -> Result<String, DiscoveryError> {
    let (parsed, host, addrs) =
        streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(url, egress)
            .await
            .map_err(|e| match e {
                streamscope_mcp_auth::SsrfError::PlainHttp => derr!("probe target is not https: {url}"),
                e => derr!("ssrf: {e}"),
            })?;
    let client = build_client(&host, &addrs)?;
    let resp = client
        .post(parsed.as_str())
        .header("Accept", "application/json, text/event-stream")
        .json(body)
        .send()
        .await
        .map_err(|e| derr!("initialize probe failed: {e}"))?;
    let status = resp.status();
    if (status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN)
        && let Some(h) = resp.headers().get(axum::http::header::WWW_AUTHENTICATE)
        && let Ok(s) = h.to_str()
    {
        return Ok(s.to_string());
    }
    Err(derr!("no WWW-Authenticate on probe ({status})"))
}

/// GET `url` (SSRF-guarded, no redirects, body-capped) and return the bytes,
/// erroring on any non-2xx / oversize / transport failure.
pub(crate) async fn fetch_json(url: &str, egress: Egress) -> Result<Vec<u8>, DiscoveryError> {
    // HTTPS, except to a listed private address: plaintext metadata on a
    // trusted network.
    let (parsed, host, addrs) =
        streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(url, egress)
            .await
            .map_err(|e| match e {
                streamscope_mcp_auth::SsrfError::PlainHttp => derr!("metadata fetch is not https: {url}"),
                e => derr!("ssrf: {e}"),
            })?;
    let client = build_client(&host, &addrs)?;
    let resp = client
        .get(parsed.as_str())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| derr!("fetch failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(derr!("non-success status {}", resp.status()));
    }
    read_capped_body(resp).await
}

/// POST `body` as JSON to `url` (SSRF-guarded, no redirects, body-capped) and
/// return the response bytes, erroring on any non-2xx / oversize / transport
/// failure. RFC 7591 success is 201 Created; some servers reply 200 — both are
/// `is_success`.
async fn post_json_capped(
    url: &str,
    body: &serde_json::Value,
    egress: Egress,
) -> Result<Vec<u8>, DiscoveryError> {
    let (parsed, host, addrs) =
        streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(url, egress)
            .await
            .map_err(|e| match e {
                streamscope_mcp_auth::SsrfError::PlainHttp => derr!("registration target is not https: {url}"),
                e => derr!("ssrf: {e}"),
            })?;
    let client = build_client(&host, &addrs)?;
    let resp = client
        .post(parsed.as_str())
        .header("Accept", "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| derr!("registration POST failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(derr!("non-success status {}", resp.status()));
    }
    read_capped_body(resp).await
}

/// Stream the response body, aborting the moment the cumulative length crosses
/// [`BODY_CAP`] — a hostile upstream can't make the gateway buffer a large body
/// before the cap fires (dropping `resp` cancels the connection). Mirrors
/// `streamscope_core::web::fetch::read_capped_body`.
async fn read_capped_body(resp: reqwest::Response) -> Result<Vec<u8>, DiscoveryError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut stream = resp;
    while let Some(chunk) = stream.chunk().await.map_err(|e| derr!("body read: {e}"))? {
        if buf.len() + chunk.len() > BODY_CAP {
            return Err(derr!("body exceeds {BODY_CAP} cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Build a per-hop reqwest client pinned to the vetted addresses, refusing
/// redirects (the pin only covers `host`) and honoring a custom CA bundle.
fn build_client(
    host: &str,
    addrs: &[std::net::SocketAddr],
) -> Result<reqwest::Client, DiscoveryError> {
    streamscope_core::tls::add_custom_roots(
        reqwest::Client::builder()
            .user_agent("streamscope-gateway-oauth-discovery/1.0")
            .connect_timeout(HOP_TIMEOUT)
            .timeout(HOP_TIMEOUT)
            .resolve_to_addrs(host, addrs)
            .redirect(reqwest::redirect::Policy::none()),
        crate::custom_ca::current().as_deref(),
    )
    .build()
    .map_err(|e| derr!("client build: {e}"))
}

/// Parse `resource_metadata="<url>"` out of a `WWW-Authenticate` header value.
fn parse_resource_metadata(www: &str) -> Option<String> {
    let marker = "resource_metadata=";
    let rest = &www[www.find(marker)? + marker.len()..];
    let rest = rest.trim_start_matches('"');
    let end = rest.find(['"', ',']).unwrap_or(rest.len());
    let url = rest[..end].trim().trim_matches('"');
    if url.starts_with("https://") || url.starts_with("http://") {
        Some(url.to_string())
    } else {
        None
    }
}

/// RFC 9728 says `authorization_servers` is an array of strings; some servers
/// emit `{issuer|url: ...}` objects. Accept both; return the first non-empty
/// issuer (trailing slash trimmed).
fn first_authorization_server(servers: &[serde_json::Value]) -> Option<String> {
    let raw = servers.first()?;
    let s = match raw {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(o) => o
            .get("issuer")
            .or_else(|| o.get("url"))
            .and_then(|v| v.as_str())
            .map(str::to_string)?,
        _ => return None,
    };
    let s = s.trim().trim_end_matches('/');
    (!s.is_empty()).then(|| s.to_string())
}

/// Clamp the scope list echoed back from a hostile metadata document — bound
/// the count and each string length, drop empties.
fn clamp_scopes(scopes: Vec<String>) -> Vec<String> {
    scopes
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(|mut s| {
            if s.len() > MAX_SCOPE_LEN {
                s.truncate(s.floor_char_boundary(MAX_SCOPE_LEN));
            }
            s
        })
        .take(MAX_SCOPES)
        .collect()
}

/// Registrable-domain heuristic for the issuer/upstream host-relation warning.
/// Returns the last two labels of the host (`mcp.linear.app` → `linear.app`).
/// A heuristic, not a public-suffix lookup — it can't tell `co.uk` apart, so it
/// drives a UI *warning* on the reviewed save path, never a hard security gate.
fn registrable_domain(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        Some(host)
    } else {
        Some(labels[labels.len() - 2..].join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_resource_metadata_header() {
        let www = r#"Bearer realm="OAuth", error="invalid_token", resource_metadata="https://mcp.sentry.dev/.well-known/oauth-protected-resource/mcp""#;
        assert_eq!(
            parse_resource_metadata(www).as_deref(),
            Some("https://mcp.sentry.dev/.well-known/oauth-protected-resource/mcp")
        );
    }

    #[test]
    fn resource_metadata_absent() {
        assert_eq!(parse_resource_metadata(r#"Bearer realm="OAuth""#), None);
    }

    #[test]
    fn first_auth_server_string_and_object() {
        assert_eq!(
            first_authorization_server(&[serde_json::json!("https://issuer.example.com/")]),
            Some("https://issuer.example.com".to_string())
        );
        assert_eq!(
            first_authorization_server(&[serde_json::json!({"issuer": "https://i.example.com"})]),
            Some("https://i.example.com".to_string())
        );
        assert_eq!(first_authorization_server(&[]), None);
    }

    #[test]
    fn registrable_domain_matches_subdomains() {
        assert_eq!(registrable_domain("https://mcp.linear.app/mcp"), registrable_domain("https://account.linear.app"));
        assert_eq!(registrable_domain("https://mcp.stripe.com"), registrable_domain("https://access.stripe.com/mcp"));
        assert_ne!(registrable_domain("https://tools.legit.com/mcp"), registrable_domain("https://login.evil.com"));
    }

    #[tokio::test]
    async fn a_plaintext_endpoint_is_refused_before_any_lookup() {
        // With nothing listable the https gate runs ahead of the resolver, so
        // this is decided without touching DNS — which is also why it can be
        // asserted here at all.
        // `registration_endpoint` rides this same check, and a plaintext one is
        // what turns "the server offers registration" into "register by hand":
        // the code that steals an authorization code off a plaintext hop is the
        // same code that would steal the client secret off a plaintext one.
        let refused = check_discovered_endpoint("http://idp.example.com/token", Egress::PublicOnly)
            .await
            .expect_err("a plaintext endpoint must not be handed back to the operator");
        // Pin WHY it refused: an incidental resolver failure would satisfy a bare
        // `is_err`, and would keep passing if the scheme check were deleted.
        assert!(refused.to_string().contains("not https"), "{refused}");
    }

    #[test]
    fn clamp_scopes_bounds_count_and_len() {
        let many: Vec<String> = (0..200).map(|i| format!("scope{i}")).collect();
        assert_eq!(clamp_scopes(many).len(), MAX_SCOPES);
        let long = vec!["x".repeat(500)];
        assert!(clamp_scopes(long)[0].len() <= MAX_SCOPE_LEN);
        assert!(clamp_scopes(vec!["  ".to_string(), "read".to_string()]).len() == 1);
    }
}
