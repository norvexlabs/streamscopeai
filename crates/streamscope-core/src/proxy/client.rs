//! Upstream HTTP client with connection pooling and retry.
//!
//! Wraps `reqwest::Client` with configurable pool sizes, timeouts, and
//! exponential backoff retry for transient errors (429, 500, 502, 503).
//! Sets protocol-appropriate headers (Anthropic version, Beta features)
//! and handles streaming vs. non-streaming response collection.

use streamscope_mcp_auth::egress::Surface;
use streamscope_mcp_auth::ssrf::{check_url_for, Egress, SsrfError};
use std::time::Duration;

use axum::http::HeaderMap;
use bytes::Bytes;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use crate::api::sse::ApiVersion;
use crate::config::upstream_transport::UpstreamTransport;
use crate::error::AppError;
use crate::settings::core_settings;

/// The `anthropic-version` every request to an Anthropic-protocol endpoint must
/// carry — forwarded calls, MCP sampling, and admin-side model discovery alike.
/// One constant because a request that omits it is refused, and a split value
/// would leave one surface pinned to a revision the others have moved off.
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Client request headers every forward copies upstream. An ALLOWlist, so
/// gateway-internal identity (x-app-id, x-session-id, the inline-path
/// x-client-ip / x-authenticated-*) and engine control headers a client could
/// use to jump the queue (vLLM's `X-Vllm-Priority`, `X-data-parallel-rank`)
/// never reach a provider.
const FORWARDED_CLIENT_HEADERS: &[&str] = &["x-request-id", "openai-organization"];

/// Where an upstream request goes, and how it is carried there.
///
/// The three fields travel together by construction: a URL without its transport
/// would be addressed with the wrong path prefix, and a credential without its
/// transport would be sent in the wrong header. Build one with
/// [`UpstreamTarget::endpoint`](super::routing::UpstreamTarget::endpoint) rather
/// than assembling the parts at a call site.
#[derive(Clone, Copy)]
pub struct UpstreamEndpoint<'a> {
    /// The server's base URL, as configured.
    pub url: &'a str,
    /// The stored credential — an API key, or (for `azure_openai_entra`) the
    /// client-credentials document a token is minted from.
    pub api_key: &'a str,
    /// How the request is addressed and authenticated.
    pub transport: UpstreamTransport,
}

/// `api_key` is a live credential — and on the Entra transport it is the whole
/// client-credentials document, `client_secret` included — so it is redacted by
/// hand rather than derived. The struct is `Copy` and threads through every
/// forward path, which is exactly how one stray `tracing::debug!(?endpoint)`
/// would write a secret to the operator log.
impl std::fmt::Debug for UpstreamEndpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamEndpoint")
            .field("url", &self.url)
            .field("api_key", &"<redacted>")
            .field("transport", &self.transport)
            .finish()
    }
}

impl UpstreamEndpoint<'_> {
    /// The full URL for a canonical upstream path.
    fn url_for(&self, canonical_path: &str) -> String {
        self.transport.upstream_url(self.url, canonical_path)
    }

    /// The credential header a request to this endpoint carries with no BYOK
    /// override — the header an admin-side probe must reproduce exactly, so a
    /// liveness check or a model discovery is authenticated the way real traffic
    /// is. `None` means the header is protocol-decided (see
    /// [`UpstreamClient::forward`]).
    ///
    /// For a minting transport this performs the token exchange, which is the
    /// most valuable thing a probe can report on such a server: a credential
    /// document that cannot mint is otherwise invisible until traffic runs.
    pub async fn stored_credential_header(
        &self,
    ) -> Result<Option<(&'static str, String)>, AppError> {
        self.credential_header(None).await
    }

    /// [`Self::stored_credential_header`], with a token endpoint's refusal of a
    /// minting transport's credential told apart from every other failure — for
    /// the admin write path's check, which must not call an outage a bad key.
    pub async fn stored_credential_header_classified(
        &self,
    ) -> Result<Option<(&'static str, String)>, super::minted_token::MintFailure> {
        self.credential_header_classified(None).await
    }

    /// The credential header this transport names for itself, or `None` when the
    /// header is protocol-decided (the default transport — see [`UpstreamClient::forward`]).
    ///
    /// A BYOK request carries the client's own credential straight through: as a
    /// bearer token when it arrived as one (an Entra token the client minted),
    /// otherwise in the transport's own credential header. A minting transport
    /// cannot be a pass-through (refused at write time), so it never takes that
    /// branch.
    ///
    /// The match below is exhaustive on purpose: a transport added later must
    /// state what it sends here rather than inheriting the raw-credential arm,
    /// which for a minting transport would put the whole stored document —
    /// secret included — in a header.
    async fn credential_header(
        &self,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<Option<(&'static str, String)>, AppError> {
        self.credential_header_classified(auth_override).await.map_err(AppError::from)
    }

    async fn credential_header_classified(
        &self,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<Option<(&'static str, String)>, super::minted_token::MintFailure> {
        let Some(header) = self.transport.raw_credential_header() else {
            return Ok(None);
        };

        if let Some(fwd) = auth_override {
            let name = if fwd.header_value.starts_with("Bearer ") { "authorization" } else { header };
            return Ok(Some((name, fwd.header_value.clone())));
        }
        // A minting transport presents a short-lived bearer token; the stored
        // credential is the document it is minted from and must never be sent.
        match self.transport {
            // Protocol-decided — `raw_credential_header` already returned `None`
            // for these, so this arm exists only to keep the match exhaustive.
            UpstreamTransport::Default | UpstreamTransport::AwsBedrock => Ok(None),
            UpstreamTransport::AzureOpenAi => Ok(Some((header, self.api_key.to_string()))),
            UpstreamTransport::AzureOpenAiEntra => {
                let token = super::azure_entra::access_token(self.api_key).await?;
                Ok(Some(("authorization", format!("Bearer {token}"))))
            }
            UpstreamTransport::GoogleVertex => {
                let token = super::google_sa::access_token(self.api_key).await?;
                Ok(Some(("authorization", format!("Bearer {token}"))))
            }
        }
    }
}

/// The longest wait this gateway will spend INSIDE a request honouring an
/// upstream's hint. A retry sleeps on the caller's own clock, so a generous
/// bound is not generosity: two hints of twenty seconds would add forty to a
/// request whose client has long since given up, and the fallback target the
/// alias was given for exactly this case would never be reached. Past this, the
/// hint is taken as "not soon" and the attempt ends so the caller can spill.
const MAX_HONOURED_RETRY_AFTER: Duration = Duration::from_secs(5);

/// `Retry-After` as the HTTP spec defines it: delay-seconds, or an HTTP date.
/// A header that is neither is no instruction at all, so the ordinary backoff
/// applies.
pub fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?.trim().to_string();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    // The date form: chrono already parses RFC 2822 and RFC 3339, which covers
    // what providers actually send; anything else leaves the ordinary backoff in
    // place rather than guessing.
    let when = chrono::DateTime::parse_from_rfc2822(&raw)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&raw))
        .ok()?;
    (when.with_timezone(&chrono::Utc) - chrono::Utc::now()).to_std().ok()
}

/// Returns true if the HTTP status code is retryable (transient upstream error).
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503)
}

/// How far a backoff may stray from its nominal value, either way. Every edge
/// replica that saw the same upstream fail would otherwise retry it on the same
/// beat, and a recovering engine meets them all at once.
const RETRY_JITTER: f64 = 0.2;

/// What a retry waits before `attempt` (≥ 1), or `None` when the upstream asked
/// for longer than [`MAX_HONOURED_RETRY_AFTER`] — the attempt then ends so the
/// caller can spill or fail over. Jittered by `unit` (in `[0, 1)`) either way:
/// the gateway's own backoff by ±[`RETRY_JITTER`], an upstream's `Retry-After`
/// upward only, so it is never shortened — every replica told "two seconds"
/// would otherwise return on the same beat, the herd the jitter is for.
fn retry_delay(attempt: u32, base_ms: u64, asked: Option<Duration>, unit: f64) -> Option<Duration> {
    if asked.is_some_and(|a| a > MAX_HONOURED_RETRY_AFTER) {
        return None;
    }
    let unit = unit.clamp(0.0, 1.0);
    let nominal = base_ms.saturating_mul(1u64.checked_shl(attempt.saturating_sub(1)).unwrap_or(u64::MAX));
    let backoff = Duration::from_millis((nominal as f64 * (1.0 - RETRY_JITTER + 2.0 * RETRY_JITTER * unit)) as u64);
    // The ask's jitter stays under the cap: the cap bounds how long a header
    // can park a request, jitter included.
    Some(asked.map_or(backoff, |a| backoff.max(a.mul_f64(1.0 + RETRY_JITTER * unit).min(MAX_HONOURED_RETRY_AFTER).max(a))))
}

/// Cap for buffering an upstream *error* body. Only its message is ever
/// surfaced, so buffering more than this is pointless and a hostile upstream
/// returning a giant error body must not OOM the edge.
const MAX_ERROR_BODY_BYTES: u64 = 64 * 1024;

/// How long an error answer's body may take to arrive. A streaming request has
/// no total deadline, and an error framed as a stream can simply never end — so
/// without this bound the retry, the failover to the next target and the audit
/// row would all wait on it forever. An error body is small and immediate; one
/// that is neither is abandoned, not awaited.
const ERROR_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Best-effort read of a bounded upstream error body as text. Any failure —
/// transport, the body exceeding [`MAX_ERROR_BODY_BYTES`], or it not arriving
/// within [`ERROR_BODY_READ_TIMEOUT`] — falls back to a fixed message.
async fn read_error_body(resp: reqwest::Response) -> String {
    let read = crate::http_body::read_body_capped(resp, MAX_ERROR_BODY_BYTES);
    match tokio::time::timeout(ERROR_BODY_READ_TIMEOUT, read).await {
        Ok(Ok(b)) => String::from_utf8_lossy(&b).into_owned(),
        Ok(Err(_)) | Err(_) => "upstream error".to_string(),
    }
}

/// Percent-encode set for a single URL path segment. Encodes every character
/// that could break out of the `{model}` segment in the Gemini upstream URL —
/// the `:` that separates the action, the `/` that adds a path segment, and the
/// `?`/`#` that start the query/fragment — plus `%` and controls/space. The
/// client-supplied model name is otherwise interpolated raw into the path.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    // The WHATWG URL parser normalizes `\` to `/` for http(s) schemes, so a raw
    // backslash would re-introduce a segment break after this encode pass.
    .add(b'\\')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Build the Gemini `generateContent` upstream URL, percent-encoding the model
/// into a single path segment.
///
/// In BYOK pass-through the model is client-controlled (`/fwd/{key}/v1beta/models/{model}:...`),
/// so it MUST be encoded — a raw `/`, `:`, `?`, or `#` would otherwise reshape
/// the path or inject the action/query.
fn gemini_upstream_url(
    transport: UpstreamTransport,
    upstream_url: &str,
    model: &str,
    is_streaming: bool,
) -> String {
    let model = utf8_percent_encode(model, PATH_SEGMENT).to_string();
    transport.gemini_url(upstream_url, &model, is_streaming)
}

/// What a provider may be reached at: an internal address only when the
/// platform's `llm` egress list lists it; the cloud metadata endpoint never.
pub const LLM_EGRESS: Egress = Egress::Surface(Surface::Llm);

/// A client builder for every other call to a provider (liveness probes, model
/// discovery, engine gauges): the [`LLM_EGRESS`] resolver and a
/// redirect policy re-vetting each hop, with the caller's trusted CAs. A
/// request to an IP-literal URL is vetted with [`check_provider_url`] first.
pub fn provider_client_builder(custom_ca: Option<&str>) -> reqwest::ClientBuilder {
    crate::mcp::oauth_http::guarded_egress_builder(LLM_EGRESS, 10, custom_ca)
}

/// The provider URL check a write and a probe apply: an http(s) URL with a
/// host, never the metadata endpoint, and an internal IP literal only when the
/// `llm` egress list lists it. A host name is vetted at connect.
pub fn check_provider_url(url: &str) -> Result<(), SsrfError> {
    check_url_for(url, LLM_EGRESS).map(|_| ())
}

/// The IP-literal half of the provider guard: the connector never hands a
/// literal to the resolver, so a request to one is vetted here before it is
/// sent. A host name is vetted by the client's resolver at connect.
fn guard_literal(url: &str) -> Result<(), AppError> {
    match check_url_for(url, LLM_EGRESS) {
        Ok(_) => Ok(()),
        Err(SsrfError::InternalAddress) => Err(AppError::EgressRefused(
            "the provider's address is internal and the platform's llm egress list does not list it"
                .to_string(),
        )),
        Err(e) => Err(AppError::UpstreamUnbuildable(e.to_string())),
    }
}

/// Upstream HTTP client with connection pooling. The pool is rebuilt when the
/// egress lists change, so a connection opened to a provider while its address
/// was listed is never reused after the address is removed.
#[derive(Clone)]
pub struct UpstreamClient {
    clients: std::sync::Arc<streamscope_mcp_auth::egress::Cached<reqwest::Client>>,
    retry_backoff_base_ms: u64,
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamClient").field("retry_backoff_base_ms", &self.retry_backoff_base_ms).finish()
    }
}

impl UpstreamClient {
    /// Build from [`core_settings()`] upstream configuration.
    ///
    /// The client is built WITHOUT a total request timeout. `upstream_request_timeout`
    /// is applied per-request in [`forward`] / [`forward_media`] / [`forward_catchall`]
    /// only for non-streaming calls. Streaming responses (SSE) rely on
    /// `connect_timeout` plus the per-event idle timeout enforced in
    /// `pipeline::response_pipeline` — a total wall-clock cutoff on a long
    /// generation would truncate the stream mid-flight and trigger the
    /// zero-token guard with a misleading `overloaded_error`.
    pub fn new() -> Result<Self, AppError> {
        let this = Self {
            clients: std::sync::Arc::new(streamscope_mcp_auth::egress::Cached::new()),
            retry_backoff_base_ms: core_settings().upstream_retry_backoff_ms,
        };
        this.client()?;
        Ok(this)
    }

    /// The pooled client under the egress lists in force.
    fn client(&self) -> Result<reqwest::Client, AppError> {
        self.clients.get_or_try_build(LLM_EGRESS, || {
            let s = core_settings();
            provider_client_builder(s.custom_ca_bundle.as_deref())
                .pool_max_idle_per_host(s.upstream_pool_max_idle)
                .pool_idle_timeout(s.upstream_pool_idle_timeout)
                .connect_timeout(s.upstream_connect_timeout)
                .tcp_nodelay(true)
                .http2_adaptive_window(true)
                .build()
                .map_err(|e| AppError::Internal(format!("failed to build HTTP client: {e}")))
        })
    }

    /// Per-request total timeout to apply to non-streaming upstream calls.
    /// Streaming calls omit this and rely on the per-event idle timeout.
    fn non_streaming_timeout() -> Duration {
        core_settings().upstream_request_timeout
    }

    /// Forward a request to the upstream provider.
    ///
    /// When `auth_override` is `Some`, the client's original auth header is forwarded
    /// instead of using the `api_key` parameter (BYOK mode).
    #[allow(clippy::too_many_arguments)]
    pub async fn forward(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        body: Bytes,
        original_headers: &HeaderMap,
        api_version: ApiVersion,
        endpoint_path: Option<&str>,
        auth_override: Option<&super::ForwardAuthContext>,
        upstream_model: Option<&str>,
        is_streaming: bool,
        gateway_headers: &[(&'static str, String)],
    ) -> Result<reqwest::Response, AppError> {
        let url = match api_version {
            ApiVersion::GoogleGemini => {
                let model = upstream_model.unwrap_or("gemini-2.5-flash");
                gemini_upstream_url(endpoint.transport, endpoint.url, model, is_streaming)
            }
            _ => {
                let path = match api_version {
                    // A per-target override (`chat_endpoint_path`) reaches OpenAI-
                    // compatible providers whose chat path differs from the
                    // canonical `/v1/chat/completions` (e.g. Writer `/chat`,
                    // DeepInfra `/chat/completions` with no `/v1`).
                    ApiVersion::ChatCompletions => endpoint_path.unwrap_or("/v1/chat/completions"),
                    ApiVersion::Responses => "/v1/responses",
                    ApiVersion::AnthropicMessages => "/v1/messages",
                    ApiVersion::GoogleGemini => unreachable!("handled in outer match arm"),
                };
                endpoint.url_for(path)
            }
        };

        guard_literal(&url)?;
        // A Gemini model is sent its calls as it wrote them: an id the gateway
        // gave a call it left unidentified is the gateway's alone.
        let body = if api_version == ApiVersion::GoogleGemini {
            crate::api::call_ids::without_gateway_call_ids(body)
        } else {
            body
        };
        let mut req = self
            .client()?
            .post(&url)
            .header("content-type", "application/json")
            .body(body);
        // Non-streaming: enforce a total upstream timeout. Streaming SSE responses
        // omit this — they're gated by per-event idle timeout in `response_pipeline`
        // so long generations don't get truncated mid-stream.
        if !is_streaming {
            req = req.timeout(Self::non_streaming_timeout());
        }

        // Set auth headers. A transport that names its own credential header
        // (the Azure surfaces) wins; otherwise the header is protocol-decided,
        // using the BYOK override when the client supplied one.
        if let Some((name, value)) = endpoint.credential_header(auth_override).await? {
            req = req.header(name, value);
        } else if let Some(fwd) = auth_override {
            let is_bearer = fwd.header_value.starts_with("Bearer ");
            let credential = if let Some(stripped) = fwd.header_value.strip_prefix("Bearer ") {
                stripped
            } else {
                &fwd.header_value
            };
            // Set the correct auth header for the UPSTREAM protocol.
            // For Anthropic: OAuth tokens (from Authorization: Bearer) must be forwarded
            // as Authorization: Bearer — x-api-key only works for API keys.
            match api_version {
                ApiVersion::AnthropicMessages => {
                    if is_bearer {
                        // OAuth token — forward as Authorization: Bearer (Anthropic requires this for OAuth)
                        req = req.header("authorization", &fwd.header_value);
                    } else {
                        // API key — forward as x-api-key
                        req = req.header("x-api-key", credential);
                    }
                    req = req.header("anthropic-version", ANTHROPIC_API_VERSION);
                    if let Some(beta) = original_headers.get("anthropic-beta") {
                        req = req.header("anthropic-beta", beta);
                    }
                }
                ApiVersion::GoogleGemini => {
                    if is_bearer {
                        req = req.header("authorization", &fwd.header_value);
                    } else {
                        req = req.header("x-goog-api-key", credential);
                    }
                }
                _ => {
                    req = req.header("authorization", format!("Bearer {credential}"));
                }
            }
        } else {
            match api_version {
                ApiVersion::AnthropicMessages => {
                    req = req
                        .header("x-api-key", endpoint.api_key)
                        .header("anthropic-version", ANTHROPIC_API_VERSION);
                    if let Some(beta) = original_headers.get("anthropic-beta") {
                        req = req.header("anthropic-beta", beta);
                    }
                }
                ApiVersion::GoogleGemini => {
                    req = req.header("x-goog-api-key", endpoint.api_key);
                }
                _ => {
                    req = req.header("authorization", format!("Bearer {}", endpoint.api_key));
                }
            }
        }

        // Forward select headers from the original request. This is an
        // allowlist: internal attribution/identity headers (x-app-id,
        // x-session-id, and the inline-path x-client-ip / x-authenticated-*)
        // are deliberately absent, so gateway-internal identity never leaks to
        // the provider.
        for key in FORWARDED_CLIENT_HEADERS {
            if let Some(value) = original_headers.get(*key) {
                req = req.header(*key, value);
            }
        }
        // Headers the GATEWAY states about this request — today the engine's
        // scheduling priority, on a protocol whose body has no field for it.
        // A separate channel from the client's headers above on purpose: the
        // allowlist exists because a client must never steer the engine, and
        // that stays true — these values are computed here from the caller's
        // resolved class and applied after the copy, so a client's own header
        // can neither add to them nor override them.
        for (name, value) in gateway_headers {
            req = req.header(*name, value);
        }
        // Forward test-fixture control headers (`x-mock-*`). Real LLM upstreams
        // ignore unrecognized headers, so there's no production risk; E2E tests
        // rely on these to trigger deterministic mock behaviors (forced status
        // codes, canned response shapes) that can't be encoded in the body
        // without conflating test controls with real request content.
        for (name, value) in original_headers.iter() {
            if name.as_str().starts_with("x-mock-") {
                req = req.header(name.as_str(), value);
            }
        }

        let resp = req.send().await.map_err(|e| AppError::upstream_send_error(&e))?;

        Ok(resp)
    }

    /// Forward a media request to the upstream provider at an explicit path.
    ///
    /// Unlike [`forward`], this accepts an explicit endpoint `path` (e.g. `/v1/embeddings`)
    /// and `content_type` (e.g. `application/json` or `multipart/form-data; boundary=...`).
    /// Used for media endpoints where the path and content type vary per endpoint.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_media(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        body: Bytes,
        original_headers: &HeaderMap,
        path: &str,
        content_type: &str,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<reqwest::Response, AppError> {
        let url = endpoint.url_for(path);
        guard_literal(&url)?;

        let mut req = self
            .client()?
            .post(&url)
            .header("content-type", content_type)
            .body(body)
            .timeout(Self::non_streaming_timeout());

        // Set auth headers. A transport that names its own credential header
        // (the Azure surfaces) wins; the media endpoints are otherwise
        // OpenAI-shaped, so the fallback is Bearer — the BYOK override when the
        // client supplied one, else the stored key.
        if let Some((name, value)) = endpoint.credential_header(auth_override).await? {
            req = req.header(name, value);
        } else if let Some(fwd) = auth_override {
            let credential = if let Some(stripped) = fwd.header_value.strip_prefix("Bearer ") {
                stripped
            } else {
                &fwd.header_value
            };
            req = req.header("authorization", format!("Bearer {credential}"));
        } else {
            req = req.header("authorization", format!("Bearer {}", endpoint.api_key));
        }

        // Forward select headers from the original request. This is an
        // allowlist: internal attribution/identity headers (x-app-id,
        // x-session-id, and the inline-path x-client-ip / x-authenticated-*)
        // are deliberately absent, so gateway-internal identity never leaks to
        // the provider.
        for key in FORWARDED_CLIENT_HEADERS {
            if let Some(value) = original_headers.get(*key) {
                req = req.header(*key, value);
            }
        }
        // Forward test-fixture control headers (`x-mock-*`). See `forward` for rationale.
        for (name, value) in original_headers.iter() {
            if name.as_str().starts_with("x-mock-") {
                req = req.header(name.as_str(), value);
            }
        }

        let resp = req.send().await.map_err(|e| AppError::upstream_send_error(&e))?;

        Ok(resp)
    }

    /// The wait before retry `attempt`, logged — or `None`, also logged, when
    /// the upstream asked for longer than a retry may wait (see [`retry_delay`]).
    /// Every retrying path goes through here, so all three honour `Retry-After`
    /// and jitter alike.
    fn retry_wait(&self, attempt: u32, asked: Option<Duration>, path: &'static str) -> Option<Duration> {
        let delay = retry_delay(attempt, self.retry_backoff_base_ms, asked, rand::random::<f64>());
        match delay {
            Some(d) => tracing::warn!(attempt, path, "retrying upstream request in {:?}", d),
            None => tracing::warn!(
                attempt,
                path,
                asked_ms = asked.map_or(0, |a| a.as_millis()),
                "upstream asked for longer than a retry may wait; leaving it for another target"
            ),
        }
        delay
    }

    /// Forward a media request with configurable retry and exponential backoff.
    ///
    /// Retries on transient errors (429, 500, 502, 503) up to `max_retries` times.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_media_with_retry(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        body: Bytes,
        original_headers: &HeaderMap,
        path: &str,
        content_type: &str,
        max_retries: u32,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<reqwest::Response, AppError> {
        let mut last_err = None;
        let mut retry_after: Option<Duration> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let Some(delay) = self.retry_wait(attempt, retry_after.take(), "media") else { break };
                tokio::time::sleep(delay).await;
            }
            match self
                .forward_media(endpoint, body.clone(), original_headers, path, content_type, auth_override)
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    if !is_retryable_status(resp.status()) {
                        let status = resp.status().as_u16();
                        let err_body = read_error_body(resp).await;
                        return Err(AppError::upstream(status, err_body));
                    }
                    let status = resp.status().as_u16();
                    retry_after = parse_retry_after(resp.headers());
                    tracing::warn!(attempt, status, "retryable upstream media error");
                    last_err = Some(AppError::upstream(status, read_error_body(resp).await));
                }
                // A request that could not be built fails the same way every
                // time, so it is returned at once. Anything else — no answer, a
                // credential that could not be minted this time — may not recur.
                Err(e @ (AppError::UpstreamUnbuildable(_) | AppError::EgressRefused(_))) => return Err(e),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "upstream media request failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| AppError::Internal("media retry exhausted with no error".into())))
    }

    /// Forward a catch-all request to the upstream provider, preserving the HTTP method.
    ///
    /// Unlike [`forward_media`], this sends the request using the caller's HTTP method
    /// (GET, POST, PUT, DELETE, PATCH) rather than always POSTing. The path and content-type
    /// are forwarded as-is.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_catchall(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        method: reqwest::Method,
        body: Bytes,
        original_headers: &HeaderMap,
        path: &str,
        content_type: &str,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<reqwest::Response, AppError> {
        let url = endpoint.url_for(path);
        guard_literal(&url)?;

        let mut req = self
            .client()?
            .request(method, &url)
            .header("content-type", content_type)
            .body(body)
            .timeout(Self::non_streaming_timeout());

        // Set auth headers. A transport that names its own credential header
        // (the Azure surfaces) wins; otherwise Bearer, from the BYOK override
        // when the client supplied one.
        if let Some((name, value)) = endpoint.credential_header(auth_override).await? {
            req = req.header(name, value);
        } else if let Some(fwd) = auth_override {
            let credential = if let Some(stripped) = fwd.header_value.strip_prefix("Bearer ") {
                stripped
            } else {
                &fwd.header_value
            };
            req = req.header("authorization", format!("Bearer {credential}"));
        } else {
            req = req.header("authorization", format!("Bearer {}", endpoint.api_key));
        }

        // Forward select headers from the original request. This is an
        // allowlist: internal attribution/identity headers (x-app-id,
        // x-session-id, and the inline-path x-client-ip / x-authenticated-*)
        // are deliberately absent, so gateway-internal identity never leaks to
        // the provider.
        for key in FORWARDED_CLIENT_HEADERS {
            if let Some(value) = original_headers.get(*key) {
                req = req.header(*key, value);
            }
        }

        let resp = req.send().await.map_err(|e| AppError::upstream_send_error(&e))?;

        Ok(resp)
    }

    /// Forward a catch-all request with configurable retry and exponential backoff.
    ///
    /// Retries on transient errors (429, 500, 502, 503) up to `max_retries` times.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_catchall_with_retry(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        method: reqwest::Method,
        body: Bytes,
        original_headers: &HeaderMap,
        path: &str,
        content_type: &str,
        max_retries: u32,
        auth_override: Option<&super::ForwardAuthContext>,
    ) -> Result<reqwest::Response, AppError> {
        let mut last_err = None;
        let mut retry_after: Option<Duration> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let Some(delay) = self.retry_wait(attempt, retry_after.take(), "catchall") else { break };
                tokio::time::sleep(delay).await;
            }
            match self
                .forward_catchall(endpoint, method.clone(), body.clone(), original_headers, path, content_type, auth_override)
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    if !is_retryable_status(resp.status()) {
                        // Non-retryable: return the response directly (caller will handle)
                        return Ok(resp);
                    }
                    let status = resp.status().as_u16();
                    retry_after = parse_retry_after(resp.headers());
                    tracing::warn!(attempt, status, "retryable upstream catchall error");
                    last_err = Some(AppError::upstream(status, read_error_body(resp).await));
                }
                // A request that could not be built fails the same way every
                // time, so it is returned at once. Anything else — no answer, a
                // credential that could not be minted this time — may not recur.
                Err(e @ (AppError::UpstreamUnbuildable(_) | AppError::EgressRefused(_))) => return Err(e),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "upstream catchall request failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| AppError::Internal("catchall retry exhausted with no error".into())))
    }

    /// Forward a request to the upstream provider with configurable retry and exponential backoff.
    ///
    /// Retries on transient errors (429, 500, 502, 503) up to `max_retries` times.
    /// Non-retryable error responses (e.g. 400, 401, 404) are returned as `Err(AppError::Upstream)` immediately.
    /// Successful responses are returned as `Ok(response)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn forward_with_retry(
        &self,
        endpoint: UpstreamEndpoint<'_>,
        body: Bytes,
        original_headers: &HeaderMap,
        api_version: ApiVersion,
        endpoint_path: Option<&str>,
        max_retries: u32,
        auth_override: Option<&super::ForwardAuthContext>,
        upstream_model: Option<&str>,
        is_streaming: bool,
        gateway_headers: &[(&'static str, String)],
    ) -> Result<reqwest::Response, AppError> {
        let mut last_err = None;
        // What the upstream asked us to wait, when it said so. An exponential
        // backoff that ignores `Retry-After` retries in milliseconds a request
        // the provider said to hold for twenty seconds — which is exactly what
        // providers that punish retry storms are watching for.
        let mut retry_after: Option<Duration> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let Some(delay) = self.retry_wait(attempt, retry_after.take(), "llm") else { break };
                tokio::time::sleep(delay).await;
            }
            match self
                .forward(endpoint, body.clone(), original_headers, api_version, endpoint_path, auth_override, upstream_model, is_streaming, gateway_headers)
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    if !is_retryable_status(resp.status()) {
                        let status = resp.status().as_u16();
                        let err_body = read_error_body(resp).await;
                        return Err(AppError::upstream(status, err_body));
                    }
                    // Retryable status — log and continue
                    let status = resp.status().as_u16();
                    retry_after = parse_retry_after(resp.headers());
                    tracing::warn!(attempt, status, "retryable upstream error");
                    last_err = Some(AppError::upstream(status, read_error_body(resp).await));
                }
                // A request that could not be built fails the same way every
                // time, so it is returned at once. Anything else — no answer, a
                // credential that could not be minted this time — may not recur.
                Err(e @ (AppError::UpstreamUnbuildable(_) | AppError::EgressRefused(_))) => return Err(e),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "upstream request failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| AppError::Internal("retry exhausted with no error".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loopback upstream that hands back the head of each request it gets.
    async fn capture_heads() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).to_ascii_lowercase());
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await;
            }
        });
        (url, rx)
    }

    /// The gateway's own engine-control header travels; the client's does not.
    #[tokio::test]
    async fn the_gateways_own_header_reaches_the_upstream_and_the_clients_does_not() {
        // The two halves of one rule. The client's `x-vllm-priority` is dropped
        // (it must not let a caller jump the engine's queue), and the gateway's
        // own — computed from the caller's resolved class — travels, because a
        // protocol whose body has no priority field has nowhere else to put it.
        // Sent on a separate channel for exactly that reason: if the gateway
        // wrote into the client's header map, the allowlist would drop it too.
        let (url, mut heads) = capture_heads().await;
        let client = UpstreamClient::new().unwrap();
        let endpoint = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };
        let mut headers = HeaderMap::new();
        headers.insert("x-vllm-priority", "-100".parse().unwrap());

        client
            .forward(
                endpoint,
                Bytes::from_static(b"{}"),
                &headers,
                ApiVersion::AnthropicMessages,
                None,
                None,
                None,
                false,
                &[("x-vllm-priority", "20".to_string())],
            )
            .await
            .unwrap();

        let head = heads.recv().await.unwrap();
        assert!(head.contains("x-vllm-priority: 20"), "the gateway's value is missing:\n{head}");
        assert!(!head.contains("-100"), "the client's value travelled:\n{head}");
    }

    /// No forward path carries an engine control header a client set, while
    /// an allowlisted one still travels (the positive control).
    #[tokio::test]
    async fn no_forward_path_passes_an_engine_control_header() {
        let (url, mut heads) = capture_heads().await;
        let client = UpstreamClient::new().unwrap();
        let endpoint = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };
        let mut headers = HeaderMap::new();
        headers.insert("x-vllm-priority", "-100".parse().unwrap());
        headers.insert("x-data-parallel-rank", "0".parse().unwrap());
        headers.insert("x-request-id", "req-42".parse().unwrap());

        client
            .forward(endpoint, Bytes::from_static(b"{}"), &headers, ApiVersion::ChatCompletions, None, None, None, false, &[])
            .await
            .unwrap();
        client
            .forward_media(endpoint, Bytes::from_static(b"{}"), &headers, "/v1/embeddings", "application/json", None)
            .await
            .unwrap();
        client
            .forward_catchall(endpoint, reqwest::Method::POST, Bytes::from_static(b"{}"), &headers, "/v1/pooling", "application/json", None)
            .await
            .unwrap();

        for path in ["forward", "forward_media", "forward_catchall"] {
            let head = heads.recv().await.unwrap();
            assert!(head.contains("x-request-id: req-42"), "{path}: allowlisted header missing:\n{head}");
            assert!(!head.contains("x-vllm-priority"), "{path}: forwarded x-vllm-priority:\n{head}");
            assert!(!head.contains("x-data-parallel-rank"), "{path}: forwarded x-data-parallel-rank:\n{head}");
        }
    }

    /// A loopback upstream that refuses every request with `429` and `body`.
    async fn always_refuses(body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                // Read the whole request — head AND body — before answering:
                // closing a socket with unread bytes resets it, and the client
                // would then see a transport error instead of the 429.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let complete = |buf: &[u8]| {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        return false;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    buf.len() >= end + 4 + length
                };
                while !complete(&buf) {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
            }
        });
        url
    }

    /// A refusal that outlasts every retry still says what the upstream said:
    /// the last attempt's own body is the error, on all three retrying paths.
    /// A synthesized stand-in would leave the client, the audit row and the
    /// log with nothing but the status.
    #[tokio::test]
    async fn a_retried_refusal_keeps_the_upstreams_own_body() {
        const BODY: &str = r#"{"error":{"message":"the upstream's own words"}}"#;
        let url = always_refuses(BODY).await;
        let client = UpstreamClient::new().unwrap();
        let endpoint = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };
        let headers = HeaderMap::new();

        let llm = client
            .forward_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, ApiVersion::ChatCompletions, None, 1, None, None, false, &[])
            .await;
        let media = client
            .forward_media_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, "/v1/embeddings", "application/json", 1, None)
            .await;
        let catchall = client
            .forward_catchall_with_retry(endpoint, reqwest::Method::POST, Bytes::from_static(b"{}"), &headers, "/v1/pooling", "application/json", 1, None)
            .await;

        for (path, result) in [("forward", llm), ("media", media), ("catchall", catchall)] {
            let Err(AppError::Upstream { status, body, .. }) = result else {
                panic!("{path}: a refusal on every attempt must end as an upstream error");
            };
            assert_eq!(status, 429, "{path}");
            assert_eq!(body, BODY, "{path}: the last attempt's body was replaced");
        }
    }

    /// A loopback upstream that hangs up on every connection without a word,
    /// counting them.
    async fn hangs_up() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                drop(sock);
            }
        });
        (url, accepted)
    }

    /// A loopback upstream that answers every request 429 with this
    /// `Retry-After`, counting the requests it saw.
    async fn throttles(retry_after: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // The whole request, body included: closing a socket with
                // unread data resets it, and the client would see a transport
                // error instead of the 429 and its hint.
                let complete = |buf: &[u8]| {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    buf.len() >= end + 4 + length
                };
                while !complete(&buf) {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let answer = format!(
                    "HTTP/1.1 429 Too Many Requests\r\nretry-after: {retry_after}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
                );
                let _ = sock.write_all(answer.as_bytes()).await;
            }
        });
        (url, seen)
    }

    /// Every retrying path honours `Retry-After`: an ask past the cap ends the
    /// retries at once, and the positive control — an ask of zero — is retried,
    /// so the first assertion cannot pass by never retrying at all.
    #[tokio::test]
    async fn every_retrying_path_honours_retry_after() {
        let headers = HeaderMap::new();
        let client = UpstreamClient::new().unwrap();
        for (asked, attempts) in [("60", 1usize), ("0", 2), ("1", 2)] {
            let (url, seen) = throttles(asked).await;
            // Each path's own wait: at least the ask, where it is retried.
            let floor = if attempts == 2 { Duration::from_secs(asked.parse().unwrap()) } else { Duration::ZERO };
            let started = std::time::Instant::now();
            let endpoint = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };
            let llm = client
                .forward_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, ApiVersion::ChatCompletions, None, 1, None, None, false, &[])
                .await;
            assert!(llm.is_err());
            assert_eq!(seen.swap(0, std::sync::atomic::Ordering::SeqCst), attempts, "llm, asked {asked}");
            assert!(started.elapsed() >= floor, "llm waited the ask {asked}");
            let started = std::time::Instant::now();
            let media = client
                .forward_media_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, "/v1/embeddings", "application/json", 1, None)
                .await;
            assert!(media.is_err());
            assert_eq!(seen.swap(0, std::sync::atomic::Ordering::SeqCst), attempts, "media, asked {asked}");
            assert!(started.elapsed() >= floor, "media waited the ask {asked}");
            let started = std::time::Instant::now();
            let catchall = client
                .forward_catchall_with_retry(endpoint, reqwest::Method::POST, Bytes::from_static(b"{}"), &headers, "/v1/pooling", "application/json", 1, None)
                .await;
            assert!(catchall.is_err());
            assert_eq!(seen.swap(0, std::sync::atomic::Ordering::SeqCst), attempts, "catchall, asked {asked}");
            assert!(started.elapsed() >= floor, "catchall waited the ask {asked}");
        }
    }

    /// Only a request that could not be built is returned at once, on all
    /// three retrying paths; an upstream that did not answer is asked again.
    #[tokio::test]
    async fn only_a_request_that_cannot_be_built_is_not_retried() {
        let (url, accepted) = hangs_up().await;
        let headers = HeaderMap::new();
        let unbuildable = UpstreamEndpoint { url: &url, api_key: "k\nwith-a-newline", transport: UpstreamTransport::Default };
        let reachable = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };
        // A retry of the unbuildable request would sit out this backoff, so
        // finishing inside the deadline below is the proof it was not retried.
        let mut patient = UpstreamClient::new().unwrap();
        patient.retry_backoff_base_ms = 600_000;
        let prompt = UpstreamClient::new().unwrap();
        for (client, endpoint, attempts) in [(&patient, unbuildable, 0), (&prompt, reachable, 2)] {
            accepted.store(0, std::sync::atomic::Ordering::SeqCst);
            let all = async {
                (
                    client
                        .forward_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, ApiVersion::ChatCompletions, None, 1, None, None, false, &[])
                        .await,
                    client
                        .forward_media_with_retry(endpoint, Bytes::from_static(b"{}"), &headers, "/v1/embeddings", "application/json", 1, None)
                        .await,
                    client
                        .forward_catchall_with_retry(endpoint, reqwest::Method::POST, Bytes::from_static(b"{}"), &headers, "/v1/pooling", "application/json", 1, None)
                        .await,
                )
            };
            let (llm, media, catchall) = tokio::time::timeout(Duration::from_secs(30), all)
                .await
                .unwrap_or_else(|_| panic!("attempts {attempts}: a retry sat out its backoff"));
            for (path, result) in [("forward", llm), ("media", media), ("catchall", catchall)] {
                let e = result.expect_err("nothing answers");
                if attempts == 0 {
                    assert!(matches!(e, AppError::UpstreamUnbuildable(_)), "{path}: {e:?}");
                } else {
                    assert!(matches!(e, AppError::UpstreamUnreachable { .. }), "{path}: {e:?}");
                }
            }
            // Three paths, each reaching the upstream `attempts` times.
            assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 3 * attempts);
        }
    }

    /// An error answer whose body never ends — a refusal framed as a stream —
    /// is abandoned after [`ERROR_BODY_READ_TIMEOUT`], not awaited: a streaming
    /// request has no total deadline, so otherwise the request, its failover
    /// and its audit row would all hang behind it.
    #[tokio::test]
    async fn an_error_body_that_never_ends_is_not_waited_on() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The loopback server is a private address the `llm` list must list.
        crate::test_egress::install();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut chunk = [0u8; 4096];
                    let _ = sock.read(&mut chunk).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 429 Too Many Requests\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n")
                        .await;
                    // Hold the connection open, the body unfinished.
                    tokio::time::sleep(Duration::from_secs(600)).await;
                });
            }
        });
        let client = UpstreamClient::new().unwrap();
        let endpoint = UpstreamEndpoint { url: &url, api_key: "k", transport: UpstreamTransport::Default };

        let started = std::time::Instant::now();
        let result = client
            .forward_with_retry(endpoint, Bytes::from_static(b"{}"), &HeaderMap::new(), ApiVersion::ChatCompletions, None, 0, None, None, true, &[])
            .await;
        let Err(AppError::Upstream { status, .. }) = result else {
            panic!("the refusal must still end as an upstream error");
        };
        assert_eq!(status, 429);
        assert!(
            started.elapsed() < ERROR_BODY_READ_TIMEOUT + Duration::from_secs(5),
            "waited {:?} on a body that never ends",
            started.elapsed()
        );
    }

    #[test]
    fn retryable_statuses() {
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(reqwest::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!is_retryable_status(reqwest::StatusCode::OK));
        assert!(!is_retryable_status(reqwest::StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn gemini_url_passes_plain_model_through() {
        assert_eq!(
            gemini_upstream_url(UpstreamTransport::Default, "https://x.test", "gemini-2.5-flash", false),
            "https://x.test/v1beta/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(
            gemini_upstream_url(UpstreamTransport::Default, "https://x.test", "gemini-2.5-flash", true),
            "https://x.test/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn gemini_url_encodes_reserved_chars_in_client_model() {
        // A BYOK client controls the model segment; reserved chars must not
        // reshape the path or inject the action/query.
        let url = gemini_upstream_url(UpstreamTransport::Default, "https://x.test", "../v1beta/models/evil:generateContent", false);
        assert_eq!(
            url,
            "https://x.test/v1beta/models/..%2Fv1beta%2Fmodels%2Fevil%3AgenerateContent:generateContent"
        );
        assert!(!url.contains("evil:generateContent:"), "':' must be encoded so the action can't be hijacked");

        // A '?' in the model must not start a query string.
        let url = gemini_upstream_url(UpstreamTransport::Default, "https://x.test", "m?alt=json", false);
        assert_eq!(url, "https://x.test/v1beta/models/m%3Falt=json:generateContent");

        // A backslash must be encoded — the URL parser would normalize a raw `\`
        // to `/` for the https scheme, re-introducing a segment break.
        let url = gemini_upstream_url(UpstreamTransport::Default, "https://x.test", "..\\evil", false);
        assert_eq!(url, "https://x.test/v1beta/models/..%5Cevil:generateContent");
    }

    /// Vertex puts the model in the path too, so it inherits the same encoding —
    /// a second URL grammar is a second place the segment could be broken out of.
    #[test]
    fn vertex_gemini_url_encodes_the_model_segment_the_same_way() {
        let base = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/l";
        let url = gemini_upstream_url(
            UpstreamTransport::GoogleVertex,
            base,
            "../publishers/anthropic/models/evil:rawPredict",
            false,
        );
        assert_eq!(
            url,
            format!(
                "{base}/publishers/google/models/\
                 ..%2Fpublishers%2Fanthropic%2Fmodels%2Fevil%3ArawPredict:generateContent"
            )
            .replace(' ', "")
        );
        assert!(!url.contains("evil:rawPredict:"), "':' must be encoded");
        assert!(url.ends_with(":generateContent"));
    }
}

#[cfg(test)]
mod retry_after_tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(reqwest::header::RETRY_AFTER, value.parse().expect("header value"));
        h
    }

    #[test]
    fn a_delay_in_seconds_is_honoured() {
        assert_eq!(parse_retry_after(&headers("20")), Some(Duration::from_secs(20)));
    }

    #[test]
    fn a_date_in_the_future_becomes_the_wait_until_then() {
        let when = chrono::Utc::now() + chrono::Duration::seconds(30);
        let parsed = parse_retry_after(&headers(&when.to_rfc2822())).expect("parsed");
        // Rounded to whole seconds by the format, so allow the boundary.
        assert!(parsed <= Duration::from_secs(30) && parsed >= Duration::from_secs(28));
    }

    #[test]
    fn a_date_in_the_past_asks_for_no_wait_at_all() {
        let when = chrono::Utc::now() - chrono::Duration::seconds(30);
        assert_eq!(parse_retry_after(&headers(&when.to_rfc2822())), None);
    }

    #[test]
    fn a_header_that_is_neither_form_leaves_the_backoff_alone() {
        assert_eq!(parse_retry_after(&headers("soon")), None);
        assert_eq!(parse_retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn the_cap_is_a_wait_a_caller_can_absorb_not_a_providers_whole_hint() {
        // It bounds time spent inside someone's request. Long enough to be worth
        // waiting rather than hammering, short enough that two of them still
        // leave room to fail over.
        assert!(MAX_HONOURED_RETRY_AFTER >= Duration::from_secs(1));
        assert!(MAX_HONOURED_RETRY_AFTER <= Duration::from_secs(10));
    }

    const MS: fn(u64) -> Duration = Duration::from_millis;

    #[test]
    fn an_ask_past_the_cap_ends_the_retries_and_one_at_the_cap_is_waited() {
        let over = MAX_HONOURED_RETRY_AFTER + MS(1);
        assert_eq!(retry_delay(1, 500, Some(over), 0.5), None);
        assert_eq!(retry_delay(1, 500, Some(MAX_HONOURED_RETRY_AFTER), 0.0), Some(MAX_HONOURED_RETRY_AFTER));
    }

    #[test]
    fn an_ask_is_a_floor_under_the_backoff_never_a_ceiling() {
        // Asked less than the backoff: the backoff stands.
        assert_eq!(retry_delay(2, 500, Some(MS(100)), 0.5), Some(MS(1000)));
        // Asked more: the ask stands, and the jitter never shortens it.
        assert_eq!(retry_delay(1, 500, Some(MS(3000)), 0.0), Some(MS(3000)));
    }

    #[test]
    fn without_an_ask_the_backoff_doubles_from_its_base() {
        assert_eq!(retry_delay(1, 500, None, 0.5), Some(MS(500)));
        assert_eq!(retry_delay(2, 500, None, 0.5), Some(MS(1000)));
        assert_eq!(retry_delay(3, 500, None, 0.5), Some(MS(2000)));
    }

    proptest::proptest! {
        /// An upstream's ask is a floor the jitter only lengthens, by at most
        /// its band — and a backoff longer than it still stands.
        #[test]
        fn an_ask_is_jittered_upward_only(attempt in 1u32..4, base in 1u64..2_000, asked_ms in 0u64..=5_000, unit in 0.0f64..1.0) {
            let got = retry_delay(attempt, base, Some(MS(asked_ms)), unit).unwrap().as_millis() as f64;
            let nominal = (base * (1u64 << (attempt - 1))) as f64;
            proptest::prop_assert!(got >= asked_ms as f64);
            proptest::prop_assert!(got <= (asked_ms as f64 * (1.0 + RETRY_JITTER)).max(nominal * (1.0 + RETRY_JITTER)) + 1.0);
            proptest::prop_assert!(got + 1.0 >= (nominal * (1.0 - RETRY_JITTER)).floor());
        }
    }

    #[test]
    fn a_jittered_ask_never_passes_the_cap() {
        for unit in [0.0, 0.5, 0.99] {
            assert_eq!(retry_delay(1, 10, Some(MAX_HONOURED_RETRY_AFTER), unit), Some(MAX_HONOURED_RETRY_AFTER));
        }
        // Positive control: under the cap, the jitter still lengthens it.
        assert!(retry_delay(1, 10, Some(MS(4500)), 0.99).unwrap() > MS(4500));
    }

    #[test]
    fn replicas_told_the_same_ask_do_not_all_return_on_its_beat() {
        let low = retry_delay(1, 10, Some(MS(2000)), 0.0).unwrap();
        let high = retry_delay(1, 10, Some(MS(2000)), 0.99).unwrap();
        assert_eq!(low, MS(2000), "never shorter than the ask");
        assert!(high > MS(2300), "spread above it: {high:?}");
    }

    #[test]
    fn a_huge_attempt_saturates_instead_of_overflowing() {
        assert!(retry_delay(200, 500, None, 0.5).is_some());
    }

    proptest::proptest! {
        /// The jitter stays within its band on both sides, so no two replicas
        /// retry in lockstep and none waits more than the band's top.
        #[test]
        fn the_backoff_stays_within_its_jitter_band(attempt in 1u32..8, base in 1u64..10_000, unit in 0.0f64..1.0) {
            let nominal = base * (1u64 << (attempt - 1));
            let got = retry_delay(attempt, base, None, unit).unwrap().as_millis() as f64;
            proptest::prop_assert!(got >= (nominal as f64 * (1.0 - RETRY_JITTER)).floor());
            proptest::prop_assert!(got <= nominal as f64 * (1.0 + RETRY_JITTER));
        }
    }
}
