//! Outbound calls to registered A2A agents. Every hop rides the shared
//! SSRF-guarded client (`mcp::upstream::guarded_agent_client` — the
//! resolver validates the connected IP, closing DNS rebinding), reading the
//! platform's `a2a` egress list.

use streamscope_core::config::a2a::{A2aAuthMode, A2aUpstreamAgent};
use streamscope_core::error::{AppError, AuthError};

use streamscope_mcp_auth::egress::Surface;
use streamscope_mcp_auth::ssrf::Egress;



/// What A2A egress (agent calls; the admin side's card fetches read the same
/// list) may reach: an internal address only when the platform's `a2a` egress
/// list lists it. Never per-tenant. IMDS stays refused whatever the list says.
pub(crate) const A2A_EGRESS: Egress = Egress::Surface(Surface::A2a);

const NOT_LISTED: &str = "the agent's address is not on the platform's a2a egress list";

/// The client a call to `agent` goes through, vetted against the lists as
/// they stand now. Over https: the pooled guarded client (`streaming` picks
/// its deadline shape), after an IP-literal check (the connector never hands
/// a literal to the resolver). Over plain http — the agent's credential in
/// clear — only to listed private addresses, resolved once here and pinned
/// into a one-call client, so the name cannot be rebound onto a public address
/// between the check and the connection. Neither follows a redirect: a 3xx
/// reaches the caller as the agent's answer.
async fn agent_client(agent: &A2aUpstreamAgent, streaming: bool) -> Result<reqwest::Client, AppError> {
    let refused = |e: &dyn std::fmt::Display| {
        tracing::warn!(agent = %agent.slug, "a2a upstream refused by the SSRF guard: {e}");
        AppError::EgressRefused(NOT_LISTED.to_string())
    };
    use streamscope_mcp_auth::ssrf::SsrfError;
    let url = match streamscope_mcp_auth::ssrf::check_url_for(&agent.agent_url, A2A_EGRESS) {
        Ok(url) => url,
        Err(SsrfError::InternalAddress) => return Err(refused(&SsrfError::InternalAddress)),
        Err(e) => {
            tracing::warn!(agent = %agent.slug, "a2a upstream URL unusable: {e}");
            return Err(AppError::Internal("upstream agent unreachable".into()));
        }
    };
    if url.scheme() == "https" {
        return crate::mcp::upstream::guarded_agent_client(streaming).map_err(|e| {
            tracing::error!(agent = %agent.slug, "could not build the agent client: {e}");
            AppError::Internal("upstream agent unreachable".into())
        });
    }
    let (_, host, addrs) = streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(&agent.agent_url, A2A_EGRESS)
        .await
        .map_err(|e| match e {
            SsrfError::DnsLookup(_) | SsrfError::NoAddresses => {
                tracing::warn!(agent = %agent.slug, "a2a upstream did not resolve: {e}");
                AppError::Internal("upstream agent unreachable".into())
            }
            SsrfError::PlainHttp => {
                tracing::warn!(
                    agent = %agent.slug,
                    "a2a upstream refused: plain http reaches only a private address on the a2a egress list"
                );
                AppError::EgressRefused(
                    "plain http reaches only a private address on the platform's a2a egress list".to_string(),
                )
            }
            e => refused(&e),
        })?;
    crate::mcp::upstream::pinned_plain_http_client(&host, &addrs, streaming).map_err(|e| {
        tracing::error!(agent = %agent.slug, "could not build the agent client: {e}");
        AppError::Internal("upstream agent unreachable".into())
    })
}

/// A failed send: the guard's typed refusal (a name resolving to an unlisted
/// private address, a redirect hop) is a policy refusal; anything else an
/// agent that did not answer.
fn send_failure(agent: &A2aUpstreamAgent, e: &reqwest::Error, what: &str) -> AppError {
    // Only an address refusal can occur: neither agent client follows a
    // redirect, so no downgrade is ever met.
    if streamscope_mcp_auth::ssrf::refusal(e).is_some() {
        tracing::warn!(agent = %agent.slug, "a2a upstream refused by the SSRF guard: {e}");
        return AppError::EgressRefused(NOT_LISTED.to_string());
    }
    tracing::warn!(agent = %agent.slug, "a2a upstream {what} failed: {e}");
    AppError::Internal("upstream agent unreachable".into())
}

/// Total per-call timeout toward the upstream agent. `SendMessage` blocks
/// until the task reaches a terminal/interrupted state by default
/// (`returnImmediately: false`), so this is generous; clients wanting
/// long-running work poll `GetTask` or use `returnImmediately: true`.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Streaming size cap for a reply read from an upstream agent.
///
/// A registered A2A agent is a third party, so an unbounded read lets it OOM
/// the proxy replica serving every tenant. The bound matches the MCP one: an
/// A2A artifact carries the same inline-file payloads a `resources/read` does,
/// and a caller has no reason to meet a different ceiling on one protocol than
/// the other.
const A2A_MAX_RESPONSE_BYTES: u64 = streamscope_core::mcp::MCP_MAX_RESPONSE_BYTES;

/// Read an upstream agent's body under [`A2A_MAX_RESPONSE_BYTES`]. An
/// oversized or unreadable body is the same outcome to the caller — the reply
/// is unusable — and neither is echoed to the client.
async fn read_agent_body(
    resp: reqwest::Response,
    agent_slug: &str,
    context: &str,
) -> Result<bytes::Bytes, AppError> {
    streamscope_core::http_body::read_body_capped(resp, A2A_MAX_RESPONSE_BYTES)
        .await
        .map_err(|e| {
            tracing::warn!(agent = %agent_slug, "a2a upstream {context} body read failed: {e}");
            AppError::Internal("upstream agent response unreadable".into())
        })
}

/// The upstream's reply to a forwarded JSON-RPC call: HTTP status + raw body
/// bytes (a JSON-RPC envelope on the happy path — forwarded verbatim so
/// unknown fields survive).
pub struct UpstreamReply {
    pub status: u16,
    pub body: bytes::Bytes,
    pub latency_ms: u64,
}

/// Resolve the agent's upstream credential into an `(header, value)` pair.
/// `None` for `no_auth`. Decryption failure is a hard error — never fall
/// back to an unauthenticated call against an agent that expects one.
fn resolve_credential(agent: &A2aUpstreamAgent) -> Result<Option<(String, String)>, AppError> {
    match agent.auth_mode {
        A2aAuthMode::NoAuth => Ok(None),
        A2aAuthMode::ServiceAccount => {
            let ciphertext = agent.encrypted_credential.as_deref().ok_or_else(|| {
                AppError::Auth(AuthError::ServiceUnavailable(
                    "upstream agent credential unavailable".into(),
                ))
            })?;
            let key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
                AppError::Auth(AuthError::ServiceUnavailable(
                    "encryption key not configured".into(),
                ))
            })?;
            let plain = streamscope_core::crypto::decrypt(ciphertext, &key).map_err(|e| {
                tracing::error!(agent = %agent.slug, "decrypt a2a upstream credential: {e}");
                AppError::Auth(AuthError::ServiceUnavailable(
                    "upstream agent credential unavailable".into(),
                ))
            })?;
            match agent.credential_header.as_deref() {
                Some(header) => Ok(Some((header.to_string(), plain))),
                None => Ok(Some(("authorization".to_string(), format!("Bearer {plain}")))),
            }
        }
    }
}

/// What the upstream did with a streaming request.
pub(crate) enum StreamOpen {
    /// It opened an SSE stream — pipe it.
    Sse(reqwest::Response),
    /// It answered a plain JSON-RPC envelope instead. This is a legitimate,
    /// spec-defined outcome, not a failure: `SubscribeToTask` on a task that
    /// already reached a terminal state answers `UnsupportedOperation`
    /// (-32004). Forward the upstream's envelope verbatim rather than
    /// inventing a gateway error that would mask it.
    Json(UpstreamReply),
}

/// Read the envelope of an answer to a streaming request that turned out not to be
/// a stream.
///
/// `read_timeout` is load-bearing and must be the REQUEST/RESPONSE deadline, never the
/// stream one this response arrived on. An envelope is a few hundred bytes, but an agent
/// that misframes a long-lived stream as `application/json` produces one that never
/// ends, and the streaming client's deadlines are a wall-clock ceiling plus an idle bound
/// measured in minutes — so the caller's own request would hang for that long before the
/// gateway said anything at all.
async fn read_stream_refusal_envelope(
    resp: reqwest::Response,
    agent_slug: &str,
    read_timeout: std::time::Duration,
) -> Result<bytes::Bytes, AppError> {
    match tokio::time::timeout(read_timeout, read_agent_body(resp, agent_slug, "stream-refusal"))
        .await
    {
        Ok(body) => body,
        Err(_) => {
            tracing::warn!(
                agent = %agent_slug,
                "a2a upstream answered a stream request with a non-stream body that did not end"
            );
            Err(AppError::Internal("upstream agent response unreadable".into()))
        }
    }
}

/// Open a streaming call against the agent.
pub(crate) async fn open_stream(
    agent: &A2aUpstreamAgent,
    body: bytes::Bytes,
    service_headers: &[(&str, String)],
) -> Result<StreamOpen, AppError> {
    let credential = resolve_credential(agent)?;
    // Same SSRF guard, stream deadlines: the request/response client's short
    // total timeout would kill a legitimately long agent task mid-stream.
    let client = agent_client(agent, true).await?;
    let started = std::time::Instant::now();

    let mut req = client
        .post(&agent.agent_url)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream, application/json")
        .body(body);
    for (name, value) in service_headers {
        req = req.header(*name, value);
    }
    if let Some((header, value)) = credential {
        req = req.header(header, value);
    }

    let resp = req.send().await.map_err(|e| send_failure(agent, &e, "stream open"))?;

    let is_sse = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if is_sse && resp.status().is_success() {
        return Ok(StreamOpen::Sse(resp));
    }

    // Not a stream — read the envelope and let the caller forward it.
    let status = resp.status().as_u16();
    let body = read_stream_refusal_envelope(resp, &agent.slug, REQUEST_TIMEOUT).await?;
    Ok(StreamOpen::Json(UpstreamReply {
        status,
        body,
        latency_ms: started.elapsed().as_millis() as u64,
    }))
}

/// Forward one JSON-RPC envelope to the agent and return its reply.
///
/// `service_headers` carries the pass-through A2A service parameters
/// (`A2A-Version`, `A2A-Extensions`) exactly as the client sent them.
/// Transport-level failures come back as `AppError::Upstream`-free internal
/// errors — the caller renders a sanitized JSON-RPC `-32603`, never the raw
/// transport error.
pub(crate) async fn forward_call(
    agent: &A2aUpstreamAgent,
    body: bytes::Bytes,
    service_headers: &[(&str, String)],
) -> Result<UpstreamReply, AppError> {
    let credential = resolve_credential(agent)?;
    let client = agent_client(agent, false).await?;
    let started = std::time::Instant::now();

    let mut req = client
        .post(&agent.agent_url)
        .timeout(REQUEST_TIMEOUT)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body);
    for (name, value) in service_headers {
        req = req.header(*name, value);
    }
    if let Some((header, value)) = credential {
        req = req.header(header, value);
    }

    let resp = req.send().await.map_err(|e| send_failure(agent, &e, "call"))?;
    let status = resp.status().as_u16();
    let body = read_agent_body(resp, &agent.slug, "call").await?;
    Ok(UpstreamReply {
        status,
        body,
        latency_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One HTTP/1.1 response on a fresh loopback port, written by hand so the
    /// body can be left deliberately unfinished — the shape an agent produces
    /// when it misframes a long-lived stream as `application/json`, and one no
    /// HTTP server library will emit for us.
    async fn serve_once(payload: &'static str, finish: bool) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut scratch = [0u8; 4096];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await;
            let _ = sock
                .write_all(format!("{:X}\r\n{payload}\r\n", payload.len()).as_bytes())
                .await;
            if finish {
                let _ = sock.write_all(b"0\r\n\r\n").await;
                return;
            }
            std::future::pending::<()>().await;
        });
        (format!("http://{addr}/"), task)
    }

    #[tokio::test]
    async fn an_a2a_stream_refusal_that_never_ends_is_not_waited_on() {
        // The defect this pins: the envelope read inherited the deadlines of
        // the STREAM client the response arrived on — a wall-clock ceiling plus
        // an idle bound measured in minutes — so an agent that answered a
        // streaming request with a body it never terminated held the CALLER's
        // request for that long before the gateway said anything at all.
        let (url, server) = serve_once(r#"{"jsonrpc":"2.0"}"#, false).await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let started = std::time::Instant::now();
        let out =
            read_stream_refusal_envelope(resp, "agent", std::time::Duration::from_millis(200)).await;
        assert!(out.is_err(), "a body that never ends is not an envelope");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        server.abort();
    }

    #[tokio::test]
    async fn an_a2a_envelope_that_ends_is_still_forwarded() {
        // The positive control the bound needs. A refusal envelope is a
        // legitimate, spec-defined answer to a streaming request — a
        // `SubscribeToTask` on an already-terminal task answers `-32004` this
        // way — so a deadline that turned every non-stream answer into an error
        // would replace the agent's own verdict with a gateway fault, and the
        // test above would go on passing without noticing.
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32004,"message":"terminal"}}"#;
        let (url, server) = serve_once(body, true).await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let out =
            read_stream_refusal_envelope(resp, "agent", std::time::Duration::from_secs(10)).await;
        assert_eq!(out.expect("a finished envelope is readable"), body.as_bytes());
        server.abort();
    }
}
