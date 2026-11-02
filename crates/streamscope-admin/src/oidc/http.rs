//! SSRF-guarded transport for every OIDC hop.
//!
//! `openidconnect` talks to the IdP through an [`AsyncHttpClient`] the caller
//! supplies. The crate ships one over `reqwest`, and we deliberately do not use
//! it: it caps no response body and applies no egress guard, so a hostile or
//! compromised issuer could point discovery at an internal address or answer
//! with an unbounded stream. This implementation routes discovery, JWKS, and
//! the token exchange through the same [`GuardedResolver`] posture the MCP
//! upstream path already uses.
//!
//! The guard is two-layered on purpose, because neither layer alone is enough:
//! a hostname-only pre-check cannot see where DNS will actually land, and the
//! resolver never runs for a URL whose host is already an IP literal.

use streamscope_mcp_auth::egress::Surface;
use streamscope_mcp_auth::ssrf::Egress;
use std::collections::HashMap;
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::sync::{LazyLock, RwLock};

use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};

/// Cap on a discovery / JWKS / token response. Generous next to a real
/// document (a large JWKS is a few KiB) and small enough that a misbehaving
/// issuer cannot make an admin worker buffer without bound.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OidcHttpError {
    #[error("refused for SSRF safety: {0}")]
    Ssrf(String),
    /// No usable answer came back: the request timed out, the connection was
    /// refused or could not be routed, a body the provider started was cut
    /// short, or the provider answered 502, 503 or 504. An outage, which a retry may clear —
    /// never a refusal, a TLS fault or a name that does not resolve, which are
    /// the configuration's and stay [`OidcHttpError::Transport`]. Decided here,
    /// for every hop (discovery, keys, token), so one outage reads the same
    /// wherever it hits.
    #[error("no answer: {0}")]
    Unreachable(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("response exceeds the {0}-byte cap")]
    BodyTooLarge(usize),
    #[error("malformed response: {0}")]
    Malformed(String),
}

/// Which part of an exchange failed — the same error kind means different
/// things before and after the provider answered.
#[derive(Clone, Copy)]
enum Phase {
    /// Connecting and sending: only a connection that was never made (refused,
    /// unroutable) or a timeout is no answer. A connection reset or closed
    /// here is often the TLS handshake failing — a configuration fault.
    Request,
    /// Reading a body the provider started: a cut connection is the answer
    /// never arriving whole.
    Body,
}

/// A request or body read that failed, classified: [`OidcHttpError::Unreachable`]
/// when nothing (complete) answered, [`OidcHttpError::Transport`] otherwise.
fn transport_error(phase: Phase, e: reqwest::Error) -> OidcHttpError {
    if got_no_answer(phase, &e) {
        OidcHttpError::Unreachable(e.to_string())
    } else {
        OidcHttpError::Transport(e.to_string())
    }
}

/// Whether a request failed because nothing (complete) answered — see
/// [`OidcHttpError::Unreachable`] and [`Phase`]. Read from the error's own
/// kinds anywhere in its source chain, never its text.
fn got_no_answer(phase: Phase, e: &reqwest::Error) -> bool {
    use std::io::ErrorKind as K;
    if e.is_timeout() {
        return true;
    }
    let no_answer = |kind: K| match phase {
        Phase::Request => matches!(kind, K::ConnectionRefused | K::TimedOut | K::HostUnreachable | K::NetworkUnreachable),
        Phase::Body => matches!(
            kind,
            K::ConnectionReset | K::ConnectionAborted | K::TimedOut | K::UnexpectedEof | K::BrokenPipe
        ),
    };
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>()
            && no_answer(io.kind())
        {
            return true;
        }
        source = s.source();
    }
    false
}

/// An [`AsyncHttpClient`] over a guarded `reqwest` client.
pub struct GuardedOidcHttpClient {
    client: reqwest::Client,
    egress: Egress,
}

/// What an identity provider may be reached at: an internal address only when
/// the platform's `oidc` egress list lists it — a platform setting, never
/// per-tenant, so a tenant admin cannot point their issuer at the deployment's
/// internal network. IMDS stays refused whatever the list says.
pub(crate) const OIDC_EGRESS: Egress = Egress::Surface(Surface::Oidc);

impl GuardedOidcHttpClient {
    pub fn new() -> Self {
        Self { client: guarded_client(OIDC_EGRESS), egress: OIDC_EGRESS }
    }
}

impl Default for GuardedOidcHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl<'c> AsyncHttpClient<'c> for GuardedOidcHttpClient {
    type Error = OidcHttpError;
    // `Send + Sync` so the returned future is spawnable from an axum handler,
    // mirroring the bound the crate's own reqwest implementation carries.
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            // Layer 1 — fast-fail on an internal IP *literal*. The resolver
            // below never sees these: hyper connects straight to the address
            // without a DNS lookup, so without this check they would bypass
            // the guard entirely.
            streamscope_mcp_auth::ssrf::check_url_for(
                &request.uri().to_string(),
                self.egress,
            )
            .map_err(|e| OidcHttpError::Ssrf(e.to_string()))?;

            // Layer 2 — the resolver vets whatever DNS returns, at connect
            // time, closing the rebinding window a pre-flight lookup leaves
            // open. Redirects are refused outright by the client's policy: a
            // discovery or token endpoint answers directly, and a followed hop
            // would land somewhere neither layer vetted.
            let req: reqwest::Request = request
                .try_into()
                .map_err(|e: reqwest::Error| OidcHttpError::Transport(e.to_string()))?;
            let resp = self.client.execute(req).await.map_err(|e| transport_error(Phase::Request, e))?;
            // A gateway or availability error is the provider not answering. A
            // 500 is left to the library: some providers send a configuration
            // error (`invalid_client`) with it, which must reach the operator.
            if matches!(resp.status().as_u16(), 502..=504) {
                return Err(OidcHttpError::Unreachable(format!("the provider answered {}", resp.status())));
            }

            let mut builder = openidconnect::http::Response::builder()
                .status(resp.status())
                .version(resp.version());
            for (name, value) in resp.headers() {
                builder = builder.header(name, value);
            }
            builder
                .body(read_capped(resp).await?)
                .map_err(|e| OidcHttpError::Malformed(e.to_string()))
        })
    }
}

/// Read a response body, refusing rather than truncating past the cap —
/// a truncated JWKS or discovery document would fail later with a confusing
/// parse error instead of the real reason.
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, OidcHttpError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| transport_error(Phase::Body, e))? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(OidcHttpError::BodyTooLarge(MAX_RESPONSE_BYTES));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Process-cached clients keyed by egress posture **and trusted-CA content**,
/// so repeated logins reuse pooled connections without pinning the trust set.
///
/// Keying on the CA is what makes an operator's CA import take effect: a client
/// cached on first use would otherwise freeze whatever was trusted at the first
/// login of this process and never re-read it — nondeterministic staleness, not
/// the clean restart semantics a startup-built client has. `reqwest::Client` is
/// an `Arc` inside, so handing back a clone is cheap and keeps the pool shared.
fn guarded_client(egress: Egress) -> reqwest::Client {
    static CACHE: LazyLock<RwLock<HashMap<(Egress, u64), reqwest::Client>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    let ca = crate::custom_ca::current();
    // The egress generation too: a list change drops every pooled connection,
    // opened under the old lists.
    let fingerprint = {
        let mut h = DefaultHasher::new();
        ca.hash(&mut h);
        streamscope_mcp_auth::egress::generation(egress).hash(&mut h);
        h.finish()
    };
    let key = (egress, fingerprint);
    if let Some(client) = CACHE.read().ok().and_then(|m| m.get(&key).cloned()) {
        return client;
    }
    let client = build(egress, ca.as_deref());
    if let Ok(mut m) = CACHE.write() {
        // A CA change makes every earlier entry unreachable — drop them rather
        // than let the map grow one generation per import.
        m.retain(|(_, f), _| *f == fingerprint);
        m.insert(key, client.clone());
    }
    client
}

fn build(egress: Egress, custom_ca: Option<&str>) -> reqwest::Client {
    let settings = crate::settings::admin_settings();
    let (resolver, _handle) = streamscope_mcp_auth::ssrf::GuardedResolver::pair(egress);
    let builder = reqwest::Client::builder()
        .pool_max_idle_per_host(4)
        .timeout(settings.oidc_client_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(settings.oidc_skip_tls_verify)
        .dns_resolver(resolver);
    // The operator's trusted-CA bundle: an IdP behind a private CA is the
    // common self-hosted shape, and the E2E stack's Dex sits behind Caddy's
    // local CA.
    streamscope_core::tls::add_custom_roots(builder, custom_ca)
        .build()
        .expect("build guarded OIDC http client")
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    /// Every test installing lists installs these: `oidc` lists every private
    /// address.
    fn listed_client() -> GuardedOidcHttpClient {
        let mut lists = std::collections::BTreeMap::new();
        lists.insert("oidc".to_string(), vec!["*".to_string()]);
        streamscope_mcp_auth::egress::install(streamscope_mcp_auth::egress::Lists::from_entries(&lists).unwrap());
        GuardedOidcHttpClient::new()
    }

    fn get(uri: &str) -> HttpRequest {
        openidconnect::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(Vec::new())
            .expect("well-formed request")
    }

    async fn call(client: &GuardedOidcHttpClient, uri: &str) -> Result<HttpResponse, OidcHttpError> {
        client.call(get(uri)).await
    }

    /// IP literals never reach the resolver, so layer 1 is the only thing
    /// standing between a crafted issuer URL and the internal network.
    #[tokio::test]
    async fn refuses_internal_ip_literals() {
        let client = GuardedOidcHttpClient { client: guarded_client(Egress::PublicOnly), egress: Egress::PublicOnly };
        for uri in [
            "http://127.0.0.1/.well-known/openid-configuration",
            "http://10.0.0.5/.well-known/openid-configuration",
            "http://192.168.1.1/jwks.json",
            "http://[::1]/jwks.json",
        ] {
            assert_matches!(
                call(&client, uri).await,
                Err(OidcHttpError::Ssrf(_)),
                "{uri} must be refused"
            );
        }
    }

    /// IMDS is refused whatever the egress list says — a deployment listing
    /// every private address still must not hand an IdP the instance
    /// credentials endpoint.
    #[tokio::test]
    async fn refuses_imds_even_when_every_private_address_is_listed() {
        let client = listed_client();
        for uri in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ] {
            assert_matches!(
                call(&client, uri).await,
                Err(OidcHttpError::Ssrf(_)),
                "{uri} must be refused whatever the list says"
            );
        }
    }

    // A non-HTTP scheme is unreachable here: every URL the crate hands us is
    // built from a validated `IssuerUrl`, and `http::Request` refuses to hold
    // one anyway. The scheme rule is enforced (and tested) in the shared guard.

    /// A listed private issuer is reached, or the E2E IdP is unreachable.
    #[tokio::test]
    async fn permits_a_listed_private_issuer() {
        let client = listed_client();
        // Nothing is listening, so this fails at the transport — the point is
        // that it got past the guard rather than being refused by it.
        assert_matches!(
            call(&client, "http://10.0.0.5:9/jwks.json").await,
            Err(OidcHttpError::Transport(_) | OidcHttpError::Unreachable(_))
        );
    }

    /// A provider that is not available is no usable answer, on any hop — read
    /// here, before the library sees the status. A 4xx, and a 500 (which may
    /// carry a configuration error), are the provider's answer and are passed
    /// on (the positive controls).
    #[tokio::test]
    async fn a_server_error_is_no_answer_and_a_client_error_is_an_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let serve = |status: &'static str| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let reply = format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}");
                let _ = sock.write_all(reply.as_bytes()).await;
            });
            format!("http://{addr}/token")
        };
        let client = listed_client();
        assert_matches!(call(&client, &serve("503 Service Unavailable").await).await, Err(OidcHttpError::Unreachable(_)));
        let answered = call(&client, &serve("400 Bad Request").await).await.expect("a 4xx is an answer");
        assert_eq!(answered.status(), 400);
        let answered = call(&client, &serve("500 Internal Server Error").await).await.expect("a 500 is an answer");
        assert_eq!(answered.status(), 500);
    }

    /// A peer that accepts and then closes before answering is what a failed
    /// TLS handshake looks like (a version or SNI mismatch, plain HTTP on the
    /// TLS port): a configuration fault, never "try again".
    #[tokio::test]
    async fn a_connection_closed_before_any_answer_is_not_an_outage() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            drop(sock);
        });
        let client = listed_client();
        assert_matches!(call(&client, &format!("http://{addr}/jwks.json")).await, Err(OidcHttpError::Transport(_)));
    }

    /// A refused connection is no answer — an outage, not a configuration
    /// fault. A guard refusal beside it (above) is never one.
    #[tokio::test]
    async fn a_refused_connection_is_no_answer() {
        let client = listed_client();
        assert_matches!(call(&client, "http://127.0.0.1:1/jwks.json").await, Err(OidcHttpError::Unreachable(_)));
    }
}
