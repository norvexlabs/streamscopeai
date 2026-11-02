//! Talking to a third-party IdP's token endpoint on a user's behalf.
//!
//! Two hops use this: the authorization-code exchange (admin-api, when a user
//! connects an upstream MCP server) and the refresh-token grant (proxy, when
//! that user's access token has aged out). Both ship the user's credentials —
//! authorization code, refresh token, and the operator's `client_secret` — to
//! an operator-configured URL, so both run over an SSRF-guarded transport.
//!
//! The `oauth2` crate builds the request and parses the response; everything
//! about *how* the bytes travel is ours. Its bundled reqwest transport caps no
//! body and applies no egress guard, which is why [`GuardedOauthHttpClient`]
//! exists.
//!
//! The guard is two-layered on purpose, because neither layer alone is enough:
//! a hostname-only pre-check cannot see where DNS will actually land, and the
//! resolver never runs for a URL whose host is already an IP literal.
//!
//! Revocation deliberately does **not** go through `oauth2`. It is a
//! fire-and-forget POST whose response we discard, so the crate would
//! contribute only an https-only check that is wrong for an operator whose IdP
//! sits on a private network it listed on the `mcp` egress list.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use oauth2::{AsyncHttpClient, HttpRequest, HttpResponse};

/// Cap on a token-endpoint response. A real one is a few hundred bytes; this
/// is generous enough for an IdP that inlines an ID token and small enough
/// that a hostile one cannot make a worker buffer without bound.
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum OauthHttpError {
    #[error("refused for SSRF safety: {0}")]
    Ssrf(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("response exceeds the {0}-byte cap")]
    BodyTooLarge(usize),
    #[error("malformed response: {0}")]
    Malformed(String),
}

use streamscope_mcp_auth::ssrf::Egress;

/// An [`AsyncHttpClient`] over a guarded `reqwest` client.
///
/// The client is supplied by the caller rather than built here: the proxy
/// hands over its process-cached MCP egress client (pooled connections, env
/// CA bundle) while admin-api builds one per call so a live custom-CA change
/// is picked up. Cloning is cheap — `reqwest::Client` is internally an `Arc`.
pub struct GuardedOauthHttpClient {
    client: reqwest::Client,
    egress: Egress,
    /// Per-call deadline. Applied to the converted request rather than baked
    /// into the client, so a shared pooled client can still serve callers with
    /// different per-upstream timeouts.
    timeout: Option<Duration>,
}

impl GuardedOauthHttpClient {
    pub fn new(client: reqwest::Client, egress: Egress, timeout: Option<Duration>) -> Self {
        Self { client, egress, timeout }
    }
}

impl<'c> AsyncHttpClient<'c> for GuardedOauthHttpClient {
    type Error = OauthHttpError;
    // `Send + Sync` so the returned future is spawnable from an axum handler.
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            // Layer 1 — fast-fail on an internal IP *literal*. The resolver
            // below never sees these: hyper connects straight to the address
            // without a DNS lookup, so without this check they would bypass
            // the guard entirely. IMDS is refused inside the shared guard
            // whatever the egress list says.
            streamscope_mcp_auth::ssrf::check_url_for(
                &request.uri().to_string(),
                self.egress,
            )
            .map_err(|e| OauthHttpError::Ssrf(e.to_string()))?;

            // Layer 2 — the resolver vets whatever DNS returns, at connect
            // time, closing the rebinding window a pre-flight lookup leaves
            // open. The caller's client also bounds redirects; a token
            // endpoint answers directly, and a followed hop would land
            // somewhere neither layer vetted.
            let mut req: reqwest::Request = request
                .try_into()
                .map_err(|e: reqwest::Error| OauthHttpError::Transport(e.to_string()))?;
            *req.timeout_mut() = self.timeout;

            let resp = self
                .client
                .execute(req)
                .await
                .map_err(|e| OauthHttpError::Transport(e.to_string()))?;

            // The `oauth2` error vocabulary keeps the RFC 6749 error code but
            // not the HTTP status, and an IdP behind a broken load balancer
            // answers with neither (a 503 HTML page). Log the status here so
            // that case stays diagnosable — the body is deliberately NOT
            // logged, since it is exactly where an echoed credential would be.
            if !resp.status().is_success() {
                tracing::warn!(
                    status = %resp.status(),
                    host = resp.url().host_str().unwrap_or("?"),
                    "upstream OAuth token endpoint returned a non-success status"
                );
            }

            let mut builder = oauth2::http::Response::builder()
                .status(resp.status())
                .version(resp.version());
            for (name, value) in resp.headers() {
                builder = builder.header(name, value);
            }
            let body = crate::http_body::read_body_capped(resp, MAX_TOKEN_RESPONSE_BYTES as u64)
                .await
                .map_err(|e| match e {
                    crate::http_body::CappedReadError::Oversized { .. } => {
                        OauthHttpError::BodyTooLarge(MAX_TOKEN_RESPONSE_BYTES)
                    }
                    crate::http_body::CappedReadError::Transport(t) => {
                        OauthHttpError::Transport(t.to_string())
                    }
                })?;
            builder
                .body(body.to_vec())
                .map_err(|e| OauthHttpError::Malformed(e.to_string()))
        })
    }
}

/// A `reqwest` client builder carrying the shared MCP egress guard: the
/// connect-time resolver, a bounded redirect policy that re-vets every hop,
/// and the caller's trusted-CA bundle.
///
/// `custom_ca` is a parameter rather than a lookup because the two callers
/// legitimately differ: the proxy has no admin DB and reads the env bundle,
/// while admin-api resolves the platform override (DB, env fallback). Picking
/// one here would silently narrow trust for the other.
///
/// Callers add their own deadline shape (one total timeout for a
/// request/response call, a ceiling plus idle bound for a long-lived stream)
/// and their own connection-pool sizing.
///
/// **Invariant to preserve when updating this:** the resolver and the redirect
/// policy must stay paired. Dropping either one leaves a client that looks
/// guarded and is not — the resolver alone still follows a 3xx to an internal
/// address, and the policy alone cannot see a DNS rebind.
pub fn guarded_egress_builder(
    egress: Egress,
    max_redirects: usize,
    custom_ca: Option<&str>,
) -> reqwest::ClientBuilder {
    let (resolver, _handle) = streamscope_mcp_auth::ssrf::GuardedResolver::pair(egress);
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > max_redirects {
            return attempt.error(format!("redirect limit ({max_redirects}) exceeded"));
        }
        // Never down to plain http: the hop would carry the same credentials
        // in clear to wherever it points.
        if attempt.url().scheme() == "http" && attempt.previous().iter().any(|u| u.scheme() == "https") {
            let target = attempt.url().to_string();
            return attempt.error(streamscope_mcp_auth::ssrf::DowngradeRefused(target));
        }
        if streamscope_mcp_auth::ssrf::redirect_target_is_internal_ip_literal(
            attempt.url(),
            egress,
        ) {
            // Typed, so a caller tells a policy refusal from an upstream that
            // did not answer (`ssrf::refusal`).
            let target = attempt.url().to_string();
            return attempt.error(streamscope_mcp_auth::ssrf::AddressRefused(format!("redirect to {target}")));
        }
        attempt.follow()
    });
    let builder = reqwest::Client::builder().redirect(policy).dns_resolver(resolver);
    crate::tls::add_custom_roots(builder, custom_ca)
}

/// A guarded client for admin-api's outbound MCP/OAuth calls.
///
/// Admin-api builds these per user-triggered action rather than caching one,
/// so a live custom-CA change takes effect without a restart. The proxy, whose
/// egress is hot-path, keeps its own process-cached clients on top of
/// [`guarded_egress_builder`] instead.
pub fn build_guarded_client(
    egress: Egress,
    custom_ca: Option<&str>,
    timeout: Option<Duration>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = guarded_egress_builder(egress, 3, custom_ca);
    if let Some(t) = timeout {
        builder = builder.timeout(t);
    }
    builder.build()
}

/// Strip any echo of the credentials we submitted out of an error string
/// before it reaches an audit record, a log line, or a user-visible redirect.
///
/// A hostile or merely careless IdP can reflect the `refresh_token`,
/// authorization `code`, or `client_secret` it just received straight back in
/// an `error_description`. Every one of those is a live credential at the
/// moment it is echoed.
///
/// Empty secrets are skipped — replacing `""` would shred the string.
pub fn redact_oauth_secrets(s: &str, secrets: &[&str]) -> String {
    let mut out = s.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            out = out.replace(secret, "<REDACTED>");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    /// `mcp` lists every private address (`crate::test_egress`).
    fn list_every_private_address() -> Egress {
        crate::test_egress::install();
        Egress::Surface(streamscope_mcp_auth::egress::Surface::Mcp)
    }

    fn client(egress: Egress) -> GuardedOauthHttpClient {
        GuardedOauthHttpClient::new(
            guarded_egress_builder(egress, 3, None)
                .build()
                .expect("build guarded client"),
            egress,
            Some(Duration::from_secs(5)),
        )
    }

    fn post(uri: &str) -> HttpRequest {
        oauth2::http::Request::builder()
            .method("POST")
            .uri(uri)
            .body(b"grant_type=refresh_token".to_vec())
            .expect("well-formed request")
    }

    /// IP literals never reach the resolver, so layer 1 is the only thing
    /// standing between a crafted token URL and the internal network.
    #[tokio::test]
    async fn refuses_internal_ip_literals() {
        let c = client(Egress::PublicOnly);
        for uri in [
            "http://127.0.0.1/token",
            "http://10.0.0.5/token",
            "http://192.168.1.1/token",
            "http://[::1]/token",
        ] {
            assert_matches!(
                c.call(post(uri)).await,
                Err(OauthHttpError::Ssrf(_)),
                "{uri} must be refused"
            );
        }
    }

    /// IMDS is refused whatever the egress list says — a deployment listing
    /// every private address still must not ship a client_secret to the
    /// instance credentials endpoint.
    #[tokio::test]
    async fn refuses_imds_even_when_every_private_address_is_listed() {
        let c = client(list_every_private_address());
        for uri in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
        ] {
            assert_matches!(
                c.call(post(uri)).await,
                Err(OauthHttpError::Ssrf(_)),
                "{uri} must be refused whatever the list says"
            );
        }
    }

    /// A listed private address is reached, or the E2E mock upstream is
    /// unreachable.
    #[tokio::test]
    async fn permits_a_listed_private_address() {
        // Nothing is listening, so this fails at the transport — the point is
        // that it got past the guard rather than being refused by it. The
        // short deadline bounds the case where the address is filtered rather
        // than refused, so the test cannot hang a build.
        let egress = list_every_private_address();
        let c = GuardedOauthHttpClient::new(
            guarded_egress_builder(egress, 3, None).build().expect("build guarded client"),
            egress,
            Some(Duration::from_secs(2)),
        );
        assert_matches!(
            c.call(post("http://10.0.0.5:9/token")).await,
            Err(OauthHttpError::Transport(_))
        );
    }

    #[test]
    fn redaction_removes_every_supplied_secret() {
        let msg = "bad grant for rt_abc using secret sk_xyz";
        let out = redact_oauth_secrets(msg, &["rt_abc", "sk_xyz"]);
        assert_eq!(out, "bad grant for <REDACTED> using secret <REDACTED>");
    }

    /// An empty secret must not match — `str::replace` with `""` splices the
    /// marker between every character, destroying the message.
    #[test]
    fn redaction_ignores_empty_secrets() {
        assert_eq!(redact_oauth_secrets("plain message", &["", ""]), "plain message");
    }

    #[test]
    fn redaction_handles_a_secret_echoed_more_than_once() {
        let out = redact_oauth_secrets("rt_abc then rt_abc again", &["rt_abc"]);
        assert_eq!(out, "<REDACTED> then <REDACTED> again");
    }
}
