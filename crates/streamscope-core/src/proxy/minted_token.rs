//! The cache and the egress path behind every transport that mints its own
//! bearer token.
//!
//! Two transports authenticate with a short-lived OAuth token rather than a
//! stored key — Azure OpenAI via Microsoft Entra ID, and Vertex AI via a Google
//! service account. Both sit directly in front of a user request, so both need
//! the same three properties, and getting any of them wrong is invisible until
//! it is expensive:
//!
//! - **A burst costs one mint.** The per-entry mutex serialises minting for one
//!   credential; without it a cold cache under load issues one token request per
//!   in-flight request.
//! - **A token is retired before it expires**, never at the moment it does.
//! - **A degenerate lifetime cannot mean "mint every time"** — see
//!   [`usable_for`].
//!
//! The cache key is supplied by the caller and must be derived from every field
//! that changes which token comes back, so a rotated secret or a re-scoped
//! credential can never be served the previous token.
//!
//! Every mint dials its provider's token endpoint through [`post_token_form`],
//! which is the ONLY egress path a minting transport may use. The request body
//! it carries is a live credential — a client secret, or a JWT-bearer assertion
//! signed with the account's private key — so the host allowlist each transport
//! applies to its own endpoint is a first layer, never the whole guard: the
//! shared SSRF guard vets the address that host actually resolves to, at connect
//! time. A transport added later that builds its own `reqwest::Client` reopens
//! that hole silently, because a hostname allowlist looks like enough right up
//! until the deployment's DNS is what moved.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use dashmap::DashMap;

use bytes::Bytes;

use crate::error::AppError;
use crate::http_body::read_body_capped;
use streamscope_mcp_auth::egress::{Cached, Surface, egress_slot};
use streamscope_mcp_auth::ssrf::Egress;
use crate::settings::core_settings;

/// Re-mint this long before the stated expiry, so a token is never presented to
/// the provider in the seconds around its own expiry.
const REFRESH_SKEW: Duration = Duration::from_secs(300);

/// The shortest a minted token is cached for.
///
/// `expires_in` is always present in practice, but it is parsed with a default,
/// so a response omitting it would otherwise state a zero lifetime — and a
/// zero-lifetime entry means one serialized mint per request, behind the
/// per-credential mutex, each with its own request timeout. A floor turns that
/// degenerate mode into an ordinary short cache.
const MIN_TOKEN_LIFETIME: Duration = Duration::from_secs(60);

/// How long a token with the given stated lifetime is served for.
///
/// Normally the lifetime minus the refresh skew. A lifetime at or below the skew
/// would otherwise compute to zero and make every single request mint a token,
/// so a short-lived token is served for half its life instead — never less than
/// [`MIN_TOKEN_LIFETIME`].
fn usable_for(expires_in_secs: u64) -> Duration {
    let stated = Duration::from_secs(expires_in_secs);
    stated
        .checked_sub(REFRESH_SKEW)
        .filter(|d| !d.is_zero())
        .unwrap_or(stated / 2)
        .max(MIN_TOKEN_LIFETIME)
}

/// One freshly minted token, as the provider stated it.
pub struct MintedToken {
    /// The bearer value to present.
    pub value: String,
    /// The provider's stated lifetime in seconds.
    pub expires_in_secs: u64,
}

struct CachedToken {
    value: String,
    /// When this entry stops being served — already skew-adjusted.
    good_until: Instant,
}

/// One credential's cached token plus its mint lock. The lock is what makes a
/// burst of concurrent requests cost exactly one token request.
struct Entry {
    token: ArcSwapOption<CachedToken>,
    mint: tokio::sync::Mutex<()>,
}

impl Default for Entry {
    fn default() -> Self {
        Self { token: ArcSwapOption::empty(), mint: tokio::sync::Mutex::new(()) }
    }
}

/// A process-wide cache of minted tokens, keyed by credential.
pub struct MintedTokenCache {
    entries: DashMap<String, Arc<Entry>>,
}

impl Default for MintedTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl MintedTokenCache {
    pub fn new() -> Self {
        Self { entries: DashMap::new() }
    }

    /// Return a valid token for `key`, calling `mint` only if the cache holds
    /// nothing usable.
    ///
    /// `mint` runs under a per-key lock and is re-checked against the cache
    /// after acquiring it, so a concurrent caller that already refreshed is
    /// served rather than duplicated.
    pub async fn get_or_mint<F, Fut, E>(&self, key: String, mint: F) -> Result<String, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MintedToken, E>>,
    {
        let entry = self.entries.entry(key).or_default().clone();

        if let Some(tok) = entry.token.load_full()
            && Instant::now() < tok.good_until
        {
            return Ok(tok.value.clone());
        }

        // Serialize the mint per credential. Re-check inside the lock: a
        // concurrent caller may already have refreshed while this task waited.
        let _guard = entry.mint.lock().await;
        if let Some(tok) = entry.token.load_full()
            && Instant::now() < tok.good_until
        {
            return Ok(tok.value.clone());
        }

        let requested_at = Instant::now();
        let minted = mint().await?;
        let value = minted.value.clone();
        entry.token.store(Some(Arc::new(CachedToken {
            value: minted.value,
            good_until: requested_at + usable_for(minted.expires_in_secs),
        })));
        Ok(value)
    }
}

/// Why a token exchange issued no token.
///
/// The data plane reports every case alike — the inner `AppError`, which is
/// `Internal` everywhere this is built, so a client sees the same 500 whichever
/// it was. Only the admin write path tells them apart, to say "the provider
/// refused this credential" only when the provider said so.
#[derive(Debug)]
pub enum MintFailure {
    /// The token endpoint answered and refused the credential.
    Declined(AppError),
    /// No token for any other reason: the endpoint was not reached or not
    /// permitted, answered unreadably or with a server-side error, or the
    /// gateway could not build the request.
    NotIssued(AppError),
}

impl MintFailure {
    /// A token endpoint's non-2xx answer. 400, 401 and 403 are its refusal of
    /// the credential (OAuth's `invalid_client` / `invalid_grant` are 400 or
    /// 401); any other status — a 429, a 5xx — says nothing about the credential.
    pub fn from_refusal(status: reqwest::StatusCode, err: AppError) -> Self {
        if matches!(status.as_u16(), 400 | 401 | 403) { Self::Declined(err) } else { Self::NotIssued(err) }
    }

    pub fn is_declined(&self) -> bool {
        matches!(self, Self::Declined(_))
    }

    pub fn error(&self) -> &AppError {
        match self {
            Self::Declined(e) | Self::NotIssued(e) => e,
        }
    }
}

impl From<AppError> for MintFailure {
    fn from(e: AppError) -> Self {
        Self::NotIssued(e)
    }
}

impl From<MintFailure> for AppError {
    fn from(f: MintFailure) -> Self {
        match f {
            MintFailure::Declined(e) | MintFailure::NotIssued(e) => e,
        }
    }
}

/// A token response is a JWT plus a few scalars — kilobytes at most. Bounding it
/// keeps a hostile or broken endpoint from ballooning the replica's memory.
const TOKEN_BODY_CAP: u64 = 64 * 1024;

/// Total wall-clock budget for one token request. A mint sits in front of a user
/// request, so it fails fast rather than holding the caller open.
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A token endpoint answers directly. Following a 3xx would resend the form body
/// — which IS the credential — to whatever the hop names, so no hop is followed.
const TOKEN_MAX_REDIRECTS: usize = 0;

/// What token minting may reach: an internal address only when the platform's
/// `upstream_token` egress list lists it — a deployment-level decision, never a
/// per-tenant one; IMDS stays refused whatever the list says.
const TOKEN_EGRESS: Egress = Egress::Surface(Surface::UpstreamToken);

/// What one token endpoint answered, already bounded.
pub struct TokenEndpointResponse {
    pub status: reqwest::StatusCode,
    pub body: Bytes,
}

/// Process-cached guarded clients, one per egress (each surface, and
/// public-only), rebuilt when the egress lists change so no pooled connection
/// outlives the listing it was opened under. Carries the process's trusted CA
/// ([`crate::tls::trusted_ca`]) and is rebuilt when it changes, so an
/// appliance behind an inspecting proxy can still reach the provider and
/// admin-api follows a console-uploaded CA without a restart.
fn token_egress_client(egress: Egress) -> Result<reqwest::Client, AppError> {
    type Slot = Cached<reqwest::Client, (u64, Option<Arc<str>>)>;
    static SLOTS: [Slot; Surface::ALL.len() + 1] = [const { Cached::new() }; Surface::ALL.len() + 1];
    SLOTS[egress_slot(egress)].get_or_try_build_with(egress, crate::tls::trusted_ca, |ca| {
        let s = core_settings();
        crate::mcp::oauth_http::guarded_egress_builder(egress, TOKEN_MAX_REDIRECTS, ca.as_deref())
            .connect_timeout(s.upstream_connect_timeout)
            .timeout(TOKEN_REQUEST_TIMEOUT)
            .tcp_nodelay(true)
            .build()
            .map_err(|e| AppError::Internal(format!("failed to build the token egress client: {e}")))
    })
}

/// POST a form to a provider's token endpoint over the guarded egress path.
///
/// `label` names the endpoint the way an operator reading a log would ("the
/// Microsoft identity platform"), and is the only part of the failure text that
/// varies — nothing derived from the response is returned, because a token
/// endpoint's error body echoes the credential it was just handed.
pub async fn post_token_form(
    endpoint: &str,
    label: &'static str,
    form: &[(&str, &str)],
) -> Result<TokenEndpointResponse, AppError> {
    post_token_form_guarded(endpoint, label, form, TOKEN_EGRESS).await
}

/// [`post_token_form`] with the egress posture supplied rather than read, so the
/// guard can be exercised without depending on the process's environment.
async fn post_token_form_guarded(
    endpoint: &str,
    label: &'static str,
    form: &[(&str, &str)],
    egress: Egress,
) -> Result<TokenEndpointResponse, AppError> {
    // Layer 1 — an IP-literal host never reaches the resolver, because hyper
    // connects straight to the address without a DNS lookup. Layer 2 (the
    // resolver inside the client) vets what a *hostname* resolves to, at connect
    // time, which is the window a pre-flight lookup leaves open. Neither layer
    // subsumes the other.
    match streamscope_mcp_auth::ssrf::check_url_for(endpoint, egress) {
        Ok(_) => {}
        Err(streamscope_mcp_auth::ssrf::SsrfError::InternalAddress) => {
            tracing::error!(label, "token endpoint refused for SSRF safety");
            return Err(AppError::EgressRefused(format!("{label} is not a permitted egress target")));
        }
        Err(e) => {
            tracing::error!(error = %e, label, "token endpoint URL unusable");
            return Err(AppError::Internal(format!("{label} has no usable address")));
        }
    }

    let resp = token_egress_client(egress)?
        .post(endpoint)
        .form(form)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, label, "token request failed");
            if streamscope_mcp_auth::ssrf::refusal(&e).is_some() {
                AppError::EgressRefused(format!("{label} is not a permitted egress target"))
            } else {
                AppError::Internal(format!("could not reach {label}"))
            }
        })?;

    let status = resp.status();
    let body = read_body_capped(resp, TOKEN_BODY_CAP).await.map_err(|e| {
        tracing::error!(error = %e, label, "reading token response");
        AppError::Internal(format!("unreadable response from {label}"))
    })?;
    Ok(TokenEndpointResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Only the endpoint's refusal of the credential is a decline; a status that
    /// is the endpoint's own trouble (or no answer about the key) is not.
    #[test]
    fn only_a_refusal_of_the_credential_is_a_decline() {
        let classify = |code: u16| {
            MintFailure::from_refusal(reqwest::StatusCode::from_u16(code).unwrap(), AppError::Internal("x".into()))
                .is_declined()
        };
        for code in [400, 401, 403] {
            assert!(classify(code), "{code} refuses the credential");
        }
        for code in [399, 402, 404, 408, 429, 500, 502, 503, 504] {
            assert!(!classify(code), "{code} says nothing about the credential");
        }
        assert!(!MintFailure::from(AppError::Internal("could not reach".into())).is_declined());
    }

    #[test]
    fn a_normal_lifetime_is_served_minus_the_refresh_skew() {
        assert_eq!(usable_for(3600), Duration::from_secs(3600 - 300));
    }

    /// A lifetime at or below the skew must not compute to zero — that would
    /// mint a token per request, serialized behind the per-credential lock.
    #[test]
    fn a_short_lifetime_never_computes_to_zero() {
        for stated in [0, 1, 60, 120, 300, 301] {
            let usable = usable_for(stated);
            assert!(usable >= MIN_TOKEN_LIFETIME, "stated {stated}s served for {usable:?}");
        }
        // At or below the skew it is half the stated life, floored.
        assert_eq!(usable_for(300), Duration::from_secs(150));
        assert_eq!(usable_for(60), MIN_TOKEN_LIFETIME);
        assert_eq!(usable_for(0), MIN_TOKEN_LIFETIME);
        // Above the skew the ordinary rule applies, and an absurd lifetime must
        // not overflow the arithmetic.
        assert_eq!(usable_for(3000), Duration::from_secs(2700));
        assert_eq!(usable_for(3599), Duration::from_secs(3299));
        assert!(usable_for(u64::MAX) >= MIN_TOKEN_LIFETIME);
    }

    #[tokio::test]
    async fn a_cached_token_is_reused_and_a_distinct_key_is_not() {
        let cache = MintedTokenCache::new();
        let mints = AtomicUsize::new(0);
        let mint = |v: &'static str| {
            let n = &mints;
            async move {
                n.fetch_add(1, Ordering::SeqCst);
                Ok::<_, AppError>(MintedToken { value: v.to_string(), expires_in_secs: 3600 })
            }
        };

        assert_eq!(cache.get_or_mint("a".into(), || mint("tok-a")).await.unwrap(), "tok-a");
        assert_eq!(cache.get_or_mint("a".into(), || mint("other")).await.unwrap(), "tok-a");
        assert_eq!(mints.load(Ordering::SeqCst), 1, "a cached token must not be re-minted");

        assert_eq!(cache.get_or_mint("b".into(), || mint("tok-b")).await.unwrap(), "tok-b");
        assert_eq!(mints.load(Ordering::SeqCst), 2, "a distinct credential mints its own token");
    }

    /// `upstream_token` lists every private address (`crate::test_egress`).
    fn listed() -> Egress {
        crate::test_egress::install();
        TOKEN_EGRESS
    }

    /// The guard is exercised with the egress passed in, so these assert the
    /// guard itself.
    ///
    /// Port 9 (discard) is deliberate: nothing listens, so a request that gets
    /// PAST the guard fails with a transport error and a DIFFERENT message. That
    /// is what separates "refused" from "merely unreachable" — an assertion that
    /// the call simply failed would pass with no guard at all.
    #[tokio::test]
    async fn an_internal_target_is_refused_under_the_strict_posture() {
        let refused = post_token_form_guarded("https://127.0.0.1:9/token", "the test endpoint", &[], Egress::PublicOnly)
            .await
            .err()
            .expect("an internal literal must not receive a credential");
        assert!(
            matches!(&refused, AppError::EgressRefused(m) if m.contains("not a permitted egress target")),
            "expected an SSRF refusal, got: {refused}"
        );

        // Same address, listed: the guard steps aside and the call
        // gets far enough to fail on the socket instead.
        let unreachable = post_token_form_guarded("https://127.0.0.1:9/token", "the test endpoint", &[], listed())
            .await
            .err()
            .expect("nothing listens on the discard port");
        assert!(
            format!("{unreachable}").contains("could not reach"),
            "expected a transport failure, got: {unreachable}"
        );
    }

    /// IMDS is off-limits on every posture. A minting transport runs on the same
    /// box as the cloud metadata service on all three major clouds, and an
    /// operator who opened internal egress to reach a private stand-in did not
    /// thereby agree to hand out instance credentials.
    #[tokio::test]
    async fn imds_is_refused_even_when_internal_egress_is_permitted() {
        for target in ["https://169.254.169.254/token", "https://[fd00:ec2::254]/token"] {
            // `TokenEndpointResponse` carries a live token, so it deliberately
            // has no `Debug` — hence `.err()` rather than `expect_err`.
            let refused = post_token_form_guarded(target, "the test endpoint", &[], listed())
                .await
                .err()
                .unwrap_or_else(|| panic!("{target} must be refused"));
            assert!(
                matches!(&refused, AppError::EgressRefused(m) if m.contains("not a permitted egress target")),
                "expected an SSRF refusal for {target}, got: {refused}"
            );
        }
    }

    /// A one-connection-at-a-time HTTP/1.1 server on loopback, answering every
    /// request with `reply`. Returns its port and a task handle.
    ///
    /// It exists so the resolver and the redirect policy can be exercised against
    /// a real socket: both only run for a *hostname* target, and both are
    /// invisible to any assertion that stops at "the request failed".
    async fn loopback_server(replies: &'static [&'static str]) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let mut n = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                // Replies are served in order, repeating the last — so a
                // redirect can be answered ONCE and then succeed. A server that
                // redirected forever would fail the request through the hop
                // limit whatever the limit was set to, which would make the
                // redirect assertion below pass with the policy removed.
                let reply = replies[n.min(replies.len() - 1)];
                n += 1;
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        (port, handle)
    }

    /// The IP-literal layer cannot see a *hostname* that resolves internal —
    /// hyper looks that one up, so only the resolver inside the client catches
    /// it. Asserted against a socket that really answers, so the permissive run
    /// SUCCEEDS: a test that merely expected failure would pass with the whole
    /// guard deleted, since the strict run fails either way.
    #[tokio::test]
    async fn a_hostname_resolving_internal_is_refused_by_the_resolver() {
        let (port, server) =
            loopback_server(&["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]).await;
        let url = format!("http://localhost:{port}/token");

        let served = post_token_form_guarded(&url, "the test endpoint", &[], listed())
            .await
            .unwrap_or_else(|e| panic!("the permissive posture must reach it: {e}"));
        assert_eq!(served.status, 200);
        assert_eq!(served.body.as_ref(), b"ok");

        let refused = post_token_form_guarded(&url, "the test endpoint", &[], Egress::PublicOnly)
            .await
            .err()
            .expect("`localhost` resolves internal — the resolver must refuse it");
        assert!(
            matches!(&refused, AppError::EgressRefused(m) if m.contains("not a permitted egress target")),
            "expected the resolver's typed refusal, got: {refused}"
        );
        server.abort();
    }

    /// A token endpoint answers directly. Following a 3xx would resend the form
    /// body — which IS the credential — to whatever the hop names.
    #[tokio::test]
    async fn a_redirect_from_a_token_endpoint_is_not_followed() {
        let (port, server) = loopback_server(&[
            "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ])
        .await;
        let refused = post_token_form_guarded(
            &format!("http://localhost:{port}/token"),
            "the test endpoint",
            &[("client_secret", "s3cr3t")],
            listed(),
        )
        .await
        .err()
        .expect("a redirect must not carry the credential to a second hop");
        assert!(
            format!("{refused}").contains("could not reach"),
            "expected the hop to be refused, got: {refused}"
        );
        server.abort();
    }

    /// A failed mint must not poison the entry: the next request tries again
    /// rather than being served a stale or empty value.
    #[tokio::test]
    async fn a_failed_mint_is_retried_on_the_next_request() {
        let cache = MintedTokenCache::new();
        let err = cache
            .get_or_mint("k".into(), || async { Err(AppError::Internal("boom".into())) })
            .await;
        assert!(err.is_err());
        let ok = cache
            .get_or_mint("k".into(), || async {
                Ok::<_, AppError>(MintedToken { value: "tok".into(), expires_in_secs: 3600 })
            })
            .await;
        assert_eq!(ok.unwrap(), "tok");
    }
}
