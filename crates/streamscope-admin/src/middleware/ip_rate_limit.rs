//! Per-source-IP request limiter for the unauthenticated pre-auth surfaces.
//!
//! Caps total requests per client IP per window across login, account setup,
//! OIDC/OAuth exchange, invite acceptance, tenant auth-info, and the MCP-OAuth
//! metadata/grant/register flow. The per-account login limiter keys on
//! `tenant_slug:email`, so an attacker who varies the email (or `client_id`) on
//! every request gets a fresh key each time and never trips it; this layer
//! bounds them by source IP regardless of the identity string, and with them the
//! `security_audit` volume their attempts can drive.
//!
//! The throttle reuses the shared `RateLimiter` and resolves the client IP through
//! [`extract_client_ip`] under the configured `TRUSTED_PROXY_HOPS` trust model —
//! without that an attacker could spoof `X-Forwarded-For` for a fresh limiter key
//! per request. It is mounted as the OUTERMOST pre-auth layer, so a throttled
//! flood is rejected before `security_audit_mw` buffers the body or writes a row
//! — no audit amplification. The rejection still carries the `rate_limit_exceeded`
//! code for client/UI consistency with the other rate-limit responses.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use streamscope_core::middleware::ip_rate_limit::{extract_client_ip, limiter_key};
use crate::routes::ApiError;
use crate::AdminState;

/// Header on which the browser tier (admin-ui's server) proves, on every call
/// it makes to this API, that the request is its own. The browser tier relays
/// no browser header of this name. Keep the name, and [`BROWSER_TIER_PROOF_DOMAIN`],
/// identical to `admin-ui/src/lib/server/client-address.ts` —
/// the `lint-admin-fetch.sh` lint fails when they differ.
pub const BROWSER_TIER_HEADER: &str = "x-streamscope-browser-tier";

/// Domain separator of the browser-tier proof.
pub const BROWSER_TIER_PROOF_DOMAIN: &str = "streamscope-browser-tier-hop";

/// The value the browser tier presents: a one-way derivation of
/// `INTERNAL_SERVICE_SECRET`, never the secret itself. It rides every console
/// request, so it is the header most likely to reach an access log; a leaked
/// proof lets its holder choose a limiter key and an audit address, while the
/// secret also opens the sign-in exchanges. `None` when no secret is
/// configured: nothing then proves anything.
pub fn browser_tier_proof(internal_service_secret: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    if internal_service_secret.is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(BROWSER_TIER_PROOF_DOMAIN.as_bytes());
    h.update([0u8]);
    h.update(internal_service_secret.as_bytes());
    Some(hex::encode(h.finalize()))
}

static BROWSER_TIER_PROOF: std::sync::LazyLock<Option<String>> = std::sync::LazyLock::new(|| {
    browser_tier_proof(&std::env::var("INTERNAL_SERVICE_SECRET").unwrap_or_default())
});

/// The client address a request is attributed to — the key of every per-IP
/// limiter and the `actor_ip` of every audit row. Every admin-api consumer
/// resolves it here, never through core `extract_client_ip` directly.
///
/// `TRUSTED_PROXY_HOPS` counts the proxies in front of the deployment, which is
/// the whole chain for a request reaching this API directly. A request relayed
/// by the browser tier crossed one more: that tier appends the address it was
/// reached from to `X-Forwarded-For`, exactly as a reverse proxy does, and so is
/// counted as one more trusted hop — but only when it proves itself. Without the
/// proof every console request would be attributed to the browser tier's own
/// address, so every user would share one limiter bucket.
///
/// This assumes the console is reached through the same number of proxies as
/// this API. A deployment adding a proxy in front of the console only (an
/// authenticating proxy under header auth) reads one entry short.
pub fn client_ip(headers: &HeaderMap, extensions: &axum::http::Extensions) -> Option<std::net::IpAddr> {
    client_ip_with(
        headers,
        extensions,
        streamscope_core::settings::core_settings().trusted_proxy_hops,
        BROWSER_TIER_PROOF.as_deref(),
    )
}

fn client_ip_with(
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    trusted_proxy_hops: u32,
    browser_tier_proof: Option<&str>,
) -> Option<std::net::IpAddr> {
    let from_browser_tier = browser_tier_proof.is_some_and(|proof| {
        headers.get(BROWSER_TIER_HEADER).is_some_and(|v| {
            subtle::ConstantTimeEq::ct_eq(v.as_bytes(), proof.as_bytes()).into()
        })
    });
    let hops = if from_browser_tier {
        trusted_proxy_hops.saturating_add(1)
    } else {
        trusted_proxy_hops
    };
    extract_client_ip(headers, extensions, hops)
}

pub async fn pre_auth_ip_rate_limit_mw(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let limiter = &state.pre_auth_ip_rate_limiter;
    // max_attempts == 0 disables the limiter (the construction divides the cap by
    // the instance count, and the raw setting can be set to 0 to turn it off).
    if limiter.max_attempts() > 0
        && let Some(ip) = client_ip(req.headers(), req.extensions())
        && limiter.check_rate_limit(&limiter_key(ip))
    {
        tracing::warn!(%ip, "pre-auth request rate limited by source IP");
        return ApiError::too_many_requests("too many requests — try again later").into_response();
    }
    next.run(req).await
}

/// The pre-auth cap on `/portal/auth/header-me`, except under header auth.
///
/// One route, two roles: under `AUTH_MODE=header` it is the portal's per-request
/// session check, which the browser tier calls for every portal request and a
/// cap sized for anonymous traffic would throttle; under standard auth it is the
/// secret-gated claim exchange, which mints sessions for named users and keeps
/// the cap.
pub async fn claim_exchange_ip_rate_limit_mw(
    state: State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    if !claim_exchange_is_capped(crate::routes::admin_auth::auth_mode()) {
        return next.run(req).await;
    }
    pre_auth_ip_rate_limit_mw(state, req, next).await
}

/// Whether `/portal/auth/header-me` carries the pre-auth cap under `mode`.
fn claim_exchange_is_capped(mode: crate::routes::admin_auth::AuthMode) -> bool {
    !matches!(mode, crate::routes::admin_auth::AuthMode::Header)
}

/// The `ak-` automation key this request presents, if it presents one.
///
/// Only that family enters the tenant-resolve scan; a JWT session is verified
/// by signature and costs nothing to reject, so it is deliberately out of scope
/// here — see [`automation_key_ip_rate_limit_mw`] for why that matters.
pub(crate) fn presented_automation_key(headers: &HeaderMap) -> Option<&str> {
    crate::routes::bearer_token(headers)
        .ok()
        .filter(|v| v.starts_with("ak-"))
}

/// How many DISTINCT automation keys a single source may fail to authenticate
/// with, per window.
///
/// Counting *distinct keys* rather than raw failures is what separates the two
/// populations. A prober's whole method is to vary the token, so every attempt
/// adds one; a misconfigured client repeats one revoked or mistyped key forever,
/// so it contributes exactly one however long it runs — and a NAT'd site is not
/// throttled as a whole because one of its clients is broken.
///
/// It also removes the need to clear the count on a successful call, which was
/// the tempting shape and the wrong one: `ak-` resolution scans **every** tenant
/// (`automation_keys` is FORCE-RLS, so a key can only be read inside its own
/// tenant's context), which makes one guess a guess at every tenant at once. On
/// a multi-tenant deployment the attacker can hold a perfectly valid key of
/// their own — they need only be a customer — and interleaving one valid call
/// per window would have kept the counter permanently clear while they probed
/// everybody else's.
pub struct DistinctKeyFailures {
    max: u32,
    window: Duration,
    cleanup_threshold: usize,
    /// source → (key hashes seen failing, window start).
    sources: Mutex<HashMap<String, (HashSet<String>, Instant)>>,
}

impl DistinctKeyFailures {
    pub fn new(max: u32, window_secs: u64, cleanup_threshold: usize, instance_count: u32) -> Self {
        // Divided per instance like every other admin-side limiter, and never
        // truncated from a nonzero cap to 0 — 0 means "disabled", so that would
        // silently turn the limiter off rather than tighten it.
        let per = max / instance_count.max(1);
        let per = if max > 0 { per.max(1) } else { 0 };
        Self {
            max: per,
            window: Duration::from_secs(window_secs),
            cleanup_threshold,
            sources: Mutex::new(HashMap::new()),
        }
    }

    /// Configured cap. `0` disables the limiter — callers must short-circuit,
    /// since every source is trivially at a cap of 0.
    pub fn max(&self) -> u32 {
        self.max
    }

    /// Has this source already failed with `max` distinct keys this window?
    /// Does not count the current request.
    pub fn is_limited(&self, source: &str) -> bool {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if sources.len() > self.cleanup_threshold {
            sources.retain(|_, (_, started)| now.duration_since(*started) < self.window);
        }
        sources
            .get(source)
            .is_some_and(|(keys, started)| {
                now.duration_since(*started) < self.window && keys.len() as u32 >= self.max
            })
    }

    /// Record that `key_hash` failed to authenticate from `source`.
    pub fn record(&self, source: &str, key_hash: &str) {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let entry = sources
            .entry(source.to_string())
            .or_insert_with(|| (HashSet::new(), now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (HashSet::new(), now);
        }
        // Stop growing once the source is limited: the set is the counter, so
        // beyond the cap it holds no more information and would otherwise be an
        // unbounded, attacker-chosen allocation.
        if (entry.0.len() as u32) < self.max {
            entry.0.insert(key_hash.to_string());
        }
    }
}

/// Response extension the auth layer sets on its 503 for an `ak-` key it could
/// not look up (the database did not answer). The per-source throttle charges
/// it like the refusal the request would otherwise have been: the probe cost a
/// tenant scan either way, and an uncharged 503 would leave a prober who keeps
/// the pool saturated unthrottled. A handler's own 503 carries no marker — that
/// caller's key authenticated — and is never charged.
#[derive(Clone, Copy, Debug)]
pub struct AutomationKeyUnverified;

impl AutomationKeyUnverified {
    /// The auth layer's answer for an `ak-` key it could not check, marked so
    /// the throttle charges it when it is the 503 of a database that could not
    /// be asked. A 500 (a server fault) is not marked: a client must not be
    /// throttled for the server's defect. Every `ak-` entry point answers
    /// through this, so none can forget the marker.
    pub fn response(err: ApiError) -> Response {
        let unavailable = err.status == StatusCode::SERVICE_UNAVAILABLE;
        let mut resp = err.into_response();
        if unavailable {
            resp.extensions_mut().insert(Self);
        }
        resp
    }
}

/// Per-source throttle on **failed** `ak-` authentications, for the guarded
/// admin and portal routers.
///
/// The per-key limiter (`automation_key_rate_limiter`) bounds repetition of ONE
/// key — the leaked-key case. It is no help against a prober, who varies the
/// token and draws a fresh bucket every single time; each attempt then runs the
/// full O(tenants) resolve scan. This layer bounds the *source* instead, and is
/// mounted OUTSIDE the auth middleware so a throttled prober is rejected before
/// any of that work happens. Inside it the throttle would still fire, but only
/// after paying for the work it exists to prevent.
///
/// Three narrowings keep it off legitimate traffic, each load-bearing:
///
/// 1. **Only `ak-` requests are considered.** A JWT session is verified by
///    signature and costs nothing to reject; counting session 401s would let one
///    expired tab throttle everybody sharing its address.
/// 2. **Only a key the auth layer did not accept counts** — a 401, or a 503
///    marked [`AutomationKeyUnverified`]. A 403 means the caller authenticated
///    and was denied by authorization — a read-only account clicking around
///    must never accumulate toward a lockout.
/// 3. **Distinct keys are counted, not attempts** — see [`DistinctKeyFailures`]
///    for why that is the property worth counting, and why clearing the tally on
///    a successful call would have been unsound.
pub async fn automation_key_ip_rate_limit_mw(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let limiter = &state.automation_key_ip_rate_limiter;
    let Some(key) = presented_automation_key(req.headers()) else {
        return next.run(req).await;
    };
    // A cap of 0 disables the limiter; every source is trivially at a cap of 0.
    if limiter.max() == 0 {
        return next.run(req).await;
    }
    // No attributable source (no `ConnectInfo`, no trusted forwarding header)
    // means no bucket to charge — pass through, as the pre-auth limiter does.
    let Some(ip) = client_ip(req.headers(), req.extensions()) else {
        return next.run(req).await;
    };
    let source = limiter_key(ip);

    if limiter.is_limited(&source) {
        tracing::warn!(%ip, "automation-key authentication throttled by source");
        return ApiError::too_many_requests("too many failed authentications — try again later")
            .into_response();
    }

    // Hashed before the handler runs, so no plaintext credential is held across
    // it. The same hash the auth path computes, so the two agree on identity.
    let key_hash = streamscope_core::auth::virtual_key::hash_key(key);

    let resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED
        || resp.extensions().get::<AutomationKeyUnverified>().is_some()
    {
        limiter.record(&source, &key_hash);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_ak_family_is_in_scope() {
        let mut h = HeaderMap::new();
        assert!(
            presented_automation_key(&h).is_none(),
            "no header is not automation traffic"
        );

        for (value, expected) in [
            ("Bearer ak-abc123", Some("ak-abc123")),
            // A JWT session: verified by signature, no tenant scan behind it.
            ("Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig", None),
            // Proxy data-plane keys never reach the control plane's routers.
            ("Bearer sk-abc123", None),
            ("Bearer vk-abc123", None),
            // The scheme is part of the shape — a bare key is not a bearer.
            ("ak-abc123", None),
            // Nothing after the scheme.
            ("Bearer ", None),
        ] {
            h.insert("authorization", value.parse().expect("header value"));
            assert_eq!(
                presented_automation_key(&h),
                expected,
                "{value:?} classified wrongly"
            );
        }
    }

    fn relayed(
        xff: Option<&str>,
        proof: Option<&str>,
    ) -> (HeaderMap, axum::http::Extensions) {
        let mut h = HeaderMap::new();
        if let Some(v) = xff {
            h.insert("x-forwarded-for", v.parse().expect("header value"));
        }
        if let Some(v) = proof {
            h.insert(BROWSER_TIER_HEADER, v.parse().expect("header value"));
        }
        let mut ext = axum::http::Extensions::new();
        // The browser tier's own address, as the TCP peer of its calls.
        ext.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [172, 18, 0, 5],
            40000,
        ))));
        (h, ext)
    }

    fn ip(s: &str) -> Option<std::net::IpAddr> {
        Some(s.parse().expect("ip"))
    }

    /// A proven browser-tier call is attributed to the address the tier was
    /// reached from, under both deployment topologies — so two users of the
    /// console land in two limiter buckets, not the tier's one.
    #[test]
    fn a_proven_browser_tier_call_is_attributed_to_its_client() {
        // Loopback shape (0 hops): the tier appends the browser's address.
        let (h, e) = relayed(Some("203.0.113.7"), Some("proof"));
        assert_eq!(client_ip_with(&h, &e, 0, Some("proof")), ip("203.0.113.7"));

        // One front proxy: it wrote the client, the tier appended the proxy.
        let (h, e) = relayed(Some("203.0.113.7, 172.18.0.2"), Some("proof"));
        assert_eq!(client_ip_with(&h, &e, 1, Some("proof")), ip("203.0.113.7"));
    }

    /// A browser can still prepend anything to the chain; only the entries the
    /// trusted hops wrote are read.
    #[test]
    fn a_forged_leading_entry_is_not_read_through_the_browser_tier() {
        let (h, e) = relayed(Some("198.51.100.66, 203.0.113.7"), Some("proof"));
        assert_eq!(client_ip_with(&h, &e, 0, Some("proof")), ip("203.0.113.7"));
    }

    /// Without the proof the extra hop is not granted: a direct caller cannot
    /// pick its own limiter key by claiming to be the browser tier.
    #[test]
    fn the_extra_hop_needs_the_proof() {
        let peer = ip("172.18.0.5");
        for (presented, expected) in [
            (None, Some("proof")),
            (Some("wrong"), Some("proof")),
            // No secret configured: nothing proves anything, not even "".
            (Some(""), None),
        ] {
            let (h, e) = relayed(Some("203.0.113.7"), presented);
            assert_eq!(client_ip_with(&h, &e, 0, expected), peer, "{presented:?}");
        }
        // One hop, no proof: the last entry — the hop the deployment trusts.
        let (h, e) = relayed(Some("203.0.113.7, 172.18.0.2"), None);
        assert_eq!(client_ip_with(&h, &e, 1, Some("proof")), ip("172.18.0.2"));
    }

    /// Both sides of the one decision: the per-request portal check under
    /// header auth is uncapped, the claim exchange under standard auth is not.
    #[test]
    fn header_me_is_capped_except_under_header_auth() {
        use crate::routes::admin_auth::AuthMode;
        assert!(!claim_exchange_is_capped(AuthMode::Header));
        assert!(claim_exchange_is_capped(AuthMode::Standard));
    }

    /// The proof is derived, never the secret itself, and the browser tier
    /// derives the same value: this vector is repeated in
    /// `admin-ui/src/lib/server/client-address.test.ts`.
    #[test]
    fn the_browser_tier_proof_is_a_derivation_both_tiers_agree_on() {
        let proof = browser_tier_proof("s3cret").expect("a secret yields a proof");
        assert_eq!(
            proof,
            "17aa813299fc4e86513b20e0fe3149439627026ee1e6ee2331ffa839fc9dcaee"
        );
        assert!(!proof.contains("s3cret"));
        assert_eq!(browser_tier_proof(""), None);
    }

    /// The property the limiter counts: how many DIFFERENT keys a source has
    /// failed with, not how often it has failed.
    #[test]
    fn one_repeated_key_never_trips_but_varied_keys_do() {
        let limiter = DistinctKeyFailures::new(3, 300, 100, 1);

        // A misconfigured client hammering one revoked key: one distinct key,
        // however many attempts. Throttling this would take the whole NAT'd
        // site down with it.
        for _ in 0..50 {
            limiter.record("203.0.113.9", "hash-of-one-stale-key");
        }
        assert!(!limiter.is_limited("203.0.113.9"));

        // A prober: a new key each time.
        let probe = DistinctKeyFailures::new(3, 300, 100, 1);
        for i in 0..3 {
            assert!(
                !probe.is_limited("198.51.100.4"),
                "attempt {i} is under the cap"
            );
            probe.record("198.51.100.4", &format!("hash-{i}"));
        }
        assert!(probe.is_limited("198.51.100.4"));
        // Another source is untouched — otherwise one prober could lock every
        // automation client out of the deployment.
        assert!(!probe.is_limited("203.0.113.9"));
    }

    /// A source at its cap must not keep growing the set it is measured by:
    /// the keys are attacker-chosen, so an unbounded set is an unbounded
    /// allocation an unauthenticated caller controls.
    #[test]
    fn a_limited_source_stops_accumulating_keys() {
        let limiter = DistinctKeyFailures::new(2, 300, 100, 1);
        for i in 0..1000 {
            limiter.record("203.0.113.9", &format!("hash-{i}"));
        }
        let sources = limiter.sources.lock().expect("not poisoned");
        assert_eq!(sources["203.0.113.9"].0.len(), 2);
    }

    /// A nonzero cap must never divide down to 0, which reads as "disabled".
    #[test]
    fn dividing_across_instances_never_disables_the_limiter() {
        assert_eq!(DistinctKeyFailures::new(3, 300, 100, 8).max(), 1);
        assert_eq!(DistinctKeyFailures::new(60, 300, 100, 2).max(), 30);
        // An explicit 0 stays off.
        assert_eq!(DistinctKeyFailures::new(0, 300, 100, 4).max(), 0);
    }
}
