//! Source-IP throttling primitives, shared by the control plane and the data
//! plane.
//!
//! Two pieces, deliberately together: a fixed-window [`RateLimiter`] and the
//! [`extract_client_ip`] resolver that supplies its key. They live in `core`
//! because both processes throttle unauthenticated surfaces — admin-api the
//! login / OIDC / invite / MCP-OAuth pre-auth routes, the proxy the public
//! discovery documents (MCP protected-resource metadata, the A2A agent card) —
//! and one topology model must serve both. Two independent client-IP resolvers
//! would be two chances to read `X-Forwarded-For` wrongly.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

/// Configurable in-memory rate limiter.
/// Tracks attempts per key with a fixed window. Used for login brute-force protection
/// (credential-based, not IP-based) and defense-in-depth on other public endpoints.
pub struct RateLimiter {
    max_attempts: u32,
    window_secs: u64,
    cleanup_threshold: usize,
    /// Map of key → (attempt_count, window_start).
    attempts: std::sync::Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64, cleanup_threshold: usize) -> Self {
        Self {
            max_attempts,
            window_secs,
            cleanup_threshold,
            attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Construct a limiter whose per-window cap is split across `instance_count`
    /// admin-api instances — each instance enforces its share, so a client spread
    /// evenly across instances sees the full cap fleet-wide (the same convergence
    /// the other admin-side limiters use). `instance_count` is floored at 1.
    pub fn per_instance(
        max_attempts: u32,
        window_secs: u64,
        cleanup_threshold: usize,
        instance_count: u32,
    ) -> Self {
        // Divide the cap across instances, but never let integer truncation turn a
        // nonzero cap into 0: a 0 cap silently disables the per-IP limiter (which
        // treats 0 as "off") and makes the always-on per-account limiters reject
        // every request after the first. A configured 0 stays 0 (explicit off).
        let per = max_attempts / instance_count.max(1);
        let per = if max_attempts > 0 { per.max(1) } else { 0 };
        Self::new(per, window_secs, cleanup_threshold)
    }

    /// Configured per-window cap. `0` means the limiter is disabled — callers
    /// must short-circuit, since a `0` cap would otherwise reject every key.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Check if the key is currently rate-limited. Returns `true` if the request should be rejected.
    pub fn is_limited(&self, key: &str) -> bool {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        // Clean up expired entries periodically.
        if map.len() > self.cleanup_threshold {
            map.retain(|_, (_, start)| now.duration_since(*start) < window);
        }

        let Some(entry) = map.get(key) else { return false };

        // Window expired — not limited.
        if now.duration_since(entry.1) >= window { return false }

        entry.0 >= self.max_attempts
    }

    /// Record a failed attempt. Called on authentication failure for login endpoints.
    pub fn record_failure(&self, key: &str) {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let entry = map.entry(key.to_string()).or_insert((0, now));

        // Reset window if expired.
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }

        entry.0 += 1;
    }

    /// Reset the counter on successful login.
    pub fn reset(&self, key: &str) {
        let mut map = self.attempts.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(key);
    }

    /// Check rate limit and record the attempt in one call. Returns `true` if limited.
    /// Use this for endpoints where every request counts (no success/failure distinction).
    pub fn check_rate_limit(&self, key: &str) -> bool {
        if self.is_limited(key) {
            return true;
        }
        self.record_failure(key);
        false
    }
}

/// Resolve the originating client IP under a configured trusted-proxy depth.
///
/// `trusted_proxy_hops` is the number of trusted reverse proxies between the
/// client and the gateway (see `TRUSTED_PROXY_HOPS`). Each proxy appends the
/// address it received the connection from to `X-Forwarded-For`, so the
/// rightmost entries are the ones our own proxies wrote: an attacker may prepend
/// forged entries on the left but cannot forge the right. The client is the Nth
/// entry counting from the right; a shorter-than-configured chain falls back to
/// the leftmost (furthest-out) entry visible. `hops == 0` means the gateway is
/// directly exposed — forwarding headers are client-controlled and ignored, so
/// only the real TCP peer (`ConnectInfo`) is trusted. `None` only when no source
/// can be determined at all.
///
/// Invariant: every consumer that keys security decisions on the client IP (the
/// admin pre-auth IP limiter, the proxy's public-metadata limiter, audit
/// `actor_ip`) MUST go through this — reading `X-Forwarded-For` directly
/// reintroduces the spoofable-key hole. A limiter then charges the bucket
/// [`limiter_key`] names, never the address itself.
///
/// Invariant: `ConnectInfo` only reaches the extensions when the server is
/// mounted with `into_make_service_with_connect_info` — both binaries are, and a
/// plain `into_make_service` would silently strip the peer fallback, leaving
/// every `hops == 0` deployment with no key at all.
pub fn extract_client_ip(
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    trusted_proxy_hops: u32,
) -> Option<IpAddr> {
    let peer = extensions.get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip());

    if trusted_proxy_hops == 0 {
        return peer;
    }

    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let hops: Vec<&str> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !hops.is_empty() {
            let idx = hops.len().saturating_sub(trusted_proxy_hops as usize);
            if let Ok(ip) = hops[idx].parse() {
                return Some(ip);
            }
        }
    }
    // No usable X-Forwarded-For: fall straight to the real TCP peer. We do NOT
    // honor X-Real-IP here — it is a single value with no hop semantics, so it
    // can't be position-validated and is fully client-settable; every supported
    // front proxy (Caddy, ingress-nginx) populates X-Forwarded-For, so this path
    // is the trusted proxy's own address, not an attacker-forgeable header.
    peer
}

/// The bucket a source IP is charged to: an IPv4 address alone (an IPv4 client
/// carried in IPv6 — IPv4-mapped, or translated under the well-known NAT64
/// prefix 64:ff9b::/96 — reads as its IPv4 address), an IPv6 address by its
/// /64 — the smallest network a site is given, which a single host may rotate
/// through, so a per-address bucket would let one client spend a fresh budget
/// per request. Every limiter keys on this, never on the address itself.
pub fn limiter_key(ip: IpAddr) -> String {
    const NAT64: u128 = 0x0064_ff9b_u128 << 96;
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None if v6.to_bits() >> 32 == NAT64 >> 32 => {
                std::net::Ipv4Addr::from_bits(v6.to_bits() as u32).to_string()
            }
            None => {
                let net = std::net::Ipv6Addr::from_bits(v6.to_bits() & !((1u128 << 64) - 1));
                format!("{net}/64")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv6_source_is_charged_by_its_64() {
        let key = |s: &str| limiter_key(s.parse().expect("ip"));
        // Two hosts, or one rotating, inside one /64 share a bucket.
        assert_eq!(key("2001:db8:1:2::1"), key("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_eq!(key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        // The next /64 is another network.
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        // IPv4 stays per address, the mapped form included.
        assert_eq!(key("203.0.113.7"), "203.0.113.7");
        assert_ne!(key("203.0.113.7"), key("203.0.113.8"));
        assert_eq!(key("::ffff:203.0.113.7"), "203.0.113.7");
        // An IPv4 client translated by NAT64 is its IPv4 address, not one shared /64.
        assert_eq!(key("64:ff9b::203.0.113.7"), "203.0.113.7");
        assert_ne!(key("64:ff9b::203.0.113.7"), key("64:ff9b::203.0.113.8"));
        // Only the /96 is: the rest of its /64 is an ordinary IPv6 network.
        assert_eq!(key("64:ff9b::1:0:0:1"), "64:ff9b::/64");
        // Both sides of one /64's edge.
        assert_ne!(key("2001:db8:1:1:ffff:ffff:ffff:ffff"), key("2001:db8:1:2::"));
    }

    // The claim: two IPv6 sources outside the IPv4-carrying ranges share a
    // bucket exactly when they share a /64, and an IPv4 source is its own. Not
    // claimed: that the key is an address (a /64's key is a network).
    proptest::proptest! {
        #[test]
        fn an_ipv6_bucket_is_exactly_a_64(a: u128, b: u128, low: u64) {
            let carried = |v: u128| v >> 32 == 0xffff || v >> 32 == (0x0064_ff9b_u128 << 64);
            proptest::prop_assume!(!carried(a) && !carried(b));
            let key = |v: u128| limiter_key(IpAddr::V6(std::net::Ipv6Addr::from_bits(v)));
            proptest::prop_assert_eq!(key(a) == key(b), a >> 64 == b >> 64);
            // Any host of a's /64 is a's bucket.
            let sibling = (a & !u128::from(u64::MAX)) | u128::from(low);
            proptest::prop_assume!(!carried(sibling));
            proptest::prop_assert_eq!(key(sibling), key(a));
        }

        #[test]
        fn an_ipv4_bucket_is_its_address(a: u32, b: u32) {
            let key = |v: u32| limiter_key(IpAddr::V4(std::net::Ipv4Addr::from_bits(v)));
            proptest::prop_assert_eq!(key(a) == key(b), a == b);
            // The same client carried in IPv6 is the same bucket.
            let mapped = IpAddr::V6(std::net::Ipv4Addr::from_bits(a).to_ipv6_mapped());
            proptest::prop_assert_eq!(limiter_key(mapped), key(a));
            let nat64 = IpAddr::V6(std::net::Ipv6Addr::from_bits((0x0064_ff9b_u128 << 96) | u128::from(a)));
            proptest::prop_assert_eq!(limiter_key(nat64), key(a));
        }
    }

    fn ip_ctx(
        xff: Option<&str>,
        real_ip: Option<&str>,
        peer: Option<&str>,
    ) -> (HeaderMap, axum::http::Extensions) {
        let mut headers = HeaderMap::new();
        if let Some(v) = xff {
            headers.insert("x-forwarded-for", v.parse().unwrap());
        }
        if let Some(v) = real_ip {
            headers.insert("x-real-ip", v.parse().unwrap());
        }
        let mut ext = axum::http::Extensions::new();
        if let Some(p) = peer {
            ext.insert(ConnectInfo(SocketAddr::new(p.parse::<IpAddr>().unwrap(), 1234)));
        }
        (headers, ext)
    }

    #[test]
    fn client_ip_hops_zero_ignores_forwarding_headers() {
        // Directly exposed: a client-set XFF/X-Real-IP must not be trusted.
        let (h, e) = ip_ctx(Some("9.9.9.9"), Some("8.8.8.8"), Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 0).map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn client_ip_one_hop_takes_rightmost() {
        // One trusted proxy: it appends the real client, so an attacker-prepended
        // spoof on the left is ignored and the rightmost entry wins.
        let (h, e) = ip_ctx(Some("1.2.3.4, 203.0.113.7"), None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 1).map(|i| i.to_string()).as_deref(), Some("203.0.113.7"));

        // Single entry (no client-sent XFF): that entry is the client.
        let (h, e) = ip_ctx(Some("203.0.113.7"), None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 1).map(|i| i.to_string()).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn client_ip_two_hops_skips_inner_proxy() {
        // Two trusted proxies: client, then each proxy's view. Nth-from-right=2.
        let (h, e) = ip_ctx(Some("203.0.113.7, 70.0.0.1"), None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 2).map(|i| i.to_string()).as_deref(), Some("203.0.113.7"));
        // With an attacker prefix the genuine client is still Nth-from-right.
        let (h, e) = ip_ctx(Some("1.2.3.4, 203.0.113.7, 70.0.0.1"), None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 2).map(|i| i.to_string()).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn client_ip_short_chain_falls_back_to_leftmost() {
        // Chain shorter than configured hops — take the furthest-out entry seen.
        let (h, e) = ip_ctx(Some("203.0.113.7"), None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 3).map(|i| i.to_string()).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn client_ip_no_xff_ignores_real_ip_uses_peer() {
        // hops>=1, no XFF: X-Real-IP is NOT trusted (client-settable, no hop
        // semantics) — fall straight to the unforgeable TCP peer.
        let (h, e) = ip_ctx(None, Some("9.9.9.9"), Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 1).map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));
        let (h, e) = ip_ctx(None, None, Some("10.0.0.5"));
        assert_eq!(extract_client_ip(&h, &e, 1).map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));
        let (h, e) = ip_ctx(None, None, None);
        assert_eq!(extract_client_ip(&h, &e, 1), None);
    }

    /// The window is per key: one source exhausting its cap must not throttle
    /// another. A shared counter here would let one noisy client take the
    /// public discovery documents offline for everybody.
    #[test]
    fn the_cap_is_per_key_and_trips_on_the_nth_request() {
        let limiter = RateLimiter::new(3, 300, 100);
        for i in 0..3 {
            assert!(!limiter.check_rate_limit("203.0.113.7"), "request {i} is under the cap");
        }
        assert!(limiter.check_rate_limit("203.0.113.7"), "the 4th request trips");
        assert!(!limiter.check_rate_limit("198.51.100.4"), "a different source is untouched");
    }

    /// A nonzero cap must never divide down to 0, which reads as "disabled".
    #[test]
    fn dividing_across_instances_never_disables_the_limiter() {
        assert_eq!(RateLimiter::per_instance(3, 300, 100, 8).max_attempts(), 1);
        assert_eq!(RateLimiter::per_instance(600, 300, 100, 2).max_attempts(), 300);
        // An explicit 0 stays off.
        assert_eq!(RateLimiter::per_instance(0, 300, 100, 4).max_attempts(), 0);
    }
}
