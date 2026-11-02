//! IP-based SSRF guard.
//!
//! Three layers:
//!
//! 1. [`check_url`] — synchronous, IP-literal-only. Rejects URLs whose host
//!    parses as an IP literal in a private / loopback / link-local /
//!    multicast / IMDS range. Hostnames pass this guard ("not obviously
//!    bad"); the caller decides whether to also DNS-resolve.
//!
//! 2. [`resolve_and_pin_addrs`] — async. Calls [`check_url`] first, then
//!    DNS-resolves the host, rejects if **any** resolved record is in an
//!    internal range, and returns the verified addresses. Callers feed the
//!    result into [`reqwest::ClientBuilder::resolve_to_addrs`] so the actual
//!    HTTP connection uses an IP we already vetted — closing the
//!    DNS-rebinding window between the SSRF check and the connect. Use this
//!    for one-shot outbound calls.
//!
//! 3. [`GuardedResolver`] — a [`reqwest::dns::Resolve`] impl that runs the
//!    same per-name guard inside reqwest's connector. Build one client with
//!    `.dns_resolver(GuardedResolver::pair(egress).0)` and a
//!    [`reqwest::redirect::Policy`] that follows hops — every redirect
//!    target re-enters the resolver, so the guard re-vets it without a
//!    fresh `Client` per hop.
//!
//! What a call may reach is its [`Egress`]: public addresses always; a private
//! address only when its surface's allowlist ([`crate::egress`]) lists it, read
//! when the address is checked, so a list change applies to the next
//! connection; the cloud instance-metadata endpoint never.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use url::{Host, Url};

use crate::egress::{self, Surface};

/// Which private addresses an outbound call may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Egress {
    /// None: public destinations only.
    PublicOnly,
    /// Those the surface's allowlist lists, as it stands when the address is
    /// checked.
    Surface(Surface),
}

/// The one decision every path applies to an address `ip` reached as `host`
/// (the name looked up; `None` for an IP literal): the metadata endpoint is
/// refused whatever a list says, a public address passes, and a private one
/// passes only when listed.
fn refused(ip: IpAddr, host: Option<&str>, egress: Egress) -> bool {
    if is_imds_ip(ip) {
        return true;
    }
    if !is_internal_ip(ip) {
        return false;
    }
    match egress {
        Egress::PublicOnly => true,
        Egress::Surface(s) => !egress::current().get(s).permits(ip, host),
    }
}

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("URL parse failed: {0}")]
    UrlParse(String),
    #[error("URL scheme must be http or https")]
    BadScheme,
    #[error("URL must include a host")]
    MissingHost,
    #[error("URL host is in a private/internal IP range — refused for SSRF safety")]
    InternalAddress,
    #[error("DNS lookup failed: {0}")]
    DnsLookup(String),
    #[error("URL did not resolve to any address")]
    NoAddresses,
    #[error("a plain-http URL must reach a listed private address; a public one needs https")]
    PlainHttp,
}

/// Validate `url` for SSRF safety. Returns Ok if safe-on-its-face; Err if the
/// URL parses to an internal IP literal we can lock out.
pub fn check_url(url: &str) -> Result<Url, SsrfError> {
    check_url_for(url, Egress::PublicOnly)
}

/// Like [`check_url`], but an internal IP literal passes when `egress` lists
/// it (scheme + host are still enforced).
///
/// **IMDS is refused whatever the list says.** For an IP-literal host this
/// function is the only guard that runs — the resolver never sees a URL that
/// needs no DNS lookup — so the decision has to be applied here as well as on
/// the resolver and redirect paths.
pub fn check_url_for(url: &str, egress: Egress) -> Result<Url, SsrfError> {
    let parsed = Url::parse(url).map_err(|e| SsrfError::UrlParse(e.to_string()))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(SsrfError::BadScheme);
    }

    let Some(host) = parsed.host() else {
        return Err(SsrfError::MissingHost);
    };

    // Hostnames pass this guard — the caller takes responsibility for DNS-lock
    // if it cares. An IP literal is classified here, because nothing later will.
    let literal = match host {
        Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        Host::Domain(_) => None,
    };
    if let Some(ip) = literal
        && refused(ip, None, egress)
    {
        return Err(SsrfError::InternalAddress);
    }

    Ok(parsed)
}

/// True when `host` parses as an IP literal in a known-internal range. Hostnames
/// (anything that fails to parse as an IP) return false — see the module doc.
pub fn is_internal_address(host: &str) -> bool {
    host.parse::<IpAddr>()
        .map(is_internal_ip)
        .unwrap_or(false)
}

/// Async SSRF guard that closes the DNS-rebinding window.
///
/// Steps:
///   1. Run [`check_url`] (rejects bad scheme, IP-literal internals).
///   2. Resolve the host via the OS resolver.
///   3. If **any** resolved record is in an internal range, refuse.
///   4. Return the verified [`SocketAddr`] list (caller pins via
///      `reqwest::ClientBuilder::resolve_to_addrs(host, &addrs)`).
///
/// Returns `(parsed_url, host_string, verified_addrs)`. The host string and
/// the addrs are split out so callers can pass them straight to reqwest
/// without re-parsing the URL.
pub async fn resolve_and_pin_addrs(
    url: &str,
) -> Result<(Url, String, Vec<SocketAddr>), SsrfError> {
    resolve_and_pin_addrs_for(url, Egress::PublicOnly).await
}

/// Like [`resolve_and_pin_addrs`], but an internal address passes when
/// `egress` lists it (by address, or by the host name looked up).
///
/// **IMDS is hard-blocked whatever the list says.** The cloud
/// instance-metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, and any
/// host that resolves to them — e.g. `metadata.google.internal`) are never a
/// legitimate OAuth target, and discovery reaches its hosts via
/// *attacker-advertised* `authorization_servers` / redirects rather than
/// hand-typed literals, so the metadata service stays off-limits even on a
/// trusted-network deployment.
pub async fn resolve_and_pin_addrs_for(
    url: &str,
    egress: Egress,
) -> Result<(Url, String, Vec<SocketAddr>), SsrfError> {
    let parsed = check_url_for(url, egress)?;
    let host = parsed.host_str().ok_or(SsrfError::MissingHost)?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // IP-literal hosts skip DNS (and `lookup_host` chokes on the bracketed
    // IPv6 form anyway); domains are resolved through the OS resolver.
    let resolved: Vec<SocketAddr> = match parsed.host() {
        Some(Host::Ipv4(v4)) => vec![SocketAddr::new(IpAddr::V4(v4), port)],
        Some(Host::Ipv6(v6)) => vec![SocketAddr::new(IpAddr::V6(v6), port)],
        Some(Host::Domain(d)) => tokio::net::lookup_host((d, port))
            .await
            .map_err(|e| SsrfError::DnsLookup(e.to_string()))?
            .collect(),
        None => return Err(SsrfError::MissingHost),
    };

    let name = match parsed.host() {
        Some(Host::Domain(d)) => Some(d.to_string()),
        _ => None,
    };
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for sock in resolved {
        if refused(sock.ip(), name.as_deref(), egress) {
            return Err(SsrfError::InternalAddress);
        }
        addrs.push(sock);
    }
    if addrs.is_empty() {
        return Err(SsrfError::NoAddresses);
    }
    Ok((parsed, host, addrs))
}

/// [`resolve_and_pin_addrs_for`] for a path that otherwise requires https:
/// plain http passes only when every address the URL reaches is private —
/// and so listed, or the resolution would have refused it — so a credential
/// or a registration never crosses a public network in clear.
pub async fn resolve_and_pin_https_or_listed(
    url: &str,
    egress: Egress,
) -> Result<(Url, String, Vec<SocketAddr>), SsrfError> {
    // Decided before any lookup when it can be — nothing listed on the
    // surface, or a public IP literal — so a name an upstream chose is never
    // even resolved for a plain-http hop that cannot pass.
    let parsed = check_url_for(url, egress)?;
    if parsed.scheme() != "https" {
        let public_literal = match parsed.host() {
            Some(Host::Ipv4(v4)) => !is_internal_ip(IpAddr::V4(v4)),
            Some(Host::Ipv6(v6)) => !is_internal_ip(IpAddr::V6(v6)),
            _ => false,
        };
        let nothing_listed = match egress {
            Egress::PublicOnly => true,
            Egress::Surface(s) => egress::current().get(s).is_empty(),
        };
        if nothing_listed || public_literal {
            return Err(SsrfError::PlainHttp);
        }
    }
    let pinned = resolve_and_pin_addrs_for(url, egress).await?;
    if pinned.0.scheme() != "https" && pinned.2.iter().any(|a| !is_internal_ip(a.ip())) {
        return Err(SsrfError::PlainHttp);
    }
    Ok(pinned)
}

/// True for the cloud instance-metadata-service addresses that must never be a
/// fetch target — including when an allowlist would otherwise permit the
/// surrounding range. Covers AWS/GCP/Azure IMDS
/// (`169.254.169.254`) and the AWS IPv6 IMDS (`fd00:ec2::254`), plus the same
/// addresses tunnelled through an IPv4-in-IPv6 encoding.
pub fn is_imds_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets() == [169, 254, 169, 254],
        IpAddr::V6(v6) => {
            v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
                || embedded_ipv4(v6).map(|m| m.octets() == [169, 254, 169, 254]).unwrap_or(false)
        }
    }
}

/// Returns `true` when a target URL must be refused because its host is an IP
/// **literal** in an internal range — the case [`GuardedResolver`] can't catch,
/// since hyper-util's connector parses IP-literal hosts directly and skips the
/// `dns::Resolve` hook. Used both to vet a redirect hop and to vet an
/// upstream-supplied initial URL (e.g. a legacy-SSE `endpoint` event). Hostnames
/// return `false` here (they take the resolver path). IMDS literals are refused
/// whatever `egress` lists; another internal literal unless `egress` lists it.
pub fn redirect_target_is_internal_ip_literal(url: &Url, egress: Egress) -> bool {
    let ip: IpAddr = match url.host() {
        Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
        Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
        _ => return false,
    };
    refused(ip, None, egress)
}

/// `reqwest::dns::Resolve` impl that enforces the SSRF guard at name-resolution
/// time. One `Client` configured with this resolver covers a multi-hop redirect
/// chain without per-hop client rebuilds — reqwest re-enters `resolve()` for
/// each redirect target, so the guard re-vets it.
///
/// `egress` decides each resolved address: a name resolving to any address it
/// refuses fails the resolution.
///
/// Refusals surface inside reqwest as a connector error. The caller wraps the
/// resolver in [`GuardedResolverHandle`] to recover the typed [`SsrfError`]:
/// `resolve()` stashes the first refusal into a shared slot, and
/// [`GuardedResolverHandle::take_refusal`] drains it after a failing `send()`.
pub struct GuardedResolver {
    egress: Egress,
    last_refusal: Arc<Mutex<Option<SsrfError>>>,
}

impl GuardedResolver {
    /// Build a `(resolver, handle)` pair. The `Arc<dyn Resolve>` goes to
    /// `ClientBuilder::dns_resolver`; the handle stays with the caller so it
    /// can drain the typed refusal after a failed request.
    pub fn pair(egress: Egress) -> (Arc<dyn reqwest::dns::Resolve>, GuardedResolverHandle) {
        let last_refusal = Arc::new(Mutex::new(None));
        let resolver = Arc::new(Self {
            egress,
            last_refusal: last_refusal.clone(),
        });
        (resolver, GuardedResolverHandle { last_refusal })
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let egress = self.egress;
        let last_refusal = self.last_refusal.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0 — reqwest replaces it with the scheme's port (per the
            // `dns::Resolve` doc).
            let resolved: Vec<SocketAddr> = match tokio::net::lookup_host((host.as_str(), 0)).await
            {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    let err = SsrfError::DnsLookup(e.to_string());
                    *last_refusal.lock().unwrap() = Some(err);
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            };
            if resolved.is_empty() {
                *last_refusal.lock().unwrap() = Some(SsrfError::NoAddresses);
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "no addresses",
                ));
            }
            if let Some(addr) = resolved.iter().find(|s| refused(s.ip(), Some(&host), egress))
            {
                *last_refusal.lock().unwrap() = Some(SsrfError::InternalAddress);
                return Err(Box::new(AddressRefused(format!("{host} → {addr}")))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addrs: reqwest::dns::Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

/// The resolver's refusal, as reqwest carries it inside a connect error: a
/// caller finds it by walking the error's sources, without the paired handle
/// (which a shared client cannot tie to one request).
#[derive(Debug)]
pub struct AddressRefused(pub String);

impl std::fmt::Display for AddressRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "internal address refused: {}", self.0)
    }
}

impl std::error::Error for AddressRefused {}

/// A redirect hop from https down to plain http, refused whatever a list
/// says: the hop would carry the request's credentials in clear.
#[derive(Debug)]
pub struct DowngradeRefused(pub String);

impl std::fmt::Display for DowngradeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "redirect from https down to plain http refused: {}", self.0)
    }
}

impl std::error::Error for DowngradeRefused {}

/// What the guard refused, found inside a failed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A private address the egress list does not list (or the metadata
    /// endpoint): [`AddressRefused`].
    Address,
    /// A redirect from https down to plain http: [`DowngradeRefused`].
    Downgrade,
}

/// The guard's refusal carried by `e` or an error it wraps — a policy
/// refusal, not an upstream that failed to answer — if any.
pub fn refusal(e: &(dyn std::error::Error + 'static)) -> Option<Refusal> {
    let mut source = Some(e);
    while let Some(s) = source {
        if s.downcast_ref::<AddressRefused>().is_some() {
            return Some(Refusal::Address);
        }
        if s.downcast_ref::<DowngradeRefused>().is_some() {
            return Some(Refusal::Downgrade);
        }
        source = s.source();
    }
    None
}

/// Handle paired with a [`GuardedResolver`]. After a failing `reqwest`
/// request, drain it to recover the typed [`SsrfError`] that the resolver
/// rejected with — reqwest only surfaces a generic connector error.
pub struct GuardedResolverHandle {
    last_refusal: Arc<Mutex<Option<SsrfError>>>,
}

impl GuardedResolverHandle {
    /// Returns the first refusal recorded by the resolver since the last call,
    /// clearing it. `None` if the resolver hasn't refused (request failure
    /// was something else — connect timeout, TLS, body read, etc.).
    pub fn take_refusal(&self) -> Option<SsrfError> {
        self.last_refusal.lock().unwrap().take()
    }
}

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // The whole `0.0.0.0/8` "this host on this network" block — not
                // just `0.0.0.0` (which `is_unspecified` covers); on Linux it
                // routes to loopback.
                || o[0] == 0
                // Carrier-grade NAT (RFC 6598) — not is_private() but still internal.
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // 169.254.169.254 — IMDS, already covered by is_link_local but
                // worth the explicit assertion.
                || o == [169, 254, 169, 254]
                // IETF-reserved special-purpose ranges that should never be a
                // fetch target: 192.0.0.0/24 (IETF protocol assignments),
                // 198.18.0.0/15 (benchmarking), 240.0.0.0/4 (reserved).
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local (fc00::/7).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10).
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // Addresses that embed an IPv4 address (IPv4-mapped,
                // IPv4-compatible, NAT64, 6to4) — recurse to the v4 check on
                // the embedded address so an internal v4 can't tunnel in.
                || embedded_ipv4(v6).map(|m| is_internal_ip(IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

/// Extract the IPv4 address embedded in an IPv6 address, if any:
/// IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`, deprecated),
/// NAT64 (`64:ff9b::a.b.c.d`), or 6to4 (`2002:aabb:ccdd::`). The caller applies
/// the IPv4 internal-range check to the result so an internal v4 can't reach
/// the gateway tunnelled through one of these encodings.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    // IPv4-mapped (`::ffff:0:0/96`) and IPv4-compatible (`::/96`) both decode
    // via `to_ipv4`. (`to_ipv4_mapped` would miss the compatible form.)
    if let Some(v4) = v6.to_ipv4() {
        return Some(v4);
    }
    let seg = v6.segments();
    // NAT64 well-known prefix `64:ff9b::/96` — embedded v4 is the last 32 bits.
    if seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
    {
        return Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    // 6to4 `2002::/16` — embedded v4 is segments 1-2.
    if seg[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            (seg[1] & 0xff) as u8,
            (seg[2] >> 8) as u8,
            (seg[2] & 0xff) as u8,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests share one process-wide store, so every test installs the
    /// same lists: `web` lists only the name `localhost`, every other surface
    /// every private address.
    fn install_lists() {
        let lists: std::collections::BTreeMap<String, Vec<String>> = Surface::ALL
            .iter()
            .map(|s| {
                let entry = if *s == Surface::Web { "localhost" } else { "*" };
                (s.as_str().to_string(), vec![entry.to_string()])
            })
            .collect();
        egress::install(egress::Lists::from_entries(&lists).unwrap());
    }

    fn all() -> Egress {
        install_lists();
        Egress::Surface(Surface::Mcp)
    }

    #[tokio::test]
    async fn plain_http_reaches_only_a_listed_private_address() {
        let listed = all();
        assert!(resolve_and_pin_https_or_listed("http://127.0.0.1:9/", listed).await.is_ok());
        assert_matches!(
            resolve_and_pin_https_or_listed("http://93.184.216.34/", listed).await,
            Err(SsrfError::PlainHttp)
        );
        assert!(resolve_and_pin_https_or_listed("https://93.184.216.34/", listed).await.is_ok());
        assert_matches!(
            resolve_and_pin_https_or_listed("http://127.0.0.1:9/", Egress::PublicOnly).await,
            Err(SsrfError::InternalAddress)
        );
        // Nothing listable: refused before any lookup, whatever the host.
        assert_matches!(
            resolve_and_pin_https_or_listed("http://no-such-host.invalid/", Egress::PublicOnly).await,
            Err(SsrfError::PlainHttp)
        );
    }

    #[tokio::test]
    async fn a_listed_name_is_reached_and_its_address_as_a_literal_is_not() {
        install_lists();
        let web = Egress::Surface(Surface::Web);
        assert!(resolve_and_pin_addrs_for("http://localhost:8080/", web).await.is_ok());
        assert_matches!(check_url_for("http://127.0.0.1:8080/", web), Err(SsrfError::InternalAddress));
        assert!(redirect_target_is_internal_ip_literal(&Url::parse("http://127.0.0.1/").unwrap(), web));
        let (resolver, handle) = GuardedResolver::pair(web);
        assert!(resolver.resolve("localhost".parse().unwrap()).await.is_ok());
        assert!(handle.take_refusal().is_none());
        // The positive control's negative: the same name on a surface listing
        // nothing is refused.
        let (strict, strict_handle) = GuardedResolver::pair(Egress::PublicOnly);
        assert!(strict.resolve("localhost".parse().unwrap()).await.is_err());
        assert_matches!(strict_handle.take_refusal(), Some(SsrfError::InternalAddress));
        // IMDS stays refused on a surface listing every private address.
        assert!(check_url_for("http://169.254.169.254/", all()).is_err());
    }
    use std::assert_matches;

    #[test]
    fn rejects_loopback_v4() {
        assert!(check_url("http://127.0.0.1/").is_err());
        assert!(check_url("https://127.0.0.1:8080/x").is_err());
    }

    #[test]
    fn rejects_imds() {
        assert!(check_url("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(check_url("https://10.0.0.1/x").is_err());
        assert!(check_url("https://172.16.0.1/x").is_err());
        assert!(check_url("https://192.168.1.1/x").is_err());
    }

    #[test]
    fn rejects_zero_network_and_reserved() {
        // The whole 0.0.0.0/8 block, not just 0.0.0.0.
        assert!(check_url("http://0.0.0.0/").is_err());
        assert!(check_url("http://0.10.20.30/").is_err());
        // IETF-reserved special-purpose ranges.
        assert!(check_url("http://192.0.0.1/").is_err()); // 192.0.0.0/24
        assert!(check_url("http://198.18.0.1/").is_err()); // 198.18.0.0/15
        assert!(check_url("http://198.19.255.1/").is_err());
        assert!(check_url("http://240.0.0.1/").is_err()); // 240.0.0.0/4
        assert!(check_url("http://255.255.255.255/").is_err());
    }

    #[test]
    fn rejects_v6_loopback_and_ula() {
        assert!(check_url("http://[::1]/").is_err());
        assert!(check_url("http://[fc00::1]/").is_err());
        assert!(check_url("http://[fe80::1]/").is_err());
    }

    #[test]
    fn rejects_v6_mapped_v4_loopback() {
        assert!(check_url("http://[::ffff:127.0.0.1]/").is_err());
    }

    #[test]
    fn rejects_v6_compatible_nat64_6to4_internal() {
        // IPv4-compatible (`::a.b.c.d`, deprecated) embedding loopback.
        assert!(check_url("http://[::7f00:1]/").is_err());
        // NAT64 `64:ff9b::/96` embedding loopback / RFC1918.
        assert!(check_url("http://[64:ff9b::7f00:1]/").is_err());
        assert!(check_url("http://[64:ff9b::a00:1]/").is_err());
        // 6to4 `2002::/16` embedding loopback / RFC1918.
        assert!(check_url("http://[2002:7f00:1::]/").is_err());
        assert!(check_url("http://[2002:a00:1::]/").is_err());
    }

    #[test]
    fn allows_v6_embedding_public_v4() {
        // NAT64 / 6to4 wrapping a public v4 (8.8.8.8) is not internal.
        assert!(check_url("http://[64:ff9b::808:808]/").is_ok());
        assert!(check_url("http://[2002:808:808::]/").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(check_url("file:///etc/passwd").is_err());
        assert!(check_url("gopher://example.com/").is_err());
    }

    #[test]
    fn allows_hostnames() {
        // Hostnames pass the IP-literal guard. The CIMD fetcher decides
        // whether to do DNS-lock; this guard is fail-open on names.
        assert!(check_url("https://example.com/.well-known/foo").is_ok());
        assert!(check_url("https://api.github.com/").is_ok());
    }

    #[test]
    fn allows_public_v4() {
        assert!(check_url("https://1.1.1.1/").is_ok());
        assert!(check_url("https://8.8.8.8/").is_ok());
    }

    #[tokio::test]
    async fn resolve_and_pin_rejects_internal_ip_literal() {
        let err = resolve_and_pin_addrs("http://127.0.0.1/").await.unwrap_err();
        assert_matches!(err, SsrfError::InternalAddress);
    }

    #[tokio::test]
    async fn resolve_and_pin_rejects_imds() {
        let err = resolve_and_pin_addrs("http://169.254.169.254/").await.unwrap_err();
        assert_matches!(err, SsrfError::InternalAddress);
    }

    #[tokio::test]
    async fn resolve_and_pin_rejects_bad_scheme() {
        let err = resolve_and_pin_addrs("file:///etc/passwd").await.unwrap_err();
        assert_matches!(err, SsrfError::BadScheme);
    }

    #[tokio::test]
    async fn a_full_list_still_blocks_imds() {
        // Even with every private address listed, the metadata service is off-limits.
        let err = resolve_and_pin_addrs_for("http://169.254.169.254/", all())
            .await
            .unwrap_err();
        assert_matches!(err, SsrfError::InternalAddress);
        let err = resolve_and_pin_addrs_for("http://[fd00:ec2::254]/", all())
            .await
            .unwrap_err();
        assert_matches!(err, SsrfError::InternalAddress);
    }

    /// The same exemption on the synchronous literal check. This is the guard
    /// that matters for an IP-literal URL: no DNS lookup happens, so the
    /// resolver never runs and this is the only thing between an
    /// allow-internal deployment and the instance-metadata endpoint.
    #[test]
    fn check_url_blocks_imds_even_when_internal_is_allowed() {
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "https://169.254.169.254/",
        ] {
            assert_matches!(
                check_url_for(url, all()),
                Err(SsrfError::InternalAddress),
                "{url} must be refused whatever the list says"
            );
        }
    }

    /// Allow-internal still has to permit the private ranges it exists for —
    /// the IMDS exemption must not widen into a blanket refusal.
    #[test]
    fn check_url_permits_private_ranges_when_internal_is_allowed() {
        for url in [
            "http://127.0.0.1:8080/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://[::1]/",
        ] {
            assert!(
                check_url_for(url, all()).is_ok(),
                "{url} must be permitted when every private address is listed"
            );
        }
    }

    #[test]
    fn imds_ip_detection() {
        assert!(is_imds_ip("169.254.169.254".parse().unwrap()));
        assert!(is_imds_ip("fd00:ec2::254".parse().unwrap()));
        // IMDS tunnelled through IPv4-mapped IPv6.
        assert!(is_imds_ip("::ffff:169.254.169.254".parse().unwrap()));
        // A neighbouring link-local address is not IMDS specifically.
        assert!(!is_imds_ip("169.254.1.1".parse().unwrap()));
        assert!(!is_imds_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn redirect_literal_check_blocks_imds_whatever_the_list_says() {
        let imds = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&imds, Egress::PublicOnly));
        // IMDS stays blocked even when general internal ranges are permitted.
        assert!(redirect_target_is_internal_ip_literal(&imds, all()));

        let loopback = Url::parse("http://127.0.0.1/").unwrap();
        assert!(redirect_target_is_internal_ip_literal(&loopback, Egress::PublicOnly));
        // A general internal literal is allowed when listed.
        assert!(!redirect_target_is_internal_ip_literal(&loopback, all()));

        // Public literals and hostnames are not refused here (hostnames take
        // the resolver path).
        let public = Url::parse("http://1.1.1.1/").unwrap();
        assert!(!redirect_target_is_internal_ip_literal(&public, Egress::PublicOnly));
        let hostname = Url::parse("https://example.com/").unwrap();
        assert!(!redirect_target_is_internal_ip_literal(&hostname, Egress::PublicOnly));
    }

    // GuardedResolver tests — exercise the resolver via a real reqwest client.
    // The reqwest `dns::Name` type is constructed by reqwest's connector; we
    // can't build it directly. So we run the resolver through a `Client` that
    // tries to hit an internal target and check that (a) the request fails
    // and (b) `take_refusal()` reports the typed reason.

    #[tokio::test]
    async fn guarded_resolver_refuses_internal_v4() {
        let (resolver, handle) = GuardedResolver::pair(Egress::PublicOnly);
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        // Use a hostname that resolves only to a loopback address.
        let err = client
            .get("http://localhost/")
            .send()
            .await
            .expect_err("loopback target must fail");
        assert!(err.is_connect() || err.is_request(), "got: {err:?}");
        let refusal = handle.take_refusal().expect("refusal recorded");
        assert_matches!(refusal, SsrfError::InternalAddress);
    }

    #[tokio::test]
    async fn guarded_resolver_passes_a_listed_address() {
        let (resolver, handle) = GuardedResolver::pair(all());
        let _client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .build()
            .unwrap();
        // No request issued — just confirm the handle starts clean and the
        // resolver doesn't preemptively populate a refusal.
        assert!(handle.take_refusal().is_none());
    }

    #[tokio::test]
    async fn guarded_resolver_take_refusal_drains() {
        let (resolver, handle) = GuardedResolver::pair(Egress::PublicOnly);
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let _ = client.get("http://localhost/").send().await;
        assert!(handle.take_refusal().is_some());
        // Second drain is empty.
        assert!(handle.take_refusal().is_none());
    }
}
