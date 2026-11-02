//! The deployment's internal-egress allowlists — which private addresses each
//! outbound surface may reach.
//!
//! A public destination is always reachable and the cloud instance-metadata
//! endpoint never is; between the two, a private (internal) address is
//! reachable only when the [`Surface`]'s [`Allowlist`] lists it. The lists are
//! a platform setting the SYSTEM super-admin edits: admin-api installs them
//! from the database, a gateway from the config-sync `global` body, both
//! through [`install`]. The guard ([`crate::ssrf`]) reads [`current`] at
//! resolve time, so a change applies to the next connection without a restart.
//!
//! An entry is one of:
//! - `*` — every private address;
//! - an IP address or a CIDR prefix (`10.0.0.0/8`, `fd00::/8`) — the private
//!   addresses inside it;
//! - a host name — every address that exact name resolves to (no suffix or
//!   wildcard match: `mcp.lan` does not cover `a.mcp.lan`). Listing a name
//!   trusts its DNS for that name.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;

/// An outbound surface with its own allowlist. The string form is the stored
/// and wire key, and is append-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// LLM providers: the gateway's upstream calls, liveness probes, model
    /// discovery and replica endpoints.
    Llm,
    /// MCP upstream servers and their OAuth discovery.
    Mcp,
    /// A2A upstream agents.
    A2a,
    /// OpenID Connect identity providers (discovery, keys, token exchange).
    Oidc,
    /// The built-in web tool's fetches: URLs an end user or a model supplies.
    Web,
    /// OAuth client metadata documents (CIMD) a client advertises.
    Cimd,
    /// Upstream token endpoints the gateway mints credentials from.
    UpstreamToken,
    /// The extension endpoints a tenant sets: the web search backend and the
    /// guardrail classifier.
    Extensions,
}

impl Surface {
    pub const ALL: [Surface; 8] = [
        Surface::Llm,
        Surface::Mcp,
        Surface::A2a,
        Surface::Oidc,
        Surface::Web,
        Surface::Cimd,
        Surface::UpstreamToken,
        Surface::Extensions,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Llm => "llm",
            Surface::Mcp => "mcp",
            Surface::A2a => "a2a",
            Surface::Oidc => "oidc",
            Surface::Web => "web",
            Surface::Cimd => "cimd",
            Surface::UpstreamToken => "upstream_token",
            Surface::Extensions => "extensions",
        }
    }

    pub fn parse(s: &str) -> Option<Surface> {
        Surface::ALL.into_iter().find(|v| v.as_str() == s)
    }

    fn index(self) -> usize {
        Surface::ALL.iter().position(|v| *v == self).unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.len)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is that IPv4 address: a
/// listed IPv4 prefix covers it, and an IPv6 prefix does not.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// A prefix as matched: an IPv4-mapped IPv6 prefix of at least 96 bits is the
/// IPv4 prefix it maps (the address an IPv4-mapped peer is compared as); a
/// shorter one stays IPv6.
fn prefix(addr: IpAddr, len: u8) -> Prefix {
    match addr {
        IpAddr::V6(v6) if len >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => Prefix { addr: IpAddr::V4(v4), len: len - 96 },
            None => Prefix { addr, len },
        },
        _ => Prefix { addr, len },
    }
}

/// One surface's allowlist, parsed. The default is empty: no private address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowlist {
    any: bool,
    prefixes: Vec<Prefix>,
    hosts: Vec<String>,
}

/// Why an entry is not one [`Allowlist::parse`] reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("'{entry}' is not `*`, an IP address, a CIDR prefix or a host name")]
pub struct EntryError {
    pub entry: String,
}

impl Allowlist {
    /// Parse a list of entries (see the module doc). Surrounding whitespace is
    /// trimmed, a host name is compared lowercased without a trailing dot, and
    /// a CIDR keeps only its prefix bits. Every entry must parse.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Allowlist, EntryError> {
        let mut list = Allowlist::default();
        for raw in entries {
            let entry = raw.as_ref().trim();
            let refuse = || EntryError { entry: entry.to_string() };
            if entry == "*" {
                list.any = true;
            } else if let Some((addr, len)) = entry.split_once('/') {
                let addr: IpAddr =
                    addr.trim_start_matches('[').trim_end_matches(']').parse().map_err(|_| refuse())?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                let len: u8 = len.parse().ok().filter(|l| *l <= max).ok_or_else(refuse)?;
                list.prefixes.push(prefix(addr, len));
            } else if let Ok(addr) = entry.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
                let len = if addr.is_ipv4() { 32 } else { 128 };
                list.prefixes.push(prefix(addr, len));
            } else {
                let host = entry.trim_end_matches('.').to_ascii_lowercase();
                if !is_host_name(&host) {
                    return Err(refuse());
                }
                list.hosts.push(host);
            }
        }
        Ok(list)
    }

    /// True when a private address `ip`, reached as `host` (the name looked
    /// up, `None` for an IP literal), is listed. Says nothing about a public
    /// address or the metadata endpoint, which the guard decides first.
    pub fn permits(&self, ip: IpAddr, host: Option<&str>) -> bool {
        if self.any || self.prefixes.iter().any(|p| p.contains(ip)) {
            return true;
        }
        host.map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .is_some_and(|h| self.hosts.contains(&h))
    }

    pub fn is_empty(&self) -> bool {
        !self.any && self.prefixes.is_empty() && self.hosts.is_empty()
    }
}

/// A DNS host name: dot-separated labels of letters, digits, `-` and `_`, none
/// empty, none starting or ending with `-`.
fn is_host_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Every surface's allowlist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lists {
    lists: [Allowlist; 8],
}

impl Lists {
    /// Parse the stored form: surface key → entries. A key that names no
    /// surface is skipped (the endpoint writing the lists refuses one); an
    /// entry that does not parse refuses the whole set, naming its surface.
    pub fn from_entries(map: &BTreeMap<String, Vec<String>>) -> Result<Lists, (Surface, EntryError)> {
        let mut lists = Lists::default();
        for (key, entries) in map {
            if let Some(surface) = Surface::parse(key) {
                lists.lists[surface.index()] = Allowlist::parse(entries).map_err(|e| (surface, e))?;
            }
        }
        Ok(lists)
    }

    pub fn get(&self, surface: Surface) -> &Allowlist {
        &self.lists[surface.index()]
    }
}

/// The index of `egress` among `Surface::ALL.len() + 1` per-egress slots
/// (each surface, then public-only).
pub fn egress_slot(egress: crate::ssrf::Egress) -> usize {
    match egress {
        crate::ssrf::Egress::PublicOnly => Surface::ALL.len(),
        crate::ssrf::Egress::Surface(surface) => surface.index(),
    }
}

static CURRENT: LazyLock<ArcSwap<Lists>> = LazyLock::new(|| ArcSwap::from_pointee(Lists::default()));
/// Per egress (each surface, then public-only, as [`egress_slot`] numbers
/// them): how many times its list has changed.
static GENERATIONS: [std::sync::atomic::AtomicU64; Surface::ALL.len() + 1] =
    [const { std::sync::atomic::AtomicU64::new(0) }; Surface::ALL.len() + 1];

/// Make `lists` the process's allowlists. The next connection on every
/// surface reads them; a surface whose list changed moves its
/// [`generation`], so its cached clients drop their idle pooled connections —
/// opened under the old list — and reconnect under the new one. A connection
/// in use (a stream being read) runs on until it ends.
pub fn install(lists: Lists) {
    let current = CURRENT.load();
    if **current == lists {
        return;
    }
    let changed: Vec<Surface> =
        Surface::ALL.into_iter().filter(|s| current.get(*s) != lists.get(*s)).collect();
    CURRENT.store(Arc::new(lists));
    for s in changed {
        GENERATIONS[s.index()].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// How many times the list deciding `egress` has changed (never, for
/// public-only). A process-cached client is keyed on it ([`Cached`]).
pub fn generation(egress: crate::ssrf::Egress) -> u64 {
    GENERATIONS[egress_slot(egress)].load(std::sync::atomic::Ordering::SeqCst)
}

/// A value — a client and its connection pool — for one egress, rebuilt when
/// that egress's list changes, so an idle pooled connection never outlives
/// the listing it was opened under. One caller builds; the others wait for it.
///
/// `K` is what the value is built for: the list's [`generation`], or with
/// [`Self::get_or_try_build_with`] that and a second input the build reads (a
/// CA bundle), so the value is rebuilt when either changes.
pub struct Cached<T: Clone, K = u64> {
    slot: std::sync::RwLock<Option<(K, T)>>,
}

impl<T: Clone, K> Cached<T, K> {
    pub const fn new() -> Self {
        Cached { slot: std::sync::RwLock::new(None) }
    }
}

impl<T: Clone> Cached<T> {
    /// The value built under `egress`'s current list, built now with `build`
    /// when there is none or the list changed since. A failed build is
    /// returned and nothing is cached.
    pub fn get_or_try_build<E>(
        &self,
        egress: crate::ssrf::Egress,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.get_at(|| generation(egress), |_| build())
    }

    /// [`Self::get_or_try_build`] for a `build` that cannot fail.
    pub fn get_or_build(&self, egress: crate::ssrf::Egress, build: impl FnOnce() -> T) -> T {
        match self.get_or_try_build::<std::convert::Infallible>(egress, || Ok(build())) {
            Ok(value) => value,
            Err(never) => match never {},
        }
    }
}

impl<T: Clone, X: PartialEq + Clone> Cached<T, (u64, X)> {
    /// [`Cached::get_or_try_build`] for a value that also depends on what
    /// `extra` reads: built with `build` (handed that) when there is none, the
    /// list changed, or the value was built for another `extra`.
    pub fn get_or_try_build_with<E>(
        &self,
        egress: crate::ssrf::Egress,
        extra: impl Fn() -> X,
        build: impl FnOnce(X) -> Result<T, E>,
    ) -> Result<T, E> {
        self.get_at(|| (generation(egress), extra()), |(_, x)| build(x.clone()))
    }
}

impl<T: Clone, K: PartialEq> Cached<T, K> {
    /// The value for the key `key` reads, built with `build` (handed that key)
    /// when the slot holds another. The key is read again under the write
    /// lock, and the build uses that reading: a caller that read an older key
    /// cannot store over a value built for a newer one.
    fn get_at<E>(&self, key: impl Fn() -> K, build: impl FnOnce(&K) -> Result<T, E>) -> Result<T, E> {
        let current = |slot: &Option<(K, T)>, key: &K| match slot {
            Some((k, value)) if k == key => Some(value.clone()),
            _ => None,
        };
        if let Some(value) = self.slot.read().ok().and_then(|slot| current(&slot, &key())) {
            return Ok(value);
        }
        // Under the write lock, checked again: of the callers that missed
        // together, the first builds and the rest take its value.
        let mut slot = match self.slot.write() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        let key = key();
        if let Some(value) = current(&slot, &key) {
            return Ok(value);
        }
        let value = build(&key)?;
        *slot = Some((key, value.clone()));
        Ok(value)
    }
}

impl<T: Clone> Default for Cached<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The process's allowlists now: empty everywhere until [`install`] runs.
pub fn current() -> Arc<Lists> {
    CURRENT.load_full()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // On an explicit generation: the process-wide one moves whenever another
    // test of this binary installs other lists.
    #[test]
    fn a_cached_value_is_rebuilt_only_when_the_generation_moves() {
        let c: Cached<u32> = Cached::new();
        let mut builds = 0;
        let mut get = |g: u64| c.get_at::<()>(|| g, |_| { builds += 1; Ok(builds) }).unwrap();
        assert_eq!(get(7), 1);
        assert_eq!(get(7), 1, "the same generation: the cached value");
        assert_eq!(get(8), 2, "a new generation: rebuilt");
        assert_eq!(get(8), 2);
        let failed: Result<u32, &str> = c.get_at(|| 9, |_| Err("no"));
        assert!(failed.is_err());
        assert_eq!(get(8), 2, "a failed build caches nothing");
    }

    #[test]
    fn a_value_with_an_extra_input_is_rebuilt_when_that_input_changes() {
        let c: Cached<String, (u64, Option<&str>)> = Cached::new();
        let mut builds = 0;
        let mut get = |g: u64, ca: Option<&'static str>| {
            c.get_at::<()>(|| (g, ca), |_| {
                builds += 1;
                Ok(format!("{builds}:{ca:?}"))
            })
            .unwrap()
        };
        assert_eq!(get(1, None), "1:None");
        assert_eq!(get(1, None), "1:None", "the same inputs: the cached value");
        assert_eq!(get(1, Some("a")), "2:Some(\"a\")", "another bundle: rebuilt");
        assert_eq!(get(2, Some("a")), "3:Some(\"a\")", "a new generation: rebuilt");
        assert_eq!(get(2, Some("a")), "3:Some(\"a\")");
    }

    #[test]
    fn the_build_is_handed_the_extra_input_it_is_cached_under() {
        let c: Cached<String, (u64, String)> = Cached::new();
        let mcp = crate::ssrf::Egress::Surface(Surface::Mcp);
        let got = c.get_or_try_build_with::<()>(mcp, || "bundle-a".to_string(), Ok).unwrap();
        assert_eq!(got, "bundle-a");
        let again = c.get_or_try_build_with::<()>(mcp, || "bundle-a".to_string(), |_| Ok("rebuilt".into())).unwrap();
        assert_eq!(again, "bundle-a", "the same bundle under the same list: not rebuilt");
    }

    #[test]
    fn installing_the_lists_in_force_again_moves_no_generation() {
        // The lists this binary's other tests install are all in the ssrf
        // module and identical, so a repeat install is the common case.
        let mcp = crate::ssrf::Egress::Surface(Surface::Mcp);
        let before = (generation(mcp), (*current()).clone());
        install(before.1.clone());
        let after = (generation(mcp), (*current()).clone());
        assert!(after.1 != before.1 || after.0 == before.0, "an identical install moved the generation");
    }

    #[test]
    fn an_empty_list_permits_nothing() {
        let l = Allowlist::parse::<&str>(&[]).unwrap();
        assert!(l.is_empty());
        assert!(!l.permits(ip("10.0.0.1"), Some("mcp.lan")));
    }

    #[test]
    fn a_star_permits_every_private_address() {
        let l = Allowlist::parse(&["*"]).unwrap();
        assert!(l.permits(ip("10.0.0.1"), None));
        assert!(l.permits(ip("fd00::1"), None));
    }

    #[test]
    fn a_prefix_permits_inside_and_refuses_on_both_sides() {
        let l = Allowlist::parse(&["10.1.0.0/16"]).unwrap();
        assert!(l.permits(ip("10.1.0.0"), None));
        assert!(l.permits(ip("10.1.255.255"), None));
        assert!(!l.permits(ip("10.0.255.255"), None));
        assert!(!l.permits(ip("10.2.0.0"), None));
    }

    #[test]
    fn a_prefix_of_zero_or_full_length() {
        assert!(Allowlist::parse(&["0.0.0.0/0"]).unwrap().permits(ip("192.168.1.1"), None));
        let one = Allowlist::parse(&["192.168.1.7/32"]).unwrap();
        assert!(one.permits(ip("192.168.1.7"), None));
        assert!(!one.permits(ip("192.168.1.6"), None));
        assert!(!one.permits(ip("192.168.1.8"), None));
        assert!(Allowlist::parse(&["10.0.0.0/33"]).is_err());
        assert!(Allowlist::parse(&["fd00::/129"]).is_err());
    }

    #[test]
    fn an_ip_entry_is_that_address_only() {
        let l = Allowlist::parse(&["10.20.30.40", "[fd00::5]"]).unwrap();
        assert!(l.permits(ip("10.20.30.40"), None));
        assert!(!l.permits(ip("10.20.30.41"), None));
        assert!(l.permits(ip("fd00::5"), None));
        assert!(!l.permits(ip("fd00::6"), None));
    }

    #[test]
    fn a_mapped_v4_address_is_its_v4_address() {
        let l = Allowlist::parse(&["10.0.0.0/8"]).unwrap();
        assert!(l.permits(IpAddr::V6(Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped()), None));
        let v6 = Allowlist::parse(&["::ffff:0:0/96"]).unwrap();
        assert!(v6.permits(ip("10.1.2.3"), None), "a mapped prefix is read as its v4 prefix");
    }

    #[test]
    fn a_mapped_prefix_shorter_than_96_bits_stays_ipv6() {
        let l = Allowlist::parse(&["::ffff:0:0/95"]).unwrap();
        assert!(!l.permits(ip("10.1.2.3"), None), "a v6 prefix never covers a mapped address");
        assert!(l.permits(ip("::fffe:1:2"), None), "it is still the v6 prefix it says");
    }

    #[test]
    fn a_mapped_prefix_is_its_v4_prefix_on_both_sides() {
        let l = Allowlist::parse(&["::ffff:10.0.0.0/104"]).unwrap();
        assert!(l.permits(ip("10.255.255.255"), None));
        assert!(!l.permits(ip("11.0.0.0"), None));
        assert!(!l.permits(ip("9.255.255.255"), None));
    }

    #[test]
    fn a_bracketed_v6_prefix_is_read() {
        let l = Allowlist::parse(&["[fd00::]/8"]).unwrap();
        assert!(l.permits(ip("fd12::1"), None));
        assert!(!l.permits(ip("fe80::1"), None));
    }

    #[test]
    fn a_list_with_any_entry_is_not_empty() {
        for entry in ["*", "10.0.0.0/8", "mcp.lan"] {
            assert!(!Allowlist::parse(&[entry]).unwrap().is_empty(), "{entry}");
        }
    }

    #[test]
    fn a_host_name_may_carry_dashes_and_underscores() {
        for name in ["my-host.lan", "my_host", "a-b_c.d-e"] {
            assert!(Allowlist::parse(&[name]).is_ok(), "{name}");
        }
    }

    #[test]
    fn a_host_entry_matches_that_exact_name() {
        let l = Allowlist::parse(&["MCP.lan."]).unwrap();
        assert!(l.permits(ip("10.0.0.1"), Some("mcp.lan")));
        assert!(l.permits(ip("10.0.0.1"), Some("Mcp.Lan.")));
        assert!(!l.permits(ip("10.0.0.1"), Some("a.mcp.lan")));
        assert!(!l.permits(ip("10.0.0.1"), Some("mcp.lan.evil")));
        assert!(!l.permits(ip("10.0.0.1"), None), "an IP literal never matches a name");
    }

    #[test]
    fn what_is_not_an_entry_is_refused() {
        for bad in ["", "*.lan", "http://mcp.lan", "mcp.lan:8080", "-a.lan", "a..lan", "10.0.0.0/x", "a b"] {
            assert!(Allowlist::parse(&[bad]).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_stored_form_names_the_surface_of_a_bad_entry_and_skips_an_unknown_one() {
        let mut m = BTreeMap::new();
        m.insert("mcp".to_string(), vec!["10.0.0.0/8".to_string()]);
        m.insert("future_surface".to_string(), vec!["!!".to_string()]);
        let lists = Lists::from_entries(&m).unwrap();
        assert!(lists.get(Surface::Mcp).permits(ip("10.2.3.4"), None));
        assert!(lists.get(Surface::Llm).is_empty());
        m.insert("oidc".to_string(), vec!["bad entry".to_string()]);
        assert_eq!(Lists::from_entries(&m).unwrap_err().0, Surface::Oidc);
    }

    #[test]
    fn every_surface_key_round_trips() {
        for s in Surface::ALL {
            assert_eq!(Surface::parse(s.as_str()), Some(s));
        }
        assert_eq!(Surface::parse("LLM"), None);
    }

    fn v4() -> impl Strategy<Value = Ipv4Addr> {
        any::<u32>().prop_map(Ipv4Addr::from)
    }

    proptest! {
        // The claim: a prefix entry permits exactly the addresses sharing its
        // first `len` bits — never one outside it. Not a property: anything
        // about a public address or IMDS (the guard decides those before the
        // list), and nothing about host names, which are exact strings.
        #[test]
        fn a_v4_prefix_permits_exactly_the_addresses_inside_it(net in v4(), len in 0u8..=32, probe in v4()) {
            let l = Allowlist::parse(&[format!("{net}/{len}")]).unwrap();
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            let inside = u32::from(net) & mask == u32::from(probe) & mask;
            prop_assert_eq!(l.permits(IpAddr::V4(probe), None), inside);
        }

        #[test]
        fn a_v6_prefix_permits_exactly_the_addresses_inside_it(net in any::<u128>(), len in 0u8..=128, probe in any::<u128>()) {
            let net = Ipv6Addr::from(net);
            let probe = Ipv6Addr::from(probe);
            prop_assume!(net.to_ipv4_mapped().is_none() && probe.to_ipv4_mapped().is_none());
            let l = Allowlist::parse(&[format!("{net}/{len}")]).unwrap();
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            let inside = u128::from(net) & mask == u128::from(probe) & mask;
            prop_assert_eq!(l.permits(IpAddr::V6(probe), None), inside);
        }

        // A host entry permits a name only when it is that name, compared
        // case-insensitively without a trailing dot — never a suffix of it.
        #[test]
        fn a_host_entry_never_matches_another_name(listed in "[a-z0-9]{1,8}(\\.[a-z0-9]{1,8}){0,2}", asked in "[a-zA-Z0-9]{1,8}(\\.[a-zA-Z0-9]{1,8}){0,3}\\.?") {
            let l = Allowlist::parse(&[listed.as_str()]).unwrap();
            let same = asked.trim_end_matches('.').eq_ignore_ascii_case(&listed);
            prop_assert_eq!(l.permits(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some(&asked)), same);
        }
    }
}
