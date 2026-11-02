//! A tenant's destination lists: named sets of network destinations that a
//! consumer attaches as **allow** or **block** — the sandbox guard on a
//! developer's machine, and the built-in Web tool's URL filter.
//!
//! A list is only a set of destinations; what a match means is the
//! attachment's. It is not the platform's internal-egress list, which decides
//! what the gateway itself may reach, and it never widens that list. Pure,
//! like the rest of the crate: the CLI's guard and the server's Web filter
//! read it.
//!
//! An entry is `<target>[:<ports>]`:
//! - a host name, matched exactly (`git.corp.example`);
//! - `*.<suffix>` — every name **under** the suffix, never the bare suffix
//!   (`*.corp.example` matches `a.corp.example`, not `corp.example`); the
//!   suffix has at least two labels, so `*.com` is refused;
//! - an IPv4 or IPv6 address, or a CIDR prefix (`10.0.0.0/8`,
//!   `[fd00::]/8`; an IPv6 target carrying ports is bracketed);
//! - `<ports>`: a comma-separated list of ports and ranges (`443,8000-8100`).
//!   Without it, what the entry names is the attachment's ([`Mode`]): an
//!   allowed entry is port 443 only, a blocked one every port — a host an
//!   administrator blocks is blocked whole.
//!
//! Refused: `*`, a prefix of length zero, a scheme or a path. The cloud
//! instance-metadata address never matches any entry, whatever the list says.
//!
//! A name entry matches a name; an address or prefix entry matches an address —
//! an IP-literal target, or (for the sandbox guard, which resolves) the
//! address a name resolved to. Matching never resolves.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most entries one list holds.
pub const MAX_ENTRIES: usize = 512;
/// The longest entry read.
pub const MAX_ENTRY_LEN: usize = 300;

/// The port an allowed entry without ports names.
pub const DEFAULT_PORT: u16 = 443;

/// How a list is attached, which decides what an entry without ports names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Port [`DEFAULT_PORT`] only.
    Allow,
    /// Every port.
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Exact(String),
    Suffix(String),
    Net(Prefix),
}

/// An inclusive port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Span {
    first: u16,
    last: u16,
}

/// One parsed entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    target: Target,
    /// Sorted, non-overlapping, non-adjacent, never empty; `None` when the
    /// entry states no ports (see [`Mode`]).
    ports: Option<Vec<Span>>,
}

/// Why an entry is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DestinationError {
    #[error("'{0}' is too long")]
    TooLong(String),
    #[error("'{0}' is empty")]
    Empty(String),
    #[error("'{0}' names every destination")]
    Everything(String),
    #[error("'{0}' carries a scheme or a path: write only the host")]
    NotAHost(String),
    #[error("'{0}' is not a host name, `*.suffix`, an IP address or a CIDR prefix")]
    BadTarget(String),
    #[error("'{0}' is a suffix of a single label: name at least two (`*.corp.example`)")]
    BareSuffix(String),
    #[error("'{0}' carries a bad port list: ports are 1-65535, a range is `first-last`")]
    BadPorts(String),
}

impl Destination {
    /// Parse one entry (see the module doc). Surrounding whitespace is
    /// trimmed; a name is lowercased without a trailing dot.
    pub fn parse(raw: &str) -> Result<Destination, DestinationError> {
        let entry = raw.trim();
        let owned = || entry.to_string();
        if entry.len() > MAX_ENTRY_LEN {
            return Err(DestinationError::TooLong(entry.chars().take(40).collect()));
        }
        if entry.is_empty() {
            return Err(DestinationError::Empty(owned()));
        }
        if entry.contains("://") || entry.contains('?') || entry.contains('#') || entry.contains('@') {
            return Err(DestinationError::NotAHost(owned()));
        }
        let (target, ports) = split_ports(entry).ok_or_else(|| DestinationError::BadTarget(owned()))?;
        let ports = match ports {
            None => None,
            Some(p) => Some(parse_ports(p).ok_or_else(|| DestinationError::BadPorts(owned()))?),
        };
        let target = parse_target(target).map_err(|e| e(owned()))?;
        Ok(Destination { target, ports })
    }

    /// True when `host` (a name, or an IP literal with or without brackets) on
    /// `port` is inside this entry, attached as `mode`. A name never matches
    /// an address entry, nor an address a name entry.
    pub fn matches(&self, host: &str, port: u16, mode: Mode) -> bool {
        match host_ip(host) {
            Some(ip) => self.matches_ip(ip, port, mode),
            None => self.matches_name(host, port, mode),
        }
    }

    /// True when the name `host` on `port` is inside this (name) entry.
    pub fn matches_name(&self, host: &str, port: u16, mode: Mode) -> bool {
        if !self.has_port(port, mode) {
            return false;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match &self.target {
            Target::Exact(name) => *name == host,
            Target::Suffix(suffix) => {
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix.as_str())
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
            Target::Net(_) => false,
        }
    }

    /// True when the address `ip` on `port` is inside this (address) entry.
    /// The metadata address is never inside any entry.
    pub fn matches_ip(&self, ip: IpAddr, port: u16, mode: Mode) -> bool {
        match &self.target {
            Target::Net(net) => self.has_port(port, mode) && !is_imds_ip(ip) && net.contains(ip),
            _ => false,
        }
    }

    /// True for an address or prefix entry, which only a resolved or literal
    /// address can match.
    pub fn is_address(&self) -> bool {
        matches!(self.target, Target::Net(_))
    }

    fn has_port(&self, port: u16, mode: Mode) -> bool {
        match (&self.ports, mode) {
            (Some(spans), _) => spans.iter().any(|s| s.first <= port && port <= s.last),
            (None, Mode::Allow) => port == DEFAULT_PORT,
            (None, Mode::Block) => true,
        }
    }
}

/// The canonical form: what is stored and shown, and what [`Destination::parse`]
/// reads back to the same entry. Ports are written as the entry states them.
impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            Target::Exact(name) => write!(f, "{name}")?,
            Target::Suffix(suffix) => write!(f, "*.{suffix}")?,
            Target::Net(net) => {
                let full = if net.addr.is_ipv4() { 32 } else { 128 };
                match (net.addr, net.len == full) {
                    (IpAddr::V4(v4), true) => write!(f, "{v4}")?,
                    (IpAddr::V4(v4), false) => write!(f, "{v4}/{}", net.len)?,
                    (IpAddr::V6(v6), true) => write!(f, "[{v6}]")?,
                    (IpAddr::V6(v6), false) => write!(f, "[{v6}]/{}", net.len)?,
                }
            }
        }
        let Some(ports) = &self.ports else {
            return Ok(());
        };
        f.write_str(":")?;
        for (i, span) in ports.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            if span.first == span.last {
                write!(f, "{}", span.first)?;
            } else {
                write!(f, "{}-{}", span.first, span.last)?;
            }
        }
        Ok(())
    }
}

/// A host as an address: an IP literal, bracketed or not.
pub fn host_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

fn masked(net: Prefix) -> IpAddr {
    match net.addr {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(net.len)).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(net.len)).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

/// Split `<target>[:<ports>]`. A bracketed target ends at its `]`; an
/// unbracketed one holding two or more `:` is a bare IPv6 address or prefix
/// and carries no ports.
fn split_ports(entry: &str) -> Option<(&str, Option<&str>)> {
    if entry.starts_with('[') {
        let close = entry.find(']')?;
        let rest = &entry[close + 1..];
        // `[v6]`, `[v6]/len`, then optionally `:ports`.
        let (len_part, ports): (&str, Option<&str>) = match rest.split_once(':') {
            Some((len_part, ports)) => (len_part, Some(ports)),
            None => (rest, None),
        };
        if !len_part.is_empty() && !len_part.starts_with('/') {
            return None;
        }
        return Some((&entry[..close + 1 + len_part.len()], ports));
    }
    if entry.matches(':').count() >= 2 {
        return Some((entry, None));
    }
    Some(match entry.split_once(':') {
        Some((target, ports)) => (target, Some(ports)),
        None => (entry, None),
    })
}

fn parse_ports(list: &str) -> Option<Vec<Span>> {
    let mut spans = Vec::new();
    for part in list.split(',') {
        let part = part.trim();
        let (first, last) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let first: u16 = first.parse().ok().filter(|p| *p > 0)?;
        let last: u16 = last.parse().ok().filter(|p| *p > 0)?;
        if first > last {
            return None;
        }
        spans.push(Span { first, last });
    }
    spans.sort();
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        match merged.last_mut() {
            Some(prev) if u32::from(span.first) <= u32::from(prev.last) + 1 => {
                prev.last = prev.last.max(span.last);
            }
            _ => merged.push(span),
        }
    }
    Some(merged)
}

type Refusal = fn(String) -> DestinationError;

fn parse_target(target: &str) -> Result<Target, Refusal> {
    if target == "*" || target == "*." {
        return Err(DestinationError::Everything);
    }
    if let Some(suffix) = target.strip_prefix("*.") {
        let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
        if !is_host_name(&suffix) {
            return Err(DestinationError::BadTarget);
        }
        if !suffix.contains('.') {
            return Err(DestinationError::BareSuffix);
        }
        return Ok(Target::Suffix(suffix));
    }
    if let Some((addr, len)) = target.split_once('/') {
        let Some(addr) = host_ip(addr) else {
            return Err(if is_host_name(addr) { DestinationError::NotAHost } else { DestinationError::BadTarget });
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len: u8 = len.parse().ok().filter(|l| *l <= max).ok_or(DestinationError::BadTarget as Refusal)?;
        let net = prefix(addr, len);
        if net.len == 0 {
            return Err(DestinationError::Everything);
        }
        return Ok(Target::Net(Prefix { addr: masked(net), len: net.len }));
    }
    if let Some(addr) = host_ip(target) {
        let addr = canonical_ip(addr);
        let len = if addr.is_ipv4() { 32 } else { 128 };
        return Ok(Target::Net(Prefix { addr, len }));
    }
    let name = target.trim_end_matches('.').to_ascii_lowercase();
    if !is_host_name(&name) {
        return Err(DestinationError::BadTarget);
    }
    Ok(Target::Exact(name))
}

/// A list's entries, parsed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DestinationSet {
    entries: Vec<Destination>,
}

/// An entry of a list that does not parse, by its position.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("entry {index}: {error}")]
pub struct ListError {
    pub index: usize,
    pub error: DestinationError,
}

impl DestinationSet {
    /// Parse one list's entries; the first that does not parse refuses the
    /// list, and so does a list longer than [`MAX_ENTRIES`].
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<DestinationSet, ListError> {
        if entries.len() > MAX_ENTRIES {
            return Err(ListError {
                index: MAX_ENTRIES,
                error: DestinationError::TooLong(format!("{} entries", entries.len())),
            });
        }
        Self::parse_union(entries)
    }

    /// Parse the entries of several lists flattened together — what a
    /// consumer receives — with no cap on their number: each list was capped
    /// when it was saved.
    pub fn parse_union<S: AsRef<str>>(entries: &[S]) -> Result<DestinationSet, ListError> {
        let entries = entries
            .iter()
            .enumerate()
            .map(|(index, e)| Destination::parse(e.as_ref()).map_err(|error| ListError { index, error }))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DestinationSet { entries })
    }

    /// The entries' canonical forms, in order, duplicates removed.
    pub fn canonical(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            let s = e.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// Parse the flattened union of allowed entries leniently: an entry this
    /// build cannot read is left out (it allows less) and returned beside the
    /// set, for the caller to report. Blocked entries are never read this way
    /// — leaving one out would allow what it blocks ([`Self::parse_union`]).
    pub fn parse_allowed<S: AsRef<str>>(entries: &[S]) -> (DestinationSet, Vec<(String, DestinationError)>) {
        let mut set = DestinationSet::default();
        let mut skipped = Vec::new();
        for e in entries {
            match Destination::parse(e.as_ref()) {
                Ok(d) => set.entries.push(d),
                Err(err) => skipped.push((e.as_ref().to_string(), err)),
            }
        }
        (set, skipped)
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Add another set's entries.
    pub fn extend(&mut self, other: DestinationSet) {
        self.entries.extend(other.entries);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True when an address or prefix entry is in the set — only then can a
    /// resolved address of a name the set does not name match it.
    pub fn has_addresses(&self) -> bool {
        self.entries.iter().any(Destination::is_address)
    }

    /// See [`Destination::matches`].
    pub fn matches(&self, host: &str, port: u16, mode: Mode) -> bool {
        self.entries.iter().any(|e| e.matches(host, port, mode))
    }

    /// See [`Destination::matches_name`].
    pub fn matches_name(&self, host: &str, port: u16, mode: Mode) -> bool {
        self.entries.iter().any(|e| e.matches_name(host, port, mode))
    }

    /// See [`Destination::matches_ip`].
    pub fn matches_ip(&self, ip: IpAddr, port: u16, mode: Mode) -> bool {
        self.entries.iter().any(|e| e.matches_ip(ip, port, mode))
    }
}

/// What a name alone decides for the sandbox guard, before any resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameDecision {
    /// A block entry names it: refused, whatever it resolves to.
    Blocked,
    /// An allow entry names it: each resolved address is still checked
    /// against the block entries ([`Policy::permits_addr`]).
    Allowed,
    /// No name entry decides: only an address entry can allow it.
    Undecided,
}

/// The sandbox's attached lists, flattened: a block match refuses, then an
/// allow match permits, then everything else is refused. The gateway is
/// decided before this, by the guard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub allow: DestinationSet,
    pub block: DestinationSet,
}

impl Policy {
    /// The verdict a name target's own entries give.
    pub fn by_name(&self, host: &str, port: u16) -> NameDecision {
        if self.block.matches_name(host, port, Mode::Block) {
            NameDecision::Blocked
        } else if self.allow.matches_name(host, port, Mode::Allow) {
            NameDecision::Allowed
        } else {
            NameDecision::Undecided
        }
    }

    /// True when the address `ip` on `port` may be dialled — an IP-literal
    /// target, or one address the name resolved to, given what the name
    /// decided (`name_allowed`). The metadata address never may. An allowed
    /// name never carries a loopback or unspecified address: the dial is made
    /// outside the confinement, which keeps this machine's loopback services
    /// out of reach — only an address entry naming one opens it. (A name
    /// resolving to another of the machine's own addresses — a LAN or bridge
    /// interface — is dialled like any other: the guard does not enumerate
    /// interfaces.)
    pub fn permits_addr(&self, name_allowed: bool, ip: IpAddr, port: u16) -> bool {
        let canon = canonical_ip(ip);
        let local = canon.is_loopback() || canon.is_unspecified();
        !is_imds_ip(ip)
            && !self.block.matches_ip(ip, port, Mode::Block)
            && ((name_allowed && !local) || self.allow.matches_ip(ip, port, Mode::Allow))
    }

    /// True when the policy can permit anything at all besides the gateway.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }

    /// True when resolving a name the entries do not decide can still find an
    /// address an allow entry matches.
    pub fn allows_by_address(&self) -> bool {
        self.allow.has_addresses()
    }
}

/// An address prefix. An IPv4-mapped IPv6 prefix of at least 96 bits is kept
/// as the IPv4 prefix it maps, the form an IPv4-mapped peer is compared as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, canonical_ip(ip)) {
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

/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is that IPv4 address.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn prefix(addr: IpAddr, len: u8) -> Prefix {
    match addr {
        IpAddr::V6(v6) if len >= 96 => match v6.to_ipv4_mapped() {
            Some(v4) => Prefix { addr: IpAddr::V4(v4), len: len - 96 },
            None => Prefix { addr, len },
        },
        _ => Prefix { addr, len },
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

/// The cloud instance-metadata addresses — `169.254.169.254` and AWS's
/// `fd00:ec2::254`, also as an IPv4-mapped, IPv4-compatible, NAT64
/// (`64:ff9b::/96`) or 6to4 (`2002::/16`) address. The same set the server's SSRF guard refuses;
/// keep them equal (locked by
/// `the_destination_matcher_and_the_ssrf_guard_agree_on_the_metadata_address`).
pub fn is_imds_ip(ip: IpAddr) -> bool {
    const V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
    match ip {
        IpAddr::V4(v4) => v4 == V4,
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            let v4_in = |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
            let nat64 = seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] && v4_in(seg[6], seg[7]) == V4;
            let six_to_four = seg[0] == 0x2002 && v4_in(seg[1], seg[2]) == V4;
            v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) || v6.to_ipv4() == Some(V4) || nat64 || six_to_four
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::assert_matches;

    const A: Mode = Mode::Allow;

    fn d(s: &str) -> Destination {
        Destination::parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_allowed_entry_without_ports_is_port_443_only() {
        let e = d("git.corp.example");
        assert!(e.matches("git.corp.example", 443, A));
        assert!(!e.matches("git.corp.example", 442, A));
        assert!(!e.matches("git.corp.example", 444, A));
        assert!(!e.matches("git.corp.example", 80, A));
        assert_eq!(e.to_string(), "git.corp.example", "the canonical form keeps that it states no ports");
    }

    #[test]
    fn a_blocked_entry_without_ports_is_every_port_and_one_with_ports_only_those() {
        let bare = d("pastebin.com");
        for port in [1, 80, 443, 65535] {
            assert!(bare.matches("pastebin.com", port, Mode::Block), "{port}");
        }
        assert!(!bare.matches("other.com", 80, Mode::Block));
        let net = d("10.9.0.0/16");
        assert!(net.matches_ip(ip("10.9.1.1"), 22, Mode::Block));
        assert!(!net.matches_ip(ip("10.9.1.1"), 22, A));
        let stated = d("git.lan:22");
        assert!(stated.matches("git.lan", 22, Mode::Block));
        assert!(!stated.matches("git.lan", 443, Mode::Block), "stated ports bind a block too");
        assert_eq!(d("git.lan:443").to_string(), "git.lan:443", "a stated 443 stays stated");
    }

    #[test]
    fn a_port_range_is_inclusive_on_both_ends() {
        let e = d("svc.lan:8000-8100");
        assert!(!e.matches("svc.lan", 7999, A));
        assert!(e.matches("svc.lan", 8000, A));
        assert!(e.matches("svc.lan", 8100, A));
        assert!(!e.matches("svc.lan", 8101, A));
    }

    #[test]
    fn a_port_list_matches_each_and_nothing_between() {
        let e = d("github.com:443,22");
        assert!(e.matches("github.com", 22, A));
        assert!(e.matches("github.com", 443, A));
        assert!(!e.matches("github.com", 23, A));
        assert_eq!(e.to_string(), "github.com:22,443");
    }

    #[test]
    fn overlapping_and_adjacent_ranges_merge() {
        assert_eq!(d("a.lan:10-20,15-30,31,40").to_string(), "a.lan:10-31,40");
        assert_eq!(d("a.lan:5,5").to_string(), "a.lan:5");
        assert_eq!(d("a.lan:65535,1").to_string(), "a.lan:1,65535");
    }

    #[test]
    fn a_bad_port_list_is_refused() {
        for e in ["a.lan:0", "a.lan:65536", "a.lan:", "a.lan:20-10", "a.lan:x", "a.lan:1,,2", "a.lan:-5", "a.lan:0-5"] {
            assert_matches!(Destination::parse(e), Err(DestinationError::BadPorts(_)), "{e}");
        }
        assert!(Destination::parse("a.lan:1-65535").is_ok(), "the full range is a list an admin may write");
    }

    #[test]
    fn an_exact_name_matches_only_itself() {
        let e = d("Git.Corp.Example.");
        assert!(e.matches("git.corp.example", 443, A));
        assert!(e.matches("GIT.corp.example.", 443, A));
        assert!(!e.matches("a.git.corp.example", 443, A));
        assert!(!e.matches("git.corp.example.evil", 443, A));
        assert!(!e.matches("corp.example", 443, A));
    }

    #[test]
    fn a_suffix_matches_names_under_it_and_never_the_bare_suffix() {
        let e = d("*.corp.example");
        assert!(e.matches("a.corp.example", 443, A));
        assert!(e.matches("a.b.corp.example", 443, A));
        assert!(!e.matches("corp.example", 443, A), "the bare suffix");
        assert!(!e.matches("evilcorp.example", 443, A), "a name merely ending with the suffix text");
        assert!(!e.matches("a.corp.example.evil", 443, A));
        assert!(!e.matches(".corp.example", 443, A), "an empty label is not a name under it");
        assert_eq!(e.to_string(), "*.corp.example");
    }

    #[test]
    fn a_single_label_suffix_and_everything_are_refused() {
        assert_matches!(Destination::parse("*.com"), Err(DestinationError::BareSuffix(_)));
        for e in ["*", "*.", "*:443", "0.0.0.0/0", "[::]/0", "::/0", "::ffff:0.0.0.0/96"] {
            assert_matches!(Destination::parse(e), Err(DestinationError::Everything(_)), "{e}");
        }
        assert!(Destination::parse("0.0.0.0/1").is_ok(), "the shortest prefix that is not everything");
        assert!(Destination::parse("*.co.uk").is_ok(), "two labels are a suffix an admin may write");
    }

    #[test]
    fn a_scheme_or_a_path_is_refused() {
        for e in ["https://github.com", "github.com/org", "user@github.com", "a.lan?x", "a.lan#x"] {
            assert_matches!(
                Destination::parse(e),
                Err(DestinationError::NotAHost(_)),
                "{e}"
            );
        }
        for e in ["", "   "] {
            assert_matches!(Destination::parse(e), Err(DestinationError::Empty(_)), "{e:?}");
        }
        for e in ["a..lan", "-a.lan", "a b", "[nope]", "[fd00::1]x", "10.0.0.0/33", "[fd00::]/129", "*.a..b"] {
            assert!(Destination::parse(e).is_err(), "{e}");
        }
        assert_matches!(
            Destination::parse(&"a".repeat(MAX_ENTRY_LEN + 1)),
            Err(DestinationError::TooLong(_))
        );
    }

    #[test]
    fn a_prefix_matches_inside_and_refuses_on_both_sides() {
        let e = d("10.1.0.0/16");
        assert!(e.matches_ip(ip("10.1.0.0"), 443, A));
        assert!(e.matches_ip(ip("10.1.255.255"), 443, A));
        assert!(!e.matches_ip(ip("10.0.255.255"), 443, A));
        assert!(!e.matches_ip(ip("10.2.0.0"), 443, A));
        assert!(!e.matches_ip(ip("10.1.0.1"), 80, A), "outside its ports");
    }

    #[test]
    fn an_address_entry_never_matches_a_name_nor_a_name_entry_an_address() {
        assert!(!d("10.0.0.0/8").matches("ten.lan", 443, A));
        assert!(!d("ten.lan").matches_ip(ip("10.0.0.1"), 443, A));
        assert!(d("10.0.0.5").matches("10.0.0.5", 443, A), "an IP-literal host is matched as an address");
        assert!(d("[fd00::5]:22").matches("[fd00::5]", 22, A));
        assert!(d("10.0.0.5").is_address());
        assert!(!d("*.lan.example").is_address());
    }

    #[test]
    fn the_canonical_prefix_drops_its_host_bits_and_maps_v4() {
        assert_eq!(d("10.1.2.3/16").to_string(), "10.1.0.0/16");
        assert_eq!(d("10.1.2.3/32").to_string(), "10.1.2.3");
        assert_eq!(d("[::ffff:10.0.0.0]/104:80").to_string(), "10.0.0.0/8:80");
        assert_eq!(d("::ffff:10.1.2.3").to_string(), "10.1.2.3");
        assert_eq!(d("[fd00::1]/8:22").to_string(), "[fd00::]/8:22");
        assert_eq!(d("fd00::1").to_string(), "[fd00::1]");
    }

    #[test]
    fn the_metadata_address_never_matches_whatever_the_list_says() {
        for e in ["169.254.169.254", "169.254.0.0/16", "0.0.0.0/1", "128.0.0.0/1", "[fd00:ec2::254]", "[fd00::]/8"] {
            let e = d(e);
            assert!(!e.matches_ip(ip("169.254.169.254"), 443, A), "{e}");
            assert!(!e.matches_ip(ip("fd00:ec2::254"), 443, A), "{e}");
        }
        assert!(d("169.254.0.0/16").matches_ip(ip("169.254.169.253"), 443, A), "its neighbour still matches");
        let p = Policy { allow: DestinationSet::parse(&["169.254.0.0/16"]).unwrap(), block: DestinationSet::default() };
        assert!(!p.permits_addr(true, ip("169.254.169.254"), 443), "not even through an allowed name");
        assert!(p.permits_addr(true, ip("169.254.169.253"), 443));
    }

    #[test]
    fn an_allowed_name_never_reaches_a_local_address_an_address_entry_does_not_name() {
        let p = Policy { allow: DestinationSet::parse(&["a.lan"]).unwrap(), block: DestinationSet::default() };
        for local in ["127.0.0.1", "127.8.9.1", "::1", "0.0.0.0", "::", "::ffff:127.0.0.1"] {
            assert!(!p.permits_addr(true, ip(local), 443), "{local}");
        }
        assert!(p.permits_addr(true, ip("10.0.0.1"), 443), "the positive control");
        let named = Policy { allow: DestinationSet::parse(&["127.0.0.1:5000"]).unwrap(), block: DestinationSet::default() };
        assert!(named.permits_addr(true, ip("127.0.0.1"), 5000), "an address entry naming it opens it");
        assert!(named.permits_addr(false, ip("127.0.0.1"), 5000));
    }

    #[test]
    fn a_block_wins_over_an_allow() {
        let p = Policy {
            allow: DestinationSet::parse(&["*.corp.example", "10.0.0.0/8"]).unwrap(),
            block: DestinationSet::parse(&["hr.corp.example", "10.9.0.0/16"]).unwrap(),
        };
        assert_eq!(p.by_name("git.corp.example", 443), NameDecision::Allowed);
        assert_eq!(p.by_name("hr.corp.example", 443), NameDecision::Blocked);
        assert_eq!(p.by_name("example.org", 443), NameDecision::Undecided);
        assert!(p.permits_addr(false, ip("10.1.0.1"), 443));
        assert!(!p.permits_addr(false, ip("10.9.0.1"), 443), "a blocked prefix inside an allowed one");
        assert_eq!(p.by_name("hr.corp.example", 80), NameDecision::Blocked, "a bare block is every port");
        assert!(!p.permits_addr(true, ip("10.9.0.1"), 22));
        assert!(!p.permits_addr(true, ip("10.9.0.1"), 443), "an allowed name resolving into a blocked prefix");
        assert!(p.permits_addr(true, ip("203.0.113.1"), 443), "an allowed name, any unblocked address");
        assert!(!p.permits_addr(false, ip("203.0.113.1"), 443), "nothing allows it");
        assert!(p.allows_by_address());
        let names_only = Policy { allow: DestinationSet::parse(&["a.lan"]).unwrap(), block: DestinationSet::default() };
        assert!(!names_only.allows_by_address());
        assert!(!names_only.is_empty());
        assert!(Policy::default().is_empty());
    }

    #[test]
    fn a_list_names_its_first_bad_entry_and_canonicalises_without_duplicates() {
        let err = DestinationSet::parse(&["a.lan", "b.lan", "*"]).unwrap_err();
        assert_eq!(err.index, 2);
        let s = DestinationSet::parse(&["A.lan", "a.lan.", "b.lan:22"]).unwrap();
        assert_eq!(s.canonical(), vec!["a.lan".to_string(), "b.lan:22".to_string()]);
        let many: Vec<String> = (0..=MAX_ENTRIES).map(|i| format!("h{i}.lan")).collect();
        assert_eq!(DestinationSet::parse(&many).unwrap_err().index, MAX_ENTRIES);
        assert!(DestinationSet::parse(&many[..MAX_ENTRIES]).is_ok());
        assert!(DestinationSet::parse_union(&many).is_ok(), "several lists flattened are not one list");
        assert_eq!(DestinationSet::parse_union(&["a.lan", "*"]).unwrap_err().index, 1);
        let (set, skipped) = DestinationSet::parse_allowed(&["a.lan", "*", "b.lan"]);
        assert_eq!(set.canonical(), vec!["a.lan".to_string(), "b.lan".to_string()]);
        assert_eq!(set.len(), 2);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "*");
    }

    #[test]
    fn an_entry_is_read_up_to_its_length_cap_and_refused_past_it() {
        // `aaaaaaaaaa.lan:1`, padded with ports and a leading label byte to
        // exactly `len` bytes.
        let at = |len: usize| {
            let mut e = String::from("aaaaaaaaaa.lan:1");
            while e.len() + 2 <= len {
                e.push_str(",1");
            }
            if e.len() < len {
                e.insert(0, 'b');
            }
            e
        };
        assert_eq!(at(MAX_ENTRY_LEN).len(), MAX_ENTRY_LEN);
        assert!(Destination::parse(&at(MAX_ENTRY_LEN)).is_ok(), "an entry at the cap is read");
        assert_eq!(at(MAX_ENTRY_LEN + 1).len(), MAX_ENTRY_LEN + 1);
        assert_matches!(Destination::parse(&at(MAX_ENTRY_LEN + 1)), Err(DestinationError::TooLong(_)));
    }

    #[test]
    fn a_one_port_range_is_a_port() {
        assert_eq!(d("a.lan:5-5").to_string(), "a.lan:5");
        assert!(d("a.lan:5-5").matches("a.lan", 5, A));
    }

    #[test]
    fn an_ipv6_prefix_masks_and_matches_its_own_bits() {
        assert_eq!(d("[2001:db8:1:2:3:4:5:6]/64").to_string(), "[2001:db8:1:2::]/64");
        assert_eq!(d("10.1.2.3/24").to_string(), "10.1.2.0/24");
        let e = d("[2001:db8::]/32");
        assert!(e.matches_ip(ip("2001:db8:ffff:ffff::1"), 443, A));
        assert!(e.matches_ip(ip("2001:db8::"), 443, A));
        assert!(!e.matches_ip(ip("2001:db9::"), 443, A));
        assert!(!e.matches_ip(ip("2001:db7:ffff::"), 443, A));
        // Below /96 an IPv4-mapped prefix stays IPv6, and never covers a v4 address.
        let short = d("[::ffff:0:0]/95");
        assert!(!short.matches_ip(ip("10.1.2.3"), 443, A));
        assert!(short.matches_ip(ip("::fffe:1:2"), 443, A));
    }

    #[test]
    fn a_set_extends_and_matches_names_and_addresses() {
        let mut s = DestinationSet::parse(&["a.lan"]).unwrap();
        assert!(s.matches("a.lan", 443, A) && !s.matches("b.lan", 443, A));
        s.extend(DestinationSet::parse(&["b.lan", "10.0.0.0/8"]).unwrap());
        assert!(s.matches("b.lan", 443, A) && s.matches("10.1.1.1", 443, A) && !s.matches("c.lan", 443, A));
        assert!(s.has_addresses());
        assert!(!DestinationSet::parse(&["a.lan"]).unwrap().has_addresses());
    }

    #[test]
    fn the_metadata_address_is_recognised_in_every_encoding_and_only_it() {
        for yes in ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254", "::169.254.169.254",
                    "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::"] {
            assert!(is_imds_ip(ip(yes)), "{yes}");
        }
        for no in ["169.254.169.253", "169.254.168.254", "fd00:ec2::253", "::ffff:169.254.169.253",
                   "64:ff9b::a9fe:a9fd", "64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fd::", "2003:a9fe:a9fe::",
                   "::1", "10.0.0.1"] {
            assert!(!is_imds_ip(ip(no)), "{no}");
        }
    }

    // A label starts with a letter: an all-digit name is an IPv4 literal,
    // which is matched as an address.
    fn label() -> impl Strategy<Value = String> {
        "[a-z]([a-z0-9-]{0,6}[a-z0-9])?"
    }

    fn name() -> impl Strategy<Value = String> {
        prop::collection::vec(label(), 1..4).prop_map(|l| l.join("."))
    }

    fn entry() -> impl Strategy<Value = String> {
        let ports = prop::option::of(prop::collection::vec((1u16..=65535, 0u16..50), 1..4).prop_map(|v| {
            v.iter()
                .map(|(a, w)| if *w == 0 { a.to_string() } else { format!("{a}-{}", a.saturating_add(*w)) })
                .collect::<Vec<_>>()
                .join(",")
        }));
        let target = prop_oneof![
            name(),
            prop::collection::vec(label(), 2..4).prop_map(|l| format!("*.{}", l.join("."))),
            (any::<u32>(), 1u8..=32).prop_map(|(a, l)| format!("{}/{l}", std::net::Ipv4Addr::from(a))),
            any::<u32>().prop_map(|a| std::net::Ipv4Addr::from(a).to_string()),
            (any::<u128>(), 1u8..=128).prop_map(|(a, l)| format!("[{}]/{l}", std::net::Ipv6Addr::from(a))),
        ];
        (target, ports).prop_map(|(t, p)| match p {
            Some(p) => format!("{t}:{p}"),
            None => t,
        })
    }

    proptest! {
        /// The canonical form reads back to the same entry, and is a fixed point.
        #[test]
        fn the_canonical_form_reads_back_to_the_same_entry(e in entry()) {
            if let Ok(parsed) = Destination::parse(&e) {
                let canon = parsed.to_string();
                let again = Destination::parse(&canon).unwrap();
                prop_assert_eq!(&again, &parsed);
                prop_assert_eq!(again.to_string(), canon);
            }
        }

        /// A suffix entry matches a name only when the name is strictly under
        /// the suffix, label-aligned.
        #[test]
        fn a_suffix_never_matches_a_name_outside_it(suffix in prop::collection::vec(label(), 2..3), host in name(), port in 1u16..=65535) {
            let suffix = suffix.join(".");
            let e = Destination::parse(&format!("*.{suffix}:1-65535")).unwrap();
            let host_matches = e.matches(&host, port, A);
            prop_assert_eq!(host_matches, host.ends_with(&format!(".{suffix}")));
            let under = format!("{host}.{suffix}");
            prop_assert!(e.matches(&under, port, A));
            prop_assert!(!e.matches(&suffix, port, A));
        }

        /// An exact entry matches its own name and no other.
        #[test]
        fn an_exact_name_never_matches_another_name(a in name(), b in name()) {
            let e = Destination::parse(&a).unwrap();
            prop_assert_eq!(e.matches(&b, 443, A), a == b);
        }

        /// A prefix entry matches exactly the addresses its mask covers.
        #[test]
        fn a_prefix_matches_exactly_its_mask(net in any::<u32>(), len in 1u8..=32, probe in any::<u32>()) {
            let e = Destination::parse(&format!("{}/{len}", std::net::Ipv4Addr::from(net))).unwrap();
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            let probe_ip = IpAddr::V4(probe.into());
            let inside = net & mask == probe & mask && !is_imds_ip(probe_ip);
            prop_assert_eq!(e.matches_ip(probe_ip, 443, A), inside);
        }

        /// No entry the parser accepts ever matches the metadata address.
        #[test]
        fn no_entry_matches_the_metadata_address(e in entry(), port in 1u16..=65535) {
            if let Ok(parsed) = Destination::parse(&e) {
                prop_assert!(!parsed.matches_ip(ip("169.254.169.254"), port, A));
                prop_assert!(!parsed.matches_ip(ip("fd00:ec2::254"), port, A));
            }
        }
    }

    // Deliberately NOT a property: that every generated entry parses. The
    // generator emits port ranges past 65535 (saturated) and single-label
    // suffixes are refused by design; acceptance is pinned by the example
    // tests above.
}
