//! Outbound HTTP to a tenant-configured extension endpoint — the web search
//! backend (`web.endpoint`) and the guardrail classifier (`classifier_url`).
//!
//! Both URLs are written by a TENANT admin, so every call goes through the
//! shared SSRF guard ([`streamscope_mcp_auth::ssrf`]): a [`GuardedResolver`]
//! inside the client vets every resolved address, an up-front
//! [`check_url_for`] vets an IP-literal host (the connector never
//! hands a literal to the resolver), and redirects are not followed at all.
//! The instance-metadata endpoint is refused on every path.
//!
//! An internal address is reachable only when the platform's `extensions`
//! egress allowlist lists it (by address, prefix or host name) — a list the
//! SYSTEM super-admin keeps, never a tenant.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use streamscope_mcp_auth::egress::Surface;
use streamscope_mcp_auth::ssrf::{Egress, GuardedResolver, GuardedResolverHandle, SsrfError, check_url_for};
use url::Url;

/// What an extension endpoint may reach.
const EGRESS: Egress = Egress::Surface(Surface::Extensions);

/// Parse a tenant-supplied extension endpoint at the write path and refuse
/// what the runtime guard would refuse now: not an absolute http(s) URL with a
/// host, the instance-metadata address, or an internal IP literal the
/// `extensions` egress allowlist does not list. A host NAME is resolved only at
/// call time (by the client's resolver), so an internal address behind one is
/// refused there, not here. Returns the reason it is unusable.
pub fn validate_endpoint(raw: &str) -> Result<Url, &'static str> {
    check_url_for(raw.trim(), EGRESS).map_err(refusal_reason)
}

fn refusal_reason(e: SsrfError) -> &'static str {
    match e {
        SsrfError::UrlParse(_) => "must be an absolute http(s) URL",
        SsrfError::BadScheme => "must use the http or https scheme",
        SsrfError::MissingHost => "must include a host",
        SsrfError::InternalAddress => {
            "is an internal address the platform's extensions egress list does not list (the \
             cloud metadata endpoint is never reachable)"
        }
        SsrfError::DnsLookup(_) | SsrfError::NoAddresses => "could not be resolved",
        SsrfError::PlainHttp => "must use https unless it is a listed private address",
    }
}

/// Bound on the warn-once memory and on the pending-refusal map; each is
/// cleared when full so neither grows with the number of endpoints tenants write.
const MEMORY_CAP: usize = 1024;

/// What the resolver reported for a host name — kept by kind so a caller can
/// rebuild the typed [`SsrfError`] after a failed send.
#[derive(Clone)]
enum ResolveFailure {
    /// The shared guard refused the resolved address.
    Refused,
    NoAddresses,
    Lookup(String),
}

impl ResolveFailure {
    fn from_ssrf(e: &SsrfError) -> Self {
        match e {
            SsrfError::NoAddresses => Self::NoAddresses,
            SsrfError::DnsLookup(m) => Self::Lookup(m.clone()),
            _ => Self::Refused,
        }
    }

    fn to_ssrf(&self) -> SsrfError {
        match self {
            Self::Refused => SsrfError::InternalAddress,
            Self::NoAddresses => SsrfError::NoAddresses,
            Self::Lookup(m) => SsrfError::DnsLookup(m.clone()),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::NoAddresses | Self::Lookup(_) => "lookup",
        }
    }
}

/// State shared by one extension's resolvers: the warn-once memory, keyed by
/// (kind, target) so a lookup failure never silences a later refusal, and the
/// last resolve failure per host, drained by [`ExtensionClients::take_refusal`].
#[derive(Default)]
struct ResolverState {
    seen: Mutex<HashSet<(&'static str, String)>>,
    failures: Mutex<HashMap<String, ResolveFailure>>,
}

impl ResolverState {
    fn first_time(&self, kind: &'static str, target: &str) -> bool {
        match self.seen.lock() {
            Ok(mut seen) => {
                if seen.len() >= MEMORY_CAP {
                    seen.clear();
                }
                seen.insert((kind, target.to_string()))
            }
            Err(_) => true,
        }
    }

    fn warn_refused(&self, extension: &'static str, target: &str, reason: &dyn std::fmt::Display) {
        if self.first_time("refused", target) {
            tracing::warn!(
                extension,
                target,
                "{extension} endpoint refused by the SSRF guard: {reason} — an internal \
                 address is reachable only when the platform's extensions egress list lists it"
            );
        }
    }

    fn record(&self, extension: &'static str, host: &str, failure: ResolveFailure) {
        match &failure {
            ResolveFailure::Refused => {
                self.warn_refused(extension, host, &SsrfError::InternalAddress);
            }
            ResolveFailure::NoAddresses | ResolveFailure::Lookup(_) => {
                if self.first_time(failure.kind(), host) {
                    tracing::warn!(extension, host, "{extension} endpoint host lookup failed");
                }
            }
        }
        if let Ok(mut failures) = self.failures.lock() {
            if failures.len() >= MEMORY_CAP {
                failures.clear();
            }
            failures.insert(host.to_string(), failure);
        }
    }

    fn take(&self, host: &str) -> Option<ResolveFailure> {
        self.failures.lock().ok()?.remove(host)
    }
}

/// `GuardedResolver` with its verdict made visible: every decision is the
/// shared guard's; this only records and logs what it reported.
struct LoggingResolver {
    inner: Arc<dyn reqwest::dns::Resolve>,
    handle: Arc<GuardedResolverHandle>,
    extension: &'static str,
    state: Arc<ResolverState>,
}

impl reqwest::dns::Resolve for LoggingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let fut = self.inner.resolve(name);
        let extension = self.extension;
        let handle = self.handle.clone();
        let state = self.state.clone();
        Box::pin(async move {
            let out = fut.await;
            if out.is_err() {
                // The guard stashes its typed verdict in the handle just before
                // returning the error; draining it here, with no await between,
                // ties it to this host.
                let failure = handle
                    .take_refusal()
                    .map_or_else(
                        || ResolveFailure::Lookup("resolution failed".to_string()),
                        |e| ResolveFailure::from_ssrf(&e),
                    );
                state.record(extension, &host, failure);
            }
            out
        })
    }
}

/// The client one extension sends through, guarded by the `extensions`
/// egress allowlist, and rebuilt when the egress lists change so a pooled
/// connection never outlives the listing it was opened under.
pub struct ExtensionClients {
    extension: &'static str,
    base: Box<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>,
    client: streamscope_mcp_auth::egress::Cached<reqwest::Client>,
    state: Arc<ResolverState>,
}

impl ExtensionClients {
    /// Build the client from `base`, which carries the caller's tuning (pool,
    /// timeouts, custom CA roots). `extension` names the surface in logs.
    ///
    /// Redirects are never followed: a search backend and a classifier answer
    /// in place. A 3xx reaches the caller as a non-success status.
    pub fn build(
        extension: &'static str,
        base: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static,
    ) -> Result<Self, reqwest::Error> {
        let this = Self {
            extension,
            base: Box::new(base),
            client: streamscope_mcp_auth::egress::Cached::new(),
            state: Arc::new(ResolverState::default()),
        };
        this.client()?;
        Ok(this)
    }

    fn client(&self) -> Result<reqwest::Client, reqwest::Error> {
        self.client.get_or_try_build(EGRESS, || {
            let (inner, handle) = GuardedResolver::pair(EGRESS);
            (self.base)()
                .dns_resolver(Arc::new(LoggingResolver {
                    inner,
                    handle: Arc::new(handle),
                    extension: self.extension,
                    state: self.state.clone(),
                }))
                .redirect(reqwest::redirect::Policy::none())
                .build()
        })
    }

    /// The client for `endpoint`, or the guard's refusal. An IP-literal host
    /// is classified here (IMDS refused whatever the list says); a host name
    /// is classified by the client's resolver at connect — after a failed send,
    /// [`Self::take_refusal`] recovers that verdict.
    pub fn for_endpoint(&self, endpoint: &str) -> Result<reqwest::Client, SsrfError> {
        match check_url_for(endpoint, EGRESS) {
            // A client that cannot be rebuilt (its TLS roots fail to load) is
            // no client: reported as the endpoint being unusable.
            Ok(_) => self.client().map_err(|e| SsrfError::DnsLookup(format!("client unavailable: {e}"))),
            Err(e) => {
                let target = Url::parse(endpoint)
                    .map(|u| u.origin().ascii_serialization())
                    .unwrap_or_else(|_| "<unparseable>".to_string());
                self.state.warn_refused(self.extension, &target, &e);
                Err(e)
            }
        }
    }

    /// After a failed send to `url`, the typed verdict the resolver reached for
    /// its host, if resolution is what failed — so a DNS-time refusal surfaces
    /// as an [`SsrfError`] rather than a generic connect error. Drains it.
    pub fn take_refusal(&self, url: &Url) -> Option<SsrfError> {
        self.state.take(url.host_str()?).map(|f| f.to_ssrf())
    }
}

/// Process-wide client for the guardrail classifier, trusting the process's
/// CA bundle ([`crate::tls::trusted_ca`]) beside the system roots, with the
/// classifier's tuning: warm keep-alive pool and `tcp_nodelay` on the small
/// JSON bodies.
///
/// One client is held, for the bundle it was built with, and rebuilt when the
/// bundle changes — so admin-api's console-uploaded CA reaches the classifier
/// without a restart. A build failure is held for its bundle too and returned
/// as text — the caller resolves it through the tenant `fail_mode`.
pub fn classifier_clients() -> Result<Arc<ExtensionClients>, String> {
    static HELD: HeldClients = RwLock::new(None);
    held_for(&HELD, crate::tls::trusted_ca, |roots| {
        ExtensionClients::build("classifier", move || {
            crate::tls::add_custom_roots(
                reqwest::Client::builder()
                    .tcp_nodelay(true)
                    .pool_idle_timeout(std::time::Duration::from_secs(90))
                    .pool_max_idle_per_host(16),
                roots.as_deref(),
            )
        })
    })
}

/// The one client a process holds for a surface, with the CA bundle it trusts.
type HeldClients = RwLock<Option<Held>>;
type Held = (Option<Arc<str>>, Result<Arc<ExtensionClients>, String>);

/// The client `held` keeps for the bundle `ca` reads, built with `build`
/// (handed the bundle) when `held` is empty or was built for another bundle.
fn held_for(
    held: &HeldClients,
    ca: impl Fn() -> Option<Arc<str>>,
    build: impl FnOnce(Option<Arc<str>>) -> Result<ExtensionClients, reqwest::Error>,
) -> Result<Arc<ExtensionClients>, String> {
    let current = |slot: &Option<Held>, ca: &Option<Arc<str>>| match slot {
        Some((bundle, clients)) if bundle == ca => Some(clients.clone()),
        _ => None,
    };
    if let Some(clients) = current(&held.read().unwrap_or_else(std::sync::PoisonError::into_inner), &ca()) {
        return clients;
    }
    // Built under the write lock for the bundle read again under it: of the
    // callers that missed together, one builds and the rest take its client,
    // and a caller that read an older bundle cannot store over a newer one. A
    // build happens only when the bundle changes.
    let mut slot = held.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    let ca = ca();
    if let Some(clients) = current(&slot, &ca) {
        return clients;
    }
    let built = build(ca.clone()).map(Arc::new).map_err(|e| e.to_string());
    *slot = Some((ca, built.clone()));
    built
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// `extensions` lists exactly `10.0.0.5` (`crate::test_egress`).
    fn clients() -> ExtensionClients {
        crate::test_egress::install();
        ExtensionClients::build("test", reqwest::Client::builder).unwrap()
    }

    #[test]
    fn a_held_client_is_rebuilt_only_when_the_bundle_changes() {
        crate::test_egress::install();
        let held: HeldClients = RwLock::new(None);
        let builds = std::cell::Cell::new(0);
        let get = |ca: Option<&str>| {
            let ca: Option<Arc<str>> = ca.map(Arc::from);
            held_for(&held, move || ca.clone(), |roots| {
                builds.set(builds.get() + 1);
                ExtensionClients::build("test", move || {
                    crate::tls::add_custom_roots(reqwest::Client::builder(), roots.as_deref())
                })
            })
            .unwrap()
        };
        let none = get(None);
        assert!(Arc::ptr_eq(&none, &get(None)), "the same bundle reuses the client");
        assert_eq!(builds.get(), 1);
        let uploaded = get(Some("bundle a"));
        assert!(!Arc::ptr_eq(&none, &uploaded), "a new bundle builds a new client");
        assert!(Arc::ptr_eq(&uploaded, &get(Some("bundle a"))), "the same text is the same bundle");
        assert_eq!(builds.get(), 2);
        get(Some("bundle b"));
        get(None);
        assert_eq!(builds.get(), 4, "a bundle removed is a change too");
    }

    #[test]
    fn an_internal_literal_is_reached_only_when_listed() {
        let c = clients();
        assert!(c.for_endpoint("http://10.0.0.5:8080/").is_ok());
        assert_matches!(c.for_endpoint("http://10.0.0.6:8080/"), Err(SsrfError::InternalAddress));
        assert_matches!(c.for_endpoint("http://127.0.0.1:8080/"), Err(SsrfError::InternalAddress));
        // A public literal needs no listing.
        assert!(c.for_endpoint("http://93.184.216.34/").is_ok());
    }

    #[test]
    fn the_metadata_endpoint_is_refused() {
        let c = clients();
        assert_matches!(
            c.for_endpoint("http://169.254.169.254/latest/meta-data"),
            Err(SsrfError::InternalAddress)
        );
        assert_matches!(c.for_endpoint("http://[fd00:ec2::254]/"), Err(SsrfError::InternalAddress));
    }

    #[test]
    fn a_non_http_endpoint_is_refused() {
        assert_matches!(clients().for_endpoint("file:///etc/passwd"), Err(SsrfError::BadScheme));
        assert_matches!(clients().for_endpoint("not a url"), Err(SsrfError::UrlParse(_)));
    }

    #[test]
    fn validation_accepts_an_http_url_with_a_host_and_nothing_else() {
        let _ = clients();
        assert!(validate_endpoint("http://search.example:8080").is_ok());
        assert!(validate_endpoint(" https://classify.example/ ").is_ok());
        assert!(validate_endpoint("ftp://search.example").is_err());
        assert!(validate_endpoint("search.example:8080").is_err());
        assert!(validate_endpoint("not a url").is_err());
        assert!(validate_endpoint("http://").is_err());
        assert!(validate_endpoint("file:///tmp/x").is_err());
        assert!(validate_endpoint("").is_err());
    }

    #[test]
    fn validation_refuses_an_internal_literal_the_list_does_not_list() {
        let _ = clients();
        assert!(validate_endpoint("http://10.0.0.5:8080/sub").is_ok());
        assert!(validate_endpoint("http://10.0.0.6:8080").is_err());
        assert!(validate_endpoint("http://127.0.0.1").is_err());
        // A host name is resolved only at call time.
        assert!(validate_endpoint("http://search.internal:8080").is_ok());
        assert!(validate_endpoint("http://169.254.169.254/").is_err());
    }
}
