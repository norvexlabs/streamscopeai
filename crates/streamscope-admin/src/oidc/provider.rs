//! Cached provider metadata and signing keys.
//!
//! Discovery is a network round trip plus a JWKS fetch, and it is on the login
//! path, so it is cached per issuer. Two behaviours here are correctness rather
//! than optimisation, and both are easy to omit:
//!
//! 1. **Key rotation.** A provider rolls its signing key whenever it likes and
//!    announces it only by signing with a new `kid`. A cache that waits out its
//!    TTL would reject every login until it expired. On an unresolvable `kid`
//!    the entry is dropped and re-fetched once — bounded by a cooldown so a
//!    stream of bogus tokens cannot turn logins into a fetch amplifier.
//!
//! 2. **Algorithm pinning.** The verifier defaults to RS256 but then *widens*
//!    to whatever the provider's metadata advertises. For a confidential client
//!    that legally includes the HMAC algorithms, whose key is the client secret
//!    — so a provider advertising HS256 could hand us a token signed with a
//!    value we already hold, and it would verify. We intersect with an
//!    asymmetric-only allowlist and refuse rather than fall back.

use std::sync::Arc;
use std::time::Duration;

use openidconnect::core::CoreJwsSigningAlgorithm;
use openidconnect::{IssuerUrl, ProviderMetadataWithLogout};

use super::http::GuardedOidcHttpClient;
use super::OidcError;

/// How long provider metadata stays cached. Matches what a provider's own
/// cache headers typically suggest; key rotation is handled by the `kid`-miss
/// path rather than by shortening this.
const METADATA_TTL: Duration = Duration::from_secs(3600);

/// Bound on distinct issuers held at once. A deployment has one issuer per
/// tenant at most, and tenants sharing an IdP share the entry.
const MAX_ISSUERS: u64 = 256;

/// Minimum gap between forced re-fetches for one issuer, so a stream of tokens
/// bearing unknown `kid`s cannot be turned into load on the provider.
const REFETCH_COOLDOWN: Duration = Duration::from_secs(60);

/// How long a discovery failure is remembered. Short enough that a provider
/// coming back is noticed promptly, long enough that a request loop cannot turn
/// into an outbound loop.
const FAILURE_TTL: Duration = Duration::from_secs(60);

/// The signature algorithms an ID token may use.
///
/// Asymmetric only, deliberately. The alternative is verifying a token with the
/// client secret, which converts a value the provider and we both hold into a
/// signing key — anything able to read it could then mint identities.
const ASYMMETRIC_ALGS: &[CoreJwsSigningAlgorithm] = &[
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha384,
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha512,
    CoreJwsSigningAlgorithm::RsaSsaPssSha256,
    CoreJwsSigningAlgorithm::RsaSsaPssSha384,
    CoreJwsSigningAlgorithm::RsaSsaPssSha512,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EcdsaP384Sha384,
    CoreJwsSigningAlgorithm::EcdsaP521Sha512,
    CoreJwsSigningAlgorithm::EdDsa,
];

/// A provider's metadata plus the keys fetched with it.
pub struct CachedProvider {
    pub metadata: ProviderMetadataWithLogout,
}

/// Per-issuer cache of discovery documents.
#[derive(Clone)]
pub struct ProviderCache {
    entries: moka::future::Cache<String, Arc<CachedProvider>>,
    /// Issuers whose entry was force-refreshed recently, keyed to suppress a
    /// repeat. Presence is the whole value; the unit payload is incidental.
    refetch_cooldown: moka::future::Cache<String, ()>,
    /// Issuers whose last discovery failed, with the failure, held briefly.
    ///
    /// `try_get_with` caches successes only, so without this a provider that is
    /// down or misconfigured is re-contacted on **every** request. That matters
    /// because `/begin` is reachable through an unauthenticated relay on the
    /// browser tier: a loop against a tenant whose IdP is erroring would turn
    /// one inbound request into one outbound discovery plus one JWKS fetch,
    /// indefinitely. Remembering the failure for a minute makes the cost of a
    /// flood constant instead of proportional, and stops us hammering a
    /// provider that is already having a bad day.
    failures: moka::future::Cache<String, Arc<OidcError>>,
}

impl ProviderCache {
    pub fn new() -> Self {
        Self {
            entries: moka::future::Cache::builder()
                .max_capacity(MAX_ISSUERS)
                .time_to_live(METADATA_TTL)
                .build(),
            refetch_cooldown: moka::future::Cache::builder()
                .max_capacity(MAX_ISSUERS)
                .time_to_live(REFETCH_COOLDOWN)
                .build(),
            failures: moka::future::Cache::builder()
                .max_capacity(MAX_ISSUERS)
                .time_to_live(FAILURE_TTL)
                .build(),
        }
    }

    /// Fetch (or reuse) the provider's metadata and keys.
    ///
    /// Concurrent misses for one issuer collapse into a single fetch, so a
    /// burst of logins against a cold cache does not fan out into a burst of
    /// requests at the provider. A recent failure is replayed rather than
    /// retried, for the same reason — see [`ProviderCache::failures`].
    pub async fn get(&self, issuer: &str) -> Result<Arc<CachedProvider>, OidcError> {
        let key = normalize_issuer(issuer);
        if let Some(recent) = self.failures.get(&key).await {
            return Err(recent.as_ref().clone());
        }
        // Keyed on the normalized form so the two spellings share one entry,
        // but discovered with the operator's own — the provider is asked using
        // the string the operator configured, never a rewritten one.
        let owned = issuer.to_string();
        let result = self
            .entries
            .try_get_with(key.clone(), async move { discover(&owned).await.map(Arc::new) })
            .await;
        match result {
            Ok(provider) => Ok(provider),
            Err(e) => {
                self.failures.insert(key, e.clone()).await;
                Err(e.as_ref().clone())
            }
        }
    }

    /// Forget a remembered failure, so the next call re-contacts the provider.
    ///
    /// An operator who just corrected their issuer URL must not be told the old
    /// error for another minute — the settings save is exactly the event that
    /// makes the cached failure stale.
    pub async fn forget_failure(&self, issuer: &str) {
        self.failures.invalidate(&normalize_issuer(issuer)).await;
    }

    /// Drop an issuer's entry and fetch again, at most once per cooldown.
    ///
    /// Returns the refreshed entry, or `None` when the cooldown suppressed the
    /// attempt — the caller then treats the original failure as final.
    pub async fn refresh_after_key_miss(
        &self,
        issuer: &str,
    ) -> Result<Option<Arc<CachedProvider>>, OidcError> {
        let key = normalize_issuer(issuer);
        if self.refetch_cooldown.get(&key).await.is_some() {
            return Ok(None);
        }
        self.refetch_cooldown.insert(key.clone(), ()).await;
        self.entries.invalidate(&key).await;
        self.get(issuer).await.map(Some)
    }

    /// The provider's RP-initiated logout endpoint, when it publishes one.
    pub async fn end_session_endpoint(&self, issuer: &str) -> Result<Option<String>, OidcError> {
        Ok(self
            .get(issuer)
            .await?
            .metadata
            .additional_metadata()
            .end_session_endpoint
            .as_ref()
            .map(|u| u.to_string()))
    }
}

impl Default for ProviderCache {
    fn default() -> Self {
        Self::new()
    }
}

/// The cache key for an issuer: one entry however the operator spelled it.
///
/// Purely a key. It is never what the provider is asked with — see [`discover`],
/// which uses the operator's own string.
pub(crate) fn normalize_issuer(issuer: &str) -> String {
    issuer.trim_end_matches('/').to_string()
}

/// The same issuer written the other way round.
///
/// Providers disagree about the trailing slash — Auth0's canonical issuer
/// carries one, Dex's does not — and the value an operator copies out of their
/// provider's console is whichever that provider prefers.
fn toggle_trailing_slash(issuer: &str) -> String {
    match issuer.strip_suffix('/') {
        Some(without) => without.to_string(),
        None => format!("{issuer}/"),
    }
}

/// Fetch a provider's discovery document and keys.
///
/// The crate compares the document's declared `issuer` against the string we
/// asked with, byte for byte, and a trailing slash is enough to fail it. That
/// comparison exists to catch a document pointing at a *different* provider,
/// which a slash never does — so a spelling mismatch is retried with the other
/// spelling rather than surfaced to the operator, who has no way to tell it
/// apart from an unreachable provider. Every other failure — unreachable,
/// malformed, or an issuer that is genuinely somebody else — propagates on the
/// first attempt.
async fn discover(issuer: &str) -> Result<CachedProvider, OidcError> {
    match discover_exact(issuer).await {
        Err(DiscoverFailure::IssuerSpelling(first)) => {
            discover_exact(&toggle_trailing_slash(issuer))
                .await
                // Report the operator's own spelling on failure. The retry is an
                // implementation detail, and naming a URL they never typed sends
                // them looking for a configuration mistake that isn't there. A
                // provider that did not answer the retry is still an outage.
                .map_err(|e| match OidcError::from(e) {
                    unreachable @ OidcError::Unreachable(_) => unreachable,
                    _ => OidcError::Discovery(first),
                })
        }
        other => other.map_err(OidcError::from),
    }
}

/// Why a single discovery attempt failed.
///
/// Only the issuer-spelling case is worth a second attempt, so it is a distinct
/// variant rather than a string match on the crate's message — which would turn
/// a message reword upstream into a silently-lost retry.
enum DiscoverFailure {
    IssuerSpelling(String),
    Other(OidcError),
}

impl From<DiscoverFailure> for OidcError {
    fn from(f: DiscoverFailure) -> Self {
        match f {
            DiscoverFailure::IssuerSpelling(msg) => OidcError::Discovery(msg),
            DiscoverFailure::Other(e) => e,
        }
    }
}

async fn discover_exact(issuer: &str) -> Result<CachedProvider, DiscoverFailure> {
    let http = GuardedOidcHttpClient::new();
    let url = IssuerUrl::new(issuer.to_string()).map_err(|e| {
        DiscoverFailure::Other(OidcError::Discovery(format!("issuer URL is invalid: {e}")))
    })?;

    // Fetches the discovery document and the JWKS, and refuses a document
    // whose declared `issuer` is not the one we asked for — the check that
    // stops a compromised response redirecting us to another provider's
    // endpoints.
    match ProviderMetadataWithLogout::discover_async(url, &http).await {
        Ok(metadata) => Ok(CachedProvider { metadata }),
        Err(openidconnect::DiscoveryError::Validation(msg)) => {
            Err(DiscoverFailure::IssuerSpelling(msg))
        }
        Err(openidconnect::DiscoveryError::Request(super::http::OidcHttpError::Unreachable(e))) => {
            Err(DiscoverFailure::Other(OidcError::Unreachable(e)))
        }
        Err(e) => Err(DiscoverFailure::Other(OidcError::Discovery(e.to_string()))),
    }
}

/// The algorithms this provider may sign with: what it advertises, narrowed to
/// what we accept.
///
/// An empty intersection is an error rather than a fallback — a provider that
/// offers only symmetric algorithms is one we decline to trust, and silently
/// reverting to a default would defeat the pinning.
pub fn pinned_algs(
    advertised: &[CoreJwsSigningAlgorithm],
) -> Result<Vec<CoreJwsSigningAlgorithm>, OidcError> {
    let allowed: Vec<CoreJwsSigningAlgorithm> = advertised
        .iter()
        .filter(|a| ASYMMETRIC_ALGS.contains(a))
        .cloned()
        .collect();
    if allowed.is_empty() {
        return Err(OidcError::Verification(
            "the identity provider advertises no asymmetric signing algorithm".into(),
        ));
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    /// The discovery document Microsoft publishes as AD FS's own, verbatim
    /// (learn.microsoft.com, "Single log-out for OpenID Connect with AD FS").
    /// It carries values outside the OIDC registries — `srv_challenge`,
    /// `windows_client_authentication`, `pairwise`, token-binding flags — and
    /// every one of them must parse, or no AD FS tenant can sign in at all.
    const ADFS_DISCOVERY: &str = r#"{
        "issuer":"https://fs.fabidentity.com/adfs",
        "authorization_endpoint":"https://fs.fabidentity.com/adfs/oauth2/authorize/",
        "token_endpoint":"https://fs.fabidentity.com/adfs/oauth2/token/",
        "jwks_uri":"https://fs.fabidentity.com/adfs/discovery/keys",
        "token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic","private_key_jwt","windows_client_authentication"],
        "response_types_supported":["code","id_token","code id_token","id_token token","code token","code id_token token"],
        "response_modes_supported":["query","fragment","form_post"],
        "grant_types_supported":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:jwt-bearer","implicit","password","srv_challenge"],
        "subject_types_supported":["pairwise"],
        "scopes_supported":["allatclaims","email","user_impersonation","logon_cert","aza","profile","vpn_cert","winhello_cert","openid"],
        "id_token_signing_alg_values_supported":["RS256"],
        "token_endpoint_auth_signing_alg_values_supported":["RS256"],
        "access_token_issuer":"http://fs.fabidentity.com/adfs/services/trust",
        "claims_supported":["aud","iss","iat","exp","auth_time","nonce","at_hash","c_hash","sub","upn","unique_name","pwd_url","pwd_exp","sid"],
        "microsoft_multi_refresh_token":true,
        "userinfo_endpoint":"https://fs.fabidentity.com/adfs/userinfo",
        "capabilities":[],
        "end_session_endpoint":"https://fs.fabidentity.com/adfs/oauth2/logout",
        "as_access_token_token_binding_supported":true,
        "as_refresh_token_token_binding_supported":true,
        "resource_access_token_token_binding_supported":true,
        "op_id_token_token_binding_supported":true,
        "rp_id_token_token_binding_supported":true,
        "frontchannel_logout_supported":true,
        "frontchannel_logout_session_supported":true
    }"#;

    #[test]
    fn the_adfs_discovery_document_parses_and_pins_rs256() {
        let metadata: ProviderMetadataWithLogout =
            serde_json::from_str(ADFS_DISCOVERY).expect("AD FS discovery parses");
        assert_eq!(metadata.issuer().as_str(), "https://fs.fabidentity.com/adfs");
        assert_eq!(
            metadata
                .additional_metadata()
                .end_session_endpoint
                .as_ref()
                .map(|u| u.as_str()),
            Some("https://fs.fabidentity.com/adfs/oauth2/logout"),
        );
        assert_eq!(
            pinned_algs(metadata.id_token_signing_alg_values_supported()).expect("RS256 is kept"),
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        );
    }

    #[test]
    fn the_cache_key_collapses_trailing_slashes() {
        assert_eq!(normalize_issuer("https://idp.test/"), "https://idp.test");
        assert_eq!(normalize_issuer("https://idp.test"), "https://idp.test");
        assert_eq!(normalize_issuer("https://idp.test/dex/"), "https://idp.test/dex");
    }

    /// Both spellings must be reachable from either, and applying it twice must
    /// come back — otherwise the retry would ask with the same string twice and
    /// look, from the outside, exactly like no retry at all.
    #[test]
    fn toggling_the_trailing_slash_round_trips() {
        for issuer in ["https://tenant.us.auth0.com", "https://idp.test/dex"] {
            let toggled = toggle_trailing_slash(issuer);
            assert_ne!(toggled, issuer);
            assert_eq!(toggle_trailing_slash(&toggled), issuer);
            assert_eq!(normalize_issuer(&toggled), normalize_issuer(issuer));
        }
        assert_eq!(toggle_trailing_slash("https://idp.test/"), "https://idp.test");
    }

    #[test]
    fn pinning_keeps_the_asymmetric_algorithms_a_provider_offers() {
        let advertised = vec![
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            CoreJwsSigningAlgorithm::EcdsaP256Sha256,
        ];
        let allowed = pinned_algs(&advertised).expect("intersection is non-empty");
        assert_eq!(allowed.len(), 2);
    }

    /// The case pinning exists for: a provider advertising HMAC alongside a
    /// real algorithm must have the HMAC dropped, not honoured.
    #[test]
    fn pinning_drops_symmetric_algorithms() {
        let advertised = vec![
            CoreJwsSigningAlgorithm::HmacSha256,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        ];
        let allowed = pinned_algs(&advertised).expect("intersection is non-empty");
        assert_eq!(allowed, vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
        assert!(!allowed.contains(&CoreJwsSigningAlgorithm::HmacSha256));
    }

    /// A symmetric-only provider is refused outright — falling back to a
    /// default would silently undo the pinning.
    #[test]
    fn a_symmetric_only_provider_is_refused() {
        let advertised = vec![
            CoreJwsSigningAlgorithm::HmacSha256,
            CoreJwsSigningAlgorithm::HmacSha512,
        ];
        assert_matches!(pinned_algs(&advertised), Err(OidcError::Verification(_)));
    }

    #[test]
    fn a_provider_advertising_nothing_is_refused() {
        assert_matches!(pinned_algs(&[]), Err(OidcError::Verification(_)));
    }

    /// `alg: none` is not in the allowlist, so a provider offering it gets it
    /// dropped like any other unacceptable algorithm.
    #[test]
    fn pinning_drops_the_none_algorithm() {
        let advertised = vec![
            CoreJwsSigningAlgorithm::None,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        ];
        let allowed = pinned_algs(&advertised).expect("intersection is non-empty");
        assert_eq!(allowed, vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
    }

    #[test]
    fn a_none_only_provider_is_refused() {
        assert_matches!(
            pinned_algs(&[CoreJwsSigningAlgorithm::None]),
            Err(OidcError::Verification(_))
        );
    }
}
