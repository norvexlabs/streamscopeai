//! Per-tenant JWT signing keys, and the ring that verifies them.
//!
//! Every streamscope-issued JWT — console session, portal session, CLI access,
//! MCP access, and both OAuth surfaces' refresh tokens — is signed with a key
//! derived from `AUTH_SECRET` and the tenant the token belongs to, so a key
//! recovered from one tenant signs nothing for another. The MCP access token
//! signs ES256 over a derived P-256 key (its holder may verify it against the
//! published key set); every other surface is HS256.
//!
//! The `kid` header names that key as `<generation>.<tenant_id>`, where the
//! generation is a fingerprint of the secret the key came from. A verifier
//! therefore picks both the secret and the tenant out of the header alone.
//!
//! A ring carries the active signer plus one optional verify-only companion,
//! `AUTH_SECRET_SECONDARY`. The name is direction-neutral on purpose: the
//! companion holds the *outgoing* secret while a rotation drains, and the
//! *incoming* one while a rotation is being staged. That symmetry is what makes
//! a rolling rotation safe across several replicas — during the promote step
//! one replica holds `{active old, secondary new}` and another
//! `{active new, secondary old}`, and because a ring publishes and accepts both
//! members regardless of which one signs, the two are indistinguishable to any
//! verifier. Rotating in one step instead leaves a window where a token minted
//! by a rotated replica cannot be verified against a snapshot built by one that
//! has not restarted yet.
//!
//! Three invariants to preserve when changing this module:
//!
//! * **The generation id must stay a one-way function of the secret** — it
//!   travels in the clear in every token header.
//! * **The secondary must never sign.** Only its verification side is used; a
//!   ring that signed with it would mint tokens nobody had agreed to accept.
//! * **admin-api derives; the proxy is told.** admin-api mints every token, and
//!   verifies console/portal/CLI/refresh, from this ring. The proxy holds no
//!   signing secret: it verifies MCP access tokens against the per-tenant public
//!   keys [`Keyring::public_jwks`] puts on the config snapshot. So a change to
//!   the derivation reaches the data plane only through that snapshot.

use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

/// Domain separation for a per-tenant signing key. The tenant id is appended.
const KEY_INFO_PREFIX: &[u8] = b"streamscope-jwt-v1:";

/// Domain separation for a per-tenant ES256 signing key. The tenant id is
/// appended, then a retry counter (see [`Generation::tenant_ec_secret`]).
///
/// Distinct from [`KEY_INFO_PREFIX`] so the HMAC key and the ECDSA private
/// scalar for one tenant are independent outputs of the same secret: recovering
/// either must say nothing about the other.
const EC_KEY_INFO_PREFIX: &[u8] = b"streamscope-jwt-es256-v1:";

/// Domain separation for the generation fingerprint that names a secret.
const GENERATION_INFO: &[u8] = b"streamscope-jwt-kid-v1";

/// Fingerprint length. 9 bytes encode to exactly 12 base64url characters with
/// no padding, and 72 bits is far past any accidental collision between two
/// secrets an operator might configure.
const GENERATION_BYTES: usize = 9;

/// Minimum `AUTH_SECRET` length both binaries enforce at startup. A short
/// secret weakens every per-tenant key derived from it.
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("token is not a well-formed JWT")]
    MalformedToken,
    #[error("token carries no `kid` header")]
    MissingKid,
    #[error("token `kid` is malformed")]
    MalformedKid,
    #[error("token `kid` names an unknown key generation")]
    UnknownGeneration,
}

/// Split a `kid` into the generation that names a secret and the tenant it was
/// derived for.
///
/// Both halves are attacker-supplied — they only *select* a key. What
/// authenticates a token is that the selected key validates the signature, and
/// that the caller cross-checks the tenant against the verified payload.
///
/// Only the first `.` separates the two: a tenant id is a UUID and its hyphens
/// carry no structure, but a future id format containing a dot must not be
/// truncated here.
pub fn parse_kid(kid: &str) -> Result<(&str, &str), KeyError> {
    let (generation, tenant_id) = kid.split_once('.').ok_or(KeyError::MalformedKid)?;
    if generation.is_empty() || tenant_id.is_empty() {
        return Err(KeyError::MalformedKid);
    }
    Ok((generation, tenant_id))
}

/// Memo for [`Keyring::public_jwks`], keyed by `(generation id, tenant id)`.
///
/// Deriving a tenant's public point costs an HKDF plus a P-256 scalar
/// multiplication, and the snapshot builder derives one per generation per
/// tenant on **every** edge reconnect — a fleet-wide resync would otherwise pay
/// thousands of them. The generation id is a one-way fingerprint of the secret,
/// so an entry cannot outlive the secret it describes: a rotation changes the
/// key and misses the cache rather than serving a stale point.
///
/// **Only `public_jwks` may use this**, because only there is `tenant_id` a row
/// id read from the database. The verification paths take their tenant from a
/// token's `kid`, which any caller can choose, and caching on that would let a
/// stream of junk `kid`s grow this map. The cap below means even a mistake
/// there degrades to "uncached" instead of unbounded, but it is a backstop, not
/// the argument.
static PUBLIC_JWK_MEMO: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<(String, String), crate::metadata::JsonWebKey>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Ceiling on [`PUBLIC_JWK_MEMO`] entries — generous against any real tenant
/// count, so the cap is never reached in normal operation.
const PUBLIC_JWK_MEMO_MAX: usize = 8192;

/// One `AUTH_SECRET`'s worth of key material, plus the id that names it.
struct Generation {
    id: String,
    secret: String,
}

impl Generation {
    fn new(secret: &str) -> Self {
        let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
        let mut okm = [0u8; GENERATION_BYTES];
        hk.expand(GENERATION_INFO, &mut okm)
            .expect("HKDF expand: 9 bytes is always valid for SHA-256");
        Self {
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(okm),
            secret: secret.to_string(),
        }
    }

    fn tenant_key(&self, tenant_id: &str) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, self.secret.as_bytes());
        let mut info = Vec::with_capacity(KEY_INFO_PREFIX.len() + tenant_id.len());
        info.extend_from_slice(KEY_INFO_PREFIX);
        info.extend_from_slice(tenant_id.as_bytes());
        let mut okm = vec![0u8; 32];
        hk.expand(&info, &mut okm)
            .expect("HKDF expand: 32 bytes is always valid for SHA-256");
        okm
    }

    /// The tenant's P-256 private scalar, derived rather than stored.
    ///
    /// Deriving is what keeps the asymmetric key free of every cost a stored
    /// one carries — no table, no encryption at rest, no rotation machinery of
    /// its own, and no channel to push it to the proxy. It works because a
    /// P-256 private key *is* a 32-byte scalar, so HKDF output is already the
    /// right shape. (An RSA key is not: deriving one means seeding a prime
    /// search, whose result depends on the implementation, so a dependency
    /// bump would silently re-key every tenant. That asymmetry is why this
    /// surface signs ES256 and not RS256.)
    ///
    /// A candidate lands outside `[1, n-1]` with probability about 2^-32, so
    /// the counter almost never advances — but it is what makes the derivation
    /// total, and it must stay in the `info` rather than the salt so the whole
    /// output changes on retry.
    fn tenant_ec_secret(&self, tenant_id: &str) -> p256::SecretKey {
        let hk = Hkdf::<Sha256>::new(None, self.secret.as_bytes());
        for counter in 0u8..=u8::MAX {
            let mut info =
                Vec::with_capacity(EC_KEY_INFO_PREFIX.len() + tenant_id.len() + 1);
            info.extend_from_slice(EC_KEY_INFO_PREFIX);
            info.extend_from_slice(tenant_id.as_bytes());
            info.push(counter);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm)
                .expect("HKDF expand: 32 bytes is always valid for SHA-256");
            if let Ok(secret) = p256::SecretKey::from_bytes(&okm.into()) {
                return secret;
            }
        }
        // 256 consecutive candidates outside the curve order is not reachable
        // for any secret — the probability is about 2^-8192.
        unreachable!("no valid P-256 scalar in 256 HKDF candidates")
    }

    /// The tenant's public point, as the base64url `(x, y)` pair a JWK carries.
    ///
    /// **This pair is the single source for the key set we publish at
    /// `jwks_uri`, the key set we hand the proxy on the config snapshot, and the
    /// key admin-api verifies with** (see [`Self::public_decoding_key`]).
    /// Deriving any of them separately would let them drift — publishing one key
    /// while accepting signatures from another is exactly the failure a key set
    /// is supposed to prevent, and it would be invisible to us because our own
    /// tokens would keep verifying.
    ///
    /// One consequence to keep in view: the proxy accepts what the *snapshot*
    /// carries, and a snapshot is built by whichever admin-api replica ran the
    /// build. So the identity above holds per build, not per deployment, and a
    /// fleet whose replicas hold different rings can publish different sets.
    /// The staged rotation in the module docs is what keeps those sets equal.
    fn public_xy(&self, tenant_id: &str) -> (String, String) {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let point = self.tenant_ec_secret(tenant_id).public_key().to_sec1_point(false);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        (
            b64.encode(point.x().expect("uncompressed point has an x coordinate")),
            b64.encode(point.y().expect("uncompressed point has a y coordinate")),
        )
    }

    fn public_decoding_key(&self, tenant_id: &str) -> jsonwebtoken::DecodingKey {
        let (x, y) = self.public_xy(tenant_id);
        jsonwebtoken::DecodingKey::from_ec_components(&x, &y)
            .expect("base64url coordinates this module just encoded")
    }

    fn public_jwk(&self, tenant_id: &str) -> crate::metadata::JsonWebKey {
        let (x, y) = self.public_xy(tenant_id);
        crate::metadata::JsonWebKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x,
            y,
            use_: "sig".to_string(),
            alg: "ES256".to_string(),
            kid: format!("{}.{tenant_id}", self.id),
        }
    }
}

/// The active signer plus any verify-only secondary.
pub struct Keyring {
    active: Generation,
    secondary: Option<Generation>,
}

impl Keyring {
    /// Build a ring from an active secret and an optional outgoing one.
    /// Returns `None` when the active secret is empty — there is nothing to
    /// sign or verify with, and every caller turns that into a 503.
    pub fn new(active: &str, secondary: Option<&str>) -> Option<Self> {
        if active.is_empty() {
            return None;
        }
        Some(Self {
            active: Generation::new(active),
            // An empty or duplicate `AUTH_SECRET_SECONDARY` is the same ring as
            // none: a duplicate derives the same generation id, so keeping it
            // would only add a redundant candidate to every lookup.
            secondary: secondary
                .filter(|s| !s.is_empty() && *s != active)
                .map(Generation::new),
        })
    }

    /// Read the ring from the environment. Deliberately **not** memoised: both
    /// binaries already read `AUTH_SECRET` per request, the derivation is a
    /// handful of HMACs, and a process-wide cache would freeze whichever value
    /// happened to be set when the first token was handled.
    pub fn from_env() -> Option<Self> {
        let active = std::env::var("AUTH_SECRET").ok()?;
        let secondary = std::env::var("AUTH_SECRET_SECONDARY").ok();
        Self::new(&active, secondary.as_deref())
    }

    /// The `kid` and key to sign a token for `tenant_id` with. Always the
    /// active generation — a secondary verifies, it never signs.
    pub fn signing_key(&self, tenant_id: &str) -> (String, Vec<u8>) {
        (
            format!("{}.{tenant_id}", self.active.id),
            self.active.tenant_key(tenant_id),
        )
    }

    /// The HS256 header and key to sign a token for `tenant_id` with.
    ///
    /// **Every mint site goes through here.** The `kid` is stamped by the same
    /// call that hands out the key, so it cannot be forgotten — and a token
    /// without one names no key, so nothing would verify it.
    pub fn signing_header(&self, tenant_id: &str) -> (jsonwebtoken::Header, Vec<u8>) {
        let (kid, key) = self.signing_key(tenant_id);
        (
            jsonwebtoken::Header {
                kid: Some(kid),
                ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256)
            },
            key,
        )
    }

    /// Resolve a `kid` to the tenant it names and the key that verifies it.
    ///
    /// The tenant here is attacker-controlled — it only selects a key. What
    /// authenticates the token is that the derived key validates the signature,
    /// and callers additionally cross-check this tenant against the verified
    /// payload so a token cannot be re-pointed at another tenant's context.
    pub fn verification_key(&self, kid: &str) -> Result<(String, Vec<u8>), KeyError> {
        let (generation, tenant_id) = parse_kid(kid)?;
        let matched = [Some(&self.active), self.secondary.as_ref()]
            .into_iter()
            .flatten()
            .find(|g| g.id == generation)
            .ok_or(KeyError::UnknownGeneration)?;
        Ok((tenant_id.to_string(), matched.tenant_key(tenant_id)))
    }

    /// The ES256 header and key to sign a token for `tenant_id` with.
    ///
    /// The `kid` is the same `<generation>.<tenant>` string the HMAC surfaces
    /// use, which is what lets one published key set describe tokens across a
    /// secret rotation: the header names the generation, and the set carries a
    /// key for each generation on the ring.
    pub fn es256_signing_header(
        &self,
        tenant_id: &str,
    ) -> (jsonwebtoken::Header, jsonwebtoken::EncodingKey) {
        use p256::pkcs8::EncodePrivateKey;
        // The scalar came from `SecretKey::from_bytes`, so it is on the curve
        // and PKCS#8 encoding of a valid key cannot fail.
        let der = self
            .active
            .tenant_ec_secret(tenant_id)
            .to_pkcs8_der()
            .expect("PKCS#8 encoding of a derived P-256 key");
        let key = jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes());
        (
            jsonwebtoken::Header {
                kid: Some(format!("{}.{tenant_id}", self.active.id)),
                ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256)
            },
            key,
        )
    }

    /// Resolve a `kid` to the tenant it names and the public key that verifies
    /// its ES256 signature.
    ///
    /// As with [`Self::verification_key`], the tenant here only *selects* a
    /// key — the caller cross-checks it against the verified payload.
    pub fn es256_verification_key(
        &self,
        kid: &str,
    ) -> Result<(String, jsonwebtoken::DecodingKey), KeyError> {
        let (generation, tenant_id) = parse_kid(kid)?;
        let matched = [Some(&self.active), self.secondary.as_ref()]
            .into_iter()
            .flatten()
            .find(|g| g.id == generation)
            .ok_or(KeyError::UnknownGeneration)?;
        Ok((tenant_id.to_string(), matched.public_decoding_key(tenant_id)))
    }

    /// Every public key that can verify a live token for `tenant_id` — the
    /// active generation first, then any verify-only secondary.
    ///
    /// This is the whole published key set for a tenant — served at `jwks_uri`
    /// and carried to the proxy on the config snapshot. Ordering is not
    /// load-bearing (a verifier selects by `kid`), but active-first keeps the
    /// document readable when someone inspects it by hand.
    ///
    /// `tenant_id` MUST be a database row id, never a value read out of a
    /// token's `kid` — see [`PUBLIC_JWK_MEMO`].
    pub fn public_jwks(&self, tenant_id: &str) -> Vec<crate::metadata::JsonWebKey> {
        // One memo key per ring member rather than per ring, so a rotation
        // reuses the member it carried over instead of missing on both.
        let generations: Vec<&Generation> = [Some(&self.active), self.secondary.as_ref()]
            .into_iter()
            .flatten()
            .collect();

        let mut out = Vec::with_capacity(generations.len());
        for g in generations {
            let memo_key = (g.id.clone(), tenant_id.to_string());
            // Read lock first: the steady state is a hit, and the whole point is
            // to keep a fleet-wide resync off the scalar-multiply path.
            if let Ok(memo) = PUBLIC_JWK_MEMO.read()
                && let Some(hit) = memo.get(&memo_key)
            {
                out.push(hit.clone());
                continue;
            }
            let jwk = g.public_jwk(tenant_id);
            if let Ok(mut memo) = PUBLIC_JWK_MEMO.write() {
                // A full map is dropped rather than merely closed to new
                // entries. Rotations retire generations, and their entries are
                // dead weight that can never be read again — keeping them would
                // let the cap fill with retired keys and make the *live*
                // generation miss forever, which is a silent, permanent
                // slowdown that only a restart ends.
                if memo.len() >= PUBLIC_JWK_MEMO_MAX {
                    memo.clear();
                }
                memo.insert(memo_key, jwk.clone());
            }
            out.push(jwk);
        }
        out
    }

    /// The id naming the secret this ring signs with. Exposed for diagnostics.
    pub fn active_generation(&self) -> &str {
        &self.active.id
    }

    /// A stable name for the *set* of generations this ring can verify.
    ///
    /// Sorted and joined, so two replicas mid-rotation produce the same string
    /// whichever way round they hold the pair — which is precisely the promote
    /// step, where one holds `{active old, secondary new}` and another
    /// `{active new, secondary old}`. Comparing active ids alone would call
    /// those two different and set a fleet re-push flapping between them.
    ///
    /// This is what admin-api records to notice that the published key set has
    /// changed and every tenant's snapshot needs rebuilding. It is derived from
    /// generation ids, which are one-way fingerprints, so it is safe to persist
    /// and to log.
    pub fn generation_signature(&self) -> String {
        let mut ids: Vec<&str> = [Some(&self.active), self.secondary.as_ref()]
            .into_iter()
            .flatten()
            .map(|g| g.id.as_str())
            .collect();
        ids.sort_unstable();
        ids.join(",")
    }
}

/// Boot-time check on the signing secrets, shared so both binaries enforce one
/// rule. Returns the active generation id — worth logging, since it is how an
/// operator confirms a rotation actually took effect on every replica.
///
/// A too-short `AUTH_SECRET_SECONDARY` is fatal rather than ignored: silently
/// dropping it would log every session out at exactly the moment the operator
/// was trying to avoid that.
pub fn validate_env_secrets() -> Result<String, String> {
    let active = std::env::var("AUTH_SECRET")
        .map_err(|_| "AUTH_SECRET is required for JWT signing — refusing to start".to_string())?;
    if active.len() < MIN_SECRET_LEN {
        return Err(format!(
            "AUTH_SECRET is only {} bytes — minimum {MIN_SECRET_LEN} required for secure JWT signing",
            active.len()
        ));
    }
    let secondary = std::env::var("AUTH_SECRET_SECONDARY").unwrap_or_default();
    if !secondary.is_empty() && secondary.len() < MIN_SECRET_LEN {
        return Err(format!(
            "AUTH_SECRET_SECONDARY is only {} bytes — minimum {MIN_SECRET_LEN}, or unset it to end the rotation overlap",
            secondary.len()
        ));
    }
    Ok(Generation::new(&active).id)
}

/// Resolve the verification key for `token` from its `kid` header.
///
/// A token with no `kid` is refused rather than tried against the active
/// generation: the header is what makes key selection explicit, and accepting
/// its absence would silently pin every unlabelled token to one secret forever.
pub fn verification_key_for(
    token: &str,
    ring: &Keyring,
) -> Result<(String, Vec<u8>), KeyError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| KeyError::MalformedToken)?;
    let kid = header.kid.ok_or(KeyError::MissingKid)?;
    ring.verification_key(&kid)
}

/// Read a token's `kid` and split it, without touching any key material.
///
/// This is the first half of verification for a holder that has no ring — the
/// proxy, which must learn *which tenant* a token claims before it can look up
/// that tenant's published keys. Both returned halves are unverified: they
/// select, they do not authenticate. See
/// [`crate::jwt::decode_and_verify_with_key`] for the check that binds them.
pub fn kid_and_tenant_of(token: &str) -> Result<(String, String), KeyError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| KeyError::MalformedToken)?;
    let kid = header.kid.ok_or(KeyError::MissingKid)?;
    let (_generation, tenant_id) = parse_kid(&kid)?;
    let tenant_id = tenant_id.to_string();
    Ok((kid, tenant_id))
}

/// Find the published key named by `kid` in a key set and turn it into a
/// verification key.
///
/// The counterpart to [`Keyring::es256_verification_key`] for a verifier whose
/// keys arrive as data rather than being derived from a secret. Selection is by
/// `kid` alone — a set that does not carry the token's generation yields
/// [`KeyError::UnknownGeneration`], which callers MUST treat as "reject this
/// token", never as a cue to fall back to a locally derived key.
pub fn es256_key_from_jwks(
    kid: &str,
    jwks: &[crate::metadata::JsonWebKey],
) -> Result<jsonwebtoken::DecodingKey, KeyError> {
    let jwk = jwks
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(KeyError::UnknownGeneration)?;
    jsonwebtoken::DecodingKey::from_ec_components(&jwk.x, &jwk.y)
        .map_err(|_| KeyError::MalformedKid)
}

/// Resolve the ES256 public verification key for `token` from its `kid` header.
///
/// The `kid`-is-mandatory rule of [`verification_key_for`] applies here for the
/// same reason, and one more: this key is *published*, so a client picks it out
/// of the key set by `kid`. A token that names no key could not be verified by
/// anyone but us.
pub fn es256_verification_key_for(
    token: &str,
    ring: &Keyring,
) -> Result<(String, jsonwebtoken::DecodingKey), KeyError> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| KeyError::MalformedToken)?;
    let kid = header.kid.ok_or(KeyError::MissingKid)?;
    ring.es256_verification_key(&kid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    const ACTIVE: &str = "active-secret-at-least-32-characters";
    const SECONDARY: &str = "secondary-secret-at-least-32-characters";

    fn ring() -> Keyring {
        Keyring::new(ACTIVE, Some(SECONDARY)).expect("ring")
    }

    #[test]
    fn generation_id_is_stable_and_secret_specific() {
        assert_eq!(Generation::new(ACTIVE).id, Generation::new(ACTIVE).id);
        assert_ne!(Generation::new(ACTIVE).id, Generation::new(SECONDARY).id);
        // 9 bytes of base64url, unpadded.
        assert_eq!(Generation::new(ACTIVE).id.len(), 12);
    }

    #[test]
    fn per_tenant_keys_diverge() {
        let g = Generation::new(ACTIVE);
        assert_ne!(g.tenant_key("tenant-a"), g.tenant_key("tenant-b"));
        assert_eq!(g.tenant_key("tenant-a").len(), 32);
    }

    /// The whole point of the fingerprint: the id in a public header must not
    /// hand back the secret it names.
    #[test]
    fn generation_id_does_not_contain_the_secret() {
        let id = Generation::new(ACTIVE).id;
        assert!(!ACTIVE.contains(&id));
        assert!(!id.contains(ACTIVE));
    }

    #[test]
    fn signing_key_names_the_active_generation() {
        let ring = ring();
        let (kid, key) = ring.signing_key("tenant-a");
        assert_eq!(kid, format!("{}.tenant-a", Generation::new(ACTIVE).id));
        assert_eq!(key, Generation::new(ACTIVE).tenant_key("tenant-a"));
    }

    #[test]
    fn a_secondary_generation_still_verifies() {
        let ring = ring();
        let kid = format!("{}.tenant-a", Generation::new(SECONDARY).id);
        let (tenant, key) = ring.verification_key(&kid).expect("secondary verifies");
        assert_eq!(tenant, "tenant-a");
        assert_eq!(key, Generation::new(SECONDARY).tenant_key("tenant-a"));
    }

    #[test]
    fn a_secondary_that_is_gone_stops_verifying() {
        let ring = Keyring::new(ACTIVE, None).expect("ring");
        let kid = format!("{}.tenant-a", Generation::new(SECONDARY).id);
        assert_matches!(
            ring.verification_key(&kid),
            Err(KeyError::UnknownGeneration)
        );
    }

    #[test]
    fn malformed_kids_are_refused() {
        let ring = ring();
        for kid in ["", "no-separator", ".tenant-a", "generation."] {
            assert_matches!(
                ring.verification_key(kid),
                Err(KeyError::MalformedKid),
                "accepted {kid:?}"
            );
        }
    }

    /// A tenant id is opaque to the ring, and a UUID's hyphens must not be
    /// mistaken for structure — only the first `.` separates the two halves.
    #[test]
    fn tenant_half_is_taken_whole() {
        let ring = ring();
        let tenant = "5bc9419e-555d-46e4-8f73-31b90d98274c";
        let (kid, _) = ring.signing_key(tenant);
        let (resolved, _) = ring.verification_key(&kid).expect("resolves");
        assert_eq!(resolved, tenant);
    }

    #[test]
    fn an_empty_active_secret_yields_no_ring() {
        assert!(Keyring::new("", Some(SECONDARY)).is_none());
    }

    /// A secondary identical to the active secret derives the same generation
    /// id, so carrying it would add a duplicate candidate and nothing else.
    #[test]
    fn a_duplicate_secondary_is_dropped() {
        let ring = Keyring::new(ACTIVE, Some(ACTIVE)).expect("ring");
        assert!(ring.secondary.is_none());
    }

    #[test]
    fn a_token_without_a_kid_is_refused() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let ring = ring();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({"sub": "s"}),
            &EncodingKey::from_secret(b"whatever"),
        )
        .expect("encode");
        assert_matches!(
            verification_key_for(&token, &ring),
            Err(KeyError::MissingKid)
        );
    }

    #[test]
    fn the_ec_key_is_deterministic_and_per_tenant() {
        let a = Generation::new(ACTIVE);
        assert_eq!(a.public_xy("tenant-a"), Generation::new(ACTIVE).public_xy("tenant-a"));
        assert_ne!(a.public_xy("tenant-a"), a.public_xy("tenant-b"));
        // Two secrets must not derive the same key for one tenant, or a
        // rotation would publish a key set that cannot tell them apart.
        assert_ne!(a.public_xy("tenant-a"), Generation::new(SECONDARY).public_xy("tenant-a"));
    }

    /// The published key outlives the curve library: tokens issued before an
    /// upgrade verify after it only while the same secret derives the same
    /// point. Pinned to the bytes an independent derivation gives.
    #[test]
    fn the_ec_key_a_secret_derives_does_not_change() {
        assert_eq!(
            Generation::new(ACTIVE).public_xy("tenant-a"),
            (
                "vncEalpILRVP93qvZuozfxarguvmqo-p8B12y48GiaA".to_string(),
                "R50uYQcSDn4FbmWeH0QXwIQswNuNHDByqzTynSBPCsg".to_string()
            )
        );
    }

    /// The memo is keyed by generation, so it cannot serve a key derived from a
    /// secret that is no longer on the ring. This is the property that makes
    /// caching a *signing*-derived value safe at all: warm the cache under one
    /// secret, then ask a ring built from another for the same tenant, and the
    /// answer must change.
    #[test]
    fn the_memo_cannot_serve_a_key_from_a_retired_secret() {
        let tenant = "memo-rotation-tenant";
        let before = Keyring::new(ACTIVE, None).expect("ring").public_jwks(tenant);
        // Warm it a second time — a hit must equal the miss it replaced.
        let warm = Keyring::new(ACTIVE, None).expect("ring").public_jwks(tenant);
        assert_eq!((&before[0].kid, &before[0].x), (&warm[0].kid, &warm[0].x));

        let after = Keyring::new(SECONDARY, None).expect("ring").public_jwks(tenant);
        assert_eq!(after.len(), 1);
        assert_ne!(before[0].x, after[0].x, "memo served a retired generation's key");
        assert_ne!(before[0].kid, after[0].kid);
    }

    /// A ring spanning two generations must publish both, and the memo must not
    /// collapse them into one entry — each is keyed by its own generation id.
    #[test]
    fn the_memo_keeps_the_two_generations_apart() {
        let tenant = "memo-two-generation-tenant";
        let jwks = ring().public_jwks(tenant);
        assert_eq!(jwks.len(), 2);
        assert_ne!(jwks[0].kid, jwks[1].kid);
        assert_ne!(jwks[0].x, jwks[1].x);
        // Identical on a second call, now served from the memo.
        let warm = ring().public_jwks(tenant);
        assert_eq!(
            jwks.iter().map(|k| (&k.kid, &k.x)).collect::<Vec<_>>(),
            warm.iter().map(|k| (&k.kid, &k.x)).collect::<Vec<_>>(),
        );
    }

    /// The promote step of a staged rotation swaps which member is active
    /// without changing the set. Both orderings must name the same signature, or
    /// a rolling restart would look like a key change to every replica in turn.
    #[test]
    fn the_signature_ignores_which_member_is_active() {
        let promoting = Keyring::new(ACTIVE, Some(SECONDARY)).expect("ring");
        let promoted = Keyring::new(SECONDARY, Some(ACTIVE)).expect("ring");
        assert_eq!(promoting.generation_signature(), promoted.generation_signature());
        // Retiring the companion is a real change and must be visible.
        let retired = Keyring::new(SECONDARY, None).expect("ring");
        assert_ne!(promoted.generation_signature(), retired.generation_signature());
    }

    #[test]
    fn parse_kid_splits_on_the_first_dot_only() {
        assert_eq!(parse_kid("gen.tenant-a"), Ok(("gen", "tenant-a")));
        assert_eq!(parse_kid("gen.a.b"), Ok(("gen", "a.b")));
        for bad in ["", "no-separator", ".tenant-a", "generation."] {
            assert_matches!(parse_kid(bad), Err(KeyError::MalformedKid), "accepted {bad:?}");
        }
    }

    /// The HMAC key and the EC scalar for one tenant come from the same secret,
    /// so the domain separation between them is the only thing keeping one from
    /// being derivable from the other.
    #[test]
    fn the_ec_scalar_is_not_the_hmac_key() {
        let g = Generation::new(ACTIVE);
        let scalar = g.tenant_ec_secret("tenant-a").to_bytes().to_vec();
        assert_ne!(scalar, g.tenant_key("tenant-a"));
    }

    #[test]
    fn the_key_set_carries_both_generations_and_names_them_by_kid() {
        let ring = ring();
        let jwks = ring.public_jwks("tenant-a");
        assert_eq!(jwks.len(), 2, "active + secondary");
        assert_eq!(jwks[0].kid, format!("{}.tenant-a", Generation::new(ACTIVE).id));
        assert_eq!(jwks[1].kid, format!("{}.tenant-a", Generation::new(SECONDARY).id));
        // Coordinates are 32 bytes each, base64url-unpadded — 43 characters.
        for k in &jwks {
            assert_eq!(k.x.len(), 43, "x: {}", k.x);
            assert_eq!(k.y.len(), 43, "y: {}", k.y);
        }
    }

    /// A ring with no secondary publishes one key. Publishing a stale key
    /// would tell verifiers a rotated-out generation is still live.
    #[test]
    fn a_ring_with_no_secondary_publishes_one_key() {
        let ring = Keyring::new(ACTIVE, None).expect("ring");
        assert_eq!(ring.public_jwks("tenant-a").len(), 1);
    }

    #[test]
    fn an_es256_kid_resolves_to_its_generation() {
        let ring = ring();
        let kid = format!("{}.tenant-a", Generation::new(SECONDARY).id);
        let (tenant, _) = ring.es256_verification_key(&kid).expect("secondary verifies");
        assert_eq!(tenant, "tenant-a");

        assert_matches!(ring.es256_verification_key("no-separator"), Err(KeyError::MalformedKid));
        assert_matches!(
            ring.es256_verification_key("unknown-gen.tenant-a"),
            Err(KeyError::UnknownGeneration)
        );
    }

    #[test]
    fn a_non_token_is_refused_before_any_key_work() {
        let ring = ring();
        assert_matches!(
            verification_key_for("not-a-jwt", &ring),
            Err(KeyError::MalformedToken)
        );
    }
}
