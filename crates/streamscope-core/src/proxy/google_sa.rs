//! Google Cloud access tokens for the `google_vertex` transport.
//!
//! Vertex AI accepts only OAuth 2.0 bearer tokens — there is no API-key form —
//! so the gateway holds a service-account key and exchanges it for an access
//! token with the JWT-bearer grant (RFC 7523): a short-lived assertion signed
//! with the account's private key, presented to Google's token endpoint.
//!
//! The credential is stored in the ordinary encrypted upstream-credential column
//! as a JSON document — the very file the Cloud console hands out — so it
//! travels the existing AES-256-GCM path and the existing config-sync channel
//! with no separate secret plumbing.
//!
//! Three invariants to preserve:
//! - **The token host is allowlisted.** `token_uri` comes out of an
//!   operator-supplied document; honouring it blindly would let an admin point
//!   the gateway's signed assertion at an arbitrary address.
//! - **The private key never reaches a log or an error body.** `Debug` is
//!   redacted by hand, and a failed exchange reports the status, not the
//!   response — Google's error bodies echo the assertion back.
//! - **The exchange dials through [`crate::proxy::minted_token::post_token_form`]**,
//!   never a client of its own — the allowlist pins the host, the shared SSRF
//!   guard pins what that host resolves to.

use std::sync::LazyLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::proxy::minted_token::{post_token_form, MintFailure, MintedToken, MintedTokenCache};

/// The scope a Vertex AI call is authorised by. Google publishes no narrower
/// scope for `aiplatform.googleapis.com`; access is bounded by the service
/// account's IAM roles, not by the scope.
pub const DEFAULT_VERTEX_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The token endpoint every service-account key issued today carries.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Hosts the gateway will present a signed assertion to.
const ALLOWED_TOKEN_HOSTS: [&str; 2] = ["oauth2.googleapis.com", "accounts.google.com"];

/// How the endpoint is named in an operator-facing failure.
const TOKEN_ENDPOINT_LABEL: &str = "Google's OAuth token endpoint";

/// Lifetime of the assertion itself. Google caps it at one hour; it is not the
/// lifetime of the access token that comes back.
const ASSERTION_LIFETIME_SECS: u64 = 3600;

/// A stored Google service-account key.
#[derive(Clone, Deserialize)]
pub struct GoogleServiceAccount {
    /// The account's address, which is the assertion's issuer.
    pub client_email: String,
    /// PEM-encoded private key, as the console emits it.
    pub private_key: String,
    /// Key id, published as the assertion's `kid` so Google can select the
    /// public half without trying every key on the account.
    #[serde(default)]
    pub private_key_id: Option<String>,
    /// The project the key belongs to. Carried for the operator-facing check
    /// that a Vertex base URL names the same project.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Token endpoint; defaults to [`DEFAULT_TOKEN_URI`].
    #[serde(default)]
    pub token_uri: Option<String>,
    /// Scope to request; defaults to [`DEFAULT_VERTEX_SCOPE`].
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for GoogleServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleServiceAccount")
            .field("client_email", &self.client_email)
            .field("private_key", &"<redacted>")
            .field("private_key_id", &self.private_key_id)
            .field("project_id", &self.project_id)
            .field("token_uri", &self.token_uri)
            .field("scope", &self.scope)
            .finish()
    }
}

impl GoogleServiceAccount {
    /// The scope this key requests a token for.
    pub fn scope(&self) -> &str {
        self.scope.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(DEFAULT_VERTEX_SCOPE)
    }

    /// The token endpoint this key authenticates against, validated against the
    /// hosts Google issues tokens from.
    pub fn token_uri(&self) -> Result<&str, AppError> {
        let uri = self
            .token_uri
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .unwrap_or(DEFAULT_TOKEN_URI);
        // Parsed rather than split by hand: the host is the ONE field the
        // allowlist may be matched on, and `https://oauth2.googleapis.com:pw@evil.example/`
        // has an authority that *reads* as the allowlisted host while resolving
        // to another — a hand-rolled split accepts it and sends the signed
        // assertion to whoever the operator named.
        let parsed = url::Url::parse(uri).map_err(|_| {
            AppError::BadRequest("The service account's token_uri must be an https:// URL.".into())
        })?;
        if parsed.scheme() != "https" {
            return Err(AppError::BadRequest(
                "The service account's token_uri must be an https:// URL.".into(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(AppError::BadRequest(
                "The service account's token_uri must not embed credentials.".into(),
            ));
        }
        // The allowlist is about WHO the assertion is presented to, so it is
        // matched on the host alone; a port names the same party.
        let host = parsed.host_str().unwrap_or_default();
        if !ALLOWED_TOKEN_HOSTS.contains(&host) {
            return Err(AppError::BadRequest(format!(
                "`{host}` is not a recognised Google OAuth token host."
            )));
        }
        Ok(uri)
    }

    /// Validate every field the exchange needs, without performing one.
    ///
    /// The private key is parsed here rather than at first use: a key that only
    /// fails when signing would surface as an opaque upstream error on a user's
    /// request instead of on the page that set it.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.client_email.trim().is_empty() {
            return Err(AppError::BadRequest(
                "The service-account key needs a client_email.".into(),
            ));
        }
        if self.private_key.trim().is_empty() {
            return Err(AppError::BadRequest(
                "The service-account key needs a private_key.".into(),
            ));
        }
        self.token_uri()?;
        self.encoding_key().map(|_| ())
    }

    fn encoding_key(&self) -> Result<jsonwebtoken::EncodingKey, AppError> {
        jsonwebtoken::EncodingKey::from_rsa_pem(self.private_key.as_bytes()).map_err(|_| {
            AppError::BadRequest(
                "The service account's private_key is not a PEM-encoded RSA key. Paste the \
                 JSON key file exactly as Google Cloud emitted it."
                    .into(),
            )
        })
    }

    /// Key this credential's cache entry. Derived from every field that changes
    /// which token comes back, so a rotated key or a re-scoped credential cannot
    /// be served the previous token.
    fn cache_key(&self) -> String {
        let mut h = Sha256::new();
        for part in [
            self.client_email.as_str(),
            self.private_key.as_str(),
            self.private_key_id.as_deref().unwrap_or_default(),
            self.token_uri().unwrap_or(DEFAULT_TOKEN_URI),
            self.scope(),
        ] {
            h.update(part.as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    }
}

/// Parse a stored service-account document.
pub fn parse_credential(doc: &str) -> Result<GoogleServiceAccount, AppError> {
    let sa: GoogleServiceAccount = serde_json::from_str(doc.trim()).map_err(|_| {
        AppError::BadRequest(
            "The Vertex AI credential must be a Google service-account JSON key, with \
             client_email and private_key."
                .into(),
        )
    })?;
    sa.validate()?;
    Ok(sa)
}

#[derive(serde::Serialize)]
struct Assertion<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

static TOKENS: LazyLock<MintedTokenCache> = LazyLock::new(MintedTokenCache::new);

/// Return a valid access token for the stored service-account document, minting
/// one if the cache holds nothing usable.
///
/// A refusal by the token endpoint is told apart from every other failure
/// ([`MintFailure`]); the data plane reports both alike.
pub async fn access_token(credential_doc: &str) -> Result<String, MintFailure> {
    // A malformed stored document is a CONFIGURATION fault, but this runs on the
    // data plane — so it is logged for the operator and sanitized for the client,
    // never surfaced as a 400 describing the gateway's own stored credential.
    // The admin write path calls `parse_credential` directly and keeps its
    // operator-facing message.
    let sa = parse_credential(credential_doc).map_err(|e| {
        tracing::error!(error = %e, "stored Vertex AI service-account key is unusable");
        AppError::Internal("the upstream credential for this server is not usable".into())
    })?;
    TOKENS.get_or_mint(sa.cache_key(), || mint(&sa)).await
}

/// Sign one assertion and exchange it for an access token.
async fn mint(sa: &GoogleServiceAccount) -> Result<MintedToken, MintFailure> {
    let token_uri = sa.token_uri()?;
    let assertion = sign_assertion(sa, token_uri, now_secs())?;

    let answered = post_token_form(
        token_uri,
        TOKEN_ENDPOINT_LABEL,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ],
    )
    .await?;
    let (status, body) = (answered.status, answered.body);

    if !status.is_success() {
        // The endpoint's body echoes the assertion back in its error text, so it
        // is logged for the operator and never returned.
        tracing::error!(
            status = status.as_u16(),
            error = %String::from_utf8_lossy(&body).chars().take(512).collect::<String>(),
            "Google token request rejected"
        );
        return Err(MintFailure::from_refusal(status, AppError::Internal(format!(
            "Google rejected the upstream service-account credential (status {})",
            status.as_u16()
        ))));
    }

    let parsed: TokenResponse = serde_json::from_slice(&body)
        .map_err(|_| AppError::Internal("unrecognised response from Google's OAuth token endpoint".into()))?;
    if parsed.access_token.is_empty() {
        return Err(AppError::Internal("Google returned an empty access token".into()).into());
    }

    Ok(MintedToken { value: parsed.access_token, expires_in_secs: parsed.expires_in })
}

/// Seconds since the Unix epoch. A clock before the epoch would make `iat`
/// nonsensical; saturating to 0 lets Google reject the assertion rather than
/// panicking the request.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build and RS256-sign the JWT-bearer assertion.
fn sign_assertion(
    sa: &GoogleServiceAccount,
    token_uri: &str,
    issued_at: u64,
) -> Result<String, AppError> {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = sa.private_key_id.as_deref().map(str::trim).filter(|k| !k.is_empty()).map(str::to_string);
    let claims = Assertion {
        iss: sa.client_email.trim(),
        scope: sa.scope(),
        aud: token_uri,
        iat: issued_at,
        exp: issued_at + ASSERTION_LIFETIME_SECS,
    };
    jsonwebtoken::encode(&header, &claims, &sa.encoding_key()?).map_err(|e| {
        tracing::error!(error = %e, "signing Google service-account assertion");
        AppError::Internal("could not sign the Vertex AI service-account assertion".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway RSA key pair generated for these tests only. The assertion is
    /// signed and verified for real, because a signature that silently fails to
    /// verify would look exactly like a working one from this side.
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDda9tl9vb/c00A\naUAhxDIFYWFq+jwBaxS618TiZ/82+q3TK2g1C2rmr3PLnUbyaOZqtB+t1wPLQLLQ\nRZZU1Q/b7R4uy3WIyCkC6Gb2CB8VzQ73+oJS+Rf5SG8YzFscJYdji4Kz4A08t9Dh\nA3V3yOtuUcLcrNnNqiUA+Jjv8CPrfp7n2bdREz9A1tdfYjuyNInzhN3x3TeDzDZ7\nT29tHxVmEbe1L3f/XWsnng+4zmjfJmhQt7ijaGywywGHFJu6rexjE9o16WMTNVhL\n0peomFkhtRxo0eIDWHtH78aqAWLGd15vDQkCNdMdAIFiXlp1K5L8ubSk1zvMiUj8\n919DNrOJAgMBAAECggEAa+JtmBTo7DaFwjmGIe2yYaS9Dp62NgqyowcWyynY1DT4\nFPgFYjMZ9yRtyzvqoZozCrKQ7Obi1lnDxm7hfJwDiijSmAJSVj8QnHYYFLCIVNsA\n/Bp2/W6ZG8ELQI3xppkyinIjUPlN+dOmVryUs7SV4b68r0EZLnhEZ2C5Q89B8S9s\ncy8NJbPRz1jrOGG9BDtJc7YmsJleLWEMk+66vzTpk1OntTE+f77WRjRqoBPGtkqO\n20HOJmfI8lSaXs4wYMaRNQV4T192Hk7UPqyLjSgHrSWoG1X4AeWlR7iWBGjDzQNb\nHqIal2nJIHMIjwqikSeLObmDAlQFELZvy8UsHq2+8QKBgQD6wtdMA1ExpUvQzADz\nEvEtdtTeSVYcFSGNLu3HlF4j+8hAtJHwirhiSR4JfdR0Ur3cIX6UkAmvMokoZ0fq\naZkHrKYz3AWJevZfMDpN8YNyXqltKahsefeANGn+j/a4k/4bBR7ZIUKNysWDQmHx\nn2EGXlJ+H4kWxuqkreHiRWYAwwKBgQDiDBi0MEeWvNcJ5n4yq/WtwXoSpxWQTHTF\nagzQXYS+rnQ4LJK5gY6y80I47Rh+bMdtk6/5ZCqSDlO0WMe6h1E60aH5btUWMHdD\np3hEHyVo6sRzfu3JG3fR48pMHkjPq6p8o7UYjZHwjBSAuMwR5mrrRhTjXorrKkcP\nRUNpJHl1wwKBgAYItDePCOAh8x4WGpu+w/DtIBgtOZY5Z/JGw8/+oPlKsLnl3nEk\nVWWADun5jigyaYEniS03/hOqKqS/P3rDibwmimVLERMK02zc8zo26ovQ/VC0JOpf\nUPZTzI0kl7I/VWj/CYv+AeT5kSEkcsjmpeYKVP/V8G2M4c6OpJXWR6sTAoGBAJYB\n1wcEnw1eRgnw5sBzszbalUr5jGrVAgzcAqLn3Ka5mLCKi9gFLRB+M+0ZEk8bmwCR\nqI8EtOd2EIA3Blw3XmV9JlMkBM6T3SGNalcyoB3O5g2LJvt1ef9UfjQjSMhfsGTE\nMvKXSEjsfNKrT+l1EnENceEtJV1IEh4FJeYJaX0HAoGBANcjOfCbG4bgr7cq4rcy\nSzC8lw3cz+S3jbcSj0dw1N4lCava3H8wnK2FAC82VYwafrYihMpQdkcFb35XKki6\nLK1MSwULhpzrHr4/3Rus7JgnzadF3Bcromll9Tpi/V3vE9G/P6ZjYX2kvv9o60mL\nF1euDZFImwwdkio6dPZoXCDW\n-----END PRIVATE KEY-----\n";
    const TEST_PUB: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3WvbZfb2/3NNAGlAIcQy\nBWFhavo8AWsUutfE4mf/Nvqt0ytoNQtq5q9zy51G8mjmarQfrdcDy0Cy0EWWVNUP\n2+0eLst1iMgpAuhm9ggfFc0O9/qCUvkX+UhvGMxbHCWHY4uCs+ANPLfQ4QN1d8jr\nblHC3KzZzaolAPiY7/Aj636e59m3URM/QNbXX2I7sjSJ84Td8d03g8w2e09vbR8V\nZhG3tS93/11rJ54PuM5o3yZoULe4o2hssMsBhxSbuq3sYxPaNeljEzVYS9KXqJhZ\nIbUcaNHiA1h7R+/GqgFixndebw0JAjXTHQCBYl5adSuS/Lm0pNc7zIlI/PdfQzaz\niQIDAQAB\n-----END PUBLIC KEY-----\n";

    fn doc(extra: &str) -> String {
        format!(
            r#"{{"type":"service_account",
                 "project_id":"my-proj",
                 "private_key_id":"kid-1",
                 "client_email":"svc@my-proj.iam.gserviceaccount.com",
                 "private_key":"{}"{extra}}}"#,
            TEST_KEY.replace('\n', "\\n")
        )
    }

    #[test]
    fn parses_a_console_key_and_defaults_scope_and_token_uri() {
        let sa = parse_credential(&doc("")).unwrap();
        assert_eq!(sa.client_email, "svc@my-proj.iam.gserviceaccount.com");
        assert_eq!(sa.project_id.as_deref(), Some("my-proj"));
        assert_eq!(sa.scope(), DEFAULT_VERTEX_SCOPE);
        assert_eq!(sa.token_uri().unwrap(), DEFAULT_TOKEN_URI);
    }

    #[test]
    fn missing_fields_are_rejected() {
        assert!(parse_credential("{}").is_err());
        assert!(parse_credential("not json").is_err());
        // A raw API key pasted where the JSON key belongs.
        assert!(parse_credential("AIzaSyDummyKey").is_err());
        // Present but empty.
        let no_email = doc("").replace("svc@my-proj.iam.gserviceaccount.com", "");
        assert!(parse_credential(&no_email).is_err());
    }

    /// A key that only fails when signing would surface as an opaque upstream
    /// error on a user's request instead of on the page that set it.
    #[test]
    fn an_unparseable_private_key_is_refused_at_write_time() {
        let bad = doc("").replace(&TEST_KEY.replace('\n', "\\n"), "-----BEGIN PRIVATE KEY-----\\nnope\\n-----END PRIVATE KEY-----\\n");
        let err = parse_credential(&bad).unwrap_err();
        assert!(format!("{err}").contains("private_key"), "got: {err}");
    }

    #[test]
    fn only_google_token_hosts_are_accepted() {
        for host in [
            "https://oauth2.googleapis.com/token",
            "https://accounts.google.com/o/oauth2/token",
            // A port names the same party, so it does not change the answer.
            "https://oauth2.googleapis.com:3445/token",
        ] {
            let sa = parse_credential(&doc(&format!(r#","token_uri":"{host}""#))).unwrap();
            assert_eq!(sa.token_uri().unwrap(), host);
        }
        for host in [
            "https://evil.example/token",
            "http://oauth2.googleapis.com/token",
            "https://oauth2.googleapis.com.evil.example/token",
            "https://evil.example:443/oauth2.googleapis.com/token",
            // Userinfo must not smuggle a foreign host past the check. The
            // second spelling is the sharp one: its authority *reads* as the
            // allowlisted host, but the host is `evil.example`.
            "https://oauth2.googleapis.com@evil.example/token",
            "https://oauth2.googleapis.com:hunter2@evil.example/token",
            // Userinfo on the RIGHT host is refused too: nothing about this
            // exchange takes basic auth, so a URL carrying it is not one we
            // should be dialling.
            "https://user:pw@oauth2.googleapis.com/token",
            // A trailing dot resolves the same but is a different string; the
            // allowlist stays literal rather than guessing.
            "https://oauth2.googleapis.com./token",
            // No host at all.
            "https:///token",
            "not a url",
        ] {
            assert!(
                parse_credential(&doc(&format!(r#","token_uri":"{host}""#))).is_err(),
                "{host} must be refused"
            );
        }
    }

    #[test]
    fn the_private_key_never_appears_in_debug_output() {
        let sa = parse_credential(&doc("")).unwrap();
        let rendered = format!("{sa:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(!rendered.contains(&TEST_KEY[40..80]), "{rendered}");
    }

    #[test]
    fn cache_key_covers_every_field_that_changes_the_token() {
        let base = parse_credential(&doc("")).unwrap().cache_key();
        assert_eq!(base, parse_credential(&doc("")).unwrap().cache_key());

        let rescoped = parse_credential(&doc(
            r#","scope":"https://www.googleapis.com/auth/cloud-platform.read-only""#,
        ))
        .unwrap()
        .cache_key();
        assert_ne!(base, rescoped);

        let other_account = parse_credential(
            &doc("").replace("svc@my-proj", "other@my-proj"),
        )
        .unwrap()
        .cache_key();
        assert_ne!(base, other_account);

        let rotated_kid =
            parse_credential(&doc("").replace(r#""kid-1""#, r#""kid-2""#)).unwrap().cache_key();
        assert_ne!(base, rotated_kid, "a rotated key id must not reuse the cached token");
    }

    /// The assertion is what Google actually authenticates, so every claim it
    /// checks is asserted here — and the signature is verified with the matching
    /// public key rather than merely produced.
    #[test]
    fn the_assertion_is_signed_and_carries_the_claims_google_checks() {
        let sa = parse_credential(&doc("")).unwrap();
        let jwt = sign_assertion(&sa, DEFAULT_TOKEN_URI, 1_700_000_000).unwrap();

        let header = jsonwebtoken::decode_header(&jwt).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some("kid-1"));

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[DEFAULT_TOKEN_URI]);
        // The fixture's timestamp is fixed, so expiry is checked explicitly below.
        validation.validate_exp = false;
        let decoded = jsonwebtoken::decode::<serde_json::Value>(
            &jwt,
            &jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).unwrap(),
            &validation,
        )
        .expect("the assertion must verify against the account's public key");

        let c = decoded.claims;
        assert_eq!(c["iss"], "svc@my-proj.iam.gserviceaccount.com");
        assert_eq!(c["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(c["scope"], DEFAULT_VERTEX_SCOPE);
        assert_eq!(c["iat"], 1_700_000_000u64);
        assert_eq!(c["exp"], 1_700_000_000u64 + ASSERTION_LIFETIME_SECS);
    }

    /// A tampered signature must not verify — the guard that the round-trip
    /// above is exercising the signature rather than just the encoding.
    #[test]
    fn a_tampered_assertion_does_not_verify() {
        let sa = parse_credential(&doc("")).unwrap();
        let jwt = sign_assertion(&sa, DEFAULT_TOKEN_URI, 1_700_000_000).unwrap();

        let (signed, sig) = jwt.rsplit_once('.').unwrap();
        // Flip one base64url character of the signature.
        let first = sig.chars().next().unwrap();
        let flipped = if first == 'A' { 'B' } else { 'A' };
        let tampered = format!("{signed}.{flipped}{}", &sig[first.len_utf8()..]);

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[DEFAULT_TOKEN_URI]);
        validation.validate_exp = false;
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUB.as_bytes()).unwrap();
        assert!(
            jsonwebtoken::decode::<serde_json::Value>(&tampered, &key, &validation).is_err(),
            "a tampered signature must be rejected"
        );
    }
}
