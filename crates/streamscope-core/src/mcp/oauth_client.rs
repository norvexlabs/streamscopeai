//! The `oauth2` client shape both upstream token hops share.
//!
//! Admin-api performs the authorization-code exchange when a user connects an
//! upstream MCP server; the proxy performs the refresh-token grant when that
//! user's access token ages out. Same client, same IdP, same failure
//! vocabulary — so the client construction, the response type, and the error
//! classification live here once.
//!
//! Two deliberate departures from the crate's defaults, both preserving
//! behaviour we already shipped and both covered by an E2E test:
//!
//! 1. **Client credentials go in the request body**, not an `Authorization:
//!    Basic` header. The crate defaults to `BasicAuth`; an operator whose IdP
//!    only reads body credentials would silently stop being able to refresh.
//! 2. **`token_type` may be absent.** The crate makes it mandatory; real IdPs
//!    omit it. [`LenientTokenResponse`] defaults it to `Bearer`, and the
//!    caller re-asserts Bearer afterwards so the strictness lands where it
//!    belongs — on what we accept, not on whether we can parse.

use std::time::Duration;

use chrono::{DateTime, Utc};
use oauth2::basic::{
    BasicErrorResponse, BasicErrorResponseType, BasicRevocationErrorResponse,
    BasicTokenIntrospectionResponse, BasicTokenType,
};
use oauth2::{
    AccessToken, AuthType, Client, ClientId, ClientSecret, EndpointNotSet, EndpointSet,
    RefreshToken, RequestTokenError, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::oauth_http::redact_oauth_secrets;

/// A token response that tolerates an absent `token_type`.
///
/// Mirrors `oauth2::StandardTokenResponse` minus the extra-fields generic,
/// which no upstream hop uses. The one behavioural difference is the
/// `token_type` default; everything else matches the crate's parsing,
/// including case-insensitive token types and space-delimited scopes.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LenientTokenResponse {
    access_token: AccessToken,
    #[serde(default = "bearer", deserialize_with = "deserialize_token_type")]
    token_type: BasicTokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    #[serde(
        rename = "scope",
        default,
        deserialize_with = "deserialize_space_delimited_scopes",
        serialize_with = "serialize_space_delimited_scopes",
        skip_serializing_if = "Option::is_none"
    )]
    scopes: Option<Vec<Scope>>,
}

fn bearer() -> BasicTokenType {
    BasicTokenType::Bearer
}

/// RFC 6749 §7.1 makes the token type case-insensitive. The crate's own
/// `Deserialize` for `BasicTokenType` matches lowercase literals only (it
/// relies on a wrapper to fold case first), so `"Bearer"` would otherwise
/// parse as an unrecognised extension type and be rejected downstream.
fn deserialize_token_type<'de, D>(deserializer: D) -> Result<BasicTokenType, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(match raw.to_lowercase().as_str() {
        "bearer" => BasicTokenType::Bearer,
        "mac" => BasicTokenType::Mac,
        _ => BasicTokenType::Extension(raw),
    })
}

fn deserialize_space_delimited_scopes<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<Scope>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(deserializer)?;
    Ok(raw.map(|s| s.split_whitespace().map(|p| Scope::new(p.to_string())).collect()))
}

fn serialize_space_delimited_scopes<S>(
    scopes: &Option<Vec<Scope>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match scopes {
        Some(list) => {
            let joined = list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
            serializer.serialize_str(&joined)
        }
        None => serializer.serialize_none(),
    }
}

impl TokenResponse for LenientTokenResponse {
    type TokenType = BasicTokenType;

    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

/// The client both upstream hops use: token endpoint only. No authorization,
/// device, introspection, or revocation URL is ever set on it — we build the
/// authorization URL ourselves (the state format is load-bearing) and
/// revocation stays hand-rolled.
pub type UpstreamTokenClient = Client<
    BasicErrorResponse,
    LenientTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// Build the upstream token client.
///
/// Fails only on an unparseable `token_url`; the SSRF posture is enforced by
/// the transport, not here.
pub fn upstream_token_client(
    client_id: &str,
    client_secret: Option<&str>,
    token_url: &str,
) -> Result<UpstreamTokenClient, String> {
    let token_url =
        TokenUrl::new(token_url.to_string()).map_err(|e| format!("invalid token_url: {e}"))?;
    let mut client = Client::new(ClientId::new(client_id.to_string()))
        // See the module header: body credentials, not Basic auth.
        .set_auth_type(AuthType::RequestBody)
        .set_token_uri(token_url);
    if let Some(secret) = client_secret {
        client = client.set_client_secret(ClientSecret::new(secret.to_string()));
    }
    Ok(client)
}

/// A validated token response, in the shape both callers store.
pub struct UpstreamTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
}

/// Validate and unpack a token response.
///
/// **Keep this the only place a token response is unpacked.** Both hazards
/// below are easy to handle correctly in one call site and miss in the other,
/// and the miss is silent — so the two hops share this function rather than
/// each reading the response themselves:
///
/// - **The token type is IdP-controlled content.** `LenientTokenResponse`
///   preserves an unrecognised one verbatim, so echoing it into an error puts
///   an attacker-chosen string into a log line and (on the admin side) a
///   user-visible redirect. It is redacted **before** being truncated —
///   truncating first could cut a secret in half and leave the prefix
///   unmatched by the redactor, and therefore visible.
/// - **`expires_in` is IdP-controlled too**, and each step of the conversion
///   fails differently: an `as i64` cast silently *wraps* a huge value to a
///   negative one (storing a credential that is already expired, so every
///   request re-refreshes), and `chrono::Duration::seconds` *panics* out of
///   range, taking down the worker mid-refresh. `try_from` then `try_seconds`
///   makes both outcomes `None`, and the credential is stored with no expiry.
pub fn into_tokens(
    response: LenientTokenResponse,
    secrets: &[&str],
) -> Result<UpstreamTokens, UpstreamTokenError> {
    // `LenientTokenResponse` accepts an absent `token_type` so a real-world
    // IdP's response still parses; Bearer is asserted here, so the strictness
    // lands on what we accept rather than on what we can parse.
    if *response.token_type() != BasicTokenType::Bearer {
        let redacted = redact_oauth_secrets(response.token_type().as_ref(), secrets);
        return Err(UpstreamTokenError::Failed(format!(
            "unsupported token_type: {}",
            redacted.chars().take(40).collect::<String>()
        )));
    }
    Ok(UpstreamTokens {
        access_token: response.access_token().secret().clone(),
        refresh_token: response.refresh_token().map(|t| t.secret().clone()),
        expires_at: response
            .expires_in()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .and_then(chrono::Duration::try_seconds)
            .and_then(|d| Utc::now().checked_add_signed(d)),
        scope: response
            .scopes()
            .map(|s| s.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(" ")),
    })
}

/// What an upstream token endpoint told us, reduced to the distinction both
/// callers act on.
#[derive(Debug)]
pub enum UpstreamTokenError {
    /// RFC 6749 `invalid_grant`: the code or refresh token is invalid,
    /// expired, or revoked. The user must reconnect — retrying cannot help.
    InvalidGrant,
    /// Anything else. Already redacted and safe to surface to an operator,
    /// an audit record, or a user-visible redirect.
    Failed(String),
}

/// Classify a token-endpoint failure, redacting any echo of `secrets`.
///
/// **Never `Debug`-format the incoming error.** `RequestTokenError::Parse`
/// carries the raw response bytes as a field; its `Display` deliberately does
/// not print them, but `{:?}` would dump an unparsed token response — which is
/// exactly the case where the body is most likely to hold a live credential.
pub fn classify_token_error<RE>(
    err: RequestTokenError<RE, BasicErrorResponse>,
    secrets: &[&str],
) -> UpstreamTokenError
where
    RE: std::error::Error + 'static,
{
    let detail = match err {
        RequestTokenError::ServerResponse(resp) => {
            if *resp.error() == BasicErrorResponseType::InvalidGrant {
                return UpstreamTokenError::InvalidGrant;
            }
            resp.error_description()
                .cloned()
                .unwrap_or_else(|| format!("oauth error: {}", resp.error()))
        }
        RequestTokenError::Request(e) => format!("transport: {e}"),
        // Display only — see the doc comment.
        RequestTokenError::Parse(e, _raw) => format!("parse token response: {e}"),
        RequestTokenError::Other(s) => s,
    };
    UpstreamTokenError::Failed(redact_oauth_secrets(&detail, secrets))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn parse(json: &str) -> Result<LenientTokenResponse, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The whole reason this type exists: real IdPs omit `token_type`, and the
    /// crate's own response type makes it mandatory.
    #[test]
    fn a_missing_token_type_defaults_to_bearer() {
        let r = parse(r#"{"access_token":"at"}"#).expect("parses without token_type");
        assert_eq!(*r.token_type(), BasicTokenType::Bearer);
        assert_eq!(r.access_token().secret(), "at");
    }

    /// RFC 6749 §7.1 says the value is case-insensitive. Getting this wrong
    /// turns every `"Bearer"`-spelling IdP into an unsupported token type.
    #[test]
    fn token_type_is_case_insensitive() {
        for spelling in [r#""Bearer""#, r#""BEARER""#, r#""bearer""#] {
            let r = parse(&format!(r#"{{"access_token":"at","token_type":{spelling}}}"#))
                .expect("parses");
            assert_eq!(*r.token_type(), BasicTokenType::Bearer, "{spelling}");
        }
    }

    #[test]
    fn an_unrecognised_token_type_is_preserved_verbatim() {
        let r = parse(r#"{"access_token":"at","token_type":"DPoP"}"#).expect("parses");
        assert_eq!(*r.token_type(), BasicTokenType::Extension("DPoP".into()));
    }

    #[test]
    fn scopes_split_on_whitespace_and_absence_is_none() {
        let r = parse(r#"{"access_token":"at","scope":"read  write"}"#).expect("parses");
        let scopes = r.scopes().expect("scope present");
        assert_eq!(
            scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["read", "write"]
        );
        assert!(parse(r#"{"access_token":"at"}"#).expect("parses").scopes().is_none());
    }

    #[test]
    fn optional_fields_round_trip() {
        let json = r#"{"access_token":"at","token_type":"bearer","expires_in":3600,
                       "refresh_token":"rt","scope":"read"}"#;
        let r = parse(json).expect("parses");
        assert_eq!(r.expires_in(), Some(Duration::from_secs(3600)));
        assert_eq!(r.refresh_token().map(|t| t.secret().as_str()), Some("rt"));

        // Serializing must re-emit `scope` as a space-delimited string, not a
        // JSON array — the shape every OAuth server speaks.
        let back = serde_json::to_value(&r).expect("serializes");
        assert_eq!(back["scope"], "read");
    }

    #[test]
    fn invalid_grant_is_classified_as_such() {
        let resp: BasicErrorResponse =
            serde_json::from_str(r#"{"error":"invalid_grant"}"#).expect("parses");
        assert_matches!(
            classify_token_error::<std::io::Error>(
                RequestTokenError::ServerResponse(resp),
                &[]
            ),
            UpstreamTokenError::InvalidGrant
        );
    }

    /// A hostile IdP echoing our credentials back in `error_description` must
    /// not get them into a log line or a user-visible redirect.
    #[test]
    fn a_server_error_is_redacted_before_it_escapes() {
        let resp: BasicErrorResponse = serde_json::from_str(
            r#"{"error":"invalid_request","error_description":"bad token rt_secret from sk_secret"}"#,
        )
        .expect("parses");
        let UpstreamTokenError::Failed(msg) = classify_token_error::<std::io::Error>(
            RequestTokenError::ServerResponse(resp),
            &["rt_secret", "sk_secret"],
        ) else {
            panic!("expected Failed");
        };
        assert!(!msg.contains("rt_secret"), "{msg}");
        assert!(!msg.contains("sk_secret"), "{msg}");
        assert!(msg.contains("<REDACTED>"), "{msg}");
    }

    /// The `Parse` variant carries the raw response bytes. Formatting the
    /// error must surface the parse failure without the body.
    #[test]
    fn a_parse_failure_never_leaks_the_response_body() {
        // Produce the error exactly as the crate does, rather than
        // hand-constructing one.
        let raw = br#"{"secret_in_body":"rt_secret"}"#;
        let mut de = serde_json::Deserializer::from_slice(raw);
        let path_err = serde_path_to_error::deserialize::<_, LenientTokenResponse>(&mut de)
            .expect_err("no access_token, so this cannot parse");

        let UpstreamTokenError::Failed(msg) = classify_token_error::<std::io::Error>(
            RequestTokenError::Parse(path_err, raw.to_vec()),
            &["rt_secret"],
        ) else {
            panic!("expected Failed");
        };
        assert!(!msg.contains("secret_in_body"), "{msg}");
        assert!(!msg.contains("rt_secret"), "{msg}");
    }

    /// The token type is echoed into the error and `LenientTokenResponse`
    /// keeps an unrecognised one verbatim, so a hostile IdP can put a string
    /// of its choosing there — including a secret it was just handed.
    #[test]
    fn an_unsupported_token_type_is_redacted_before_it_escapes() {
        let r = parse(r#"{"access_token":"at","token_type":"sk_secret"}"#).expect("parses");
        let Err(UpstreamTokenError::Failed(msg)) = into_tokens(r, &["sk_secret"]) else {
            panic!("a non-Bearer token type must be refused");
        };
        assert!(!msg.contains("sk_secret"), "{msg}");
        assert!(msg.contains("<REDACTED>"), "{msg}");
    }

    /// Redaction must run BEFORE the length cap. Truncating first would cut a
    /// long secret in half, leaving a prefix the redactor no longer matches —
    /// and therefore visible.
    #[test]
    fn a_long_echoed_secret_is_redacted_not_truncated_into_view() {
        let secret = "s".repeat(80);
        let r = parse(&format!(r#"{{"access_token":"at","token_type":"{secret}"}}"#))
            .expect("parses");
        let Err(UpstreamTokenError::Failed(msg)) = into_tokens(r, &[&secret]) else {
            panic!("a non-Bearer token type must be refused");
        };
        // No run of the secret survives, not even the first 40 chars.
        assert!(!msg.contains(&"s".repeat(40)), "{msg}");
    }

    /// `chrono::Duration::seconds` PANICS out of range, so an absurd
    /// `expires_in` from a hostile IdP would take down the worker mid-refresh.
    #[test]
    fn an_absurd_expires_in_yields_no_expiry_rather_than_panicking() {
        let r = parse(r#"{"access_token":"at","expires_in":18446744073709551615}"#)
            .expect("parses");
        let tokens = into_tokens(r, &[]).expect("bearer default, so accepted");
        assert!(tokens.expires_at.is_none(), "an unrepresentable expiry must be dropped");
    }

    #[test]
    fn a_normal_expires_in_produces_a_future_expiry() {
        let r = parse(r#"{"access_token":"at","expires_in":3600}"#).expect("parses");
        let tokens = into_tokens(r, &[]).expect("accepted");
        let at = tokens.expires_at.expect("expiry present");
        assert!(at > Utc::now(), "expiry must be in the future");
    }

    #[test]
    fn client_construction_rejects_a_malformed_token_url() {
        assert!(upstream_token_client("cid", None, "not a url").is_err());
        assert!(upstream_token_client("cid", Some("s"), "https://idp.example/token").is_ok());
    }
}
