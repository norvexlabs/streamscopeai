//! Microsoft Entra ID access tokens for the `azure_openai_entra` transport.
//!
//! An Azure OpenAI resource accepts either a static key or an OAuth 2.0 bearer
//! token. The token is obtained with the client-credentials grant — no user, no
//! refresh token, and no long-lived secret on the wire — so the gateway mints one
//! per credential and re-mints it when it nears expiry.
//!
//! The credential is stored in the ordinary encrypted upstream-credential column
//! as a JSON document, so it travels the existing AES-256-GCM path and the
//! existing config-sync channel with no separate secret plumbing.
//!
//! Three invariants to preserve:
//! - **The authority host is allowlisted.** The tenant id is operator-supplied
//!   and lands in a URL; the host must never be, or an admin could point the
//!   gateway's credentialed egress at an arbitrary address.
//! - **The secret never reaches a log or an error body.** `Debug` is redacted by
//!   hand, and a failed mint reports the status, not the response.
//! - **The mint dials through [`crate::proxy::minted_token::post_token_form`]**,
//!   never a client of its own — the allowlist pins the host, the shared SSRF
//!   guard pins what that host resolves to.

use std::sync::LazyLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::proxy::minted_token::{post_token_form, MintFailure, MintedToken, MintedTokenCache};

/// The resource whose `.default` scope an Azure OpenAI token is issued for.
/// Foundry-flavoured resources (`*.services.ai.azure.com`) use
/// `https://ai.azure.com/.default` instead, which is why this is a default and
/// not a constant in the request builder.
pub const DEFAULT_ENTRA_SCOPE: &str = "https://cognitiveservices.azure.com/.default";

/// The Entra authority for the Azure public cloud.
pub const DEFAULT_ENTRA_AUTHORITY: &str = "https://login.microsoftonline.com";

/// Authorities the gateway will send a client secret to. Sovereign clouds have
/// their own hosts; anything else is refused rather than dialled.
const ALLOWED_AUTHORITY_HOSTS: [&str; 4] = [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.partner.microsoftonline.cn",
    "login.chinacloudapi.cn",
];

/// How the authority is named in an operator-facing failure.
const AUTHORITY_LABEL: &str = "the Microsoft identity platform";

/// A stored Entra client-credentials document.
#[derive(Clone, Deserialize)]
pub struct AzureEntraCredential {
    /// The directory (tenant) the application authenticates against — a GUID or
    /// a domain name.
    pub tenant_id: String,
    /// The application (client) id.
    pub client_id: String,
    /// The client secret generated for the application.
    pub client_secret: String,
    /// Resource scope; defaults to [`DEFAULT_ENTRA_SCOPE`].
    #[serde(default)]
    pub scope: Option<String>,
    /// Entra authority origin; defaults to [`DEFAULT_ENTRA_AUTHORITY`].
    #[serde(default)]
    pub authority: Option<String>,
}

impl std::fmt::Debug for AzureEntraCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureEntraCredential")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scope", &self.scope)
            .field("authority", &self.authority)
            .finish()
    }
}

impl AzureEntraCredential {
    /// The scope this credential requests a token for.
    pub fn scope(&self) -> &str {
        self.scope.as_deref().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(DEFAULT_ENTRA_SCOPE)
    }

    /// The authority origin this credential authenticates against.
    pub fn authority(&self) -> &str {
        self.authority
            .as_deref()
            .map(|a| a.trim().trim_end_matches('/'))
            .filter(|a| !a.is_empty())
            .unwrap_or(DEFAULT_ENTRA_AUTHORITY)
    }

    /// The full client-credentials token endpoint for this credential.
    ///
    /// Both interpolated segments are validated first: the authority against the
    /// known Entra clouds, and the tenant id against the charset a GUID or a
    /// domain name can use — neither may introduce a new host or a new path.
    pub fn token_url(&self) -> Result<String, AppError> {
        let authority = self.authority();
        let host = authority
            .strip_prefix("https://")
            .ok_or_else(|| AppError::BadRequest("Entra authority must be an https:// origin.".into()))?;
        if !ALLOWED_AUTHORITY_HOSTS.contains(&host) {
            return Err(AppError::BadRequest(format!(
                "Entra authority `{host}` is not a recognised Microsoft identity platform host."
            )));
        }
        let tenant = self.tenant_id.trim();
        if tenant.is_empty()
            || !tenant.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(AppError::BadRequest(
                "Entra tenant id must be a GUID or a domain name.".into(),
            ));
        }
        Ok(format!("{authority}/{tenant}/oauth2/v2.0/token"))
    }

    /// Validate every field the mint needs, without performing one.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.client_id.trim().is_empty() {
            return Err(AppError::BadRequest("Entra client id is required.".into()));
        }
        if self.client_secret.is_empty() {
            return Err(AppError::BadRequest("Entra client secret is required.".into()));
        }
        self.token_url().map(|_| ())
    }

    /// Key this credential's cache entry. Derived from every field that changes
    /// which token comes back, so a rotated secret or a re-scoped credential
    /// cannot be served the previous token.
    fn cache_key(&self) -> String {
        let mut h = Sha256::new();
        for part in [self.authority(), &self.tenant_id, &self.client_id, &self.client_secret, self.scope()] {
            h.update(part.as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    }
}

/// Parse a stored credential document.
pub fn parse_credential(doc: &str) -> Result<AzureEntraCredential, AppError> {
    let cred: AzureEntraCredential = serde_json::from_str(doc.trim()).map_err(|_| {
        AppError::BadRequest(
            "Entra credential must be a JSON object with tenant_id, client_id and client_secret."
                .into(),
        )
    })?;
    cred.validate()?;
    Ok(cred)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

static TOKENS: LazyLock<MintedTokenCache> = LazyLock::new(MintedTokenCache::new);

/// Return a valid access token for the stored credential document, minting one
/// if the cache holds nothing usable.
///
/// A refusal by the token endpoint is told apart from every other failure
/// ([`MintFailure`]); the data plane reports both alike.
pub async fn access_token(credential_doc: &str) -> Result<String, MintFailure> {
    // A malformed stored document is a CONFIGURATION fault, but this runs on the
    // data plane — so it is logged for the operator and sanitized for the client,
    // never surfaced as a 400 describing the gateway's own stored credential.
    // The admin write path calls `parse_credential` directly and keeps its
    // operator-facing message.
    let cred = parse_credential(credential_doc).map_err(|e| {
        tracing::error!(error = %e, "stored Entra credential is unusable");
        AppError::Internal("the upstream credential for this server is not usable".into())
    })?;
    TOKENS.get_or_mint(cred.cache_key(), || mint(&cred)).await
}

/// Perform one client-credentials token request.
async fn mint(cred: &AzureEntraCredential) -> Result<MintedToken, MintFailure> {
    let url = cred.token_url()?;
    let answered = post_token_form(
        &url,
        AUTHORITY_LABEL,
        &[
            ("client_id", cred.client_id.as_str()),
            ("client_secret", cred.client_secret.as_str()),
            ("scope", cred.scope()),
            ("grant_type", "client_credentials"),
        ],
    )
    .await?;
    let (status, body) = (answered.status, answered.body);

    if !status.is_success() {
        // The authority's body echoes the request's own parameters back in its
        // error text, so it is logged for the operator and never returned.
        tracing::error!(
            status = status.as_u16(),
            error = %String::from_utf8_lossy(&body).chars().take(512).collect::<String>(),
            "Entra token request rejected"
        );
        return Err(MintFailure::from_refusal(status, AppError::Internal(format!(
            "Microsoft Entra ID rejected the upstream credential (status {})",
            status.as_u16()
        ))));
    }

    let parsed: TokenResponse = serde_json::from_slice(&body).map_err(|_| {
        AppError::Internal("unrecognised response from the Microsoft identity platform".into())
    })?;
    if parsed.access_token.is_empty() {
        return Err(AppError::Internal(
            "the Microsoft identity platform returned an empty access token".into(),
        )
        .into());
    }

    Ok(MintedToken { value: parsed.access_token, expires_in_secs: parsed.expires_in })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(extra: &str) -> String {
        format!(
            r#"{{"tenant_id":"aaaabbbb-0000-cccc-1111-dddd2222eeee",
                 "client_id":"00001111-aaaa-2222-bbbb-3333cccc4444",
                 "client_secret":"s3cr3t"{extra}}}"#
        )
    }

    #[test]
    fn parses_a_minimal_document_and_defaults_scope_and_authority() {
        let cred = parse_credential(&doc("")).unwrap();
        assert_eq!(cred.scope(), DEFAULT_ENTRA_SCOPE);
        assert_eq!(cred.authority(), DEFAULT_ENTRA_AUTHORITY);
        assert_eq!(
            cred.token_url().unwrap(),
            "https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/oauth2/v2.0/token"
        );
    }

    #[test]
    fn a_foundry_resource_can_override_the_scope() {
        let cred = parse_credential(&doc(r#","scope":"https://ai.azure.com/.default""#)).unwrap();
        assert_eq!(cred.scope(), "https://ai.azure.com/.default");
    }

    #[test]
    fn sovereign_authorities_are_accepted_and_others_refused() {
        for host in ALLOWED_AUTHORITY_HOSTS {
            let cred =
                parse_credential(&doc(&format!(r#","authority":"https://{host}/""#))).unwrap();
            assert!(cred.token_url().unwrap().starts_with(&format!("https://{host}/")));
        }
        // An arbitrary host must not receive the client secret.
        assert!(parse_credential(&doc(r#","authority":"https://evil.example""#)).is_err());
        // Nor may a plaintext origin.
        assert!(
            parse_credential(&doc(r#","authority":"http://login.microsoftonline.com""#)).is_err()
        );
    }

    /// The tenant id is interpolated into the URL path, so it may not smuggle in
    /// extra segments or a new host.
    #[test]
    fn tenant_id_cannot_escape_its_path_segment() {
        for tenant in ["../../evil", "a/b", "tenant?x=1", "ten ant", ""] {
            let json = format!(
                r#"{{"tenant_id":"{tenant}","client_id":"c","client_secret":"s"}}"#
            );
            assert!(parse_credential(&json).is_err(), "accepted tenant: {tenant}");
        }
        // A domain-name tenant is legitimate.
        let json = r#"{"tenant_id":"contoso.onmicrosoft.com","client_id":"c","client_secret":"s"}"#;
        assert!(parse_credential(json).is_ok());
    }

    #[test]
    fn missing_fields_are_rejected() {
        assert!(parse_credential("{}").is_err());
        assert!(parse_credential("not json").is_err());
        assert!(
            parse_credential(r#"{"tenant_id":"t","client_id":"c","client_secret":""}"#).is_err()
        );
        assert!(
            parse_credential(r#"{"tenant_id":"t","client_id":"","client_secret":"s"}"#).is_err()
        );
    }

    #[test]
    fn the_secret_never_appears_in_debug_output() {
        let cred = parse_credential(&doc("")).unwrap();
        let rendered = format!("{cred:?}");
        assert!(!rendered.contains("s3cr3t"), "secret leaked into Debug: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    /// Rotating the secret must produce a different cache entry, or the previous
    /// token would keep being served after a rotation.
    #[test]
    fn cache_key_covers_every_field_that_changes_the_token() {
        let base = parse_credential(&doc("")).unwrap().cache_key();
        let rotated =
            parse_credential(r#"{"tenant_id":"aaaabbbb-0000-cccc-1111-dddd2222eeee","client_id":"00001111-aaaa-2222-bbbb-3333cccc4444","client_secret":"rotated"}"#)
                .unwrap()
                .cache_key();
        let rescoped =
            parse_credential(&doc(r#","scope":"https://ai.azure.com/.default""#)).unwrap().cache_key();
        assert_ne!(base, rotated);
        assert_ne!(base, rescoped);
        assert_eq!(base, parse_credential(&doc("")).unwrap().cache_key());
    }

}
