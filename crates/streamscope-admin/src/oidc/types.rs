//! Type aliases carrying every claim the provider sent, not only the standard set.
//!
//! `openidconnect`'s `CoreClient` is instantiated with `EmptyAdditionalClaims`,
//! so any claim outside the OIDC standard set is discarded during
//! verification. The console role and workspace auto-join are driven by exactly
//! such claims, and which one is a per-tenant choice (`groups` on most
//! providers, `group` on AD FS, a workspace may name `roles`), so the gateway
//! keeps all of them and reads the configured one by name afterwards.
//!
//! Declaring the alias set below is the crate's supported way to widen the
//! claim shape; every type is the `Core*` one with [`ExtraClaims`] substituted
//! for the empty additional-claims marker.

use std::collections::BTreeMap;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse,
    CoreTokenType,
};
use openidconnect::{
    AdditionalClaims, Client, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IdTokenClaims, IdTokenFields, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Every ID-token claim outside the OIDC standard set, verbatim.
///
/// Held as raw JSON on purpose: a typed field fails the WHOLE token when a
/// provider picks a different shape for it, and providers do — AD FS sends a
/// single-valued claim as a bare string and a multi-valued one as an array.
/// Shape is settled once, when a claim is read, by [`claim_values`].
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ExtraClaims(pub Map<String, Value>);

impl AdditionalClaims for ExtraClaims {}

/// The string values of one claim, whichever shape the provider chose.
///
/// A string is one value and an array is many; anything else (a number, an
/// object, `null`) carries no value a group name or address could be matched
/// against, and neither does an empty string. An absent claim is an empty list,
/// never an error — plenty of providers omit a claim they are not configured
/// to release.
pub fn claim_values(value: Option<&Value>) -> Vec<String> {
    let one = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
    match value {
        Some(Value::Array(items)) => items.iter().filter_map(one).collect(),
        Some(v) => one(v).into_iter().collect(),
        None => Vec::new(),
    }
}

/// Every claim of a verified ID token, standard and additional alike, as one
/// name → values map.
///
/// Reading a configured claim NAME has to see both halves: an operator may name
/// a standard claim (`preferred_username`) or a provider-specific one (`upn`),
/// and the crate splits the two into different structs. Serialising the claims
/// back is the one view with no split in it.
pub fn claim_map(claims: &SsIdTokenClaims) -> BTreeMap<String, Vec<String>> {
    let Ok(Value::Object(all)) = serde_json::to_value(claims) else {
        return BTreeMap::new();
    };
    all.iter()
        .map(|(name, value)| (name.clone(), claim_values(Some(value))))
        .filter(|(_, values)| !values.is_empty())
        .collect()
}

pub type SsIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

pub type SsTokenResponse = StandardTokenResponse<SsIdTokenFields, CoreTokenType>;

pub type SsIdTokenClaims = IdTokenClaims<ExtraClaims, CoreGenderClaim>;

/// The client shape after `from_provider_metadata` plus a redirect URI: the
/// auth and redirect endpoints are set, the token endpoint is "maybe" (the
/// provider metadata may omit it), which is why `exchange_code` returns a
/// `Result` rather than the request directly.
pub type SsClient<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    SsTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_list_claim_yields_every_string() {
        assert_eq!(claim_values(Some(&json!(["it-admins", "rd"]))), vec!["it-admins", "rd"]);
    }

    /// AD FS sends a single-valued claim as a bare string; it is one value.
    #[test]
    fn a_single_string_claim_is_one_value() {
        assert_eq!(claim_values(Some(&json!("it-admins"))), vec!["it-admins"]);
    }

    #[test]
    fn an_absent_claim_is_empty_not_an_error() {
        assert!(claim_values(None).is_empty());
    }

    /// Nothing that is not a non-empty string can match a configured name.
    #[test]
    fn values_that_are_not_strings_are_not_values() {
        assert!(claim_values(Some(&json!(""))).is_empty());
        assert!(claim_values(Some(&json!(null))).is_empty());
        assert!(claim_values(Some(&json!(42))).is_empty());
        assert!(claim_values(Some(&json!({"nested": "x"}))).is_empty());
        assert_eq!(claim_values(Some(&json!(["a", 1, "", null, "b"]))), vec!["a", "b"]);
    }

    /// A verified AD FS-shaped ID token: the claims ride the same parse the
    /// login does, so a shape that fails here fails a real login.
    fn adfs_id_token(extra: Value) -> SsIdTokenClaims {
        let mut token = json!({
            "iss": "https://adfs.example.com/adfs",
            "sub": "vtJ9Cg0tpcVrPdOZfNmRdA==",
            "aud": "11111111-2222-3333-4444-555555555555",
            "exp": 4_102_444_800_i64,
            "iat": 1_700_000_000_i64,
            "nonce": "n-1",
        });
        let obj = token.as_object_mut().expect("object");
        for (k, v) in extra.as_object().expect("object") {
            obj.insert(k.clone(), v.clone());
        }
        serde_json::from_value(token).expect("an AD FS ID token parses")
    }

    #[test]
    fn a_single_group_id_token_parses_and_reads_as_one_group() {
        let claims = adfs_id_token(json!({"group": "CONTOSO\\streamscope-admins"}));
        let map = claim_map(&claims);
        assert_eq!(map.get("group"), Some(&vec!["CONTOSO\\streamscope-admins".to_string()]));
    }

    #[test]
    fn a_single_groups_id_token_parses_under_the_default_name() {
        let claims = adfs_id_token(json!({"groups": "streamscope-admins"}));
        assert_eq!(claim_map(&claims).get("groups"), Some(&vec!["streamscope-admins".to_string()]));
    }

    /// The claim map sees standard and provider-specific claims alike, so an
    /// operator can name either as the address claim.
    #[test]
    fn the_claim_map_holds_standard_and_additional_claims() {
        let claims = adfs_id_token(json!({
            "email": "ada@contoso.com",
            "preferred_username": "ada",
            "upn": "ada@corp.contoso.com",
            "unique_name": "CONTOSO\\ada",
        }));
        let map = claim_map(&claims);
        assert_eq!(map.get("email"), Some(&vec!["ada@contoso.com".to_string()]));
        assert_eq!(map.get("preferred_username"), Some(&vec!["ada".to_string()]));
        assert_eq!(map.get("upn"), Some(&vec!["ada@corp.contoso.com".to_string()]));
        assert_eq!(map.get("sub"), Some(&vec!["vtJ9Cg0tpcVrPdOZfNmRdA==".to_string()]));
    }

    /// Additional claims keep every shape the provider sent — no claim may make
    /// the others unreadable.
    #[test]
    fn extra_claims_accept_any_shape() {
        let claims: ExtraClaims = serde_json::from_value(json!({
            "group": "it-admins",
            "groups": ["a", "b"],
            "custom_vendor_claim": {"nested": true},
        }))
        .expect("deserializes");
        assert_eq!(claim_values(claims.0.get("group")), vec!["it-admins"]);
        assert_eq!(claim_values(claims.0.get("groups")), vec!["a", "b"]);
    }
}
