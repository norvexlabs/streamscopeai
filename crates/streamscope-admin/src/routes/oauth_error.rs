//! The RFC 6749 §5.2 error envelope, and the extractors that produce it.
//!
//! OAuth clients branch on a body shape this product does not otherwise use:
//! `{"error": "invalid_grant", "error_description": "…"}`, where `error` is one
//! of a closed set of codes. Our own surfaces answer with `ApiErrorResponse`
//! instead, and the two must not be confused for one another — a client reading
//! `error` as a string would find an object, and the admin UI reading
//! `error.code` would find nothing.
//!
//! **Containment is the design.** [`OauthError`] is a separate type, and the
//! conversion runs one way only: `From<ApiError> for OauthError` exists so an
//! RFC endpoint can call shared helpers, and the reverse deliberately does not,
//! so it is *impossible* to emit this shape from a non-RFC route. The blast
//! radius is exactly the handlers that opt in by naming `OauthError` in their
//! return type.
//!
//! Which endpoints are RFC endpoints is a narrower question than it looks. The
//! token, device-authorization, revocation and dynamic-registration endpoints
//! are driven by third-party OAuth clients, so they answer in this shape.
//! `authorize/preview`, `authorize/approve` and the `device/*` decisions are our
//! own consent backend — the browser talks to them, not a client library — so
//! they keep `ApiError` and the UI keeps branching on `error.code`.
//!
//! The request side follows the same split, and the RFCs disagree about it on
//! purpose: RFC 6749 §4.1.3 mandates form encoding at `/token`, while RFC 7591
//! §3.1 mandates JSON at `/register`. Hence two extractors, [`OauthForm`] and
//! [`OauthJson`], each failing in the RFC error shape rather than axum's
//! plain-text rejection.

use axum::extract::{FromRequest, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::Serialize;
use utoipa::ToSchema;

use crate::routes::{ApiError, ApiErrorCode};

/// The `error` values this authorization server emits.
///
/// A subset of what RFC 6749 §5.2, RFC 8628 §3.5 and RFC 7591 §3.2.2 define —
/// the codes for conditions we can actually reach. The vocabulary is the RFCs',
/// not ours, so widening it is adding a variant, never inventing a value: a code
/// outside the specified set is one no client is required to understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OauthErrorCode {
    /// Malformed request: a parameter is missing, repeated, or unparseable.
    InvalidRequest,
    /// The client could not be identified or authenticated.
    InvalidClient,
    /// The grant (code, refresh token, device code) is invalid, expired,
    /// revoked, or was issued to another client.
    InvalidGrant,
    /// The grant type is not supported by this authorization server.
    UnsupportedGrantType,
    /// RFC 8707: the requested `resource` is not one this grant covers.
    InvalidTarget,
    /// The requested scope is not one this authorization server grants.
    InvalidScope,
    /// RFC 8628: the user has not yet decided; the device should keep polling.
    AuthorizationPending,
    /// RFC 8628: the device is polling faster than the advertised interval.
    SlowDown,
    /// RFC 8628: the user refused.
    AccessDenied,
    /// RFC 8628: the device code expired before the user decided.
    ExpiredToken,
    /// The server failed for a reason the client cannot act on.
    ServerError,
    /// RFC 7591 §3.2.2: a `redirect_uris` entry is not one this server accepts.
    InvalidRedirectUri,
    /// RFC 7591 §3.2.2: some other registration metadata is unacceptable.
    InvalidClientMetadata,
}

impl OauthErrorCode {
    /// Every variant, so a test can walk the whole vocabulary rather than the
    /// handful someone remembered to list.
    #[cfg(test)]
    const ALL: &'static [Self] = &[
        Self::InvalidRequest,
        Self::InvalidClient,
        Self::InvalidGrant,
        Self::UnsupportedGrantType,
        Self::InvalidTarget,
        Self::InvalidScope,
        Self::AuthorizationPending,
        Self::SlowDown,
        Self::AccessDenied,
        Self::ExpiredToken,
        Self::ServerError,
        Self::InvalidRedirectUri,
        Self::InvalidClientMetadata,
    ];

    /// The wire spelling, for the codes that travel as a **query parameter**
    /// rather than in a JSON body — the RFC 6749 §4.1.2.1 error redirect.
    ///
    /// **Invariant to preserve when adding a variant:** this must agree with
    /// the `Serialize` impl character for character. A client comparing the
    /// `error` it reads from a redirect against the one it reads from a token
    /// response has no reason to expect two spellings, and
    /// `as_str_matches_the_serialized_form` fails if they diverge.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidScope => "invalid_scope",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::AccessDenied => "access_denied",
            Self::ExpiredToken => "expired_token",
            Self::ServerError => "server_error",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
        }
    }

    /// The status RFC 6749 §5.2 pairs with each code.
    ///
    /// `invalid_client` is 401 and the pending/slow-down pair are 400 — the
    /// latter is what makes a polling device treat them as "keep going" rather
    /// than as a failure.
    fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// An error in the shape a third-party OAuth client expects.
#[derive(Debug)]
pub struct OauthError {
    pub code: OauthErrorCode,
    pub description: String,
    /// Set only via [`OauthError::with_status`]; `None` means the code decides.
    status: Option<StatusCode>,
}

#[derive(Serialize, ToSchema)]
pub struct OauthErrorResponse {
    pub error: OauthErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl OauthError {
    pub fn new(code: OauthErrorCode, description: impl Into<String>) -> Self {
        Self { code, description: description.into(), status: None }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(OauthErrorCode::InvalidRequest, description)
    }

    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(OauthErrorCode::UnsupportedGrantType, description)
    }

    pub fn server_error(description: impl Into<String>) -> Self {
        Self::new(OauthErrorCode::ServerError, description)
    }

    /// RFC 7591 §3.2.2 — the client's registration metadata is unacceptable.
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new(OauthErrorCode::InvalidClientMetadata, description)
    }

    /// Override the status this error answers with.
    ///
    /// Use ONLY where the governing RFC leaves the status open. RFC 7591 §3.2.2
    /// fixes 400 for the registration errors it names, but says nothing about a
    /// server that refuses for a reason of its own — a per-tenant quota, or a
    /// tenant that has not enabled the feature. Those keep the status that
    /// describes them (429 for a quota) while still answering in a shape the
    /// client can parse. Never reach for this to restyle an RFC-defined code:
    /// a client branching on `invalid_grant` expects the status the RFC pairs
    /// with it.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }
}

impl IntoResponse for OauthError {
    fn into_response(self) -> Response {
        let body = OauthErrorResponse {
            error: self.code,
            error_description: description_if_useful(self.description),
        };
        // RFC 6749 §5.1: a token response must never be cached, and that
        // applies to the error too — a cached `authorization_pending` would
        // stall a device poll indefinitely.
        (
            self.status.unwrap_or_else(|| self.code.status()),
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(body),
        )
            .into_response()
    }
}

/// Map a shared helper's [`ApiError`] onto the RFC shape.
///
/// One-directional on purpose — see the module docs. The mapping reads the
/// machine-readable code where there is one and falls back on the status, which
/// is why `ApiErrorCode` stays the source of truth rather than the message text.
impl From<ApiError> for OauthError {
    fn from(e: ApiError) -> Self {
        use ApiErrorCode as C;
        let code = match e.code {
            // Everything that means "this grant is no good" collapses into one
            // RFC code. Our own vocabulary distinguishes a bad code from a bad
            // verifier from a mismatched redirect URI; the RFC deliberately does
            // not, because telling a caller *which* part of a failed grant was
            // wrong helps an attacker more than a client.
            C::McpOauthInvalidGrant
            | C::OauthInvalidGrant
            | C::McpOauthInvalidVerifier
            | C::OauthInvalidVerifier
            | C::McpOauthRedirectUriMismatch
            | C::OauthRedirectUriMismatch => OauthErrorCode::InvalidGrant,
            C::McpOauthClientNotFound | C::OauthClientNotFound => {
                OauthErrorCode::InvalidClient
            }
            C::McpOauthInvalidResource => OauthErrorCode::InvalidTarget,
            // RFC 7591 §3.2.2 registration vocabulary. These reach an RFC
            // endpoint only from `/register` and the CIMD document it resolves
            // on the way; the admin CRUD that shares the codes answers in
            // `ApiErrorResponse` and never passes through here.
            C::McpOauthRedirectUriInvalid => OauthErrorCode::InvalidRedirectUri,
            C::McpOauthDcrInvalidRequest
            | C::McpOauthCimdFetchFailed
            | C::McpOauthCimdInvalidMetadata => OauthErrorCode::InvalidClientMetadata,
            // RFC 8628 polling states. A device reads these to decide whether to
            // keep waiting, so mapping one of them onto a generic failure would
            // abandon a login the user is about to approve.
            C::OauthAuthorizationPending => OauthErrorCode::AuthorizationPending,
            C::OauthSlowDown => OauthErrorCode::SlowDown,
            C::OauthAccessDenied => OauthErrorCode::AccessDenied,
            C::OauthExpiredToken => OauthErrorCode::ExpiredToken,
            _ => match e.status {
                StatusCode::UNAUTHORIZED => OauthErrorCode::InvalidClient,
                StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                    OauthErrorCode::InvalidRequest
                }
                _ => OauthErrorCode::ServerError,
            },
        };
        Self::new(code, e.message)
    }
}

/// Omit an empty description rather than serializing `""`.
fn description_if_useful(d: String) -> Option<String> {
    (!d.trim().is_empty()).then_some(d)
}

/// A form-encoded request body that fails in the RFC shape.
///
/// Axum's own `Form` rejection is a plain-text 415/422, which a client parsing
/// `{"error": …}` cannot read — so a client sending a slightly wrong body would
/// get an error it reports as "unparseable response" rather than as the actual
/// problem. This wrapper is the difference between a diagnosable failure and a
/// confusing one.
pub struct OauthForm<T>(pub T);

impl<T, S> FromRequest<S> for OauthForm<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = OauthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::Form::<T>::from_request(req, state)
            .await
            .map(|axum::Form(v)| Self(v))
            .map_err(|e| match e {
                // Too large, late or broken off: nothing about its encoding.
                axum::extract::rejection::FormRejection::BytesRejection(e) => {
                    OauthError::invalid_request(format!("the request body could not be read: {e}"))
                }
                e => OauthError::invalid_request(format!(
                    "the request body must be application/x-www-form-urlencoded: {e}"
                )),
            })
    }
}

/// A JSON request body that fails in the RFC shape.
///
/// The counterpart to [`OauthForm`] for RFC 7591 §3.1, which specifies JSON at
/// the registration endpoint. Same reasoning: a client that posts a slightly
/// wrong body must get a parseable error describing it, not axum's plain-text
/// rejection that reads as an unparseable response.
pub struct OauthJson<T>(pub T);

impl<T, S> FromRequest<S> for OauthJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = OauthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| Self(v))
            .map_err(|e| match e {
                // Too large, late or broken off: nothing about its metadata,
                // said under the one code RFC 7591 §3.2.2 gives a body it refuses.
                axum::extract::rejection::JsonRejection::BytesRejection(e) => OauthError::new(
                    OauthErrorCode::InvalidClientMetadata,
                    format!("the request body could not be read: {e}"),
                ),
                e => OauthError::new(
                    OauthErrorCode::InvalidClientMetadata,
                    format!("the request body must be JSON matching RFC 7591 §2: {e}"),
                ),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_as_the_rfc_spells_them() {
        for (code, expected) in [
            (OauthErrorCode::InvalidRequest, "\"invalid_request\""),
            (OauthErrorCode::InvalidGrant, "\"invalid_grant\""),
            (OauthErrorCode::UnsupportedGrantType, "\"unsupported_grant_type\""),
            (OauthErrorCode::AuthorizationPending, "\"authorization_pending\""),
            (OauthErrorCode::SlowDown, "\"slow_down\""),
            (OauthErrorCode::InvalidTarget, "\"invalid_target\""),
        ] {
            assert_eq!(serde_json::to_string(&code).expect("serializes"), expected);
        }
    }

    /// The redirect spelling and the JSON-body spelling are the same string.
    /// A client that reads `error` from an authorization-endpoint redirect and
    /// from a token-endpoint body compares them against one vocabulary.
    #[test]
    fn as_str_matches_the_serialized_form() {
        for code in OauthErrorCode::ALL {
            assert_eq!(
                serde_json::to_string(code).expect("serializes"),
                format!("\"{}\"", code.as_str()),
                "{code:?} spells differently in a redirect than in a body"
            );
        }
    }

    /// `error` must be a bare string, not the nested object our own surfaces
    /// use — a client reads it directly.
    #[test]
    fn the_body_is_the_flat_rfc_shape() {
        let body = serde_json::to_value(OauthErrorResponse {
            error: OauthErrorCode::InvalidGrant,
            error_description: Some("code already redeemed".into()),
        })
        .expect("serializes");
        assert_eq!(body["error"], "invalid_grant");
        assert_eq!(body["error_description"], "code already redeemed");
    }

    #[test]
    fn an_empty_description_is_omitted_rather_than_sent_blank() {
        let body = serde_json::to_value(OauthErrorResponse {
            error: OauthErrorCode::ServerError,
            error_description: description_if_useful("  ".into()),
        })
        .expect("serializes");
        assert!(body.get("error_description").is_none());
    }

    /// The pending/slow-down pair must stay 400: a device treats a 4xx with
    /// those codes as "keep polling" and anything else as a hard failure.
    #[test]
    fn polling_codes_are_400_and_client_errors_are_401() {
        assert_eq!(OauthErrorCode::AuthorizationPending.status(), StatusCode::BAD_REQUEST);
        assert_eq!(OauthErrorCode::SlowDown.status(), StatusCode::BAD_REQUEST);
        assert_eq!(OauthErrorCode::InvalidClient.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(OauthErrorCode::ServerError.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn an_api_error_maps_by_code_before_status() {
        let e: OauthError = ApiError::bad_request("nope")
            .code(ApiErrorCode::OauthInvalidGrant)
            .into();
        assert_eq!(e.code, OauthErrorCode::InvalidGrant);

        // No code to read: the status decides.
        let e: OauthError = ApiError::unauthorized("who?").into();
        assert_eq!(e.code, OauthErrorCode::InvalidClient);
        let e: OauthError = ApiError::internal("boom").into();
        assert_eq!(e.code, OauthErrorCode::ServerError);
    }

    /// The distinctions our vocabulary draws inside a failed grant are not
    /// distinctions the RFC draws — every one of them is `invalid_grant`.
    #[test]
    fn every_failed_grant_reads_as_invalid_grant() {
        for code in [
            ApiErrorCode::McpOauthInvalidGrant,
            ApiErrorCode::OauthInvalidGrant,
            ApiErrorCode::McpOauthInvalidVerifier,
            ApiErrorCode::OauthInvalidVerifier,
            ApiErrorCode::McpOauthRedirectUriMismatch,
            ApiErrorCode::OauthRedirectUriMismatch,
        ] {
            let e: OauthError = ApiError::bad_request("x").code(code).into();
            assert_eq!(e.code, OauthErrorCode::InvalidGrant, "{code:?}");
        }
    }

    /// A device decides whether to keep polling from these, so a mapping slip
    /// here abandons a login the user is in the middle of approving.
    #[test]
    fn device_polling_states_survive_the_mapping() {
        for (api, oauth) in [
            (ApiErrorCode::OauthAuthorizationPending, OauthErrorCode::AuthorizationPending),
            (ApiErrorCode::OauthSlowDown, OauthErrorCode::SlowDown),
            (ApiErrorCode::OauthAccessDenied, OauthErrorCode::AccessDenied),
            (ApiErrorCode::OauthExpiredToken, OauthErrorCode::ExpiredToken),
        ] {
            let e: OauthError = ApiError::bad_request("x").code(api).into();
            assert_eq!(e.code, oauth, "{api:?}");
        }
    }
}
