//! OIDC Relying Party.
//!
//! Identity arrives as a signature this process verifies, not as claims another
//! tier asserts. The pieces:
//!
//! * [`http`] — the SSRF-guarded transport every hop to the provider travels on.
//! * [`types`] — the claim shape, widened to carry `groups`.
//! * [`provider`] — cached discovery documents and signing keys, with the
//!   algorithm pinning and key-rotation handling the crate leaves to the caller.
//! * [`flow`] — the login's secrets, sealed so only this process can open them.
//! * [`identity`] — the console's provisioning decision: account linking,
//!   group-derived roles, lockout guards and domain restrictions.

pub mod flow;
pub mod http;
pub mod identity;
pub mod provider;
pub mod types;

use crate::routes::{ApiError, ApiErrorCode};

/// What can go wrong between a login starting and an identity being proven.
///
/// The variants carry detail for the operator's logs. They are deliberately
/// *not* carried to the client: a provider's response can quote back request
/// contents, and the browser has no use for the difference between a JWKS that
/// failed to parse and one that failed to fetch.
#[derive(Debug, Clone, thiserror::Error)]
pub enum OidcError {
    #[error("this tenant has no identity provider configured")]
    NotConfigured,
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    /// The provider gave no usable answer — the connection failed, timed out or
    /// was cut short, or it answered 502, 503 or 504
    /// ([`http::OidcHttpError::Unreachable`]). Says nothing about this
    /// deployment's configuration, so it is never reported as one.
    #[error("the identity provider could not be reached: {0}")]
    Unreachable(String),
    #[error("token verification failed: {0}")]
    Verification(String),
    #[error("code exchange failed: {0}")]
    Exchange(String),
    #[error("login state: {0}")]
    Flow(String),
    #[error("ENCRYPTION_KEY is unavailable")]
    EncryptionUnavailable,
}

impl From<OidcError> for ApiError {
    fn from(e: OidcError) -> Self {
        // Log the detail, hand the client a code and a sentence. Sanitising
        // here rather than at each call site is what makes it hard to leak an
        // upstream body by adding a new handler later.
        match e {
            OidcError::NotConfigured => ApiError::bad_request(
                "this tenant has no identity provider configured",
            )
            .code(ApiErrorCode::OidcNotConfigured),
            OidcError::Flow(detail) => {
                tracing::debug!(%detail, "oidc: login state was refused");
                ApiError::bad_request("this login could not be completed — start again")
                    .code(ApiErrorCode::OidcExchangeFailed)
            }
            OidcError::Verification(detail) => {
                tracing::warn!(%detail, "oidc: identity token failed verification");
                ApiError::unauthorized("the identity provider's response could not be verified")
                    .code(ApiErrorCode::OidcExchangeFailed)
            }
            OidcError::Unreachable(detail) => {
                tracing::warn!(%detail, "oidc: the identity provider could not be reached");
                ApiError::service_unavailable("the identity provider could not be reached — try again")
                    .code(ApiErrorCode::OidcProviderUnreachable)
            }
            OidcError::Discovery(detail) | OidcError::Exchange(detail) => {
                // A misconfiguration as much as a refused answer: a name that
                // does not resolve, a TLS failure, a malformed document.
                tracing::warn!(%detail, "oidc: the identity provider exchange failed");
                ApiError::internal("the identity provider exchange failed")
                    .code(ApiErrorCode::OidcExchangeFailed)
            }
            OidcError::EncryptionUnavailable => {
                tracing::error!("oidc: ENCRYPTION_KEY is unavailable — logins cannot proceed");
                ApiError::internal("the gateway is not configured to complete logins")
                    .code(ApiErrorCode::OidcExchangeFailed)
            }
        }
    }
}
