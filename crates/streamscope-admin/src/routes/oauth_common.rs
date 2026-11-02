//! Shared plumbing for the gateway's first-party OAuth 2.1 surfaces (MCP
//! spec-OAuth in `mcp_oauth`, CLI provisioning in `cli_oauth`): token TTLs,
//! redirect-URI validation, code generation, tenant resolution, the
//! portal-session gate used by consent backends, and the wire shapes of the
//! `/token` endpoints. Surface-specific grant logic (claims shapes, storage
//! rows) stays in each surface's module.

use jsonwebtoken::{decode, DecodingKey};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;


use streamscope_mcp_auth::Keyring;

use super::admin_auth::{decode_session_jwt, keyring, session_verification_key};
use super::oauth_error::OauthErrorCode;
use super::portal_auth::{PortalClaims, PortalUser, SCOPE_PORTAL};
use super::{ApiError, ApiErrorCode};
use crate::db::tenant::Scoped;

// ---------------------------------------------------------------------------
// Token lifetimes (shared across surfaces)
// ---------------------------------------------------------------------------

/// Lifetime of issued access tokens. RFC 6749 §4.1.4 recommends short-lived
/// tokens; refresh tokens extend the session beyond the access TTL. 1 hour
/// mirrors what most OAuth providers ship with.
pub const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

/// Lifetime of refresh tokens — long enough that clients don't pester the
/// user with re-consent on each work session, short enough that a leaked
/// refresh token has bounded blast radius. 30 days mirrors what Google /
/// Microsoft / Auth0 ship by default for first-party scopes.
pub const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 24 * 3600;

/// Marker on a refresh-token JWT — reused by the /token handlers to refuse
/// presenting an access token where a refresh token is expected (or vice
/// versa). The rest of the JWT shape is identical so we can sign with the
/// same per-tenant key.
pub const REFRESH_TOKEN_TYP: &str = "refresh";

/// Lifetime of authorization codes (RFC 6749 §4.1.2 recommends ≤10 minutes).
/// 60s is what most spec-compliant OAuth clients exchange within.
pub const AUTH_CODE_TTL_SECS: i64 = 60;

/// Lifetime of RFC 8628 device codes — long enough for the user to walk to
/// another machine, open the verification URI, and log in; the RFC's example
/// and most providers ship 10–15 minutes.
pub const DEVICE_CODE_TTL_SECS: i64 = 600;

/// Minimum seconds between device-grant token polls (RFC 8628 §3.2
/// `interval`; the RFC default is 5).
pub const DEVICE_POLL_INTERVAL_SECS: i32 = 5;

// ---------------------------------------------------------------------------
// Redirect-URI validation
// ---------------------------------------------------------------------------

/// Validate a redirect URI for an OAuth client.
///
/// Accepts: `https://...` (any host), `http://localhost[:port][/...]`,
/// `http://127.0.0.1[:port][/...]`, and RFC 8252 §7.1 private-use URI schemes
/// (`com.example.app:/cb`). Rejects: other schemes, fragments (RFC 6749
/// §3.1.2), empty strings, and prefix-only matches like `http://localhost.evil`
/// that would let an attacker register a malicious URI passing as loopback.
pub fn validate_redirect_uri(uri: &str) -> bool {
    // A control character is never part of a redirect a browser can be sent
    // to (the URL parser percent-encodes it, so exact matching could never
    // hit), and U+0000 is refused by the column the URI is stored in.
    if uri.is_empty() || uri.contains('#') || uri.chars().any(char::is_control) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    match parsed.scheme() {
        // Any host is fine over TLS, but userinfo is not: `https://
        // trusted.example@evil.test/` reads as the trusted host to a person
        // glancing at a consent screen and resolves to the attacker's.
        "https" => parsed.host_str().is_some() && has_no_userinfo(uri, &parsed),
        "http" => is_loopback(uri, &parsed),
        scheme => is_private_use_scheme(scheme),
    }
}

/// Whether `scheme` is a private-use URI scheme a native app may claim
/// (RFC 8252 §7.1).
///
/// The rule is the RFC's own: the scheme must be a domain name the app's author
/// controls, reversed — so it contains a dot. That single requirement is also
/// what makes this safe to hand to a browser, and the reason there is no
/// denylist here: **every scheme a user-agent interprets itself is a single
/// label** (`javascript`, `data`, `file`, `blob`, `vbscript`, `about`), so none
/// can satisfy it. `private_use_schemes_exclude_browser_interpreted_ones` is
/// the test that keeps that reasoning honest.
///
/// Exact matching still applies to the URI as a whole (RFC 6749 §3.1.2), and
/// PKCE is what protects a grant when another app on the device claims the same
/// scheme — the OS offers no ownership guarantee.
fn is_private_use_scheme(scheme: &str) -> bool {
    // A scheme is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 §3.1);
    // `Url::parse` has already enforced that, so the dot is all that is left to
    // check — plus a non-empty label on each side of it, since `.foo` and `foo.`
    // are not names anyone controls.
    scheme.contains('.')
        && !scheme.starts_with('.')
        && !scheme.ends_with('.')
        && !scheme.contains("..")
}

/// Strict loopback-only variant for native public clients (the `streamscope`
/// CLI): ONLY `http://127.0.0.1[:port][/...]` / `http://localhost[:port][/...]`
/// — never https, never a remote host, so an authorization code can only land
/// on the machine that initiated the login.
pub fn validate_loopback_redirect_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.contains('#') {
        return false;
    }
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    parsed.scheme() == "http" && is_loopback(uri, &parsed)
}

/// Whether the authority carries no userinfo at all.
///
/// **Parsed, never matched by prefix.** A URI's authority is
/// `userinfo@host:port`, and userinfo may contain both `:` and `.` — so
/// `http://127.0.0.1:1@attacker.example/cb` reads as a loopback host followed
/// by a port to any string scan, while the browser connects to
/// `attacker.example`. Anything that decides where a user-agent is sent must
/// ask a URL parser for the host rather than infer it.
///
/// The raw `@` check catches the empty-userinfo form (`https://@evil.test/`),
/// which parses with an empty username and no password: userinfo has no place
/// in a redirect URI at all, and a shape this validator waves through is one
/// some other parser may read differently.
fn has_no_userinfo(uri: &str, parsed: &url::Url) -> bool {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    // Only an `@` inside the authority is userinfo; one in the path or query
    // is ordinary data.
    let after_scheme = &uri[uri.find("//").map(|i| i + 2).unwrap_or(0)..];
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    !after_scheme[..authority_end].contains('@')
}

/// Whether `uri` addresses a loopback host and carries no userinfo.
///
/// The caller has already established the scheme is `http`.
fn is_loopback(uri: &str, parsed: &url::Url) -> bool {
    has_no_userinfo(uri, parsed)
        && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

// ---------------------------------------------------------------------------
// Issuer identity (shared by discovery metadata and authorization responses)
// ---------------------------------------------------------------------------

/// Which first-party authorization server a request belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OauthSurface {
    /// MCP spec-OAuth, mounted at `/api/v1/mcp/oauth/<slug>`.
    Mcp,
    /// CLI provisioning, mounted at `/api/v1/cli/oauth/<slug>`.
    Cli,
}

impl OauthSurface {
    fn mount(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Cli => "cli",
        }
    }
}

/// The `issuer` a surface publishes — the same string its discovery document
/// declares and its authorization responses echo back as RFC 9207 `iss`.
///
/// Derived in one place because a client compares the two **byte for byte**: if
/// the redirect's `iss` differed from the metadata's `issuer` by so much as a
/// trailing slash, a conforming client would read it as the authorization-server
/// mix-up attack the parameter exists to detect and refuse a legitimate login.
/// Both ride the API origin (`resolve_oauth_discovery_origins` owns the
/// split-vhost fallback), never the browser-facing admin origin.
pub async fn surface_issuer(
    db: &crate::db::Db,
    tenant_id: Uuid,
    tenant_slug: &str,
    surface: OauthSurface,
) -> Result<String, ApiError> {
    let origins = crate::tenant_public_url::resolve_oauth_discovery_origins(db, tenant_id).await?;
    Ok(format!(
        "{}/api/v1/{}/oauth/{tenant_slug}",
        origins.api,
        surface.mount()
    ))
}

/// Append an authorization response's parameters to a client's redirect URI,
/// including the RFC 9207 `iss` that identifies which server answered.
///
/// The URI is operator- or client-supplied and may already carry a query, so
/// the separator is chosen rather than assumed.
pub fn authorization_redirect(redirect_uri: &str, params: &[(&str, &str)], issuer: &str) -> String {
    let mut out = String::from(redirect_uri);
    let mut sep = if redirect_uri.contains('?') { '&' } else { '?' };
    for (k, v) in params.iter().chain(std::iter::once(&("iss", issuer))) {
        out.push(sep);
        out.push_str(k);
        out.push('=');
        out.push_str(&urlencode(v));
        sep = '&';
    }
    out
}

/// Append an RFC 6749 §4.1.2.1 error response to a client's redirect URI.
///
/// `state` is echoed only when the client sent one — the RFC makes it REQUIRED
/// *if present in the request*, and inventing an empty one would give a client
/// correlating on `state` something that matches nothing.
pub fn authorization_error_redirect(
    redirect_uri: &str,
    error: OauthErrorCode,
    description: &str,
    state: &str,
    issuer: &str,
) -> String {
    let mut params: Vec<(&str, &str)> = vec![("error", error.as_str())];
    if !description.is_empty() {
        params.push(("error_description", description));
    }
    if !state.is_empty() {
        params.push(("state", state));
    }
    authorization_redirect(redirect_uri, &params, issuer)
}

// ---------------------------------------------------------------------------
// Authorization-endpoint rejections (RFC 6749 §4.1.2.1)
// ---------------------------------------------------------------------------

/// How an `/authorize` validation failure must reach whoever needs to see it.
///
/// RFC 6749 §4.1.2.1 splits authorization errors in two, and the split is a
/// security boundary rather than a presentation preference. When the client
/// identifier or its redirect URI cannot be validated, the server "MUST NOT
/// automatically redirect the user-agent to the invalid redirection URI" —
/// nothing has vouched for that URI yet, so bouncing to it would turn the
/// consent page into an open redirect wearing the tenant's own branding. Every
/// *other* failure has to reach the client at its registered URI, or a
/// conforming client sits waiting on a callback that never comes.
///
/// **Invariant to preserve when adding a check:** a check that runs before the
/// client and its redirect URI are both confirmed can only ever be
/// [`Self::Render`]. Ordering is therefore load-bearing — the validators put
/// the identity checks first and mark the point where redirecting becomes
/// legal. `cli_oauth`'s `an_unvouched_uri_wins_over_a_later_redirectable_error`
/// pins it for the surface whose validator is pure enough to unit-test.
#[derive(Debug)]
pub enum AuthorizeRejection {
    /// Show the error to the resource owner; do not redirect.
    Render(ApiError),
    /// Deliver the error to the client at its already-validated redirect URI.
    Redirect {
        error: OauthErrorCode,
        description: String,
    },
}

impl AuthorizeRejection {
    pub fn redirect(error: OauthErrorCode, description: impl Into<String>) -> Self {
        Self::Redirect { error, description: description.into() }
    }
}

/// Anything reached with `?` before the redirect boundary renders.
///
/// This is deliberately the *safe* direction: a failure whose provenance the
/// conversion cannot see is one that must not be redirected. Sites past the
/// boundary name [`AuthorizeRejection::redirect`] explicitly rather than
/// leaning on this.
impl From<ApiError> for AuthorizeRejection {
    fn from(e: ApiError) -> Self {
        Self::Render(e)
    }
}

// ---------------------------------------------------------------------------
// /token wire shapes (one schema shared by every surface's token endpoint)
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    /// Required when `grant_type=authorization_code`. Ignored for `refresh_token`.
    #[serde(default)]
    pub code: Option<String>,
    /// Required when `grant_type=authorization_code`. Ignored for `refresh_token`.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    pub client_id: String,
    /// Required when `grant_type=authorization_code` (PKCE). Ignored for
    /// `refresh_token` — the refresh-token JWT signature itself is the
    /// proof-of-possession.
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// Required when `grant_type=refresh_token`.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Required when `grant_type=urn:ietf:params:oauth:grant-type:device_code`
    /// (RFC 8628). Ignored for the other grants.
    #[serde(default)]
    pub device_code: Option<String>,
    /// RFC 8707 §2.2: the protected resource this token is being requested for.
    ///
    /// The metadata document advertises `resource_parameter_supported`, so a
    /// conforming client sends it and is entitled to have it honoured — a
    /// value that disagrees with the audience the grant was issued for is
    /// refused rather than quietly ignored, which is the difference between a
    /// token scoped where the client believes it is and one that is not.
    #[serde(default)]
    pub resource: Option<String>,
}

/// The no-store headers RFC 6749 §5.1 requires on a response carrying a
/// credential. A cached one would hand a second client something minted for the
/// first — which is why this covers the device-authorization response too: a
/// `device_code` redeems for tokens with no PKCE to bind it.
pub type CredentialReply<T> = ([(axum::http::HeaderName, &'static str); 2], axum::Json<T>);

pub type TokenReply = CredentialReply<TokenResponse>;

pub fn credential_ok<T>(body: T) -> CredentialReply<T> {
    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        axum::Json(body),
    )
}

pub fn token_ok(body: TokenResponse) -> TokenReply {
    credential_ok(body)
}

#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    /// Issued alongside the access token. Long-lived (30d). Present a
    /// refresh token to `POST /token` with `grant_type=refresh_token` to
    /// rotate to a fresh access + refresh token pair without re-consent.
    pub refresh_token: String,
    /// TTL of the issued refresh token, in seconds.
    pub refresh_token_expires_in: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AuthorizeApproveResponse {
    pub redirect_to: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verify a portal-session JWT supplied via `Authorization: Bearer ...`.
/// Returns the `PortalUser` for the request. Mirrors the inline logic in
/// `portal_auth` middleware but doesn't require the route to be mounted under
/// it (the /authorize consent backends are public-tenant routes, not under
/// `/api/v1/portal`).
///
/// Only an interactive portal session (`scope = "portal"`) may consent — a
/// provision-scoped CLI token must never be able to approve a grant and mint
/// further tokens.
pub async fn require_portal_session(
    headers: &axum::http::HeaderMap,
) -> Result<PortalUser, ApiError> {
    let token = crate::routes::bearer_token(headers)?.to_string();

    let ring =
        keyring().ok_or_else(crate::routes::no_signing_key)?;

    // The `kid` names the key and the tenant; `decode_session_jwt` binds the
    // verified token's `aud` AND `tenant_id` to it, which matters here because
    // `tenant_id` below becomes the `PortalUser` every authorization check on
    // this request runs against.
    let (claims, _tenant_id_from_token) =
        decode_session_jwt::<PortalClaims>(&ring, &token).ok_or_else(|| {
            ApiError::unauthorized("invalid portal token").code(ApiErrorCode::InvalidCredentials)
        })?;
    if claims.role != "user" {
        return Err(ApiError::forbidden("admin token cannot consent on behalf of user"));
    }
    if claims.scope != SCOPE_PORTAL {
        return Err(ApiError::forbidden("an interactive portal session is required to consent")
            .code(ApiErrorCode::ProvisionScopeForbidden));
    }

    let user_tenant: Uuid = claims
        .tenant_id
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid token"))?;
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid token"))?;
    Ok(PortalUser {
        user_id,
        session_iat: Some(claims.iat),
        email: claims.email,
        tenant_id: user_tenant,
        key_id: None,
        key_workspace_id: None,
    })
}

/// The consent-backend gate every `/authorize/*` and `/device/*` endpoint
/// shares: verify the portal session, resolve the URL's tenant slug, and
/// enforce the cross-tenant binding — a portal-session JWT for tenant A must
/// NOT act on tenant B's grants (403 before any DB write).
pub async fn require_tenant_portal_session(
    pool: &crate::db::Db,
    tenant_slug: &str,
    headers: &axum::http::HeaderMap,
) -> Result<(PortalUser, Uuid), ApiError> {
    let portal = require_portal_session(headers).await?;
    let tenant_id = resolve_tenant_id(pool, tenant_slug).await?;
    if portal.tenant_id != tenant_id {
        return Err(ApiError::forbidden(
            "portal session does not belong to this tenant",
        ));
    }

    // The session JWT proves who minted it, not that they are still anybody.
    // Consent is what mints new OAuth grants, so a disabled or deleted user —
    // or one who has since signed out — reaching it would keep issuing
    // themselves credentials for the life of a token they already hold, and an
    // MCP access token or CLI provisioning token outlives the session that
    // authorised it. Checked here rather than in each of the six consent
    // handlers, so a new one cannot forget.
    let mut db = crate::db::tenant::TenantConn::acquire(
        pool,
        crate::db::tenant::TenantId::from_credential(tenant_id),
    )
    .await
    .map_err(|e| {
        tracing::error!("require_tenant_portal_session: tdb: {e}");
        ApiError::internal("failed to verify account")
    })?;
    let row: Option<(bool, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT is_active, sessions_valid_after FROM users WHERE id = $1")
            .bind(portal.user_id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("require_tenant_portal_session: user lookup: {e}");
                ApiError::internal("failed to verify account")
            })?;
    let Some((active, sessions_valid_after)) = row else {
        return Err(ApiError::forbidden("account disabled").code(ApiErrorCode::PermissionDenied));
    };
    if !active {
        return Err(ApiError::forbidden("account disabled").code(ApiErrorCode::PermissionDenied));
    }
    // An `ak-` key carries no `session_iat` and is revoked through its own
    // `revoked_at` column, so the watermark does not apply to it.
    if let Some(iat) = portal.session_iat
        && crate::routes::admin_auth::session_is_revoked(iat, sessions_valid_after)
    {
        return Err(ApiError::forbidden("session signed out").code(ApiErrorCode::PermissionDenied));
    }

    Ok((portal, tenant_id))
}

pub async fn resolve_tenant_id(pool: &crate::db::Db, tenant_slug: &str) -> Result<Uuid, ApiError> {
    // A lookup the database could not answer is a 503, never "no such tenant".
    let Some((id, is_active)) = super::admin_auth::lookup_tenant_slug(pool, tenant_slug).await? else {
        return Err(ApiError::not_found("tenant not found", ApiErrorCode::TenantNotFound));
    };
    if !is_active {
        return Err(ApiError::not_found("tenant inactive", ApiErrorCode::TenantInactive));
    }
    Ok(id)
}

/// The two claims [`decode_refresh_jwt`] checks for itself, on every shape it
/// can deserialize.
///
/// Implementing the trait is what makes both checks unskippable at a call site:
/// the MCP and CLI surfaces sign with the same per-tenant key, so without
/// `surface` nothing in the payload stops one surface's refresh token being
/// spent on the other's `/token` endpoint, and `tenant_id` is what catches a
/// payload disagreeing with the `kid` that selected its key.
pub trait RefreshClaims {
    fn surface(&self) -> &str;
    fn tenant_id(&self) -> &str;
}

/// Encode surface-specific refresh-token claims with the ring's active
/// per-tenant key — the one signing shape both OAuth surfaces' rotating refresh
/// tokens share. The `kid` names the key so a rotated-out secret still verifies.
pub fn encode_refresh_jwt<T: serde::Serialize>(
    claims: &T,
    tenant_id: &str,
    ring: &Keyring,
) -> Result<String, jsonwebtoken::errors::Error> {
    let (header, key) = ring.signing_header(tenant_id);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_secret(&key),
    )
}

/// Decode + verify a refresh-token JWT against the key its `kid` names, and
/// confirm it was minted for `expected_surface`.
///
/// The tenant binding is cryptographic: the key is derived from the tenant in
/// the `kid`, so a token minted for tenant A cannot verify under tenant B's
/// key. `aud` is therefore deliberately not validated here — the two surfaces
/// mean different things by it. An MCP refresh token's `aud` is the RFC 8707
/// resource URI, which its handler checks against the audience stored with the
/// token's own row; a CLI refresh token's is the tenant. A single expected
/// audience would fit neither.
pub fn decode_refresh_jwt<T: serde::de::DeserializeOwned + RefreshClaims>(
    token: &str,
    ring: &Keyring,
    expected_surface: &str,
) -> Result<T, jsonwebtoken::errors::Error> {
    let invalid = || {
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
    };
    let (kid_tenant, key) = session_verification_key(ring, token).ok_or_else(invalid)?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "sub"]);
    validation.set_issuer(&[streamscope_mcp_auth::TOKEN_ISSUER]);
    let data = decode::<T>(token, &DecodingKey::from_secret(&key), &validation)?;
    if data.claims.surface() != expected_surface {
        tracing::debug!(
            presented = %data.claims.surface(),
            expected = %expected_surface,
            "refresh token presented on the wrong OAuth surface"
        );
        return Err(invalid());
    }
    // The `kid` picked the key but is attacker-supplied, so the verified payload
    // must name the same tenant — otherwise a token could be re-pointed at
    // another tenant while still validating under its own key.
    if data.claims.tenant_id() != kid_tenant {
        return Err(invalid());
    }
    Ok(data.claims)
}

/// Handle a refresh token presented after it already rotated — RFC 9700 §4.14.2.
///
/// Rotation makes a refresh token single-use, so a second presentation is only
/// possible when two parties hold the same token: whoever rotated it, and
/// whoever is presenting it now. Refusing this one request is not enough. The
/// party that rotated first keeps a live, still-rotating descendant; the loser's
/// client sees `invalid_grant`, re-authenticates onto a *fresh* chain, and
/// reports itself perfectly healthy. The theft resolves in the attacker's
/// favour and nobody is told.
///
/// Retiring the lineage is what makes the outcome symmetric: both parties lose
/// the credential, and the legitimate one notices, because it has to consent
/// again.
///
/// **An expired token is not reuse.** Both surfaces rotate with an atomic
/// `UPDATE … WHERE revoked_at IS NULL AND expires_at > NOW()`, which declines an
/// expired token and a replayed one identically. Only the still-live,
/// already-revoked case is evidence a copy exists, and this probes for exactly
/// that — so a client that comes back after a month's idle is not treated as an
/// attacker and does not lose a chain it is the sole holder of.
///
/// Returns whether a chain was retired. On a surface the **proxy** verifies
/// (MCP) the revoked jtis reach it in the tenant's config body (the change
/// triggers on `oauth_issued_tokens`); callers holding an open transaction must
/// commit it, or the retirement rolls back and the replay is refused without
/// being acted on.
pub async fn retire_chain_on_reuse(
    conn: &mut Scoped,
    tenant_id: Uuid,
    presented_jti: Uuid,
    surface: &'static str,
) -> Result<bool, ApiError> {
    let row: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        r#"SELECT login_chain, user_id
             FROM oauth_issued_tokens
            WHERE tenant_id = $1
              AND jti = $2
              AND surface = $3
              AND revoked_at IS NOT NULL
              AND expires_at > NOW()"#,
    )
    .bind(tenant_id)
    .bind(presented_jti)
    .bind(surface)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("refresh reuse probe: {e}");
        ApiError::internal("failed to check refresh token")
    })?;

    // Unknown to us, or expired on its own. Nothing to conclude either way.
    let Some((chain, user_id)) = row else {
        return Ok(false);
    };

    let retired = sqlx::query(
        r#"UPDATE oauth_issued_tokens
              SET revoked_at = NOW()
            WHERE tenant_id = $1
              AND login_chain = $2
              AND revoked_at IS NULL"#,
    )
    .bind(tenant_id)
    .bind(chain)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("refresh reuse retire chain: {e}");
        ApiError::internal("failed to revoke refresh token")
    })?
    .rows_affected();

    tracing::warn!(
        surface,
        user_id = ?user_id,
        login_chain = %chain,
        retired,
        "refresh token replayed after rotation — retiring the whole login chain"
    );
    // `retired == 0` when a concurrent revoke got there first. The chain is
    // still gone, and the caller's follow-up (pushing the revoked set to the
    // proxy) is what makes that visible — so this reports the chain's fate, not
    // this statement's row count.
    Ok(true)
}

pub fn generate_authorization_code() -> String {
    use base64::Engine;
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_control_character_anywhere() {
        assert!(validate_redirect_uri("https://example.com/cb"));
        assert!(!validate_redirect_uri("https://example.com/c\u{0}b"));
        assert!(!validate_redirect_uri("https://example.com/cb\u{7}"));
        assert!(!validate_redirect_uri("http://localhost:8080/\u{1f}"));
    }

    #[test]
    fn accepts_https_any_host() {
        assert!(validate_redirect_uri("https://example.com/cb"));
        assert!(validate_redirect_uri("https://app.tenant.example.com/oauth"));
        assert!(validate_redirect_uri("https://example.com:8443/cb"));
    }

    #[test]
    fn accepts_loopback_with_port_path_query_or_eos() {
        assert!(validate_redirect_uri("http://localhost"));
        assert!(validate_redirect_uri("http://localhost/cb"));
        assert!(validate_redirect_uri("http://localhost:8080/cb"));
        assert!(validate_redirect_uri("http://localhost?state=x"));
        assert!(validate_redirect_uri("http://127.0.0.1:3000/cb"));
    }

    #[test]
    fn rejects_subdomain_takeover_via_prefix_match() {
        assert!(!validate_redirect_uri("http://localhost.attacker.com/cb"));
        assert!(!validate_redirect_uri("http://localhostfoo/cb"));
        assert!(!validate_redirect_uri("http://127.0.0.1.evil.com/cb"));
        assert!(!validate_redirect_uri("http://127.0.0.1foo/cb"));
        assert!(!validate_loopback_redirect_uri("http://localhost.attacker.com/cb"));
        assert!(!validate_loopback_redirect_uri("http://127.0.0.1.evil.com/cb"));
    }

    /// Userinfo is where a URI stops meaning what it looks like: everything
    /// before an `@` in the authority is credentials, not the host. The
    /// port-shaped form is the dangerous one — `127.0.0.1:1@evil` scans as
    /// "loopback, then a port" while the browser connects to `evil`. Both
    /// validators decide where a user-agent gets sent, and one of those sends
    /// happens with no click, so neither may accept it.
    #[test]
    fn rejects_userinfo_masquerading_as_a_loopback_host() {
        for uri in [
            "http://127.0.0.1:1@attacker.example/cb",
            "http://localhost:1@attacker.example/cb",
            "http://127.0.0.1@attacker.example/cb",
            "http://localhost@attacker.example/cb",
            "http://127.0.0.1:0@evil.test/cb?x=1",
            "http://user:pass@127.0.0.1:8731/cb",
            // Empty userinfo: parses with no username and no password, so the
            // parser alone waves it through.
            "http://@127.0.0.1:8731/cb",
        ] {
            assert!(!validate_redirect_uri(uri), "validate_redirect_uri accepted {uri}");
            assert!(
                !validate_loopback_redirect_uri(uri),
                "validate_loopback_redirect_uri accepted {uri}"
            );
        }
        // The same trick over TLS: any host is allowed there, but a consent
        // screen reading `trusted.example` must not resolve to `evil.test`.
        assert!(!validate_redirect_uri("https://trusted.example@evil.test/cb"));
        assert!(!validate_redirect_uri("https://@evil.test/cb"));
        // An `@` outside the authority is ordinary data, not userinfo.
        assert!(validate_redirect_uri("https://example.com/cb?email=a@b.com"));
        assert!(validate_loopback_redirect_uri("http://127.0.0.1:8731/cb?u=a@b.com"));
    }

    #[test]
    fn rejects_other_schemes_fragments_and_empty() {
        assert!(!validate_redirect_uri(""));
        assert!(!validate_redirect_uri("ftp://localhost/cb"));
        assert!(!validate_redirect_uri("javascript://localhost"));
        assert!(!validate_redirect_uri("https://example.com/cb#x"));
        assert!(!validate_redirect_uri("http://example.com/cb"));
        assert!(!validate_redirect_uri("file:///etc/passwd"));
        assert!(!validate_redirect_uri("custom://app/cb"));
    }

    #[test]
    fn accepts_rfc8252_private_use_schemes() {
        // Both spellings native SDKs emit: path-only, and authority-style.
        assert!(validate_redirect_uri("com.example.myapp:/oauth2redirect"));
        assert!(validate_redirect_uri("com.example.myapp://callback"));
        assert!(validate_redirect_uri("io.streamscope.cli:/cb?x=1"));
        // A fragment is still refused, whatever the scheme (RFC 6749 §3.1.2).
        assert!(!validate_redirect_uri("com.example.myapp:/cb#x"));
    }

    /// The safety argument for accepting arbitrary custom schemes: the RFC 8252
    /// reverse-DNS requirement excludes every scheme a browser interprets
    /// itself, because all of them are single-label. If the dot rule is ever
    /// relaxed, this test is what fails.
    #[test]
    fn private_use_schemes_exclude_browser_interpreted_ones() {
        for uri in [
            "javascript:alert(1)",
            "javascript://localhost/%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "blob:https://evil.test/uuid",
            "about:blank",
            // Single-label schemes generally, including plausible-looking ones.
            "custom://app/cb",
            "myapp:/cb",
            "ftp://localhost/cb",
        ] {
            assert!(!validate_redirect_uri(uri), "accepted {uri}");
        }
    }

    /// A dot alone is not a name — these are the degenerate shapes that satisfy
    /// "contains a dot" without naming anything an author could control.
    #[test]
    fn degenerate_dotted_schemes_are_refused() {
        // `Url::parse` requires a leading ALPHA, so `.foo:` never parses; the
        // reachable degenerate forms are trailing and doubled dots.
        for uri in ["foo.:/cb", "com..example:/cb"] {
            assert!(!validate_redirect_uri(uri), "accepted {uri}");
        }
    }

    /// The CLI surface stays loopback-only: a private-use scheme would let an
    /// authorization code land in another application on the device.
    #[test]
    fn the_loopback_variant_still_refuses_private_use_schemes() {
        assert!(!validate_loopback_redirect_uri("com.example.myapp:/cb"));
    }

    #[test]
    fn loopback_variant_rejects_https_and_remote_hosts() {
        assert!(validate_loopback_redirect_uri("http://127.0.0.1:8731/callback"));
        assert!(validate_loopback_redirect_uri("http://localhost:8731/callback"));
        assert!(!validate_loopback_redirect_uri("https://example.com/cb"));
        assert!(!validate_loopback_redirect_uri("https://127.0.0.1/cb"));
        assert!(!validate_loopback_redirect_uri("http://example.com/cb"));
        assert!(!validate_loopback_redirect_uri(""));
        assert!(!validate_loopback_redirect_uri("http://127.0.0.1/cb#x"));
    }

    // -----------------------------------------------------------------------
    // urlencode — pinned because the percent-encoding replacement must be
    // byte-for-byte identical. The device-grant `verification_uri_complete` is
    // asserted verbatim in e2e, and any widening of the unreserved set would
    // change already-issued URLs.
    // -----------------------------------------------------------------------

    /// RFC 3986 §2.3 unreserved characters pass through untouched. This is the
    /// exact set a replacement must preserve — `percent_encoding`'s
    /// `NON_ALPHANUMERIC` set escapes `-._~`, so it needs those four removed.
    #[test]
    fn urlencode_passes_through_the_rfc3986_unreserved_set() {
        let unreserved =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
        assert_eq!(urlencode(unreserved), unreserved);
    }

    #[test]
    fn urlencode_escapes_reserved_and_delimiter_characters() {
        assert_eq!(urlencode(" "), "%20");
        assert_eq!(urlencode("/"), "%2F");
        assert_eq!(urlencode("?"), "%3F");
        assert_eq!(urlencode("#"), "%23");
        assert_eq!(urlencode("&"), "%26");
        assert_eq!(urlencode("="), "%3D");
        assert_eq!(urlencode("+"), "%2B");
        assert_eq!(urlencode(":"), "%3A");
        assert_eq!(urlencode("%"), "%25");
    }

    /// Uppercase hex digits (RFC 3986 §2.1 says producers SHOULD uppercase) and
    /// per-byte escaping of multi-byte UTF-8 rather than per-char.
    #[test]
    fn urlencode_uses_uppercase_hex_and_escapes_utf8_per_byte() {
        assert_eq!(urlencode("\u{00e9}"), "%C3%A9");
        assert_eq!(urlencode("\u{20ac}"), "%E2%82%AC");
        assert_eq!(urlencode("caf\u{00e9} bar"), "caf%C3%A9%20bar");
    }

    #[test]
    fn urlencode_handles_empty_and_control_bytes() {
        assert_eq!(urlencode(""), "");
        assert_eq!(urlencode("\n"), "%0A");
        assert_eq!(urlencode("\t"), "%09");
    }

    /// The realistic payload: an error detail spliced into a redirect query.
    #[test]
    fn urlencode_escapes_an_error_detail_safely() {
        assert_eq!(
            urlencode("invalid_grant: code expired?retry=1&x=2"),
            "invalid_grant%3A%20code%20expired%3Fretry%3D1%26x%3D2"
        );
    }

    #[test]
    fn an_error_redirect_carries_the_rfc_parameters() {
        let out = authorization_error_redirect(
            "https://client.example/cb",
            OauthErrorCode::InvalidTarget,
            "virtual server not found",
            "st-42",
            "https://gw.example/api/v1/mcp/oauth/acme",
        );
        assert_eq!(
            out,
            "https://client.example/cb?error=invalid_target\
             &error_description=virtual%20server%20not%20found\
             &state=st-42\
             &iss=https%3A%2F%2Fgw.example%2Fapi%2Fv1%2Fmcp%2Foauth%2Facme"
        );
    }

    /// RFC 6749 §4.1.2.1 makes `state` REQUIRED *if present in the request*.
    /// Emitting an empty one would hand a client correlating on `state`
    /// something that matches none of its outstanding requests.
    #[test]
    fn an_error_redirect_omits_a_state_the_client_never_sent() {
        let out = authorization_error_redirect(
            "https://client.example/cb",
            OauthErrorCode::InvalidRequest,
            "",
            "",
            "https://gw.example/iss",
        );
        assert_eq!(
            out,
            "https://client.example/cb?error=invalid_request&iss=https%3A%2F%2Fgw.example%2Fiss"
        );
    }

    /// A redirect URI may already carry a query — an operator's IdP policy
    /// parameter, a client's own correlation token — so the separator is
    /// chosen, never assumed.
    #[test]
    fn an_error_redirect_appends_to_an_existing_query() {
        let out = authorization_error_redirect(
            "https://client.example/cb?tenant=acme",
            OauthErrorCode::AccessDenied,
            "",
            "st",
            "https://gw.example/iss",
        );
        assert!(
            out.starts_with("https://client.example/cb?tenant=acme&error=access_denied&state=st&"),
            "{out}"
        );
    }

    // ── Refresh-token binding ───────────────────────────────────────────────

    const SECRET: &str = "refresh-binding-test-secret-32-chars";
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";

    /// The two claims `decode_refresh_jwt` enforces, plus the spec claims it
    /// requires. Named in full so a field added to the required set breaks this
    /// fixture rather than silently going unexercised.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestRefreshClaims {
        sub: String,
        iss: String,
        tenant_id: String,
        surface: String,
        iat: i64,
        nbf: i64,
        exp: i64,
    }

    impl RefreshClaims for TestRefreshClaims {
        fn surface(&self) -> &str {
            &self.surface
        }
        fn tenant_id(&self) -> &str {
            &self.tenant_id
        }
    }

    fn refresh_claims(tenant: &str, surface: &str) -> TestRefreshClaims {
        let now = chrono::Utc::now().timestamp();
        TestRefreshClaims {
            sub: uuid::Uuid::nil().to_string(),
            iss: streamscope_mcp_auth::TOKEN_ISSUER.to_string(),
            tenant_id: tenant.to_string(),
            surface: surface.to_string(),
            iat: now,
            nbf: now,
            exp: now + 3600,
        }
    }

    fn ring() -> Keyring {
        Keyring::new(SECRET, None).expect("ring")
    }

    fn decode(token: &str, expected: &str) -> bool {
        decode_refresh_jwt::<TestRefreshClaims>(token, &ring(), expected).is_ok()
    }

    /// The MCP and CLI surfaces sign with the same per-tenant key, so a token
    /// from one is cryptographically valid on the other. Only the `surface`
    /// claim keeps them apart — this isolates that, holding every other claim
    /// identical so nothing else can be doing the rejecting.
    #[test]
    fn a_refresh_token_is_confined_to_the_surface_that_minted_it() {
        let mcp = encode_refresh_jwt(
            &refresh_claims(TENANT, streamscope_mcp_auth::SURFACE_MCP),
            TENANT,
            &ring(),
        )
        .expect("encode");
        let cli = encode_refresh_jwt(
            &refresh_claims(TENANT, streamscope_mcp_auth::SURFACE_CLI),
            TENANT,
            &ring(),
        )
        .expect("encode");

        assert!(decode(&mcp, streamscope_mcp_auth::SURFACE_MCP));
        assert!(decode(&cli, streamscope_mcp_auth::SURFACE_CLI));
        assert!(!decode(&mcp, streamscope_mcp_auth::SURFACE_CLI));
        assert!(!decode(&cli, streamscope_mcp_auth::SURFACE_MCP));
    }

    /// The `kid` selects the key; the payload must agree with it. A token
    /// signed under tenant A's key but claiming tenant B would otherwise be
    /// read as B's while verifying as A's.
    #[test]
    fn a_refresh_token_whose_payload_disagrees_with_its_kid_is_refused() {
        let other = "22222222-2222-4222-8222-222222222222";
        let token = encode_refresh_jwt(
            &refresh_claims(other, streamscope_mcp_auth::SURFACE_MCP),
            TENANT,
            &ring(),
        )
        .expect("encode");
        assert!(!decode(&token, streamscope_mcp_auth::SURFACE_MCP));
    }

    /// The subset shape `/revoke` uses: it names only the claims revocation
    /// needs, so it deserializes happily from a token with no `nbf` at all.
    /// That is what makes it the honest test of `set_required_spec_claims` —
    /// on a shape whose `nbf` field is mandatory, serde does the rejecting and
    /// the requirement could be dropped without any test noticing.
    #[derive(serde::Deserialize)]
    struct SubsetClaims {
        tenant_id: String,
        surface: String,
    }

    impl RefreshClaims for SubsetClaims {
        fn surface(&self) -> &str {
            &self.surface
        }
        fn tenant_id(&self) -> &str {
            &self.tenant_id
        }
    }

    /// `validate_nbf` passes silently on a token that omits the claim, so the
    /// requirement is what makes the not-yet-valid check real rather than
    /// something any minter can opt out of.
    #[test]
    fn a_refresh_token_without_nbf_is_refused() {
        let mut payload = serde_json::to_value(refresh_claims(
            TENANT,
            streamscope_mcp_auth::SURFACE_MCP,
        ))
        .expect("claims");
        payload.as_object_mut().expect("object").remove("nbf");
        let token = encode_refresh_jwt(&payload, TENANT, &ring()).expect("encode");

        // Control: with `nbf` present the same subset shape decodes, so the
        // refusal below is about the missing claim and not the shape.
        let intact = encode_refresh_jwt(
            &refresh_claims(TENANT, streamscope_mcp_auth::SURFACE_MCP),
            TENANT,
            &ring(),
        )
        .expect("encode");
        assert!(decode_refresh_jwt::<SubsetClaims>(
            &intact,
            &ring(),
            streamscope_mcp_auth::SURFACE_MCP
        )
        .is_ok());

        assert!(decode_refresh_jwt::<SubsetClaims>(
            &token,
            &ring(),
            streamscope_mcp_auth::SURFACE_MCP
        )
        .is_err());
    }

    /// A token with no `kid` names no key. Refusing it is what makes rotation
    /// possible at all.
    #[test]
    fn a_refresh_token_without_a_kid_is_refused() {
        let (_, key) = ring().signing_key(TENANT);
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &refresh_claims(TENANT, streamscope_mcp_auth::SURFACE_MCP),
            &jsonwebtoken::EncodingKey::from_secret(&key),
        )
        .expect("encode");
        assert!(!decode(&token, streamscope_mcp_auth::SURFACE_MCP));
    }
}
