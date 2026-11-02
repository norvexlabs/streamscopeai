//! The OpenID Connect login flow, end to end.
//!
//! Three endpoints carry a login: [`begin`] hands back the URL to send the
//! browser to, [`callback`] turns the provider's answer into a session, and
//! [`end_session_url`] builds the logout redirect. The browser tier drives
//! them; it holds cookies and issues redirects, and knows nothing else.
//!
//! **What lives here and what lives in the browser tier.** Every decision that
//! can be got wrong in a way that matters — the PKCE verifier, the nonce, which
//! plane a login authenticates, whether a `return_to` is safe, which algorithms
//! may sign an ID token, whether the address was vouched for — is made in this
//! process. The tier in front owns cookies and redirects only. It cannot own
//! more: the session cookies are path-scoped to the **UI** origin, and on every
//! production deployment that is a different origin from this API, so a
//! `Set-Cookie` from here would land in the wrong jar. Handing the session back
//! through a redirect URL instead was rejected — it would put the token in the
//! referrer, browser history, and every access log along the way.
//!
//! **The caller is authenticated, never believed about identity.**
//! `INTERNAL_SERVICE_SECRET` proves which service is calling. It does not prove
//! who the user is; that comes from a signature this process checks against the
//! provider's published keys.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use openidconnect::core::{CoreAuthPrompt, CoreAuthenticationFlow};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::tenant::{TenantConn, TenantId};
use crate::oidc::flow::{self, FlowState, Plane};
use crate::oidc::http::GuardedOidcHttpClient;
use crate::oidc::identity::{oidc_email_assurance, VerifiedOidcIdentity};
use crate::oidc::provider::{normalize_issuer, pinned_algs, ProviderCache};
use crate::oidc::types::{claim_map, SsClient};
use crate::oidc::OidcError;
use crate::routes::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::AdminState;

/// Discovery documents and signing keys, shared across tenants that use the
/// same provider. Process-global rather than per-tenant: the contents are the
/// provider's public metadata, and a deployment where every tenant federates to
/// one IdP should fetch it once.
static PROVIDERS: LazyLock<ProviderCache> = LazyLock::new(ProviderCache::new);

/// Drop a remembered discovery failure for `issuer`.
///
/// The cache is process-local and per-replica, so this clears it here only; the
/// point is that the admin who just saved a corrected issuer sees the effect on
/// their own next attempt rather than waiting out a TTL. Other replicas expire
/// theirs on their own.
pub async fn forget_provider_failure(issuer: &str) {
    PROVIDERS.forget_failure(issuer).await;
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/begin", post(begin))
        .route("/callback", post(callback))
        .route("/end-session-url", post(end_session_url))
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct BeginRequest {
    /// Tenant whose identity provider should authenticate this login.
    pub tenant_slug: String,
    /// Which plane the user is signing in to: `admin` or `portal`.
    pub plane: String,
    /// Standard OIDC `prompt`. Only `login` and `select_account` are honoured;
    /// anything else is ignored, which yields the default silent SSO.
    pub prompt: Option<String>,
    /// Where to land after a successful portal login. Honoured only when it is
    /// a same-origin path under `/portal/`.
    pub return_to: Option<String>,
    /// The URL the provider will redirect back to. Must be one the provider has
    /// registered for this client; it is pinned into the flow so the token
    /// exchange presents exactly the value the authorization request carried.
    pub redirect_uri: String,
}

#[derive(Serialize, ToSchema)]
pub struct BeginResponse {
    /// Send the browser here.
    pub authorization_url: String,
    /// Opaque. Hand it back to `/callback` unchanged; it cannot be read or
    /// altered outside this process.
    pub flow_token: String,
    /// The plane this login will authenticate, after a `return_to` has been
    /// taken into account. Returned so the caller can route a failure to the
    /// right login page; the authoritative copy is sealed inside `flow_token`.
    pub plane: String,
    pub tenant_slug: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CallbackRequest {
    pub flow_token: String,
    pub code: String,
    pub state: String,
}

#[derive(Serialize, ToSchema)]
pub struct CallbackResponse {
    /// `admin` or `portal`.
    pub plane: String,
    pub tenant_slug: String,
    /// The session JWT for the resolved plane.
    pub token: String,
    /// The provider's ID token, for use as `id_token_hint` at logout.
    pub id_token: String,
    /// Where to send the browser now.
    pub redirect_to: String,
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct EndSessionRequest {
    pub tenant_slug: String,
    /// The ID token from the login being ended, so the provider knows which
    /// session to close.
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EndSessionResponse {
    /// `None` when the provider publishes no `end_session_endpoint`, in which
    /// case the caller clears its own cookies and stops there.
    pub url: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Start a login: build the provider's authorization URL and seal the secrets
/// that the callback will need to finish it.
#[utoipa::path(
    post,
    path = "/api/v1/internal/oidc/begin",
    tag = "Auth Config",
    request_body = BeginRequest,
    responses(
        (status = 200, description = "Authorization URL and sealed flow state", body = BeginResponse),
        (status = 400, description = "Tenant has no identity provider configured", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid service secret", body = ApiErrorResponse),
        (status = 500, description = "The identity provider exchange failed, or the gateway could not complete the login", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer, or the identity provider did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn begin(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<BeginRequest>,
) -> Result<Json<BeginResponse>, ApiError> {
    let cfg = load_tenant_oidc(&state, &req.tenant_slug).await?;
    // Fresh trusted-CA read before any hop to the IdP. The cache is
    // process-local and only the replica that handled an import refreshes
    // it on its own, and an IdP behind a private CA is the common
    // self-hosted shape — without this a login succeeds or fails by which
    // replica the load balancer picked.
    crate::custom_ca::refresh_from_db(&state.db).await;

    // A `return_to` is portal-only by construction, so its presence pins the
    // portal plane whatever the caller asked for. This is what carries the MCP
    // consent delegate, which starts a login with a `/portal/...` return_to and
    // no plane of its own. Resolved once, here, and sealed — the callback reads
    // the decision rather than making it again.
    let return_to = safe_return_to(req.return_to.as_deref());
    let plane = if return_to.is_some() || req.plane == "portal" {
        Plane::Portal
    } else {
        Plane::Admin
    };

    let redirect_uri = RedirectUrl::new(req.redirect_uri.clone())
        .map_err(|e| ApiError::bad_request(format!("redirect_uri is not a valid URL: {e}")))?;

    let provider = PROVIDERS.get(&cfg.issuer).await?;
    let client = build_client(&cfg, &provider.metadata, redirect_uri)?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        // `openid` is added by the client itself, so passing it again would
        // just duplicate it in the URL.
        .add_scopes(
            cfg.scopes
                .iter()
                .filter(|s| *s != "openid")
                .map(|s| Scope::new(s.clone())),
        );

    // Only the two re-authentication prompts a login link may legitimately ask
    // for. `none` is excluded deliberately: it must never be driven from a
    // user-facing link, where it turns a login into a silent probe for whether
    // someone has a session.
    match req.prompt.as_deref() {
        Some("login") => request = request.add_prompt(CoreAuthPrompt::Login),
        Some("select_account") => request = request.add_prompt(CoreAuthPrompt::SelectAccount),
        _ => {}
    }

    // OAuth 2.0 Form Post Response Mode: the provider POSTs the code back. The
    // redirect URI is unchanged — the UI tier's entrypoint relays that POST into
    // the same GET callback, so everything after this line is mode-agnostic.
    if cfg.form_post {
        request = request.add_extra_param("response_mode", "form_post");
    }

    let (auth_url, csrf, nonce) = request.url();

    let sealed = flow::seal(&FlowState::new(
        csrf.secret().clone(),
        verifier.secret().clone(),
        nonce.secret().clone(),
        cfg.tenant_id,
        req.tenant_slug.clone(),
        cfg.issuer.clone(),
        plane,
        req.redirect_uri,
        return_to,
        chrono::Utc::now().timestamp(),
    ))?;

    Ok(Json(BeginResponse {
        authorization_url: auth_url.to_string(),
        flow_token: sealed,
        plane: plane_str(plane).to_string(),
        tenant_slug: req.tenant_slug,
    }))
}

/// Finish a login: exchange the code, verify the ID token, and provision.
#[utoipa::path(
    post,
    path = "/api/v1/internal/oidc/callback",
    tag = "Auth Config",
    request_body = CallbackRequest,
    responses(
        (status = 200, description = "Session established", body = CallbackResponse),
        (status = 400, description = "Login state was refused, or the provider returned no usable identity", body = ApiErrorResponse),
        (status = 401, description = "Missing service secret, or the ID token failed verification", body = ApiErrorResponse),
        (status = 403, description = "The identity is not entitled to this plane", body = ApiErrorResponse),
        (status = 500, description = "The identity provider exchange failed, or the gateway could not complete the login", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer, or the identity provider did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn callback(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<CallbackRequest>,
) -> Result<Json<CallbackResponse>, ApiError> {
    let flow = flow::open(&req.flow_token, chrono::Utc::now().timestamp())?;
    // A replica that cannot sign the session must refuse before the IdP's
    // one-time code is redeemed and before provisioning writes anything.
    crate::routes::admin_auth::keyring().ok_or_else(crate::routes::no_signing_key)?;
    // Fresh trusted-CA read before any hop to the IdP. The cache is
    // process-local and only the replica that handled an import refreshes
    // it on its own, and an IdP behind a private CA is the common
    // self-hosted shape — without this a login succeeds or fails by which
    // replica the load balancer picked.
    crate::custom_ca::refresh_from_db(&state.db).await;

    // The state parameter came back through the browser; the sealed copy did
    // not. Comparing them is what ties this callback to a login this gateway
    // actually started.
    use subtle::ConstantTimeEq;
    if req.state.as_bytes().ct_eq(flow.state.as_bytes()).unwrap_u8() != 1 {
        tracing::warn!(tenant = %flow.tenant_slug, "oidc callback: state mismatch");
        return Err(OidcError::Flow("state mismatch".into()).into());
    }

    let cfg = load_tenant_oidc(&state, &flow.tenant_slug).await?;

    // Verify against the issuer the login STARTED with. A tenant reconfigured
    // mid-flow must not have an in-flight token checked against a provider it
    // did not come from.
    if cfg.issuer.trim_end_matches('/') != flow.issuer.trim_end_matches('/') {
        tracing::warn!(
            tenant = %flow.tenant_slug,
            "oidc callback: the tenant's issuer changed while this login was in flight"
        );
        return Err(OidcError::Flow("the identity provider changed mid-login".into()).into());
    }

    let redirect_uri = RedirectUrl::new(flow.redirect_uri.clone())
        .map_err(|e| OidcError::Flow(format!("stored redirect_uri is invalid: {e}")))?;

    let http = GuardedOidcHttpClient::new();
    let provider = PROVIDERS.get(&cfg.issuer).await?;
    let client = build_client(&cfg, &provider.metadata, redirect_uri)?;

    let token_response = client
        .exchange_code(AuthorizationCode::new(req.code))
        .map_err(|e| OidcError::Exchange(format!("token endpoint unavailable: {e}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.code_verifier.clone()))
        .request_async(&http)
        .await
        // Never `{:?}` a token error: its parse variant carries the raw
        // response body, which can quote back the code and client secret.
        .map_err(|e| match e {
            openidconnect::RequestTokenError::Request(crate::oidc::http::OidcHttpError::Unreachable(e)) => {
                OidcError::Unreachable(e)
            }
            e => OidcError::Exchange(e.to_string()),
        })?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or_else(|| OidcError::Verification("the provider returned no ID token".into()))?;

    // Pin verification to asymmetric algorithms. Left alone, the verifier
    // widens to whatever the provider advertises — which for a confidential
    // client can include HMAC, whose key is the client secret we already hold.
    let verifier = client.id_token_verifier().set_allowed_algs(pinned_algs(
        provider.metadata.id_token_signing_alg_values_supported(),
    )?);
    let nonce = Nonce::new(flow.nonce.clone());

    let claims = match id_token.claims(&verifier, &nonce) {
        Ok(claims) => claims,
        Err(e) if is_key_miss(&e) => {
            // The provider may have rolled its signing key. A cache that waited
            // out its TTL would reject every login until it expired, so
            // re-discover once — bounded by a cooldown, so a stream of tokens we
            // cannot verify does not become load on the provider.
            //
            // When the cooldown suppresses the fetch we still retry against the
            // cache rather than giving up: during a rotation the first login
            // refreshes it and every login racing behind that one would
            // otherwise fail against keys that are already present.
            let refreshed = match PROVIDERS.refresh_after_key_miss(&cfg.issuer).await? {
                Some(refreshed) => refreshed,
                None => PROVIDERS.get(&cfg.issuer).await?,
            };
            let client = build_client(
                &cfg,
                &refreshed.metadata,
                RedirectUrl::new(flow.redirect_uri.clone())
                    .map_err(|e| OidcError::Flow(format!("stored redirect_uri is invalid: {e}")))?,
            )?;
            let verifier = client.id_token_verifier().set_allowed_algs(pinned_algs(
                refreshed.metadata.id_token_signing_alg_values_supported(),
            )?);
            return finish(
                &state,
                &flow,
                &cfg.claims,
                id_token
                    .claims(&verifier, &nonce)
                    .map_err(|e| OidcError::Verification(e.to_string()))?,
                id_token.to_string(),
            )
            .await;
        }
        Err(e) => return Err(OidcError::Verification(e.to_string()).into()),
    };

    finish(&state, &flow, &cfg.claims, claims, id_token.to_string()).await
}

/// Provision the verified identity on the plane the login was started for.
async fn finish(
    state: &Arc<AdminState>,
    flow: &FlowState,
    mapping: &ClaimMapping,
    claims: &crate::oidc::types::SsIdTokenClaims,
    id_token: String,
) -> Result<Json<CallbackResponse>, ApiError> {
    let all_claims = claim_map(claims);
    let email = login_address(&all_claims, &mapping.email_claim)?;
    let groups = all_claims.get(&mapping.groups_claim).cloned().unwrap_or_default();
    let assurance = oidc_email_assurance(
        &mapping.email_claim,
        claims.email_verified(),
        mapping.allow_unverified_email,
    );

    let mut db = TenantConn::acquire(&state.db, TenantId::from_credential(flow.tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("oidc callback TenantConn: {e}");
            ApiError::service_unavailable("internal error")
        })?;

    match flow.plane {
        Plane::Portal => {
            let display_name = claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string());
            let user = crate::oidc::identity::provision_portal_user(
                &mut db,
                flow.tenant_id,
                &email,
                display_name.as_deref(),
                &all_claims,
                assurance,
            )
            .await?;
            let token = crate::routes::portal_auth::generate_portal_jwt(
                &user.id,
                &user.email,
                flow.tenant_id,
            )?;
            tracing::info!(email = %user.email, tenant = %flow.tenant_slug, "oidc login: portal");
            Ok(Json(CallbackResponse {
                plane: "portal".to_string(),
                tenant_slug: flow.tenant_slug.clone(),
                token,
                id_token,
                redirect_to: flow
                    .return_to
                    .clone()
                    .unwrap_or_else(|| format!("/portal/t/{}/home", flow.tenant_slug)),
                email: user.email,
            }))
        }
        Plane::Admin => {
            let identity = VerifiedOidcIdentity {
                email: email.clone(),
                assurance,
                subject: claims.subject().to_string(),
                issuer: flow.issuer.clone(),
                groups,
            };
            let account = crate::oidc::identity::provision_admin(
                &mut db,
                flow.tenant_id,
                &flow.tenant_slug,
                &identity.console(),
            )
            .await?;
            let token = crate::routes::admin_auth::generate_session_jwt(&account, flow.tenant_id)?;
            tracing::info!(email = %account.email, tenant = %flow.tenant_slug, "oidc login: console");
            Ok(Json(CallbackResponse {
                plane: "admin".to_string(),
                tenant_slug: flow.tenant_slug.clone(),
                token,
                id_token,
                redirect_to: format!("/t/{}/", flow.tenant_slug),
                email: account.email,
            }))
        }
    }
}

/// The address a login is keyed on: the single value of the tenant's email claim.
///
/// Email is the sole login identifier, so the value must be exactly one plain
/// address (`routes::address_domain`). A claim that is absent, empty,
/// multi-valued or not a plain address (an AD FS `unique_name` is
/// `DOMAIN\user`; `a@evil.test@corp.test` names two domains) is refused rather
/// than guessed at — picking one of several values would key the account on
/// whichever the IdP listed first.
fn login_address(
    claims: &BTreeMap<String, Vec<String>>,
    email_claim: &str,
) -> Result<String, ApiError> {
    // Judged as it will be stored: an address a directory carries with stray
    // whitespace or capitals is the same address at every other door.
    let normalized = match claims.get(email_claim).map(Vec::as_slice) {
        Some([one]) => Some(crate::routes::normalize_email(one)),
        _ => None,
    };
    match normalized {
        Some(one) if crate::routes::address_domain(&one).is_some() => Ok(one),
        _ => Err(ApiError::bad_request(format!(
            "the identity provider released no single email address in the `{email_claim}` claim — cannot sign in"
        ))
        .code(ApiErrorCode::OidcEmailClaimMissing)),
    }
}

/// Build the provider's RP-initiated logout URL, when it publishes one.
#[utoipa::path(
    post,
    path = "/api/v1/internal/oidc/end-session-url",
    tag = "Auth Config",
    request_body = EndSessionRequest,
    responses(
        (status = 200, description = "Logout URL, or null when the provider publishes none", body = EndSessionResponse),
        (status = 400, description = "Tenant has no identity provider configured", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid service secret", body = ApiErrorResponse),
        (status = 500, description = "The identity provider exchange failed", body = ApiErrorResponse),
        (status = 503, description = "The database did not answer, or the identity provider did not answer", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn end_session_url(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<EndSessionRequest>,
) -> Result<Json<EndSessionResponse>, ApiError> {
    let cfg = load_tenant_oidc(&state, &req.tenant_slug).await?;
    let Some(endpoint) = PROVIDERS.end_session_endpoint(&cfg.issuer).await? else {
        return Ok(Json(EndSessionResponse { url: None }));
    };

    // Appended through the URL's own query API: the endpoint an IdP publishes
    // may already carry parameters (Azure AD B2C names its policy that way),
    // and pasting `?` onto it would corrupt the URL.
    let mut url = openidconnect::url::Url::parse(&endpoint)
        .map_err(|e| OidcError::Discovery(format!("end_session_endpoint is not a URL: {e}")))?;
    {
        let mut q = url.query_pairs_mut();
        // Forward the hint only when THIS tenant's provider is the one that
        // issued it. An ID token is a signed statement about a person, so
        // handing one to the wrong provider publishes that person's identity to
        // a third party — and on a multi-tenant deployment the "wrong provider"
        // is an address another tenant's admin chose. The caller cannot be the
        // judge of this: it holds one token and names one tenant, and nothing
        // about either says they belong together.
        //
        // A mismatch drops the hint rather than failing the request. The user is
        // signing out; the local session is already gone by the time this is
        // called, and refusing would strand them on an error instead of the
        // login page.
        if let Some(hint) = &req.id_token_hint {
            match unverified_issuer(hint) {
                Some(iss) if normalize_issuer(&iss) == normalize_issuer(&cfg.issuer) => {
                    q.append_pair("id_token_hint", hint);
                }
                other => {
                    tracing::warn!(
                        tenant = %req.tenant_slug,
                        token_issuer = ?other,
                        "end-session: dropping an id_token_hint this tenant's provider did not issue"
                    );
                }
            }
        }
        if let Some(post) = &req.post_logout_redirect_uri {
            q.append_pair("post_logout_redirect_uri", post);
        }
        q.append_pair("client_id", &cfg.client_id);
    }

    Ok(Json(EndSessionResponse { url: Some(url.to_string()) }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The `iss` claim of a JWT, read **without** verifying its signature.
///
/// That is sufficient for its one caller, which is deciding whether an
/// `id_token_hint` may be handed back to a particular provider. The question
/// there is which provider minted the token, and a token minted for another
/// tenant names that tenant's issuer whatever its signature says. Verifying
/// would mean fetching a second provider's keys to decide we are not going to
/// use the token — work that answers a question already answered.
///
/// The failure mode this cannot have: accepting a *forged* token. A caller who
/// crafts an unsigned JWT can only name an issuer it already knows, and the
/// only thing that buys is sending its own invention to that issuer. Nothing
/// belonging to anyone else moves.
fn unverified_issuer(jwt: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("iss")?.as_str().map(str::to_string)
}

/// A tenant's identity-provider settings, with the client secret decrypted.
struct TenantOidc {
    tenant_id: Uuid,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    scopes: Vec<String>,
    /// Ask the provider for `response_mode=form_post` rather than the default
    /// query return. The UI tier relays the POST into the same GET callback.
    form_post: bool,
    claims: ClaimMapping,
}

/// Which ID-token claims a login reads, per tenant — see `tenant_auth_configs`.
struct ClaimMapping {
    /// The claim whose values are matched against the console-role groups.
    groups_claim: String,
    /// The claim the account is keyed on.
    email_claim: String,
    /// Accept an address the provider made no statement about.
    allow_unverified_email: bool,
}

async fn load_tenant_oidc(state: &Arc<AdminState>, slug: &str) -> Result<TenantOidc, ApiError> {
    let (tenant_id, is_active) = crate::routes::admin_auth::resolve_tenant_slug(&state.db, slug).await?;
    if !is_active {
        return Err(ApiError::forbidden("tenant suspended").code(ApiErrorCode::TenantInactive));
    }

    let mut db = TenantConn::acquire(&state.db, TenantId::from_row(tenant_id))
        .await
        .map_err(|e| {
            tracing::error!("load_tenant_oidc TenantConn: {e}");
            ApiError::service_unavailable("internal error")
        })?;

    #[derive(sqlx::FromRow)]
    struct OidcRow {
        auth_mode: String,
        oidc_issuer_url: Option<String>,
        oidc_client_id: Option<String>,
        encrypted_oidc_client_secret: Option<String>,
        oidc_scopes: String,
        oidc_groups_claim: String,
        oidc_email_claim: String,
        oidc_allow_unverified_email: bool,
        oidc_response_mode: String,
    }

    let row = sqlx::query_as::<_, OidcRow>(
        "SELECT auth_mode, oidc_issuer_url, oidc_client_id, encrypted_oidc_client_secret, \
                oidc_scopes, oidc_groups_claim, oidc_email_claim, oidc_allow_unverified_email, \
                oidc_response_mode \
         FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("load_tenant_oidc query: {e}");
        // A database that could not be asked says nothing about the
        // credentials (503); any other failure is a fault (500).
        super::db_read_error(&e, "sign-in could not be checked")
    })?;

    let Some(OidcRow {
        auth_mode,
        oidc_issuer_url: Some(issuer),
        oidc_client_id: Some(client_id),
        encrypted_oidc_client_secret: encrypted,
        oidc_scopes: scopes,
        oidc_groups_claim,
        oidc_email_claim,
        oidc_allow_unverified_email,
        oidc_response_mode,
    }) = row
    else {
        return Err(OidcError::NotConfigured.into());
    };
    // Switching a tenant back to internal auth leaves the issuer, client id and
    // secret populated — the settings form patches the mode and the OIDC fields
    // independently, so an operator who turns OIDC off keeps a working
    // registration at their IdP. Without this the login endpoint still honours
    // it, and anyone with an account at that IdP walks into the tenant.
    //
    // Gate it here, in the single loader both planes share, rather than in
    // either handler: a per-handler check is one a new plane can be written
    // without, and the failure is silent — a login that should not be possible
    // simply works.
    if auth_mode != "oidc" {
        tracing::info!(
            tenant_id = %tenant_id,
            auth_mode = %auth_mode,
            "OIDC login refused: tenant is not in OIDC auth mode"
        );
        return Err(OidcError::NotConfigured.into());
    }
    if issuer.is_empty() || client_id.is_empty() {
        return Err(OidcError::NotConfigured.into());
    }

    let client_secret = match encrypted {
        Some(enc) if !enc.is_empty() => {
            let key = streamscope_core::crypto::get_encryption_key()
                .ok_or(OidcError::EncryptionUnavailable)?;
            Some(streamscope_core::crypto::decrypt(&enc, &key).map_err(|e| {
                tracing::error!("decrypt oidc client secret: {e}");
                ApiError::internal("internal error")
            })?)
        }
        _ => None,
    };

    Ok(TenantOidc {
        tenant_id,
        issuer,
        client_id,
        client_secret,
        scopes: scopes.split_whitespace().map(str::to_string).collect(),
        form_post: oidc_response_mode == crate::routes::auth_config::RESPONSE_MODE_FORM_POST,
        claims: ClaimMapping {
            groups_claim: oidc_groups_claim,
            email_claim: oidc_email_claim,
            allow_unverified_email: oidc_allow_unverified_email,
        },
    })
}

fn build_client(
    cfg: &TenantOidc,
    metadata: &openidconnect::ProviderMetadataWithLogout,
    redirect_uri: RedirectUrl,
) -> Result<SsClient, ApiError> {
    // The issuer the client verifies against is the one the discovery document
    // declared, which `discover_async` has already checked equals the one we
    // asked for.
    let _ = IssuerUrl::new(cfg.issuer.clone())
        .map_err(|e| OidcError::Discovery(format!("issuer URL is invalid: {e}")))?;
    Ok(SsClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(cfg.client_id.clone()),
        cfg.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_uri))
}

/// Whether a verification failure is one that re-fetching the provider's keys
/// could plausibly fix — a rolled signing key looks like this from here.
///
/// The crate reports every signature-side failure through one variant, so this
/// also matches a genuinely bad signature and a disallowed algorithm, neither of
/// which a refetch can help. That is deliberately not narrowed: the cost of the
/// false positives is one extra discovery per issuer per cooldown window, and
/// the cost of being too narrow is every login failing until the cache expires.
fn is_key_miss(e: &openidconnect::ClaimsVerificationError) -> bool {
    matches!(e, openidconnect::ClaimsVerificationError::SignatureVerification(_))
}

/// The one rule for a `return_to`: a same-origin path under `/portal/`.
///
/// Anything else — an absolute URL, a protocol-relative `//host` that would
/// leave the origin, a path outside the portal, or one with no leading slash —
/// is dropped rather than corrected. The browser tier applies the same rule to
/// its own credentials-login form; keep the two in step.
fn safe_return_to(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    if !raw.starts_with('/') || raw.starts_with("//") || !raw.starts_with("/portal/") {
        return None;
    }
    Some(raw.to_string())
}

fn plane_str(plane: Plane) -> &'static str {
    match plane {
        Plane::Admin => "admin",
        Plane::Portal => "portal",
    }
}

/// Refuse anything that cannot prove it is the browser tier, before the audit
/// layer buffers a body or writes a row.
///
/// The layer order matters more than the check. This surface sits on the same
/// port the public vhost reverse-proxies wholesale, so anyone on the internet
/// can POST to it; were the check left to the handlers, each of those requests
/// would travel *through* `security_audit_mw` and leave a row, turning an
/// unauthenticated loop into an audit-table flood. Refusing out here means the
/// rows that do get written are all real login attempts — which is what makes a
/// run of them worth looking at.
pub async fn internal_service_secret_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, ApiError> {
    require_internal_service_secret(req.headers())?;
    Ok(next.run(req).await)
}

/// Prove the caller is an internal service.
///
/// This is caller authentication and nothing more. It says the request came
/// from the browser tier; it says nothing about who is signing in, which is
/// settled by the provider's signature.
pub(crate) fn require_internal_service_secret(headers: &axum::http::HeaderMap) -> Result<(), ApiError> {
    let token = crate::routes::bearer_token(headers)?;

    let secret = std::env::var("INTERNAL_SERVICE_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return Err(ApiError::server_misconfigured("service secret not configured"));
    }
    // Constant-time: `ct_eq` on differing lengths returns 0 without
    // short-circuiting, so no length is leaked either.
    use subtle::ConstantTimeEq;
    if token.as_bytes().ct_eq(secret.as_bytes()).unwrap_u8() != 1 {
        return Err(crate::routes::rejected_credential());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn the_login_address_is_read_from_the_configured_claim() {
        let c = claims(&[("email", &["a@x.test"]), ("upn", &["ada@corp.test"])]);
        assert_eq!(login_address(&c, "email").unwrap(), "a@x.test");
        assert_eq!(login_address(&c, "upn").unwrap(), "ada@corp.test");
    }

    #[test]
    fn the_login_address_is_normalized_before_it_is_judged() {
        let c = claims(&[("upn", &[" Ada.Lovelace@Corp.TEST "])]);
        assert_eq!(login_address(&c, "upn").unwrap(), "ada.lovelace@corp.test");
    }

    /// Anything but exactly one address-shaped value is refused, never guessed.
    #[test]
    fn a_missing_multiple_or_non_address_value_is_refused() {
        let c = claims(&[
            ("two", &["a@x.test", "b@x.test"]),
            ("unique_name", &["CONTOSO\\ada"]),
            ("none", &[]),
            ("two_ats", &["mallory@evil.test@corp.test"]),
            ("spaced", &["ada @corp.test"]),
            ("no_local", &["@corp.test"]),
            ("no_domain", &["ada@"]),
            ("nul_local", &["ada\0@corp.test"]),
            ("nul_domain", &["ada@corp.test\0"]),
        ]);
        for name in ["absent", "two", "unique_name", "none", "two_ats", "spaced", "no_local", "no_domain", "nul_local", "nul_domain"] {
            assert!(login_address(&c, name).is_err(), "`{name}` must be refused");
        }
    }

    #[test]
    fn a_portal_path_is_kept() {
        assert_eq!(
            safe_return_to(Some("/portal/t/acme/mcp/authorize?x=1")),
            Some("/portal/t/acme/mcp/authorize?x=1".to_string())
        );
    }

    /// The cases that would take a user off the deployment, or onto a console
    /// page a portal login has no business landing on.
    #[test]
    fn anything_that_could_leave_the_portal_is_dropped() {
        for raw in [
            "//evil.test/portal/x",         // protocol-relative — leaves the origin
            "https://evil.test/portal/x",   // absolute
            "/t/acme/",                     // console, not portal
            "portal/t/acme",                // no leading slash — resolves relative
            "/portalish/x",                 // prefix lookalike
            "",
        ] {
            assert_eq!(safe_return_to(Some(raw)), None, "{raw} must be refused");
        }
        assert_eq!(safe_return_to(None), None);
    }
}
