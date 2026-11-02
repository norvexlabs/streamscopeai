//! Per-user OAuth bearer resolution + refresh single-flight.
//!
//! `/mcp/<slug>` requests authenticated by an `sk-*` key need a per-(user,
//! upstream) bearer token to forward to `auth_mode = per_user_oauth`
//! upstreams. The handler:
//!
//!   1. looks up the user's credential (from snapshot or fresh-rotation
//!      overlay),
//!   2. if `expires_at` is in the past (or close enough), acquires the
//!      per-(user, upstream) refresh lock and calls the upstream IdP token
//!      endpoint with the stored `refresh_token`,
//!   3. on success, persists the rotated credential to the edge outbox for
//!      admin-api and updates the local overlay so subsequent requests skip
//!      the refresh,
//!   4. on `invalid_grant` (refresh token revoked), surfaces
//!      [`UpstreamError::UserCredentialExpired`] — the agent forwards the
//!      JSON-RPC `-32502` to the user, who reconnects via the portal.
//!
//! Cross-instance correctness is best-effort: two proxy instances racing on
//! the same `(user, upstream)` may each issue a refresh, double-spending one
//! refresh token. That rare token burn is accepted rather than coordinated —
//! the single-flight lock is in-process and ensures only the first request in
//! a single proxy waits on the IdP for any given burst.
//!
//! Tokens are written back to admin-api through the edge outbox as a
//! credential-rotation record; admin-api UPDATEs the DB row, and the other
//! instances pick up the new credential in the tenant's next config body.

use std::debug_assert_matches;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use oauth2::{RefreshToken, Scope};
use streamscope_core::config::mcp::{McpAuthMode, McpUpstreamServer, McpUserCredential};
use streamscope_core::mcp::oauth_client;
use streamscope_core::mcp::oauth_http::GuardedOauthHttpClient;
use uuid::Uuid;

use super::upstream::UpstreamError;

/// Resolve the expiry safety margin from settings (default 30s). Tokens
/// count as expired this many seconds before their nominal `expires_at`.
/// Avoids a request that races the IdP's clock and arrives just-too-late.
fn expiry_safety_margin_secs() -> i64 {
    crate::settings::proxy_settings().mcp_oauth_expiry_safety_margin_secs
}

type OverlayMap = DashMap<(Uuid, Uuid, Uuid), McpUserCredential>;
/// Refresh-lock key. `tenant_id` participates for defense-in-depth: a `user_id`
/// is already tenant-bound at admin-api, so a cross-tenant collision requires
/// a UUID collision (impossible) — but every per-process map keyed on
/// tenant-derived data must include `tenant_id` explicitly.
type RefreshLockMap = DashMap<(Uuid, Uuid, Uuid), Arc<tokio::sync::Mutex<()>>>;

/// Per-process state for per-user OAuth — the single-flight refresh lock
/// map plus a write-through overlay that bridges the gap between a
/// successful refresh and the admin-api snapshot push that carries the new
/// credential.
#[derive(Default, Clone)]
pub struct OauthState {
    /// `(tenant_id, user_id, upstream_id) → most recently refreshed credential`.
    /// Populated on refresh; consulted before the snapshot. Snapshot wins
    /// when its `expires_at` is the same or newer (rotation has propagated
    /// through the DB).
    pub overlay: Arc<OverlayMap>,
    /// `(user_id, upstream_id) → mutex` used to serialize concurrent refresh
    /// attempts within a single proxy. Tokio mutex (async-aware).
    pub refresh_locks: Arc<RefreshLockMap>,
}

impl OauthState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Lookup a user's credential — overlay wins until the snapshot has caught up.
    pub fn lookup(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
        snapshot: Option<&McpUserCredential>,
    ) -> Option<McpUserCredential> {
        let key = (tenant_id, user_id, upstream_id);
        if let Some(overlay) = self.overlay.get(&key) {
            let overlay_cred = overlay.value().clone();
            // Snapshot beats overlay if it's at least as fresh. Comparing
            // `expires_at` is the simplest correct signal — a successful
            // refresh always advances expires_at.
            if let Some(snap) = snapshot
                && snap.expires_at >= overlay_cred.expires_at
            {
                drop(overlay);
                self.overlay.remove(&key);
                return Some(snap.clone());
            }
            return Some(overlay_cred);
        }
        snapshot.cloned()
    }

    /// Insert or replace a refreshed credential into the overlay.
    pub fn record_rotation(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
        cred: McpUserCredential,
    ) {
        self.overlay.insert((tenant_id, user_id, upstream_id), cred);
    }

    /// Acquire the single-flight refresh lock for `(tenant, user, upstream)`.
    /// Other concurrent requests for the same triple wait on the same mutex.
    pub fn refresh_lock_for(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
    ) -> Arc<tokio::sync::Mutex<()>> {
        self.refresh_locks
            .entry((tenant_id, user_id, upstream_id))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

/// True if the credential's `expires_at` is null / in the past / within the
/// safety margin. A null `expires_at` is treated as "not expirable" — that
/// matches IdPs that issue long-lived bearers without rotation.
pub fn is_expired(cred: &McpUserCredential) -> bool {
    match cred.expires_at {
        None => false,
        Some(at) => at - chrono::Duration::seconds(expiry_safety_margin_secs()) <= Utc::now(),
    }
}

/// Resolve a bearer token for a per-user OAuth upstream call.
///
/// Returns `Ok(token)` if the user has a valid credential (refreshing if
/// needed); errors map to a JSON-RPC code at the call site.
///
/// The single-flight semantics: the first concurrent caller for `(user,
/// upstream)` enters the lock, refreshes, writes back; later callers wait on
/// the lock and re-check the overlay before triggering another refresh.
pub async fn resolve_user_bearer(
    state: &Arc<OauthState>,
    tenant_id: Uuid,
    user_id: Uuid,
    upstream: &McpUpstreamServer,
    snapshot_cred: Option<&McpUserCredential>,
    rotation_sink: Option<&Arc<dyn RotationSink>>,
) -> Result<String, UpstreamError> {
    debug_assert_matches!(upstream.auth_mode, McpAuthMode::PerUserOauth);

    let cred = state
        .lookup(tenant_id, user_id, upstream.id, snapshot_cred)
        .ok_or(UpstreamError::UserCredentialMissing)?;

    if !is_expired(&cred) {
        return decrypt_access_token(&cred);
    }

    // Single-flight: serialize concurrent refreshes for the same triple.
    let lock = state.refresh_lock_for(tenant_id, user_id, upstream.id);
    let _guard = lock.lock().await;

    // Re-check after acquiring the lock — another task may have refreshed
    // already and recorded the rotation in the overlay.
    let cred = state
        .lookup(tenant_id, user_id, upstream.id, snapshot_cred)
        .ok_or(UpstreamError::UserCredentialMissing)?;
    if !is_expired(&cred) {
        return decrypt_access_token(&cred);
    }

    // Refresh.
    let refresh_token = decrypt_refresh_token(&cred)?;
    let refreshed = call_token_endpoint(upstream, &refresh_token).await?;

    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or(UpstreamError::CredentialUnavailable)?;
    let encrypted_access = streamscope_core::crypto::encrypt(&refreshed.access_token, &key)
        .map_err(UpstreamError::UserOauthRefreshFailed)?;
    let encrypted_refresh = match refreshed.refresh_token.as_deref() {
        Some(rt) => Some(
            streamscope_core::crypto::encrypt(rt, &key)
                .map_err(UpstreamError::UserOauthRefreshFailed)?,
        ),
        None => cred.encrypted_refresh_token.clone(),
    };
    let new_cred = McpUserCredential {
        tenant_id,
        user_id,
        upstream_server_id: upstream.id,
        encrypted_access_token: encrypted_access,
        encrypted_refresh_token: encrypted_refresh,
        expires_at: refreshed.expires_at,
        scope: refreshed.scope.clone().or(cred.scope.clone()),
    };

    // Local overlay first — guarantees the next request in this process sees
    // the new credential immediately, before the snapshot push lands.
    state.record_rotation(tenant_id, user_id, upstream.id, new_cred.clone());

    // Write-back to admin-api through the edge outbox. Fire-and-forget — the
    // overlay covers the gap until the tenant's next config body. If the sink is missing
    // (test scaffolding), refresh still works locally; admin-api just keeps
    // the older row, and the next process restart loses the new tokens.
    if let Some(sink) = rotation_sink {
        sink.persist_rotation(new_cred).await;
    }

    Ok(refreshed.access_token)
}

/// Decrypt a credential's stored access token. Errors collapse to
/// `UserCredentialExpired` so the agent prompts the user to reconnect.
fn decrypt_access_token(cred: &McpUserCredential) -> Result<String, UpstreamError> {
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or(UpstreamError::CredentialUnavailable)?;
    streamscope_core::crypto::decrypt(&cred.encrypted_access_token, &key).map_err(|e| {
        tracing::error!(user = %cred.user_id, upstream = %cred.upstream_server_id,
            "decrypt access_token failed: {e}");
        UpstreamError::UserCredentialExpired
    })
}

fn decrypt_refresh_token(cred: &McpUserCredential) -> Result<String, UpstreamError> {
    let token = cred
        .encrypted_refresh_token
        .as_deref()
        .ok_or(UpstreamError::UserCredentialExpired)?;
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or(UpstreamError::CredentialUnavailable)?;
    streamscope_core::crypto::decrypt(token, &key).map_err(|e| {
        tracing::error!(user = %cred.user_id, upstream = %cred.upstream_server_id,
            "decrypt refresh_token failed: {e}");
        UpstreamError::UserCredentialExpired
    })
}

/// Trait for persisting a rotated credential back to admin-api. The proxy's
/// outbox sink implements it (`edge_link::OutboxSink`). Tests inject a no-op
/// or assertion sink.
pub trait RotationSink: Send + Sync {
    fn persist_rotation<'a>(
        &'a self,
        cred: McpUserCredential,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Output of a successful token-endpoint call.
pub struct RefreshedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
}

async fn call_token_endpoint(
    upstream: &McpUpstreamServer,
    refresh_token: &str,
) -> Result<RefreshedTokens, UpstreamError> {
    let token_url = upstream
        .oauth_token_url
        .as_deref()
        .ok_or(UpstreamError::OauthClientNotConfigured("oauth_token_url"))?;
    let client_id = upstream
        .oauth_client_id
        .as_deref()
        .ok_or(UpstreamError::OauthClientNotConfigured("oauth_client_id"))?;

    // Defense-in-depth SSRF guard — admin write-time validation rejects
    // RFC 1918 / loopback / IMDS literals on `oauth_token_url`, but the
    // refresh-token grant carries the user's refresh_token + decrypted
    // client_secret. If the URL somehow escapes the write-time check
    // (legacy row, future API), refuse rather than ship credentials. The
    // transport re-checks; doing it here keeps the refusal attributable
    // instead of surfacing as a generic transport failure.
    let egress = super::upstream::MCP_EGRESS;
    if let Err(e) =
        streamscope_mcp_auth::ssrf::check_url_for(token_url, egress)
    {
        return Err(UpstreamError::SsrfRefused(e.to_string()));
    }

    // Retained past the call so any echo of the secret can be stripped out of
    // an error body before it reaches a log line or the agent.
    let client_secret = match upstream.encrypted_oauth_client_secret.as_deref() {
        Some(secret_ct) => {
            let key = streamscope_core::crypto::get_encryption_key()
                .ok_or(UpstreamError::CredentialUnavailable)?;
            Some(
                streamscope_core::crypto::decrypt(secret_ct, &key).map_err(|e| {
                    tracing::error!(upstream = %upstream.id, "decrypt oauth_client_secret failed: {e}");
                    UpstreamError::CredentialUnavailable
                })?,
            )
        }
        None => None,
    };

    let client = oauth_client::upstream_token_client(client_id, client_secret.as_deref(), token_url)
        .map_err(UpstreamError::UserOauthRefreshFailed)?;

    // The guarded client pins the resolved IP at DNS time and re-vets redirect
    // hops, so the refresh_token + client_secret in the form body can't be
    // delivered to an internal target via DNS-rebinding or a 3xx. It is the
    // process-cached MCP egress client, so connections stay pooled; the
    // per-upstream deadline rides the request rather than the client.
    let http = GuardedOauthHttpClient::new(
        super::upstream::guarded_upstream_client(egress),
        egress,
        Some(Duration::from_millis(upstream.request_timeout_ms.max(1) as u64)),
    );

    let token = RefreshToken::new(refresh_token.to_string());
    let mut request = client.exchange_refresh_token(&token);
    if !upstream.oauth_default_scopes.is_empty() {
        request = request.add_scopes(
            upstream
                .oauth_default_scopes
                .iter()
                .map(|s| Scope::new(s.clone())),
        );
    }

    // Anything an error message could echo — the IdP sees all of these.
    let secrets = [refresh_token, client_secret.as_deref().unwrap_or("")];

    // The refresh token has been revoked — surface as Expired so the agent
    // prompts the user to reconnect. Retrying cannot help.
    let to_upstream_error = |e| match e {
        oauth_client::UpstreamTokenError::InvalidGrant => UpstreamError::UserCredentialExpired,
        oauth_client::UpstreamTokenError::Failed(msg) => UpstreamError::UserOauthRefreshFailed(msg),
    };

    let response = request
        .request_async(&http)
        .await
        .map_err(|e| to_upstream_error(oauth_client::classify_token_error(e, &secrets)))?;

    let tokens = oauth_client::into_tokens(response, &secrets).map_err(to_upstream_error)?;
    Ok(RefreshedTokens {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.expires_at,
        scope: tokens.scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(expires_at: Option<DateTime<Utc>>) -> McpUserCredential {
        McpUserCredential {
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            encrypted_access_token: "stub".into(),
            encrypted_refresh_token: Some("stub".into()),
            expires_at,
            scope: None,
        }
    }

    #[test]
    fn null_expires_at_is_not_expired() {
        assert!(!is_expired(&cred(None)));
    }

    #[test]
    fn future_expires_at_is_not_expired() {
        let future = Utc::now() + chrono::Duration::seconds(120);
        assert!(!is_expired(&cred(Some(future))));
    }

    #[test]
    fn within_safety_margin_is_expired() {
        let close = Utc::now() + chrono::Duration::seconds(5); // < 30s margin
        assert!(is_expired(&cred(Some(close))));
    }

    #[test]
    fn past_expires_at_is_expired() {
        let past = Utc::now() - chrono::Duration::seconds(60);
        assert!(is_expired(&cred(Some(past))));
    }

    #[test]
    fn overlay_takes_precedence_when_no_snapshot() {
        let state = OauthState::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        let mut c = cred(None);
        c.tenant_id = tenant;
        c.user_id = user;
        c.upstream_server_id = upstream;
        state.record_rotation(tenant, user, upstream, c.clone());
        let got = state.lookup(tenant, user, upstream, None).unwrap();
        assert_eq!(got.encrypted_access_token, c.encrypted_access_token);
    }

    #[test]
    fn snapshot_with_newer_expires_at_replaces_overlay() {
        let state = OauthState::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        let old_overlay = {
            let mut c = cred(Some(Utc::now() + chrono::Duration::seconds(60)));
            c.tenant_id = tenant;
            c.user_id = user;
            c.upstream_server_id = upstream;
            c.encrypted_access_token = "overlay".into();
            c
        };
        let newer_snap = {
            let mut c = cred(Some(Utc::now() + chrono::Duration::seconds(3600)));
            c.tenant_id = tenant;
            c.user_id = user;
            c.upstream_server_id = upstream;
            c.encrypted_access_token = "snapshot".into();
            c
        };
        state.record_rotation(tenant, user, upstream, old_overlay);
        let got = state
            .lookup(tenant, user, upstream, Some(&newer_snap))
            .unwrap();
        assert_eq!(got.encrypted_access_token, "snapshot");
        // Overlay was cleared.
        assert!(!state.overlay.contains_key(&(tenant, user, upstream)));
    }

    #[test]
    fn refresh_lock_returns_same_arc_for_same_triple() {
        let state = OauthState::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        let l1 = state.refresh_lock_for(tenant, user, upstream);
        let l2 = state.refresh_lock_for(tenant, user, upstream);
        assert!(Arc::ptr_eq(&l1, &l2));
    }

    #[test]
    fn refresh_lock_per_tenant_isolation() {
        // Two tenants requesting a refresh on the same `(user, upstream)`
        // UUIDs (impossible in practice — UUIDs don't collide, and `user_id`
        // is tenant-bound at admin-api — but the lock map's key includes
        // `tenant_id` for defense-in-depth).
        // Different tenants must NOT share a refresh lock.
        let state = OauthState::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        let l1 = state.refresh_lock_for(t1, user, upstream);
        let l2 = state.refresh_lock_for(t2, user, upstream);
        assert!(!Arc::ptr_eq(&l1, &l2));
    }
}
