//! Authentication layer — resolves API keys to [`UserContext`].
//!
//! Two key formats, both bound to a `(user, workspace)` pair:
//!   * `sk-*` — proxy-issued keys (`forward_auth = false`). The proxy holds the
//!     upstream credential. Reachable on `/v1/*` (LLM) and `/mcp/<slug>` (MCP);
//!     the route grammar implies the protocol.
//!   * `vk-*` — BYOK forward-auth keys (`forward_auth = true`). The client
//!     supplies its own upstream credential in the auth header, forwarded
//!     verbatim. Reachable on `/fwd/{key}/...`.
//!
//! A single key spans both LLM and MCP — there is no per-protocol key family.
//! Which provider or MCP virtual server a request may reach is decided at
//! request time by the key's **workspace allowlist**
//! ([`UserContext::allowed_provider_ids`] / [`UserContext::allowed_virtual_server_ids`]),
//! baked into the key's context by the config snapshot.
//!
//! Keys are never stored in plaintext — only SHA-256 hashes live in the database
//! and in the configuration. A key is looked up in the tenant registry config
//! sync publishes ([`crate::config::Registry::key`]), which returns it with its
//! tenant's configuration of the same version. The `forward_auth` flag keeps
//! `sk-*` keys on `/v1/*` + `/mcp/<slug>` and `vk-*` keys on `/fwd/{key}/...`.

pub mod member_limits;
pub mod virtual_key;

use axum::http::HeaderMap;

use crate::config::model_map::ModelMap;
use crate::error::{AppError, AuthError};

/// User context — a key's identity, routes and limits, as config sync delivers it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserContext {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    /// The workspace this key is bound to. Every request is gated by this
    /// workspace's allowlist + budget ceiling.
    pub workspace_id: uuid::Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// The decrypted real upstream API key.
    #[serde(skip)]
    pub real_api_key: String,
    /// The key's routes. Keys whose workspace grants the same routes share one
    /// map: config sync interns it per tenant, so a tenant's memory grows with
    /// its distinct route sets, not with its keys.
    pub model_map: std::sync::Arc<ModelMap>,
    /// The **workspace** rate-limit bucket — the workspace's configured cap,
    /// shared across all its members (enforced keyed by `workspace_id`).
    /// A workspace with no configured cap row (the Default included) carries no
    /// ceiling, so this is [`RateLimitConfig::unlimited`] and every check short-circuits.
    pub rate_limit: RateLimitConfig,
    /// The MEMBER bucket: this user's limit inside this workspace — the
    /// workspace's default member limit, replaced per metric by the member's
    /// exception ([`member_limits::resolve_member_limit`]). Baked only when it
    /// limits something. Enforced keyed by the membership
    /// ([`member_limits::member_scope_id`]), so use in one workspace never
    /// counts in another; every bucket applies and the tightest wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_rate_override: Option<RateLimitConfig>,
    /// Per-key budget bucket, baked only when this key carries an explicit
    /// `daily_budget` / `monthly_budget`. Enforced as a third bucket
    /// keyed by `key_id` — budget only (no RPM/TPM); the stricter of the
    /// workspace, user, and key buckets wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_budget: Option<RateLimitConfig>,
    /// The tenant's org-total budget ceiling, baked on every key of the tenant
    /// when an operator has set one. Budget only (no RPM/TPM), enforced keyed
    /// by `tenant_id`, and `None` when the tenant is uncapped — which is the
    /// default, so no `usage_counters` row exists for an uncapped tenant.
    pub tenant_budget: Option<RateLimitConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Downstream providers this workspace allows — the workspace's explicit
    /// allowlist rows (empty if the operator has granted none).
    #[serde(default)]
    pub allowed_provider_ids: Vec<uuid::Uuid>,
    /// MCP virtual servers this workspace allows — the workspace's explicit
    /// allowlist rows (empty if the operator has granted none).
    #[serde(default)]
    pub allowed_virtual_server_ids: Vec<uuid::Uuid>,
    /// A2A upstream agents this workspace allows — the workspace's explicit
    /// allowlist rows (empty if the operator has granted none).
    #[serde(default)]
    pub allowed_a2a_agent_ids: Vec<uuid::Uuid>,
    /// The OAuth scope granted to the MCP bearer this context came from, as the
    /// raw space-separated claim.
    ///
    /// `None` for every credential that is not a spec-OAuth token — `sk-`/`vk-`
    /// keys carry no scope and are bounded by their workspace grants instead.
    /// The distinction matters and must not be collapsed into an empty string:
    /// `None` means "not scope-limited", while `Some("")` would be a token that
    /// may call nothing. Reading it as a plain string would make the second
    /// case silently behave like the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_scope: Option<String>,
    /// True for forward-auth keys (`vk-*`) — the client supplies the bearer in
    /// the `Authorization` / `x-api-key` / `x-goog-api-key` header which is
    /// forwarded verbatim to the upstream. False for proxy-issued credential
    /// keys (`sk-*`). The route layer keeps `vk-*` on `/fwd/{key}/...` and
    /// `sk-*` off it.
    #[serde(default)]
    pub forward_auth: bool,
    /// The set of BYOK pass-through targets this key may reach. Empty = none
    /// (a `sk-*` key, or a forward key with no granted BYOK downstream, so every
    /// `model_map` miss is refused). One entry = a single-provider forward key.
    /// Multiple entries = a multi-provider inline key: on a `model_map` miss the
    /// request is forwarded verbatim to the entry selected by (protocol, origin
    /// host) with the client's own forwarded credential (each downstream is
    /// keyless). The key row is kept when a grant is revoked, so re-granting
    /// restores the entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byok_passthrough: Vec<crate::config::model_map::ByokPassthrough>,
    /// True for a key minted in the tenant's **Inline AI** workspace
    /// (`role = 'inline'`) — the credential `POST /v1/analyze` accepts.
    /// The inline key is a forward (BYOK) key: it also passes through to its
    /// workspace's granted provider endpoints on `/fwd/{key}/…`, funded by the
    /// client's own credential. This flag scopes it to the analyze surface.
    #[serde(default)]
    pub inline_ai: bool,
    /// The QoS class this key names, if any. `None` = run as the key's
    /// workspace. Resolved through
    /// [`crate::config::qos::QosTable::effective_class`], which clamps it to the
    /// workspace's class unless `qos_class_elevated` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos_class_id: Option<uuid::Uuid>,
    /// A tenant admin put this key ABOVE its workspace's class deliberately. It
    /// is the only thing that lets a key outrank its workspace, so demoting a
    /// workspace clamps every key that was not elevated.
    #[serde(default)]
    pub qos_class_elevated: bool,
}

impl UserContext {
    /// Whether this key's workspace may reach MCP virtual server `vs_id` — its
    /// explicit allowlist rows. Every key (the agent included) gates here; there
    /// is no wildcard.
    pub fn allows_virtual_server(&self, vs_id: uuid::Uuid) -> bool {
        self.allowed_virtual_server_ids.contains(&vs_id)
    }

    /// Whether this key's workspace may reach A2A upstream agent `agent_id` —
    /// same explicit-allowlist contract as [`Self::allows_virtual_server`].
    pub fn allows_a2a_agent(&self, agent_id: uuid::Uuid) -> bool {
        self.allowed_a2a_agent_ids.contains(&agent_id)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute.
    pub requests_per_minute: u32,
    /// Tokens per minute.
    pub tokens_per_minute: u32,
    /// Daily budget in the tenant's accounting currency (0 = unlimited).
    pub daily_budget: f64,
    /// Monthly budget in the tenant's accounting currency (0 = unlimited).
    pub monthly_budget: f64,
    /// Alert-only budget mode: when true, an over-cap budget does NOT block the
    /// request — the counter still accrues and the crossing still fires a
    /// notification, but enforcement is suppressed (warn-without-cutting-off).
    /// Only affects the budget check; RPM/TPM enforcement is unaffected.
    #[serde(default)]
    pub budget_alert_only: bool,
    /// Whether this user is exempt from rate limiting.
    pub exempt: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            tokens_per_minute: 100_000,
            daily_budget: 0.0,
            monthly_budget: 0.0,
            budget_alert_only: false,
            exempt: false,
        }
    }
}

impl RateLimitConfig {
    /// All limits disabled (0 = unlimited; not exempt). The workspace bucket
    /// for any workspace with no configured cap row (the Default included).
    pub fn unlimited() -> Self {
        Self {
            requests_per_minute: 0,
            tokens_per_minute: 0,
            daily_budget: 0.0,
            monthly_budget: 0.0,
            budget_alert_only: false,
            exempt: false,
        }
    }

    /// A budget-only bucket (no RPM/TPM) — the per-key ceiling. `alert_only`
    /// flips enforcement to warn-without-blocking.
    pub fn budget_only(daily_budget: f64, monthly_budget: f64, alert_only: bool) -> Self {
        Self {
            requests_per_minute: 0,
            tokens_per_minute: 0,
            daily_budget,
            monthly_budget,
            budget_alert_only: alert_only,
            exempt: false,
        }
    }
}

/// Extract API token from either `Authorization: Bearer` or `x-api-key` header.
///
/// Checks `Authorization: Bearer` first, then falls back to `x-api-key`.
/// This supports both OpenAI-style (Bearer) and Anthropic-style (x-api-key) auth.
pub fn extract_api_token(headers: &HeaderMap) -> Result<String, AppError> {
    // Try Authorization: Bearer first
    if let Some(header) = headers.get("authorization")
        && let Ok(value) = header.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return Ok(token.to_string());
    }
    // Fall back to x-api-key header
    if let Some(header) = headers.get("x-api-key")
        && let Ok(value) = header.to_str()
        && !value.is_empty()
    {
        return Ok(value.to_string());
    }
    // Fall back to x-goog-api-key header (Google Gemini downstream clients)
    if let Some(header) = headers.get("x-goog-api-key")
        && let Ok(value) = header.to_str()
        && !value.is_empty()
    {
        return Ok(value.to_string());
    }
    Err(AppError::Auth(AuthError::MissingHeader))
}

/// Google's native REST credential channel: the `key` query parameter.
///
/// Google's own API reference spells authentication this way in every `curl`
/// example it gives for `generateContent`, `streamGenerateContent` and
/// `models.list`, so a client written from those pages presents its credential
/// here and on no header at all.
///
/// **Nothing is percent-decoded, and that is a property of the vocabulary, not
/// an omission.** Google's keys and this gateway's own `sk-`/`vk-` keys
/// (`bs58`, whose alphabet is alphanumeric minus `0OIl`) are URL-safe, so a `%`
/// or a `+` in the value is not an escape waiting to be unwrapped — it is a
/// character the credential cannot contain, and decoding one would invent a key
/// nobody minted. Preserve that: if a future key format admits a reserved
/// character, this must gain a decode step and the caller must gain a test for
/// it.
///
/// The prefix is matched against the whole `name=value` pair, so `apikey=` and
/// `monkey=` are other parameters, not this one. The first non-empty value
/// wins.
pub fn key_query_param(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .filter_map(|pair| pair.strip_prefix("key="))
        .find(|value| !value.is_empty())
}

/// [`extract_api_token`], plus Google's `?key=` query channel as a last resort.
///
/// Every header channel is tried first and is unchanged, so a client that sends
/// both is unaffected and no existing caller changes behaviour.
///
/// **Pass `query` only where the request's PATH declared the Gemini protocol.**
/// A credential in a URL is visible to every intermediary that logs a request
/// line, so this channel belongs to the one surface whose own spec puts it
/// there — never as a second door onto protocols that never asked for it.
pub fn extract_api_token_with_query(
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<String, AppError> {
    extract_api_token(headers)
        .or_else(|missing| key_query_param(query).map(str::to_string).ok_or(missing))
}

/// The leading bytes of a presented credential, for a log line or an error
/// context — never the whole thing.
///
/// **Truncates on a character boundary, and must keep doing so.** The value is
/// request-controlled: a `vk-`/`sk-` bearer, or the percent-decoded key segment
/// of `/fwd/{key}/...`. A plain byte slice panics when a multi-byte character
/// straddles the cut, and on the `/fwd` path that is reachable with no
/// credential at all — a key of ten ASCII bytes followed by an emoji is enough.
pub fn credential_prefix(credential: &str, n: usize) -> String {
    credential[..credential.floor_char_boundary(n)].to_string()
}

/// An authenticated request: its key, and the configuration of the key's
/// tenant **from the same registry load**. Every config read of the request's
/// pipeline goes through `config`, so the request never meets a key of one
/// version and the routes, endpoints or credentials of another.
pub struct TenantRequestCtx {
    pub user: UserContext,
    pub config: std::sync::Arc<crate::config::TenantConfig>,
}

/// Authenticate a key against one loaded registry.
///
/// Both key formats (`sk-*`, `vk-*`) flow through the same hash-and-lookup
/// path; the `forward_auth` discriminator on the resolved [`UserContext`] is
/// what the route layer enforces via [`authenticate_proxy`] /
/// [`authenticate_forward`] to keep each format on its mount point.
pub fn authenticate(bearer: &str, registry: &crate::config::Registry) -> Result<TenantRequestCtx, AppError> {
    if !(bearer.starts_with("sk-") || bearer.starts_with("vk-")) {
        return Err(AppError::Auth(AuthError::UnrecognizedFormat(credential_prefix(bearer, 12))));
    }
    let Some((user, config)) = registry.key(&virtual_key::key_digest(bearer)) else {
        return Err(AppError::Auth(AuthError::InvalidKey(credential_prefix(bearer, 12))));
    };
    if user.expires_at.is_some_and(|at| at < chrono::Utc::now()) {
        return Err(AppError::Auth(AuthError::KeyExpired(credential_prefix(bearer, 12))));
    }
    Ok(TenantRequestCtx { user: UserContext::clone(user), config: config.clone() })
}

/// Authenticate a proxy-issued (`sk-*`, `forward_auth = false`) key.
///
/// Used by `/v1/*` and `/mcp/<slug>`. A `vk-*` forward-auth key presented here
/// is rejected with a generic [`AuthError::InvalidKey`] so a probing client
/// can't distinguish "wrong mount" from "no such key".
pub fn authenticate_proxy(bearer: &str, registry: &crate::config::Registry) -> Result<TenantRequestCtx, AppError> {
    let ctx = authenticate(bearer, registry)?;
    if ctx.user.forward_auth {
        return Err(AppError::Auth(AuthError::InvalidKey(credential_prefix(bearer, 12))));
    }
    Ok(ctx)
}

/// Authenticate a forward-auth (`vk-*`, `forward_auth = true`) key.
///
/// Used by `/fwd/{key}/...`. A proxy-issued `sk-*` key presented here is
/// rejected with the same generic [`AuthError::InvalidKey`].
pub fn authenticate_forward(bearer: &str, registry: &crate::config::Registry) -> Result<TenantRequestCtx, AppError> {
    let ctx = authenticate(bearer, registry)?;
    if !ctx.user.forward_auth {
        return Err(AppError::Auth(AuthError::InvalidKey(credential_prefix(bearer, 12))));
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use axum::http::HeaderMap;

    #[test]
    fn extract_api_token_from_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-abc123".parse().unwrap());
        let result = extract_api_token(&headers);
        assert_eq!(result.unwrap(), "sk-abc123");
    }

    #[test]
    fn extract_api_token_from_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "sk-xyz789".parse().unwrap());
        let result = extract_api_token(&headers);
        assert_eq!(result.unwrap(), "sk-xyz789");
    }

    #[test]
    fn extract_api_token_bearer_takes_precedence() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-bearer".parse().unwrap());
        headers.insert("x-api-key", "sk-xapi".parse().unwrap());
        let result = extract_api_token(&headers);
        assert_eq!(result.unwrap(), "sk-bearer");
    }

    #[test]
    fn extract_api_token_missing_both() {
        let headers = HeaderMap::new();
        let result = extract_api_token(&headers);
        assert_matches!(
            result.unwrap_err(),
            AppError::Auth(AuthError::MissingHeader)
        );
    }

    #[test]
    fn extract_api_token_empty_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "".parse().unwrap());
        let result = extract_api_token(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn extract_api_token_vk_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "vk-abc123".parse().unwrap());
        let result = extract_api_token(&headers);
        assert_eq!(result.unwrap(), "vk-abc123");
    }

    #[test]
    fn extract_api_token_vk_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer vk-abc123".parse().unwrap());
        let result = extract_api_token(&headers);
        assert_eq!(result.unwrap(), "vk-abc123");
    }

    /// The value Google's own `curl` examples put in the URL is the one that
    /// comes back — including from the streaming form, where the SDK sends
    /// `alt=sse` first, so the parameter is not the head of the query string.
    #[test]
    fn the_key_query_parameter_is_read_wherever_it_sits() {
        for query in ["key=sk-abc123", "alt=sse&key=sk-abc123", "key=sk-abc123&alt=sse"] {
            assert_eq!(
                key_query_param(Some(query)),
                Some("sk-abc123"),
                "query {query} carries the credential"
            );
        }
    }

    /// A parameter whose name merely ENDS in `key` is a different parameter.
    /// The match is on the whole `name=value` pair for exactly this reason: a
    /// substring match would read a tenant's `monkey=` as a credential, and an
    /// `apikey=` naming a DIFFERENT secret as this one.
    #[test]
    fn a_parameter_that_merely_ends_in_key_is_not_the_credential() {
        for query in ["apikey=sk-abc123", "monkey=sk-abc123", "Key=sk-abc123", "keys=sk-abc123"] {
            assert_eq!(key_query_param(Some(query)), None, "query {query} is not the key parameter");
        }
    }

    /// An empty value is no credential — it must fall through to the same
    /// "missing" refusal a bare URL gets, not be presented as a key of length
    /// zero and refused as *invalid*. The two errors say different things to a
    /// client.
    #[test]
    fn an_empty_key_parameter_is_no_credential() {
        assert_eq!(key_query_param(Some("key=")), None);
        assert_eq!(key_query_param(Some("key=&alt=sse")), None);
        assert_eq!(key_query_param(None), None);
        assert_eq!(key_query_param(Some("")), None);
        // …and an empty one does not SHADOW a real one that follows it.
        assert_eq!(key_query_param(Some("key=&key=sk-abc123")), Some("sk-abc123"));
    }

    /// Nothing is percent-decoded, deliberately: the key alphabets are URL-safe,
    /// so a `%` is a character a credential cannot contain rather than an escape.
    /// Decoding would manufacture a key nobody minted — and, worse, would let two
    /// different query strings present as the same credential.
    #[test]
    fn the_value_is_taken_verbatim() {
        assert_eq!(key_query_param(Some("key=sk-a%2Db")), Some("sk-a%2Db"));
        assert_eq!(key_query_param(Some("key=sk-a+b")), Some("sk-a+b"));
    }

    /// The header channels keep precedence, so a client sending both is
    /// unaffected — this widens the ways IN, never what an existing request
    /// resolves to.
    #[test]
    fn every_header_channel_still_outranks_the_query() {
        for (name, value) in [
            ("authorization", "Bearer sk-header"),
            ("x-api-key", "sk-header"),
            ("x-goog-api-key", "sk-header"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, value.parse().unwrap());
            assert_eq!(
                extract_api_token_with_query(&headers, Some("key=sk-query")).unwrap(),
                "sk-header",
                "{name} must outrank the query parameter"
            );
        }
    }

    /// The positive control for the pair: with no header at all the query
    /// parameter IS the credential, and with neither the refusal is still
    /// `MissingHeader`. A test that only asserted the refusal would pass with
    /// the query channel unread.
    #[test]
    fn the_query_parameter_authenticates_when_no_header_does() {
        let headers = HeaderMap::new();
        assert_eq!(
            extract_api_token_with_query(&headers, Some("alt=sse&key=sk-query")).unwrap(),
            "sk-query"
        );
        assert_matches!(
            extract_api_token_with_query(&headers, None).unwrap_err(),
            AppError::Auth(AuthError::MissingHeader)
        );
        assert_matches!(
            extract_api_token_with_query(&headers, Some("alt=sse")).unwrap_err(),
            AppError::Auth(AuthError::MissingHeader)
        );
    }

    /// The query is a LAST RESORT, not a fallback ranked against a header that
    /// failed to parse: a scheme the ladder does not recognise leaves no
    /// credential at all, so the query supplies one. Pinning it because it is
    /// the one request whose outcome this change alters beyond "was 401,
    /// now works" — before, a `Basic` header plus a valid key in the URL was
    /// refused.
    #[test]
    fn a_header_the_ladder_does_not_recognise_leaves_the_query_to_answer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_matches!(
            extract_api_token(&headers).unwrap_err(),
            AppError::Auth(AuthError::MissingHeader)
        );
        assert_eq!(
            extract_api_token_with_query(&headers, Some("key=sk-query")).unwrap(),
            "sk-query"
        );
    }
}

#[cfg(test)]
mod credential_prefix_tests {
    use super::credential_prefix;

    /// The value is request-controlled and a plain `&s[..n]` panics when a
    /// multi-byte character straddles the cut. On `/fwd/{key}/...` the key is a
    /// percent-decoded path segment, so an unauthenticated request reaches this
    /// with a credential of the attacker's choosing.
    #[test]
    fn a_multibyte_character_across_the_cut_does_not_panic() {
        // 'a' × 10 then a 4-byte emoji: a 12-byte cut lands mid-character.
        let key = "aaaaaaaaaa\u{1F600}";
        assert_eq!(credential_prefix(key, 12), "aaaaaaaaaa");
        // 6-byte cut, the /fwd log width.
        assert_eq!(credential_prefix("\u{1F600}abc", 6), "\u{1F600}ab");
        // Every prefix length over a multi-byte string must be safe, not just
        // the two the callers happen to use.
        for n in 0..=key.len() + 4 {
            let _ = credential_prefix(key, n);
        }
    }

    #[test]
    fn it_truncates_and_never_lengthens() {
        assert_eq!(credential_prefix("sk-abcdefghijklmnop", 12), "sk-abcdefghi");
        assert_eq!(credential_prefix("short", 12), "short");
        assert_eq!(credential_prefix("", 12), "");
    }
}

#[cfg(test)]
mod registry_authentication_tests {
    use super::*;
    use crate::config::{Registry, TenantConfig, TenantId};
    use std::assert_matches;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn context(tenant: uuid::Uuid, forward_auth: bool) -> UserContext {
        serde_json::from_value(serde_json::json!({
            "user_id": uuid::Uuid::new_v4(),
            "tenant_id": tenant,
            "workspace_id": uuid::Uuid::new_v4(),
            "model_map": { "mappings": {} },
            "rate_limit": RateLimitConfig::unlimited(),
            "tenant_budget": null,
            "forward_auth": forward_auth,
        }))
        .unwrap()
    }

    fn tenant_with(tenant: uuid::Uuid, keys: &[&str]) -> (TenantId, Arc<TenantConfig>) {
        let mut cfg = TenantConfig { tenant_slug: tenant.to_string(), ..TenantConfig::default() };
        for key in keys {
            cfg.keys.insert(virtual_key::key_digest(key), Arc::new(context(tenant, key.starts_with("vk-"))));
        }
        (TenantId(tenant), Arc::new(cfg))
    }

    /// Every live key authenticates, however many the gateway holds, and each to
    /// its own tenant's configuration — no capacity bound evicts a valid key.
    #[test]
    fn every_key_of_a_large_registry_authenticates_to_its_own_tenant() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let keys: Vec<String> = (0..12_000).map(|i| format!("sk-{i}")).collect();
        let (left, right) = keys.split_at(6_000);
        let left: Vec<&str> = left.iter().map(String::as_str).collect();
        let right: Vec<&str> = right.iter().map(String::as_str).collect();
        let registry = Registry::new(HashMap::from([tenant_with(a, &left), tenant_with(b, &right)]));
        for (key, tenant) in left.iter().map(|k| (k, a)).chain(right.iter().map(|k| (k, b))) {
            let ctx = authenticate_proxy(key, &registry).unwrap();
            assert_eq!(ctx.user.tenant_id, tenant);
            assert_eq!(ctx.config.tenant_slug, tenant.to_string(), "{key} got another tenant's configuration");
        }
        assert_matches!(authenticate_proxy("sk-unknown", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::InvalidKey(_))));
    }

    /// A key hash two tenants both carry authenticates to neither: picking one
    /// would hand the request to whichever tenant the index met last.
    #[test]
    fn a_key_carried_by_two_tenants_authenticates_to_neither() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let registry = Registry::new(HashMap::from([
            tenant_with(a, &["sk-shared", "sk-a"]),
            tenant_with(b, &["sk-shared"]),
        ]));
        assert_matches!(authenticate_proxy("sk-shared", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::InvalidKey(_))));
        assert!(authenticate_proxy("sk-a", &registry).is_ok(), "the tenant's other keys still authenticate");
    }

    /// A key naming another tenant than the config carrying it authenticates to
    /// neither: it would route on one tenant's settings and be accounted to the
    /// other's.
    #[test]
    fn a_key_naming_another_tenant_is_refused() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let (tid, cfg) = tenant_with(a, &["sk-own"]);
        let mut cfg = TenantConfig::clone(&cfg);
        cfg.keys.insert(virtual_key::key_digest("sk-foreign"), Arc::new(context(b, false)));
        let registry = Registry::new(HashMap::from([(tid, Arc::new(cfg))]));
        assert_matches!(authenticate_proxy("sk-foreign", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::InvalidKey(_))));
        assert!(authenticate_proxy("sk-own", &registry).is_ok());
    }

    /// Each key format stays on its own mount, and an expired key is refused.
    #[test]
    fn a_key_authenticates_only_on_its_own_mount_and_until_it_expires() {
        let t = uuid::Uuid::new_v4();
        let (tid, cfg) = tenant_with(t, &["sk-p", "vk-f"]);
        let mut cfg = TenantConfig::clone(&cfg);
        let mut expired = context(t, false);
        expired.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        cfg.keys.insert(virtual_key::key_digest("sk-old"), Arc::new(expired));
        let registry = Registry::new(HashMap::from([(tid, Arc::new(cfg))]));

        assert!(authenticate_proxy("sk-p", &registry).is_ok());
        assert!(authenticate_forward("vk-f", &registry).is_ok());
        assert_matches!(authenticate_forward("sk-p", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::InvalidKey(_))));
        assert_matches!(authenticate_proxy("vk-f", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::InvalidKey(_))));
        assert_matches!(authenticate_proxy("sk-old", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::KeyExpired(_))));
        assert_matches!(authenticate_proxy("Bearer-x", &registry).map(|c| c.user), Err(AppError::Auth(AuthError::UnrecognizedFormat(_))));
    }
}
