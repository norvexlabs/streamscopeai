//! The headers an upstream MCP request carries, from the upstream's declared
//! header inputs ([`streamscope_core::mcp::header_inputs`]).
//!
//! Each declared input is filled by the admin (stored encrypted on the
//! upstream), by the calling user (stored encrypted per user) or by the
//! calling client (sent on every request, never stored). A `per_user_oauth`
//! upstream additionally carries the user's OAuth token as
//! `Authorization: Bearer`, pushed by the handler after [`InputsMemo::resolve`].
//!
//! Client-filled values are captured from the inbound request by
//! [`capture_client_inputs`]: only the header names a routed upstream
//! declares as client-filled are kept, and a name two routed upstreams both
//! claim is kept for neither — the gateway cannot tell which upstream it is
//! meant for.
//!
//! The declaration is validated once per config snapshot
//! ([`McpUpstreamServer::input_specs`]); the stored values are decrypted at
//! most once per request and upstream through the request's [`InputsMemo`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderName};
use streamscope_core::config::mcp::{McpAuthMode, McpUpstreamServer, McpUserInputs};
use streamscope_core::mcp::header_inputs::{
    self, Filler, InputSpec, InputValues, ResolveError, UpstreamAuth,
};
use uuid::Uuid;

use super::upstream::UpstreamError;

/// Whether a client-filled input `upstream` declares satisfies `f`. A
/// declaration that does not validate declares nothing here; resolving it
/// fails on its own.
fn any_client_spec(upstream: &McpUpstreamServer, mut f: impl FnMut(&InputSpec) -> bool) -> bool {
    upstream
        .input_specs()
        .as_deref()
        .is_ok_and(|specs| specs.iter().filter(|s| s.filler == Filler::Client).any(&mut f))
}

/// The header names (lowercase) `upstream` declares as client-filled. A
/// declaration that does not validate declares nothing here; resolving it
/// fails on its own.
pub fn client_header_names(upstream: &McpUpstreamServer) -> Vec<String> {
    upstream
        .input_specs()
        .as_deref()
        .map(header_inputs::client_header_names)
        .unwrap_or_default()
}

/// Whether `upstream` declares any client-filled input. Such an upstream
/// cannot be reached without a client request behind it, so the gateway
/// opens no connection of its own to it (no listener).
pub fn has_client_inputs(upstream: &McpUpstreamServer) -> bool {
    any_client_spec(upstream, |_| true)
}

/// Whether a routed upstream takes the client's own `Authorization` header,
/// which on `/mcp/<slug>` carries the gateway credential: such a virtual
/// server is reachable only on `/fwd/{key}/mcp/<slug>`.
pub fn requires_fwd_mount(upstreams: &[McpUpstreamServer]) -> bool {
    upstreams
        .iter()
        .any(|u| any_client_spec(u, |s| s.declared.header.eq_ignore_ascii_case("authorization")))
}

/// Whether every routed upstream carries only what the client sends — its own
/// `Authorization` included, no OAuth and no admin or user input — the only
/// virtual servers a pass-through (`vk-`) key may reach: such a key carries no
/// credential of the gateway's, so it must never reach a server the gateway
/// stamps a stored value on.
pub fn pass_through_only(upstreams: &[McpUpstreamServer]) -> bool {
    !upstreams.is_empty()
        && upstreams.iter().all(|u| {
            !is_oauth(u)
                && u.input_specs().as_deref().is_ok_and(|specs| {
                    specs.iter().all(|s| s.filler == Filler::Client)
                        && specs.iter().any(|s| s.declared.header.eq_ignore_ascii_case("authorization"))
                })
        })
}

/// Keep, from the inbound headers, only the client-filled header names the
/// routed upstreams declare. A name claimed by two different upstreams is
/// kept for neither (the admin API refuses that binding; a snapshot that
/// shows one anyway fails closed here).
pub fn capture_client_inputs(inbound: &HeaderMap, upstreams: &[McpUpstreamServer]) -> HeaderMap {
    let mut claims: BTreeMap<String, BTreeSet<Uuid>> = BTreeMap::new();
    for u in upstreams {
        for name in client_header_names(u) {
            claims.entry(name).or_default().insert(u.id);
        }
    }
    let mut out = HeaderMap::new();
    for (name, owners) in claims {
        if owners.len() > 1 {
            tracing::warn!(
                header = %name,
                "MCP: two routed upstreams declare the same client header; sending it to neither"
            );
            continue;
        }
        let Ok(header) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if let Some(value) = inbound.get(&header) {
            let mut value = value.clone();
            value.set_sensitive(true);
            out.insert(header, value);
        }
    }
    out
}

fn is_oauth(upstream: &McpUpstreamServer) -> bool {
    upstream.auth_mode == McpAuthMode::PerUserOauth
}

/// Decrypt an id → ciphertext map. `None` when the encryption key is absent
/// or any value does not decrypt; the error names the upstream and the id,
/// never a value.
fn decrypt_values(
    upstream: &McpUpstreamServer,
    filler: &'static str,
    encrypted: &HashMap<String, String>,
    log: Log,
) -> Option<HashMap<String, String>> {
    if encrypted.is_empty() {
        return Some(HashMap::new());
    }
    let Some(key) = streamscope_core::crypto::get_encryption_key() else {
        if log == Log::Warn {
            tracing::warn!(upstream = %upstream.id, filler, "MCP: no encryption key to read stored inputs");
        }
        return None;
    };
    let mut out = HashMap::with_capacity(encrypted.len());
    for (id, ciphertext) in encrypted {
        match streamscope_core::crypto::decrypt(ciphertext, &key) {
            Ok(v) => {
                out.insert(id.clone(), v);
            }
            Err(_) => {
                if log == Log::Warn {
                    tracing::warn!(upstream = %upstream.id, filler, input = %id, "MCP: a stored input does not decrypt");
                }
                return None;
            }
        }
    }
    Some(out)
}

/// One upstream's stored values, decrypted: `None` for a set that did not
/// decrypt (the user's is also `None`, unread, when the admin's did not).
/// No `Debug`: it holds plaintext.
struct Decrypted {
    /// What the entry was decrypted from: the upstream's admin-input version
    /// and the user whose values these are.
    cred_version: i64,
    user_id: Option<Uuid>,
    admin: Option<HashMap<String, String>>,
    user: Option<HashMap<String, String>>,
}

/// The stored values one request decrypted, by upstream — so an upstream the
/// request resolves several times (the fan-out's visibility check, the
/// listing's preflight, then the call) is decrypted once. Lives on the
/// request's context and drops with it; plaintext is never kept beyond the
/// request. An entry is read only for the admin-input version and user it was
/// decrypted for. No `Debug`: it holds plaintext.
#[derive(Default)]
pub struct InputsMemo(Mutex<HashMap<Uuid, Arc<Decrypted>>>);

impl InputsMemo {
    /// Build the declared headers for one request to `upstream`: the admin's
    /// values, the calling user's (`user`), and the client's captured headers
    /// (`client`). The OAuth bearer of a `per_user_oauth` upstream is NOT
    /// added here — the caller pushes it after its refresh.
    ///
    /// Errors: a missing user input → [`UpstreamError::UserInputsMissing`]
    /// (`-32501`, the user connects in the portal); otherwise a missing client
    /// header → [`UpstreamError::ClientHeaderMissing`] (`-32401`); a missing
    /// admin input, an invalid declaration or a value that cannot be a header
    /// → [`UpstreamError::CredentialUnavailable`] with a `warn!` naming no
    /// value.
    pub fn resolve(
        &self,
        upstream: &McpUpstreamServer,
        user: Option<&McpUserInputs>,
        client: &HeaderMap,
    ) -> Result<UpstreamAuth, UpstreamError> {
        resolve_with(upstream, user, client, Log::Warn, self)
    }

    /// [`Self::resolve`] without its warnings, for a check that only reads
    /// which error the caller would get (the call itself logs it once).
    pub fn resolve_quiet(
        &self,
        upstream: &McpUpstreamServer,
        user: Option<&McpUserInputs>,
        client: &HeaderMap,
    ) -> Result<UpstreamAuth, UpstreamError> {
        resolve_with(upstream, user, client, Log::Quiet, self)
    }

    /// Whether the caller lacks a user or client input `upstream` requires —
    /// the test an aggregated call (`tools/list` fan-out) hides an upstream
    /// by. Any other resolution failure is not the caller's to fix and is
    /// left to surface as an error.
    pub fn lacks_caller_inputs(
        &self,
        upstream: &McpUpstreamServer,
        user: Option<&McpUserInputs>,
        client: &HeaderMap,
    ) -> bool {
        matches!(
            self.resolve_quiet(upstream, user, client),
            Err(UpstreamError::UserInputsMissing | UpstreamError::ClientHeaderMissing(_))
        )
    }

    /// The decrypted values for `upstream` and `user`. A set that did not
    /// decrypt is decrypted again on a logging pass, so its warning is still
    /// written by the request that calls the upstream.
    fn decrypted(
        &self,
        upstream: &McpUpstreamServer,
        user: Option<&McpUserInputs>,
        log: Log,
    ) -> Arc<Decrypted> {
        let user_id = user.map(|u| u.user_id);
        let held = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&upstream.id)
            .filter(|d| d.cred_version == upstream.cred_version && d.user_id == user_id)
            .cloned();
        if let Some(d) = held
            && (log == Log::Quiet || (d.admin.is_some() && d.user.is_some()))
        {
            return d;
        }
        let entry = decrypt_for(upstream, user, log);
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(upstream.id, entry.clone());
        entry
    }
}

fn admin_values(upstream: &McpUpstreamServer, log: Log) -> Option<HashMap<String, String>> {
    decrypt_values(upstream, "admin", &upstream.encrypted_admin_inputs, log)
}

fn user_values(
    upstream: &McpUpstreamServer,
    user: Option<&McpUserInputs>,
    log: Log,
) -> Option<HashMap<String, String>> {
    match user {
        Some(u) => decrypt_values(upstream, "user", &u.encrypted_values, log),
        None => Some(HashMap::new()),
    }
}

fn decrypt_for(upstream: &McpUpstreamServer, user: Option<&McpUserInputs>, log: Log) -> Arc<Decrypted> {
    let admin = admin_values(upstream, log);
    Arc::new(Decrypted {
        cred_version: upstream.cred_version,
        user_id: user.map(|u| u.user_id),
        // The user's values are not read once the admin's fail: the request
        // stops at the admin's.
        user: admin.as_ref().and_then(|_| user_values(upstream, user, log)),
        admin,
    })
}

/// [`InputsMemo::resolve`] on a fresh memo: every call decrypts.
#[cfg(test)]
pub fn resolve_inputs(
    upstream: &McpUpstreamServer,
    user: Option<&McpUserInputs>,
    client: &HeaderMap,
) -> Result<UpstreamAuth, UpstreamError> {
    InputsMemo::default().resolve(upstream, user, client)
}

/// [`InputsMemo::lacks_caller_inputs`] on a fresh memo: every call decrypts.
#[cfg(test)]
pub fn lacks_caller_inputs(
    upstream: &McpUpstreamServer,
    user: Option<&McpUserInputs>,
    client: &HeaderMap,
) -> bool {
    InputsMemo::default().lacks_caller_inputs(upstream, user, client)
}

/// Whether a resolution failure is logged: the request that calls the
/// upstream logs it once; a predicate asking only whether to hide it does not.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Log {
    Warn,
    Quiet,
}

fn resolve_with(
    upstream: &McpUpstreamServer,
    user: Option<&McpUserInputs>,
    client: &HeaderMap,
    log: Log,
    memo: &InputsMemo,
) -> Result<UpstreamAuth, UpstreamError> {
    let decrypted = memo.decrypted(upstream, user, log);
    let admin = decrypted.admin.as_ref().ok_or(UpstreamError::CredentialUnavailable)?;
    // A user value that does not decrypt is treated as unfilled: the user
    // fixes it by entering it again in the portal.
    let unfilled = HashMap::new();
    let user_values = decrypted.user.as_ref().unwrap_or(&unfilled);
    let values = InputValues {
        admin: Some(admin),
        user: Some(user_values),
        client: Some(client),
    };
    upstream.resolve_inputs(values).map_err(|e| map_resolve_error(upstream, e, log))
}

fn map_resolve_error(upstream: &McpUpstreamServer, e: ResolveError, log: Log) -> UpstreamError {
    let warn = log == Log::Warn;
    match e {
        // What only the admin can fix comes first: telling the user to
        // connect would send them to a portal that cannot repair it.
        ResolveError::Missing(m) if !m.admin.is_empty() => {
            if warn {
                tracing::warn!(
                    upstream = %upstream.id,
                    inputs = ?m.admin,
                    "MCP: the upstream's admin inputs are not filled"
                );
            }
            UpstreamError::CredentialUnavailable
        }
        ResolveError::Missing(m) if !m.user.is_empty() => UpstreamError::UserInputsMissing,
        ResolveError::Missing(m) if !m.client.is_empty() => {
            UpstreamError::ClientHeaderMissing(m.client.join(", "))
        }
        ResolveError::Missing(_) => UpstreamError::CredentialUnavailable,
        ResolveError::Declaration(err) => {
            if warn {
                tracing::warn!(upstream = %upstream.id, error = %err, "MCP: the upstream's header declaration is invalid");
            }
            UpstreamError::CredentialUnavailable
        }
        ResolveError::InvalidValue(header) => {
            if warn {
                tracing::warn!(upstream = %upstream.id, header = %header, "MCP: an input value cannot be carried in its header");
            }
            UpstreamError::CredentialUnavailable
        }
    }
}

/// Add a `per_user_oauth` upstream's token as `Authorization: Bearer` — the
/// only header the OAuth leg contributes. A token that cannot be a header
/// value reads as an unusable credential: the user reconnects.
pub fn push_oauth_token(
    upstream_auth: &mut UpstreamAuth,
    upstream: &McpUpstreamServer,
    token: &str,
) -> Result<(), UpstreamError> {
    upstream_auth.push_bearer(token).ok_or_else(|| {
        tracing::warn!(upstream = %upstream.id, "MCP: the user's OAuth token cannot be carried in a header");
        UpstreamError::UserCredentialExpired
    })
}

/// Whether every input `upstream` declares is admin-filled — the same headers
/// for every caller. False on an invalid declaration.
pub fn every_input_is_admin(upstream: &McpUpstreamServer) -> bool {
    upstream
        .input_specs()
        .as_deref()
        .is_ok_and(|specs| specs.iter().all(|s| s.filler == Filler::Admin))
}

/// A fingerprint of the inputs a gateway-owned connection to `upstream` was
/// opened with: the upstream's `cred_version` (bumped on every admin input,
/// declaration or filler change), the user's stored values and OAuth
/// credential, and the values the calling client sent for the upstream's client-filled headers. A connection
/// opened under another fingerprint is not reused. It lives in memory only.
pub fn inputs_fingerprint(
    upstream: &McpUpstreamServer,
    user: Option<&McpUserInputs>,
    oauth: Option<&streamscope_core::config::mcp::McpUserCredential>,
    client: &HeaderMap,
) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    upstream.cred_version.hash(&mut h);
    if let Some(u) = user {
        let sorted: BTreeMap<&String, &String> = u.encrypted_values.iter().collect();
        sorted.hash(&mut h);
    }
    // The stored OAuth credential: a reconnect (perhaps as another account)
    // stores a new one, and must not ride the session the old one opened.
    if let Some(c) = oauth {
        c.encrypted_refresh_token.as_ref().unwrap_or(&c.encrypted_access_token).hash(&mut h);
    }
    for name in client_header_names(upstream) {
        name.hash(&mut h);
        client.get(name.as_str()).map(|v| v.as_bytes()).hash(&mut h);
    }
    h.finish()
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// An upstream declaring `headers` (a `server.json` `headers` array) with
    /// `fillers` (input id → filler).
    pub(crate) fn upstream(
        auth_mode: McpAuthMode,
        headers: serde_json::Value,
        fillers: serde_json::Value,
    ) -> McpUpstreamServer {
        let remote = serde_json::from_value(serde_json::json!({
            "type": "streamable-http",
            "url": "https://up.example/mcp",
            "headers": headers,
            "_meta": { "ai.streamscope/inputs": { "fillers": fillers } },
        }))
        .unwrap();
        McpUpstreamServer {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "u".into(),
            description: None,
            upstream_url: "https://up.example/mcp".into(),
            transport: streamscope_core::config::mcp::McpTransport::StreamableHttp,
            auth_mode,
            cred_version: 1,
            encrypted_credential: None,
            remote,
            encrypted_admin_inputs: HashMap::new(),
            oauth_issuer_url: None,
            oauth_authorization_url: None,
            oauth_token_url: None,
            oauth_revocation_url: None,
            oauth_client_id: None,
            encrypted_oauth_client_secret: None,
            oauth_default_scopes: vec![],
            enabled: true,
            connect_timeout_ms: 10_000,
            request_timeout_ms: 60_000,
            input_specs_cache: Default::default(),
        }
    }

    pub(crate) fn sealed(plaintext: &str) -> String {
        // SAFETY: same value as every other ENCRYPTION_KEY setter in this binary.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-mcp-token-secret-very-long");
        }
        let key = streamscope_core::crypto::get_encryption_key().expect("ENCRYPTION_KEY is set");
        streamscope_core::crypto::encrypt(plaintext, &key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{sealed, upstream};
    use super::*;
    use serde_json::json;
    use std::assert_matches;

    fn one(name: &str, required: bool, secret: bool) -> serde_json::Value {
        json!({ "name": name, "isRequired": required, "isSecret": secret })
    }

    fn inbound(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn user_inputs(up: &McpUpstreamServer, values: &[(&str, &str)]) -> McpUserInputs {
        McpUserInputs {
            tenant_id: up.tenant_id,
            user_id: Uuid::new_v4(),
            upstream_server_id: up.id,
            encrypted_values: values.iter().map(|(k, v)| (k.to_string(), sealed(v))).collect(),
        }
    }

    fn sent(auth: &UpstreamAuth) -> Vec<(String, String)> {
        auth.headers()
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect()
    }

    fn client_token_upstream() -> McpUpstreamServer {
        upstream(
            McpAuthMode::Headers,
            json!([one("X-Token", true, true)]),
            json!({ "X-Token": "client" }),
        )
    }

    /// Only a declared client-filled name is captured: the gateway key's
    /// `Authorization`, an undeclared header and a header the upstream fills
    /// itself never reach the upstream from the client.
    #[test]
    fn only_a_declared_client_header_is_captured_and_sent() {
        let mut up = upstream(
            McpAuthMode::Headers,
            json!([one("X-Token", true, true), one("X-Org", true, false)]),
            json!({ "X-Token": "client", "X-Org": "admin" }),
        );
        up.encrypted_admin_inputs.insert("X-Org".into(), sealed("acme"));
        let captured = capture_client_inputs(
            &inbound(&[
                ("authorization", "Bearer sk-gateway-key"),
                ("x-token", "client-secret-1"),
                ("x-undeclared", "nope"),
                ("x-org", "client-tries-the-admin-input"),
            ]),
            std::slice::from_ref(&up),
        );
        assert_eq!(captured.len(), 1);
        assert_eq!(captured.get("x-token").unwrap(), "client-secret-1");
        let auth = resolve_inputs(&up, None, &captured).unwrap();
        assert_eq!(
            sent(&auth),
            vec![
                ("x-token".to_string(), "client-secret-1".to_string()),
                ("x-org".to_string(), "acme".to_string()),
            ]
        );
    }

    /// Two routed upstreams claiming one client header: it goes to neither.
    /// The positive control: distinct names are each kept.
    #[test]
    fn a_client_header_two_upstreams_claim_goes_to_neither() {
        let a = client_token_upstream();
        let b = client_token_upstream();
        let headers = inbound(&[("x-token", "v1"), ("x-other", "v2")]);
        assert!(capture_client_inputs(&headers, &[a.clone(), b]).is_empty());

        let c = upstream(
            McpAuthMode::Headers,
            json!([one("X-Other", true, false)]),
            json!({ "X-Other": "client" }),
        );
        let captured = capture_client_inputs(&headers, &[a.clone(), c]);
        assert_eq!(captured.len(), 2);
        // The same upstream routed twice is one claim, not a collision.
        assert_eq!(capture_client_inputs(&headers, &[a.clone(), a]).len(), 1);
    }

    #[test]
    fn only_a_client_filled_authorization_requires_the_fwd_mount() {
        let client_auth = upstream(
            McpAuthMode::Headers,
            json!([one("Authorization", true, true)]),
            json!({ "Authorization": "client" }),
        );
        let admin_auth = upstream(
            McpAuthMode::Headers,
            json!([one("Authorization", true, true)]),
            json!({ "Authorization": "admin" }),
        );
        assert!(requires_fwd_mount(&[client_token_upstream(), client_auth]));
        assert!(!requires_fwd_mount(&[client_token_upstream(), admin_auth]));
    }

    /// A pass-through key reaches a virtual server only when every route
    /// carries just the client's own Authorization: a sibling holding an
    /// admin value, an OAuth upstream or no route at all refuses it.
    #[test]
    fn a_pass_through_key_reaches_only_servers_holding_nothing_of_the_gateways() {
        let client_auth = || {
            upstream(McpAuthMode::Headers, json!([one("Authorization", true, true)]), json!({ "Authorization": "client" }))
        };
        let admin_auth = upstream(
            McpAuthMode::Headers,
            json!([one("Authorization", true, true)]),
            json!({ "Authorization": "admin" }),
        );
        assert!(pass_through_only(&[client_auth()]));
        assert!(!pass_through_only(&[client_auth(), admin_auth]));
        assert!(!pass_through_only(&[client_token_upstream()]), "no client Authorization");
        let mut oauth = client_auth();
        oauth.auth_mode = McpAuthMode::PerUserOauth;
        assert!(!pass_through_only(&[oauth]));
        assert!(!pass_through_only(&[]));
    }

    /// A missing user input is the user's to fill (-32501), and wins over a
    /// missing client header; filled, the header is sent.
    #[test]
    fn a_missing_user_input_is_a_needs_connection_error() {
        let up = upstream(
            McpAuthMode::Headers,
            json!([one("X-User-Key", true, true), one("X-Token", true, true)]),
            json!({ "X-User-Key": "user", "X-Token": "client" }),
        );
        assert_matches!(
            resolve_inputs(&up, None, &HeaderMap::new()),
            Err(UpstreamError::UserInputsMissing)
        );
        let mine = user_inputs(&up, &[("X-User-Key", "user-secret-1")]);
        let client = inbound(&[("x-token", "client-secret-1")]);
        let auth = resolve_inputs(&up, Some(&mine), &client).unwrap();
        assert_eq!(sent(&auth)[0], ("x-user-key".to_string(), "user-secret-1".to_string()));
    }

    /// A user value that does not decrypt reads as unfilled.
    #[test]
    fn an_undecryptable_user_value_reads_as_unfilled() {
        let up = upstream(
            McpAuthMode::Headers,
            json!([one("X-User-Key", true, true)]),
            json!({ "X-User-Key": "user" }),
        );
        let mut mine = user_inputs(&up, &[("X-User-Key", "x")]);
        mine.encrypted_values.insert("X-User-Key".into(), "not-a-ciphertext".into());
        assert_matches!(
            resolve_inputs(&up, Some(&mine), &HeaderMap::new()),
            Err(UpstreamError::UserInputsMissing)
        );
    }

    /// A missing client header names the header (-32401); sent, it reaches
    /// the upstream.
    #[test]
    fn a_missing_client_header_is_named() {
        let up = client_token_upstream();
        let err = resolve_inputs(&up, None, &HeaderMap::new()).unwrap_err();
        assert_matches!(&err, UpstreamError::ClientHeaderMissing(h) if h == "X-Token");
        assert!(resolve_inputs(&up, None, &inbound(&[("x-token", "client-secret-1")])).is_ok());
    }

    /// What the caller cannot fix — an unfilled admin input, an invalid
    /// declaration, a value no header can carry — is the upstream being
    /// unavailable (-32500); the filled admin input is the positive control.
    #[test]
    fn what_the_caller_cannot_fix_is_an_unavailable_upstream() {
        let mut up = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true)]),
            json!({ "X-Api-Key": "admin" }),
        );
        assert_matches!(
            resolve_inputs(&up, None, &HeaderMap::new()),
            Err(UpstreamError::CredentialUnavailable)
        );
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), sealed(" padded"));
        assert_matches!(
            resolve_inputs(&up, None, &HeaderMap::new()),
            Err(UpstreamError::CredentialUnavailable)
        );
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), sealed("admin-secret-1"));
        let auth = resolve_inputs(&up, None, &HeaderMap::new()).unwrap();
        assert_eq!(sent(&auth), vec![("x-api-key".to_string(), "admin-secret-1".to_string())]);

        // An admin gap wins over the user's own: the user must not be sent
        // to a portal that cannot repair the upstream.
        let both = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true), one("X-User-Key", true, true)]),
            json!({ "X-Api-Key": "admin", "X-User-Key": "user" }),
        );
        assert_matches!(
            resolve_inputs(&both, None, &HeaderMap::new()),
            Err(UpstreamError::CredentialUnavailable)
        );

        let undeclared_filler = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true)]),
            json!({}),
        );
        assert_matches!(
            resolve_inputs(&undeclared_filler, None, &HeaderMap::new()),
            Err(UpstreamError::CredentialUnavailable)
        );
    }

    /// An aggregated call hides an upstream missing a user or client input,
    /// and only those: an unavailable upstream stays visible (its error is not
    /// the caller's to fix), and a complete one is shown.
    #[test]
    fn only_a_missing_caller_input_hides_an_upstream() {
        assert!(lacks_caller_inputs(&client_token_upstream(), None, &HeaderMap::new()));
        let user = upstream(
            McpAuthMode::Headers,
            json!([one("X-User-Key", true, true)]),
            json!({ "X-User-Key": "user" }),
        );
        assert!(lacks_caller_inputs(&user, None, &HeaderMap::new()));
        let admin = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true)]),
            json!({ "X-Api-Key": "admin" }),
        );
        assert!(!lacks_caller_inputs(&admin, None, &HeaderMap::new()));
        assert!(!lacks_caller_inputs(
            &client_token_upstream(),
            None,
            &inbound(&[("x-token", "client-secret-1")])
        ));
    }

    /// The OAuth leg adds exactly `Authorization: Bearer <token>` — alone on
    /// an upstream declaring nothing, after the declared headers otherwise.
    #[test]
    fn an_oauth_upstream_sends_exactly_its_bearer() {
        let up = upstream(McpAuthMode::PerUserOauth, json!([]), json!({}));
        let mut auth = resolve_inputs(&up, None, &HeaderMap::new()).unwrap();
        push_oauth_token(&mut auth, &up, "oauth-access-token").unwrap();
        assert_eq!(
            sent(&auth),
            vec![("authorization".to_string(), "Bearer oauth-access-token".to_string())]
        );
        assert_eq!(auth.secrets().collect::<Vec<_>>(), vec!["oauth-access-token"]);

        let mut with_url = upstream(
            McpAuthMode::PerUserOauth,
            json!([one("X-Jira-Url", true, false)]),
            json!({ "X-Jira-Url": "admin" }),
        );
        with_url.encrypted_admin_inputs.insert("X-Jira-Url".into(), sealed("https://jira.example"));
        let mut auth = resolve_inputs(&with_url, None, &HeaderMap::new()).unwrap();
        push_oauth_token(&mut auth, &with_url, "oauth-access-token").unwrap();
        assert_eq!(
            sent(&auth),
            vec![
                ("x-jira-url".to_string(), "https://jira.example".to_string()),
                ("authorization".to_string(), "Bearer oauth-access-token".to_string()),
            ]
        );
        assert_matches!(
            push_oauth_token(&mut auth, &with_url, "bad\ntoken"),
            Err(UpstreamError::UserCredentialExpired)
        );
    }

    /// A request's memo decrypts an upstream's stored values once: a second
    /// resolve reads the first one's values. It is read only for the
    /// admin-input version and the user it was decrypted for.
    #[test]
    fn the_memo_decrypts_once_per_version_and_user() {
        let mut up = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true), one("X-User-Key", true, true)]),
            json!({ "X-Api-Key": "admin", "X-User-Key": "user" }),
        );
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), sealed("admin-one"));
        let alice = user_inputs(&up, &[("X-User-Key", "alice-key")]);
        let memo = InputsMemo::default();
        let none = HeaderMap::new();
        assert_eq!(sent(&memo.resolve(&up, Some(&alice), &none).unwrap())[0].1, "admin-one");

        // The same version: the memo's values, not the ciphertext's.
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), sealed("admin-two"));
        assert_eq!(sent(&memo.resolve(&up, Some(&alice), &none).unwrap())[0].1, "admin-one");
        assert!(!memo.lacks_caller_inputs(&up, Some(&alice), &none));
        // Without the memo, every resolve decrypts.
        assert_eq!(sent(&resolve_inputs(&up, Some(&alice), &none).unwrap())[0].1, "admin-two");

        // A new admin-input version is decrypted again.
        up.cred_version += 1;
        assert_eq!(sent(&memo.resolve(&up, Some(&alice), &none).unwrap())[0].1, "admin-two");

        // Another user's values are never the memo's.
        let bob = user_inputs(&up, &[("X-User-Key", "bob-key")]);
        assert_eq!(sent(&memo.resolve(&up, Some(&bob), &none).unwrap())[1].1, "bob-key");
        assert_matches!(memo.resolve(&up, None, &none), Err(UpstreamError::UserInputsMissing));
    }

    /// A set that did not decrypt on a quiet check is decrypted again by the
    /// call, which reports (and logs) it as before; a quiet check reads the
    /// memo's failure.
    #[test]
    fn the_memo_decrypts_a_failed_set_again_on_the_call() {
        let mut up = upstream(
            McpAuthMode::Headers,
            json!([one("X-Api-Key", true, true)]),
            json!({ "X-Api-Key": "admin" }),
        );
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), "not-a-ciphertext".into());
        let memo = InputsMemo::default();
        let none = HeaderMap::new();
        assert_matches!(memo.resolve_quiet(&up, None, &none), Err(UpstreamError::CredentialUnavailable));
        up.encrypted_admin_inputs.insert("X-Api-Key".into(), sealed("admin-one"));
        assert_matches!(memo.resolve_quiet(&up, None, &none), Err(UpstreamError::CredentialUnavailable));
        assert_eq!(sent(&memo.resolve(&up, None, &none).unwrap())[0].1, "admin-one");
    }

    #[test]
    fn the_fingerprint_moves_with_the_admin_version_and_the_users_values() {
        let mut up = client_token_upstream();
        let mine = user_inputs(&up, &[("X-User-Key", "a")]);
        let none = HeaderMap::new();
        let base = inputs_fingerprint(&up, Some(&mine), None, &none);
        assert_eq!(base, inputs_fingerprint(&up, Some(&mine), None, &none));
        assert_ne!(base, inputs_fingerprint(&up, None, None, &none));
        let mut changed = mine.clone();
        changed.encrypted_values.insert("X-User-Key".into(), sealed("b"));
        assert_ne!(base, inputs_fingerprint(&up, Some(&changed), None, &none));
        // A client's own token is part of it; an undeclared header is not.
        let declared = client_header_names(&up);
        let token = HeaderName::from_bytes(declared[0].as_bytes()).unwrap();
        let mut a = HeaderMap::new();
        a.insert(token.clone(), "client-a".parse().unwrap());
        let mut b = HeaderMap::new();
        b.insert(token, "client-b".parse().unwrap());
        assert_ne!(inputs_fingerprint(&up, Some(&mine), None, &a), inputs_fingerprint(&up, Some(&mine), None, &b));
        let mut noise = a.clone();
        noise.insert(HeaderName::from_static("x-undeclared"), "n".parse().unwrap());
        assert_eq!(inputs_fingerprint(&up, Some(&mine), None, &a), inputs_fingerprint(&up, Some(&mine), None, &noise));
        // The stored OAuth credential is part of it: a reconnect moves it.
        let cred = |token: &str| streamscope_core::config::mcp::McpUserCredential {
            tenant_id: up.tenant_id,
            user_id: Uuid::new_v4(),
            upstream_server_id: up.id,
            encrypted_access_token: sealed(token),
            encrypted_refresh_token: None,
            expires_at: None,
            scope: None,
        };
        let (old, new) = (cred("old-account"), cred("new-account"));
        assert_ne!(
            inputs_fingerprint(&up, Some(&mine), Some(&old), &none),
            inputs_fingerprint(&up, Some(&mine), Some(&new), &none)
        );
        assert_eq!(
            inputs_fingerprint(&up, Some(&mine), Some(&old), &none),
            inputs_fingerprint(&up, Some(&mine), Some(&old), &none)
        );
        up.cred_version += 1;
        assert_ne!(base, inputs_fingerprint(&up, Some(&mine), None, &none));
    }
}
