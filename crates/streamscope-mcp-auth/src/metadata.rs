//! RFC 9728 (Protected Resource Metadata) and RFC 8414 (Authorization Server
//! Metadata) response types.
//!
//! These structs are serialized verbatim by the proxy's `/.well-known/...`
//! handlers. Field naming uses serde rename so the on-the-wire JSON matches
//! the spec without manual `serde_json::Value` shuffling.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// -----------------------------------------------------------------------------
// RFC 9728 — OAuth 2.0 Protected Resource Metadata
// -----------------------------------------------------------------------------

/// Body of `GET /.well-known/oauth-protected-resource/<resource_path>`.
///
/// The MCP handler returns 401 + `WWW-Authenticate: Bearer
/// resource_metadata="<this URL>"` when an unauthenticated request hits an
/// OAuth-enabled virtual server. The client fetches this document to learn
/// which authorization server can mint a valid bearer.
///
/// We populate only the fields the spec mandates. The client is free to ignore
/// fields it doesn't recognize.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProtectedResourceMetadata {
    /// Canonical resource URI — exactly the audience the client must request
    /// in its `resource` parameter (RFC 8707) and that we'll mint into the
    /// `aud` claim.
    pub resource: String,

    /// Authorization servers that can mint bearers for this resource. We
    /// return exactly one — the proxy's per-tenant AS.
    pub authorization_servers: Vec<String>,

    /// We accept the bearer in the `Authorization: Bearer <token>` header.
    pub bearer_methods_supported: Vec<String>,

    /// We sign access tokens for this resource with ES256. A holder that wants
    /// to verify one locally fetches the authorization server's `jwks_uri` and
    /// selects the key by the token's `kid`.
    pub resource_signing_alg_values_supported: Vec<String>,

    /// Every scope a client may request for this resource. A client following
    /// least privilege picks the narrowest entry that covers what it intends to
    /// do; one that asks for nothing receives full access.
    pub scopes_supported: Vec<String>,
}

// -----------------------------------------------------------------------------
// RFC 8414 — OAuth 2.0 Authorization Server Metadata
// -----------------------------------------------------------------------------

/// Body of `GET /.well-known/oauth-authorization-server` for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier — the URL that prefixes our /authorize and /token
    /// endpoints, and the exact string our authorization responses echo back as
    /// the RFC 9207 `iss` parameter. Clients compare the two byte for byte.
    pub issuer: String,

    pub authorization_endpoint: String,
    pub token_endpoint: String,

    /// RFC 7591 dynamic client registration endpoint. Optional in the spec but
    /// always present here so MCP clients that prefer DCR over manual
    /// registration can discover it without out-of-band setup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// RFC 7009 token-revocation endpoint. Both first-party surfaces publish
    /// one; the field stays optional because the type describes the wire
    /// format, not our deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// RFC 8628 device-authorization endpoint. Present only on surfaces that
    /// support the device grant (the CLI provisioning surface — headless
    /// logins); the MCP surface omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,

    /// RFC 8414 `jwks_uri` — where this authorization server publishes the
    /// public keys that verify the tokens it issues.
    ///
    /// Present only on surfaces whose tokens are asymmetrically signed, which
    /// today is the MCP surface alone. Advertising it elsewhere would promise a
    /// verification path that does not exist: the CLI surface's access tokens
    /// are HS256 and are only ever presented back to us.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub scopes_supported: Vec<String>,

    /// Whether we support the RFC 8707 `resource` parameter on /authorize and
    /// /token. Always `true`.
    pub resource_parameter_supported: bool,

    /// Whether the authorization server accepts URL-formatted `client_id`
    /// values that resolve to a JSON metadata document
    /// ([draft-ietf-oauth-client-id-metadata-document-00]). Per MCP 2025-11-25
    /// § Authorization, clients SHOULD prefer CIMD over Dynamic Client
    /// Registration when this flag is `true` — so it must never be advertised
    /// unless the authorization endpoint really does accept a URL, or a
    /// conforming client picks the path that fails.
    pub client_id_metadata_document_supported: bool,

    /// Streamscope extension (CLI surface only): the public origin of the
    /// canonical admin-API, where the token/portal endpoints live. Possibly
    /// distinct from the browser-facing origin serving
    /// `authorization_endpoint` — admin-UI and admin-API are separate vhosts
    /// on every production deploy shape, and the discovery document itself
    /// may be fetched through the UI origin's GET-only passthrough. The
    /// `ssai` CLI directs every API call here after discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_origin: Option<String>,

    /// RFC 9207 §3. **Load-bearing when true**: the parameter defaults to
    /// `false` when the field is absent, and a conformant client keys its
    /// validation on this flag — so a server that emits `iss` without
    /// advertising it has built a protection nobody checks.
    pub authorization_response_iss_parameter_supported: bool,
}

// -----------------------------------------------------------------------------
// RFC 7517 — JSON Web Key Set
// -----------------------------------------------------------------------------

/// One public key in the set published at `jwks_uri`.
///
/// Only the shape we actually publish: a P-256 verification key. Every field is
/// mandatory on the wire because every field is one a verifier needs to select
/// and use the key, so `Option` would only describe documents we never emit.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JsonWebKey {
    /// Key type. Always `EC`.
    pub kty: String,
    /// Curve. Always `P-256`.
    pub crv: String,
    /// Base64url (unpadded) big-endian affine x coordinate.
    pub x: String,
    /// Base64url (unpadded) big-endian affine y coordinate.
    pub y: String,
    /// Always `sig` — these keys verify signatures and nothing else.
    #[serde(rename = "use")]
    pub use_: String,
    /// Always `ES256`.
    pub alg: String,
    /// Matches the `kid` header of the tokens this key verifies, so a client
    /// selects by header rather than by trying each key in turn.
    pub kid: String,
}

/// Body of the `jwks_uri` document (RFC 7517 §5).
///
/// Carries the active signing key **and** any verify-only secondary, which is
/// what makes an `AUTH_SECRET` rotation invisible to clients: a token minted
/// before the rotation still names a key the set publishes, so a verifier that
/// re-fetches finds it rather than failing every signature for the overlap.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

// -----------------------------------------------------------------------------
// RFC 8707 audience helper
// -----------------------------------------------------------------------------

/// Build the canonical resource URI / RFC 8707 audience for a virtual server
/// slug.
///
/// `public_origin` is the proxy's externally-reachable URL (no trailing slash —
/// the helper handles that). For example, given `https://gw.example.com` and
/// slug `acme-tools`, returns `https://gw.example.com/mcp/acme-tools`.
///
/// The audience is the canonical identifier of the resource — it appears in
/// the protected-resource-metadata `resource` field, in the JWT `aud` claim,
/// and in the `WWW-Authenticate` challenge URL. Always lowercase, never
/// percent-encoded (slug regex restricts charset to `[a-z0-9-]`).
pub fn audience_for_slug(public_origin: &str, slug: &str) -> String {
    let trimmed = public_origin.trim_end_matches('/');
    format!("{trimmed}/mcp/{slug}")
}

// -----------------------------------------------------------------------------
// Scopes
// -----------------------------------------------------------------------------

/// Full access to the bound virtual server, and the scope granted when a client
/// asks for nothing narrower. Every other scope names a subset of it.
pub const IMPLICIT_SCOPE: &str = "mcp:invoke";

/// Enumerate the server's tools (`tools/list`).
pub const SCOPE_TOOLS_READ: &str = "mcp:tools.read";
/// Invoke a tool (`tools/call`) — the scope that can cause side effects.
pub const SCOPE_TOOLS_CALL: &str = "mcp:tools.call";
/// Enumerate and read resources, including templates and subscriptions.
pub const SCOPE_RESOURCES_READ: &str = "mcp:resources.read";
/// Enumerate and render prompts.
pub const SCOPE_PROMPTS_READ: &str = "mcp:prompts.read";

/// Every scope this authorization server will grant, most privileged first.
///
/// Advertised verbatim in both discovery documents, and the set `/authorize`
/// narrows a request against. **Append-only**: a client may hold a token naming
/// a scope indefinitely, so removing one silently widens or breaks it.
pub const SUPPORTED_SCOPES: &[&str] = &[
    IMPLICIT_SCOPE,
    SCOPE_TOOLS_READ,
    SCOPE_TOOLS_CALL,
    SCOPE_RESOURCES_READ,
    SCOPE_PROMPTS_READ,
];

/// What a granted token must carry to call a given method.
///
/// The two variants exist because "needs no scope" and "we have no rule for
/// this" must not collapse into one another — they are opposite answers, and a
/// single "list of permitted scopes" representation makes an empty list mean
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodScopeRule {
    /// Callable by any valid token, whatever its scope.
    Unrestricted,
    /// Callable by a token carrying any one of these scopes — or
    /// [`IMPLICIT_SCOPE`], which permits everything. An **empty** list is
    /// therefore "full access only".
    AnyOf(&'static [&'static str]),
}

/// The scope rule for a JSON-RPC method.
///
/// An **unrecognised method needs [`IMPLICIT_SCOPE`]**, which is the
/// fail-closed half of this map: the gateway passes methods it does not
/// classify through to an upstream best-effort, so a narrow token must not
/// reach one. A newly classified method gets an entry here; until it does, only
/// a full-access token can call it.
///
/// Lifecycle and transport methods are [`MethodScopeRule::Unrestricted`]: they
/// carry no server data, and gating them would break a client that legitimately
/// holds a narrow token, since it could not complete the handshake needed to
/// use that token at all.
pub fn scope_rule(method: &str) -> MethodScopeRule {
    match method {
        "initialize" | "ping" | "logging/setLevel" => MethodScopeRule::Unrestricted,
        m if m.starts_with("notifications/") => MethodScopeRule::Unrestricted,

        // MCP 2026-07-28 § Discovery. `server/discover` is the modern era's
        // `initialize`: it reports supported versions, capabilities and
        // identity, and a client MUST be able to reach it to learn what
        // version to speak. Gating it would strand a narrow token exactly
        // as gating `initialize` would — it could never complete the
        // discovery its own use depends on.
        "server/discover" => MethodScopeRule::Unrestricted,

        // MCP 2026-07-28 § Subscriptions. Opening the stream needs *a* read
        // scope; which notification types actually flow on it is narrowed
        // per type against these same rules when the subscription filter is
        // honored, so a tools-only token opens a stream that carries tool
        // list changes and nothing else. Listing every read scope here
        // rather than leaving it unclassified is what keeps a narrow token
        // from having to hold full access just to be told a list changed.
        "subscriptions/listen" => MethodScopeRule::AnyOf(&[
            SCOPE_TOOLS_READ,
            SCOPE_TOOLS_CALL,
            SCOPE_PROMPTS_READ,
            SCOPE_RESOURCES_READ,
        ]),

        // A call-only token still has to discover what it may call, so
        // `tools/list` accepts either tools scope.
        "tools/list" => MethodScopeRule::AnyOf(&[SCOPE_TOOLS_READ, SCOPE_TOOLS_CALL]),
        "tools/call" => MethodScopeRule::AnyOf(&[SCOPE_TOOLS_CALL]),

        "resources/list"
        | "resources/read"
        | "resources/templates/list"
        | "resources/subscribe"
        | "resources/unsubscribe" => MethodScopeRule::AnyOf(&[SCOPE_RESOURCES_READ]),

        "prompts/list" | "prompts/get" => MethodScopeRule::AnyOf(&[SCOPE_PROMPTS_READ]),

        // Argument autocompletion resolves against either a prompt or a
        // resource template, so holding either read scope is enough. Splitting
        // it by `ref` type would need the params, which no caller of this
        // function has — and the finer rule would buy little, since a
        // completion candidate is a subset of what the matching read returns.
        "completion/complete" => {
            MethodScopeRule::AnyOf(&[SCOPE_PROMPTS_READ, SCOPE_RESOURCES_READ])
        }

        _ => MethodScopeRule::AnyOf(&[]),
    }
}

/// Does a granted `scope` claim permit `method`?
///
/// On refusal, returns the scope to name in the `WWW-Authenticate` challenge so
/// the client knows what to ask for next (RFC 6750 §3.1).
pub fn scope_permits(granted: &str, method: &str) -> Result<(), &'static str> {
    let permitted = match scope_rule(method) {
        MethodScopeRule::Unrestricted => return Ok(()),
        MethodScopeRule::AnyOf(scopes) => scopes,
    };
    let ok = granted
        .split_whitespace()
        .any(|g| g == IMPLICIT_SCOPE || permitted.contains(&g));
    if ok {
        Ok(())
    } else {
        Err(permitted.first().copied().unwrap_or(IMPLICIT_SCOPE))
    }
}

/// Narrow a client's requested `scope` parameter to what this server grants
/// (RFC 6749 §3.3), preserving the order the client asked in.
///
/// `None` — the client asked for nothing — grants [`IMPLICIT_SCOPE`], which is
/// what keeps every client written before per-method scopes existed working
/// unchanged.
///
/// Returns `None` when the request named scopes but **none** were grantable:
/// that is `invalid_scope`, not an empty grant. Silently issuing a token with
/// no scope would hand the client a credential it will misread as sufficient.
pub fn narrow_requested_scopes(requested: Option<&str>) -> Option<String> {
    let Some(requested) = requested.filter(|s| s.split_whitespace().next().is_some()) else {
        return Some(IMPLICIT_SCOPE.to_string());
    };
    let mut granted: Vec<&str> = Vec::new();
    for want in requested.split_whitespace() {
        if SUPPORTED_SCOPES.contains(&want) && !granted.contains(&want) {
            granted.push(want);
        }
    }
    if granted.is_empty() {
        return None;
    }
    Some(granted.join(" "))
}

/// Build the protected-resource-metadata body for a given virtual server.
/// The proxy calls this from `/.well-known/oauth-protected-resource/mcp/<slug>`;
/// the admin API calls it from tests + introspection. Centralised here so the
/// `authorization_servers` URL is constructed in exactly one place.
/// `auth_server_origin` is the origin that actually serves the
/// `/api/v1/mcp/oauth/*` endpoints — the canonical admin-API origin on
/// split-vhost deploys, the admin/UI origin on co-resident installs (the
/// caller resolves which).
pub fn build_protected_resource_metadata(
    proxy_origin: &str,
    auth_server_origin: &str,
    tenant_slug: &str,
    vs_slug: &str,
) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: audience_for_slug(proxy_origin, vs_slug),
        authorization_servers: vec![format!(
            "{}/api/v1/mcp/oauth/{}",
            auth_server_origin.trim_end_matches('/'),
            tenant_slug
        )],
        bearer_methods_supported: vec!["header".to_string()],
        resource_signing_alg_values_supported: vec!["ES256".to_string()],
        scopes_supported: SUPPORTED_SCOPES.iter().map(|s| s.to_string()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_strips_trailing_slash() {
        assert_eq!(
            audience_for_slug("https://gw.example.com/", "acme"),
            "https://gw.example.com/mcp/acme"
        );
        assert_eq!(
            audience_for_slug("https://gw.example.com", "acme"),
            "https://gw.example.com/mcp/acme"
        );
    }

    #[test]
    fn full_access_permits_every_method() {
        for m in [
            "initialize",
            "tools/list",
            "tools/call",
            "resources/read",
            "prompts/get",
            "completion/complete",
            "some/method/we/have/never/seen",
        ] {
            assert_eq!(scope_permits(IMPLICIT_SCOPE, m), Ok(()), "{m}");
        }
    }

    #[test]
    fn a_narrow_scope_reaches_only_its_own_methods() {
        assert_eq!(scope_permits(SCOPE_TOOLS_CALL, "tools/call"), Ok(()));
        // A caller that may invoke tools must be able to enumerate them.
        assert_eq!(scope_permits(SCOPE_TOOLS_CALL, "tools/list"), Ok(()));
        // ...but read-only tools access must not reach the invoking method.
        assert_eq!(
            scope_permits(SCOPE_TOOLS_READ, "tools/call"),
            Err(SCOPE_TOOLS_CALL)
        );
        assert_eq!(
            scope_permits(SCOPE_TOOLS_CALL, "resources/read"),
            Err(SCOPE_RESOURCES_READ)
        );
        assert_eq!(
            scope_permits(SCOPE_RESOURCES_READ, "prompts/get"),
            Err(SCOPE_PROMPTS_READ)
        );
        // Space-separated grants are read as a set, not a string.
        let both = format!("{SCOPE_TOOLS_CALL} {SCOPE_PROMPTS_READ}");
        assert_eq!(scope_permits(&both, "prompts/get"), Ok(()));
        assert_eq!(scope_permits(&both, "resources/list"), Err(SCOPE_RESOURCES_READ));
    }

    /// Lifecycle methods stay open, or a narrow token could never complete the
    /// handshake that lets it use the scope it does hold.
    #[test]
    fn lifecycle_methods_need_no_scope() {
        for m in ["initialize", "ping", "logging/setLevel", "notifications/initialized"] {
            assert_eq!(scope_rule(m), MethodScopeRule::Unrestricted, "{m}");
            assert_eq!(scope_permits(SCOPE_PROMPTS_READ, m), Ok(()), "{m}");
        }
    }

    /// MCP 2026-07-28 § Discovery — `server/discover` replaces `initialize`
    /// and is reachable for the same reason: a client cannot learn which
    /// version to speak if discovery itself is gated behind a scope it may
    /// not hold.
    #[test]
    fn modern_discovery_needs_no_scope() {
        assert_eq!(scope_rule("server/discover"), MethodScopeRule::Unrestricted);
        for granted in [SCOPE_PROMPTS_READ, SCOPE_TOOLS_READ, SCOPE_RESOURCES_READ] {
            assert_eq!(scope_permits(granted, "server/discover"), Ok(()), "{granted}");
        }
    }

    /// Opening a notification stream needs *a* read scope, not full access —
    /// otherwise every narrowly-scoped modern client would have to hold
    /// `IMPLICIT_SCOPE` just to be told a list changed. Which notification
    /// types then flow is narrowed per type by the gateway.
    #[test]
    fn opening_a_notification_stream_needs_a_read_scope() {
        for granted in [
            SCOPE_TOOLS_READ,
            SCOPE_TOOLS_CALL,
            SCOPE_PROMPTS_READ,
            SCOPE_RESOURCES_READ,
        ] {
            assert_eq!(
                scope_permits(granted, "subscriptions/listen"),
                Ok(()),
                "{granted}"
            );
        }
        // Positive control's negative half: a token carrying no read scope at
        // all is still refused, so this is a narrowing rather than an opening.
        assert!(scope_permits("mcp:something-else", "subscriptions/listen").is_err());
    }

    /// The fail-closed half: an unclassified method passes through to an
    /// upstream best-effort, so a narrow token must not reach one.
    #[test]
    fn an_unclassified_method_needs_full_access() {
        assert_eq!(scope_rule("tasks/list"), MethodScopeRule::AnyOf(&[]));
        assert_eq!(
            scope_permits(SCOPE_TOOLS_CALL, "tasks/list"),
            Err(IMPLICIT_SCOPE)
        );
        assert_eq!(scope_permits(IMPLICIT_SCOPE, "tasks/list"), Ok(()));
    }

    /// A scope string is a set of whitespace-separated tokens, so a granted
    /// scope must never match by substring — `mcp:tools.call` must not be
    /// satisfied by something that merely contains it.
    #[test]
    fn scope_matching_is_by_token_not_substring() {
        assert_eq!(
            scope_permits("mcp:tools.callable", "tools/call"),
            Err(SCOPE_TOOLS_CALL)
        );
        assert_eq!(scope_permits("xmcp:invoke", "tools/call"), Err(SCOPE_TOOLS_CALL));
    }

    #[test]
    fn narrowing_keeps_grantable_scopes_and_drops_the_rest() {
        // No request at all is full access — what every pre-scopes client sends.
        assert_eq!(narrow_requested_scopes(None).as_deref(), Some(IMPLICIT_SCOPE));
        assert_eq!(narrow_requested_scopes(Some("   ")).as_deref(), Some(IMPLICIT_SCOPE));

        let asked = format!("{SCOPE_TOOLS_CALL} openid {SCOPE_PROMPTS_READ}");
        assert_eq!(
            narrow_requested_scopes(Some(&asked)).as_deref(),
            Some(format!("{SCOPE_TOOLS_CALL} {SCOPE_PROMPTS_READ}").as_str())
        );

        // Duplicates collapse rather than accumulating in the token.
        let dup = format!("{SCOPE_TOOLS_CALL} {SCOPE_TOOLS_CALL}");
        assert_eq!(narrow_requested_scopes(Some(&dup)).as_deref(), Some(SCOPE_TOOLS_CALL));

        // Nothing grantable is `invalid_scope`, NOT an empty grant.
        assert_eq!(narrow_requested_scopes(Some("openid profile")), None);
    }

    #[test]
    fn rfc9728_serialization_matches_field_names() {
        let m = ProtectedResourceMetadata {
            resource: "https://gw.example.com/mcp/x".to_string(),
            authorization_servers: vec!["https://gw.example.com/mcp/auth/acme".to_string()],
            bearer_methods_supported: vec!["header".to_string()],
            resource_signing_alg_values_supported: vec!["HS256".to_string()],
            scopes_supported: vec!["mcp:invoke".to_string()],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"resource\":"));
        assert!(s.contains("\"authorization_servers\":"));
        assert!(s.contains("\"bearer_methods_supported\":"));
        assert!(s.contains("\"resource_signing_alg_values_supported\":"));
        assert!(s.contains("\"scopes_supported\":"));
    }
}
