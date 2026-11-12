//! MCP gateway configuration — slugged virtual-server bundles + their routes
//! to upstream MCP servers. Synced verbatim from admin-api in the per-tenant
//! config snapshot WS push (see `streamscope_admin::edge_sync`).
//!
//! Shape mirrors the SQL tables created by migration 034:
//!
//! - [`McpUpstreamServer`] — one real MCP server we know how to talk to.
//! - [`McpVirtualServer`] — one slugged bundle exposed at `/mcp/<slug>`.
//! - [`McpVirtualRoute`] — fan-in entry: upstream + namespace prefix +
//!   per-route allow/deny filters.
//!
//! The proxy looks up by slug to resolve `(virtual_server, [routes])`, then
//! the MCP handler walks each route in turn (capability merge, namespace
//! strip-and-stamp, JSON-RPC dispatch).

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::mcp::header_inputs;

/// Transport currently spoken to the upstream MCP server. Only
/// `streamable_http` is honored; `sse` rejects with
/// `mcp_transport_unsupported` (legacy fallback is not wired).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    #[default]
    StreamableHttp,
    Sse,
}

/// Authentication mode at the upstream.
///
/// - `Headers`: only the headers the remote declares (none = no auth), each
///   filled by the admin, the user or the client
///   ([`crate::mcp::header_inputs`]).
/// - `PerUserOauth`: the same declared headers, plus the user's OAuth token as
///   `Authorization: Bearer`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAuthMode {
    #[default]
    Headers,
    PerUserOauth,
}

impl McpAuthMode {
    /// Parse the stored value. `None` for anything else: the caller disables
    /// the upstream rather than guess (fail closed).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "headers" => Some(Self::Headers),
            "per_user_oauth" => Some(Self::PerUserOauth),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Headers => "headers",
            Self::PerUserOauth => "per_user_oauth",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpUpstreamServer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub upstream_url: String,
    #[serde(default)]
    pub transport: McpTransport,
    #[serde(default)]
    pub auth_mode: McpAuthMode,
    #[serde(default)]
    pub cred_version: i64,
    /// AES-256-GCM ciphertext, base64-encoded (matches `crypto::encrypt`
    /// output). Set only on the built-in web upstream, where it holds the
    /// search backend's API key; it is never upstream auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_credential: Option<String>,
    /// The adopted `server.json` remote: its declared headers and, in its
    /// `_meta`, each input's filler. `upstream_url` is its finished URL.
    #[serde(default)]
    pub remote: header_inputs::Remote,
    /// Admin-filled input id → AES-256-GCM ciphertext (base64), one per input.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub encrypted_admin_inputs: HashMap<String, String>,

    // ── Per-user OAuth client config ──
    // Populated when `auth_mode = PerUserOauth`. The portal initiates the
    // OAuth dance against `oauth_authorization_url`; tokens are exchanged at
    // `oauth_token_url`; revoke calls (best-effort) hit `oauth_revocation_url`.
    // `oauth_issuer_url` is the authorization server's identifier. It links
    // from the admin/portal UI, and — load-bearing — it is what a returned
    // RFC 9207 `iss` is validated against on the connect callback, which is
    // the check that closes the OAuth mix-up attack. Leaving it unset costs
    // that defence, so discovery fills it in and a hand-configured upstream
    // should carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_revocation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
    /// AES-256-GCM ciphertext (base64-encoded UTF-8 bytes, same shape as
    /// `encrypted_credential`). Decrypted at request time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_oauth_client_secret: Option<String>,
    /// Default scopes requested at the IdP. Operator-configured; the portal
    /// connect flow ships them verbatim into the authorization URL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth_default_scopes: Vec<String>,

    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: i32,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: i32,
    /// The validated declaration of `remote` under `auth_mode`, filled on
    /// first use. Built with `Default::default()`; read only through
    /// [`McpUpstreamServer::input_specs`].
    #[serde(skip)]
    pub input_specs_cache: InputSpecsCache,
}

/// What [`header_inputs::validate_fillers`] returned for an upstream's
/// `remote` and `auth_mode`, kept beside the copy of both it was computed
/// from. The cell is shared by every clone — filled or not — so every request
/// cloning an upstream out of one config snapshot fills and reads the same
/// validation.
#[derive(Clone, Default)]
pub struct InputSpecsCache(Arc<OnceLock<CachedInputSpecs>>);

struct CachedInputSpecs {
    auth_mode: McpAuthMode,
    remote: header_inputs::Remote,
    specs: Result<Vec<header_inputs::InputSpec>, header_inputs::RemoteError>,
}

impl std::fmt::Debug for InputSpecsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.get().is_some() { "InputSpecsCache(filled)" } else { "InputSpecsCache(empty)" })
    }
}

impl McpUpstreamServer {
    /// The upstream's input specs: [`header_inputs::validate_fillers`] over
    /// its `remote`, with `Authorization` reserved when `auth_mode` is
    /// `per_user_oauth`. Validated once and kept; an entry computed from a
    /// `remote` or `auth_mode` the struct no longer holds is never returned —
    /// the specs are then validated afresh (and not kept), so a mutated
    /// struct can never read a stale declaration.
    pub fn input_specs(
        &self,
    ) -> Cow<'_, Result<Vec<header_inputs::InputSpec>, header_inputs::RemoteError>> {
        let oauth = self.auth_mode == McpAuthMode::PerUserOauth;
        let cached = self.input_specs_cache.0.get_or_init(|| CachedInputSpecs {
            auth_mode: self.auth_mode,
            remote: self.remote.clone(),
            specs: header_inputs::validate_fillers(&self.remote, oauth),
        });
        if cached.auth_mode == self.auth_mode && cached.remote == self.remote {
            Cow::Borrowed(&cached.specs)
        } else {
            Cow::Owned(header_inputs::validate_fillers(&self.remote, oauth))
        }
    }

    /// [`header_inputs::resolve`] for this upstream, over its kept specs.
    pub fn resolve_inputs(
        &self,
        values: header_inputs::InputValues<'_>,
    ) -> Result<header_inputs::UpstreamAuth, header_inputs::ResolveError> {
        match &*self.input_specs() {
            Ok(specs) => header_inputs::resolve_validated(&self.remote, specs, values),
            Err(e) => Err(header_inputs::ResolveError::Declaration(e.clone())),
        }
    }
}

/// Per-user OAuth credential — one ciphertext blob per (tenant, user, upstream)
/// pair. Synced to the proxy in the per-tenant snapshot so the dispatcher can
/// resolve a user's bearer token at request time without a round-trip.
///
/// All token fields are AES-256-GCM ciphertext (base64-encoded UTF-8 bytes,
/// same shape as `McpUpstreamServer::encrypted_credential`). The proxy
/// decrypts on-use with the process `ENCRYPTION_KEY`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpUserCredential {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub upstream_server_id: Uuid,
    pub encrypted_access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// One user's filled inputs for one upstream: input id → AES-256-GCM
/// ciphertext (base64). Only the user-filled ids of the upstream's
/// declaration are read from it ([`crate::mcp::header_inputs::resolve`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpUserInputs {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub upstream_server_id: Uuid,
    pub encrypted_values: HashMap<String, String>,
}

fn default_true() -> bool { true }
fn default_connect_timeout() -> i32 { 10000 }
fn default_request_timeout() -> i32 { 60000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpVirtualServer {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub slug: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MCP 2025-11-25 `serverInfo.title` — display-friendly variant of
    /// `name`. When `None`, the gateway's `initialize` response omits the
    /// field (client falls back to `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_title: Option<String>,
    /// MCP 2025-11-25 `serverInfo.websiteUrl` — optional URL the client may
    /// surface to users. Stamped on `initialize` when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// When true, this virtual server accepts spec-compliant OAuth
    /// JWT bearers in addition to `sk-*` keys. Unauthenticated requests get
    /// `WWW-Authenticate: Bearer resource_metadata=...` (RFC 9728) so MCP
    /// clients can discover our authorization server.
    #[serde(default)]
    pub oauth_enabled: bool,
    /// When `Some`, server-initiated `sampling/createMessage` calls on this
    /// virtual server are intercepted and answered by the proxy via a
    /// loopback into `/v1/messages`, instead of being forwarded to the
    /// connected agent. `None` preserves legacy forward-to-agent behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_intercept: Option<SamplingInterceptConfig>,
}

/// Per-virtual-server sampling intercept configuration. Present iff the
/// `sampling_intercept_enabled` master toggle is true AND both the
/// credential and model alias are set; the admin handler validates this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingInterceptConfig {
    /// AES-256-GCM ciphertext (base64-encoded UTF-8 bytes, same shape as
    /// `McpUpstreamServer::encrypted_credential`). Decrypted at request time
    /// to obtain the LLM-family bearer token used for the loopback.
    pub encrypted_credential: String,
    /// Model alias to request on the synthetic `/v1/messages` call (e.g.
    /// `claude-default`). Resolved by the normal LLM router on the loopback.
    pub model_alias: String,
}

/// Per-route allow/deny over tool / resource / prompt names. `allow` wins
/// when set; `deny` is applied to the allow set. `None` = pass-through.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpRouteFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
}

impl McpRouteFilter {
    /// Returns true if `name` is permitted by this filter.
    pub fn permits(&self, name: &str) -> bool {
        if let Some(allow) = &self.allow
            && !allow.iter().any(|n| n == name)
        {
            return false;
        }
        if let Some(deny) = &self.deny
            && deny.iter().any(|n| n == name)
        {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpVirtualRoute {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub virtual_server_id: Uuid,
    pub upstream_server_id: Uuid,
    /// Empty string = no namespacing (only on a virtual server's first route;
    /// prefixed routes may be added beside it).
    #[serde(default)]
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_filter: Option<McpRouteFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_filter: Option<McpRouteFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts_filter: Option<McpRouteFilter>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub position: i32,
}

/// Per-tenant MCP config snapshot — collated upstream servers + virtual
/// servers + routes, indexed for the proxy's hot path. Built at config
/// snapshot time; the proxy looks up by slug.
#[derive(Debug, Clone, Default)]
pub struct McpConfig {
    pub upstream_servers: HashMap<Uuid, McpUpstreamServer>,
    pub virtual_servers: HashMap<Uuid, McpVirtualServer>,
    /// `slug -> virtual_server_id` for `/mcp/<slug>` lookup.
    pub virtual_server_by_slug: HashMap<String, Uuid>,
    /// `virtual_server_id -> [routes]` ordered by `position` ASC, `id` tiebreaker.
    pub routes_by_virtual_server: HashMap<Uuid, Vec<McpVirtualRoute>>,
    /// `(user_id, upstream_server_id) -> credential` lookup for the per-user
    /// OAuth dispatcher. Disabled upstreams are dropped on entry
    /// (mirrors `routes_by_virtual_server`'s "drop dependent rows" semantics).
    pub user_credentials: HashMap<(Uuid, Uuid), McpUserCredential>,
    /// `(user_id, upstream_server_id) -> filled inputs`. Like
    /// `user_credentials`, rows of disabled upstreams are dropped.
    pub user_inputs: HashMap<(Uuid, Uuid), McpUserInputs>,
    /// Set of revoked or expired-but-recently-issued JWT `jti`s.
    /// The MCP handler rejects requests with a JWT bearer whose `jti` lives
    /// in this set. Populated by config sync from MCP-surface
    /// `oauth_issued_tokens WHERE revoked_at IS NOT NULL` for tokens not yet
    /// past `expires_at + slop`.
    pub revoked_jtis: std::collections::HashSet<Uuid>,
    /// The tenant's ES256 public keys — every generation that can verify a live
    /// MCP access token, as admin-api derived them at snapshot-build time.
    ///
    /// **This is the proxy's only source of MCP token verification keys.** The
    /// data plane holds no signing secret, so a token whose `kid` names a
    /// generation absent from this list is rejected; there is deliberately no
    /// fallback to a locally derived key. Two consequences to preserve:
    ///
    /// * The list must carry **every** generation on admin-api's ring, not just
    ///   the active one, or a token minted before a rotation stops verifying the
    ///   moment the snapshot lands.
    /// * A snapshot is the *only* thing that retires a key here. The proxy also
    ///   restores its last snapshot from disk at boot, so a generation an
    ///   operator has dropped keeps verifying until a fresh snapshot arrives —
    ///   which is why admin-api re-pushes every tenant when its ring changes.
    pub jwks: Vec<streamscope_mcp_auth::metadata::JsonWebKey>,
    /// `prefix → upstream_server_name` index built from
    /// `routes_by_virtual_server`. Surfaces every non-empty namespace prefix
    /// the tenant has wired up so the LLM proxy can recognise a virtual-prefixed
    /// tool a client DECLARES on a request (`gh__create_issue`) and resolve it
    /// through the field-profile registry as if it had arrived through the MCP
    /// path. Model-emitted tool calls do not consult it.
    ///
    /// Empty prefixes (routes without namespacing) are excluded — they'd
    /// collide with bare upstream tool names.
    ///
    /// Ambiguity policy: when two routes share a prefix (across virtual
    /// servers, with different upstream names), we keep the lowest-id
    /// route's upstream — the LLM proxy is best-effort here, the MCP path is
    /// the authoritative resolution. Operators who care should keep prefixes
    /// unique within a tenant.
    pub virtual_prefix_index: HashMap<String, String>,
}

/// The route prefixes a virtual server accepts: empty, or at most 16 of
/// `a-z`, `0-9` and `_`, starting with a letter, with no `__` and no trailing
/// `_`. Those last two make every stamped name `<prefix>__<local>` split
/// exactly: the first `__` in it is always the separator, whatever `__` the
/// upstream's own name carries. Shared by the admin (which refuses anything
/// else) and the tests that hold [`split_route_prefix`] to it.
pub fn is_valid_route_prefix(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    s.len() <= 16
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !s.ends_with('_')
        && !s.contains("__")
}

/// Split a wire name stamped `<prefix>__<local>` at its first `__` when the
/// text before it is a configured prefix (`is_prefix`) and the local name is
/// not empty. Exact for every prefix [`is_valid_route_prefix`] accepts: such a
/// prefix holds no `__` and cannot end in `_`, so the first `__` of the
/// stamped name is the one the stamp added (locked by
/// `a_stamped_name_splits_back_exactly`). Returns `None` otherwise; the caller
/// then treats the whole name as un-prefixed.
pub fn split_route_prefix(
    name: &str,
    is_prefix: impl Fn(&str) -> bool,
) -> Option<(&str, &str)> {
    let (prefix, local) = name.split_once("__")?;
    (!prefix.is_empty() && !local.is_empty() && is_prefix(prefix)).then_some((prefix, local))
}

/// The route a stamped tool/prompt name belongs to on a virtual server whose
/// routes carry `prefixes` (`""` for its empty-prefix route), and the name the
/// upstream knows it by. A name whose first `__` follows one of the prefixes
/// splits onto that route ([`split_route_prefix`]); any other name belongs to
/// the empty-prefix route, untouched — which is what lets an upstream name its
/// own tools with `__` (`aws___search_documentation`). A name that starts with
/// some prefix's `<prefix>__` without splitting onto it (a prefix that ends in
/// `_` or holds `__`, or the empty name `gh__`) is no route's: it is never
/// handed to the empty-prefix upstream instead. Both the proxy's dispatch and
/// the portal's catalog preview decide through this one function (locked by
/// `a_name_resolves_to_its_own_prefix_or_to_no_prefix_any_other_claims`).
pub fn resolve_route_prefix<'n>(name: &'n str, prefixes: &[&str]) -> Option<(&'n str, &'n str)> {
    if let Some(split) = split_route_prefix(name, |p| prefixes.contains(&p)) {
        return Some(split);
    }
    let claimed = prefixes.iter().any(|p| {
        !p.is_empty() && name.strip_prefix(p).is_some_and(|rest| rest.starts_with("__"))
    });
    (!claimed && prefixes.contains(&"")).then_some(("", name))
}

/// Whether a name the route on `listing_prefix` advertises routes back to that
/// route — the condition for advertising it at all, so every listed name is
/// one a call reaches the advertising upstream with.
pub fn routes_back_to(name: &str, prefixes: &[&str], listing_prefix: &str) -> bool {
    resolve_route_prefix(name, prefixes).is_some_and(|(p, _)| p == listing_prefix)
}

impl McpConfig {
    /// Build from raw lists. Only enabled rows are indexed.
    pub fn from_rows(
        upstream_servers: Vec<McpUpstreamServer>,
        virtual_servers: Vec<McpVirtualServer>,
        virtual_routes: Vec<McpVirtualRoute>,
    ) -> Self {
        Self::from_rows_with_credentials(upstream_servers, virtual_servers, virtual_routes, vec![])
    }

    /// Build with an additional `user_credentials` slice.
    pub fn from_rows_with_credentials(
        upstream_servers: Vec<McpUpstreamServer>,
        virtual_servers: Vec<McpVirtualServer>,
        virtual_routes: Vec<McpVirtualRoute>,
        user_credentials: Vec<McpUserCredential>,
    ) -> Self {
        let upstream_servers: HashMap<Uuid, McpUpstreamServer> = upstream_servers
            .into_iter()
            .filter(|u| u.enabled)
            .map(|u| (u.id, u))
            .collect();

        let mut virtual_server_by_slug = HashMap::new();
        let virtual_servers: HashMap<Uuid, McpVirtualServer> = virtual_servers
            .into_iter()
            .filter(|v| v.enabled)
            .map(|v| {
                virtual_server_by_slug.insert(v.slug.clone(), v.id);
                (v.id, v)
            })
            .collect();

        let mut routes_by_virtual_server: HashMap<Uuid, Vec<McpVirtualRoute>> = HashMap::new();
        for route in virtual_routes {
            if !route.enabled {
                continue;
            }
            // Drop routes whose virtual server or upstream is missing/disabled.
            if !virtual_servers.contains_key(&route.virtual_server_id) {
                continue;
            }
            if !upstream_servers.contains_key(&route.upstream_server_id) {
                continue;
            }
            routes_by_virtual_server
                .entry(route.virtual_server_id)
                .or_default()
                .push(route);
        }
        for routes in routes_by_virtual_server.values_mut() {
            routes.sort_by(|a, b| a.position.cmp(&b.position).then(a.id.cmp(&b.id)));
        }

        // Index credentials only for upstreams that survived the enabled filter.
        let user_credentials: HashMap<(Uuid, Uuid), McpUserCredential> = user_credentials
            .into_iter()
            .filter(|c| upstream_servers.contains_key(&c.upstream_server_id))
            .map(|c| ((c.user_id, c.upstream_server_id), c))
            .collect();

        // Collect non-empty prefix → upstream-name pairs, ordered
        // by route id so collisions resolve deterministically.
        let mut prefix_pairs: Vec<(String, String, Uuid)> = Vec::new();
        for routes in routes_by_virtual_server.values() {
            for r in routes {
                if r.prefix.is_empty() {
                    continue;
                }
                let Some(upstream) = upstream_servers.get(&r.upstream_server_id) else {
                    continue;
                };
                prefix_pairs.push((r.prefix.clone(), upstream.name.clone(), r.id));
            }
        }
        prefix_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        let mut virtual_prefix_index: HashMap<String, String> = HashMap::new();
        for (prefix, name, route_id) in prefix_pairs {
            match virtual_prefix_index.entry(prefix.clone()) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(existing) => {
                    if existing.get() != &name {
                        tracing::warn!(
                            prefix = %prefix,
                            kept_upstream = %existing.get(),
                            ignored_upstream = %name,
                            ignored_route_id = %route_id,
                            "MCP virtual prefix collision — multiple routes share the same prefix; LLM-side resolution is best-effort and picks the lowest route id. Make prefixes unique within a tenant for deterministic LLM-path routing."
                        );
                    }
                }
            }
        }

        Self {
            upstream_servers,
            virtual_servers,
            virtual_server_by_slug,
            routes_by_virtual_server,
            user_credentials,
            user_inputs: HashMap::new(),
            revoked_jtis: std::collections::HashSet::new(),
            jwks: Vec::new(),
            virtual_prefix_index,
        }
    }

    /// Recognise a tool a client DECLARES on an LLM request under a tenant-
    /// configured virtual server prefix. Returns `(local_name, mcp_server)`
    /// when `<name>` splits as `<prefix>__<local>` ([`split_route_prefix`])
    /// and `<prefix>` is in the index. The mcp_server return value is the
    /// upstream's `name`, suitable to feed straight into
    /// [`crate::config::tool_rules::FieldProfileSet`] for `tool_id` resolution.
    ///
    /// Returns `None` for un-prefixed names AND for names whose prefix isn't
    /// configured. Callers try [`crate::config::tool_rules::parse_mcp_namespace`]
    /// (the `mcp__<server>__<local>` convention) first, then this; model-emitted
    /// tool calls and tool results consult only the former.
    pub fn parse_virtual_namespace<'a>(
        &self,
        tool_name: &'a str,
    ) -> Option<(&'a str, &str)> {
        let (prefix, local) =
            split_route_prefix(tool_name, |p| self.virtual_prefix_index.contains_key(p))?;
        let upstream_name = self.virtual_prefix_index.get(prefix)?;
        Some((local, upstream_name.as_str()))
    }

    /// Lookup a user's credential for a given upstream. Returns `None` when
    /// no credential is stored (the user has never connected) or the upstream
    /// is disabled.
    pub fn user_credential(
        &self,
        user_id: Uuid,
        upstream_id: Uuid,
    ) -> Option<&McpUserCredential> {
        self.user_credentials.get(&(user_id, upstream_id))
    }

    /// Index the users' filled inputs, keeping only rows of indexed upstreams.
    pub fn set_user_inputs(&mut self, rows: Vec<McpUserInputs>) {
        self.user_inputs = rows
            .into_iter()
            .filter(|r| self.upstream_servers.contains_key(&r.upstream_server_id))
            .map(|r| ((r.user_id, r.upstream_server_id), r))
            .collect();
    }

    /// A user's filled inputs for an upstream.
    pub fn user_inputs(&self, user_id: Uuid, upstream_id: Uuid) -> Option<&McpUserInputs> {
        self.user_inputs.get(&(user_id, upstream_id))
    }

    /// Resolve `/mcp/<slug>` to `(virtual_server, routes)`.
    pub fn lookup_by_slug(&self, slug: &str) -> Option<(&McpVirtualServer, &[McpVirtualRoute])> {
        let id = self.virtual_server_by_slug.get(slug)?;
        let vs = self.virtual_servers.get(id)?;
        let routes = self
            .routes_by_virtual_server
            .get(id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        Some((vs, routes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Uuid { Uuid::new_v4() }

    /// An upstream read the way a snapshot reads one, declaring one
    /// `Authorization` header filled by `filler`.
    fn declaring_authorization(auth_mode: &str, filler: &str) -> McpUpstreamServer {
        serde_json::from_value(serde_json::json!({
            "id": id(), "tenant_id": id(), "name": "u", "upstream_url": "https://up.example/mcp",
            "auth_mode": auth_mode,
            "remote": {
                "type": "streamable-http", "url": "https://up.example/mcp",
                "headers": [{ "name": "Authorization", "isRequired": true, "isSecret": true }],
                "_meta": { "ai.streamscope/inputs": { "fillers": { "Authorization": filler } } },
            },
        }))
        .unwrap()
    }

    /// The specs are validated once and shared by every clone; an entry is
    /// never read for a `remote` or `auth_mode` the struct no longer holds.
    #[test]
    fn kept_input_specs_always_match_the_remote_and_auth_mode() {
        use std::borrow::Cow;
        let up = declaring_authorization("headers", "admin");
        // A clone taken BEFORE the first read shares the cell too: the proxy
        // clones upstreams out of the snapshot per request.
        let early = up.clone();
        let first = up.input_specs();
        let Cow::Borrowed(first) = first else { panic!("a filled entry is borrowed") };
        assert_eq!(first, &header_inputs::validate_fillers(&up.remote, false));
        assert!(first.is_ok());
        let again = up.input_specs();
        assert!(matches!(again, Cow::Borrowed(r) if std::ptr::eq(r, first)), "validated once");
        let copy = up.clone();
        assert!(matches!(copy.input_specs(), Cow::Borrowed(r) if std::ptr::eq(r, first)), "a clone shares it");
        assert!(matches!(early.input_specs(), Cow::Borrowed(r) if std::ptr::eq(r, first)), "an earlier clone shares it");

        // `Authorization` is the token's on an OAuth upstream: the same remote
        // under the other mode validates differently, and is read so.
        let mut oauth = up.clone();
        oauth.auth_mode = McpAuthMode::PerUserOauth;
        assert_eq!(
            *oauth.input_specs(),
            Err(header_inputs::RemoteError::ReservedForOauth)
        );
        let mut client = up.clone();
        client.remote = declaring_authorization("headers", "client").remote;
        let specs = client.input_specs();
        assert_eq!(specs.as_deref().unwrap()[0].filler, header_inputs::Filler::Client);
        // The original still reads its own entry.
        assert_eq!(up.input_specs().as_deref().unwrap()[0].filler, header_inputs::Filler::Admin);
    }

    #[test]
    fn permits_with_allow_wins() {
        let f = McpRouteFilter {
            allow: Some(vec!["a".into(), "b".into()]),
            deny: None,
        };
        assert!(f.permits("a"));
        assert!(!f.permits("c"));
    }

    #[test]
    fn permits_with_deny_subtracts() {
        let f = McpRouteFilter {
            allow: Some(vec!["a".into(), "b".into()]),
            deny: Some(vec!["b".into()]),
        };
        assert!(f.permits("a"));
        assert!(!f.permits("b"));
        assert!(!f.permits("c"));
    }

    #[test]
    fn lookup_by_slug_only_returns_enabled() {
        let tenant_id = id();
        let vs_id = id();
        let up_id = id();
        let cfg = McpConfig::from_rows(
            vec![McpUpstreamServer {
                id: up_id, tenant_id, name: "u".into(), description: None,
                upstream_url: "http://u".into(), transport: McpTransport::StreamableHttp,
                auth_mode: McpAuthMode::Headers, cred_version: 1,
                encrypted_credential: None, remote: Default::default(),
                encrypted_admin_inputs: HashMap::new(),
                oauth_issuer_url: None, oauth_authorization_url: None,
                oauth_token_url: None, oauth_revocation_url: None,
                oauth_client_id: None, encrypted_oauth_client_secret: None,
                oauth_default_scopes: vec![],
                enabled: true, connect_timeout_ms: 10000, request_timeout_ms: 60000,
                input_specs_cache: Default::default(),
            }],
            vec![McpVirtualServer {
                id: vs_id, tenant_id, slug: "alpha".into(), name: "Alpha".into(),
                description: None, display_title: None, website_url: None,
                enabled: true, oauth_enabled: false,
                sampling_intercept: None,
            }],
            vec![McpVirtualRoute {
                id: id(), tenant_id, virtual_server_id: vs_id, upstream_server_id: up_id,
                prefix: "".into(), tools_filter: None, resources_filter: None,
                prompts_filter: None, enabled: true, position: 0,
            }],
        );
        let (vs, routes) = cfg.lookup_by_slug("alpha").expect("found");
        assert_eq!(vs.slug, "alpha");
        assert_eq!(routes.len(), 1);
        assert!(cfg.lookup_by_slug("missing").is_none());
    }

    #[test]
    fn drop_routes_when_upstream_disabled() {
        let tenant_id = id();
        let vs_id = id();
        let up_id = id();
        let cfg = McpConfig::from_rows(
            vec![McpUpstreamServer {
                id: up_id, tenant_id, name: "u".into(), description: None,
                upstream_url: "http://u".into(), transport: McpTransport::StreamableHttp,
                auth_mode: McpAuthMode::Headers, cred_version: 1,
                encrypted_credential: None, remote: Default::default(),
                encrypted_admin_inputs: HashMap::new(),
                oauth_issuer_url: None, oauth_authorization_url: None,
                oauth_token_url: None, oauth_revocation_url: None,
                oauth_client_id: None, encrypted_oauth_client_secret: None,
                oauth_default_scopes: vec![],
                enabled: false, connect_timeout_ms: 10000, request_timeout_ms: 60000,
                input_specs_cache: Default::default(),
            }],
            vec![McpVirtualServer {
                id: vs_id, tenant_id, slug: "alpha".into(), name: "Alpha".into(),
                description: None, display_title: None, website_url: None,
                enabled: true, oauth_enabled: false,
                sampling_intercept: None,
            }],
            vec![McpVirtualRoute {
                id: id(), tenant_id, virtual_server_id: vs_id, upstream_server_id: up_id,
                prefix: "".into(), tools_filter: None, resources_filter: None,
                prompts_filter: None, enabled: true, position: 0,
            }],
        );
        let (_, routes) = cfg.lookup_by_slug("alpha").expect("vs is enabled");
        assert!(routes.is_empty(), "route dropped because upstream disabled");
    }
}

#[cfg(test)]
mod route_prefix_tests {
    use super::{is_valid_route_prefix, split_route_prefix};
    use proptest::prelude::*;

    fn split<'a>(name: &'a str, prefixes: &[&str]) -> Option<(&'a str, &'a str)> {
        split_route_prefix(name, |p| prefixes.contains(&p))
    }

    #[test]
    fn a_prefix_that_could_hide_the_separator_is_refused() {
        for ok in ["", "gh", "g_h", "github_v1", "a1", &"a".repeat(16)] {
            assert!(is_valid_route_prefix(ok), "{ok:?}");
        }
        for bad in ["gh_", "gh__x", "_gh", "Gh", "1gh", "gh-bot", &"a".repeat(17)] {
            assert!(!is_valid_route_prefix(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_configured_prefix_splits_at_its_own_separator() {
        assert_eq!(split("gh__search", &["gh"]), Some(("gh", "search")));
        // The local name keeps every `_` and `__` of its own.
        assert_eq!(split("gh__a__b", &["gh"]), Some(("gh", "a__b")));
        assert_eq!(split("gh___search", &["gh"]), Some(("gh", "_search")));
    }

    #[test]
    fn a_name_no_configured_prefix_leads_is_unprefixed() {
        // An upstream's own `__` is not a route prefix.
        assert_eq!(split("aws___search_documentation", &["gh"]), None);
        assert_eq!(split("aws___search_documentation", &[]), None);
        // No empty prefix, no empty local name.
        assert_eq!(split("__bad", &[""]), None);
        assert_eq!(split("gh__", &["gh"]), None);
        assert_eq!(split("", &["gh"]), None);
    }

    proptest! {
        /// Every name a valid prefix stamps splits back into exactly that
        /// prefix and local name, whatever `_` and `__` the local name holds
        /// and whatever other valid prefixes the server carries. A two-letter
        /// alphabet makes prefixes share their leading letters often.
        #[test]
        fn a_stamped_name_splits_back_exactly(
            prefix in "[ab][ab_]{0,15}".prop_filter("valid", |p| is_valid_route_prefix(p)),
            others in proptest::collection::vec(
                "[ab][ab_]{0,15}".prop_filter("valid", |p| is_valid_route_prefix(p)),
                0..4,
            ),
            local in "[ab_]{1,12}",
        ) {
            let name = format!("{prefix}__{local}");
            let mut accepted: Vec<&str> = others.iter().map(String::as_str).collect();
            accepted.push(&prefix);
            prop_assert_eq!(split(&name, &accepted), Some((prefix.as_str(), local.as_str())));
        }

        /// Wherever a name resolves, it resolves honestly: onto a configured
        /// prefix it is exactly stamped by, or onto the empty-prefix route
        /// untouched and only when no prefix claims its start; and it is
        /// unrouted only when there is no empty-prefix route or a prefix
        /// claims it. Prefixes here include ones the admin refuses.
        #[test]
        fn a_name_resolves_to_its_own_prefix_or_to_no_prefix_any_other_claims(
            prefixes in proptest::collection::vec("[ab][ab_]{0,3}", 0..4),
            empty_route in any::<bool>(),
            name in "[ab_]{0,10}",
        ) {
            let mut configured: Vec<&str> = prefixes.iter().map(String::as_str).collect();
            if empty_route {
                configured.push("");
            }
            let claimed = prefixes.iter().any(|p| name.starts_with(&format!("{p}__")));
            // A name a VALID prefix stamps always reaches that prefix's route.
            let stamped_by_valid = prefixes.iter().find(|p| {
                is_valid_route_prefix(p)
                    && name.strip_prefix(p.as_str()).and_then(|r| r.strip_prefix("__")).is_some_and(|l| !l.is_empty())
            });
            if let Some(p) = stamped_by_valid {
                let resolved = super::resolve_route_prefix(&name, &configured);
                prop_assert_eq!(resolved.map(|(prefix, _)| prefix), Some(p.as_str()));
            }
            match super::resolve_route_prefix(&name, &configured) {
                Some(("", local)) => {
                    prop_assert!(empty_route);
                    prop_assert_eq!(local, name.as_str());
                    prop_assert!(!claimed);
                }
                Some((prefix, local)) => {
                    prop_assert!(prefixes.iter().any(|p| p == prefix));
                    prop_assert_eq!(format!("{prefix}__{local}"), name.clone());
                    prop_assert!(!local.is_empty());
                }
                None => prop_assert!(!empty_route || claimed),
            }
        }

        /// A name stamped by a valid prefix that is not configured is never
        /// split, whatever valid prefixes are — `_` inside them included.
        #[test]
        fn an_unconfigured_lead_is_never_split(
            lead in "[ab][ab_]{0,15}".prop_filter("valid", |p| is_valid_route_prefix(p)),
            prefixes in proptest::collection::vec(
                "[ab][ab_]{0,15}".prop_filter("valid", |p| is_valid_route_prefix(p)),
                0..4,
            ),
            local in "[ab_]{1,12}",
        ) {
            prop_assume!(!prefixes.contains(&lead));
            let name = format!("{lead}__{local}");
            let accepted: Vec<&str> = prefixes.iter().map(String::as_str).collect();
            prop_assert_eq!(split(&name, &accepted), None);
        }
    }
}
