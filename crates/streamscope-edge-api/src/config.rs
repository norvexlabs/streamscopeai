//! The config body the admin builds and the edge applies: one
//! [`ConfigResponse`] per tenant, wrapped per deployment in
//! [`MultiTenantConfigResponse`]. Both ends compile these types; neither keeps
//! a copy of its own.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

/// One tenant's config body — the payload of a `tenant:<id>` resource.
#[derive(Serialize, Deserialize, Clone)]
pub struct ConfigResponse {
    /// Tenant URL slug, shipped per-tenant so the proxy can resolve
    /// `tenant_id → slug` for the OAuth metadata endpoint without a separate
    /// admin call. Always populated — the proxy requires it.
    pub tenant_slug: String,
    pub model_mappings: Vec<EdgeModelMapping>,
    pub api_keys: Vec<EdgeApiKey>,
    pub settings: HashMap<String, serde_json::Value>,
    pub transform_programs: Vec<EdgeTransformProgram>,
    /// MCP gateway tables synced verbatim. Empty when no MCP servers
    /// have been registered for the tenant.
    pub mcp_upstream_servers: Vec<EdgeMcpUpstreamServer>,
    pub mcp_virtual_servers: Vec<EdgeMcpVirtualServer>,
    pub mcp_virtual_routes: Vec<EdgeMcpVirtualRoute>,
    /// Per-user OAuth credentials, encrypted at rest.
    pub mcp_user_credentials: Vec<EdgeMcpUserCredential>,
    /// Revoked spec-OAuth JWT `jti`s. Set by the proxy on every
    /// inbound JWT bearer; tokens whose `jti` is here are rejected.
    pub mcp_revoked_jtis: Vec<uuid::Uuid>,
    /// The tenant's ES256 public keys — every generation on this admin-api's
    /// signing ring, derived at build time.
    ///
    /// The proxy holds no signing secret, so this is the *only* way it can
    /// verify an MCP access token. Wire shape requires the key (admin-api
    /// always emits it, empty list included); no `#[serde(default)]` shim — a
    /// defaulted field would let a proxy accept a snapshot that carries no keys
    /// and then reject every MCP token with nothing to point at.
    pub mcp_jwks: Vec<streamscope_mcp_auth::metadata::JsonWebKey>,
    /// A2A gateway agents synced verbatim (`a2a_upstream_agents`). Empty when
    /// none are registered. Workspace A2A grants ride each key's baked
    /// `allowed_a2a_agent_ids`, not this wire.
    pub a2a_agents: Vec<EdgeA2aAgent>,
    /// Per-workspace rate-limit ceilings, keyed by `workspaces.id`. The
    /// spec-OAuth JWT path (bound to the claim's workspace) resolves its bucket
    /// from here; cached `sk-`/`vk-` rows already inline it. Missing entry →
    /// uncapped.
    pub workspace_rate_limits: HashMap<uuid::Uuid, streamscope_core::auth::RateLimitConfig>,
    /// The tenant's org-total budget ceiling, or `None` when uncapped. Cached
    /// `sk-`/`vk-` rows inline it on every key context; the spec-OAuth JWT path
    /// resolves it from here, so an MCP token is held to the same ceiling as a
    /// key. Budget only — no RPM/TPM at tenant scope.
    pub tenant_budget: Option<streamscope_core::auth::RateLimitConfig>,
    /// Workspaces whose spend does NOT roll into the tenant's org-total budget.
    ///
    /// Baked keys already carry the decision (a key in one of these workspaces
    /// is baked with no `tenant_budget` at all), so this set exists for the
    /// spec-OAuth JWT path, which mints its context at request time from the
    /// claim's workspace and has no baked row to read. Empty on a tenant that
    /// funds everything, which is the default.
    pub workspaces_outside_tenant_budget: BTreeSet<uuid::Uuid>,
    /// Each workspace's default member limit. Baked keys carry the resolved
    /// member bucket; the spec-OAuth JWT path resolves it from this and
    /// [`Self::member_limit_exceptions`] with the same core resolver.
    pub member_limit_defaults: HashMap<uuid::Uuid, streamscope_core::auth::member_limits::MemberLimits>,
    /// Member exceptions — see [`Self::member_limit_defaults`].
    pub member_limit_exceptions: Vec<streamscope_core::auth::member_limits::MemberLimitException>,
    /// Every server's enabled replica endpoints (primary first), and the
    /// endpoints serving each model not every endpoint serves. Empty: every
    /// target goes to its mapping's own URL, the server's primary.
    pub upstream_endpoints: streamscope_core::config::endpoints::EndpointTable,
    /// The tenant's QoS classes, which class each workspace runs in, each
    /// workspace's share of a saturated pool, and the classes a route target
    /// restricts itself to. Empty: no request has a class and the dispatch
    /// gate stays off.
    pub qos: streamscope_core::config::qos::QosTable,
    /// The destination lists the tenant attaches to the Web tool, flattened
    /// by mode. Empty: the Web tool considers every public URL.
    pub web_destinations: streamscope_core::web::WebDestinationLists,
    /// Resolved proxy public URL for this tenant (per-tenant override
    /// layered over the SYSTEM default; collapsed by admin-api at snapshot
    /// time). `None` = neither layer configured.
    pub proxy_public_url: Option<String>,
    /// Resolved admin/portal public URL for this tenant. Same layering
    /// semantics as `proxy_public_url`.
    pub admin_public_url: Option<String>,
    /// Resolved canonical admin-API origin for this tenant. Same layering
    /// semantics as `proxy_public_url`. The proxy advertises it as the MCP
    /// OAuth authorization-server origin (RFC 9728), falling back to
    /// `admin_public_url` when `None` (API co-resident with the UI).
    pub api_public_url: Option<String>,
    /// The tenant's Default workspace id. The proxy stamps it onto
    /// synthetic `UserContext`s minted post-validation (spec-OAuth JWT path).
    /// `None` only in degenerate states (tenant created without seeding).
    pub default_workspace_id: Option<uuid::Uuid>,
    /// `(workspace_id, kind, profile_id)` — explicit per-(workspace, kind)
    /// profile choices (`workspace_profile_assignments`). Only workspaces with a
    /// row for a kind appear; the rest inherit [`Self::default_profiles`].
    /// `Some(pid)` selects a profile; **`None` is an explicit Off** (the row's
    /// `profile_id IS NULL` — the kind's policy is fully disabled for that
    /// workspace). A kind the edge does not know fails the body. The proxy folds these
    /// into [`TenantConfig::workspace_profiles`] and pre-buckets each reachable
    /// profile's content.
    pub workspace_profiles: Vec<(uuid::Uuid, streamscope_core::config::ProfileKind, Option<uuid::Uuid>)>,
    /// `(kind, profile_id)` — the tenant's per-kind default profile
    /// (`profiles.is_default = true`), the fallback for a workspace with no
    /// explicit selection for that kind.
    pub default_profiles: Vec<(streamscope_core::config::ProfileKind, uuid::Uuid)>,
    /// `(profile_id, kind, standalone)` — each profile's inheritance mode under
    /// the Default-as-base model. `standalone = true` → the profile owns its full
    /// content (ignores the Default); `false` → Layered (inherits the Default +
    /// its own diff). The proxy uses this with [`Self::default_profiles`] to bucket
    /// a Layered profile as `Default ⊕ own` vs a Standalone as `own`. The Default
    /// profile itself is `standalone = true` (it is the base).
    pub profile_modes: Vec<(uuid::Uuid, streamscope_core::config::ProfileKind, bool)>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeMcpUpstreamServer {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub upstream_url: String,
    pub transport: String,
    pub auth_mode: String,
    pub cred_version: i64,
    /// AES-256-GCM ciphertext (base64 string).
    /// The DB column is BYTEA; admin stores the base64 ciphertext as UTF-8 bytes.
    /// Read back here as `String` for the tenant body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_credential: Option<String>,
    // ── Per-user OAuth client config ──
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
    /// AES-256-GCM ciphertext (base64). Decrypted at the proxy when calling
    /// the upstream IdP token endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_oauth_client_secret: Option<String>,
    /// Operator-configured default scopes — shipped verbatim to the IdP. The
    /// DB column is `TEXT[]`; sqlx maps to `Vec<String>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub oauth_default_scopes: Vec<String>,
    pub enabled: bool,
    pub connect_timeout_ms: i32,
    pub request_timeout_ms: i32,
}

/// A2A upstream agent row synced to the edge (`a2a_upstream_agents`).
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeA2aAgent {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub slug: String,
    pub agent_url: String,
    /// Cached upstream agent card (raw JSONB) — the proxy rewrites it per
    /// request for the mount's well-known endpoint.
    pub agent_card: serde_json::Value,
    /// Last upstream card fetch — the mount's `Last-Modified` source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    pub auth_mode: String,
    /// AES-256-GCM ciphertext (base64 string; BYTEA round-tripped like
    /// `EdgeMcpUpstreamServer::encrypted_credential`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_header: Option<String>,
    pub enabled: bool,
}

/// Per-user OAuth credential row. Shipped per-tenant so the proxy
/// can resolve a user's bearer token at request time without a round-trip.
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeMcpUserCredential {
    pub tenant_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub upstream_server_id: uuid::Uuid,
    /// AES-256-GCM ciphertext (base64).
    pub encrypted_access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeMcpVirtualServer {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub slug: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MCP 2025-11-25 `serverInfo.title`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_title: Option<String>,
    /// MCP 2025-11-25 `serverInfo.websiteUrl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    pub enabled: bool,
    /// When true, accept spec-OAuth JWT bearers on this VS.
    pub oauth_enabled: bool,
    /// Sampling intercept master toggle — see `McpVirtualServer::sampling_intercept`.
    pub sampling_intercept_enabled: bool,
    /// AES-GCM ciphertext (base64-encoded UTF-8 bytes). The DB column is
    /// BYTEA holding the same UTF-8 bytes the proxy decrypts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_model_alias: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeMcpVirtualRoute {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub virtual_server_id: uuid::Uuid,
    pub upstream_server_id: uuid::Uuid,
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_filter: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_filter: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts_filter: Option<serde_json::Value>,
    pub enabled: bool,
    pub position: i32,
}

/// Multi-tenant config snapshot — wraps per-tenant configs for all active tenants.
#[derive(Serialize, Deserialize, Clone)]
pub struct MultiTenantConfigResponse {
    pub tenants: HashMap<String, ConfigResponse>,
    /// Global log level (process-wide, not per-tenant).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    /// Global platform setting overrides (token → value) — the full set the
    /// edge persists and applies on its next restart.
    pub runtime_overrides: HashMap<String, String>,
    /// The internal-egress allowlists (see [`GlobalConfig::egress`]).
    pub egress: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EdgeTransformProgram {
    pub id: String,
    pub name: String,
    pub source: String,
    pub phase: String,
    pub scope: String,
    pub priority: i32,
    pub enabled: bool,
    pub version: i32,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    pub trigger_regex: Option<String>,
    pub match_mode: Option<String>,
    /// Transform profile scope. `None` → shared (every profile's baseline);
    /// `Some` → specific to that profile. Carried as text on the wire.
    pub profile_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
pub struct EdgeModelMapping {
    /// Alias binding UUID.
    pub id: String,
    /// Tenant UUID (for grouping by tenant and filtering).
    pub tenant_id: String,
    pub alias: String,
    pub provider: String,
    pub upstream_model: String,
    pub priority: i32,
    pub weight: i32,
    pub enabled: bool,
    /// The route's response-cache generation: an edge drops the route's
    /// cached responses when it rises; no edge compares it on first apply.
    pub cache_generation: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i32>,
    pub client_context_window: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_api_format: Option<String>,
    /// Override for the appended chat-completions endpoint path (None = default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_endpoint_path: Option<String>,
    /// How the server is addressed and authenticated — the URL prefix and the
    /// credential header, orthogonal to `upstream_api_format`.
    #[cfg_attr(feature = "sqlx", sqlx(try_from = "String"))]
    pub transport: streamscope_core::config::upstream_transport::UpstreamTransport,
    /// How this server expresses a request's QoS class, if it does. `none`
    /// (the default) sends nothing: dispatch order stays the gateway's alone.
    #[cfg_attr(feature = "sqlx", sqlx(try_from = "String"))]
    pub scheduling_dialect: streamscope_core::config::qos::SchedulingDialect,
    /// Server UUID (names its stored credential, and audit tracking).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_server_id: Option<String>,
    /// Owning downstream provider UUID — lets the catch-all pick the upstream
    /// backing the route-policy-matched provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream_provider_id: Option<String>,
    /// Model UUID (for audit tracking).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_model_id: Option<String>,
    // ── Capability flags (resolved: model → catalog → default) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_vision: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_reasoning: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_function_calling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_caching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_audio_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_audio_output: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_video_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_pdf_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_response_schema: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_system_messages: Option<bool>,
    /// Whether a `model_catalog` row matched this model. Read only by
    /// admin-api's known-non-reasoner bake; never sent to an edge.
    #[serde(skip)]
    pub catalog_matched: bool,
    /// Per-model JSON healing override (NULL = inherit tenant healing_enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healing_enabled: Option<bool>,
    /// Resolved native invocation preset `settings` for this (alias → model)
    /// target (route's preset, else the model's default). `{}` = passthrough.
    pub preset_settings: serde_json::Value,
    // ── Resolved response-cache policy (route's cache preset, flattened) ──
    // NULL mode = the alias references no cache preset, i.e. uncached. Baked to
    // values here exactly like `preset_settings`, so editing a cache preset
    // re-bakes every referencing alias and propagates on the normal config sweep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_threshold: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_share_scope: Option<String>,
    // ── Pricing (resolved: upstream_model's own map, else the catalog row of
    // the SAME provider; never another vendor's) ──
    /// Price per billing unit plus the currency they are quoted in. An empty map
    /// is a price we do not know, which the proxy bills at a floor of zero AND
    /// badges — distinct from a rate of zero, which is a genuinely free request.
    #[serde(default = "streamscope_core::pricing::Rates::unknown")]
    #[cfg_attr(feature = "sqlx", sqlx(json))]
    pub rates: streamscope_core::pricing::Rates,
}

/// One live `sk-`/`vk-` key: the SHA-256 the database stores, and the context
/// the gateway authenticates it to — typed, so a key a gateway could not read
/// cannot be sent.
#[derive(Serialize, Deserialize, Clone)]
pub struct EdgeApiKey {
    pub key_hash: String,
    pub user_context: streamscope_core::auth::UserContext,
}

/// The `global` resource: deployment-wide values every edge applies,
/// whichever tenants it serves.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GlobalConfig {
    /// Process log level; `None` keeps the edge's own.
    pub log_level: Option<String>,
    /// Platform setting overrides (token → value), the full set.
    pub runtime_overrides: HashMap<String, String>,
    /// The internal-egress allowlists (surface key → entries), the full set;
    /// a surface absent reaches no private address. Applied without a
    /// restart.
    pub egress: std::collections::BTreeMap<String, Vec<String>>,
}

impl ConfigResponse {
    /// Put every list in a total order, so equal rows give equal bytes on any
    /// replica whatever order a query returned them in (see
    /// [`crate::digest`]). Where a list's order means something to its
    /// consumer, the key starts with that order: model mappings by alias, then
    /// priority and weight descending (failover and round-robin groups);
    /// transforms by priority then name (execution order); MCP routes by
    /// server then position. Every key ends in a unique field. Lists inside
    /// `settings` and the endpoint table are ordered by the queries that
    /// build them.
    pub fn canonicalize(&mut self) {
        use std::cmp::Reverse;
        self.model_mappings.sort_by(|a, b| {
            (&a.alias, Reverse(a.priority), Reverse(a.weight), &a.id)
                .cmp(&(&b.alias, Reverse(b.priority), Reverse(b.weight), &b.id))
        });
        self.api_keys.sort_by(|a, b| a.key_hash.cmp(&b.key_hash));
        self.transform_programs
            .sort_by(|a, b| (a.priority, &a.name, &a.id).cmp(&(b.priority, &b.name, &b.id)));
        self.mcp_upstream_servers.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        self.mcp_virtual_servers.sort_by(|a, b| (&a.slug, a.id).cmp(&(&b.slug, b.id)));
        self.mcp_virtual_routes.sort_by(|a, b| {
            (a.virtual_server_id, a.position, a.id).cmp(&(b.virtual_server_id, b.position, b.id))
        });
        self.mcp_user_credentials.sort_by(|a, b| {
            (a.user_id, a.upstream_server_id).cmp(&(b.user_id, b.upstream_server_id))
        });
        self.mcp_revoked_jtis.sort();
        self.mcp_revoked_jtis.dedup();
        self.mcp_jwks.sort_by(|a, b| a.kid.cmp(&b.kid));
        self.a2a_agents.sort_by(|a, b| (&a.slug, a.id).cmp(&(&b.slug, b.id)));
        self.member_limit_exceptions.sort_by_key(|e| (e.workspace_id, e.user_id));
        self.workspace_profiles.sort();
        self.default_profiles.sort();
        self.profile_modes.sort();
        for classes in self.qos.route_classes.values_mut() {
            classes.sort();
        }
        // A set: the matcher reads no order.
        for entries in [&mut self.web_destinations.allow, &mut self.web_destinations.block] {
            entries.sort();
            entries.dedup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn uuid(n: u8) -> uuid::Uuid {
        uuid::Uuid::from_bytes([n; 16])
    }

    /// A body whose every canonicalized list has several entries, with ties on
    /// each consumer order key so only the final tiebreak separates them.
    fn fixture() -> ConfigResponse {
        let mapping = |id: &str, alias: &str, priority: i32, weight: i32| {
            serde_json::json!({
                "id": id, "tenant_id": "t", "alias": alias, "provider": "openai",
                "upstream_model": "m", "priority": priority, "weight": weight, "enabled": true,
                "cache_generation": 0, "transport": "default", "scheduling_dialect": "none",
                "preset_settings": {},
            })
        };
        let transform = |id: &str, name: &str, priority: i32| {
            serde_json::json!({
                "id": id, "name": name, "source": "", "phase": "request", "scope": "global",
                "priority": priority, "enabled": true, "version": 1,
            })
        };
        let key = |hash: &str| {
            serde_json::json!({ "key_hash": hash, "user_context": {
                "user_id": uuid(0), "tenant_id": uuid(0), "workspace_id": uuid(0),
                "model_map": { "mappings": {} },
                "rate_limit": streamscope_core::auth::RateLimitConfig::unlimited(),
                "tenant_budget": null,
            } })
        };
        let route = |id: u8, vs: u8, position: i32| {
            serde_json::json!({
                "id": uuid(id), "tenant_id": uuid(0), "virtual_server_id": uuid(vs),
                "upstream_server_id": uuid(9), "position": position, "prefix": "p", "enabled": true,
            })
        };
        let body = serde_json::json!({
            "version": 0,
            "tenant_slug": "acme",
            "model_mappings": [
                mapping("m4", "b", 1, 1), mapping("m1", "a", 1, 1), mapping("m3", "a", 5, 1),
                mapping("m2", "a", 1, 1), mapping("m5", "a", 1, 3),
            ],
            "api_keys": [key("h3"), key("h1"), key("h2")],
            "transform_programs": [
                transform("t3", "x", 2), transform("t1", "x", 2), transform("t2", "a", 2), transform("t0", "z", 1),
            ],
            "mcp_virtual_routes": [route(4, 2, 0), route(3, 1, 1), route(2, 1, 1), route(1, 1, 0)],
            "mcp_revoked_jtis": [uuid(3), uuid(1), uuid(2), uuid(1)],
            "mcp_jwks": [],
            "tenant_budget": null,
            "member_limit_exceptions": [],
            "proxy_public_url": null,
            "admin_public_url": null,
            "api_public_url": null,
            "settings": {},
            "mcp_upstream_servers": [],
            "mcp_virtual_servers": [],
            "mcp_user_credentials": [],
            "a2a_agents": [],
            "workspace_rate_limits": {},
            "workspaces_outside_tenant_budget": [],
            "member_limit_defaults": {},
            "upstream_endpoints": {},
            "workspace_profiles": [[uuid(2), "tools", null], [uuid(1), "tools", uuid(5)], [uuid(1), "guardrail", null]],
            "default_profiles": [["tools", uuid(7)], ["guardrail", uuid(6)]],
            "profile_modes": [[uuid(5), "tools", true], [uuid(4), "tools", false]],
            "qos": { "route_classes": { uuid(1).to_string(): [uuid(3), uuid(1), uuid(2)] } },
            "web_destinations": { "allow": ["b.lan:443", "a.lan:443"], "block": ["c.lan:443"] },
        });
        serde_json::from_value(body).expect("fixture parses")
    }

    fn canonical_bytes(mut body: ConfigResponse) -> Vec<u8> {
        body.canonicalize();
        serde_json::to_vec(&crate::digest::canonical_value(&body).unwrap()).unwrap()
    }

    /// Fisher–Yates driven by a seed, so proptest can shrink the seed.
    fn shuffle<T>(v: &mut [T], mut seed: u64) {
        for i in (1..v.len()).rev() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.swap(i, (seed >> 33) as usize % (i + 1));
        }
    }

    proptest! {
        #[test]
        fn any_list_order_canonicalizes_to_the_same_bytes(seed in any::<u64>()) {
            let mut shuffled = fixture();
            shuffle(&mut shuffled.model_mappings, seed);
            shuffle(&mut shuffled.api_keys, seed ^ 1);
            shuffle(&mut shuffled.transform_programs, seed ^ 2);
            shuffle(&mut shuffled.mcp_virtual_routes, seed ^ 3);
            shuffle(&mut shuffled.mcp_revoked_jtis, seed ^ 4);
            shuffle(&mut shuffled.workspace_profiles, seed ^ 5);
            shuffle(&mut shuffled.default_profiles, seed ^ 6);
            shuffle(&mut shuffled.profile_modes, seed ^ 7);
            for classes in shuffled.qos.route_classes.values_mut() {
                shuffle(classes, seed ^ 8);
            }
            shuffle(&mut shuffled.web_destinations.allow, seed ^ 9);
            prop_assert_eq!(canonical_bytes(shuffled), canonical_bytes(fixture()));
        }
    }

    #[test]
    fn canonical_order_keeps_each_consumers_order() {
        let mut body = fixture();
        body.canonicalize();
        let mappings: Vec<_> = body.model_mappings.iter().map(|m| m.id.as_str()).collect();
        // Alias, then priority DESC, then weight DESC, then id.
        assert_eq!(mappings, ["m3", "m5", "m1", "m2", "m4"]);
        let transforms: Vec<_> = body.transform_programs.iter().map(|t| t.id.as_str()).collect();
        // Priority ascending (execution order), then name, then id.
        assert_eq!(transforms, ["t0", "t2", "t1", "t3"]);
        let routes: Vec<_> = body.mcp_virtual_routes.iter().map(|r| (r.virtual_server_id, r.position)).collect();
        assert_eq!(routes, [(uuid(1), 0), (uuid(1), 1), (uuid(1), 1), (uuid(2), 0)]);
        assert_eq!(body.mcp_revoked_jtis, [uuid(1), uuid(2), uuid(3)]);
        assert_eq!(body.web_destinations.allow, ["a.lan:443", "b.lan:443"]);
    }
}
