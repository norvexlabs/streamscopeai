//! Per-tenant configuration and the tenant registry.
//!
//! Each tenant gets a [`TenantConfig`] with model mappings, feature flags, and
//! policy rules. Configs are stored in a [`TenantRegistry`] backed by `arc-swap`
//! for lock-free reads on the hot path — writes clone-on-write the inner map.
//! The special [`TenantId::SYSTEM`] tenant serves as the default in single-tenant
//! deployments (platform operator only, no customer workloads).

pub mod a2a;
pub mod credentials;
pub mod endpoints;
pub mod qos;
pub mod mcp;
pub mod model_map;
pub mod tool_rules;
pub mod tool_rules_detectors;
pub mod tool_rules_normalize;
pub mod tool_rules_semantic;
pub mod upstream_transport;

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

use self::model_map::ModelMap;

/// Default idle timeout (seconds) for SSE streaming responses.
pub const DEFAULT_STREAM_IDLE_TIMEOUT_SECS: u64 = 300;

/// Tenant identifier — a newtype over UUID used in config sync and proxy routing.
///
/// Intentionally duplicated in `streamscope_admin::db::tenant::TenantId` — that
/// copy carries axum extractor and RLS integration; this copy carries serde
/// derives for wire format. Both define `SYSTEM = UUID(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TenantId(pub uuid::Uuid);

impl TenantId {
    /// The built-in system tenant (UUID = 1). Used as the default in single-tenant deployments.
    pub const SYSTEM: TenantId = TenantId(uuid::Uuid::from_u128(1));
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Policy domain a [`profiles`] row (and a `workspace_profile_assignments` row)
/// belongs to — the closed set of profile kinds the binary knows.
///
/// The DB `profiles.kind` / `workspace_profile_assignments.kind` columns are
/// open `TEXT` so a new domain is purely additive at the schema layer; this enum
/// is the closed set the code resolves against. An unrecognized stored value is
/// left out of a config body with a warning ([`ProfileKind::parse`]); on the
/// wire the kind is typed, so an edge refuses a body naming one it does not
/// know.
///
/// `Copy` so it can key the per-request resolution maps
/// ([`TenantConfig::workspace_profiles`]) with no allocation on the hot path.
/// Adding a variant forces every `match` to handle it — the compiler is the
/// drift guard for "wire up a new kind everywhere".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// Tool-call policy rules (`system_settings.tool_rules`, tagged by profile_id).
    Tools,
    /// Inline guardrail posture (`system_settings.guardrail_profiles`, keyed by profile id).
    Guardrail,
    /// Request/response transform programs (`transform_programs`, tagged by profile_id).
    Transform,
    /// Which agent experts analyze a workspace's conversations
    /// (`expert_profile_members`). Admin-side only — no proxy hot-path resolution.
    Expert,
    /// Which client profiles a workspace is offered, what its developers'
    /// sandboxes may reach, and what the portal hides from its members — four
    /// sections (`client_access_members`, `client_access_destinations`,
    /// `client_access_sandbox`, `client_access_portal`). Admin-side only, and
    /// never in a config body ([`Self::on_edge`]).
    ClientAccess,
}

impl ProfileKind {
    /// Every known kind — the iteration source for seeding defaults and the
    /// drift test. Adding a variant here + to the enum is the only place a new
    /// kind's identity is declared.
    pub const ALL: &'static [ProfileKind] =
        &[ProfileKind::Tools, ProfileKind::Guardrail, ProfileKind::Transform, ProfileKind::Expert, ProfileKind::ClientAccess];

    /// Stable wire / DB string for the kind. Keep in sync with [`Self::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileKind::Tools => "tools",
            ProfileKind::Guardrail => "guardrail",
            ProfileKind::Transform => "transform",
            ProfileKind::Expert => "expert",
            ProfileKind::ClientAccess => "client_access",
        }
    }

    /// Whether the kind's profiles ride the config body. Client access is read
    /// by admin-api alone (the portal and the provision bundle), so it is left
    /// out and an edge never has to know it.
    pub fn on_edge(self) -> bool {
        !matches!(self, ProfileKind::ClientAccess)
    }

    /// Parse a stored or request `kind` string. `None` for an unrecognized
    /// value.
    pub fn parse(s: &str) -> Option<ProfileKind> {
        match s {
            "tools" => Some(ProfileKind::Tools),
            "guardrail" => Some(ProfileKind::Guardrail),
            "transform" => Some(ProfileKind::Transform),
            "expert" => Some(ProfileKind::Expert),
            "client_access" => Some(ProfileKind::ClientAccess),
            _ => None,
        }
    }
}

/// Ordered by the wire string, so a sorted list of kinds serializes in the
/// same order as the strings would.
impl Ord for ProfileKind {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for ProfileKind {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A workspace's **explicit** per-kind profile choice, stored in
/// [`TenantConfig::workspace_profiles`]. The *absence* of an entry for a
/// `(workspace, kind)` key means "inherit the tenant default"; an entry present
/// means the workspace made an explicit choice — either a specific profile or
/// turning the policy fully `Off`. This three-state model (inherit / off /
/// profile) is the per-workspace governance primitive every kind shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceProfile {
    /// Policy explicitly turned **off** for this workspace+kind — no profile is
    /// applied (e.g. the Agent workspace defaults guardrail+transform to `Off`
    /// so the agent sees raw PII and never transforms its own traffic).
    Off,
    /// A specific profile the workspace selected.
    Use(uuid::Uuid),
}

/// The **resolved** per-kind profile state for a request, returned by
/// [`TenantConfig::effective_profile`]. Folds the workspace's explicit choice
/// ([`WorkspaceProfile`]) with the tenant default into a single verdict the
/// per-kind `effective_*` helpers branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveProfile {
    /// Explicitly off → the kind's helper returns its empty form (no tool rules,
    /// a disabled guardrail, no transforms).
    Off,
    /// Apply this profile id (the workspace's explicit pick, or the tenant default).
    Use(uuid::Uuid),
    /// Neither an explicit choice nor a tenant default resolved (degenerate /
    /// SYSTEM) — the helper applies its own built-in safety net (shared tool
    /// baseline, the resolved guardrail default, …). Seeding always creates a
    /// default profile, so this is a safety net, not a normal path.
    Unset,
}

/// Client detection pattern — matches UA substrings, Referer domains and the
/// opening of the system prompt to an app_id.
///
/// Every pattern is ASCII-lowercase and non-empty: the matchers compare it
/// against an ASCII-lowercased header or prompt, so a mixed-case pattern would
/// never match and an empty one would match everything. The config fold (`parse_app_patterns` in
/// the proxy) normalizes them; keep any other constructor doing the same.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AppPattern {
    pub app_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ua_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referer_patterns: Vec<String>,
    /// Substrings of the system prompt's opening — see
    /// [`crate::middleware::attribution::infer_app_from_system_prompt`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_patterns: Vec<String>,
}

/// Route policy for the catch-all proxy — controls which `/v1/*` paths are forwarded
/// for a given downstream provider.
///
/// Matching rules:
/// - Exact: `/v1/completions` matches only that path.
/// - Wildcard suffix: `/v1/batches/*` matches `/v1/batches/123`, `/v1/batches/123/cancel`, etc.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoutePolicy {
    /// Path pattern, e.g. `/v1/completions` (exact) or `/v1/batches/*` (wildcard).
    pub path_pattern: String,
    /// Whether this route is enabled. Disabled policies are ignored during matching.
    pub enabled: bool,
    /// Optional per-route rate limit (requests per minute). `None` = use key's default RPM.
    pub rate_limit_rpm: Option<i32>,
    /// Maximum request body size in bytes for this route.
    pub max_body_bytes: i64,
    /// Whether to capture the request/response body in audit records.
    pub audit_body: bool,
}

impl RoutePolicy {
    /// Check if this policy matches the given canonical path (e.g. `/v1/batches/123`).
    pub fn matches(&self, path: &str) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(prefix) = self.path_pattern.strip_suffix("/*") {
            // Wildcard: `/v1/batches/*` matches `/v1/batches/` and deeper.
            path.starts_with(prefix) && path.len() > prefix.len() && path.as_bytes()[prefix.len()] == b'/'
        } else {
            // Exact match.
            path == self.path_pattern
        }
    }
}

/// Find the first matching route policy for a given path from a list of policies.
pub fn find_matching_policy<'a>(policies: &'a [RoutePolicy], path: &str) -> Option<&'a RoutePolicy> {
    policies.iter().find(|p| p.matches(path))
}

/// Per-tenant configuration — hot-reloadable via `arc-swap`.
///
/// Each tenant gets its own config with model mappings, feature flags, and policy rules.
/// In single-tenant deployments, all config lives under `TenantId::SYSTEM`.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    pub model_map: ModelMap,
    pub audit_enabled: bool,
    pub debug_mode: bool,
    pub healing_enabled: bool,
    /// Idle timeout (seconds) for SSE streaming responses. If no event is received
    /// from upstream within this duration, the stream is terminated.
    pub stream_idle_timeout_secs: u64,
    /// When true, capture request/response content for deep inspection.
    pub content_logging_enabled: bool,
    /// Runtime log level: "error", "warn", "info", "debug". Applied dynamically via reload handle.
    pub log_level: String,
    /// When true, sanitize invalid characters from tool/function names in requests.
    pub sanitize_tool_names: bool,
    /// How the Rhai transform engine should react when a script errors.
    /// Stored as a string for settings simplicity; use
    /// [`crate::scripting::ScriptFailMode::parse`] to get the typed value.
    /// Values: `"open"` (default — skip failed script, continue) or
    /// `"closed"` (abort request / suppress block on any script error).
    pub rhai_fail_mode: String,
    /// Parsed tool risk rules from `system_settings.tool_rules.rules`.
    /// Strongly typed — config sync deserializes JSONB to `Rule` once at
    /// snapshot load. Invalid entries are dropped with a warning so a single
    /// bad rule can't break tenant routing.
    pub tool_rules: Vec<crate::config::tool_rules::Rule>,
    /// Per-(tool, field) normaliser registry merged from
    /// `system_settings.tool_field_profiles` (the hand-curated agentic-client
    /// catalog and the auto-imported MCP catalog land in the same array on
    /// the wire, see B.2 in `field_typed_normalisers` plan). Resolved at
    /// snapshot load and pre-sorted by `(priority, position)` so lookup is
    /// deterministic. Empty when no profiles registered → resolvers fall
    /// back to raw stringified arg values (pre-Stage-B behaviour).
    pub tool_field_profiles: std::sync::Arc<crate::config::tool_rules::FieldProfileSet>,
    /// `(workspace_id, kind)` → the workspace's **explicit** choice
    /// ([`WorkspaceProfile`]: a specific profile or `Off`), from
    /// `workspace_profile_assignments`. A *missing* entry for a kind — the
    /// Default workspace, or any workspace that hasn't picked for that kind —
    /// inherits [`Self::default_profiles`]. Resolved per request via
    /// [`Self::effective_profile`] (and its callers [`Self::effective_tool_rules`]
    /// / [`Self::effective_guardrail`]). `ProfileKind` is `Copy` so the lookup
    /// allocates nothing on the hot path.
    pub workspace_profiles: HashMap<(uuid::Uuid, ProfileKind), WorkspaceProfile>,
    /// Per-kind tenant default profile id (`profiles.is_default = true`) — the
    /// fallback for a workspace with no explicit selection for that kind. A kind
    /// absent here has no default (degenerate / SYSTEM); the kind's
    /// `effective_*` resolver then applies its own safety-net default.
    pub default_profiles: HashMap<ProfileKind, uuid::Uuid>,
    /// [`Self::tool_rules`] pre-bucketed by profile id, built once at snapshot
    /// load so the per-request hot path borrows a profile's slice with no
    /// allocation (Default-as-base): a Layered profile's bucket is the Default's
    /// rules (minus the ones it forked) ∪ its own; the Default and any Standalone
    /// bucket is its own rules. Built via [`Self::build_profile_buckets`].
    pub tool_rules_by_profile: HashMap<uuid::Uuid, Vec<crate::config::tool_rules::Rule>>,
    /// Client detection patterns from app registry (synced from admin-api).
    pub app_patterns: std::sync::Arc<[AppPattern]>,
    /// Active transform programs (Rhai scripts) for this tenant — the **full**
    /// flat list (every profile's programs, the Default included). Kept whole for
    /// the script-engine warm-up (which pre-compiles the union of all reachable
    /// programs); per-request resolution borrows a profile's pre-bucketed slice
    /// from [`Self::transform_programs_by_profile`].
    pub transform_programs: Vec<crate::scripting::TransformProgram>,
    /// [`Self::transform_programs`] pre-bucketed by **transform** profile id,
    /// built once at snapshot load so the per-request hot path borrows a profile's
    /// slice with no allocation (Default-as-base): a Layered profile's bucket is
    /// the Default's programs ∪ its own; the Default and any Standalone bucket is
    /// its own. Resolved per request via [`Self::effective_transforms`].
    /// Built via [`Self::build_transform_buckets`].
    pub transform_programs_by_profile:
        HashMap<uuid::Uuid, Vec<crate::scripting::TransformProgram>>,
    /// Catch-all route policies keyed by downstream_provider_id.
    /// Controls which `/v1/*` paths are forwarded as-is to the upstream.
    pub route_policies: HashMap<uuid::Uuid, Vec<RoutePolicy>>,
    /// When true, extract base64 media from chat messages and store as blobs
    /// in `audit_media_blobs`. When false, strip base64 entirely.
    pub media_blob_storage_enabled: bool,
    /// Max blob size in MB. Media larger than this is not stored at all.
    pub media_blob_max_size_mb: u64,
    /// MCP gateway snapshot — slugged virtual servers + their fan-in routes.
    /// Empty when the tenant hasn't configured any MCP servers.
    pub mcp: crate::config::mcp::McpConfig,
    pub a2a: crate::config::a2a::A2aConfig,
    /// Tenant URL slug — duplicate of `tenants.slug` shipped per-tenant so
    /// the proxy can resolve `tenant_id → slug` without a separate map.
    /// Empty for the SYSTEM tenant fallback. Populated on every snapshot push.
    pub tenant_slug: String,
    /// Per-workspace rate-limit ceilings, keyed by `workspaces.id`. The cached
    /// `UserContext` for `sk-` / `vk-` keys already inlines its workspace bucket,
    /// but the spec-OAuth JWT path mints a synthetic `UserContext` bound to the
    /// claim's workspace and looks the cap up here. Missing entry → the
    /// workspace is uncapped ([`crate::auth::RateLimitConfig::unlimited`]) — the
    /// no-row-means-uncapped rule applies to any workspace without a row.
    pub workspace_rate_limits: HashMap<uuid::Uuid, crate::auth::RateLimitConfig>,
    /// The tenant's org-total budget ceiling — the ceiling every workspace's
    /// spend rolls into, enforced keyed by `tenant_id`. `None` = uncapped (the
    /// default). Read by the spec-OAuth JWT path, which mints a synthetic
    /// `UserContext`; `sk-`/`vk-` keys already carry it inlined.
    pub tenant_budget: Option<crate::auth::RateLimitConfig>,
    /// Workspaces whose spend does not roll into [`Self::tenant_budget`].
    ///
    /// Read through [`Self::tenant_budget_for`], never directly. A `sk-`/`vk-`
    /// key needs neither: admin bakes its `tenant_budget` as `None` outright, so
    /// only the spec-OAuth path — which builds its context from a claim rather
    /// than a baked key — has to consult the set.
    pub workspaces_outside_tenant_budget: std::collections::HashSet<uuid::Uuid>,
    /// Each workspace's DEFAULT member limit, keyed by `workspaces.id`. Read
    /// through [`Self::member_limit_for`], never directly.
    pub member_limit_defaults: HashMap<uuid::Uuid, crate::auth::member_limits::MemberLimits>,
    /// Member EXCEPTIONS, keyed by `(workspace_id, user_id)`. Read through
    /// [`Self::member_limit_for`], never directly.
    pub member_limit_exceptions:
        HashMap<(uuid::Uuid, uuid::Uuid), crate::auth::member_limits::MemberLimits>,
    /// Every server's enabled replica endpoints, and which serve which model.
    /// A route target is forwarded to its model's endpoints in the order
    /// [`crate::config::endpoints::order_endpoints`] gives each request; a server
    /// the table does not know is not forwarded to.
    pub endpoints: crate::config::endpoints::EndpointTable,
    /// The tenant's QoS classes, which class each workspace runs in, and each
    /// workspace's share of a saturated pool. Read through
    /// [`crate::config::qos::QosTable::effective_class`], never directly — a key
    /// may sit above its workspace only when an admin elevated it. An empty
    /// table means no request has a class and the dispatch gate stays off.
    pub qos: crate::config::qos::QosTable,
    /// Per-tenant settings for the built-in Web MCP (`/mcp/web`).
    /// Backed by `system_settings.web` key; synced through the config-sync
    /// sweeper. Default = unconfigured → `tools/list` returns `[]`.
    pub web: crate::web::WebSettings,
    /// Tenant-wide response-cache settings. Backed by the `system_settings.cache`
    /// key; per-alias policy rides the route's baked [`CachePolicy`], not this.
    pub cache: crate::proxy::response_cache::CacheSettings,
    /// The currency this tenant keeps its books in, and the operator's table for
    /// converting a provider's quote into it. Every budget cap, spend aggregate
    /// and audit total is expressed in that currency; the rate used is stamped on
    /// each row so past spend does not move when the table does. A pair with no
    /// configured rate leaves the charge unstated and badged rather than
    /// converted at a guess.
    pub pricing: crate::pricing::PricingSettings,
    /// Resolved guardrail settings pre-bucketed by **guardrail** profile id,
    /// built once at snapshot load (tenant-wide [`GuardrailBackendSettings`]
    /// folded with each profile's [`GuardrailPolicy`] via
    /// [`crate::guardrail::GuardrailSettings::resolve`]). Resolved per request
    /// via [`Self::effective_guardrail`].
    pub guardrail_by_profile: HashMap<uuid::Uuid, crate::guardrail::GuardrailSettings>,
    /// Fallback resolved guardrail for a workspace that resolves to no guardrail
    /// profile (degenerate / SYSTEM — seeding always creates a default guardrail
    /// profile, so this is a safety net). Backend folded with the default
    /// profile's policy (or [`crate::guardrail::GuardrailPolicy::default`]).
    pub guardrail_default: crate::guardrail::GuardrailSettings,
    /// **Resolved** public URL of the proxy gateway for this tenant — the
    /// admin-api collapses the SYSTEM-default-with-tenant-override layering
    /// into a single value at snapshot time. Used by MCP spec-OAuth to
    /// compute the audience and validate JWT bearers, and by the MCP CORS
    /// allowlist. `None` means *neither* the tenant override nor the SYSTEM
    /// default is configured — dependent surfaces fail closed (503).
    pub proxy_public_url: Option<String>,
    /// **Resolved** public URL of the admin/portal UI for this tenant —
    /// same layering as `proxy_public_url`. The co-resident fallback for
    /// `api_public_url`, and (indirectly via the admin-api) the origin for
    /// login/invite/email links. `None` means dependent surfaces fail closed.
    pub admin_public_url: Option<String>,
    /// **Resolved** public URL of the canonical admin-API origin for this
    /// tenant — same layering as `proxy_public_url`. The production deploy
    /// shapes serve UI and API on separate vhosts, so machine-facing OAuth
    /// discovery (the RFC 9728 `authorization_servers` entry) must point
    /// here. `None` means the API is co-resident with the UI — dependent
    /// surfaces fall back to `admin_public_url`.
    pub api_public_url: Option<String>,
    /// The tenant's Default workspace id (`workspaces.role = 'default'`).
    /// Used as the workspace binding for contexts minted without an API key
    /// (spec-OAuth JWTs). `None` until the snapshot carries it.
    pub default_workspace_id: Option<uuid::Uuid>,
    /// Every live `sk-`/`vk-` key of the tenant, by the raw SHA-256 of the key
    /// ([`crate::auth::virtual_key::key_digest`]).
    ///
    /// **Keys live in the configuration they route on**, published in the same
    /// value: a key's model map names servers this config's
    /// [`endpoints`](Self::endpoints) and [`credentials`](Self::credentials)
    /// carry, so the two must never be read from different versions. Read
    /// through [`crate::auth::authenticate`], which takes both from one
    /// [`Registry`] load.
    pub keys: HashMap<[u8; 32], std::sync::Arc<crate::auth::UserContext>>,
    /// Each upstream server's stored credential, opened, by server id.
    pub credentials: crate::config::credentials::ServerCredentials,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            model_map: ModelMap::default(),
            pricing: crate::pricing::PricingSettings::default(),
            audit_enabled: true,
            debug_mode: false,
            healing_enabled: false,
            stream_idle_timeout_secs: DEFAULT_STREAM_IDLE_TIMEOUT_SECS,
            content_logging_enabled: true,
            log_level: "info".to_string(),
            sanitize_tool_names: true,
            rhai_fail_mode: "open".to_string(),
            tool_rules: default_tool_rules(),
            tool_field_profiles: std::sync::Arc::default(),
            workspace_profiles: HashMap::new(),
            default_profiles: HashMap::new(),
            tool_rules_by_profile: HashMap::new(),
            app_patterns: std::sync::Arc::from([]),
            transform_programs: Vec::new(),
            transform_programs_by_profile: HashMap::new(),
            route_policies: HashMap::new(),
            media_blob_storage_enabled: true,
            media_blob_max_size_mb: 10,
            mcp: crate::config::mcp::McpConfig::default(),
            a2a: crate::config::a2a::A2aConfig::default(),
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: std::collections::HashSet::new(),
            member_limit_defaults: HashMap::new(),
            member_limit_exceptions: HashMap::new(),
            endpoints: crate::config::endpoints::EndpointTable::default(),
            qos: crate::config::qos::QosTable::default(),
            web: crate::web::WebSettings::default(),
            cache: crate::proxy::response_cache::CacheSettings::default(),
            guardrail_by_profile: HashMap::new(),
            guardrail_default: crate::guardrail::GuardrailSettings::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            keys: HashMap::new(),
            credentials: crate::config::credentials::ServerCredentials::default(),
        }
    }
}

impl TenantConfig {
    /// Parsed Rhai fail mode (see [`crate::scripting::ScriptFailMode`]).
    /// Unknown / missing / misspelled values silently fall back to
    /// `ScriptFailMode::Open` — safer default, preserves request flow.
    pub fn rhai_fail_mode_enum(&self) -> crate::scripting::ScriptFailMode {
        crate::scripting::ScriptFailMode::parse(&self.rhai_fail_mode)
    }

    /// The org-total budget ceiling that applies to a request from `workspace_id`
    /// — the tenant's ceiling, or `None` when the tenant is uncapped OR the
    /// workspace is one the organisation does not fund.
    ///
    /// Returning `None` for an excluded workspace is what makes the exclusion
    /// whole: the caller feeds it to [`crate::auth::UserContext::tenant_budget`],
    /// and the tenant bucket then disappears from the budget check and the budget
    /// accrual together. Accruing without enforcing would be defensible; enforcing
    /// without accruing is not, because the workspace could be blocked by a
    /// counter its own traffic can never move.
    pub fn tenant_budget_for(&self, workspace_id: uuid::Uuid) -> Option<crate::auth::RateLimitConfig> {
        if self.workspaces_outside_tenant_budget.contains(&workspace_id) {
            return None;
        }
        self.tenant_budget.clone()
    }

    /// The member bucket for `user_id` inside `workspace_id` — the workspace's
    /// default member limit, replaced per metric by the member's exception
    /// ([`crate::auth::member_limits::resolve_member_limit`]). `None` when
    /// nothing limits the member.
    ///
    /// A `sk-`/`vk-` key carries this already baked; the spec-OAuth path mints
    /// its context from a token claim and resolves it here, so a token is held
    /// to exactly the limit the member's keys are.
    pub fn member_limit_for(
        &self,
        workspace_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Option<crate::auth::RateLimitConfig> {
        crate::auth::member_limits::resolve_member_limit(
            self.member_limit_defaults.get(&workspace_id),
            self.member_limit_exceptions.get(&(workspace_id, user_id)),
        )
    }

    /// The resolved profile state for `(workspace_id, kind)`: the workspace's
    /// explicit choice ([`Self::workspace_profiles`] — a profile or `Off`) else
    /// the tenant default for that kind ([`Self::default_profiles`]) else
    /// [`EffectiveProfile::Unset`] (degenerate / SYSTEM). The single generic
    /// resolver every per-kind `effective_*` helper builds on.
    pub fn effective_profile(
        &self,
        workspace_id: uuid::Uuid,
        kind: ProfileKind,
    ) -> EffectiveProfile {
        match self.workspace_profiles.get(&(workspace_id, kind)) {
            Some(WorkspaceProfile::Off) => EffectiveProfile::Off,
            Some(WorkspaceProfile::Use(id)) => EffectiveProfile::Use(*id),
            None => match self.default_profiles.get(&kind) {
                Some(id) => EffectiveProfile::Use(*id),
                None => EffectiveProfile::Unset,
            },
        }
    }

    /// Effective tool-rule set for a request in `workspace_id`: the rules of the
    /// workspace's selected tool profile ([`Self::effective_profile`] for
    /// [`ProfileKind::Tools`]). Borrows the profile's pre-bucketed slice
    /// ([`Self::tool_rules_by_profile`]) with no allocation on the hot path — that
    /// bucket already resolves the Default-as-base model (a Layered profile's slice
    /// is the Default's rules ⊕ its own; a Standalone's is its own only). A tenant
    /// with no profile resolvable (no default — the SYSTEM tenant) degrades to an
    /// empty set (there is no shared baseline).
    pub fn effective_tool_rules(
        &self,
        workspace_id: uuid::Uuid,
    ) -> std::borrow::Cow<'_, [crate::config::tool_rules::Rule]> {
        match self.effective_profile(workspace_id, ProfileKind::Tools) {
            // Explicitly off → no tool rules at all (every tool allowed).
            EffectiveProfile::Off => std::borrow::Cow::Borrowed(&[]),
            EffectiveProfile::Use(pid) => match self.tool_rules_by_profile.get(&pid) {
                Some(rules) => std::borrow::Cow::Borrowed(rules.as_slice()),
                // Profile resolvable but no rules bucketed under it → empty set.
                None => std::borrow::Cow::Borrowed(&[]),
            },
            // No profile resolvable (no default — degenerate / SYSTEM) → empty.
            EffectiveProfile::Unset => std::borrow::Cow::Borrowed(&[]),
        }
    }

    /// Effective ordered transform-program set for a request in `workspace_id`:
    /// the programs of the workspace's selected transform profile
    /// ([`Self::effective_profile`] for [`ProfileKind::Transform`]). Borrows the
    /// profile's pre-bucketed slice ([`Self::transform_programs_by_profile`]) with
    /// no allocation on the hot path — that bucket already resolves the
    /// Default-as-base model (a Layered profile's slice is the Default's programs ∪
    /// its own; a Standalone's is its own only). **`Off` returns an empty set**
    /// (the Agent workspace's default — it never transforms its own traffic). A
    /// tenant with no transform profile resolvable (degenerate / SYSTEM) degrades
    /// to an empty set.
    pub fn effective_transforms(
        &self,
        workspace_id: uuid::Uuid,
    ) -> std::borrow::Cow<'_, [crate::scripting::TransformProgram]> {
        match self.effective_profile(workspace_id, ProfileKind::Transform) {
            // Explicitly off → no transforms at all.
            EffectiveProfile::Off => std::borrow::Cow::Borrowed(&[]),
            EffectiveProfile::Use(pid) => match self.transform_programs_by_profile.get(&pid) {
                Some(programs) => std::borrow::Cow::Borrowed(programs.as_slice()),
                // Profile resolvable but no programs bucketed under it → empty set.
                None => std::borrow::Cow::Borrowed(&[]),
            },
            // No profile resolvable (no default — degenerate / SYSTEM) → empty.
            EffectiveProfile::Unset => std::borrow::Cow::Borrowed(&[]),
        }
    }

    /// Effective resolved guardrail settings for a request in `workspace_id`: the
    /// workspace's selected guardrail profile ([`Self::effective_profile`] for
    /// [`ProfileKind::Guardrail`]), looked up in the pre-resolved
    /// [`Self::guardrail_by_profile`] map. Falls back to
    /// [`Self::guardrail_default`] when no guardrail profile resolves or its
    /// bucket is absent — a safety net (seeding always creates a default guardrail
    /// profile). Borrows; the backend↔policy fold happens once at snapshot load.
    pub fn effective_guardrail(
        &self,
        workspace_id: uuid::Uuid,
    ) -> &crate::guardrail::GuardrailSettings {
        /// A fully-inert guardrail (`enabled:false`, PII off) borrowed for the
        /// explicit-`Off` case — distinct from `guardrail_default`, which folds
        /// the tenant's default *policy* (PII may be on). `'static` coerces to
        /// the `&self` return lifetime.
        static GUARDRAIL_OFF: std::sync::LazyLock<crate::guardrail::GuardrailSettings> =
            std::sync::LazyLock::new(crate::guardrail::GuardrailSettings::disabled);
        match self.effective_profile(workspace_id, ProfileKind::Guardrail) {
            EffectiveProfile::Off => &GUARDRAIL_OFF,
            EffectiveProfile::Use(pid) => self
                .guardrail_by_profile
                .get(&pid)
                .unwrap_or(&self.guardrail_default),
            EffectiveProfile::Unset => &self.guardrail_default,
        }
    }

    /// Pre-bucket a tenant's tool rules into one ready-to-evaluate slice per
    /// reachable profile, for the [`Self::tool_rules_by_profile`] hot-path map
    /// (Default-as-base model — there is no shared `profile_id = None` baseline).
    ///
    /// `reachable_profile_ids` is the set of tool profiles any workspace can
    /// resolve to (the tool-kind values of `workspace_profiles` ∪ the tool default
    /// in `default_profiles`). `default_profile_id` is the kind's Default profile;
    /// `standalone` is the set of reachable profiles flagged standalone. For each
    /// profile P the bucket is a single in-order pass over the flat seq-ordered
    /// rule array, restricted to:
    /// - **the Default** and **Standalone** profiles → their own rules only
    ///   (`profile_id = Some(P)`); the Default *is* the base.
    /// - a **Layered** profile → the Default's rules (`profile_id = default`) whose
    ///   id is *not* forked by P, ∪ P-specific rules (`profile_id = Some(P)`).
    ///
    /// A Layered fork (a `Some(P)` rule with `forked_from = Some(default_rule_id)`)
    /// overrides its Default origin inside P by suppressing it and taking its own
    /// position.
    pub fn build_profile_buckets(
        tool_rules: &[crate::config::tool_rules::Rule],
        reachable_profile_ids: &[uuid::Uuid],
        default_profile_id: Option<uuid::Uuid>,
        standalone: &std::collections::HashSet<uuid::Uuid>,
    ) -> HashMap<uuid::Uuid, Vec<crate::config::tool_rules::Rule>> {
        let mut by_profile: HashMap<uuid::Uuid, Vec<crate::config::tool_rules::Rule>> =
            HashMap::new();
        for &pid in reachable_profile_ids {
            let layered = Some(pid) != default_profile_id && !standalone.contains(&pid);
            let bucket: Vec<crate::config::tool_rules::Rule> = if layered {
                // Default rule ids this profile has forked → suppress them here.
                let suppressed: std::collections::HashSet<&str> = tool_rules
                    .iter()
                    .filter(|r| r.profile_id == Some(pid))
                    .filter_map(|r| r.forked_from.as_deref())
                    .collect();
                tool_rules
                    .iter()
                    .filter(|r| {
                        if r.profile_id == default_profile_id {
                            // a Default rule — keep unless this profile forked it
                            !suppressed.contains(r.id.as_str())
                        } else {
                            r.profile_id == Some(pid)
                        }
                    })
                    .cloned()
                    .collect()
            } else {
                // Default or Standalone → own rules only.
                tool_rules
                    .iter()
                    .filter(|r| r.profile_id == Some(pid))
                    .cloned()
                    .collect()
            };
            by_profile.insert(pid, bucket);
        }
        by_profile
    }

    /// Pre-bucket a tenant's transform programs into one ready-to-run ordered
    /// slice per reachable transform profile, for the
    /// [`Self::transform_programs_by_profile`] hot-path map (Default-as-base model —
    /// no shared `profile_id = None` baseline).
    ///
    /// `reachable_profile_ids` is the set of transform profiles any workspace can
    /// resolve to. `default_profile_id` is the kind's Default; `standalone` the set
    /// of standalone profiles. For each profile P the bucket is, re-sorted by
    /// `(priority, name)`:
    /// - **Default** / **Standalone** → its own programs only (`profile_id = Some(P)`).
    /// - **Layered** → the Default's programs (`profile_id = default`) ∪ P-specific
    ///   (`profile_id = Some(P)`). Transforms have no fork — Layered is additive
    ///   only (to omit a Default program, make the profile Standalone).
    pub fn build_transform_buckets(
        programs: &[crate::scripting::TransformProgram],
        reachable_profile_ids: &[uuid::Uuid],
        default_profile_id: Option<uuid::Uuid>,
        standalone: &std::collections::HashSet<uuid::Uuid>,
    ) -> HashMap<uuid::Uuid, Vec<crate::scripting::TransformProgram>> {
        let mut by_profile: HashMap<uuid::Uuid, Vec<crate::scripting::TransformProgram>> =
            HashMap::new();
        for &pid in reachable_profile_ids {
            let layered = Some(pid) != default_profile_id && !standalone.contains(&pid);
            let mut bucket: Vec<crate::scripting::TransformProgram> = programs
                .iter()
                .filter(|p| {
                    if layered {
                        p.profile_id == default_profile_id || p.profile_id == Some(pid)
                    } else {
                        p.profile_id == Some(pid)
                    }
                })
                .cloned()
                .collect();
            bucket.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.name.cmp(&b.name)));
            by_profile.insert(pid, bucket);
        }
        by_profile
    }
}

/// Default tool risk classification rules (empty fallback).
///
/// Actual rules are seeded from `seeds/tool-policy/rules.json` into the DB
/// at tenant creation and synced on startup. This returns an empty vec
/// as a fallback until config sync delivers the DB-stored rules to the proxy.
pub fn default_tool_rules() -> Vec<crate::config::tool_rules::Rule> {
    Vec::new()
}

/// The OAuth-enabled virtual server published on an MCP slug.
///
/// `tenant_slug` may be empty: a tenant can enable OAuth on a virtual server
/// before it has a usable public identity. The 401 challenge treats that as
/// OAuth-enabled while the metadata document refuses to serve it, so the two
/// disagree deliberately and the emptiness is carried rather than filtered here.
#[derive(Debug, Clone)]
pub struct McpSlugOauth {
    pub tenant_slug: String,
    pub proxy_url: Option<String>,
    pub admin_url: Option<String>,
    pub api_url: Option<String>,
}

/// What the pre-auth MCP surfaces need to know about one `/mcp/<slug>` mount.
#[derive(Debug, Default)]
pub struct McpSlugEntry {
    /// Every tenant's resolved `proxy_public_url` for this slug, for tenants
    /// that have one. A slug is globally unique only while `oauth_enabled`, so
    /// a plain slug may legitimately exist in several tenants at once and the
    /// origin guard accepts a match against any of them.
    pub proxy_urls: Vec<String>,
    /// The OAuth-enabled virtual server on this slug, if any. At most one, since
    /// the DB enforces global uniqueness for OAuth-enabled slugs.
    pub oauth: Option<McpSlugOauth>,
}

/// Per-tenant config registry. Lock-free reads via ArcSwap.
///
/// Derefs to the tenant map, so it reads as one everywhere except at the
/// places that care: construction, the MCP slug lookups and the key lookup below.
pub struct Registry {
    tenants: HashMap<TenantId, Arc<TenantConfig>>,
    /// Cross-tenant `/mcp/<slug>` index.
    ///
    /// Four surfaces resolve a slug *before* the request has authenticated —
    /// the origin guard, the 401 `WWW-Authenticate` challenge, that challenge's
    /// origin lookup, and the protected-resource metadata document. Each of them
    /// used to walk every tenant, which let an anonymous caller drive O(tenants)
    /// work per request. They read this map instead.
    ///
    /// **Invariant: this is derived state and must be rebuilt from the very map
    /// it describes, in the same swap.** [`Registry::new`] is the only
    /// constructor for exactly that reason — an index published separately from
    /// the configs it indexes could disagree with them, and the origin guard it
    /// feeds is a security check (anti-DNS-rebinding), not a convenience.
    mcp_slugs: HashMap<String, McpSlugEntry>,
    /// Which tenant holds each key, by the key's SHA-256 — derived from the
    /// tenants' own [`TenantConfig::keys`] under the same invariant as
    /// `mcp_slugs`. Rebuilt on every publish: one fixed-size insert per live
    /// key of every tenant.
    key_tenants: HashMap<[u8; 32], TenantId>,
}

impl Registry {
    pub fn new(tenants: HashMap<TenantId, Arc<TenantConfig>>) -> Self {
        let mut mcp_slugs: HashMap<String, McpSlugEntry> = HashMap::new();
        let mut key_tenants: HashMap<[u8; 32], TenantId> =
            HashMap::with_capacity(tenants.values().map(|c| c.keys.len()).sum());
        // A key hash is unique across tenants in the database. Were one ever
        // carried by two, neither would authenticate: picking one would hand a
        // request to whichever tenant iterated last.
        let mut ambiguous: Vec<[u8; 32]> = Vec::new();
        let refuse = |id: &[u8; 32], why: &str| {
            let hash = hex::encode(id);
            if crate::log_throttle::due(&format!("key:{hash}"), std::time::Instant::now()) {
                tracing::error!(key_hash = %hash, "refusing an API key: {why} (logged once per key every {} s)", crate::log_throttle::EVERY.as_secs());
            }
        };
        for (tid, cfg) in &tenants {
            for (id, user) in &cfg.keys {
                // A key is accounted to the tenant it names: carried by another
                // tenant's config it would route on that tenant's settings.
                if user.tenant_id != tid.0 {
                    refuse(id, "it names another tenant than the one carrying it");
                    continue;
                }
                if key_tenants.insert(*id, *tid).is_some() {
                    ambiguous.push(*id);
                }
            }
        }
        for id in ambiguous {
            refuse(&id, "two tenants carry it");
            key_tenants.remove(&id);
        }
        for cfg in tenants.values() {
            for (slug, vs_id) in &cfg.mcp.virtual_server_by_slug {
                let entry = mcp_slugs.entry(slug.clone()).or_default();
                if let Some(url) = cfg.proxy_public_url.as_ref() {
                    entry.proxy_urls.push(url.trim_end_matches('/').to_string());
                }
                if cfg.mcp.virtual_servers.get(vs_id).is_some_and(|vs| vs.oauth_enabled) {
                    entry.oauth = Some(McpSlugOauth {
                        tenant_slug: cfg.tenant_slug.clone(),
                        proxy_url: cfg.proxy_public_url.clone(),
                        admin_url: cfg.admin_public_url.clone(),
                        api_url: cfg.api_public_url.clone(),
                    });
                }
            }
        }
        Self { tenants, mcp_slugs, key_tenants }
    }

    /// The key whose SHA-256 is `hash`, and the configuration of its tenant —
    /// from this one registry, so the key's routes and the endpoints and
    /// credentials they name are of the same version.
    pub fn key(&self, digest: &[u8; 32]) -> Option<(&Arc<crate::auth::UserContext>, &Arc<TenantConfig>)> {
        let config = self.tenants.get(self.key_tenants.get(digest)?)?;
        Some((config.keys.get(digest)?, config))
    }

    /// The `/mcp/<slug>` mount, if any tenant publishes it. `None` is the honest
    /// answer to "no such slug anywhere" — the same answer the walk gave.
    pub fn mcp_slug(&self, slug: &str) -> Option<&McpSlugEntry> {
        self.mcp_slugs.get(slug)
    }
}

impl std::ops::Deref for Registry {
    type Target = HashMap<TenantId, Arc<TenantConfig>>;
    fn deref(&self) -> &Self::Target {
        &self.tenants
    }
}

/// What [`RegistryCell::on_publish`] runs: given the registry being replaced
/// and its replacement.
pub type PublishHook = Box<dyn Fn(&Registry, &Registry) + Send + Sync>;

/// The gateway's configuration as one value, replaced whole. It has no `store`:
/// [`publish`] is the only way to replace it, so what must follow the
/// configuration exactly — the dispatch gate's bounds — is updated by
/// [`RegistryCell::on_publish`] before a request can route on the new one.
pub struct RegistryCell {
    current: ArcSwap<Registry>,
    /// How many times [`publish`] replaced it. A subscriber busy when changes
    /// land still learns that something changed, and loads the latest; several
    /// changes in between arrive as one.
    version: tokio::sync::watch::Sender<u64>,
    hooks: std::sync::Mutex<Vec<PublishHook>>,
}

impl RegistryCell {
    pub fn new(registry: Registry) -> Self {
        Self {
            current: ArcSwap::from_pointee(registry),
            version: tokio::sync::watch::channel(0).0,
            hooks: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<Registry>> {
        self.current.load()
    }

    pub fn load_full(&self) -> Arc<Registry> {
        self.current.load_full()
    }

    /// `f` on the current registry, under the lock every [`publish`] holds
    /// from its hooks to its store: what `f` sees is either from before a
    /// publish's hooks ran or after its store, never in between.
    pub fn locked<R>(&self, f: impl FnOnce(&Arc<Registry>) -> R) -> R {
        let _hooks = self.hooks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&self.current.load_full())
    }

    /// A receiver that wakes after every [`publish`] of this registry from now on.
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.version.subscribe()
    }

    /// Run `start` on the current registry, then `hook` on every [`publish`]
    /// from now on — synchronously, BEFORE the new registry is visible, so
    /// nothing routed on it finds what follows it a change behind. Both run
    /// under the lock every publish holds from its hooks to its store: no
    /// publish lands between `start` and the first `hook`, and the hooks of two
    /// publishes never interleave. They must be quick and must not publish.
    pub fn on_publish(
        &self,
        start: impl FnOnce(&Registry),
        hook: impl Fn(&Registry, &Registry) + Send + Sync + 'static,
    ) {
        let mut hooks = self.hooks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        start(&self.current.load());
        hooks.push(Box::new(hook));
    }
}

pub type TenantRegistry = Arc<RegistryCell>;

/// Replace the gateway's configuration: run the publish hooks, store it, and
/// tell every [`RegistryCell::changes`] subscriber — all under one lock, so a
/// hook never sees a publish half done. It does not merge: a caller that builds
/// `next` from the current registry is the registry's one writer (the config
/// sync loop), or it would lose another writer's change.
pub fn publish(registry: &TenantRegistry, next: Registry) {
    let hooks = registry.hooks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous = registry.current.load();
    for hook in hooks.iter() {
        hook(&previous, &next);
    }
    drop(previous);
    registry.current.store(Arc::new(next));
    registry.version.send_modify(|v| *v = v.wrapping_add(1));
    drop(hooks);
}

/// Create a new tenant registry, pre-populated with a default SYSTEM tenant config.
pub fn new_tenant_registry() -> TenantRegistry {
    let mut map = HashMap::new();
    map.insert(TenantId::SYSTEM, Arc::new(TenantConfig::default()));
    Arc::new(RegistryCell::new(Registry::new(map)))
}

#[cfg(test)]
mod tenant_budget_scope_tests {
    use super::*;

    fn config_with(cap: bool, outside: &[uuid::Uuid]) -> TenantConfig {
        TenantConfig {
            tenant_budget: cap
                .then(|| crate::auth::RateLimitConfig::budget_only(10.0, 100.0, false)),
            workspaces_outside_tenant_budget: outside.iter().copied().collect(),
            ..TenantConfig::default()
        }
    }

    /// The ordinary case: an org ceiling exists and applies to the workspace.
    #[test]
    fn a_funded_workspace_is_held_to_the_org_ceiling() {
        let ws = uuid::Uuid::new_v4();
        assert!(config_with(true, &[]).tenant_budget_for(ws).is_some());
    }

    /// The point of the flag. Not merely "its spend is left out of the total":
    /// the ceiling must not apply to it either, or the workspace would be
    /// blocked by a counter its own traffic can never advance.
    #[test]
    fn an_unfunded_workspace_is_outside_the_ceiling_entirely() {
        let ws = uuid::Uuid::new_v4();
        assert!(config_with(true, &[ws]).tenant_budget_for(ws).is_none());
    }

    /// The exclusion is per workspace, not per tenant — a sibling in the same
    /// tenant keeps the ceiling.
    #[test]
    fn excluding_one_workspace_leaves_its_siblings_capped() {
        let excluded = uuid::Uuid::new_v4();
        let sibling = uuid::Uuid::new_v4();
        let cfg = config_with(true, &[excluded]);
        assert!(cfg.tenant_budget_for(excluded).is_none());
        assert!(cfg.tenant_budget_for(sibling).is_some());
    }

    /// An uncapped tenant has nothing to exclude from, and the flag must not
    /// invent a ceiling for the workspaces that do count.
    #[test]
    fn an_uncapped_tenant_yields_no_ceiling_either_way() {
        let ws = uuid::Uuid::new_v4();
        assert!(config_with(false, &[]).tenant_budget_for(ws).is_none());
        assert!(config_with(false, &[ws]).tenant_budget_for(ws).is_none());
    }
}

#[cfg(test)]
mod profile_bucket_tests {
    use super::*;
    use crate::config::tool_rules::{Phase, Rule, RuleAction, Scope};

    fn rule(id: &str, profile_id: Option<uuid::Uuid>, forked_from: Option<&str>) -> Rule {
        Rule {
            id: id.to_string(),
            title: None,
            description: None,
            risk: "caution".into(),
            phase: Phase::Response,
            scope: Scope::ToolCalls,
            conditions: vec![],
            action: RuleAction::Classify,
            priority: 100,
            model_filter: None,
            app_filter: None,
            mcp_server_filter: None,
            a2a_agent_filter: None,
            enabled: true,
            framework_refs: vec![],
            is_builtin: false,
            profile_id,
            forked_from: forked_from.map(str::to_string),
        }
    }

    #[test]
    fn default_rules_layer_into_layered_buckets_standalone_isolated() {
        let pd = uuid::Uuid::new_v4(); // the Default profile (the base)
        let p1 = uuid::Uuid::new_v4(); // Layered
        let p2 = uuid::Uuid::new_v4(); // Standalone
        let rules = vec![
            rule("default-a", Some(pd), None),
            rule("p1-only", Some(p1), None),
            rule("default-b", Some(pd), None),
            rule("p2-only", Some(p2), None),
        ];
        let standalone: std::collections::HashSet<uuid::Uuid> = [p2].into_iter().collect();
        let buckets =
            TenantConfig::build_profile_buckets(&rules, &[pd, p1, p2], Some(pd), &standalone);

        let ids = |p: &uuid::Uuid| -> Vec<String> {
            buckets[p].iter().map(|r| r.id.clone()).collect()
        };
        // Default bucket = its own rules; Layered = Default ⊕ own (seq order
        // preserved); Standalone = own only (ignores the Default).
        assert_eq!(ids(&pd), vec!["default-a", "default-b"]);
        assert_eq!(ids(&p1), vec!["default-a", "p1-only", "default-b"]);
        assert_eq!(ids(&p2), vec!["p2-only"]);
    }

    #[test]
    fn fork_suppresses_default_origin_only_in_its_profile() {
        let pd = uuid::Uuid::new_v4();
        let p1 = uuid::Uuid::new_v4();
        let p2 = uuid::Uuid::new_v4();
        let rules = vec![
            rule("default-x", Some(pd), None),
            // p1 forks default-x: its copy overrides the Default rule in p1 only.
            rule("p1-fork-of-x", Some(p1), Some("default-x")),
        ];
        let standalone = std::collections::HashSet::new();
        let buckets =
            TenantConfig::build_profile_buckets(&rules, &[pd, p1, p2], Some(pd), &standalone);
        let ids = |p: &uuid::Uuid| -> Vec<String> {
            buckets[p].iter().map(|r| r.id.clone()).collect()
        };
        // p1 (Layered) sees its fork, NOT the Default origin; p2 (Layered) sees the
        // Default rule; the Default profile shows its own rule.
        assert_eq!(ids(&p1), vec!["p1-fork-of-x"]);
        assert_eq!(ids(&p2), vec!["default-x"]);
        assert_eq!(ids(&pd), vec!["default-x"]);
    }
}

#[cfg(test)]
mod profile_kind_tests {
    use super::*;

    #[test]
    fn kind_str_round_trips_for_every_variant() {
        // Drift guard: every ProfileKind::ALL variant must round-trip through
        // as_str/from_str. A new variant added to the enum without a string
        // mapping fails here (and the `match`es elsewhere fail to compile).
        for &k in ProfileKind::ALL {
            assert_eq!(ProfileKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(ProfileKind::parse("nope"), None);
    }

    #[test]
    fn effective_profile_prefers_assignment_over_default() {
        let ws = uuid::Uuid::new_v4();
        let assigned = uuid::Uuid::new_v4();
        let default = uuid::Uuid::new_v4();
        let mut cfg = TenantConfig::default();
        cfg.default_profiles.insert(ProfileKind::Tools, default);
        // No assignment → tenant default.
        assert_eq!(
            cfg.effective_profile(ws, ProfileKind::Tools),
            EffectiveProfile::Use(default)
        );
        // Explicit profile assignment wins.
        cfg.workspace_profiles
            .insert((ws, ProfileKind::Tools), WorkspaceProfile::Use(assigned));
        assert_eq!(
            cfg.effective_profile(ws, ProfileKind::Tools),
            EffectiveProfile::Use(assigned)
        );
        // Explicit Off overrides even the tenant default.
        cfg.workspace_profiles
            .insert((ws, ProfileKind::Tools), WorkspaceProfile::Off);
        assert_eq!(
            cfg.effective_profile(ws, ProfileKind::Tools),
            EffectiveProfile::Off
        );
        // A kind with no default + no assignment → Unset (degenerate).
        assert_eq!(
            cfg.effective_profile(ws, ProfileKind::Guardrail),
            EffectiveProfile::Unset
        );
    }

    #[test]
    fn effective_off_disables_tools_and_guardrail() {
        let ws = uuid::Uuid::new_v4();
        let mut cfg = TenantConfig::default();
        cfg.workspace_profiles
            .insert((ws, ProfileKind::Tools), WorkspaceProfile::Off);
        cfg.workspace_profiles
            .insert((ws, ProfileKind::Guardrail), WorkspaceProfile::Off);
        // Off → no tool rules at all (every tool allowed).
        assert!(cfg.effective_tool_rules(ws).is_empty());
        // Off → a fully-inert guardrail, never the (possibly PII-on) default.
        let g = cfg.effective_guardrail(ws);
        assert!(!g.enabled);
        assert!(!g.is_active());
        assert!(!g.pii.enabled);
    }

    #[test]
    fn effective_guardrail_falls_back_to_default() {
        let ws = uuid::Uuid::new_v4();
        let cfg = TenantConfig::default();
        // No guardrail profile resolves → the resolved default fallback.
        assert_eq!(cfg.effective_guardrail(ws), &cfg.guardrail_default);
    }
}

/// The cross-tenant MCP slug index.
///
/// Its consumers all run **before** a request has authenticated, so each case
/// below is a pre-auth behaviour: which origins the guard will accept, whether
/// the 401 carries an OAuth challenge, and whether the metadata document
/// resolves. The index replaced a per-request walk of every tenant, so these
/// assert that collapsing it kept every distinction the walk made.
#[cfg(test)]
mod mcp_slug_index_tests {
    use super::*;

    fn vs(id: uuid::Uuid, oauth_enabled: bool) -> crate::config::mcp::McpVirtualServer {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "tenant_id": uuid::Uuid::nil(),
            "slug": "tools",
            "name": "Tools",
            "oauth_enabled": oauth_enabled,
        }))
        .expect("virtual server fixture")
    }

    /// One tenant publishing `slug`, with the given public URL and OAuth flag.
    fn tenant(
        slug: &str,
        proxy_url: Option<&str>,
        tenant_slug: &str,
        oauth_enabled: bool,
    ) -> Arc<TenantConfig> {
        let vs_id = uuid::Uuid::new_v4();
        let mut cfg = TenantConfig {
            proxy_public_url: proxy_url.map(str::to_string),
            tenant_slug: tenant_slug.to_string(),
            ..Default::default()
        };
        cfg.mcp.virtual_servers.insert(vs_id, vs(vs_id, oauth_enabled));
        cfg.mcp.virtual_server_by_slug.insert(slug.to_string(), vs_id);
        Arc::new(cfg)
    }

    fn registry_of(tenants: Vec<Arc<TenantConfig>>) -> Registry {
        let map = tenants
            .into_iter()
            .map(|c| (TenantId(uuid::Uuid::new_v4()), c))
            .collect();
        Registry::new(map)
    }

    /// A slug nobody publishes must stay unknown — that `None` is what makes the
    /// origin guard fail closed and the metadata document 404.
    #[test]
    fn an_unpublished_slug_is_absent() {
        let reg = registry_of(vec![tenant("tools", Some("https://a.example"), "a", false)]);
        assert!(reg.mcp_slug("nope").is_none());
    }

    /// Slug uniqueness is enforced only for OAuth-enabled servers, so two
    /// tenants may share a plain slug. The origin guard accepts a match against
    /// ANY of them, so every candidate URL has to survive into the entry —
    /// keeping only the first would 403 the second tenant's own browser client.
    #[test]
    fn a_shared_slug_keeps_every_tenants_origin() {
        let reg = registry_of(vec![
            tenant("tools", Some("https://a.example"), "a", false),
            tenant("tools", Some("https://b.example"), "b", false),
        ]);
        let entry = reg.mcp_slug("tools").expect("published");
        let mut urls = entry.proxy_urls.clone();
        urls.sort();
        assert_eq!(urls, vec!["https://a.example", "https://b.example"]);
        assert!(entry.oauth.is_none(), "neither tenant enabled OAuth");
    }

    /// A trailing slash must not decide the guard: the inbound Origin is
    /// compared verbatim after the same trim, so the stored form has to be
    /// normalised or `https://a.example/` would never match `https://a.example`.
    #[test]
    fn candidate_origins_are_stored_without_a_trailing_slash() {
        let reg = registry_of(vec![tenant("tools", Some("https://a.example/"), "a", false)]);
        assert_eq!(
            reg.mcp_slug("tools").expect("published").proxy_urls,
            vec!["https://a.example"]
        );
    }

    /// Publishing the slug and having a usable public URL are different facts.
    /// The guard 503s ("operator must set the URL") only when the slug exists
    /// with no candidate at all, so existence must survive an absent URL.
    #[test]
    fn a_tenant_without_a_public_url_still_publishes_the_slug() {
        let reg = registry_of(vec![tenant("tools", None, "a", false)]);
        let entry = reg.mcp_slug("tools").expect("published despite no URL");
        assert!(entry.proxy_urls.is_empty());
    }

    /// The OAuth arm drives the 401 challenge and the metadata document, and
    /// carries the origins those need.
    #[test]
    fn an_oauth_enabled_slug_carries_its_tenants_identity() {
        let reg = registry_of(vec![tenant("tools", Some("https://a.example"), "acme", true)]);
        let oauth = reg
            .mcp_slug("tools")
            .expect("published")
            .oauth
            .as_ref()
            .expect("oauth-enabled");
        assert_eq!(oauth.tenant_slug, "acme");
        assert_eq!(oauth.proxy_url.as_deref(), Some("https://a.example"));
    }

    /// A tenant with no public identity can still enable OAuth. The 401 must
    /// treat the mount as OAuth-enabled while the metadata document refuses to
    /// name it, so the entry records it rather than filtering it out — the
    /// emptiness is the metadata handler's to reject.
    #[test]
    fn an_oauth_slug_on_an_unnamed_tenant_is_still_recorded() {
        let reg = registry_of(vec![tenant("tools", Some("https://a.example"), "", true)]);
        let oauth = reg
            .mcp_slug("tools")
            .expect("published")
            .oauth
            .as_ref()
            .expect("oauth-enabled even though the tenant has no slug");
        assert!(oauth.tenant_slug.is_empty());
    }

    /// The index is derived state: it must describe the map it was built with,
    /// never a previous one. `Registry::new` being the only way to build the
    /// type is what enforces this at every swap site.
    #[test]
    fn the_index_describes_the_map_it_was_built_from() {
        let before = registry_of(vec![tenant("tools", Some("https://a.example"), "a", true)]);
        assert!(before.mcp_slug("tools").is_some());

        let after = registry_of(vec![tenant("other", Some("https://a.example"), "a", true)]);
        assert!(
            after.mcp_slug("tools").is_none(),
            "the retired slug must not survive into the new snapshot"
        );
        assert!(after.mcp_slug("other").is_some());
    }
}
