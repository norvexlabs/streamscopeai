//! Route registration — four router tiers with distinct auth requirements.
//!
//! - **admin**: tenant-scoped management (users, keys, upstreams, transforms, etc.)
//! - **super-admin**: cross-tenant operations (tenant CRUD, edge node management)
//! - **portal**: end-user self-service (own keys, own usage stats)
//! - **edge nodes**: the edge node registry (the edge protocol itself is `edge_v2`)

pub mod a2a;
pub mod admin_audit;
pub mod admin_auth;
pub mod analytics;
pub mod appliance;
pub mod cli_oauth;
pub mod client_access_profiles;
pub mod client_profiles_admin;
pub mod audit;
pub mod auth_config;
pub mod double_option;
pub mod changelog;
pub mod destination_lists;
pub mod downstream;
pub mod expert_profiles;
pub mod guardrail;
pub mod internal_platform;
pub mod key_lifecycle;
pub mod keys;
pub mod mcp;
pub mod mcp_catalog;
pub mod mcp_discovery;
pub mod mcp_oauth;
pub mod model_presets;
pub mod model_fusion;
pub mod model_sync;
pub mod oauth_common;
pub mod oauth_error;
pub mod oidc_rp;
pub mod notifications_feed;
pub mod portal;
pub mod portal_auth;
pub mod portal_home;
pub mod portal_view;
pub mod portal_automation;
pub mod portal_manager;
pub mod portal_mcp;
pub mod portal_mcp_connections;
pub mod portal_mcp_test;
pub mod cli_dist;
pub mod provision;
pub mod quickstart;
pub mod cache_presets;
pub mod cache_settings;
pub mod route_policies;
pub mod runtime_config;
pub mod egress;
pub mod catalog;
pub mod service_accounts;
pub mod settings;
pub mod tenants;
pub mod tool_field_profiles;
pub mod profiles;
pub mod qos_classes;
pub mod tool_rules;
pub mod transforms;
pub mod server_analytics;
pub mod upstream_endpoints;
pub mod upstreams;
pub mod users;
pub mod pricing;
pub mod web;
pub mod workspaces;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::db::tenant::Scoped;
use crate::AdminState;

// ---------------------------------------------------------------------------
// Typed API error
// ---------------------------------------------------------------------------

/// Machine-readable error code enum. Ships in OpenAPI so clients can branch on
/// a stable identifier instead of parsing error messages. **Append-only: never
/// rename a variant** — mint a new one and let the old one fall out of use.
/// Every error body outside the RFC-shaped OAuth endpoints is an
/// `ApiErrorResponse` carrying one of these; a client branches on the code,
/// never on the message.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    // --- Tenant ---
    TenantNotFound,
    TenantSlugTaken,
    TenantInactive,
    TenantSystemImmutable,

    // --- Authentication ---
    InvalidCredentials,
    SessionExpired,
    MissingAuthHeader,
    AuthModeMismatch,
    OidcEmailClaimMissing,
    OidcEmailNotVerified,
    OidcExchangeFailed,
    OidcNotConfigured,

    // --- Authorization ---
    PermissionDenied,
    SuperAdminRequired,
    DomainNotAllowed,
    /// The authenticated admin account holds a read-only role and attempted a
    /// mutating (non-safe-method) request. Enforced at a single middleware
    /// chokepoint before the handler runs. Append-only — never reuse.
    ReadOnlyAccount,
    /// A SYSTEM (platform) tenant request targeted a customer-workload route it
    /// may not mutate. SYSTEM runs no customer workloads; only an explicit
    /// platform / self-management allowlist is mutable there. Enforced at the
    /// `system_workload_guard` middleware chokepoint. Append-only — never reuse.
    SystemTenantForbidden,

    // --- Users ---
    UserNotFound,
    UserEmailTaken,
    UserInactive,

    // --- API keys ---
    KeyNotFound,
    KeyAlreadyRevoked,
    KeyNameTaken,

    // --- Upstreams / downstream / models / routes ---
    ServerNotFound,
    DownstreamNotFound,
    DownstreamSlugTaken,
    ModelNotFound,
    RouteNotFound,
    RouteAliasTaken,
    /// Another route in the same downstream is already the default for one of
    /// the requested `default_for_tags` entries. Retry with `reassign_default_tags`
    /// to move the default to this route. Append-only.
    RouteDefaultTagConflict,
    UpstreamUnreachable,
    /// The upstream answered the write's reachability check and REFUSED the
    /// credential it was given (401/403, or a token exchange the provider
    /// declined). Distinct from `UpstreamUnreachable`, which means nothing
    /// answered: the address is right and the key is not, so the UI points at
    /// the credential rather than the URL. Overridable like unreachable — a
    /// provider may legitimately refuse the model list to a key that works for
    /// chat. Append-only.
    UpstreamCredentialRejected,
    UpstreamTimeout,
    CapabilityUnsupported,
    /// A server has no upstream URL and its provider seed carries no default —
    /// refused on create/update (every server states the URL it forwards to;
    /// there is no fallback host) and on discovery/sync. Append-only.
    UpstreamUrlMissing,
    /// A built-in BYOK pass-through provider (seeded from the provider catalog)
    /// cannot be deleted or renamed — turn its server off, or control its
    /// exposure via workspace grants, instead. Deleting it would let the next
    /// startup sync re-create it.
    /// Append-only.
    BuiltinProviderProtected,

    // --- Catalog ---
    CatalogEntryNotFound,
    CatalogEntryTaken,

    // --- Route policies ---
    RoutePolicyNotFound,

    // --- Transforms / experts ---
    TransformNotFound,
    TransformValidationFailed,
    SuggestionNotFound,
    SnippetNotFound,
    ExpertNotFound,
    AgentUnavailable,

    // --- Sessions / audit ---
    SessionNotFound,
    AuditRecordNotFound,
    MediaBlobNotFound,

    // --- Edge / infrastructure ---
    EdgeNodeNotFound,
    /// The web Appliance surface is not available on this deployment shape — the
    /// host daemon is not configured (`STOWAGE_HOST_SOCKET` unset, i.e. Kubernetes /
    /// dev). Append-only — never reuse.
    ApplianceUnavailable,
    /// The host daemon is configured but unreachable or returned an error; the
    /// raw daemon body is never forwarded. Append-only — never reuse.
    HostDaemonError,
    /// The host daemon is up and answered with a 2xx, but its JSON body didn't
    /// match the shape admin-api expects (a contract drift between the daemon and
    /// admin-api). Distinct from `HostDaemonError` so the two are diagnosable
    /// apart. Append-only — never reuse.
    HostDaemonBadResponse,
    /// A proposed appliance network configuration was refused by the host daemon
    /// (bad address, prefix out of range, gateway off-subnet, too many
    /// resolvers). No longer emitted: such a refusal is `ApplianceRequestInvalid`.
    /// Append-only — never reuse.
    ApplianceNetworkInvalid,
    /// A previous appliance network change is still inside its auto-revert window
    /// and has neither been confirmed nor reverted, so a second change is
    /// refused — the operator would otherwise lose the rollback target. No longer
    /// emitted: such a refusal is `ApplianceRefused`. Append-only — never reuse.
    ApplianceNetworkChangePending,
    /// A rollback was refused because the previous appliance slot could not
    /// start against the database as it stands (a database change removed
    /// something it still uses, or it predates reading newer schemas). No longer
    /// emitted: such a refusal is `ApplianceRefused`. Append-only — never reuse.
    ApplianceRollbackUnservable,
    /// The host daemon refused an appliance action for the appliance's state
    /// (a job runs, a reboot is scheduled, the release offered changed since it
    /// was confirmed, going back is unsafe). The daemon's reason rides the
    /// message. Append-only — never reuse.
    ApplianceRefused,
    /// The host daemon refused the operator's input to an appliance action
    /// (backup settings, network settings, a drain out of range). The daemon's
    /// reason rides the message. Append-only — never reuse.
    ApplianceRequestInvalid,
    /// A backup destination failed its test. No longer emitted: the test is a
    /// job, and the destination's reason is the job's error. Append-only —
    /// never reuse.
    ApplianceBackupUnreachable,
    /// The host daemon did not answer (no socket, no answer within the
    /// deadline). Distinct from `HostDaemonError` (it answered with an error) so
    /// a client can tell an appliance that is rebooting or wedged from a fault
    /// to show. Append-only — never reuse.
    HostDaemonUnreachable,
    /// The host daemon refused admin-api's own credential (a wrong or rotated
    /// `STOWAGE_HOST_TOKEN`): a misconfiguration, not a fault waiting mends.
    /// Append-only — never reuse.
    HostDaemonRefused,

    // --- Admin accounts ---
    AccountNotFound,
    AccessGrantNotFound,
    /// Refused: an admin tried to delete the account they're signed in as.
    CannotDeleteSelf,
    /// Refused: deleting/demoting/disabling would leave the tenant with no
    /// active full-Admin console account.
    LastAdminAccount,

    // --- Invites ---
    InviteNotFound,
    InviteExpired,
    InviteAlreadyUsed,

    // --- Rate limit / budgets ---
    RateLimitExceeded,
    BudgetExceeded,

    // --- Validation / conflict ---
    ValidationFailed,
    DuplicateResource,
    PayloadTooLarge,

    // --- Settings ---
    SettingInvalid,
    MaintenanceInProgress,

    /// admin-api boot failed before the live router could come up — typically
    /// a Postgres connect failure or a migration error. Surfaced on `/ready`
    /// (readiness) and every other endpoint by the degraded-mode HTTP server so
    /// operators and the future Updates tab can branch on a stable code.
    /// `/health` (liveness) stays 200 even while degraded — restarting can't fix
    /// a failed migration. See `docs/OPERATOR_GUIDE.md` § "Migration failed at boot."
    MigrationFailed,

    // --- Generic fallbacks ---
    NotImplemented,
    InternalError,

    // --- Tenant auth config / OIDC (append-only) ---
    AuthModeInvalid,
    OidcIssuerRequiresHttps,
    OidcIssuerUrlRequired,
    OidcIssuerUrlInvalid,
    OidcIssuerSsrfBlocked,
    PasswordLoginDisabled,
    PasswordTooShort,

    // --- Tenant slug validation ---
    TenantSlugInvalid,

    // --- Upstream / route validation ---
    ApiFormatInvalid,
    TransportInvalid,
    ReasoningEffortInvalid,
    RoutePathPatternInvalid,

    // --- Model presets ---
    PresetNotFound,
    PresetNameTaken,
    PresetSettingsInvalid,
    PresetDefaultUndeletable,

    // --- Transforms ---
    TransformPhaseInvalid,
    TransformScopeInvalid,
    TransformScriptTooLarge,
    TransformScriptCompileError,
    TransformTestContextInvalid,
    TransformTriggerInvalid,
    TransformSpanModeNeedsTrigger,

    // --- Suggestions ---
    SuggestionStatusInvalid,
    SuggestionRuleInvalid,

    // --- Catalog / pricing ---
    PriceNegative,

    // --- Media blobs ---
    MediaBlobTypeInvalid,

    // --- Invites ---
    InviteEmailMismatch,

    // --- Groups ---
    GroupRoleInvalid,

    // --- Tool risk rules ---
    ToolRiskRuleNotFound,
    ToolRiskRuleIdCollision,
    ToolRiskRuleIdInvalid,
    ToolRiskRuleRegexInvalid,
    ToolRiskRuleRiskInvalid,
    ToolRiskRuleActionInvalid,
    /// `(phase, scope, action.kind)` is not a permitted combination per the
    /// risk-rule matrix. Append-only — never reuse.
    ToolRiskRuleScopeInvalid,
    /// A condition's `target` isn't allowed for the rule's scope (e.g.
    /// `args` on `tool_definitions`). Append-only — never reuse.
    ToolRiskRuleTargetInvalid,
    ToolRiskConfigReadOnly,

    // --- Tool field profiles ---
    ToolFieldProfileNotFound,
    ToolFieldProfileIdCollision,
    ToolFieldProfileIdInvalid,
    /// `tool_pattern` or `field` empty, `tool_id` empty or non-identifier,
    /// or `field`/`tool_id` contains non-identifier characters. Append-only.
    ToolFieldProfileInvalid,
    /// Both `app_filter` and `mcp_server` were set on the same profile —
    /// they are mutually exclusive. Append-only — never reuse.
    ToolFieldProfileAppMcpExclusive,
    /// `server_type` was set on the same profile as `app_filter` or
    /// `mcp_server` — the three scoping fields are mutually exclusive.
    /// Append-only — never reuse.
    ToolFieldProfileServerTypeExclusive,
    /// The field-profile list's `normalizer` filter named no normaliser kind.
    /// Append-only — never reuse.
    ToolFieldProfileNormalizerInvalid,

    // --- Analytics filters ---
    /// Caller passed both `days` and `start`/`end` on the same query. Pick one.
    /// Append-only — never reuse.
    TimeWindowConflict,
    /// Time window failed validation: `days` ≤ 0, `start` ≥ `end`, or otherwise
    /// invalid. Append-only — never reuse.
    TimeWindowInvalid,

    // --- MCP gateway ---
    McpCatalogEntryNotFound,
    McpCatalogCredentialRequired,
    McpCatalogAdoptFailed,
    McpCatalogEntryInvalid,
    McpCatalogSourceNameTaken,
    McpUpstreamServerNotFound,
    McpUpstreamServerNameTaken,
    McpVirtualServerNotFound,
    McpVirtualServerSlugInvalid,
    McpVirtualServerSlugTaken,
    McpVirtualRouteNotFound,
    McpRoutePrefixInvalid,
    McpRoutePrefixTaken,

    // --- MCP service-account credentials ---
    /// `auth_mode = service_account` was set but no `credential` was supplied
    /// (on create) or empty-string was supplied (on rotate). Append-only.
    McpUpstreamCredentialRequired,
    /// `credential` was supplied with a non-service-account `auth_mode`.
    /// The field is meaningless outside service-account mode and stashing one
    /// would be confusing on rotation. Append-only.
    McpUpstreamCredentialNotAllowed,

    // --- MCP per-user OAuth client config ---
    /// `auth_mode = per_user_oauth` was set but the OAuth client config is
    /// missing required fields (issuer URL, authorization URL, token URL,
    /// client_id, or client_secret). Append-only.
    McpUpstreamOauthClientIncomplete,
    /// One or more `oauth_*` fields were supplied with a non-`per_user_oauth`
    /// `auth_mode`. They have no meaning outside that mode. Append-only.
    McpUpstreamOauthClientNotAllowed,
    /// Automatic OAuth-endpoint discovery from an MCP upstream URL failed —
    /// the server exposed no RFC 9728 protected-resource-metadata, its
    /// authorization-server metadata was unreachable/unparseable, or a probed
    /// URL was rejected by the SSRF guard. A single generic code for every
    /// failure mode so the endpoint can't be used as an internal port scanner;
    /// the operator falls back to entering the endpoints manually. Append-only.
    McpUpstreamOauthDiscoveryFailed,
    /// Automatic OAuth client registration (RFC 7591 dynamic client
    /// registration) was requested, but the upstream's authorization server
    /// advertises no `registration_endpoint` — it does not support DCR. The
    /// operator must register an OAuth app manually and enter the client ID and
    /// secret (e.g. GitHub). Distinct from the generic failure because it is an
    /// expected, actionable outcome for a successfully-discovered public IdP.
    /// Append-only.
    McpUpstreamDcrUnsupported,
    /// Automatic OAuth client registration (RFC 7591) failed for any other
    /// reason — discovery of the registration endpoint failed, the registration
    /// POST was refused/timed out, the response was unparseable, or a probed URL
    /// was rejected by the SSRF guard. A single generic code (like
    /// `McpUpstreamOauthDiscoveryFailed`) so the endpoint can't be used as an
    /// internal port scanner; the operator falls back to manual registration.
    /// Append-only.
    McpUpstreamDcrFailed,
    /// Portal-side: caller asked to connect a non-`per_user_oauth` upstream.
    /// Append-only.
    McpUpstreamNotPerUserOauth,
    /// Portal-side: pending-authorization row not found, expired, or doesn't
    /// belong to the requesting user. Append-only.
    McpPendingAuthorizationInvalid,
    /// Portal-side: the user has no stored credential for this upstream
    /// (used by the disconnect endpoint when there's nothing to disconnect).
    /// Append-only.
    McpUserCredentialNotFound,

    // --- A2A gateway ---
    A2aAgentNotFound,
    A2aAgentSlugInvalid,
    /// The `/a2a/<slug>` mount handle is globally unique across tenants (the
    /// pre-auth card endpoint resolves the tenant by slug alone). Append-only.
    A2aAgentSlugTaken,
    /// The fetched agent card is unusable: unreachable, oversized, not JSON,
    /// or missing a JSONRPC protocol-version 1.0 interface. One generic code
    /// for every fetch-failure mode so the endpoint can't be used as an
    /// internal port scanner. Append-only.
    A2aAgentCardInvalid,
    /// The fetched agent card was refused admission by the tenant's default
    /// guardrail profile: its prose was flagged as injection, could not be
    /// fully scanned, or the classifier errored while the profile fails
    /// closed. The card is never stored. Append-only.
    A2aAgentCardRejected,
    /// `auth_mode = service_account` with no credential available. Append-only.
    A2aCredentialRequired,
    /// A credential was supplied with a non-service-account `auth_mode`.
    /// Append-only.
    A2aCredentialNotAllowed,

    // --- Workspaces ---
    /// Referenced workspace id doesn't exist in this tenant. Append-only.
    WorkspaceNotFound,
    /// Caller tried to mint a key in a workspace the target user isn't a member
    /// of. Keys bill against the workspace budget; non-members can't hold one.
    /// Append-only.
    WorkspaceMembershipRequired,
    /// Caller tried a workspace-manager action (view the roster/usage, mint or
    /// revoke a member's key) without being a `manager` of that workspace.
    /// Append-only.
    WorkspaceManagerRequired,
    /// A workspace with this slug already exists in the tenant. Append-only.
    WorkspaceSlugTaken,
    /// A default member limit was set on the Agent or Inline-AI workspace, where
    /// one service member carries the whole organisation's automated traffic.
    /// Append-only.
    MemberDefaultsNotAllowed,
    /// A workspace manager tried to set, change or remove their OWN member
    /// exception — only an administrator may. Append-only.
    MemberLimitSelfEditForbidden,
    /// A workspace manager tried to set, change or remove the exception of
    /// ANOTHER manager of the workspace — a manager's limit is admin-only, or
    /// two managers could raise each other's. Append-only.
    MemberLimitManagerEditForbidden,
    /// Caller tried to delete the Default workspace (`role = 'default'`). It is
    /// the built-in workspace and cannot be removed (its members, allowlist, and
    /// rate-limit are otherwise editable like any workspace). Append-only.
    WorkspaceDefaultProtected,
    /// Caller tried to delete the Agent workspace (`role = 'agent'`). It is the
    /// built-in home of the internal analysis agent's key and cannot be removed
    /// (grants, budget, and profiles are editable like any workspace). Append-only.
    WorkspaceAgentProtected,
    /// Caller tried to delete the Inline AI workspace (`role = 'inline'`).
    /// It is the built-in home of the inline-AI managed key and cannot be
    /// removed (profiles, budget, and rate-limit are editable like any
    /// workspace). Append-only.
    WorkspaceInlineAiProtected,

    // --- Profiles (generic, all kinds) ---
    /// Referenced profile id doesn't exist in this tenant (or is the wrong kind,
    /// e.g. assigning a workspace to a profile that was deleted). Append-only.
    ProfileNotFound,
    /// A profile with this slug already exists in the tenant for its kind, or the
    /// reserved `default` slug was requested. Append-only. (Superseded by
    /// `ProfileNameTaken` — profiles dropped the vestigial slug; the code stays
    /// for the append-only contract.)
    ProfileSlugTaken,
    /// A profile with this name already exists in the tenant for its kind.
    /// Append-only.
    ProfileNameTaken,
    /// Caller tried to delete a kind's default profile (`is_default = true`). It
    /// is the fallback every workspace resolves to and cannot be removed.
    /// Append-only.
    ProfileDefaultProtected,
    /// The requested profile `kind` is not one this build knows. Append-only.
    ProfileKindInvalid,

    // --- MCP BYOT routing ---
    /// Operator tried to bind a `byot` upstream to a virtual server that already
    /// has another route. BYOT requires an unambiguous (single-route)
    /// destination because the client's bearer is forwarded to exactly one
    /// upstream. Append-only.
    McpKeyMultiUpstream,
    /// Caller tried to mutate a built-in `mcp_upstream_servers` row
    /// (`built_in = true`, e.g. the synthetic `internal://web`
    /// upstream). DELETE / PATCH / config-credential routes refuse with
    /// HTTP 409. Backend / settings edits go through the dedicated
    /// `web` admin endpoints (phase 2). Append-only.
    McpUpstreamServerBuiltInProtected,
    /// DELETE refused because the upstream is still wired into one or more
    /// `mcp_virtual_routes`. Operators detach the routes first (or delete the
    /// owning endpoint). The FK is `ON DELETE NO ACTION` deliberately — we
    /// surface the dependency rather than silently orphaning live keys.
    /// Append-only.
    McpUpstreamServerInUse,
    /// PATCH attempted to change `auth_mode` on an existing upstream. The
    /// four modes carry different credential shapes; mode flips would silently
    /// drop or strand credentials. Operators delete + recreate to switch.
    /// Append-only.
    McpUpstreamAuthModeLocked,

    // --- MCP spec-OAuth ---
    /// `client_id` lookup failed (manual/dcr/cimd registration not found).
    /// Append-only.
    McpOauthClientNotFound,
    /// `client_id` already registered for this tenant. Append-only.
    McpOauthClientIdTaken,
    /// `redirect_uri` doesn't match any registered URI for the client.
    /// Append-only.
    McpOauthRedirectUriMismatch,
    /// `code_challenge_method` is not `S256`. `plain` is rejected. Append-only.
    McpOauthInvalidChallengeMethod,
    /// Authorization code not found, expired, or already consumed. Append-only.
    McpOauthInvalidGrant,
    /// PKCE verifier did not match the stored challenge. Append-only.
    McpOauthInvalidVerifier,
    /// `resource` parameter (RFC 8707) doesn't resolve to a tenant virtual
    /// server, or the virtual server has `oauth_enabled=false`. Append-only.
    McpOauthInvalidResource,
    /// Issued JWT not found, or already revoked. Append-only.
    McpOauthTokenNotFound,
    /// No live `ssai login` session carries this token id — unknown, or
    /// already revoked. Append-only.
    CliSessionNotFound,
    /// `oauth_enabled=true` was attempted on a virtual server slug that's
    /// already used by another tenant. Spec-OAuth requires a globally-unique
    /// slug because the protected-resource-metadata path is unauthenticated.
    /// Append-only.
    McpOauthSlugCollision,
    /// `redirect_uris` empty, contains a non-`http(s)://` scheme, or contains
    /// a localhost-with-fragment URI (RFC 6749 §3.1.2). Append-only.
    McpOauthRedirectUriInvalid,
    /// Dynamic client registration (RFC 7591) is rejected because the input is
    /// malformed (missing `redirect_uris`, unsupported `grant_types`, etc.).
    /// Append-only.
    McpOauthDcrInvalidRequest,
    /// Dynamic client registration (RFC 7591) is rejected because the tenant
    /// has reached its per-tenant OAuth-client cap. Distinct from
    /// `RateLimitExceeded` (a request-rate throttle): this is a stored-resource
    /// quota, so the rejection is audited rather than dropped as throttle
    /// overflow. Append-only.
    McpOauthDcrCapReached,
    /// CIMD (Client ID Metadata Document) URL fetch failed — network error,
    /// non-200 response, body too large, or non-JSON. Append-only.
    McpOauthCimdFetchFailed,
    /// CIMD body parsed but is missing required fields (no `redirect_uris`,
    /// non-array, etc.). Append-only.
    McpOauthCimdInvalidMetadata,
    /// Sampling intercept was enabled on a virtual server without supplying
    /// both a credential and a model alias (or by clearing one of them while
    /// the toggle remained on). Append-only.
    McpSamplingMisconfigured,

    // --- Portal quickstart / client profiles ---
    /// `client_profile` id not found in this tenant's snapshot. Append-only.
    ClientProfileNotFound,
    /// The chosen key, virtual server, and template combination is invalid:
    /// e.g. `kind = mcp` template requested with no MCP key, a `byot` BYOT-only
    /// template requested with a non-BYOT key, or `template_index` out of
    /// range. Append-only.
    ClientProfileNotCompatible,
    /// Admin override of a `client_profile` body produced syntactically
    /// invalid output for its declared format (JSON / YAML / TOML). Append-only.
    ClientProfileTemplateInvalid,
    /// POST `/client-profiles` was called with an `id` that already exists in
    /// the tenant snapshot. Editing happens via PUT on the existing id.
    /// Append-only.
    ClientProfileIdExists,
    /// A saved `client_profile`'s LLM-bearing template renders a config with
    /// the gateway key nowhere in it — not inline, not in a companion file,
    /// not in an LLM-bearing sibling — and it does not declare
    /// `key_delivery = "environment"`. The user would be handed a config that
    /// cannot authenticate. Distinct from `ClientProfileTemplateInvalid`,
    /// which means the output did not parse: an operator seeing that code
    /// would hunt a syntax error that does not exist. Append-only.
    ClientProfileKeyUnreachable,

    // --- Public URLs (per-tenant with SYSTEM default) ---
    /// Neither tenant override nor SYSTEM platform default is set for
    /// `proxy_public_url`. The dependent surface (Quickstart snippet, MCP
    /// OAuth audience, MCP CORS) fails closed. Operators set the SYSTEM
    /// default under Settings → Proxy on the system tenant; tenant admins
    /// may override on their own Settings → Proxy page. Append-only.
    ProxyPublicUrlUnset,
    /// Neither tenant override nor SYSTEM platform default is set for
    /// `admin_public_url`. The dependent surface (login link, invite email,
    /// admin/portal CORS) fails closed. Same resolution path as above. Append-only.
    AdminPublicUrlUnset,
    /// Neither tenant override nor SYSTEM platform default is set for
    /// `api_public_url`. Optional setting — only meaningful when the admin-API
    /// is deployed on a hostname distinct from `admin_public_url`. Append-only.
    ApiPublicUrlUnset,
    /// Submitted URL didn't match the validator (must be `http(s)://host[:port]`,
    /// no path/query/fragment, no trailing slash). Append-only.
    PublicUrlInvalid,
    /// A SYSTEM-tenant PATCH to `/api/v1/admin/settings` carried a key that is
    /// not meaningful on SYSTEM (the SYSTEM tenant never proxies traffic).
    /// Only platform-default keys (`proxy_public_url`, `admin_public_url`,
    /// `api_public_url`, `log_level`) are accepted on SYSTEM. Append-only.
    SettingNotMeaningfulForSystem,

    // --- Web ---
    /// `POST /api/v1/admin/web/actions/test` was invoked while `web.backend` is unset.
    /// Operators must select a backend (and supply a credential for paid
    /// providers) before the test endpoint can dispatch. Append-only.
    WebBackendUnconfigured,
    /// `POST /api/v1/admin/web/actions/test` failed at the upstream — network error,
    /// credential rejected, SSRF guard refused, or the URL filter chain denied
    /// every hit. The error message carries the underlying [`WebError`]
    /// discriminator. Append-only.
    WebTestFailed,

    // --- CLI provisioning OAuth ---
    /// A provision-scoped CLI token attempted a portal route outside the
    /// provisioning allowlist (or tried to approve an OAuth consent grant —
    /// only an interactive portal session may consent). Append-only.
    ProvisionScopeForbidden,
    /// CLI OAuth surface: `client_id` is not the well-known CLI public
    /// client. Append-only.
    OauthClientNotFound,
    /// CLI OAuth surface: `code_challenge_method` is not `S256` (or the
    /// challenge is empty). Append-only.
    OauthInvalidChallengeMethod,
    /// CLI OAuth surface: `redirect_uri` is not a loopback URI. Append-only.
    OauthRedirectUriInvalid,
    /// CLI OAuth surface: `redirect_uri` at token exchange doesn't match the
    /// one the code was issued for. Append-only.
    OauthRedirectUriMismatch,
    /// CLI OAuth surface: invalid/expired/used authorization code, refresh
    /// token, grant type, or scope. Append-only.
    OauthInvalidGrant,
    /// CLI OAuth surface: PKCE verifier did not match the stored challenge.
    /// Append-only.
    OauthInvalidVerifier,
    /// CLI distribution surface: the requested download target is unknown or
    /// this deployment ships no CLI binary. Append-only.
    CliArtifactUnavailable,
    /// CLI OAuth device grant (RFC 8628): the user has not yet approved or
    /// denied the device code — the device keeps polling. Append-only.
    OauthAuthorizationPending,
    /// CLI OAuth device grant (RFC 8628): the device polled faster than the
    /// advertised interval — it must add 5 seconds to its polling interval.
    /// Append-only.
    OauthSlowDown,
    /// CLI OAuth device grant (RFC 8628): the user denied the authorization
    /// request. Append-only.
    OauthAccessDenied,
    /// CLI OAuth device grant (RFC 8628): the device code expired before the
    /// user approved or denied it — restart the login. Append-only.
    OauthExpiredToken,

    // --- Response cache ---
    /// `cache_preset` id not found in this tenant. Append-only.
    CachePresetNotFound,
    /// A cache preset with that name already exists in the tenant. Names are
    /// the operator's handle for the preset, so they are unique. Append-only.
    CachePresetNameTaken,

    // --- Upstream endpoints (replicas of a server) ---
    /// The endpoint id does not name an endpoint of this server. Append-only.
    EndpointNotFound,
    /// Another endpoint of this server already has that URL. Append-only.
    EndpointUrlTaken,
    /// The write would leave the server with no enabled endpoint — disable the
    /// server itself instead. Append-only.
    EndpointLastEnabled,
    /// A second endpoint was requested on a server that addresses a deployment
    /// rather than a replica (a non-default transport) or on a bring-your-own-key
    /// pass-through server, or the transport was switched while the server has
    /// several endpoints. Append-only.
    EndpointsUnsupported,
    /// An endpoint URL that is not an absolute http(s) URL, a weight out of
    /// range, or a reorder that does not list every endpoint once. Append-only.
    EndpointInvalid,

    // --- QoS classes (priority under load) ---
    /// The QoS class id does not name a class of this tenant. Append-only.
    QosClassNotFound,
    /// A QoS class with that name already exists in the tenant. Append-only.
    QosClassNameTaken,
    /// The class is still chosen by workspaces, keys or route targets. The
    /// response names how many of each; deleting it means reassigning them
    /// first. Append-only.
    QosClassInUse,
    /// Caller tried to delete the tenant's default class. It is what every
    /// workspace without a class of its own resolves to. Append-only.
    QosClassDefaultProtected,
    /// Caller asked for a class more important than their workspace's, which
    /// only a tenant admin may grant. Append-only.
    QosClassNotEntitled,
    /// Another class took that star (the tenant default, or a mint default)
    /// while this write was in flight. One star of each kind per tenant.
    /// Append-only.
    QosClassStarTaken,
    /// An edge-called v2 endpoint was sent no edge token, or one that names
    /// no active edge node. Append-only.
    EdgeTokenInvalid,
    /// The admin replica has not built its edge config cache yet; poll again.
    /// Append-only.
    EdgeSyncNotReady,
    /// Another edge node already has that name. Append-only.
    EdgeNodeNameTaken,
    /// An edge's media blob was refused for its data; a resend is refused the
    /// same way, so the edge drops it. Append-only.
    EdgeBlobRefused,
    /// A replica is busy reading other edges' blob uploads; the edge sends
    /// the blob again after its backoff. Append-only.
    EdgeBlobUploadsBusy,

    // --- Request shape and routing ---
    /// No API route answers this path. Also the answer of a surface that is
    /// switched off and must not advertise that it exists. Append-only.
    ApiRouteNotFound,
    /// The path exists but does not accept this HTTP method. Append-only.
    MethodNotAllowed,
    /// The request body's `Content-Type` is not one the endpoint reads
    /// (`application/json` unless documented otherwise). Append-only.
    UnsupportedMediaType,
    /// A refusal no handler gave a cause for (a bare 4xx status from a layer).
    /// Append-only.
    RequestRefused,
    /// The deployment lacks a setting this endpoint needs (an encryption or
    /// signing key, an auth backend); retrying will not help until an operator
    /// supplies it. Append-only.
    ServerMisconfigured,

    // --- Specific conflicts ---
    /// The OIDC sign-in names an account already bound to a different
    /// identity at the provider. Append-only.
    OidcIdentityConflict,
    /// A console account with that email already exists. Append-only.
    AccountEmailTaken,
    /// A downstream provider with that name already exists. Append-only.
    DownstreamNameTaken,
    /// An upstream server with that name already exists, or the name is used
    /// by a downstream provider. Append-only.
    ServerNameTaken,
    /// A route policy already exists for this provider and path pattern.
    /// Append-only.
    RoutePolicyTaken,
    /// A transform program with that name already exists. Append-only.
    TransformNameTaken,
    /// An expert on that axis already exists. Append-only.
    ExpertAxisTaken,
    /// The tenant has not finished first-start seeding; retry shortly.
    /// Append-only.
    TenantSeedingIncomplete,
    /// The tenant already has an active emergency invite. Append-only.
    EmergencyInviteActive,
    /// The invite is invalid, expired or already used; one answer for all
    /// three so the endpoint is not an oracle for which. Append-only.
    InviteUnusable,
    /// The platform's first-run setup has already been completed.
    /// Append-only.
    SetupAlreadyCompleted,
    /// The suggestion's proposed content changed since the reviewer read it
    /// (an agent re-proposal rewrote it); reload and review again.
    /// Append-only.
    SuggestionChanged,
    /// The identity provider gave no usable answer (an outage, not this
    /// deployment's configuration); try again. Append-only.
    OidcProviderUnreachable,
    /// The requested order cannot be served under a text search (a search
    /// pages through its matches newest or oldest first); filter instead.
    /// Append-only.
    SortUnsupportedWithSearch,
    /// The address is internal and the platform's egress list for that surface
    /// does not list it (or it is the cloud metadata endpoint, which no list
    /// opens). A platform administrator lists it. Append-only.
    EgressRefused,
    /// An egress list entry is not `*`, an IP address, a CIDR prefix or a host
    /// name. Append-only.
    EgressEntryInvalid,
    /// The request body did not arrive whole: it broke off, or did not arrive
    /// within its deadline. Sending it again may succeed. Append-only.
    RequestBodyIncomplete,
    /// The client is not offered to this workspace: the administrator has
    /// disabled it under Client access. Append-only.
    ClientDisabled,
    /// No destination list with that id in this tenant. Append-only.
    DestinationListNotFound,
    /// Another destination list of this tenant already has that name.
    /// Append-only.
    DestinationListNameTaken,
    /// A destination list entry is not a host name, `*.suffix`, an IP address
    /// or a CIDR prefix with optional ports, or names every destination.
    /// Append-only.
    DestinationEntryInvalid,
    /// The profile kind has only its tenant Default: no other profile of it
    /// can be created, promoted or assigned to a workspace. Append-only.
    ProfileKindDefaultOnly,
    /// The destination list is the built-in Web tool's only allowed list:
    /// deleting it would widen the Web tool to every public site. Detach it
    /// first. Append-only.
    DestinationListInUse,
    /// The appliance keeps this action for its operator, over SSH (backup
    /// settings the operator locked): waiting does not change it. The daemon's
    /// reason rides the message. Append-only.
    ApplianceOperatorOnly,
    /// A merged list (one built in memory from several sources) was asked for
    /// a page deeper than it answers: narrow the window or the filters.
    /// Append-only.
    PageTooDeep,
    /// A traffic-log search term shorter than the minimum (`MIN_SEARCH_CHARS`
    /// characters once trimmed): it would read every row in the window.
    /// Append-only.
    SearchTermTooShort,
}

/// Structured error response body matching the proxy's `ErrorResponse` format.
#[derive(Serialize, ToSchema)]
pub struct ApiErrorResponse {
    pub error: ApiErrorBody,
}

/// Error details within an API error response.
#[derive(Serialize, ToSchema)]
pub struct ApiErrorBody {
    pub message: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ApiErrorCode>,
}

/// Typed admin-api error that serializes to `{"error": {"message": ..., "type": ..., "code": ...}}`.
///
/// Use the convenience constructors (`bad_request`, `not_found`, etc.) to create errors
/// with the appropriate HTTP status code and error type, then attach a machine-readable
/// `ApiErrorCode` via `.code(ApiErrorCode::...)`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub error_type: &'static str,
    pub code: ApiErrorCode,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into(), error_type: "invalid_request", code: ApiErrorCode::ValidationFailed }
    }
    /// Build a 404. The code is an argument because no generic "not found" code
    /// is correct: the specific variant names the missing resource for clients.
    pub fn not_found(msg: impl Into<String>, code: ApiErrorCode) -> Self {
        Self { status: StatusCode::NOT_FOUND, message: msg.into(), error_type: "not_found", code }
    }
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, message: msg.into(), error_type: "auth_error", code: ApiErrorCode::InvalidCredentials }
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::FORBIDDEN, message: msg.into(), error_type: "auth_error", code: ApiErrorCode::PermissionDenied }
    }
    /// Build a 409. The code is an argument because a conflict a client cannot
    /// tell apart (which name is taken, which state blocks it) is one it cannot
    /// offer to resolve.
    pub fn conflict(msg: impl Into<String>, code: ApiErrorCode) -> Self {
        Self { status: StatusCode::CONFLICT, message: msg.into(), error_type: "conflict", code }
    }
    /// Build a 500. The message is `&'static str` so no runtime text — a
    /// database or decryption error above all — can reach the response body:
    /// log the cause, answer a fixed sentence.
    pub fn internal(msg: &'static str) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: msg.to_string(), error_type: "internal_error", code: ApiErrorCode::InternalError }
    }
    pub fn payload_too_large(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::PAYLOAD_TOO_LARGE, message: msg.into(), error_type: "invalid_request", code: ApiErrorCode::PayloadTooLarge }
    }
    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::TOO_MANY_REQUESTS, message: msg.into(), error_type: "rate_limit_error", code: ApiErrorCode::RateLimitExceeded }
    }
    pub fn service_unavailable(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::SERVICE_UNAVAILABLE, message: msg.into(), error_type: "service_unavailable", code: ApiErrorCode::MaintenanceInProgress }
    }
    /// The 404 of a path no route answers — also the answer of a surface that
    /// is switched off and must look absent, so it matches the router's own
    /// 404 word for word.
    pub fn route_not_found() -> Self {
        Self::not_found("Not Found", ApiErrorCode::ApiRouteNotFound)
    }
    /// 503 for a deployment that lacks a setting the endpoint needs (a signing
    /// or encryption key, a service secret). Retrying does not help.
    pub fn server_misconfigured(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::SERVICE_UNAVAILABLE, message: msg.into(), error_type: "service_unavailable", code: ApiErrorCode::ServerMisconfigured }
    }
    pub fn bad_gateway(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_GATEWAY, message: msg.into(), error_type: "upstream_error", code: ApiErrorCode::UpstreamUnreachable }
    }

    /// Attach a machine-readable `ApiErrorCode` to the error. Use this at every call site.
    pub fn code(mut self, code: ApiErrorCode) -> Self {
        self.code = code;
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorResponse {
            error: ApiErrorBody {
                message: self.message,
                r#type: self.error_type.to_string(),
                code: Some(self.code),
            },
        };
        (self.status, Json(body)).into_response()
    }
}

// ---------------------------------------------------------------------------
// Credential refusals — one answer per cause, shared by every plane
// ---------------------------------------------------------------------------

/// 401 `missing_auth_header`: the request carries no `Authorization` header.
pub(crate) fn missing_bearer() -> ApiError {
    ApiError::unauthorized("missing bearer credential").code(ApiErrorCode::MissingAuthHeader)
}

/// 401 `invalid_credentials`: an `Authorization` header that authenticates
/// nothing — another scheme, a bad signature, an unknown or revoked key, an
/// expired or signed-out session. One answer for every reason, so the body is
/// not an oracle for which check failed.
pub(crate) fn rejected_credential() -> ApiError {
    ApiError::unauthorized("invalid or expired credential")
}

/// The bearer token, or the refusal that fits its absence: [`missing_bearer`]
/// with no header, [`rejected_credential`] with a header that is not `Bearer`.
pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, ApiError> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(missing_bearer());
    };
    value
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty())
        .ok_or_else(rejected_credential)
}

/// 503 `server_misconfigured` for a replica with no session-signing key: a
/// valid credential cannot be verified, and a 401 would sign the caller out.
pub(crate) fn no_signing_key() -> ApiError {
    ApiError::server_misconfigured("authentication not configured")
}

/// True when a `sqlx::Error` is a Postgres unique-constraint violation
/// (SQLSTATE `23505`).
///
/// **This is the only way to ask that question.** A duplicate is an ordinary,
/// caller-resolvable conflict — a taken name, slug or email — so a handler that
/// writes a caller-supplied value into a UNIQUE column owes a typed 409
/// ([`ApiError::conflict`]) rather than a 500 the client cannot act on and the
/// UI cannot branch on.
///
/// **Never re-derive this from the error's TEXT.** Two earlier sites matched
/// `e.to_string()` — one against the driver's English message, one against an
/// INDEX NAME — and both fail in the direction nothing notices: rename the index
/// in a migration, or change driver/locale, and the 409 silently becomes a 500
/// on the one path no happy-path test covers.
///
/// It deliberately does NOT say *which* constraint fired. Where a table has
/// several unique indexes the caller must either phrase its message so it holds
/// for any of them, or check the specific constraint another way — a message
/// naming the wrong column is worse than a generic one.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error().is_some_and(|d| d.is_unique_violation())
}

/// True when a `sqlx::Error` means the database could not be asked — the pool
/// timed out or closed, the connection failed, or Postgres refused the session
/// (SQLSTATE class `08`, `57P01`–`57P03` shutdown / starting up, `53300` too
/// many connections), or a statement it cancelled on timeout (`57014` — on these
/// key lookups, an overloaded database). Such a failure says nothing about what was being looked
/// up, so a caller answers it 503 `maintenance_in_progress`; any other error —
/// a schema the code does not match after a rollback, a revoked grant, a row
/// that does not decode — is a server fault and stays a 500, or every client
/// built to retry a 503 would retry it forever.
pub fn db_unavailable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_) => true,
        sqlx::Error::Database(d) => d
            .code()
            .is_some_and(|c| c.starts_with("08") || matches!(c.as_ref(), "57014" | "57P01" | "57P02" | "57P03" | "53300")),
        _ => false,
    }
}

/// [`ApiError`] for a failed read whose cause decides the answer: 503
/// `maintenance_in_progress` when the database could not be asked
/// ([`db_unavailable`]), 500 otherwise.
pub fn db_read_error(e: &sqlx::Error, unavailable: &str) -> ApiError {
    if db_unavailable(e) {
        ApiError::service_unavailable(unavailable)
    } else {
        ApiError::internal("internal error")
    }
}

/// True when a `sqlx::Error` is a Postgres CHECK violation (SQLSTATE `23514`),
/// asked by the driver's typed kind for the same reason as
/// [`is_unique_violation`].
pub fn is_check_violation(e: &sqlx::Error) -> bool {
    e.as_database_error().is_some_and(|d| d.is_check_violation())
}

/// True when a `sqlx::Error` is a Postgres foreign-key violation (SQLSTATE
/// `23503`) — the row a write referenced does not exist.
///
/// The companion to [`is_unique_violation`], and banned from being re-derived
/// from the error text for the same reason: matching `"foreign key"` in the
/// driver's English message decides a status from prose that no contract holds
/// stable.
pub fn is_foreign_key_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "23503")
}

/// True when a delete (or a key update) was refused because another row still
/// references the row: SQLSTATE `23503` under a `NO ACTION` foreign key, and
/// `23001` (`restrict_violation`) under `ON DELETE RESTRICT` — PostgreSQL 18
/// raises the SQL standard's own code for RESTRICT, where earlier releases
/// raised `23503`. A delete handler mapping "still in use" to a 409 asks this,
/// never the foreign-key code alone.
pub fn is_still_referenced(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "23503" || c == "23001")
}

// ---------------------------------------------------------------------------
// Per-tenant settings-blob writes
// ---------------------------------------------------------------------------

/// Atomically merge a partial JSON `patch` into a single-struct settings blob in
/// one statement and return its `(before, after)` values for the audit diff.
///
/// `INSERT … ON CONFLICT … DO UPDATE SET value = value || patch` composes per
/// top-level key, so two PUTs touching *different* fields both land — no
/// load→edit→save window, hence no lost update and no advisory lock. The
/// `ON CONFLICT` row lock serializes concurrent writers of the *same*
/// `(key, tenant_id)` row (including the fresh-tenant first-write: the second
/// INSERT conflicts and its DO-UPDATE waits on the lock, then merges onto the
/// committed value). `base` is the full value written when the row doesn't yet
/// exist (the struct's defaults already merged with the patch); `patch` is the
/// partial object merged on conflict. Both structs are flat, so the shallow
/// `||` semantics match a wholesale field set.
///
/// **Invariant — `patch` keys must be exact serde field names of the target
/// struct.** A typo'd key is silently ignored; the per-struct round-trip unit
/// test guards against drift.
pub(crate) async fn merge_settings_blob(
    conn: &mut Scoped,
    key: &str,
    tenant_id: Uuid,
    base: &serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(Option<serde_json::Value>, serde_json::Value), ApiError> {
    sqlx::query_as::<_, (Option<serde_json::Value>, serde_json::Value)>(
        "WITH old AS (
             SELECT value FROM system_settings WHERE key = $1 AND tenant_id = $2
         ),
         up AS (
             INSERT INTO system_settings (key, tenant_id, value, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (tenant_id, key)
             DO UPDATE SET value = system_settings.value || $4, updated_at = now()
             RETURNING value
         )
         SELECT (SELECT value FROM old), up.value FROM up",
    )
    .bind(key)
    .bind(tenant_id)
    .bind(base)
    .bind(patch)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("merge settings blob '{key}': {e}");
        ApiError::internal("failed to update settings")
    })
}

/// The full value to write when a single-struct settings blob has no row yet:
/// the struct's defaults with `patch` merged on top (shallow, matching the SQL
/// `||` semantics `merge_settings_blob` applies on conflict).
pub(crate) fn default_merged<T: Default + Serialize>(patch: &serde_json::Value) -> serde_json::Value {
    let mut base = serde_json::to_value(T::default()).unwrap_or_else(|_| serde_json::json!({}));
    if let (Some(b), Some(p)) = (base.as_object_mut(), patch.as_object()) {
        for (k, v) in p {
            b.insert(k.clone(), v.clone());
        }
    }
    base
}

// ---------------------------------------------------------------------------
// Response envelopes — lists are pages, side effects an `ActionResponse` (200)
// ---------------------------------------------------------------------------

/// Default pagination shape — no `total`, cheap on partitioned/hot tables.
/// Handlers select `limit + 1` rows; `has_more` is `true` when the extra row existed.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OffsetPage<T: ToSchema> {
    pub items: Vec<T>,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
    /// `true` when a text search stopped at its scan budget before it could
    /// fill the page: more matches may exist past what was scanned, and
    /// `has_more` says nothing about them — narrow the window or the term.
    /// Always `false` for a list without a search.
    pub scan_cut: bool,
}

#[allow(dead_code)]
impl<T: ToSchema> OffsetPage<T> {
    /// Build from a vector that may contain `limit + 1` rows — the extra row signals `has_more`.
    pub fn from_overfetched(mut rows: Vec<T>, limit: i64, offset: i64) -> Self {
        let has_more = rows.len() as i64 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        Self { items: rows, limit, offset, has_more, scan_cut: false }
    }

    /// The same page, saying whether its search stopped at the scan budget.
    pub fn with_scan_cut(mut self, scan_cut: bool) -> Self {
        self.scan_cut = scan_cut;
        self
    }
}

/// Pagination with `total` — opt-in for lists where `COUNT(*)` is index-only
/// and under 50 ms at p99.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TotalPage<T: ToSchema> {
    pub items: Vec<T>,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
    pub total: i64,
}

#[allow(dead_code)]
impl<T: ToSchema> TotalPage<T> {
    pub fn new(items: Vec<T>, limit: i64, offset: i64, total: i64) -> Self {
        let has_more = offset + (items.len() as i64) < total;
        Self { items, limit, offset, has_more, total }
    }
}

// ---------------------------------------------------------------------------
// Spend — an aggregate money figure, with the currency it is stated in
// ---------------------------------------------------------------------------

/// One pricing unit's contribution to an aggregate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpendUnit {
    /// Pricing-unit wire name — `input_token`, `audio_second`, …
    #[schema(value_type = String, example = "input_token")]
    pub unit: streamscope_core::pricing::Unit,
    /// Units charged, summed over the aggregate. The provider's reported count
    /// less anything charged on a line of its own, so the lines never double
    /// count.
    pub count: i64,
    /// What that count cost, in the enclosing figure's currency.
    pub cost: f64,
}

/// A spend total and the accounting currency it is stated in.
///
/// Every audit row stamps the currency in force when it was written, because
/// changing the tenant's accounting currency must not restate spend already
/// reported. An aggregate is therefore only a figure when every row behind it
/// shares one currency — wherever this type appears as an `Option`, `None`
/// means the rows straddle a change of that setting, and adding their amounts
/// would state a total in no currency at all.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct SpendTotal {
    #[schema(value_type = String, example = "USD")]
    pub currency: streamscope_core::pricing::Currency,
    pub amount: f64,
}

/// A spend total decomposed per pricing unit.
///
/// Carries the same currency contract as [`SpendTotal`], and names its figure
/// `amount` for the same reason — one accessor renders either. `amount` is the
/// whole charge: the `units` costs summed, plus `embedding`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SpendBreakdown {
    #[schema(value_type = String, example = "USD")]
    pub currency: streamscope_core::pricing::Currency,
    pub amount: f64,
    /// The part of `amount` the media endpoints accounted for. Cuts across the
    /// units rather than adding to them — a transcription's `audio_second`
    /// line is media, an ordinary completion's `input_token` line is not.
    pub media: f64,
    /// Response-cache embedding calls, charged to the requests that triggered
    /// them. Outside `units` because they price a different model.
    pub embedding: f64,
    /// Per-pricing-unit decomposition of `amount`, in unit declaration order.
    /// A unit nothing consumed is omitted rather than reported as a zero line.
    pub units: Vec<SpendUnit>,
}

/// Per-pricing-unit aggregate columns over `llm_audit.billed_units`, for
/// splicing into an aggregate's select list (`a` must be the `llm_audit` alias,
/// as in [`crate::audit_store::filters::AUDIT_LOG_JOIN`]).
///
/// The unit vocabulary is closed, so naming every unit explicitly keeps the
/// decomposition inside the SAME scan as the rest of the aggregate. The
/// alternative shapes are both worse: a `jsonb_each` lateral multiplies every
/// audit row by its unit count before grouping, and a second query doubles the
/// scan of a partitioned table. A new `Unit` variant joins here with no SQL
/// edit — and is read back by [`read_spend_units`], which walks the same list.
///
/// Every fragment is built from `Unit::wire()`, a compile-time constant, so
/// nothing request-derived reaches the SQL text.
pub fn billed_unit_columns() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        streamscope_core::pricing::Unit::ALL
            .iter()
            .map(|u| {
                let w = u.wire();
                format!(
                    ", COALESCE(SUM((a.billed_units->'{w}'->>'count')::bigint), 0)::bigint AS u_{w}_count\
                     , COALESCE(SUM((a.billed_units->'{w}'->>'cost')::double precision), 0.0)::double precision AS u_{w}_cost"
                )
            })
            .collect()
    });
    &COLUMNS
}

/// The same columns projected from an already-aggregated subquery aliased
/// `agg` — the shape `usage_breakdown` uses, where the aggregate runs inside a
/// LIMITed subquery and the outer select only forwards it.
pub fn billed_unit_columns_forwarded() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        streamscope_core::pricing::Unit::ALL
            .iter()
            .map(|u| {
                let w = u.wire();
                format!(", agg.u_{w}_count, agg.u_{w}_cost")
            })
            .collect()
    });
    &COLUMNS
}

/// Aggregate columns that state a spend total together with the currency it is
/// in: the amount, how many distinct currencies the group holds, and which one
/// (meaningful only when that count is 1). `a` must be the `llm_audit` alias.
///
/// Pair with [`spend_total`], which turns the three back into a figure.
pub const SPEND_TOTAL_COLUMNS: &str = "COALESCE(SUM(a.cost), 0.0)::double precision AS amount\
     , COUNT(DISTINCT a.cost_currency)::bigint AS currency_count\
     , MIN(a.cost_currency) AS currency";

/// Turn a [`SPEND_TOTAL_COLUMNS`] aggregate into a figure.
///
/// - **No priced rows** → zero in `fallback`, the tenant's current accounting
///   currency. "Spent nothing" must not read the same as "spent something in a
///   denomination we cannot name".
/// - **One currency** → that figure.
/// - **More than one** → `None`. The rows straddle a change of the tenant's
///   accounting currency, so they are stated in different denominations and
///   adding them would give a total in neither.
pub fn spend_total(
    currency_count: i64,
    currency: Option<String>,
    amount: f64,
    fallback: streamscope_core::pricing::Currency,
) -> Option<SpendTotal> {
    match currency_count {
        0 => Some(SpendTotal { currency: fallback, amount: 0.0 }),
        1 => currency
            .as_deref()
            .and_then(|code| stored_currency(code, None))
            .map(|currency| SpendTotal { currency, amount }),
        _ => None,
    }
}

/// The currency a stored spend row names, or `None` when its code does not
/// parse — and then the amount it labels is not stated anywhere: a single
/// figure reads as having none, and a per-currency list leaves that group out.
/// One behaviour for every reader, so no total silently differs from another.
///
/// It cannot happen to a row the ingest wrote: `cost_currency` is written from
/// a typed `Currency` (the column defaults to `USD`), so a code that does not
/// parse was written by something else. That is logged once per
/// `(tenant, code)` per process — not on every request that reads it.
pub(crate) fn stored_currency(
    code: &str,
    tenant: Option<Uuid>,
) -> Option<streamscope_core::pricing::Currency> {
    let parsed = streamscope_core::pricing::Currency::parse(code);
    if parsed.is_none() {
        /// Every `(tenant, code)` already logged.
        type Seen = std::sync::Mutex<std::collections::HashSet<(Option<Uuid>, String)>>;
        static SEEN: std::sync::OnceLock<Seen> = std::sync::OnceLock::new();
        let first = SEEN
            .get_or_init(Default::default)
            .lock()
            .map(|mut seen| seen.insert((tenant, code.to_owned())))
            .unwrap_or(true);
        if first {
            tracing::error!(
                tenant = ?tenant,
                code,
                "a stored spend currency does not parse; the amount it labels is not stated"
            );
        }
    }
    parsed
}

/// [`spend_total`] of one [`SPEND_TOTAL_COLUMNS`] aggregate, denominating a
/// zero in the tenant's accounting currency — read only when the aggregate
/// priced nothing, the one case that needs it.
pub(crate) async fn denominated_spend(
    conn: &mut Scoped,
    currency_count: i64,
    currency: Option<String>,
    amount: f64,
) -> Option<SpendTotal> {
    let fallback = if currency_count == 0 {
        pricing::accounting_currency(conn).await
    } else {
        streamscope_core::pricing::Currency::USD
    };
    spend_total(currency_count, currency, amount, fallback)
}

/// What a ranking by spend reads of one group: the part of its spend booked
/// in the tenant's accounting currency today, the lowest currency code it
/// holds, and its whole amount when it holds one currency only.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct SpendRank {
    /// The group's spend in today's accounting currency; `None` when none of
    /// its rows is in it.
    pub in_current: Option<f64>,
    /// The lowest currency code among the group's rows; `None` for a group
    /// with no row to rank by.
    pub lowest_currency: Option<streamscope_core::pricing::Currency>,
    /// The group's whole amount, only when all its rows share one currency.
    pub single: Option<f64>,
}

impl SpendRank {
    /// The one rule every list ordered by spend follows, so it never compares
    /// two amounts in different denominations, and a group whose window
    /// straddles a change of the accounting currency keeps its place:
    ///
    /// 1. groups that spent in today's accounting currency first, by that
    ///    amount, largest first — a straddling group (`spend: null`, "mixed")
    ///    ranks by the part it spent in today's currency, so a top-N list
    ///    across a currency change still holds its top spenders;
    /// 2. then groups with nothing in today's currency, by their lowest
    ///    currency code, and within one currency by amount, largest first
    ///    (a straddling one of these is not ordered by any amount).
    ///
    /// The caller breaks the remaining ties deterministically (request count,
    /// then id). In a window that holds one currency — the ordinary case —
    /// this is simply "largest spend first". [`spend_rank_order_sql`] states
    /// the same keys as SQL; keep the two in step.
    pub(crate) fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        // DESC NULLS LAST on an amount; ASC NULLS LAST on a code.
        fn amount_desc(a: Option<f64>, b: Option<f64>) -> Ordering {
            match (a, b) {
                (Some(a), Some(b)) => b.total_cmp(&a),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        }
        let code = match (self.lowest_currency, other.lowest_currency) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        amount_desc(self.in_current, other.in_current)
            .then(code)
            .then_with(|| amount_desc(self.single, other.single))
    }
}

/// [`SpendRank::cmp`] as the leading `ORDER BY` keys of a query grouped by
/// the ranked entity over `llm_audit a`, with the current accounting
/// currency's code bound at `$current_bind`. Follow it with the caller's
/// tiebreaks.
///
/// Only same-currency amounts are compared: the first key sums one currency,
/// and the last is NULL for a group of more than one. Only an integer is
/// spliced; the rest is a constant.
pub(crate) fn spend_rank_order_sql(current_bind: u32) -> String {
    format!(
        "SUM(a.cost) FILTER (WHERE a.cost_currency = ${current_bind}) DESC NULLS LAST, \
         MIN(a.cost_currency), \
         CASE WHEN COUNT(DISTINCT a.cost_currency) = 1 THEN SUM(a.cost) END DESC NULLS LAST"
    )
}

/// The decomposition half of a spend aggregate: the media share, the
/// response-cache embedding share, and the per-unit lines. Shared by the
/// grouped and ungrouped select lists below so the two cannot drift.
fn spend_decomposition_columns() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            ", COALESCE(SUM(CASE WHEN a.media_call IS NOT NULL THEN a.cost ELSE 0 END), 0.0)::double precision AS media\
             , COALESCE(SUM(a.embedding_cost), 0.0)::double precision AS embedding{}",
            billed_unit_columns()
        )
    });
    &COLUMNS
}

/// Select list of a spend aggregate over the WHOLE window, plus the count of
/// distinct currencies in it.
///
/// This is the shape to reach for first: it rides an aggregate the caller is
/// already running (measured at ~1.1x that query, against ~2x for a second
/// scan of a partitioned table), and it answers the ordinary single-currency
/// window outright. Only when `currency_count` comes back above 1 does the
/// caller need [`spend_breakdown_columns`] — a second, grouped pass, paid for
/// exactly by the windows that genuinely straddle a currency change.
pub fn spend_breakdown_columns_ungrouped() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!("{SPEND_TOTAL_COLUMNS}{}", spend_decomposition_columns())
    });
    &COLUMNS
}

/// Select list of a **per-currency** spend aggregate over `llm_audit`. Group
/// the query by `a.cost_currency`.
pub fn spend_breakdown_columns() -> &'static str {
    static COLUMNS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "a.cost_currency AS currency\
             , COALESCE(SUM(a.cost), 0.0)::double precision AS amount{}",
            spend_decomposition_columns()
        )
    });
    &COLUMNS
}

/// Read one group of a [`spend_breakdown_columns`] aggregate.
///
/// A row whose currency the build cannot parse yields `None` rather than a
/// figure under a guessed code — an amount labelled with the wrong
/// denomination is worse than one the console declines to state.
pub fn read_spend_breakdown(row: &sqlx::postgres::PgRow, tenant: Uuid) -> Option<SpendBreakdown> {
    use sqlx::Row;
    let code: String = row.try_get("currency").ok()?;
    let currency = stored_currency(&code, Some(tenant))?;
    Some(SpendBreakdown {
        currency,
        amount: row.try_get("amount").unwrap_or(0.0),
        media: row.try_get("media").unwrap_or(0.0),
        embedding: row.try_get("embedding").unwrap_or(0.0),
        units: read_spend_units(row),
    })
}

/// Fold the rows of `tenant`'s [`spend_breakdown_columns`] aggregate,
/// largest first. A group whose currency does not parse is left out — see
/// [`stored_currency`], which logs it.
pub fn read_spend_breakdowns(rows: &[sqlx::postgres::PgRow], tenant: Uuid) -> Vec<SpendBreakdown> {
    let mut out: Vec<SpendBreakdown> =
        rows.iter().filter_map(|row| read_spend_breakdown(row, tenant)).collect();
    out.sort_by(|a, b| b.amount.total_cmp(&a.amount));
    out
}

/// Read the per-unit lines a [`billed_unit_columns`] aggregate produced.
///
/// A unit with no count and no cost is dropped: it is a unit the window never
/// consumed, not a line worth reporting as zero.
pub fn read_spend_units(row: &sqlx::postgres::PgRow) -> Vec<SpendUnit> {
    use sqlx::Row;
    streamscope_core::pricing::Unit::ALL
        .iter()
        .filter_map(|u| {
            let count: i64 = row.try_get(format!("u_{}_count", u.wire()).as_str()).unwrap_or(0);
            let cost: f64 = row.try_get(format!("u_{}_cost", u.wire()).as_str()).unwrap_or(0.0);
            (count != 0 || cost != 0.0).then_some(SpendUnit { unit: *u, count, cost })
        })
        .collect()
}

/// Envelope for side-effect / action endpoints (`POST /.../actions/{verb}`,
/// `POST /admin/maintenance/{verb}`).
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ActionResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// What the action did, as counts. Each action sets only the fields it reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<ActionImpact>,
}

#[allow(dead_code)]
impl ActionResponse {
    pub fn ok() -> Self {
        Self { ok: true, message: None, impact: None }
    }
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
    pub fn with_impact(mut self, impact: impl Into<ActionImpact>) -> Self {
        self.impact = Some(impact.into());
        self
    }
}

/// What a side-effecting action did, reported in [`ActionResponse::impact`].
/// One type for every action, so the spec states the shape; an action sets
/// only the fields it reports and the rest are absent from the body.
#[derive(Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct ActionImpact {
    /// Reset to seed: builtins written back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtins_restored: Option<usize>,
    /// Reset to seed: custom rows kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_preserved: Option<usize>,
    /// Reset to seed: deleted builtins brought back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_builtins_cleared: Option<usize>,
    /// Profile reset: content items the profile holds again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_restored: Option<i64>,
    /// Model or server delete: curated downstream routes left without a model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphaned_routes: Option<u32>,
    /// Model or server delete: the downstream providers that lost a route.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstreams: Option<Vec<String>>,
    /// Catalog delete: upstream models whose explicit link named the entry,
    /// unlinked so they auto-match again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models_unlinked: Option<u64>,
    /// Cache preset delete: routes that now serve uncached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routes_uncached: Option<i64>,
    /// Suggestion approval: the transform program it installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<Uuid>,
    /// Member removal: the member's keys in the workspace that were revoked.
    /// Server delete: the keys bound to its pass-through, revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_revoked: Option<u64>,
    /// Server delete: the model overrides of its pass-through, deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overrides_removed: Option<i64>,
    /// Server delete: the workspace grants of its pass-through, removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspaces_ungranted: Option<i64>,
    /// QoS class delete: workspaces moved to the replacement class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspaces_moved: Option<i64>,
    /// QoS class delete: keys moved to the replacement class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_moved: Option<i64>,
    /// QoS class delete: route targets moved to the replacement class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_targets_moved: Option<i64>,
}

impl From<ResetImpact> for ActionImpact {
    fn from(r: ResetImpact) -> Self {
        Self {
            builtins_restored: Some(r.builtins_restored),
            custom_preserved: Some(r.custom_preserved),
            deleted_builtins_cleared: Some(r.deleted_builtins_cleared),
            ..Self::default()
        }
    }
}

/// What a "reset builtins to seed" action did: recorded on the audit row and
/// reported through [`ActionImpact`]. Shared by every seeded collection's reset
/// — the three counts are the same question in each case ("what came back, what
/// did I keep, what deletion did I undo").
#[derive(Debug, Serialize)]
pub struct ResetImpact {
    pub builtins_restored: usize,
    pub custom_preserved: usize,
    pub deleted_builtins_cleared: usize,
}

// ---------------------------------------------------------------------------
// Shared query parameter structs — an endpoint declares only the filters it applies
// ---------------------------------------------------------------------------

/// Pagination query parameters shared across every list endpoint. Compose via
/// `#[serde(flatten)]` alongside endpoint-specific filters.
#[allow(dead_code)]
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// Maximum number of items to return. Default 50, capped at `MAX_LIMIT`.
    pub limit: Option<i64>,
    /// Number of items to skip from the beginning. Default 0.
    pub offset: Option<i64>,
}

#[allow(dead_code)]
impl PageQuery {
    pub fn resolve(&self) -> (i64, i64) {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        (limit, resolve_offset(self.offset))
    }
}

/// Deepest offset any list resolves. It lies past every row count a list can
/// hold, so the clamp never changes a page; it keeps `offset + limit + 1`
/// (every overfetch) far from `i64` overflow.
pub const MAX_OFFSET: i64 = 1_000_000_000_000_000;

/// A list's offset: absent is 0, a negative one is 0, and it never exceeds
/// [`MAX_OFFSET`]. Every list resolves its offset here.
pub fn resolve_offset(offset: Option<i64>) -> i64 {
    offset.unwrap_or(0).clamp(0, MAX_OFFSET)
}

/// Deepest offset a merged list answers. Such a list holds the first
/// `offset + limit + 1` rows of each of its sources in memory to find the
/// page, so its cost grows with the offset.
pub const MAX_MERGED_OFFSET: i64 = 10_000;

/// Refuses an offset past [`MAX_MERGED_OFFSET`] with a 400 `PageTooDeep`,
/// never a shallower page than the one asked for.
pub fn check_merged_offset(offset: i64) -> Result<(), ApiError> {
    if offset > MAX_MERGED_OFFSET {
        return Err(ApiError::bad_request(format!(
            "offset {offset} is past the deepest page this list answers ({MAX_MERGED_OFFSET}); narrow the window or the filters"
        ))
        .code(ApiErrorCode::PageTooDeep));
    }
    Ok(())
}

/// List filter on a row's origin: shipped with the product (`builtin`) or
/// written by the tenant (`custom`).
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceFilter {
    Builtin,
    Custom,
}

impl SourceFilter {
    pub fn admits(self, is_builtin: bool) -> bool {
        match self {
            Self::Builtin => is_builtin,
            Self::Custom => !is_builtin,
        }
    }
}

/// Default page size when the client omits `limit`.
#[allow(dead_code)]
pub const DEFAULT_LIMIT: i64 = 50;
/// Hard cap on page size — prevents clients from requesting unbounded pages.
#[allow(dead_code)]
pub const MAX_LIMIT: i64 = 500;

// ---------------------------------------------------------------------------
// Analytics filter primitives
//
// One canonical pair — `TimeWindow` (rolling `days` OR absolute `start`/`end`)
// and `AnalyticsScope` (cross-cutting dimensions) — driving every
// analytics-shaped endpoint. Wire fields are duplicated explicitly on each
// endpoint's `IntoParams` query struct because utoipa does not flatten in
// `IntoParams` derivation; handlers construct typed primitives via
// `query.time_window()` / `query.scope()` helpers and hand them to the audit
// store, whose `AnalyticsFilterBuilder` composes the SQL.
// ---------------------------------------------------------------------------

/// Rolling-or-absolute time window. Either `days` (rolling lookback ending
/// "now") OR `start`/`end` (RFC3339). Mixing the two is rejected at resolve
/// time; that's the explicit policy choice — no precedence ambiguity.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Deserialize)]
pub struct TimeWindow {
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[allow(dead_code)]
impl TimeWindow {
    /// Resolves into `(start, end)`. Falls back to `default_days` rolling when
    /// nothing is provided.
    ///
    /// Errors with `TimeWindowConflict` (400) if `days` and `start`/`end` are
    /// both set; with `TimeWindowInvalid` (400) if `days` ≤ 0 or `start ≥ end`.
    pub fn resolve(&self, default_days: i32) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
        let has_days = self.days.is_some();
        let has_abs = self.start.is_some() || self.end.is_some();
        if has_days && has_abs {
            return Err(ApiError::bad_request(
                "cannot mix `days` with `start`/`end`; use one or the other",
            )
            .code(ApiErrorCode::TimeWindowConflict));
        }
        let now = Utc::now();
        let (start, end) = if has_abs {
            let s = self
                .start
                .unwrap_or(now - chrono::Duration::days(default_days as i64));
            let e = self.end.unwrap_or(now);
            (s, e)
        } else {
            let d = self.days.unwrap_or(default_days);
            if d <= 0 {
                return Err(ApiError::bad_request("`days` must be a positive integer")
                    .code(ApiErrorCode::TimeWindowInvalid));
            }
            (now - chrono::Duration::days(d as i64), now)
        };
        check_bounds(Some(start), Some(end))?;
        Ok((start, end))
    }
}

/// An open-ended window (a list over everything when neither bound is set)
/// still refuses bounds that select nothing: `start` must be strictly before
/// `end` when both are given.
pub fn check_bounds(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> Result<(), ApiError> {
    match (start, end) {
        (Some(s), Some(e)) if s >= e => Err(ApiError::bad_request(
            "time window: `start` must be strictly before `end`",
        )
        .code(ApiErrorCode::TimeWindowInvalid)),
        _ => Ok(()),
    }
}

/// Refuses a traffic-log `search` term shorter than
/// [`crate::sql_pattern::MIN_SEARCH_CHARS`] characters once trimmed (400
/// `SearchTermTooShort`). An absent or blank term is no search and passes.
pub fn check_search(search: Option<&str>) -> Result<(), ApiError> {
    if crate::sql_pattern::search_too_short(search) {
        return Err(ApiError::bad_request(format!(
            "a search term needs at least {} characters",
            crate::sql_pattern::MIN_SEARCH_CHARS
        ))
        .code(ApiErrorCode::SearchTermTooShort));
    }
    Ok(())
}

/// Cross-cutting analytics dimensions. Each endpoint declares the subset of
/// fields its target table actually has on its `IntoParams` query struct, then
/// builds an `AnalyticsScope` via `query.scope()` to feed the SQL builder.
#[allow(dead_code)]
#[derive(Debug, Default, Clone, Deserialize)]
pub struct AnalyticsScope {
    pub user_id: Option<Uuid>,
    pub key_id: Option<Uuid>,
    pub app_id: Option<String>,
    pub model: Option<String>,
    pub downstream_id: Option<Uuid>,
    /// Workspace scope — narrows every analytics aggregate to traffic attributed
    /// to one of the given workspaces (`gateway_audit.workspace_id`, also
    /// denormalised onto `llm_audit` / `mcp_audit` / `web_audit`; bridged through
    /// the issuing key for `sessions` / `conversation_turns`). `None` = no
    /// workspace filter (every workspace, including the Agent workspace). The UI
    /// supplies the explicit set it wants to see — the default view ships all
    /// workspaces except the Agent one, so agent traffic is just another
    /// (deselected-by-default) workspace, not a special case.
    pub workspace_ids: Option<Vec<Uuid>>,
}

/// The `workspace_ids` query param as the typed scope set; an empty list is
/// `None` (no filter). Shared by every analytics/audit query struct's `scope()`
/// builder so the wire shape is identical across endpoints.
pub fn parse_workspace_ids(raw: &Option<WorkspaceIds>) -> Option<Vec<Uuid>> {
    let ids = &raw.as_ref()?.0;
    (!ids.is_empty()).then(|| ids.clone())
}

/// The `workspace_ids` query parameter: comma-separated workspace UUIDs. A
/// token that is not a UUID refuses the request — dropping it would widen the
/// filter, to every workspace when no token is left. Empty tokens (`a,,b`, a
/// trailing comma, an empty value) are no filter of their own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspaceIds(pub Vec<Uuid>);

impl std::str::FromStr for WorkspaceIds {
    type Err = String;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        raw.split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(|t| Uuid::parse_str(t).map_err(|_| format!("`workspace_ids`: `{t}` is not a workspace id")))
            .collect::<Result<Vec<_>, _>>()
            .map(WorkspaceIds)
    }
}

impl<'de> Deserialize<'de> for WorkspaceIds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod workspace_ids_tests {
    use super::*;

    const A: &str = "6f1c0a3e-0000-4000-8000-000000000001";
    const B: &str = "6f1c0a3e-0000-4000-8000-000000000002";

    #[test]
    fn a_list_of_ids_parses_and_empty_tokens_add_nothing() {
        let ids: WorkspaceIds = format!(" {A},,{B}, ").parse().unwrap();
        assert_eq!(ids.0, vec![Uuid::parse_str(A).unwrap(), Uuid::parse_str(B).unwrap()]);
        assert_eq!(parse_workspace_ids(&Some("".parse().unwrap())), None, "an empty value is no filter");
    }

    #[test]
    fn one_token_that_is_not_an_id_refuses_the_whole_value() {
        assert!(format!("{A},not-a-uuid").parse::<WorkspaceIds>().is_err());
        assert!("not-a-uuid".parse::<WorkspaceIds>().is_err(), "never widened to every workspace");
    }

    #[test]
    fn a_query_with_a_bad_id_is_refused_at_extraction() {
        let parse = |q: &str| {
            let uri: axum::http::Uri = format!("/x?{q}").parse().unwrap();
            axum::extract::Query::<WindowWorkspacesQuery>::try_from_uri(&uri)
        };
        assert!(parse(&format!("workspace_ids={A}")).is_ok());
        assert!(parse("workspace_ids=nope").is_err());
    }
}

/// A time window and nothing else — for an aggregate no other dimension
/// narrows.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WindowQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339). Defaults to now when only `start` is set.
    pub end: Option<DateTime<Utc>>,
}

impl WindowQuery {
    pub fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
}

/// A time window narrowed to some workspaces — the shape of an aggregate over
/// traffic, which every such endpoint owes (`workspace_ids`).
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WindowWorkspacesQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339). Defaults to now when only `start` is set.
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl WindowWorkspacesQuery {
    pub fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    pub fn workspace_ids(&self) -> Option<Vec<Uuid>> {
        parse_workspace_ids(&self.workspace_ids)
    }
}

/// The single catalog-resolution join: how an `upstream_models` row inherits from
/// `model_catalog`. Every site that resolves a model against the catalog uses this
/// — there is no second matcher.
///
/// **Capabilities and pricing resolve on DIFFERENT ladders**, so this emits TWO
/// laterals: `c` for capabilities, `catp` for pricing. They are properties of
/// different things. A model's context window, modalities and tool support belong
/// to the *weights*, so a self-hosted gemma-4 legitimately inherits what a hosted
/// one publishes and `c` falls back across providers. A model's **price belongs to
/// whoever serves it** — a self-hosted deployment's cost is compute, not another
/// vendor's per-token rate — so `catp` matches ONLY a row whose provider matches the
/// server's, and yields NULL (unknown, badged) rather than borrowing. Without that
/// split, a vLLM or Cerebras server whose model name matched three other vendors' rows
/// would take whichever sorted first and present it as real cost.
///
/// An explicit `catalog_model_id` link wins on both ladders regardless of provider
/// AND regardless of scope: an operator who links a row is stating intent, and a
/// link that silently resolved to nothing — capabilities falling to defaults,
/// price to unknown, with no marker anywhere — is worse than honouring it.
///
/// **A row scoped to this server outranks the global row on both ladders.** A
/// catalog row is global (`server_id IS NULL`) or scoped to one server, and the
/// scoped one is the narrower statement about the same model: a self-hosted
/// deployment's real compute cost, or an AWS Bedrock region's price, which the
/// global row cannot express because `canonical_catalog_key` deliberately folds
/// every region of a model onto one key. A row scoped to a DIFFERENT server is
/// not a candidate at all — that is what keeps the two from borrowing from each
/// other. On the pricing ladder such a row also qualifies WITHOUT the provider
/// match: naming the server states who serves the model outright, and a server
/// carries exactly one provider, so the row can mean nothing else. Only the
/// global row must still prove provider agreement before it may price anything.
///
/// **The pricing ladder considers only rows that carry a price.** A row with an
/// empty rate map answers "what does this cost" no better than no row at all —
/// both yield the same empty map — so it is excluded rather than ranked last.
/// Without that, a server-scoped capabilities-only row would outrank a priced
/// global one and silently unprice the model, which stops its budget accruing.
///
/// `model` and `server` are the outer aliases for `upstream_models` and
/// `upstream_servers`. Both are `&'static str` because they are spliced into SQL —
/// a caller cannot pass request-derived text.
/// Marker a SQL literal carries on its own line where [`catalog_join`] belongs.
///
/// Deliberately a marker-and-replace rather than a `format!` placeholder: these
/// queries contain their own braces (jsonb and array literals), which `format!`
/// would try to interpret, so templating them means escaping every one — a silent
/// hazard on a query nobody re-reads. Shaped as a SQL comment so the literal stays
/// readable as SQL.
pub const CATALOG_JOIN_MARKER: &str = "--{catalog_join}";

/// Splice [`catalog_join`] into a SQL literal at its [`CATALOG_JOIN_MARKER`].
/// Both aliases are `&'static str`, so no request-derived text can reach the SQL.
pub fn with_catalog_join(sql: &'static str, model: &'static str, server: &'static str) -> String {
    sql.replace(CATALOG_JOIN_MARKER, &catalog_join(model, server))
}

/// The provider grants the gateway honours, as `(workspace_id,
/// downstream_provider_id)` rows: every `workspace_downstream_access` grant,
/// except a pass-through's while its server is off. Off, the provider does not
/// exist for the gateway, so neither its pass-through nor its override routes
/// nor its forwarded paths reach any key kind. The edge snapshot builds from it
/// and the agent's granted-model warning reads it; a check that reads the raw
/// table instead reports a grant the proxy refuses.
pub const LIVE_PROVIDER_GRANTS: &str = concat!(
    "SELECT a.workspace_id, a.downstream_provider_id \
       FROM workspace_downstream_access a \
       JOIN downstream_providers dp ON dp.id = a.downstream_provider_id \
       LEFT JOIN upstream_servers s ON s.id = dp.upstream_server_id \
      WHERE ",
    live_passthrough_sql!("dp.byok", "s.enabled"),
);

/// Marker a SQL literal carries on its own line where [`LIVE_PROVIDER_GRANTS`]
/// belongs as a subquery; shaped like [`CATALOG_JOIN_MARKER`] for the same
/// reason.
pub const LIVE_PROVIDER_GRANTS_MARKER: &str = "--{live_provider_grants}";

/// Splice [`LIVE_PROVIDER_GRANTS`] into a SQL literal at its marker. A read
/// that offers a provider to a member, or checks a grant before binding or
/// rendering, reads `(--{live_provider_grants}) wda` in place of the table —
/// same two columns — so a pass-through whose server is off is neither offered
/// nor accepted, exactly as the gateway treats it. Only constants are spliced.
pub fn with_live_provider_grants(sql: &'static str) -> String {
    sql.replace(LIVE_PROVIDER_GRANTS_MARKER, LIVE_PROVIDER_GRANTS)
}

/// Whether a `vk-` key in workspace `workspace_id` may bind to downstream
/// `provider_id`: a BYOK downstream holding a live grant on that workspace.
/// Every key-minting path (console, portal, workspace manager, quickstart)
/// asks this one question; each answers a refusal with its own error.
pub async fn byok_downstream_bindable(
    conn: &mut Scoped,
    provider_id: Uuid,
    workspace_id: Uuid,
) -> Result<bool, sqlx::Error> {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        with_live_provider_grants(
            "SELECT EXISTS(SELECT 1 FROM downstream_providers dp \
             JOIN (\n--{live_provider_grants}\n) wda ON wda.downstream_provider_id = dp.id \
             WHERE dp.id = $1 AND dp.byok AND wda.workspace_id = $2)",
        )
    });
    sqlx::query_scalar(sqlx::AssertSqlSafe(SQL.as_str()))
        .bind(provider_id)
        .bind(workspace_id)
        .fetch_one(&mut *conn)
        .await
}

/// The refusal of a `vk-` key's pass-through binding — not a BYOK downstream
/// live-granted to the key's workspace, or deleted while the key was minted.
/// One answer for the console, portal and workspace-manager mints, whichever
/// of the two checks refuses.
pub fn byok_binding_refused() -> ApiError {
    ApiError::bad_request("BYOK downstream not found or not granted to the workspace")
        .code(ApiErrorCode::ValidationFailed)
}

/// The foreign key binding a key to its pass-through (`api_keys`, 001).
const API_KEYS_PASSTHROUGH_FK: &str = "api_keys_tenant_id_downstream_provider_id_fkey";

/// Whether a key INSERT was refused because the pass-through it binds was
/// deleted after [`byok_downstream_bindable`] said yes: the delete holds the
/// provider row, so the INSERT's foreign-key check waits on it and then fails
/// (`23503`). Every key-minting path answers it with its own binding refusal —
/// a client error, never a 500.
pub fn bound_passthrough_gone(e: &sqlx::Error) -> bool {
    is_foreign_key_violation(e)
        && e.as_database_error().and_then(|d| d.constraint()) == Some(API_KEYS_PASSTHROUGH_FK)
}

/// Marker a SQL literal carries on its own line where [`AGENT_GRANTED`] belongs.
const AGENT_GRANTED_MARKER: &str = "--{agent_granted}";

/// `EXISTS(…)`: the Agent workspace holds a live grant on route `r`'s provider,
/// so the gateway lets the analysis agent's key use the route.
const AGENT_GRANTED: &str = "EXISTS(
    SELECT 1 FROM (
--{live_provider_grants}
    ) g
    JOIN workspaces w ON w.id = g.workspace_id
    WHERE w.role = 'agent' AND g.downstream_provider_id = r.provider_id
)";

/// Marker a SQL literal carries on its own line where [`JUDGE_CAPABLE`] belongs.
pub(crate) const JUDGE_CAPABLE_MARKER: &str = "--{judge_capable}";

/// Model `m` can answer the judge — or serve as a client's chat model slot:
/// its type is not one that produces no text reply (`model_type` is free
/// text, so the known non-chat kinds are excluded rather than one spelling of
/// "chat" required).
pub(crate) const JUDGE_CAPABLE: &str =
    "COALESCE(m.model_type, 'text') NOT IN ('image', 'audio', 'video', 'embedding', 'rerank')";

/// Splice the agent-route fragments into a query over route `r` and its model
/// `m`: [`AGENT_GRANTED`] and [`JUDGE_CAPABLE`]. Only constants are spliced,
/// and the base query is `&'static str`, so no request-derived text can reach
/// the SQL.
pub fn with_agent_route_parts(sql: &'static str) -> String {
    sql.replace(
        AGENT_GRANTED_MARKER,
        &with_live_provider_grants(AGENT_GRANTED),
    )
    .replace(JUDGE_CAPABLE_MARKER, JUDGE_CAPABLE)
}

pub fn catalog_join(model: &'static str, server: &'static str) -> String {
    // Provider agreement between the catalog row and the server. COALESCE to false
    // because a LEFT-JOINed server (an orphan route) makes this NULL, and a NULL
    // sorts FIRST under DESC — which would rank "provider unknown" above "provider
    // matches" and quietly invert the ladder.
    let provider_match_of =
        |a: &str| format!("COALESCE({a}.provider_key = canonical_provider_key({server}.provider), false)");
    let provider_match = provider_match_of("mc");
    // A catalog row is either global (`server_id IS NULL`) or scoped to one
    // server. Both are candidates for a model on that server; a row scoped to a
    // DIFFERENT server is not, which is what makes per-region and per-deployment
    // prices safe to store side by side.
    let scope_visible_of = |a: &str| format!("({a}.server_id IS NULL OR {a}.server_id = {server}.id)");
    let scope_visible = scope_visible_of("mc");
    // COALESCE for the same reason `provider_match` does: on a global row this
    // comparison is NULL, and NULL sorts FIRST under DESC — which would rank the
    // global row above the server's own and invert the tier.
    let scope_match_of = |a: &str| format!("COALESCE({a}.server_id = {server}.id, false)");
    let scope_match = scope_match_of("mc");
    // The capability candidates. The scope filter guards the AUTO-MATCH arm only.
    // An operator who links a row has stated intent, and a link that silently
    // resolved to nothing — capabilities falling to defaults, price to unknown,
    // with no marker anywhere — is the one outcome worse than either honouring
    // it or rejecting it outright.
    let candidates_of = |a: &str| {
        format!(
            "{a}.tenant_id = {model}.tenant_id AND NOT {a}.suppressed \
             AND ( {a}.id = {model}.catalog_model_id \
                   OR ({model}.catalog_model_id IS NULL \
                       AND {} \
                       AND {a}.model_key = canonical_catalog_key({model}.upstream_model)) )",
            scope_visible_of(a)
        )
    };
    // The capability ladder, best first.
    let tiers_of = |a: &str| {
        let pm = provider_match_of(a);
        format!(
            "({a}.id = {model}.catalog_model_id) DESC, {} DESC, ({pm} AND {a}.model = {model}.upstream_model) DESC, \
             {pm} DESC, ({a}.model = {model}.upstream_model) DESC",
            scope_match_of(a)
        )
    };
    let (candidates, tiers) = (candidates_of("mc"), tiers_of("mc"));
    // The reasoning flag alone is read over the rows tied at the top of the
    // same ladder, a stated one before a silent one: the feed states the flag
    // only when true, so one reseller's silence beside another's "true" for
    // the same weights is a gap in that feed, not a "no". A stated "false"
    // comes only from an operator and wins over both. Silence decides only
    // when every tied row is silent (`edge_reasoning_flag`). The other
    // capabilities stay those of the row the ladder's tie-break picks.
    let reasoning = format!(
        "(SELECT r.supports_reasoning FROM model_catalog r WHERE {} \
          ORDER BY {}, CASE r.supports_reasoning WHEN false THEN 0 WHEN true THEN 1 ELSE 2 END \
          LIMIT 1)",
        candidates_of("r"),
        tiers_of("r")
    );
    format!(
        r#"
    LEFT JOIN LATERAL (
        SELECT mc.id as catalog_match_id, mc.context_window, mc.max_output_tokens,
               mc.supports_vision, {reasoning} AS supports_reasoning, mc.supports_function_calling,
               mc.supports_caching, mc.supports_audio_input, mc.supports_audio_output,
               mc.supports_video_input, mc.supports_pdf_input, mc.supports_response_schema,
               mc.supports_system_messages, mc.model_type, mc.output_vector_size,
               mc.deprecation_date
        FROM model_catalog mc
        WHERE {candidates}
        ORDER BY {tiers}, mc.model, mc.provider_key
        LIMIT 1
    ) c ON true
    LEFT JOIN LATERAL (
        SELECT mc.rates
        FROM model_catalog mc
        WHERE mc.tenant_id = {model}.tenant_id AND NOT mc.suppressed
              -- Scope guards the auto-match arm only; an explicit link is intent.
              AND ( mc.id = {model}.catalog_model_id
                    OR ({model}.catalog_model_id IS NULL
                        AND {scope_visible}
                        -- A row scoped to THIS server names who serves the model
                        -- outright, which is the very thing the provider match
                        -- approximates — so it qualifies on its own. A server has
                        -- exactly one provider, so such a row can only ever mean
                        -- "what this model costs here". Only the global row has to
                        -- prove provider agreement before it may price anything.
                        AND ({scope_match} OR {provider_match})
                        -- A row carrying NO prices is never an answer to "what does
                        -- this cost" — it is only ever a worse one than a row that
                        -- has them, and matching it yields the same empty map as
                        -- matching nothing. Excluding it here rather than ranking it
                        -- last is what stops a catalog entry added for its context
                        -- window from shadowing the entry that knows what the model
                        -- costs, at ANY tier: a server-scoped capabilities-only row
                        -- would otherwise outrank a priced global one and silently
                        -- unprice the model, which stops its budget accruing.
                        AND mc.rates -> 'units' <> '{{}}'::jsonb
                        AND mc.model_key = canonical_catalog_key({model}.upstream_model)) )
        ORDER BY (mc.id = {model}.catalog_model_id) DESC,
                 {scope_match} DESC,
                 (mc.model = {model}.upstream_model) DESC,
                 mc.model
        LIMIT 1
    ) catp ON true
"#
    )
}

// ---------------------------------------------------------------------------
// Shared auth helpers
// ---------------------------------------------------------------------------

/// The domain of a plain address — exactly one `@`, a non-empty local part and
/// domain, and no whitespace or control characters — or `None` for anything else.
///
/// An address is the login identifier and the domain is what `allowed_domains`
/// judges, so both must come from one unambiguous reading: with two `@`s,
/// `mallory@evil.test@corp.test` would read as a `corp.test` address to a
/// last-`@` split while naming a mailbox somewhere else entirely.
pub(crate) fn address_domain(address: &str) -> Option<&str> {
    let (local, domain) = address.split_once('@')?;
    let plain = |s: &str| !s.is_empty() && !s.chars().any(|c| c == '@' || c.is_whitespace() || c.is_control());
    (plain(local) && plain(domain)).then_some(domain)
}

/// An address as the product stores and compares it: surrounding whitespace
/// removed and ASCII letters lower-cased. Login addresses are identities
/// compared without regard to case (an AD FS UPN is often
/// `Ada.Lovelace@Contoso.com` for an account created lower-case), so every
/// place an address ENTERS — a login, an invite, an account created or renamed,
/// an identity provider's claim, a proxy header — passes it through here, and
/// everything behind those doors compares exactly.
///
/// ASCII only, deliberately: Unicode case folding maps look-alikes onto ASCII
/// (KELVIN SIGN U+212A to `k`), which would put a different mailbox on an
/// existing account.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Refuse anything but one plain address as a login identifier — applied, after
/// [`normalize_email`], at every place an address is stored: a blank or
/// malformed one must not become an account, and every door must accept the
/// same identifiers (an address one door stores and another refuses can never be
/// signed in to through the second).
pub(crate) fn require_address(email: &str) -> Result<(), ApiError> {
    if address_domain(email).is_none() {
        return Err(ApiError::bad_request("a valid email address is required")
            .code(ApiErrorCode::ValidationFailed));
    }
    Ok(())
}

/// Check email against tenant's `allowed_domains` whitelist.
/// Returns `Ok(())` if no restriction is configured or the domain matches.
pub(crate) fn check_allowed_domains(email: &str, allowed_domains: &Option<Vec<String>>) -> Result<(), ApiError> {
    let domains = match allowed_domains {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(()),
    };
    let Some(email_domain) = address_domain(email).map(str::to_lowercase) else {
        return Err(ApiError::forbidden("invalid email address").code(ApiErrorCode::ValidationFailed));
    };
    if domains.iter().any(|d| d.to_lowercase() == email_domain) {
        Ok(())
    } else {
        tracing::warn!(email = %email, "access denied — email domain not in allowed_domains");
        Err(ApiError::forbidden("email domain not allowed for this tenant")
            .code(ApiErrorCode::DomainNotAllowed))
    }
}

/// Admin management API routes.
pub fn admin_router() -> Router<Arc<AdminState>> {
    Router::new()
        // Users
        .route("/users", post(users::create_user))
        .route("/users", get(users::list_users))
        .route("/users/{id}", get(users::get_user).patch(users::update_user).delete(users::delete_user))
        .route("/users/{id}/usage", get(users::get_user_usage))
        // API Keys — revoke is an action on the retained row, not a destroy
        .route("/keys", post(keys::create_key))
        .route("/keys", get(keys::list_keys))
        .route("/keys/{id}", get(keys::get_key).patch(keys::update_key))
        .route("/keys/{id}/actions/revoke", post(keys::revoke_key))
        .route("/keys/{id}/usage", get(keys::get_key_usage))
        // Service accounts — non-human automation principals + their keys (ak-/sk-)
        .route("/service-accounts", post(service_accounts::create_service_account_handler))
        .route("/service-accounts", get(service_accounts::list_service_accounts))
        .route("/service-accounts/{id}", get(service_accounts::get_service_account))
        .route("/service-accounts/{id}/actions/disable", post(service_accounts::disable_service_account))
        .route("/service-accounts/{id}/actions/enable", post(service_accounts::enable_service_account))
        .route("/service-accounts/{id}/actions/revoke", post(service_accounts::revoke_service_account))
        .route("/service-accounts/{id}/actions/rotate-agent-key", post(service_accounts::rotate_agent_key))
        .route("/service-accounts/{id}/actions/rotate-inline-ai-key", post(service_accounts::rotate_inline_ai_key))
        .route("/service-accounts/{id}/keys", post(service_accounts::mint_service_account_key))
        .route("/service-accounts/{id}/keys", get(service_accounts::list_service_account_keys))
        .route("/service-accounts/{id}/keys/{key_id}/actions/revoke", post(service_accounts::revoke_service_account_key))
        .route("/service-accounts/{id}/keys/{key_id}/actions/rotate", post(service_accounts::rotate_service_account_key))
        // Servers
        .route("/servers", post(upstreams::create_server))
        .route("/servers", get(upstreams::list_servers))
        .route("/servers/provider-defaults", get(upstreams::list_provider_defaults))
        .route("/servers/{id}", get(upstreams::get_server).patch(upstreams::patch_server).delete(upstreams::delete_server))
        .route("/servers/{id}/actions/sync", post(upstreams::sync_server_models))
        .route("/servers/{id}/actions/sync-now", post(upstreams::sync_now))
        .route("/servers/{id}/models", post(upstreams::create_server_models).delete(upstreams::batch_delete_models))
        .route("/servers/{id}/endpoints", get(upstream_endpoints::list_endpoints).post(upstream_endpoints::create_endpoint))
        .route("/servers/{id}/endpoints/actions/reorder", post(upstream_endpoints::reorder_endpoints))
        .route("/servers/{id}/endpoints/actions/discover", post(upstream_endpoints::discover_endpoint))
        .route("/servers/{id}/actions/probe-engine", post(upstream_endpoints::probe_engine))
        .route("/servers/{id}/endpoints/{endpoint_id}", patch(upstream_endpoints::patch_endpoint).delete(upstream_endpoints::delete_endpoint))
        .route("/servers/{id}/membership", get(upstream_endpoints::get_membership))
        // Models
        .route("/models", get(upstreams::list_models))
        .route("/models/actions/bulk-update", post(upstreams::bulk_update_models))
        .route("/models/{id}", patch(upstreams::update_model).delete(upstreams::delete_model))
        .route("/upstream-models/{model_id}/presets", get(model_presets::list_presets).post(model_presets::create_preset))
        .route("/upstream-models/{model_id}/presets/{preset_id}", patch(model_presets::update_preset).delete(model_presets::delete_preset))
        .route("/upstream-models/{model_id}/presets/{preset_id}/actions/set-default", post(model_presets::set_default_preset))
        // Catalog — tenant-scoped collection actions
        .route("/catalog", post(catalog::create_catalog_entry))
        .route("/catalog", get(catalog::list_catalog))
        .route("/catalog/actions/remove-seeded", post(catalog::remove_all_seeded))
        .route("/catalog/actions/reset", post(catalog::reset_catalog))
        .route("/catalog/{id}", get(catalog::get_catalog_entry).patch(catalog::update_catalog_entry).delete(catalog::delete_catalog_entry))
        // Admin-action audit (operator mutations log — who modified what)
        .route("/admin-audit", get(admin_audit::list_admin_audit))
        // Portal-action audit (end-user mutations — key/MCP/quickstart)
        .route("/portal-audit", get(admin_audit::list_portal_audit))
        // Pre-auth security events (login / setup / invite / oauth attempts)
        .route("/security-audit", get(admin_audit::list_security_audit))
        // Audit
        .route("/audit", get(audit::list_audit_logs))
        .route("/audit/media/{hash}", get(audit::get_media_blob))
        .route("/audit/tool-definitions/{hash}", get(audit::get_tool_definition_blob))
        .route(
            "/audit/{request_id}/web",
            get(audit::list_web_calls_for_request),
        )
        // Traces + Sessions
        .route("/traces/{request_id}", get(audit::get_trace))
        .route("/sessions/{session_id}", get(audit::get_session))
        .route(
            "/sessions/{session_id}/conversation",
            get(audit::get_session_conversation),
        )
        .route("/sessions", get(audit::list_sessions))
        .route(
            "/sessions/{session_id}/linked",
            get(audit::get_session_linked),
        )
        // Settings — verbs moved to /admin/maintenance/* since they modify audit data, not settings
        .route(
            "/settings",
            get(settings::get_settings).patch(settings::update_settings),
        )
        .route("/settings/db-stats", get(settings::get_db_stats))
        // Web — settings + operator test runner for the built-in Web
        // virtual MCP (search + fetch). Settings live in
        // `system_settings.web`; the credential rotates on the synthetic
        // `builtin-web` row in `mcp_upstream_servers`.
        .route(
            "/settings/pricing",
            get(pricing::get_pricing_settings)
                .patch(pricing::update_pricing_settings),
        )
        .route(
            "/settings/web",
            get(web::get_web_settings)
                .patch(web::update_web_settings),
        )
        .route(
            "/web/actions/test",
            post(web::test_web),
        )
        // Guardrail — settings for the inline injection guardrail on untrusted
        // web search/fetch. Settings live in `system_settings.guardrail`.
        .route(
            "/settings/guardrail",
            get(guardrail::get_guardrail_settings)
                .patch(guardrail::update_guardrail_settings),
        )
        // Response cache — tenant-wide switch + entry-size ceiling. Per-alias
        // policy rides the named cache preset a route references.
        .route(
            "/settings/cache",
            get(cache_settings::get_cache_settings)
                .patch(cache_settings::update_cache_settings),
        )
        // Check an embedding alias the way the cache would use it: same targets,
        // same request shape, same timeout — so a green result means semantic
        // matching will actually work.
        .route(
            "/settings/cache/actions/probe-embedding",
            post(cache_settings::probe_embedding_alias),
        )
        .route(
            "/settings/cache/embedding-aliases",
            get(cache_settings::list_embedding_aliases),
        )
        // Maintenance — housekeeping verbs
        .route("/maintenance/purge-audit", post(settings::trigger_purge))
        .route("/maintenance/wipe-sessions", post(settings::wipe_audit_sessions))
        .route("/maintenance/flush-response-cache", post(downstream::flush_tenant_cache))
        // Analytics — the consolidated surface.
        // overview/timeseries/breakdown/proxy/users-keys/tools/tools-activity/transforms
        // are the primary endpoints. The specialized errors/media/apps surfaces are
        // kept alongside since their response shapes carry dimensions that don't fit
        // a generic breakdown (error_category, media direction).
        .route("/analytics/overview", get(analytics::usage_summary))
        .route("/analytics/breakdown", get(analytics::usage_breakdown))
        .route("/analytics/tools", get(analytics::tool_inventory))
        .route("/tool-calls", get(analytics::tool_calls))
        .route("/analytics/transforms", get(analytics::transform_stats))
        .route("/analytics/apps", get(analytics::list_apps))
        .route("/analytics/timeseries", get(analytics::usage_timeseries))
        .route("/analytics/users-keys", get(analytics::users_keys_dashboard))
        .route("/analytics/proxy", get(analytics::proxy_dashboard))
        .route("/analytics/errors", get(analytics::error_analytics))
        .route("/analytics/media", get(analytics::media_analytics))
        .route("/analytics/cache", get(analytics::cache_analytics))
        // MCP Dashboard panels — all under /mcp/dashboard. The 9 top-N
        // panels delegate to the shared `mcp_dashboard_panel` SQL builder
        // pivoting on different `MCP_AUDIT_JOIN` columns. Plus 3 substantial
        // endpoints: summary (6 metric cards), timeseries (call volume by
        // method + dual-latency split), errors-by-method.
        .route("/mcp/dashboard/by-resource", get(analytics::mcp_dashboard_by_resource))
        .route("/mcp/dashboard/by-prompt", get(analytics::mcp_dashboard_by_prompt))
        .route("/mcp/dashboard/by-tool", get(analytics::mcp_dashboard_by_tool))
        .route("/mcp/dashboard/by-endpoint", get(analytics::mcp_dashboard_by_endpoint))
        .route("/mcp/dashboard/by-upstream", get(analytics::mcp_dashboard_by_upstream))
        .route("/mcp/dashboard/by-method", get(analytics::mcp_dashboard_by_method))
        .route("/mcp/dashboard/by-user", get(analytics::mcp_dashboard_by_user))
        .route("/mcp/dashboard/by-app", get(analytics::mcp_dashboard_by_app))
        .route("/mcp/dashboard/summary", get(analytics::mcp_dashboard_summary))
        // A2A Dashboard panels — the agent-to-agent analog of the MCP set: what
        // agents were called, with which operations, and how their tasks ended.
        .route("/a2a/dashboard/summary", get(analytics::a2a_dashboard_summary))
        .route("/a2a/dashboard/by-agent", get(analytics::a2a_dashboard_by_agent))
        .route("/a2a/dashboard/by-method", get(analytics::a2a_dashboard_by_method))
        .route("/a2a/dashboard/by-task-state", get(analytics::a2a_dashboard_by_task_state))
        .route("/a2a/dashboard/by-user", get(analytics::a2a_dashboard_by_user))
        .route("/a2a/dashboard/by-app", get(analytics::a2a_dashboard_by_app))
        .route("/mcp/dashboard/timeseries", get(analytics::mcp_dashboard_timeseries))
        .route("/mcp/dashboard/errors-by-method", get(analytics::mcp_dashboard_errors_by_method))
        // Web Dashboard panels — pivot on web_audit (search/fetch) joined to gateway_audit.
        .route("/web/dashboard/summary", get(analytics::web_dashboard_summary))
        .route("/web/dashboard/by-host", get(analytics::web_dashboard_by_host))
        .route("/web/dashboard/by-query", get(analytics::web_dashboard_by_query))
        .route("/web/dashboard/by-user", get(analytics::web_dashboard_by_user))
        // Cross-protocol analytics (Dashboard Overview consumers).
        .route("/analytics/cross/overview", get(analytics::cross_overview))
        .route("/analytics/cross/timeseries", get(analytics::cross_timeseries))
        .route("/analytics/cross/upstream-timeseries", get(analytics::cross_upstream_timeseries))
        .route("/analytics/cross/attention", get(analytics::cross_attention))
        .route("/analytics/servers", get(server_analytics::server_fleet))
        .route("/analytics/servers/{id}", get(server_analytics::server_dashboard))
        .route("/analytics/servers/{id}/recent-load", get(server_analytics::server_recent_load))
        .route("/notifications", get(notifications_feed::list_notifications))
        // Admin accounts
        .route(
            "/admin-accounts",
            post(admin_auth::create_admin_account).get(admin_auth::list_admin_accounts),
        )
        .route(
            "/admin-accounts/{id}",
            get(admin_auth::get_admin_account).patch(admin_auth::update_admin_account).delete(admin_auth::delete_admin_account),
        )
        // Downstream Providers
        .route("/downstream-providers", post(downstream::create_provider).get(downstream::list_providers))
        .route("/downstream-providers/{id}", get(downstream::get_provider).put(downstream::update_provider).delete(downstream::delete_provider))
        .route("/downstream-providers/{id}/routes", get(downstream::list_routes).post(downstream::create_route))
        .route("/downstream-providers/{id}/routes/actions/batch-create", post(downstream::batch_create_routes))
        .route("/downstream-providers/{id}/routes/{route_id}", patch(downstream::update_route).delete(downstream::delete_route))
        .route("/downstream-providers/{id}/routes/{route_id}/actions/flush-cache", post(downstream::flush_route_cache))
        .route("/downstream-routes/collisions", get(downstream::list_route_collisions))
        // Route Policies
        .route("/route-policies", get(route_policies::list_route_policies).post(route_policies::create_route_policy))
        .route("/route-policies/{id}", patch(route_policies::update_route_policy).delete(route_policies::delete_route_policy))
        // MCP gateway — admin CRUD surface for upstream/virtual servers/routes.
        .route(
            "/mcp/upstream-servers",
            get(mcp::list_mcp_upstream_servers).post(mcp::create_mcp_upstream_server),
        )
        // A2A gateway: the upstream agent registry behind /a2a/<slug>.
        .route(
            "/a2a/agents",
            get(a2a::list_a2a_agents).post(a2a::create_a2a_agent),
        )
        .route(
            "/a2a/agents/{id}",
            get(a2a::get_a2a_agent)
                .patch(a2a::update_a2a_agent)
                .delete(a2a::delete_a2a_agent),
        )
        // Re-fetch + re-validate the upstream agent card in place.
        .route(
            "/a2a/agents/{id}/actions/refresh-card",
            post(a2a::refresh_a2a_agent_card),
        )
        // Discover a per-user-OAuth upstream's endpoints from its URL (RFC 9728
        // → RFC 8414/OIDC). Returns the endpoints for operator review; persists
        // nothing.
        .route(
            "/mcp/upstream-servers/actions/discover-oauth",
            post(mcp_discovery::discover_upstream_oauth),
        )
        // Register an OAuth client with a per-user-OAuth upstream via RFC 7591
        // dynamic client registration. Returns the issued client_id/secret for
        // the operator to save; persists nothing.
        .route(
            "/mcp/upstream-servers/actions/register-oauth-client",
            post(mcp_discovery::register_upstream_oauth_client),
        )
        .route(
            "/mcp/upstream-servers/{id}",
            get(mcp::get_mcp_upstream_server)
                .patch(mcp::update_mcp_upstream_server)
                .delete(mcp::delete_mcp_upstream_server),
        )
        .route(
            "/mcp/virtual-servers",
            get(mcp::list_mcp_virtual_servers).post(mcp::create_mcp_virtual_server),
        )
        .route(
            "/mcp/virtual-servers/{id}",
            get(mcp::get_mcp_virtual_server)
                .patch(mcp::update_mcp_virtual_server)
                .delete(mcp::delete_mcp_virtual_server),
        )
        .route(
            "/mcp/virtual-routes",
            get(mcp::list_mcp_virtual_routes).post(mcp::create_mcp_virtual_route),
        )
        .route(
            "/mcp/virtual-routes/{id}",
            get(mcp::get_mcp_virtual_route)
                .patch(mcp::update_mcp_virtual_route)
                .delete(mcp::delete_mcp_virtual_route),
        )
        // MCP spec-OAuth: OAuth client CRUD + issued token revoke.
        .route(
            "/mcp/oauth-clients",
            get(mcp_oauth::list_oauth_clients).post(mcp_oauth::create_oauth_client),
        )
        .route(
            "/mcp/oauth-clients/{id}",
            get(mcp_oauth::get_oauth_client)
                .patch(mcp_oauth::update_oauth_client)
                .delete(mcp_oauth::delete_oauth_client),
        )
        // CIMD clients hold tokens without ever registering, so they are
        // invisible to the client CRUD above and are inventoried from the
        // tokens themselves.
        .route("/mcp/cimd-clients", get(mcp_oauth::list_cimd_clients))
        .route(
            "/mcp/cimd-clients/actions/revoke",
            post(mcp_oauth::revoke_cimd_client),
        )
        .route("/mcp/issued-tokens", get(mcp_oauth::list_issued_tokens))
        .route(
            "/mcp/issued-tokens/{jti}/actions/revoke",
            post(mcp_oauth::revoke_issued_token),
        )
        // CLI device sessions — the `surface='cli'` half of oauth_issued_tokens,
        // which the MCP-shaped view above deliberately excludes.
        .route("/cli/sessions", get(cli_oauth::list_cli_sessions))
        .route(
            "/cli/sessions/{id}/actions/revoke",
            post(cli_oauth::revoke_cli_session),
        )
        // MCP per-user-OAuth admin view (which users connected each upstream).
        .route(
            "/mcp/upstreams/{id}/connections",
            get(mcp::list_mcp_upstream_connections),
        )
        .route(
            "/mcp/upstreams/{id}/connections/{user_id}",
            axum::routing::delete(mcp::delete_mcp_upstream_connection),
        )
        // MCP server catalog — browse curated remote MCP servers + one-click adopt.
        .route(
            "/mcp/catalog",
            get(mcp_catalog::list_mcp_catalog).post(mcp_catalog::create_mcp_catalog_entry),
        )
        // Read-only, sourced from `seeds/mcp_servers/oauth_provider_recipes.json`.
        // The upstream-server modal uses these to guide OAuth-app registration.
        .route(
            "/mcp/oauth-provider-recipes",
            get(mcp_catalog::list_oauth_provider_recipes),
        )
        .route("/mcp/catalog/actions/reset", post(mcp_catalog::reset_mcp_catalog))
        .route(
            "/mcp/catalog/{id}",
            get(mcp_catalog::get_mcp_catalog_entry)
                .patch(mcp_catalog::update_mcp_catalog_entry)
                .delete(mcp_catalog::delete_mcp_catalog_entry),
        )
        .route(
            "/mcp/catalog/{id}/actions/adopt",
            post(mcp_catalog::adopt_mcp_catalog_entry),
        )
        // Tool Risk Rules — first-class CRUD over the per-tenant rule list.
        .route(
            "/tool-rules",
            get(tool_rules::list_tool_rules).post(tool_rules::create_tool_rule),
        )
        .route(
            "/tool-rules/{id}",
            get(tool_rules::get_tool_rule)
                .patch(tool_rules::update_tool_rule)
                .delete(tool_rules::delete_tool_rule),
        )
        .route(
            "/tool-rules/actions/reset",
            post(tool_rules::reset_tool_rules),
        )
        .route(
            "/tool-rules/actions/test",
            post(tool_rules::test_tool_rule),
        )
        .route(
            "/security-frameworks",
            get(tool_rules::list_security_frameworks),
        )
        .route(
            "/tool-rule-detectors",
            get(tool_rules::list_tool_rule_detectors),
        )
        // Destination lists — the static `actions/reset` segment precedes `{id}`.
        .route(
            "/destination-lists/actions/reset",
            post(destination_lists::reset_all),
        )
        .route(
            "/destination-lists",
            get(destination_lists::list).post(destination_lists::create),
        )
        .route(
            "/destination-lists/{id}",
            get(destination_lists::get_one)
                .patch(destination_lists::update)
                .delete(destination_lists::delete),
        )
        .route(
            "/destination-lists/{id}/actions/reset",
            post(destination_lists::reset),
        )
        // Client profiles — admin override surface for portal quickstart templates.
        // The static `placeholders` segment MUST precede the `{id}` route or it
        // is matched as a profile id.
        .route(
            "/client-profiles/placeholders",
            get(client_profiles_admin::placeholders),
        )
        .route(
            "/client-profiles/actions/preview",
            post(client_profiles_admin::preview),
        )
        .route(
            "/client-profiles",
            get(client_profiles_admin::list)
                .post(client_profiles_admin::create),
        )
        .route(
            "/client-profiles/{id}",
            get(client_profiles_admin::get_one)
                .put(client_profiles_admin::update)
                .delete(client_profiles_admin::delete),
        )
        .route(
            "/client-profiles/{id}/actions/reset",
            post(client_profiles_admin::reset),
        )
        // Collection reset — the only way back to a builtin the operator
        // deleted, since a suppressed row is filtered out of every read.
        .route(
            "/client-profiles/actions/reset",
            post(client_profiles_admin::reset_all),
        )
        // Tool Field Profiles — typed per-(tool, field) normaliser registry.
        // Discovery route MUST be registered before the `{id}` route so
        // `/tool-field-profiles/discover` is not interpreted as id="discover".
        .route(
            "/tool-field-profiles/discover",
            get(tool_field_profiles::discover_tool_fields),
        )
        .route(
            "/tool-field-profiles/known-server-types",
            get(tool_field_profiles::list_known_server_tool_types),
        )
        .route(
            "/tool-field-profiles/actions/reset",
            post(tool_field_profiles::reset_tool_field_profiles),
        )
        .route(
            "/tool-field-profiles",
            get(tool_field_profiles::list_tool_field_profiles)
                .post(tool_field_profiles::create_tool_field_profile),
        )
        .route(
            "/tool-field-profiles/{id}",
            get(tool_field_profiles::get_tool_field_profile)
                .patch(tool_field_profiles::update_tool_field_profile)
                .delete(tool_field_profiles::delete_tool_field_profile),
        )
        // Canonical tool_id taxonomy — read-only, sourced from
        // `seeds/tool-policy/tool_ids.json`. UI uses this for autocomplete.
        .route("/tool-ids", get(tool_field_profiles::list_tool_ids))
        // Parallel resource_id and prompt_id taxonomies for the
        // `(_, resource_reads)` and `(request, prompt_invocations)` rule
        // editor autocomplete. Same shape as `/tool-ids`.
        .route("/resource-ids", get(tool_field_profiles::list_resource_ids))
        .route("/prompt-ids", get(tool_field_profiles::list_prompt_ids))
        // Transforms & Experts
        .nest("/transforms", transforms::transforms_router())
        .nest("/experts", transforms::experts_router())
        // Workspaces (scope: members, allowlists, rate ceilings, tool profile)
        .nest("/workspaces", workspaces::workspaces_router())
        // Profiles (generic per-kind policy bundles a workspace points at:
        // tool rules, guardrail policy, …) + per-profile guardrail sub-resource.
        .nest("/profiles", profiles::profiles_router())
        // QoS classes (the tenant's priority bands under load).
        .nest("/qos-classes", qos_classes::qos_classes_router())
        // Response-cache presets: named policies a route's `cache_preset_id`
        // points at (mode, TTL, threshold, sharing scope).
        .nest("/cache-presets", cache_presets::cache_presets_router())
        // Config sync status (tenant-scoped)
        .route("/config-sync/tenant-status", get(crate::edge_v2::status::tenant_sync_status))
        // Changelog
        .route("/changelog", get(changelog::get_changelog))
        .route("/changelog/actions/dismiss", post(changelog::dismiss_changelog))
}

/// Edge node management routes (super-admin only — guard applied at route layer).
/// Edge nodes are global infrastructure, not tenant-scoped.
pub fn edge_admin_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/edge-nodes", post(crate::edge_nodes::create_edge_node))
        .route("/edge-nodes", get(crate::edge_nodes::list_edge_nodes))
        .route(
            "/edge-nodes/{id}",
            patch(crate::edge_nodes::update_edge_node).delete(crate::edge_nodes::delete_edge_node),
        )
}

/// Super-admin global routes — cross-tenant queries mounted at
/// `/api/v1/admin/global/*` behind the super-admin middleware. One authz fence.
/// Do NOT re-mount these handlers anywhere under `/admin/tenants/*`.
pub fn super_admin_global_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/analytics/overview", get(analytics::global_usage_summary))
        .route("/edge-stats", get(analytics::global_edge_stats))
        .route("/edge-sync", get(crate::edge_v2::status::edge_sync_status))
        .route(
            "/runtime-config",
            get(runtime_config::get_runtime_config).patch(runtime_config::patch_runtime_config),
        )
        .route("/egress", get(egress::get_egress).patch(egress::patch_egress))
        // Cross-tenant audit feeds — merge every non-SYSTEM tenant's rows in
        // one chronological feed; carry `tenant_slug` per row so the UI can
        // render a tenant column. The security feed additionally surfaces
        // platform-level events with no resolvable tenant (failed login to an
        // unknown slug, portal-login attempts) that the tenant-scoped read
        // cannot show.
        .route("/admin-audit", get(admin_audit::list_global_admin_audit))
        .route("/portal-audit", get(admin_audit::list_global_portal_audit))
        .route("/security-audit", get(admin_audit::list_global_security_audit))
        // Web Appliance surface (Kairos VM only — gated by STOWAGE_HOST_SOCKET).
        .nest("/appliance", appliance::router())
}

/// Auth routes (login/logout/setup — NOT behind admin_auth middleware).
pub fn auth_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/login", post(admin_auth::login))
        .route("/logout", post(admin_auth::logout))
        .route("/setup", post(admin_auth::setup))
        .route("/setup/status", get(admin_auth::setup_status))
}

/// The claim exchange (`ALLOW_OIDC_CLAIM_EXCHANGE`), mounted under `/api/v1/auth`
/// by `build_app` only when a deployment turns it on — unmounted, every
/// request, whatever its method, content type or body, gets the router's own
/// 404, so a disabled surface cannot be told from an absent one. Mounted, its
/// outermost layer is the service-secret check, so an anonymous body is refused
/// before it is parsed or audited.
pub fn claim_exchange_router() -> Router<Arc<AdminState>> {
    Router::new().route("/oidc-exchange", post(admin_auth::oidc_exchange))
}

/// Portal API routes (user self-service — behind portal_auth middleware).
pub fn portal_router() -> Router<Arc<AdminState>> {
    Router::new()
        // Auth (me is behind middleware, login is handled separately)
        .route("/auth/me", get(portal::me))
        // Keys — revoke is an action on the retained row, not a destroy
        .route("/keys", get(portal::list_keys).post(portal::create_key))
        .route("/keys/{id}/actions/revoke", post(portal::revoke_key))
        // Home — the landing page's one read
        .route("/home", get(portal_home::home))
        // Stats
        .route("/stats", get(portal::my_stats))
        // --- Self-service activity (member tier — own data only) ---
        .route("/sessions", get(portal::my_sessions))
        .route("/sessions/{id}/conversation", get(portal::my_session_conversation))
        .route("/sessions/{id}/linked", get(portal::my_session_linked))
        .route("/audit", get(portal::my_audit))
        .route("/audit/filter-options", get(portal::my_audit_filter_options))
        .route("/audit/media/{hash}", get(portal::my_media))
        .route("/audit/tool-definitions/{hash}", get(portal::my_tool_definition_blob))
        .route("/audit/{request_id}", get(portal::my_trace))
        .route("/audit/{request_id}/web", get(portal::my_web_calls_for_request))
        // --- MCP self-service ---
        .route("/mcp/virtual-servers", get(portal_mcp::list_virtual_servers))
        // --- MCP per-user OAuth connections ---
        .route("/mcp/connections", get(portal_mcp_connections::list_connections))
        .route(
            "/mcp/connections/{upstream_id}/actions/connect",
            post(portal_mcp_connections::connect_init),
        )
        .route(
            "/mcp/connections/{upstream_id}/actions/revoke",
            post(portal_mcp_connections::revoke_connection),
        )
        // --- MCP catalog smoke test ---
        .route(
            "/mcp/virtual-servers/{virtual_server_id}/actions/test",
            post(portal_mcp_test::test_virtual_server),
        )
        // --- Quickstart (client config snippets) ---
        .route("/quickstart/clients", get(quickstart::list_clients))
        .route("/quickstart/clients/{id}", get(quickstart::get_client))
        .route("/quickstart/routes", get(quickstart::list_routes))
        .route("/quickstart/keys", get(quickstart::list_keys))
        .route("/quickstart/actions/render", post(quickstart::render_endpoint))
        // --- CLI client provisioning (bundle = raw templates + typed placeholders) ---
        .route("/provision/actions/bundle", post(provision::bundle))
        .route("/client-access", get(provision::client_access))
        // --- Workspace manager (elevated workspace role) ---
        .route(
            "/workspaces/{id}/members",
            get(portal_manager::list_members),
        )
        .route("/workspaces/{id}/stats", get(portal_manager::member_stats))
        .route(
            "/workspaces/{id}/members/{uid}/keys",
            get(portal_manager::list_member_keys).post(portal_manager::mint_member_key),
        )
        .route(
            "/workspaces/{id}/members/{uid}/keys/{key_id}/actions/revoke",
            post(portal_manager::revoke_member_key),
        )
        .route(
            "/workspaces/{id}/members/{uid}/keys/{key_id}/budget",
            put(portal_manager::set_member_key_budget),
        )
        .route("/workspaces/{id}/limits", get(portal_manager::limits_overview))
        .route("/workspaces/{id}/member-exceptions", get(portal_manager::list_member_exceptions))
        .route(
            "/workspaces/{id}/members/{uid}/limits",
            get(portal_manager::member_limits)
                .put(portal_manager::set_member_exception)
                .delete(portal_manager::remove_member_exception),
        )
        .route("/workspaces/{id}/my-limits", get(portal::my_limits))
        // --- Workspace automation accounts + portal `ak-` keys (manager only) ---
        .route(
            "/workspaces/{id}/automation-accounts",
            get(portal_automation::list_automation_accounts)
                .post(portal_automation::create_automation_account),
        )
        .route(
            "/workspaces/{id}/automation-accounts/{said}/keys",
            get(portal_automation::list_automation_keys)
                .post(portal_automation::mint_automation_key),
        )
        .route(
            "/workspaces/{id}/automation-accounts/{said}/keys/{key_id}/actions/revoke",
            post(portal_automation::revoke_automation_key),
        )
        .route(
            "/workspaces/{id}/automation-accounts/{said}/actions/revoke",
            post(portal_automation::revoke_automation_account),
        )
}

/// The admin plane's per-request session check. The browser tier calls it once
/// for EVERY console request (page loads and each proxied API call), so it must
/// stay out of `auth_router`: that router carries the pre-auth per-IP flood cap,
/// sized for anonymous sign-in traffic, which a busy dashboard exhausts.
pub fn auth_session_router() -> Router<Arc<AdminState>> {
    Router::new().route("/me", get(admin_auth::me))
}

/// The portal plane's per-request session check under header auth — the same
/// role, and the same reason to stay off the pre-auth flood cap, as
/// [`auth_session_router`]. Under standard auth the same route is the
/// secret-gated claim exchange, and `build_app` keeps the cap on it there
/// (`claim_exchange_ip_rate_limit_mw`).
pub fn portal_header_session_router() -> Router<Arc<AdminState>> {
    Router::new().route("/auth/header-me", get(portal_auth::portal_header_me))
}

/// Whether `/portal/auth/header-me` exists at all: under header auth it is the
/// per-request session check, and under standard auth it is the claim
/// exchange, which exists only when a deployment turns it on. Absent, it
/// answers the router's own 404 to every method and every burst, exactly like
/// a path that was never there.
pub fn header_me_is_mounted(header_auth: bool, claim_exchange: bool) -> bool {
    header_auth || claim_exchange
}

/// Portal auth routes (login — NOT behind portal_auth middleware).
pub fn portal_auth_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/auth/login", post(portal_auth::portal_login))
        .route("/auth/logout", post(portal_auth::portal_logout))
        // OAuth callback — must be reachable WITHOUT a portal
        // session token because the browser arrives via an external IdP
        // redirect. Authentication of the request is bound to the
        // pending-authorization `state` parameter (random nonce + DB row).
        .route(
            "/mcp/connections/oauth/callback",
            get(portal_mcp_connections::oauth_callback),
        )
}

/// Public MCP OAuth flow routes. Mounted under
/// `/api/v1/mcp/oauth/{tenant_slug}/...`. None of these are gated by the
/// admin or portal middlewares: `.well-known/...` and `/token` are
/// unauthenticated by spec; `/authorize/preview` and `/authorize/approve`
/// authenticate inline against the portal session JWT carried in the
/// `Authorization` header (the SvelteKit consent page reads it from
/// localStorage).
pub fn mcp_oauth_public_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route(
            "/{tenant_slug}/.well-known/oauth-authorization-server",
            get(mcp_oauth::authorization_server_metadata),
        )
        // Public key set (RFC 7517) for the ES256 access tokens this surface
        // issues. Unauthenticated, like the discovery document that points at it.
        .route(
            "/{tenant_slug}/jwks.json",
            get(mcp_oauth::jwks_document),
        )
        // (cli_oauth_public_router below carries the CLI-provisioning twin
        // of this surface under /api/v1/cli/oauth.)
        .route(
            "/{tenant_slug}/authorize/preview",
            post(mcp_oauth::authorize_preview),
        )
        .route(
            "/{tenant_slug}/authorize/approve",
            post(mcp_oauth::authorize_approve),
        )
        .route(
            "/{tenant_slug}/authorize/deny",
            post(mcp_oauth::authorize_deny),
        )
        .route(
            "/{tenant_slug}/token",
            post(mcp_oauth::token_endpoint),
        )
        .route(
            "/{tenant_slug}/register",
            post(mcp_oauth::register_dynamic_client),
        )
        .route(
            "/{tenant_slug}/revoke",
            post(mcp_oauth::revoke_endpoint),
        )
}

/// Public CLI-provisioning OAuth flow routes. Mounted under
/// `/api/v1/cli/oauth/{tenant_slug}/...` — same gating model as
/// [`mcp_oauth_public_router`]: metadata and `/token`/`/revoke` are
/// unauthenticated by spec; `/authorize/{preview,approve}` authenticate
/// inline against the portal session JWT carried by the SvelteKit consent
/// page at `/portal/t/<slug>/cli/authorize`.
pub fn cli_oauth_public_router() -> Router<Arc<AdminState>> {
    Router::new()
        .route(
            "/{tenant_slug}/.well-known/oauth-authorization-server",
            get(cli_oauth::cli_authorization_server_metadata),
        )
        .route(
            "/{tenant_slug}/authorize/preview",
            post(cli_oauth::cli_authorize_preview),
        )
        .route(
            "/{tenant_slug}/authorize/approve",
            post(cli_oauth::cli_authorize_approve),
        )
        .route(
            "/{tenant_slug}/authorize/deny",
            post(cli_oauth::cli_authorize_deny),
        )
        .route(
            "/{tenant_slug}/device_authorization",
            post(cli_oauth::cli_device_authorization),
        )
        .route(
            "/{tenant_slug}/device/preview",
            post(cli_oauth::cli_device_preview),
        )
        .route(
            "/{tenant_slug}/device/approve",
            post(cli_oauth::cli_device_approve),
        )
        .route(
            "/{tenant_slug}/device/deny",
            post(cli_oauth::cli_device_deny),
        )
        .route("/{tenant_slug}/token", post(cli_oauth::cli_token_endpoint))
        .route("/{tenant_slug}/revoke", post(cli_oauth::cli_revoke_endpoint))
}

#[cfg(test)]
mod spend_tests {
    use super::*;
    use streamscope_core::pricing::{Currency, Unit};

    fn eur() -> Currency {
        Currency::parse("EUR").expect("EUR is a currency")
    }

    #[test]
    fn nothing_spent_is_a_zero_in_the_tenants_own_currency() {
        // Not `None`: a window that priced nothing is a fact the console can
        // state, and reporting it the same way as "we cannot name the
        // denomination" would make an idle month look like a broken ledger.
        let spend = spend_total(0, None, 0.0, eur()).expect("a zero is still a figure");
        assert_eq!(spend.amount, 0.0);
        assert_eq!(spend.currency, eur());
    }

    #[test]
    fn one_currency_is_the_figure_and_the_fallback_is_ignored() {
        let spend = spend_total(1, Some("USD".to_string()), 4.25, eur())
            .expect("one currency states one figure");
        assert_eq!(spend.amount, 4.25);
        assert_eq!(spend.currency, Currency::USD, "the rows' currency, not the tenant's current one");
    }

    #[test]
    fn more_than_one_currency_states_no_figure() {
        // The amount is a real sum of two denominations — which is exactly why
        // it must not be reported. Passing it in proves the guard keys on the
        // count and not on the amount being absent or zero.
        assert!(spend_total(2, Some("USD".to_string()), 9.99, eur()).is_none());
    }

    #[test]
    fn a_currency_the_build_cannot_name_states_no_figure() {
        // Labelling an amount with a guessed denomination is worse than
        // declining to state it.
        assert!(spend_total(1, Some("dollars".to_string()), 1.0, eur()).is_none());
        assert!(spend_total(1, None, 1.0, eur()).is_none());
    }

    /// A group's rank key from its per-currency amounts.
    fn group(parts: &[(&str, f64)], current: &str) -> SpendRank {
        let codes: std::collections::BTreeSet<&str> = parts.iter().map(|(c, _)| *c).collect();
        let in_current: Vec<f64> =
            parts.iter().filter(|(c, _)| *c == current).map(|(_, a)| *a).collect();
        SpendRank {
            in_current: (!in_current.is_empty()).then(|| in_current.iter().sum()),
            lowest_currency: codes.iter().next().and_then(|c| Currency::parse(c)),
            single: (codes.len() == 1).then(|| parts.iter().map(|(_, a)| a).sum()),
        }
    }

    /// Sort named groups with the rule and return their names in rank order.
    fn ranked(mut groups: Vec<(&'static str, SpendRank)>) -> Vec<&'static str> {
        groups.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));
        groups.into_iter().map(|(name, _)| name).collect()
    }

    #[test]
    fn spend_ranks_by_amount_within_one_denomination() {
        // The ordinary window: one currency, largest first, a zero last.
        let out = ranked(vec![
            ("one", group(&[("USD", 1.0)], "USD")),
            ("zero", group(&[("USD", 0.0)], "USD")),
            ("three", group(&[("USD", 3.0)], "USD")),
        ]);
        assert_eq!(out, vec!["three", "one", "zero"]);
    }

    #[test]
    fn spend_never_ranks_amounts_in_two_denominations_against_each_other() {
        // A large amount in another currency does not outrank a small one in
        // today's; the other denominations follow by code, each by amount.
        let out = ranked(vec![
            ("usd-900", group(&[("USD", 900.0)], "EUR")),
            ("eur-1", group(&[("EUR", 1.0)], "EUR")),
            ("gbp-5", group(&[("GBP", 5.0)], "EUR")),
            ("usd-2", group(&[("USD", 2.0)], "EUR")),
            ("eur-4", group(&[("EUR", 4.0)], "EUR")),
        ]);
        assert_eq!(out, vec!["eur-4", "eur-1", "gbp-5", "usd-900", "usd-2"]);
    }

    #[test]
    fn a_straddling_big_spender_keeps_its_place_by_what_it_spent_today() {
        // A top-N list cut by LIMIT across a currency change keeps its biggest
        // spender, who spent on both sides: it ranks by its spend in today's
        // currency alone.
        let out = ranked(vec![
            ("small", group(&[("EUR", 1.0)], "EUR")),
            ("big-straddler", group(&[("USD", 500.0), ("EUR", 40.0)], "EUR")),
            ("mid", group(&[("EUR", 10.0)], "EUR")),
        ]);
        assert_eq!(out, vec!["big-straddler", "mid", "small"]);
        // Positive control: what it spent in the other currency is never what
        // places it — the same straddler with less today ranks below `mid`.
        let out = ranked(vec![
            ("straddler", group(&[("USD", 500.0), ("EUR", 5.0)], "EUR")),
            ("mid", group(&[("EUR", 10.0)], "EUR")),
        ]);
        assert_eq!(out, vec!["mid", "straddler"]);
        // Two groups with nothing today, one of them straddling: ordered by
        // their lowest code, and never by adding their currencies' amounts.
        let a = group(&[("GBP", 1.0), ("USD", 900.0)], "EUR");
        let b = group(&[("GBP", 2.0)], "EUR");
        assert_eq!(a.single, None);
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Greater, "a mixed group's amount is no key");
    }

    #[test]
    fn the_sql_ranking_states_the_same_keys() {
        let sql = spend_rank_order_sql(7);
        let keys: Vec<&str> = sql.split(", ").map(str::trim).collect();
        assert_eq!(
            keys,
            vec![
                "SUM(a.cost) FILTER (WHERE a.cost_currency = $7) DESC NULLS LAST",
                "MIN(a.cost_currency)",
                "CASE WHEN COUNT(DISTINCT a.cost_currency) = 1 THEN SUM(a.cost) END DESC NULLS LAST",
            ],
            "{sql}"
        );
    }

    #[test]
    fn per_unit_columns_name_every_unit_in_the_vocabulary() {
        // The aggregate and its reader walk the same list, so a `Unit` variant
        // added later joins both at once. A column list that fell behind would
        // silently drop that unit's spend out of every decomposition while the
        // total kept including it.
        let sql = billed_unit_columns();
        let forwarded = billed_unit_columns_forwarded();
        for unit in Unit::ALL {
            let w = unit.wire();
            assert!(sql.contains(&format!("AS u_{w}_count")), "{w} count missing from {sql}");
            assert!(sql.contains(&format!("AS u_{w}_cost")), "{w} cost missing from {sql}");
            assert!(forwarded.contains(&format!("agg.u_{w}_count")), "{w} count not forwarded");
            assert!(forwarded.contains(&format!("agg.u_{w}_cost")), "{w} cost not forwarded");
        }
    }
}

#[cfg(test)]
mod time_window_tests {
    use super::*;
    use std::assert_matches;

    fn approx_eq(a: chrono::Duration, b: chrono::Duration, tol: chrono::Duration) -> bool {
        let diff = if a > b { a - b } else { b - a };
        diff <= tol
    }

    #[test]
    fn default_falls_back_to_default_days() {
        let w = TimeWindow::default();
        let (s, e) = w.resolve(7).expect("default rolling resolves");
        assert!(e > s);
        assert!(approx_eq(e - s, chrono::Duration::days(7), chrono::Duration::seconds(2)));
    }

    #[test]
    fn rolling_only_uses_days() {
        let w = TimeWindow { days: Some(3), ..Default::default() };
        let (s, e) = w.resolve(7).expect("rolling-only resolves");
        assert!(approx_eq(e - s, chrono::Duration::days(3), chrono::Duration::seconds(2)));
    }

    #[test]
    fn absolute_only_uses_inputs() {
        let s_in = Utc::now() - chrono::Duration::days(10);
        let e_in = Utc::now() - chrono::Duration::days(5);
        let w = TimeWindow { start: Some(s_in), end: Some(e_in), ..Default::default() };
        let (s, e) = w.resolve(7).expect("absolute resolves");
        assert_eq!(s, s_in);
        assert_eq!(e, e_in);
    }

    #[test]
    fn absolute_partial_defaults_end_to_now() {
        let s_in = Utc::now() - chrono::Duration::days(10);
        let w = TimeWindow { start: Some(s_in), ..Default::default() };
        let (s, e) = w.resolve(7).expect("partial absolute resolves");
        assert_eq!(s, s_in);
        assert!(e > s);
    }

    #[test]
    fn mix_modes_rejected() {
        let w = TimeWindow {
            days: Some(7),
            start: Some(Utc::now() - chrono::Duration::days(1)),
            end: None,
        };
        let err = w.resolve(7).expect_err("mixed mode rejected");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_matches!(err.code, ApiErrorCode::TimeWindowConflict);
    }

    #[test]
    fn zero_or_negative_days_rejected() {
        for d in [0, -1, -100] {
            let w = TimeWindow { days: Some(d), ..Default::default() };
            let err = w.resolve(7).expect_err("non-positive days rejected");
            assert_matches!(err.code, ApiErrorCode::TimeWindowInvalid);
        }
    }

    #[test]
    fn inverted_range_rejected() {
        let s_in = Utc::now() - chrono::Duration::days(1);
        let e_in = Utc::now() - chrono::Duration::days(10);
        let w = TimeWindow { start: Some(s_in), end: Some(e_in), ..Default::default() };
        let err = w.resolve(7).expect_err("start>=end rejected");
        assert_matches!(err.code, ApiErrorCode::TimeWindowInvalid);
    }

    #[test]
    fn equal_start_end_rejected() {
        let t = Utc::now();
        let w = TimeWindow { start: Some(t), end: Some(t), ..Default::default() };
        let err = w.resolve(7).expect_err("start==end rejected");
        assert_matches!(err.code, ApiErrorCode::TimeWindowInvalid);
    }

    #[test]
    fn an_offset_resolves_between_zero_and_its_ceiling() {
        assert_eq!(resolve_offset(None), 0);
        assert_eq!(resolve_offset(Some(-1)), 0);
        assert_eq!(resolve_offset(Some(i64::MIN)), 0);
        assert_eq!(resolve_offset(Some(MAX_OFFSET)), MAX_OFFSET);
        assert_eq!(resolve_offset(Some(MAX_OFFSET + 1)), MAX_OFFSET);
        assert_eq!(resolve_offset(Some(i64::MAX)), MAX_OFFSET);
        // Every overfetch `offset + limit + 1` stays in range at the ceiling.
        let (limit, offset) = PageQuery { limit: Some(i64::MAX), offset: Some(i64::MAX) }.resolve();
        assert!(offset.checked_add(limit).and_then(|n| n.checked_add(1)).is_some());
    }

    #[test]
    fn a_merged_list_answers_down_to_its_deepest_page_and_no_further() {
        assert!(check_merged_offset(0).is_ok());
        assert!(check_merged_offset(MAX_MERGED_OFFSET).is_ok());
        let err = check_merged_offset(MAX_MERGED_OFFSET + 1).expect_err("one past the deepest page");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_matches!(err.code, ApiErrorCode::PageTooDeep);
        assert_matches!(check_merged_offset(MAX_OFFSET).map_err(|e| e.code), Err(ApiErrorCode::PageTooDeep));
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn an_address_is_stored_trimmed_and_ascii_lower_cased() {
        assert_eq!(normalize_email("  Ada.Lovelace@Contoso.COM "), "ada.lovelace@contoso.com");
        assert_eq!(normalize_email("ada@corp.test"), "ada@corp.test");
    }

    /// A non-ASCII look-alike is a different address, never folded onto one.
    #[test]
    fn only_ascii_letters_fold() {
        assert_eq!(normalize_email("\u{212A}ate@corp.test"), "\u{212A}ate@corp.test");
        assert_ne!(normalize_email("\u{212A}ate@corp.test"), normalize_email("Kate@corp.test"));
    }

    #[test]
    fn a_plain_address_yields_its_domain() {
        assert_eq!(address_domain("ada@corp.test"), Some("corp.test"));
        assert_eq!(address_domain("Ada.Lovelace+x@Corp.Test"), Some("Corp.Test"));
    }

    /// Anything a last-`@` split would read one way and a mail system another.
    #[test]
    fn an_ambiguous_or_malformed_address_has_no_domain() {
        for bad in [
            "mallory@evil.test@corp.test",
            "ada",
            "@corp.test",
            "ada@",
            "ada @corp.test",
            "ada@corp.test\n",
            "",
        ] {
            assert_eq!(address_domain(bad), None, "{bad:?}");
        }
    }

    /// The allowlist judges the one domain the address has, and refuses an
    /// address with two — the positive control is the same allowlist admitting
    /// a plain address in that domain.
    #[test]
    fn the_domain_allowlist_cannot_be_reached_through_a_second_at() {
        let allowed = Some(vec!["corp.test".to_string()]);
        assert!(check_allowed_domains("ada@corp.test", &allowed).is_ok());
        assert!(check_allowed_domains("ada@CORP.test", &allowed).is_ok());
        assert!(check_allowed_domains("mallory@evil.test@corp.test", &allowed).is_err());
        assert!(check_allowed_domains("mallory@evil.test", &allowed).is_err());
    }
}

#[cfg(test)]
mod db_unavailable_tests {
    use super::db_unavailable;

    /// A Postgres error carrying `code`, as the driver would surface it.
    #[derive(Debug)]
    struct Pg(&'static str);
    impl std::fmt::Display for Pg {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "sqlstate {}", self.0)
        }
    }
    impl std::error::Error for Pg {}
    impl sqlx::error::DatabaseError for Pg {
        fn message(&self) -> &str {
            self.0
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.0.into())
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }
    fn pg(code: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(Pg(code)))
    }

    /// The database could not be asked → an outage; everything else — a schema
    /// mismatch after a rollback, a revoked grant, a row that does not decode —
    /// is a fault, or a client retrying 503s would retry it forever. Each
    /// outage class sits beside a neighbour that is not one.
    #[test]
    fn only_a_database_that_could_not_be_asked_is_an_outage() {
        for outage in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            pg("08006"), // connection failure
            pg("08000"),
            pg("57P01"), // admin shutdown
            pg("57P02"),
            pg("57P03"), // cannot connect now
            pg("53300"), // too many connections
            pg("57014"), // statement timeout — an overloaded database
        ] {
            assert!(db_unavailable(&outage), "{outage} is an outage");
        }
        for fault in [
            sqlx::Error::RowNotFound,
            sqlx::Error::ColumnNotFound("last_seen_version".into()),
            pg("42703"), // undefined column — a rollback across a schema change
            pg("42501"), // insufficient privilege — a revoked grant
            pg("57P04"), // beside 57P01–57P03
            pg("53200"), // out of memory — beside 53300
            pg("09000"), // beside class 08
        ] {
            assert!(!db_unavailable(&fault), "{fault} is not an outage");
        }
    }
}
