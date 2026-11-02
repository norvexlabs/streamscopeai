//! Streamscope admin API server.
//!
//! Central management plane: runs database migrations, seeds default data,
//! registers route handlers, and spawns background tasks (retention purge,
//! LLM agent analysis). Serves both the admin dashboard API and the edge
//! protocol (`/api/v2/edge`: config sync and audit ingest, over plain HTTP).
//!
//! Authentication is dual-mode: `ADMIN_API_KEY` header for service clients
//! and JWT session tokens for browser-based admin and portal users.

// The release binary is a static musl build, whose own allocator is slow under
// concurrent load.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

/// The output cap a model resolves to, as a SQL expression over the model row
/// `$m` and its catalog row `$c`. The model's own value (an operator's, or one the
/// provider reported) wins as it is. One inherited from the catalog is taken as
/// it is too, unless the model states a window smaller than the catalog's (or the
/// catalog states none) — a shorter deployment of the same model: then it is held to half the model's
/// window (at least one token), since clients send the cap as `max_tokens` on
/// every call and an engine refuses a request whose prompt plus `max_tokens`
/// exceeds its window. A window of 0 or less states nothing. No cap
/// on either row stays no cap (`LEAST` alone would skip the NULL and invent one).
/// Every query resolving `max_output_tokens` reads this one expression, so the
/// model list, the per-call clamp and provisioned client configs agree.
macro_rules! resolved_max_output_sql {
    ($m:literal, $c:literal) => {
        concat!(
            "COALESCE(", $m, ".max_output_tokens, CASE WHEN ", $c, ".max_output_tokens IS NOT NULL AND ",
            $m, ".context_window > 0 AND (", $c, ".context_window IS NULL OR ", $m, ".context_window < ",
            $c, ".context_window) THEN LEAST(",
            $c, ".max_output_tokens, GREATEST(", $m, ".context_window / 2, 1)) ELSE ", $c,
            ".max_output_tokens END)"
        )
    };
}

/// The URL of the upstream server row `$s`: its primary endpoint's — the first
/// ENABLED endpoint by `(position, created_at, id)` — or NULL when it has no
/// enabled endpoint. The endpoint table is the one place a server's URLs are
/// stored; every query that states a server's URL reads this one expression.
macro_rules! server_url_sql {
    ($s:literal) => {
        concat!(
            "(SELECT pe.url FROM upstream_server_endpoints pe WHERE pe.tenant_id = ", $s,
            ".tenant_id AND pe.server_id = ", $s,
            ".id AND pe.enabled ORDER BY pe.position, pe.created_at, pe.id LIMIT 1)"
        )
    };
}

/// SQL predicate: a provider's grants reach something — a key-managed one's
/// always, a pass-through's unless its server is off. `$byok` is the
/// provider's `byok` column and `$enabled` its server's `enabled` (NULL when
/// no server is linked). The one rule behind [`routes::LIVE_PROVIDER_GRANTS`]
/// and the workspace grant list's Off mark.
macro_rules! live_passthrough_sql {
    ($byok:literal, $enabled:literal) => {
        concat!("(NOT ", $byok, " OR COALESCE(", $enabled, ", true))")
    };
}

/// SQL scalar: how many keys are bound to provider `$provider` (a BYOK `vk-`
/// key's pass-through) and not revoked — expired ones included — narrowed by
/// `$and` (`""` or an `AND ...` on `k`). The same set a provider delete
/// revokes (`key_lifecycle::revoke_keys_bound_to`), and what removing a grant
/// leaves refused.
macro_rules! bound_keys_sql {
    ($provider:literal, $and:literal) => {
        concat!(
            "(SELECT COUNT(*) FROM api_keys k WHERE k.downstream_provider_id = ", $provider,
            " AND k.revoked_at IS NULL ", $and, ")::bigint"
        )
    };
}

/// SQL predicate: route `r` is served — the route, its model `m` and that
/// model's server `s` are all on. The edge snapshot builds routes from it, so
/// every read that offers or resolves a route for a client uses it too: one
/// that checks less offers a model the gateway refuses.
macro_rules! live_route_sql {
    () => {
        "(r.enabled AND m.enabled AND s.enabled)"
    };
}

mod agent;
mod alerts;
mod audit_store;
mod authz;
mod batch_delete;
mod body_read;
mod config_builder;
mod content_store;
mod conversation;
mod custom_ca;
mod db;
mod egress;
mod edge_nodes;
mod edge_v2;
mod inline_ai;
pub mod leader;
mod limits;
mod qos;
mod metrics;
mod middleware;
mod notifications;
mod oidc;
mod retention;
mod routes;
/// In-process tests over the production router built by `build_app`.
#[cfg(test)]
mod router_tests;
/// The API design rules, checked against the published spec and the router.
#[cfg(test)]
mod api_conformance_tests;
mod seed_loader;
mod seed_scripts;
mod service_account;
mod settings;
mod sql_pattern;
mod tenant_public_url;
mod usage_rollup;
/// Delay before first retention/partition check after startup.
const RETENTION_STARTUP_DELAY: std::time::Duration = std::time::Duration::from_secs(60);

/// Last-resort panic boundary for the HTTP stack. A panic inside a request
/// handler is unwound here and turned into a sanitized 500 (`ApiErrorResponse`
/// envelope) instead of dropping the connection. The panic payload is
/// intentionally discarded — the panic hook (`install_panic_logger`) has
/// already logged it with a backtrace during unwinding; it never reaches the
/// client.
pub(crate) fn handle_panic(_err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    use axum::response::IntoResponse;
    routes::ApiError::internal("request handler panicked")
        .code(routes::ApiErrorCode::InternalError)
        .into_response()
}

use streamscope_core::middleware::ip_rate_limit::RateLimiter;

/// Map-cleanup threshold for the per-source-IP pre-auth limiter. Keyed by IP, it
/// can hold far more live keys than the identity-keyed limiters (a distributed
/// scan touches one entry per source), so it sweeps expired entries less often.
const PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD: usize = 10_000;

pub struct AdminState {
    pub db: crate::db::Db,
    /// Unique identifier for this admin-api instance (generated at startup).
    /// Used for edge-to-instance mapping and cross-instance command routing.
    pub instance_id: uuid::Uuid,
    /// Login rate limiter (credential-based, not IP-based).
    pub login_rate_limiter: RateLimiter,
    /// Rate limiter for invite acceptance endpoint.
    pub invite_rate_limiter: RateLimiter,
    /// Per-source-IP limiter across all unauthenticated pre-auth surfaces. Bounds
    /// an attacker who varies the identity string to slip past the per-account
    /// limiters; disabled when its cap resolves to 0.
    pub pre_auth_ip_rate_limiter: RateLimiter,
    /// Per-key limiter for authenticated `ak-` automation traffic, on both the
    /// admin and portal planes. The pre-auth IP limiter cannot cover these —
    /// an automation key authenticates, so it reaches the guarded routers.
    /// Keyed on the presented key's hash, so the check precedes any lookup.
    /// Disabled when its cap resolves to 0.
    pub automation_key_rate_limiter: RateLimiter,
    /// Per-source limiter on **failed** `ak-` authentications, on both guarded
    /// planes. Where `automation_key_rate_limiter` bounds one key, this bounds
    /// one source — the prober who varies the token, whose every attempt would
    /// otherwise drive a full tenant-resolve scan for free. Counts DISTINCT
    /// keys, so a client repeating one stale key never trips it. Disabled when
    /// its cap resolves to 0.
    pub automation_key_ip_rate_limiter: crate::middleware::DistinctKeyFailures,
    /// Shared outbound HTTP client — used for OAuth token exchange against
    /// upstream IdPs (per-user OAuth) and OIDC discovery.
    pub http_client: reqwest::Client,
    /// Browser CORS allowlist for `/api/v1/admin/*` and `/api/v1/portal/*`,
    /// derived from every tenant's resolved `admin_public_url` (per-tenant
    /// override layered over the SYSTEM default — the same single value
    /// the tenant's UI talks to). Kept current as config changes land
    /// (`watch_cors_allowlist`). Empty until the first build, after
    /// which fail-closed: requests with `Origin` mismatching nothing in
    /// the set are 403'd by the CORS layer.
    pub cors_allowlist: arc_swap::ArcSwap<std::collections::HashSet<String>>,
}

/// The customer tenants whose origins are held: SYSTEM's own origin is the
/// default ([`CorsOrigins::system`]), never a tenant entry, since its changes
/// are named `global`.
const ACTIVE_TENANTS: &str = "SELECT id FROM tenants WHERE is_active = true AND id <> $1";

/// The browser origins the admin-api CORS allowlist is built from: each active
/// tenant's own `admin_public_url` (`None` = it inherits) and the SYSTEM
/// default. The set is the union of effective per-tenant URLs — every browser
/// origin that any tenant might serve from.
///
/// `system_settings` is RLS-scoped per tenant_id, so each tenant's row is read
/// under its own `app.tenant_id` GUC.
///
/// `api_public_url` is deliberately *not* in this set. The Caddy admin-API
/// vhost is reachable from scripts (CLIs, programmatic clients) and from
/// browser-loaded tools served by the admin-API itself (e.g. Scalar at
/// `/api/docs`). Scripts are not browsers and don't send `Origin`; tools
/// served from the API origin make same-origin requests with no preflight.
/// The only `Origin` value a browser ever sends to the admin-API is the
/// origin of the page that's making the call — which is the admin-UI
/// (served via SvelteKit at `admin_public_url`), never `api_public_url`
/// itself.
#[derive(Default)]
struct CorsOrigins {
    system: Option<String>,
    tenants: std::collections::HashMap<uuid::Uuid, Option<String>>,
}

impl CorsOrigins {
    /// Every origin: the SYSTEM default, and each tenant's own or the default.
    fn allowlist(&self) -> std::collections::HashSet<String> {
        self.system
            .iter()
            .chain(self.tenants.values().filter_map(|own| own.as_ref().or(self.system.as_ref())))
            .cloned()
            .collect()
    }

    /// Read every active tenant's origin and the SYSTEM default, in two
    /// queries: the active tenants, and every tenant's own setting
    /// (`cors_origins_all`).
    async fn read_all(db: &db::Db) -> Result<Self, sqlx::Error> {
        let tenants: Vec<uuid::Uuid> = sqlx::query_scalar(ACTIVE_TENANTS)
            .bind(db::tenant::TenantId::SYSTEM.as_uuid())
            .fetch_all(db.global(db::Global::TenantIteration))
            .await?;
        let mut set: std::collections::HashMap<uuid::Uuid, Option<String>> =
            sqlx::query_as::<_, (uuid::Uuid, serde_json::Value)>("SELECT tenant_id, admin_public_url FROM cors_origins_all()")
                .fetch_all(db.global(db::Global::TenantIteration))
                .await?
                .into_iter()
                .map(|(t, v)| (t, admin_url_of(Some(&v))))
                .collect();
        let mut origins = Self {
            system: set.remove(&db::tenant::TenantId::SYSTEM.as_uuid()).flatten(),
            ..Self::default()
        };
        for t in tenants {
            origins.tenants.insert(t, set.remove(&t).flatten());
        }
        Ok(origins)
    }

    /// Drop the tenants no longer active and read the active ones not held;
    /// whether anything moved.
    async fn keep_active(&mut self, db: &db::Db) -> Result<bool, sqlx::Error> {
        let active: std::collections::HashSet<uuid::Uuid> =
            sqlx::query_scalar(ACTIVE_TENANTS)
                .bind(db::tenant::TenantId::SYSTEM.as_uuid())
                .fetch_all(db.global(db::Global::TenantIteration))
                .await?
                .into_iter()
                .collect();
        let held = self.tenants.len();
        self.tenants.retain(|t, _| active.contains(t));
        let mut changed = self.tenants.len() != held;
        for t in active {
            if let std::collections::hash_map::Entry::Vacant(slot) = self.tenants.entry(t) {
                slot.insert(read_admin_url(db, db::tenant::TenantId::from_row(t)).await?);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Re-read what the config changes to `resources` (`config_bumps`
    /// names) can have moved: `global` is the SYSTEM default, `tenant:<id>`
    /// that tenant's origin, or its removal when it is gone or inactive.
    async fn reread(&mut self, db: &db::Db, resources: &[String]) -> Result<(), sqlx::Error> {
        for resource in resources {
            if resource == "global" {
                self.system = read_admin_url(db, db::tenant::TenantId::SYSTEM).await?;
                continue;
            }
            let Some(t) = resource
                .strip_prefix("tenant:")
                .and_then(|t| t.parse::<uuid::Uuid>().ok())
                .filter(|t| *t != db::tenant::TenantId::SYSTEM.as_uuid())
            else {
                continue;
            };
            let active: Option<bool> = sqlx::query_scalar("SELECT is_active FROM tenants WHERE id = $1")
                .bind(t)
                .fetch_optional(db.global(db::Global::TenantRegistry))
                .await?;
            if active == Some(true) {
                self.tenants.insert(t, read_admin_url(db, db::tenant::TenantId::from_row(t)).await?);
            } else {
                self.tenants.remove(&t);
            }
        }
        Ok(())
    }
}

/// One tenant's own `admin_public_url`, trimmed; `None` when unset or empty.
async fn read_admin_url(db: &db::Db, t: db::tenant::TenantId) -> Result<Option<String>, sqlx::Error> {
    let mut db = db.tenant(t).await?;
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = 'admin_public_url' AND tenant_id = $1")
            .bind(t.as_uuid())
            .fetch_optional(db.conn())
            .await?;
    Ok(admin_url_of(value.as_ref()))
}

/// An `admin_public_url` setting's value, trimmed; `None` when unset or empty.
fn admin_url_of(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Keep the CORS allowlist current, from the origins `known` as of a change
/// head: each second, re-read only the origins the config changes since then
/// can have moved. With nothing known, and after the change counter went
/// backwards (a database restore), it reads all. Once a minute the tenants
/// held are checked against the active ones — the change log forgets a
/// deleted tenant's changes, so one missed between two looks would otherwise
/// leave its origin allowed. A failed look keeps what was known and retries.
async fn watch_cors_allowlist(
    state: Arc<AdminState>,
    mut known: Option<(i64, CorsOrigins)>,
    token: tokio_util::sync::CancellationToken,
) {
    const MEMBERSHIP_EVERY: u32 = 60;
    let mut looks: u32 = 0;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tick.tick() => {}
        }
        looks = (looks + 1) % MEMBERSHIP_EVERY;
        match advance_cors_origins(&state.db, known.take(), looks == 0).await {
            Ok((head, origins, changed)) => {
                if changed {
                    state.cors_allowlist.store(Arc::new(origins.allowlist()));
                }
                known = Some((head, origins));
            }
            Err((e, kept)) => {
                tracing::warn!(error = %e, "CORS allowlist refresh failed");
                known = kept;
            }
        }
    }
}

/// The origins as of the current change head, from those `known` as of an
/// earlier one (`None`: read all), and whether they may have changed. The head
/// is read before the origins, so a change landing meanwhile is seen next
/// time. On failure, what was known comes back, still labelled with its own
/// head, so the same changes are read again.
// The error hands what was known back to the once-a-second loop that owns it.
#[allow(clippy::result_large_err)]
async fn advance_cors_origins(
    db: &db::Db,
    known: Option<(i64, CorsOrigins)>,
    check_membership: bool,
) -> Result<(i64, CorsOrigins, bool), (sqlx::Error, Option<(i64, CorsOrigins)>)> {
    let head: i64 = match sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM config_bumps")
        .fetch_one(db.global(db::Global::Infra))
        .await
    {
        Ok(h) => h,
        Err(e) => return Err((e, known)),
    };
    let (mut origins, mut changed) = match known {
        Some((seen, origins)) if seen == head => (origins, false),
        Some((seen, mut origins)) if seen < head => {
            let bumped: Result<Vec<String>, sqlx::Error> =
                sqlx::query_scalar("SELECT DISTINCT resource FROM config_bumps WHERE id > $1 AND id <= $2")
                    .bind(seen)
                    .bind(head)
                    .fetch_all(db.global(db::Global::Infra))
                    .await;
            if let Err(e) = match bumped {
                Ok(resources) => origins.reread(db, &resources).await,
                Err(e) => Err(e),
            } {
                return Err((e, Some((seen, origins))));
            }
            (origins, true)
        }
        _ => match CorsOrigins::read_all(db).await {
            Ok(origins) => return Ok((head, origins, true)),
            Err(e) => return Err((e, None)),
        },
    };
    // A failed check is retried at the next one; what was re-read stands.
    if check_membership {
        match origins.keep_active(db).await {
            Ok(moved) => changed |= moved,
            Err(e) => tracing::warn!(error = %e, "CORS allowlist: active-tenant check failed"),
        }
    }
    Ok((head, origins, changed))
}

// ---------------------------------------------------------------------------
// OpenAPI specification
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Streamscope Admin API",
        version = "1.0.0",
        description = "Management API for Streamscope AI — security, audit, and cost control gateway for LLM workloads."
    ),
    paths(
        // Users
        routes::users::create_user,
        routes::users::list_users,
        routes::users::get_user,
        routes::users::update_user,
        routes::users::get_user_usage,
        routes::users::delete_user,
        // Servers
        routes::upstreams::list_provider_defaults,
        routes::upstreams::create_server,
        routes::upstreams::list_servers,
        routes::upstreams::get_server,
        routes::upstreams::patch_server,
        routes::upstreams::delete_server,
        routes::upstreams::sync_server_models,
        routes::upstreams::sync_now,
        routes::upstream_endpoints::list_endpoints,
        routes::upstream_endpoints::create_endpoint,
        routes::upstream_endpoints::patch_endpoint,
        routes::upstream_endpoints::delete_endpoint,
        routes::upstream_endpoints::reorder_endpoints,
        routes::upstream_endpoints::discover_endpoint,
        routes::upstream_endpoints::probe_engine,
        routes::upstream_endpoints::get_membership,
        // Models
        routes::upstreams::create_server_models,
        routes::upstreams::list_models,
        routes::upstreams::update_model,
        routes::upstreams::delete_model,
        routes::upstreams::batch_delete_models,
        routes::upstreams::bulk_update_models,
        // Model Presets
        routes::model_presets::list_presets,
        routes::model_presets::create_preset,
        routes::model_presets::update_preset,
        routes::model_presets::delete_preset,
        routes::model_presets::set_default_preset,
        // Downstream Providers
        routes::downstream::list_providers,
        routes::downstream::create_provider,
        routes::downstream::get_provider,
        routes::downstream::update_provider,
        routes::downstream::delete_provider,
        // Workspaces
        routes::workspaces::list_workspaces,
        routes::workspaces::create_workspace,
        routes::workspaces::get_workspace,
        routes::workspaces::update_workspace,
        routes::workspaces::delete_workspace,
        routes::workspaces::list_members,
        routes::workspaces::add_member,
        routes::workspaces::update_member,
        routes::workspaces::remove_member,
        routes::workspaces::list_workspace_providers,
        routes::workspaces::add_provider,
        routes::workspaces::remove_provider,
        routes::workspaces::list_workspace_mcp_servers,
        routes::workspaces::add_mcp_server,
        routes::workspaces::remove_mcp_server,
        routes::workspaces::list_workspace_a2a_agents,
        routes::workspaces::add_a2a_agent,
        routes::workspaces::remove_a2a_agent,
        routes::workspaces::get_rate_limits,
        routes::workspaces::put_rate_limits,
        routes::workspaces::list_rate_limit_overrides,
        routes::workspaces::put_rate_limit_override,
        routes::workspaces::delete_rate_limit_override,
        routes::workspaces::get_member_defaults,
        routes::workspaces::put_member_defaults,
        routes::workspaces::get_limits_overview,
        routes::workspaces::get_member_effective_limits,
        // Profiles (generic per-kind bundles) + per-profile guardrail policy
        routes::qos_classes::list_qos_classes,
        routes::qos_classes::get_qos_deployment_limits,
        routes::qos_classes::create_qos_class,
        routes::qos_classes::get_qos_class,
        routes::qos_classes::update_qos_class,
        routes::qos_classes::delete_qos_class,
        routes::qos_classes::set_default_qos_class,
        routes::qos_classes::set_mint_default_qos_class,
        routes::profiles::list_profiles,
        routes::profiles::create_profile,
        routes::profiles::get_profile,
        routes::profiles::update_profile,
        routes::profiles::delete_profile,
        routes::profiles::set_default_profile,
        routes::profiles::reset_profile_to_seed,
        routes::guardrail::get_profile_guardrail_policy,
        routes::guardrail::update_profile_guardrail_policy,
        routes::expert_profiles::get_profile_expert_membership,
        routes::expert_profiles::update_profile_expert_membership,
        routes::client_access_profiles::get_profile_client_access,
        routes::client_access_profiles::update_profile_client_access,
        routes::client_access_profiles::attach_developer_defaults,
        routes::destination_lists::list,
        routes::destination_lists::create,
        routes::destination_lists::get_one,
        routes::destination_lists::update,
        routes::destination_lists::delete,
        routes::destination_lists::reset,
        routes::destination_lists::reset_all,
        // Route Policies
        routes::downstream::flush_route_cache,
        routes::downstream::flush_tenant_cache,
        routes::cache_settings::get_cache_settings,
        routes::cache_settings::update_cache_settings,
        routes::cache_settings::probe_embedding_alias,
        routes::cache_settings::list_embedding_aliases,
        routes::cache_presets::list_cache_presets,
        routes::cache_presets::get_cache_preset,
        routes::cache_presets::create_cache_preset,
        routes::cache_presets::update_cache_preset,
        routes::cache_presets::delete_cache_preset,
        routes::route_policies::list_route_policies,
        routes::route_policies::create_route_policy,
        routes::route_policies::update_route_policy,
        routes::route_policies::delete_route_policy,
        // A2A gateway
        routes::a2a::list_a2a_agents,
        routes::a2a::get_a2a_agent,
        routes::a2a::create_a2a_agent,
        routes::a2a::update_a2a_agent,
        routes::a2a::delete_a2a_agent,
        routes::a2a::refresh_a2a_agent_card,
        // MCP gateway
        routes::mcp::list_mcp_upstream_servers,
        routes::mcp::get_mcp_upstream_server,
        routes::mcp::create_mcp_upstream_server,
        routes::mcp::update_mcp_upstream_server,
        routes::mcp::delete_mcp_upstream_server,
        routes::mcp_discovery::discover_upstream_oauth,
        routes::mcp_discovery::register_upstream_oauth_client,
        routes::mcp::list_mcp_virtual_servers,
        routes::mcp::get_mcp_virtual_server,
        routes::mcp::create_mcp_virtual_server,
        routes::mcp::update_mcp_virtual_server,
        routes::mcp::delete_mcp_virtual_server,
        routes::mcp::list_mcp_virtual_routes,
        routes::mcp::get_mcp_virtual_route,
        routes::mcp::create_mcp_virtual_route,
        routes::mcp::update_mcp_virtual_route,
        routes::mcp::delete_mcp_virtual_route,
        // MCP per-user-OAuth admin view (Connections section on Upstream cards)
        routes::mcp::list_mcp_upstream_connections,
        routes::mcp::delete_mcp_upstream_connection,
        // MCP spec OAuth
        routes::mcp_oauth::list_oauth_clients,
        routes::mcp_oauth::get_oauth_client,
        routes::mcp_oauth::create_oauth_client,
        routes::mcp_oauth::update_oauth_client,
        routes::mcp_oauth::delete_oauth_client,
        routes::mcp_oauth::list_issued_tokens,
        routes::mcp_oauth::revoke_issued_token,
        routes::cli_oauth::list_cli_sessions,
        routes::cli_oauth::revoke_cli_session,
        routes::mcp_oauth::authorization_server_metadata,
        routes::mcp_oauth::jwks_document,
        routes::mcp_oauth::list_cimd_clients,
        routes::mcp_oauth::revoke_cimd_client,
        routes::mcp_oauth::authorize_preview,
        routes::mcp_oauth::authorize_approve,
        routes::mcp_oauth::authorize_deny,
        routes::mcp_oauth::token_endpoint,
        routes::mcp_oauth::register_dynamic_client,
        routes::mcp_oauth::revoke_endpoint,
        routes::cli_oauth::cli_authorization_server_metadata,
        routes::cli_oauth::cli_authorize_preview,
        routes::cli_oauth::cli_authorize_approve,
        routes::cli_oauth::cli_authorize_deny,
        routes::cli_oauth::cli_device_authorization,
        routes::cli_oauth::cli_device_preview,
        routes::cli_oauth::cli_device_approve,
        routes::cli_oauth::cli_device_deny,
        routes::cli_oauth::cli_token_endpoint,
        routes::cli_oauth::cli_revoke_endpoint,
        routes::cli_dist::version,
        routes::cli_dist::install_sh,
        routes::cli_dist::install_ps1,
        routes::cli_dist::download,
        routes::cli_dist::ca,
        routes::provision::bundle,
        routes::provision::client_access,
        // Routes
        routes::downstream::list_routes,
        routes::downstream::create_route,
        routes::downstream::batch_create_routes,
        routes::downstream::update_route,
        routes::downstream::delete_route,
        routes::downstream::list_route_collisions,
        // Portal
        routes::portal::me,
        routes::portal::list_keys,
        routes::portal::create_key,
        routes::portal::revoke_key,
        routes::portal::my_stats,
        routes::portal_home::home,
        routes::portal::my_sessions,
        routes::portal::my_session_conversation,
        routes::portal::my_session_linked,
        routes::portal::my_audit,
        routes::portal::my_trace,
        routes::portal::my_audit_filter_options,
        routes::portal::my_web_calls_for_request,
        routes::portal::my_media,
        routes::portal::my_tool_definition_blob,
        routes::portal_manager::list_members,
        routes::portal_manager::list_member_keys,
        routes::portal_manager::member_stats,
        routes::portal_manager::mint_member_key,
        routes::portal_manager::revoke_member_key,
        routes::portal_manager::set_member_key_budget,
        routes::portal_manager::limits_overview,
        routes::portal_manager::list_member_exceptions,
        routes::portal_manager::member_limits,
        routes::portal_manager::set_member_exception,
        routes::portal_manager::remove_member_exception,
        routes::portal::my_limits,
        routes::portal_automation::list_automation_accounts,
        routes::portal_automation::create_automation_account,
        routes::portal_automation::list_automation_keys,
        routes::portal_automation::mint_automation_key,
        routes::portal_automation::revoke_automation_key,
        routes::portal_automation::revoke_automation_account,
        routes::portal_mcp::list_virtual_servers,
        routes::portal_mcp_connections::list_connections,
        routes::portal_mcp_connections::connect_init,
        routes::portal_mcp_connections::oauth_callback,
        routes::portal_mcp_connections::revoke_connection,
        routes::portal_mcp_test::test_virtual_server,
        // Portal Quickstart
        routes::quickstart::list_clients,
        routes::quickstart::get_client,
        routes::quickstart::list_routes,
        routes::quickstart::list_keys,
        routes::quickstart::render_endpoint,
        // Admin client-profiles override surface
        routes::client_profiles_admin::list,
        routes::client_profiles_admin::create,
        routes::client_profiles_admin::get_one,
        routes::client_profiles_admin::update,
        routes::client_profiles_admin::reset,
        routes::client_profiles_admin::reset_all,
        routes::client_profiles_admin::placeholders,
        routes::client_profiles_admin::preview,
        routes::client_profiles_admin::delete,
        // Portal Auth
        routes::portal_auth::portal_login,
        routes::portal_auth::portal_logout,
        routes::portal_auth::portal_header_me,
        // Edge Nodes
        crate::edge_nodes::create_edge_node,
        crate::edge_nodes::list_edge_nodes,
        crate::edge_nodes::update_edge_node,
        crate::edge_nodes::delete_edge_node,
        crate::edge_v2::sync::sync_handler,
        crate::edge_v2::ingest::ingest_handler,
        crate::edge_v2::blobs::put_blob_handler,
        crate::edge_v2::replay::replay_handler,
        crate::edge_v2::status::edge_sync_status,
        crate::edge_v2::status::tenant_sync_status,
        // Admin-action audit
        routes::admin_audit::list_admin_audit,
        routes::admin_audit::list_global_admin_audit,
        routes::admin_audit::list_portal_audit,
        routes::admin_audit::list_security_audit,
        routes::admin_audit::list_global_portal_audit,
        routes::admin_audit::list_global_security_audit,
        // Admin Accounts
        routes::admin_auth::create_admin_account,
        routes::admin_auth::list_admin_accounts,
        routes::admin_auth::get_admin_account,
        routes::admin_auth::update_admin_account,
        routes::admin_auth::delete_admin_account,
        // Authentication
        routes::admin_auth::login,
        routes::admin_auth::logout,
        routes::admin_auth::me,
        routes::admin_auth::setup,
        routes::admin_auth::setup_status,
        routes::admin_auth::oidc_exchange,
        // Changelog
        routes::changelog::get_changelog,
        routes::changelog::dismiss_changelog,
        // Tenants
        routes::tenants::create_tenant,
        routes::tenants::list_tenants,
        routes::tenants::get_tenant,
        routes::tenants::update_tenant,
        routes::tenants::delete_tenant,
        routes::tenants::list_tenant_admins,
        // Invites
        routes::tenants::create_invite,
        routes::tenants::list_invites,
        routes::tenants::revoke_invite,
        routes::tenants::get_invite_info,
        routes::tenants::accept_invite,
        // Auth Config
        routes::auth_config::get_auth_config,
        routes::auth_config::update_auth_config,
        routes::auth_config::test_oidc_config,
        routes::auth_config::get_tenant_auth_info,
        routes::oidc_rp::begin,
        routes::oidc_rp::callback,
        routes::oidc_rp::end_session_url,
        // Internal platform-host callbacks
        routes::internal_platform::post_platform_purge,
        // API Keys
        routes::keys::create_key,
        routes::keys::list_keys,
        routes::keys::get_key,
        routes::keys::update_key,
        routes::keys::revoke_key,
        routes::keys::get_key_usage,
        // Service accounts
        routes::service_accounts::create_service_account_handler,
        routes::service_accounts::list_service_accounts,
        routes::service_accounts::get_service_account,
        routes::service_accounts::disable_service_account,
        routes::service_accounts::enable_service_account,
        routes::service_accounts::revoke_service_account,
        routes::service_accounts::rotate_agent_key,
        routes::service_accounts::rotate_inline_ai_key,
        routes::service_accounts::mint_service_account_key,
        routes::service_accounts::list_service_account_keys,
        routes::service_accounts::revoke_service_account_key,
        routes::service_accounts::rotate_service_account_key,
        // Model Catalog
        routes::catalog::create_catalog_entry,
        routes::catalog::list_catalog,
        routes::catalog::get_catalog_entry,
        routes::catalog::update_catalog_entry,
        routes::catalog::delete_catalog_entry,
        routes::catalog::remove_all_seeded,
        routes::catalog::reset_catalog,
        // MCP catalog
        routes::mcp_catalog::list_mcp_catalog,
        routes::mcp_catalog::get_mcp_catalog_entry,
        routes::mcp_catalog::create_mcp_catalog_entry,
        routes::mcp_catalog::update_mcp_catalog_entry,
        routes::mcp_catalog::adopt_mcp_catalog_entry,
        routes::mcp_catalog::delete_mcp_catalog_entry,
        routes::mcp_catalog::reset_mcp_catalog,
        routes::mcp_catalog::list_oauth_provider_recipes,
        // Settings
        routes::settings::get_settings,
        routes::settings::update_settings,
        routes::settings::trigger_purge,
        routes::pricing::get_pricing_settings,
        routes::pricing::update_pricing_settings,
        routes::web::get_web_settings,
        routes::web::update_web_settings,
        routes::web::test_web,
        routes::guardrail::get_guardrail_settings,
        routes::guardrail::update_guardrail_settings,
        routes::settings::get_db_stats,
        routes::settings::wipe_audit_sessions,
        // Audit
        routes::audit::list_audit_logs,
        routes::audit::list_web_calls_for_request,
        routes::audit::get_media_blob,
        routes::audit::get_tool_definition_blob,
        routes::audit::get_trace,
        routes::audit::get_session,
        routes::audit::get_session_conversation,
        routes::audit::list_sessions,
        routes::audit::get_session_linked,
        // Platform runtime config
        routes::runtime_config::get_runtime_config,
        routes::runtime_config::patch_runtime_config,
        routes::egress::get_egress,
        routes::egress::patch_egress,
        // Appliance (Kairos VM only)
        routes::appliance::get_status,
        routes::appliance::get_updates,
        routes::appliance::get_job,
        routes::appliance::get_events,
        routes::appliance::get_rollback_plan,
        routes::appliance::get_backup_config,
        routes::appliance::put_backup_config,
        routes::appliance::get_backup_status,
        routes::appliance::get_backup_list,
        routes::appliance::action_restart,
        routes::appliance::action_shutdown,
        routes::appliance::action_upgrade,
        routes::appliance::action_rollback,
        routes::appliance::action_check_updates,
        routes::appliance::action_backup_run,
        routes::appliance::action_backup_test,
        routes::appliance::get_network,
        routes::appliance::put_network,
        routes::appliance::action_network_confirm,
        routes::appliance::action_network_revert,
        routes::appliance::action_network_reset,
        // Analytics
        routes::analytics::usage_summary,
        routes::analytics::usage_breakdown,
        routes::analytics::tool_inventory,
        routes::analytics::tool_calls,
        routes::analytics::transform_stats,
        routes::analytics::list_apps,
        routes::analytics::usage_timeseries,
        routes::analytics::users_keys_dashboard,
        routes::analytics::proxy_dashboard,
        routes::analytics::error_analytics,
        routes::analytics::media_analytics,
        routes::analytics::cache_analytics,
        routes::analytics::mcp_dashboard_by_resource,
        routes::analytics::mcp_dashboard_by_prompt,
        routes::analytics::mcp_dashboard_by_tool,
        routes::analytics::mcp_dashboard_by_endpoint,
        routes::analytics::mcp_dashboard_by_upstream,
        routes::analytics::mcp_dashboard_by_method,
        routes::analytics::mcp_dashboard_by_user,
        routes::analytics::mcp_dashboard_by_app,
        routes::analytics::mcp_dashboard_summary,
        routes::analytics::a2a_dashboard_summary,
        routes::analytics::a2a_dashboard_by_agent,
        routes::analytics::a2a_dashboard_by_method,
        routes::analytics::a2a_dashboard_by_task_state,
        routes::analytics::a2a_dashboard_by_user,
        routes::analytics::a2a_dashboard_by_app,
        routes::analytics::mcp_dashboard_timeseries,
        routes::analytics::mcp_dashboard_errors_by_method,
        routes::analytics::web_dashboard_summary,
        routes::analytics::web_dashboard_by_host,
        routes::analytics::web_dashboard_by_query,
        routes::analytics::web_dashboard_by_user,
        routes::analytics::cross_overview,
        routes::analytics::cross_timeseries,
        routes::analytics::cross_upstream_timeseries,
        routes::analytics::cross_attention,
        routes::server_analytics::server_fleet,
        routes::server_analytics::server_dashboard,
        routes::server_analytics::server_recent_load,
        routes::notifications_feed::list_notifications,
        routes::analytics::global_usage_summary,
        routes::analytics::global_edge_stats,
        // Transforms
        routes::transforms::create_program,
        routes::transforms::list_programs,
        routes::transforms::get_program,
        routes::transforms::update_program,
        routes::transforms::delete_program,
        routes::transforms::validate_program,
        routes::transforms::test_program,
        routes::transforms::list_suggestions,
        routes::transforms::approve_suggestion,
        routes::transforms::reject_suggestion,
        // Experts
        routes::transforms::list_experts,
        routes::transforms::create_expert,
        routes::transforms::update_expert,
        routes::transforms::delete_expert,
        routes::transforms::reset_expert,
        routes::transforms::get_expert_memory,
        routes::transforms::update_expert_memory,
        routes::transforms::agent_status,
        routes::transforms::trigger_agent_run,
        routes::transforms::get_agent_models,
        routes::transforms::expert_dashboard,
        routes::transforms::list_cross_session_issues,
        routes::transforms::list_prompt_snippets,
        routes::transforms::update_prompt_snippet,
        routes::transforms::restore_prompt_snippet,
        routes::transforms::list_tool_rule_suggestions,
        routes::transforms::approve_tool_rule_suggestion,
        routes::transforms::reject_tool_rule_suggestion,
        // Tool Risk Rules
        routes::tool_rules::list_tool_rules,
        routes::tool_rules::get_tool_rule,
        routes::tool_rules::create_tool_rule,
        routes::tool_rules::update_tool_rule,
        routes::tool_rules::delete_tool_rule,
        routes::tool_rules::reset_tool_rules,
        routes::tool_rules::test_tool_rule,
        routes::tool_rules::list_security_frameworks,
        routes::tool_rules::list_tool_rule_detectors,
        // Tool Field Profiles
        routes::tool_field_profiles::list_tool_field_profiles,
        routes::tool_field_profiles::get_tool_field_profile,
        routes::tool_field_profiles::create_tool_field_profile,
        routes::tool_field_profiles::update_tool_field_profile,
        routes::tool_field_profiles::delete_tool_field_profile,
        routes::tool_field_profiles::reset_tool_field_profiles,
        routes::tool_field_profiles::discover_tool_fields,
        routes::tool_field_profiles::list_field_profile_suggestions,
        routes::tool_field_profiles::approve_field_profile_suggestion,
        routes::tool_field_profiles::reject_field_profile_suggestion,
        routes::tool_field_profiles::list_tool_ids,
        routes::tool_field_profiles::list_resource_ids,
        routes::tool_field_profiles::list_prompt_ids,
        routes::tool_field_profiles::list_known_server_tool_types,
    ),
    components(schemas(
        // Edge protocol v2
        streamscope_edge_api::sync::SyncRequest,
        streamscope_edge_api::sync::SyncResponse,
        streamscope_edge_api::sync::Held,
        streamscope_edge_api::sync::Nack,
        streamscope_edge_api::sync::Resource,
        streamscope_edge_api::sync::Event,
        streamscope_edge_api::sync::ResourceName,
        streamscope_edge_api::digest::Digest,
        streamscope_edge_api::ingest::IngestRequest,
        streamscope_edge_api::ingest::IngestResponse,
        streamscope_edge_api::ingest::TenantShare,
        streamscope_edge_api::ingest::ShareOutcome,
        streamscope_edge_api::ingest::Content,
        streamscope_edge_api::ingest::Record,
        streamscope_edge_api::ingest::RowRef,
        streamscope_edge_api::ingest::InstanceState,
        streamscope_edge_api::replay::ReplayRequest,
        streamscope_edge_api::replay::ReplayResponse,
        streamscope_edge_api::replay::ReplayEvent,
        crate::edge_v2::status::EdgeSyncStatus,
        crate::edge_v2::status::EdgeInstanceSync,
        crate::edge_v2::status::TenantSyncStatus,
        crate::edge_v2::status::TenantEdgeSync,
        // Workspace types
        routes::workspaces::WorkspaceRole,
        routes::workspaces::WorkspaceSummary,
        routes::workspaces::Workspace,
        routes::workspaces::WorkspaceDetail,
        routes::workspaces::CreateWorkspaceRequest,
        routes::workspaces::UpdateWorkspaceRequest,
        routes::workspaces::MemberRow,
        routes::workspaces::AddMemberRequest,
        routes::workspaces::UpdateMemberRequest,
        routes::workspaces::WorkspaceProvider,
        routes::workspaces::AddProviderRequest,
        routes::workspaces::WorkspaceMcpServer,
        routes::workspaces::AddMcpServerRequest,
        routes::workspaces::WorkspaceA2aAgent,
        routes::workspaces::AddA2aAgentRequest,
        routes::workspaces::WorkspaceRateLimits,
        routes::workspaces::UserRateLimitOverride,
        routes::workspaces::PutRateLimitOverrideRequest,
        routes::workspaces::MemberLimitDefaults,
        routes::workspaces::WorkspaceLimitsOverview,
        limits::EffectiveLimitStack,
        limits::LimitLayer,
        limits::LimitMeter,
        limits::LimitBucket,
        routes::qos_classes::QosClass,
        routes::qos_classes::QosClassRow,
        routes::qos_classes::CreateQosClassRequest,
        routes::qos_classes::UpdateQosClassRequest,
        routes::qos_classes::SetMintDefaultRequest,
        routes::qos_classes::QosDeploymentLimits,
        routes::qos_classes::DeploymentMs,
        routes::upstream_endpoints::EngineProbe,
        routes::upstream_endpoints::EngineProbeResponse,
        routes::profiles::ProfileRow,
        routes::profiles::Profile,
        routes::profiles::CreateProfileRequest,
        routes::profiles::ProfileStartChoice,
        routes::profiles::StartContent,
        routes::profiles::UpdateProfileRequest,
        routes::workspaces::AssignedProfile,
        // User types
        routes::users::CreateUserRequest,
        routes::users::UpdateUserRequest,
        routes::users::UserResponse,
        routes::users::UserDetailResponse,
        routes::users::WorkspaceMembershipInfo,
        routes::users::UserUsageSummary,
        // Server types
        routes::upstreams::CreateServerRequest,
        routes::upstreams::PatchServerRequest,
        routes::upstreams::ServerResponse,
        routes::model_sync::AutoSyncStatus,
        routes::upstreams::ServerDetailResponse,
        routes::upstreams::ProviderMeta,
        // Model types
        routes::upstreams::CreateModelRequest,
        routes::upstreams::BatchCreateModelsRequest,
        routes::upstreams::ModelResponse,
        routes::upstreams::FieldSource,
        routes::upstreams::UpdateModelRequest,
        routes::upstreams::BatchDeleteRequest,
        // Model preset types
        routes::model_presets::PresetResponse,
        routes::model_presets::CreatePresetRequest,
        routes::model_presets::UpdatePresetRequest,
        // Model sync types
        routes::upstreams::DiscoveredModel,
        routes::upstreams::RemovedModelInfo,
        routes::upstreams::ModelSyncResponse,
        routes::upstreams::SyncNowResponse,
        routes::model_sync::EndpointSyncReport,
        routes::upstream_endpoints::EndpointResponse,
        routes::upstream_endpoints::EndpointMembership,
        routes::upstream_endpoints::EndpointDiscoveryStatus,
        routes::upstream_endpoints::EndpointHealth,
        routes::upstream_endpoints::EndpointHealthStatus,
        routes::upstream_endpoints::CreateEndpointRequest,
        routes::upstream_endpoints::PatchEndpointRequest,
        routes::upstream_endpoints::EndpointRemovalResponse,
        routes::upstream_endpoints::ReorderEndpointsRequest,
        routes::upstream_endpoints::DiscoverEndpointRequest,
        routes::upstream_endpoints::EndpointDiscoveryPreview,
        routes::upstream_endpoints::PreviewModel,
        routes::upstream_endpoints::PreviewModelStatus,
        routes::upstream_endpoints::ServerMembershipResponse,
        routes::upstream_endpoints::MembershipEndpoint,
        routes::upstream_endpoints::MembershipModel,
        routes::upstream_endpoints::MembershipCell,
        routes::upstream_endpoints::MembershipState,
        routes::upstreams::BulkUpdateModelsRequest,
        routes::upstreams::BulkUpdateModelsResponse,
        // Downstream provider types
        routes::downstream::CreateProviderRequest,
        routes::downstream::ProviderResponse,
        routes::downstream::GrantedWorkspace,
        routes::downstream::ProviderDetailResponse,
        // Route types
        routes::downstream::CreateRouteRequest,
        routes::downstream::BatchCreateRoutesRequest,
        routes::downstream::BatchCreateRoutesResponse,
        routes::downstream::UpdateRouteRequest,
        routes::downstream::ClientSlot,
        routes::downstream::RouteResponse,
        routes::downstream::MirrorSyncResult,
        routes::downstream::RouteCollisionsResponse,
        routes::downstream::AliasCollision,
        routes::downstream::CollisionTarget,
        // Route Policy types
        routes::cache_settings::UpdateCacheSettingsRequest,
        routes::cache_settings::ProbeEmbeddingRequest,
        routes::cache_settings::ProbeEmbeddingResponse,
        routes::cache_settings::EmbeddingProbeTarget,
        routes::cache_settings::EmbeddingAliasOption,
        streamscope_core::proxy::response_cache::CacheSettings,
        routes::cache_presets::CachePreset,
        routes::cache_presets::CreateCachePresetRequest,
        routes::cache_presets::UpdateCachePresetRequest,
        routes::ActionImpact,
        routes::route_policies::RoutePolicyRow,
        routes::route_policies::CreateRoutePolicy,
        routes::route_policies::UpdateRoutePolicy,
        // A2A gateway types
        routes::a2a::A2aAgentRow,
        routes::a2a::CreateA2aAgent,
        routes::a2a::UpdateA2aAgent,
        // MCP gateway types
        routes::mcp::McpUpstreamServerRow,
        routes::mcp::CreateMcpUpstreamServer,
        routes::mcp::UpdateMcpUpstreamServer,
        routes::mcp_discovery::DiscoverOauthRequest,
        routes::mcp_discovery::DiscoverOauthResponse,
        routes::mcp_discovery::RegisterOauthClientRequest,
        routes::mcp_discovery::RegisterOauthClientResponse,
        routes::mcp::McpVirtualServerRow,
        routes::mcp::CreateMcpVirtualServer,
        routes::mcp::UpdateMcpVirtualServer,
        routes::mcp::McpVirtualRouteRow,
        routes::mcp::CreateMcpVirtualRoute,
        routes::mcp::UpdateMcpVirtualRoute,
        routes::mcp::McpRouteFilterShape,
        // MCP spec OAuth types
        routes::mcp_oauth::OauthClientRow,
        routes::mcp_oauth::CimdClientRow,
        routes::mcp_oauth::RevokeCimdClientRequest,
        routes::mcp_oauth::CreateOauthClient,
        routes::mcp_oauth::UpdateOauthClient,
        routes::mcp_oauth::CreateOauthClientResponse,
        routes::mcp_oauth::IssuedTokenRow,
        routes::cli_oauth::CliSessionRow,
        routes::mcp_oauth::TokenStatusFilter,
        routes::mcp_oauth::TokenStatusBreakdown,
        routes::mcp_oauth::IssuedTokensListResponse,
        routes::mcp::McpUpstreamUserConnection,
        routes::mcp_oauth::AuthorizeRequest,
        routes::mcp_oauth::McpRevokeRequest,
        routes::mcp_oauth::AuthorizePreviewResponse,
        routes::oauth_common::AuthorizeApproveResponse,
        routes::oauth_common::TokenRequest,
        routes::oauth_common::TokenResponse,
        routes::mcp_oauth::DynamicRegistrationRequest,
        routes::mcp_oauth::DynamicRegistrationResponse,
        routes::cli_oauth::CliAuthorizeRequest,
        routes::cli_oauth::CliAuthorizePreviewResponse,
        routes::cli_oauth::CliRevokeRequest,
        routes::cli_oauth::DeviceAuthorizationRequest,
        routes::cli_oauth::DeviceAuthorizationResponse,
        routes::cli_oauth::DeviceConsentRequest,
        routes::cli_oauth::DeviceConsentPreviewResponse,
        routes::cli_dist::CliVersionResponse,
        routes::cli_dist::CliTargetInfo,
        // Portal provisioning bundle types
        routes::provision::ProvisionBundleRequest,
        routes::provision::ProvisionClientSelection,
        routes::provision::ProvisionBundleResponse,
        routes::provision::ProvisionClientBundle,
        routes::provision::BundleKey,
        // `streamscope_client_templates::Value` (the typed placeholder union)
        // is collected transitively through ProvisionClientBundle — listing
        // the recursive enum here directly trips a utoipa derive-codegen bug
        // (unparsable tokens), so it stays implicit.
        streamscope_mcp_auth::AuthorizationServerMetadata,
        streamscope_mcp_auth::ProtectedResourceMetadata,
        streamscope_mcp_auth::metadata::JsonWebKey,
        streamscope_mcp_auth::metadata::JsonWebKeySet,
        // Portal types
        routes::portal::PortalMeResponse,
        routes::portal::PortalUserDetail,
        routes::portal::PortalWorkspaceInfo,
        routes::portal::PortalProviderInfo,
        routes::portal::CreatePortalKeyRequest,
        routes::portal::CreatePortalKeyResponse,
        routes::portal::PortalKeyInfo,
        routes::portal::PortalStats,
        routes::portal_home::PortalHome,
        routes::portal_home::PortalExpiringKey,
        routes::portal_home::PortalSpendWindow,
        routes::portal_home::BudgetWindow,
        routes::portal_home::PortalLimitWarning,
        routes::portal_home::PortalHomeTeam,
        routes::portal_mcp::PortalMcpSignInNeeded,
        routes::portal::PortalKeyStats,
        routes::portal_manager::WorkspaceMemberInfo,
        routes::portal_manager::WorkspaceMemberUsage,
        routes::portal_manager::WorkspaceTeamStats,
        routes::portal_manager::MintForMemberRequest,
        routes::portal_manager::SetMemberKeyBudgetRequest,
        routes::portal_automation::WsAutomationAccount,
        routes::portal_automation::CreateWsAutomationAccountRequest,
        routes::portal_automation::WsAutomationKeyItem,
        routes::portal_automation::MintWsAutomationKeyRequest,
        routes::portal_automation::MintWsAutomationKeyResponse,
        routes::portal_mcp::PortalMcpVirtualServer,
        routes::portal::PortalFilterOption,
        routes::portal::PortalAuditFilterOptions,
        routes::portal_mcp_connections::PortalConnectionItem,
        routes::portal_mcp_connections::PortalConnectionVirtualServer,
        routes::portal_mcp_connections::PortalConnectionsList,
        routes::portal_mcp_connections::PortalConnectInitResponse,
        routes::portal_mcp_test::PortalMcpTestResponse,
        routes::portal_mcp_test::PortalMcpTestVirtualServer,
        routes::portal_mcp_test::PortalMcpTestRouteResult,
        routes::portal_mcp_test::PortalMcpTestEntry,
        routes::portal_mcp_test::PortalMcpTestResource,
        routes::portal_mcp_test::PortalMcpBuiltinStatus,
        // Portal Quickstart types
        routes::quickstart::ClientProfileSummary,
        routes::quickstart::ListClientsResponse,
        routes::quickstart::PortalRoute,
        routes::quickstart::RenderRequest,
        routes::quickstart::KeySpec,
        routes::quickstart::McpServerSelection,
        routes::quickstart::RenderedTemplate,
        routes::quickstart::MintedSecrets,
        routes::quickstart::MintedKey,
        routes::quickstart::RenderResponse,
        routes::quickstart::QuickstartKey,
        streamscope_client_templates::ClientProfile,
        streamscope_client_templates::ClientProfileTemplate,
        streamscope_client_templates::TemplateFormat,
        streamscope_client_templates::TemplateKind,
        streamscope_client_templates::McpAuthMode,
        streamscope_client_templates::CompanionTemplate,
        streamscope_client_templates::KeyDelivery,
        // Admin client-profiles types
        routes::client_profiles_admin::ClientProfileListResponse,
        routes::client_profiles_admin::PlaceholderRef,
        routes::client_profiles_admin::PlaceholderReference,
        routes::client_profiles_admin::PreviewedFile,
        routes::client_profiles_admin::PreviewedTemplate,
        routes::client_profiles_admin::ClientProfilePreview,
        // Portal Auth types
        routes::portal_auth::PortalLoginRequest,
        routes::portal_auth::PortalLoginResponse,
        routes::portal_auth::PortalUserResponse,
        // Edge Sync types
        crate::edge_nodes::CreateEdgeNodeRequest,
        crate::edge_nodes::UpdateEdgeNodeRequest,
        crate::edge_nodes::EdgeNodeMetadata,
        crate::edge_nodes::EdgeProxyStats,
        crate::edge_nodes::EdgeCacheStats,
        crate::edge_nodes::EdgeRuntimeReport,
        crate::edge_nodes::CreateEdgeNodeResponse,
        crate::edge_nodes::EdgeNodeResponse,
        // Admin-action audit types
        routes::admin_audit::AdminAuditRow,
        routes::admin_audit::GlobalAdminAuditRow,
        routes::admin_audit::PortalAuditRow,
        routes::admin_audit::SecurityAuditRow,
        routes::admin_audit::GlobalPortalAuditRow,
        // Admin Auth types
        routes::admin_auth::CreateAdminAccountRequest,
        routes::admin_auth::UpdateAdminAccountRequest,
        routes::admin_auth::AdminAccountResponse,
        routes::admin_auth::LoginRequest,
        routes::admin_auth::LoginResponse,
        routes::admin_auth::SetupRequest,
        routes::admin_auth::SetupResponse,
        routes::admin_auth::SetupStatusResponse,
        routes::admin_auth::MeResponse,
        routes::admin_auth::OidcExchangeRequest,
        // Tenant types
        routes::tenants::CreateTenantRequest,
        routes::tenants::UpdateTenantRequest,
        routes::tenants::TenantResponse,
        routes::tenants::TenantDetailResponse,
        routes::tenants::CreateInviteRequest,
        routes::tenants::InviteResponse,
        routes::tenants::InviteCreatedResponse,
        routes::tenants::InviteInfoResponse,
        routes::tenants::AcceptInviteRequest,
        routes::tenants::AcceptInviteResponse,
        // Auth Config types
        routes::auth_config::AuthConfigResponse,
        routes::auth_config::UpdateAuthConfigRequest,
        routes::auth_config::TenantAuthInfoResponse,
        routes::auth_config::OidcTestRequest,
        routes::auth_config::OidcTestResponse,
        routes::oidc_rp::BeginRequest,
        routes::oidc_rp::BeginResponse,
        routes::oidc_rp::CallbackRequest,
        routes::oidc_rp::CallbackResponse,
        routes::oidc_rp::EndSessionRequest,
        routes::oidc_rp::EndSessionResponse,
        // Internal platform-host callback types
        routes::internal_platform::PlatformPurgeRequest,
        routes::internal_platform::DiskPressureLevel,
        routes::internal_platform::PlatformPurgeResponse,
        // API Key types
        routes::keys::CreateKeyRequest,
        routes::keys::CreateKeyResponse,
        routes::keys::KeyBudget,
        routes::keys::KeyListItem,
        routes::keys::KeyUsageSummary,
        routes::keys::UpdateKeyRequest,
        // Service account types
        routes::service_accounts::CreateServiceAccountRequest,
        routes::service_accounts::ServiceAccountResponse,
        routes::service_accounts::ServiceAccountListItem,
        routes::service_accounts::ServiceAccountDetail,
        routes::service_accounts::ServiceAccountKeyItem,
        routes::service_accounts::MintServiceAccountKeyRequest,
        routes::service_accounts::MintServiceAccountKeyResponse,
        routes::service_accounts::RotateInlineAiKeyResponse,
        // Catalog types
        routes::catalog::CatalogEntry,
        routes::catalog::CatalogInput,
        routes::catalog::UpdateCatalogEntry,
        routes::catalog::CatalogBulkResult,
        routes::mcp_catalog::McpCatalogEntry,
        routes::mcp_catalog::McpCatalogToolSchema,
        routes::mcp_catalog::CreateMcpCatalogEntry,
        routes::mcp_catalog::UpdateMcpCatalogEntry,
        routes::mcp_catalog::AdoptCatalogEntry,
        routes::mcp_catalog::AdoptResult,
        routes::mcp_catalog::OauthProviderRecipesResponse,
        seed_loader::OauthProviderRecipe,
        seed_loader::OauthProviderField,
        seed_loader::OauthFieldValue,
        // Settings types — TenantSettings is the typed GET/PUT wire shape
        routes::settings::DbStatsResponse,
        routes::settings::TableStats,
        routes::settings::ContentDedupStats,
        routes::settings::PurgeResponse,
        routes::settings::WipeResponse,
        routes::settings::MediaDedupStats,
        routes::settings::ToolsDedupStats,
        crate::retention::PurgeSummary,
        // Audit types — typed shapes for the former Value fields
        routes::audit::ResponseFormat,
        conversation::ConversationEvent,
        conversation::ToolsChangeKind,
        conversation::DetectedSpawnPoint,
        routes::audit::ToolDefinitionBlobResponse,
        conversation::TurnMetadata,
        routes::audit::AuditLogEntry,
        routes::audit::AuditLogRow,
        routes::audit::AuditKind,
        routes::audit::McpAuditLogEntry,
        routes::audit::WebAuditLogEntry,
        routes::audit::A2aAuditLogEntry,
        streamscope_core::web::audit::WebProviderResponse,
        streamscope_core::web::audit::StrippedProviderResponse,
        routes::audit::McpTransformDiff,
        routes::audit::A2aTransformDiff,
        streamscope_core::api::domain_request::DomainContentBlock,
        conversation::A2aArtifactView,
        routes::audit::McpPolicyClassification,
        routes::audit::McpStreamSummary,
        routes::audit::McpServerInitiated,
        routes::audit::McpListChanged,
        routes::audit::McpElicitationComplete,
        routes::audit::McpSamplingInterceptOutcome,
        streamscope_core::audit::ChatMediaSummaryEntry,
        streamscope_core::audit::BlobType,
        streamscope_core::audit::AuditBadge,
        streamscope_core::audit::Phase,
        streamscope_core::audit::BlockKind,
        streamscope_core::audit::GuardrailAction,
        streamscope_core::guardrail::GuardrailCategory,
        streamscope_core::api::sse::ApiVersion,
        streamscope_core::api::domain_request::DomainRequestMeta,
        streamscope_core::api::domain_request::DomainToolSummary,
        routes::audit::TurnParams,
        streamscope_core::proxy::content::TransformDiff,
        streamscope_core::proxy::content::SyntheticSourceTag,
        streamscope_core::proxy::content::TransformStepDiff,
        streamscope_core::proxy::content::TransformProgramRef,
        streamscope_core::proxy::content::TransformProgramOutcome,
        streamscope_core::proxy::content::BlockedToolInfo,
        streamscope_core::proxy::content::InterceptBinding,
        streamscope_core::proxy::content::RedactedToolResultInfo,
        streamscope_core::proxy::content::GuardrailStepDiff,
        streamscope_core::proxy::content::GuardrailStepOutcome,
        streamscope_core::proxy::content::InjectionBlock,
        streamscope_core::proxy::content::InterceptedToolCall,
        streamscope_core::proxy::content::ToolArgModification,
        streamscope_core::api::domain_request::DroppedTelemetry,
        conversation::ToolCallBlock,
        conversation::InterceptionInfo,
        // Analytics types
        routes::analytics::MediaAnalyticsResponse,
        routes::analytics::MediaDirectionStat,
        routes::analytics::MediaUserStat,
        routes::analytics::CacheAnalyticsResponse,
        routes::analytics::CacheAliasStat,
        routes::analytics::CacheSavings,
        routes::analytics::CacheAliasSavings,
        routes::analytics::CacheSkipStat,
        routes::analytics::ToolInvocation,
        routes::analytics::ToolCallRow,
        routes::analytics::ToolCallKind,
        routes::analytics::BreakdownBy,
        routes::analytics::ToolEntry,
        routes::analytics::ToolSummary,
        routes::analytics::ToolInventoryResponse,
        routes::analytics::ProfileCoverage,
        routes::analytics::UnprofiledTool,
        routes::analytics::McpInvocationCount,
        routes::analytics::McpDashboardPanel,
        routes::analytics::A2aDashboardSummary,
        routes::analytics::A2aDashboardPanel,
        routes::analytics::A2aBreakdownItem,
        routes::analytics::DashboardSortBy,
        routes::analytics::McpDashboardSummary,
        routes::analytics::McpDashboardSummaryPrevious,
        routes::analytics::McpTimeseriesBucket,
        routes::analytics::McpTimeseriesResponse,
        routes::analytics::McpErrorsByMethodRow,
        routes::analytics::McpErrorsByMethodResponse,
        routes::analytics::WebDashboardSummary,
        routes::analytics::WebDashboardPanel,
        routes::analytics::WebDashboardItem,
        // Cross-protocol Dashboard Overview types
        routes::analytics::CrossOverview,
        routes::analytics::CrossTimeseriesBucket,
        routes::analytics::CrossTimeseriesResponse,
        routes::analytics::UpstreamTimeseriesKind,
        routes::analytics::UpstreamSparkline,
        routes::analytics::UpstreamTimeseriesResponse,
        routes::analytics::AttentionAlerts,
        routes::analytics::AttentionBlocked,
        routes::analytics::AttentionGuardrail,
        routes::analytics::AttentionExpiring,
        routes::analytics::AttentionErrors,
        routes::analytics::AttentionBudget,
        routes::analytics::AttentionResponse,
        routes::analytics::AttentionUpstreams,
        routes::server_analytics::ServerTraffic,
        routes::server_analytics::ServerLive,
        routes::server_analytics::EndpointLive,
        routes::server_analytics::EngineLive,
        routes::server_analytics::AdaptiveLive,
        streamscope_core::proxy::adaptive_concurrency::AdaptiveState,
        routes::server_analytics::ServerFleetEntry,
        routes::server_analytics::ServerFleetResponse,
        routes::server_analytics::RefusalCount,
        routes::server_analytics::ServerEndpointEntry,
        routes::server_analytics::ServerClassEntry,
        routes::server_analytics::ServerWaiter,
        routes::server_analytics::EndpointLoadSeries,
        routes::server_analytics::EndpointGaugeSeries,
        routes::server_analytics::ServerRecentLoadResponse,
        routes::server_analytics::EndpointLiveEntry,
        routes::server_analytics::ServerDashboardResponse,
        routes::upstream_endpoints::ServerHealth,
        routes::notifications_feed::NotificationItem,
        // Transform response types
        routes::transforms::ProgramResponse,
        routes::transforms::CreateProgramResponse,
        routes::transforms::StatusMessageResponse,
        routes::transforms::ValidateProgramResponse,
        routes::transforms::TestProgramResponse,
        routes::transforms::SuggestionResponse,
        routes::transforms::ToolRuleSuggestionResponse,
        routes::transforms::ApproveSuggestionRequest,
        routes::transforms::ApproveToolRuleSuggestionRequest,
        // Expert response types
        routes::transforms::ExpertResponse,
        routes::transforms::CreateExpertResponse,
        routes::transforms::ExpertMemoryResponse,
        routes::transforms::AgentStatusResponse,
        routes::transforms::AgentModelEntry,
        routes::transforms::AgentModelTarget,
        routes::transforms::AgentModelsResponse,
        routes::transforms::AlertCounts,
        routes::transforms::SuggestionCounts,
        routes::transforms::ExpertDashboardEntry,
        routes::transforms::RecentSuggestion,
        routes::transforms::AgentMetrics,
        routes::transforms::ExpertDashboardResponse,
        routes::transforms::CrossSessionIssue,
        routes::transforms::PromptSnippet,
        // Changelog types
        routes::changelog::ChangelogResponse,
        // Key lifecycle types
        routes::key_lifecycle::ImpactCheck,
        routes::key_lifecycle::MutationResult,
        routes::key_lifecycle::DeletionResponse,
        // Error types
        routes::ApiErrorResponse,
        routes::ApiErrorBody,
        routes::ApiErrorCode,
        // Shared response envelopes
        routes::ActionResponse,
        // Money in an aggregate, with the currency it is stated in
        routes::SpendTotal,
        routes::SpendBreakdown,
        routes::SpendUnit,
        // Shared query filter structs
        // (IntoParams structs are inlined per-endpoint, not registered under components.)
        // Typed TenantSettings + its structured sub-objects
        routes::settings::TenantSettings,
        routes::settings::InheritedDefaults,
        routes::settings::GetSettingsResponse,
        routes::settings::ToolRulesConfig,
        // Platform runtime config
        routes::runtime_config::RuntimeConfigResponse,
        routes::runtime_config::EdgeRuntimeStatus,
        routes::runtime_config::UpdateRuntimeConfigRequest,
        routes::egress::EgressSettings,
        routes::egress::UpdateEgressSettings,
        // Appliance (Kairos VM only)
        routes::appliance::HostVersion,
        routes::appliance::ApplianceStatus,
        routes::appliance::ApplianceDisk,
        routes::appliance::ApplianceDiskPressure,
        routes::appliance::ApplianceFailedBoot,
        routes::appliance::ApplianceUpdates,
        routes::appliance::ApplianceJob,
        routes::appliance::ApplianceEvent,
        routes::appliance::ApplianceEvents,
        routes::appliance::ApplianceEventReboot,
        routes::appliance::ApplianceRollbackPlan,
        routes::appliance::RollbackRequest,
        routes::appliance::BackupConfig,
        routes::appliance::RcloneConfigFrom,
        routes::appliance::BackupConfigUpdate,
        routes::appliance::BackupStatus,
        routes::appliance::BackupRun,
        routes::appliance::BackupObject,
        routes::appliance::BackupRunRequest,
        routes::appliance::DrainBody,
        routes::appliance::UpgradeRequest,
        routes::appliance::ApplianceNetwork,
        routes::appliance::ApplianceNetworkLive,
        routes::appliance::ApplianceNetworkConfig,
        routes::appliance::ApplianceNetworkUpdate,
        routes::appliance::ApplianceNetworkApplied,
        routes::appliance::ApplianceNetworkPending,
        routes::appliance::ApplianceNetworkSource,
        routes::appliance::ApplianceNetworkMode,
        streamscope_core::settings_catalog::SettingDescriptor,
        streamscope_core::settings_catalog::SettingGroup,
        streamscope_core::settings_catalog::SettingKind,
        // Web admin surface
        routes::pricing::PricingSettingsResponse,
        routes::pricing::UpdatePricingSettingsRequest,
        streamscope_core::pricing::Rates,
        streamscope_core::pricing::Rate,
        streamscope_core::pricing::Tier,
        streamscope_core::pricing::BilledUnit,
        streamscope_core::pricing::PricingSettings,
        routes::web::WebSettingsResponse,
        routes::web::UpdateWebSettingsRequest,
        routes::web::WebTestRequest,
        routes::web::WebTestResponse,
        streamscope_core::web::WebSettings,
        streamscope_core::web::FetchProvider,
        streamscope_core::web::WebProvider,
        // Guardrail admin surface — tenant-wide backend + per-profile policy
        routes::guardrail::GuardrailBackendResponse,
        routes::guardrail::UpdateGuardrailBackendRequest,
        routes::guardrail::GuardrailPolicyResponse,
        routes::guardrail::UpdateGuardrailPolicyRequest,
        routes::expert_profiles::ExpertMembershipResponse,
        routes::expert_profiles::UpdateExpertMembershipRequest,
        routes::client_access_profiles::ClientAccessResponse,
        routes::client_access_profiles::ClientAccessClient,
        routes::client_access_profiles::AttachedDestinationList,
        routes::client_access_profiles::DestinationAttachment,
        routes::client_access_profiles::SandboxSettings,
        routes::client_access_profiles::SandboxSettingsPatch,
        routes::client_access_profiles::SandboxPolicy,
        routes::client_access_profiles::WorkspaceClientAccess,
        routes::client_access_profiles::UpdateClientAccessRequest,
        routes::destination_lists::DestinationList,
        routes::destination_lists::DestinationListUse,
        routes::destination_lists::DestinationMode,
        routes::destination_lists::DestinationConsumer,
        routes::destination_lists::CreateDestinationListRequest,
        routes::destination_lists::UpdateDestinationListRequest,
        routes::guardrail::PiiSettingsUpdate,
        streamscope_core::guardrail::GuardrailBackendSettings,
        streamscope_core::guardrail::GuardrailPolicy,
        streamscope_core::guardrail::PiiSettings,
        streamscope_core::guardrail::GuardrailMode,
        streamscope_core::guardrail::GuardrailFailMode,
        streamscope_core::guardrail::ClassifierProtocol,
        streamscope_core::web::SearchHit,
        streamscope_core::web::SearchResult,
        // The unified risk-rule types — one schema definition shared by the
        // proxy enforcement engine, admin CRUD, and the JSONB at rest.
        routes::analytics::ToolRule,
        streamscope_core::config::tool_rules::MatchCondition,
        streamscope_core::config::tool_rules::RuleAction,
        streamscope_core::config::tool_rules::ToolDefValue,
        streamscope_core::config::tool_rules::InterceptKind,
        streamscope_core::config::tool_rules::WebInterceptKind,
        streamscope_core::config::tool_rules::Op,
        streamscope_core::config::tool_rules::Phase,
        streamscope_core::config::tool_rules::Scope,
        streamscope_core::config::tool_rules::ActionKind,
        routes::SourceFilter,
        routes::tool_rules::ToolRuleView,
        routes::analytics::ToolRiskFilter,
        routes::analytics::ToolCallOutcome,
        routes::audit::SessionLinkage,
        routes::audit::SessionSort,
        routes::analytics::AppInfo,
        // Tool Risk Rules request/response types
        routes::tool_rules::CreateToolRule,
        routes::tool_rules::UpdateToolRule,
        routes::tool_rules::ToolRuleListItem,
        routes::tool_rules::RuleActivity,
        routes::tool_rules::TestToolRule,
        routes::tool_rules::TestToolRuleResponse,
        routes::tool_rules::TestMatch,
        routes::tool_rules::SecurityFrameworksResponse,
        routes::tool_rules::ToolRuleDetector,
        routes::tool_rules::ToolRuleDetectorsResponse,
        seed_loader::SecurityFramework,
        // Tool Field Profile request/response types
        routes::tool_field_profiles::CreateFieldProfile,
        routes::tool_field_profiles::UpdateFieldProfile,
        routes::tool_field_profiles::DiscoveredField,
        routes::tool_field_profiles::DiscoverResponse,
        routes::tool_field_profiles::FieldProfileSuggestionResponse,
        routes::tool_field_profiles::ToolIdsResponse,
        routes::tool_field_profiles::KnownServerToolTypesResponse,
        streamscope_core::config::tool_rules::FieldProfile,
        streamscope_core::config::tool_rules::KnownServerToolType,
        streamscope_core::config::tool_rules_normalize::Normalizer,
        seed_loader::ToolIdEntry,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Users", description = "User CRUD, status management, usage tracking, and rate limits"),
        (name = "Servers", description = "Upstream server management and model discovery"),
        (name = "Models", description = "Upstream model CRUD and batch operations"),
        (name = "Downstream Providers", description = "Downstream provider management"),
        (name = "Routes", description = "Downstream route management and model alias mapping"),
        (name = "Route Policies", description = "Per-downstream path-level controls for catch-all proxy forwarding"),
        (name = "Tool Risk Rules", description = "Per-tenant tool risk classification and enforcement rules"),
        (name = "Tool Field Profiles", description = "Per-(tool, field) normaliser registry — drives canonical matching for tool risk rules"),
        (name = "Portal", description = "User self-service portal — personal key management, groups, and usage stats"),
        (name = "Portal Auth", description = "Portal authentication — login and header-mode SSO"),
        (name = "Edge Nodes", description = "Edge node registration, sync, and log retrieval"),
        (name = "Config Sync", description = "Configuration sync status across edge nodes"),
        (name = "Admin Accounts", description = "Admin account CRUD — create, list, update, and deactivate admin accounts"),
        (name = "Authentication", description = "Login, setup wizard, session info, and OIDC exchange"),
        (name = "Tenants", description = "Tenant CRUD — create, list, update, delete tenants (super-admin only)"),
        (name = "Invites", description = "Tenant invite management — create, list, revoke, and accept invites"),
        (name = "Auth Config", description = "OIDC and authentication configuration per tenant"),
        (name = "API Keys", description = "Virtual API key lifecycle — create, list, revoke, usage stats"),
        (name = "Model Catalog", description = "Model catalog entries for standardized model metadata"),
        (name = "MCP Catalog", description = "Curated catalog of remote MCP servers to browse and adopt"),
        (name = "Settings", description = "Tenant settings, database stats, and data management"),
        (name = "User Groups", description = "Group CRUD, membership, and downstream access control"),
        (name = "Audit", description = "Audit log queries, traces, and data export"),
        (name = "Sessions", description = "Session tracking, conversation replay, and linked sessions"),
        (name = "Analytics", description = "Usage analytics, breakdowns, tool inventory, and dashboards"),
        (name = "Transforms", description = "Request/response transform programs and suggestions"),
        (name = "Experts", description = "Expert system management, agent control, and dashboards"),
        (name = "Changelog", description = "Version changelog — per-admin 'What's New' notification"),
    )
)]
struct ApiDoc;

/// The spec `/api/docs` serves: [`ApiDoc`] minus the routes this deployment
/// does not mount, so a switched-off surface is absent from the spec as it is
/// from the router.
fn published_api_doc() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    if !crate::settings::admin_settings().allow_oidc_claim_exchange {
        doc.paths.paths.remove("/api/v1/auth/oidc-exchange");
    }
    doc
}

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer,
                ),
            ),
        );
    }
}

fn main() -> anyhow::Result<()> {
    // `--print-openapi` prints the whole API document — every route, whether
    // or not a deployment mounts it, unlike the one `/api/docs` serves — and
    // exits before anything reads the environment.
    if std::env::args().nth(1).as_deref() == Some("--print-openapi") {
        println!("{}", ApiDoc::openapi().to_json()?);
        return Ok(());
    }
    // Size the Tokio runtime canonically (cgroup-aware in K8s; on a shared host
    // the control plane caps itself small so it neither starves nor is starved by
    // the data plane + postgres). Built before tracing exists, so the chosen size
    // is logged inside `run()`.
    streamscope_core::runtime::build_runtime(streamscope_core::runtime::Role::ControlPlane)?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    // Pre-boot setup that must succeed before anything else — including the
    // degraded-mode fallback (which uses `tracing` to log its reason). If
    // these fail the process exits and Docker restarts; no fallback is
    // possible because we have no way to surface the failure.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("streamscope_admin=info".parse()?))
        .json()
        .init();
    streamscope_core::observability::install_panic_logger();
    tracing::info!(version = streamscope_core::VERSION, "starting streamscopeai-admin");
    streamscope_core::runtime::log_sizing(streamscope_core::runtime::Role::ControlPlane);
    crate::settings::admin_settings().log_non_defaults();

    // Wrap the bring-up sequence so a failure with Postgres REACHABLE (migration
    // error, pool init, RLS pre-flight, listener bind, …) routes to degraded mode
    // instead of crash-storming against a sick database — every `?`-bail and
    // explicit `anyhow!` from here surfaces as a structured 503 + MigrationFailed.
    // Startup connectivity is the exception: `connect_with_retry` (both the
    // migration and runtime app-role pools) retries and then exits non-zero (a
    // restart, not degraded mode, is what fixes an unreachable Postgres), so it
    // never reaches this guard.
    if let Err(e) = bring_up().await {
        return run_degraded_mode(format!("admin-api boot failed: {e:#}")).await;
    }
    Ok(())
}

/// Establish a startup Postgres pool, retrying with bounded backoff.
///
/// Kubernetes starts pods in parallel (no `depends_on`) and CoreDNS may still be
/// warming, so Postgres can be unreachable the instant admin-api boots — and not
/// only for the migration pool: the runtime app-role pool connects a moment later
/// and hits the same window (a transient DNS/connect blip after migrations have
/// already applied). A restart fixes connectivity, but degraded mode keeps
/// liveness (`/health`) at 200, so the orchestrator would never restart a
/// connectivity-wedged pod. Every startup pool connect therefore goes through
/// here: retry so a slow or parallel Postgres start self-heals, and if it's still
/// unreachable after the deadline, exit non-zero so the orchestrator restarts us
/// (CrashLoopBackOff self-heals once Postgres is up). Reserve degraded mode for a
/// genuine migration/script error — Postgres reachable, the work failed — where a
/// restart would not help. `connect` is retried on every attempt, so it must
/// re-establish a fresh pool each call.
pub(crate) async fn connect_with_retry<F, Fut, P>(label: &str, mut connect: F) -> P
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<P, sqlx::Error>>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut attempt = 0u32;
    loop {
        match connect().await {
            Ok(pool) => return pool,
            Err(e) => {
                attempt += 1;
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        "postgres ({label}) unreachable at startup after {attempt} attempts (~90s): {e} \
                         — exiting for orchestrator restart"
                    );
                    std::process::exit(1);
                }
                tracing::warn!(
                    "postgres ({label}) not reachable yet (attempt {attempt}): {e} — retrying in 2s"
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}

async fn bring_up() -> anyhow::Result<()> {
    // Require encryption key at startup — refuse to start without it.
    streamscope_core::crypto::require_encryption_key()
        .map_err(|msg| anyhow::anyhow!(msg))?;

    // AUTH_SECRET is required at startup. Mirrors ENCRYPTION_KEY: a missing
    // or too-short secret means JWT signing is broken or insecure, and every
    // login / portal / MCP-OAuth path returns 503 — there is no safe degraded
    // mode worth running in. Fail fast so operators see the misconfiguration
    // at boot instead of in production traffic. The optional
    // AUTH_SECRET_SECONDARY is held to the same floor by the same validator.
    let generation = streamscope_mcp_auth::keys::validate_env_secrets()
        .map_err(|msg| anyhow::anyhow!(msg))?;
    // Log the whole ring, not just the signer: the set is what gets published to
    // the proxies as verification keys, so it — not the active id alone — is
    // what an operator compares across replicas to confirm a rotation landed.
    let ring_signature = streamscope_mcp_auth::Keyring::from_env()
        .map(|r| r.generation_signature())
        .unwrap_or_else(|| generation.clone());
    tracing::info!(
        jwt_generation = %generation,
        jwt_generations = %ring_signature,
        "JWT signing key generation"
    );

    db::migrations::migrate().await?;

    // Connect as application role (subject to RLS — not superuser). Same bounded
    // retry as the migration pool: this connect lands one CoreDNS-warmup window
    // later, and a transient failure here must trigger a restart, not wedge the
    // pod in degraded mode (a connectivity error a restart would fix).
    let db = connect_with_retry("runtime app-role pool", db::create_pool).await;
    // The runtime pool's server and database pass the version and locale
    // check, and the runtime role reaches the special roles only by SET ROLE;
    // a grant that lets it inherit one would read across tenants without asking.
    db.check_roles().await?;

    // Load the custom CA bundle (super-admin `CUSTOM_CA_BUNDLE_PEM` platform
    // override, env fallback) so every admin outbound HTTPS client trusts it.
    // Refreshed in-process on each runtime-config write — no restart needed.
    custom_ca::refresh_from_db(&db).await;
    // The internal-egress allowlists every admin outbound call reads; kept
    // fresh by `egress::spawn_refresh` below.
    let _ = egress::refresh(&db).await;

    // One-shot bootstrap seed: populate any missing SYSTEM-tenant
    // public-URL rows from `BOOTSTRAP_*_PUBLIC_URL` env vars. Idempotent —
    // operator-set values are never overwritten on subsequent boots.
    if let Err(e) = tenant_public_url::run_bootstrap_seed(&db).await {
        tracing::warn!("public-URL bootstrap seed failed: {e}");
    }

    // Create the current + next weekly partitions BEFORE the HTTP server
    // accepts traffic. PG routes any insert that doesn't match a child range
    // into `_default`, and once a default partition has rows in the current
    // week's range, `CREATE TABLE … PARTITION OF … FOR VALUES FROM (this week)
    // TO (next week)` is rejected for the rest of the week. Without this eager
    // call the first batch of traffic (demo seeding, real users hitting the
    // proxy on a fresh deploy) populates `_default` for the current week before
    // the background retention worker fires its first cycle 60s later, and the
    // current week's partition can never be added.
    //
    // MUST run as the runtime app role (`db`), not the migration role:
    // PostgreSQL stamps the executor as the partition's owner, and the
    // retention worker (also app role) can only DROP partitions it owns. The
    // migration sets `ALTER TABLE … OWNER TO streamscope_app` on the parent
    // tables, so child partitions created here inherit the right owner.
    if let Err(e) = retention::ensure_future_partitions(&db).await {
        tracing::warn!("eager partition creation at startup failed: {e}");
    }
    if let Err(e) = retention::ensure_future_sse_event_partitions(&db).await {
        tracing::warn!("eager hourly SSE-event partition creation at startup failed: {e}");
    }


    // Auto-provision edge node when EDGE_TOKEN is set (for local/docker-compose deployments).
    if let Ok(edge_token) = std::env::var("EDGE_TOKEN")
        && !edge_token.is_empty()
    {
        auto_provision_edge_node(&db, &edge_token).await;
    }

    // Log auth mode.
    let current_auth_mode = routes::admin_auth::auth_mode();
    tracing::info!(?current_auth_mode, "authentication mode");
    if current_auth_mode == routes::admin_auth::AuthMode::Header {
        // Refuse to start rather than warn. In header mode `GET /api/v1/auth/me`
        // returns a console session for whatever address an `X-Auth-Request-*`
        // header names, with no credential — correct when a proxy in front has
        // already authenticated the request, and a full tenant compromise when
        // one has not. This process is published on its own vhost on every
        // deploy shape, so "there is a proxy in front" is not something it can
        // observe; it is something the operator has to state.
        //
        // A warning was what stood here, and a warning is not a control: the
        // chart makes header mode a one-line change, ships no ingress
        // authentication with it, and nothing between those two facts ever
        // stops. Naming the proxy is cheap for a deployment that has one and
        // impossible to satisfy accidentally for a deployment that does not.
        let trusted_proxy = crate::settings::admin_settings()
            .header_auth_trusted_proxy
            .trim()
            .to_string();
        if trusted_proxy.is_empty() {
            anyhow::bail!(
                "FATAL: AUTH_MODE=header requires HEADER_AUTH_TRUSTED_PROXY. \
                 In header mode this API accepts an identity header as proof of who \
                 the caller is, so anything that can reach it can sign in as any \
                 existing account. Set HEADER_AUTH_TRUSTED_PROXY to the reverse proxy \
                 that authenticates your users (e.g. 'authelia'), which asserts this \
                 API is reachable only through it — and make sure that is true for \
                 the API vhost as well as the console. To sign users in without a \
                 front proxy, use AUTH_MODE=standard with OIDC instead."
            );
        }
        tracing::warn!(
            trusted_proxy = %trusted_proxy,
            "AUTH_MODE=header — identity comes from X-Auth-Request-* headers. \
             Every route on this port, including the API vhost, MUST be reachable \
             only through the named proxy."
        );
    }

    let instance_id = uuid::Uuid::new_v4();
    tracing::info!(%instance_id, "admin-api instance starting");

    // Root cancellation token. The `graceful` shutdown future cancels it on
    // SIGTERM/SIGINT; every background worker holds a child token and unwinds at its next iteration boundary.
    let root_token = tokio_util::sync::CancellationToken::new();

    let state = Arc::new(AdminState {
        db,
        instance_id,
        login_rate_limiter: {
            let s = crate::settings::admin_settings();
            RateLimiter::per_instance(s.rate_limit_login_max, s.rate_limit_window_secs, s.rate_limit_cleanup_threshold(), s.rate_limit_instance_count)
        },
        invite_rate_limiter: {
            let s = crate::settings::admin_settings();
            RateLimiter::per_instance(s.rate_limit_invite_max(), s.rate_limit_window_secs, s.rate_limit_cleanup_threshold(), s.rate_limit_instance_count)
        },
        pre_auth_ip_rate_limiter: {
            let s = crate::settings::admin_settings();
            RateLimiter::per_instance(s.pre_auth_ip_rate_limit_max, s.rate_limit_window_secs, PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD, s.rate_limit_instance_count)
        },
        automation_key_rate_limiter: {
            let s = crate::settings::admin_settings();
            RateLimiter::per_instance(s.automation_key_rate_limit_max, s.rate_limit_window_secs, PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD, s.rate_limit_instance_count)
        },
        automation_key_ip_rate_limiter: {
            let s = crate::settings::admin_settings();
            crate::middleware::DistinctKeyFailures::new(s.automation_key_ip_rate_limit_max, s.rate_limit_window_secs, PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD, s.rate_limit_instance_count)
        },
        http_client: streamscope_core::tls::add_custom_roots(
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)),
            custom_ca::current().as_deref(),
        )
        .build()
        .expect("build admin http client"),
        cors_allowlist: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
    });

    // Initial CORS allowlist build before the HTTP server starts. Picks up
    // the SYSTEM-default `admin_public_url` (seeded by Path-A bootstrap
    // env or a prior operator save) plus any tenant overrides.
    let cors_known = match advance_cors_origins(&state.db, None, false).await {
        Ok((head, origins, _)) => {
            state.cors_allowlist.store(Arc::new(origins.allowlist()));
            Some((head, origins))
        }
        Err((e, _)) => {
            tracing::warn!("initial CORS allowlist build failed: {e}");
            None
        }
    };

    // Background workers. Each holds a child of `root_token` and exits at its
    // next iteration boundary when the token is cancelled; `main()` awaits all
    // handles after the HTTP server drains.
    let mut worker_handles: Vec<(&'static str, tokio::task::JoinHandle<()>)> = Vec::new();

    // Sync seed data for all existing tenants (merge updates from seeds/).
    //
    // Runs as a worker, NOT inline: its cost scales with tenant count, and
    // awaiting it here would hold the HTTP listener unbound for that whole
    // time — the process is not merely un-ready but unreachable, so an
    // orchestrator's startup probe eventually kills the pod and the restart
    // repeats the same work, never converging. It is safe to defer because a
    // tenant is seeded when it is created; this pass only refreshes builtin
    // rows from newer seed files, and the change triggers carry the refresh to
    // the edges.
    //
    // Leader-elected: the pass writes shared state (every tenant's builtin rows)
    // and is byte-identical on every instance, so N replicas would rewrite all
    // tenants N times and contend on the same rows — simultaneously, since a
    // rolling upgrade boots every replica at once and a new build invalidates
    // every tenant's seed stamp. A non-leader has nothing to do: the leader's
    // writes are shared, and an unstamped tenant is retried on the next boot.
    {
        let db = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push((
            "seed_sync",
            tokio::spawn(async move {
                // Wait for the lock rather than giving up on the first miss.
                // This worker runs ONCE at startup instead of on a cadence, so
                // it cannot rely on the next tick the way the other
                // leader-elected workers do, and `try_acquire_leader` returns
                // `None` for a *failed* acquire as well as a held lock: a
                // one-shot skip would silently drop the whole reconcile for the
                // process lifetime on a transient DB error — with no sibling to
                // pick it up on the N=1 appliance. Waiting also covers a leader
                // that dies mid-pass (its connection closes, the lock frees, a
                // waiter finishes the job). The wait costs almost nothing: once
                // the holder has stamped every tenant, the pass a waiter
                // eventually runs is a no-op.
                const RETRY_EVERY: std::time::Duration = std::time::Duration::from_secs(15);
                const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
                let waiting_since = std::time::Instant::now();
                loop {
                    if let Some(leader_conn) =
                        leader::try_acquire_leader(&db, leader::LOCK_SEED_SYNC).await
                    {
                        tokio::select! {
                            _ = async {
                                seed_scripts::sync_all_tenants(&db).await;
                                // Sequenced after the reconcile, not merely
                                // alongside it: the agent key is issued into the
                                // tenant's Agent workspace, which the reconcile
                                // backfills for a tenant that pre-dates it, and
                                // provisioning has no later retry pass.
                                agent::provision_agent_account(&db).await;
                            } => {}
                            _ = token.cancelled() => {
                                tracing::info!("seed sync interrupted by shutdown");
                            }
                        }
                        // Released on BOTH paths — completion and shutdown — so
                        // the lock is freed at once, not when the pool resets the
                        // returned connection.
                        leader::release_leader(leader_conn, leader::LOCK_SEED_SYNC).await;
                        return;
                    }
                    if waiting_since.elapsed() >= MAX_WAIT {
                        tracing::error!(
                            "seed sync: no leader lock after {}s — builtin content is NOT refreshed \
                             this boot; it retries on the next restart",
                            MAX_WAIT.as_secs()
                        );
                        return;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(RETRY_EVERY) => {}
                        _ = token.cancelled() => return,
                    }
                }
            }),
        ));
    }

    // Agent worker. Self-governs based on DB config (agent_enabled setting) and
    // tolerates a key the seed worker has not issued yet.
    worker_handles.push((
        "agent",
        agent::spawn_agent_task(state.clone(), root_token.child_token()),
    ));
    tracing::info!("LLM driver agent task spawned (checks DB config each cycle)");

    // Change-bump and edge-event housekeeping, on every replica (any may run it).
    edge_v2::events::spawn_janitor(state.db.clone());
    worker_handles.push(("edge_event_listener", edge_v2::events::spawn_listener(root_token.child_token())));
    // The edge config cache: built now, so `/ready` turns 200 only once this
    // replica can answer edge syncs.
    worker_handles.push(("edge_sync_refresh", edge_v2::sync::spawn_refresh(state.db.clone(), root_token.child_token())));
    worker_handles.push(("egress_refresh", egress::spawn_refresh(state.db.clone(), root_token.child_token())));

    {
        let state = state.clone();
        let token = root_token.child_token();
        worker_handles.push((
            "cors_allowlist",
            tokio::spawn(async move { watch_cors_allowlist(state, cors_known, token).await }),
        ));
    }

    // Spawn background retention/purge task (leader-only via advisory lock).
    {
        let pool = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push(("retention", tokio::spawn(async move {
            // Wait after startup for migrations to settle.
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(RETENTION_STARTUP_DELAY) => {}
            }

            let cycle_interval = crate::settings::admin_settings().retention_cycle_interval;

            loop {
                if token.is_cancelled() {
                    tracing::info!("retention worker: shutdown signalled, exiting");
                    break;
                }
                // Try to acquire leader lock for retention.
                // Hold the connection for the entire purge cycle.
                if let Some(leader_conn) = leader::try_acquire_leader(&pool, leader::LOCK_RETENTION).await {
                    tracing::info!("acquired retention leader lock");

                    if let Err(e) = retention::ensure_future_partitions(&pool).await {
                        tracing::error!("partition creation: {e}");
                    }
                    if let Err(e) = retention::ensure_future_sse_event_partitions(&pool).await {
                        tracing::error!("hourly sse-event partition creation: {e}");
                    }

                    match retention::run_purge(&pool).await {
                        Ok(summary) => tracing::info!(?summary, "retention purge complete"),
                        Err(e) => tracing::error!("retention purge failed: {e}"),
                    }

                    // Drop hourly mcp_sse_events partitions older than the
                    // configured retention window (default 1h). Separate
                    // pass so the SSE-event cadence doesn't interfere with
                    // the daily mcp_audit cadence.
                    let sse_cutoff = chrono::Utc::now()
                        - chrono::Duration::seconds(
                            crate::settings::admin_settings().mcp_sse_retention_secs as i64,
                        );
                    if let Err(e) =
                        retention::drop_old_sse_event_partitions(&pool, &sse_cutoff).await
                    {
                        tracing::error!("drop old sse-event partitions: {e}");
                    }

                    leader::release_leader(leader_conn, leader::LOCK_RETENTION).await;
                }

                tokio::select! {
                    _ = token.cancelled() => {
                        tracing::info!("retention worker: shutdown signalled, exiting");
                        break;
                    }
                    _ = tokio::time::sleep(cycle_interval) => {}
                }
            }
        })));
    }

    // Spawn the OAuth housekeeping sweeper (leader-only, 5-minute cadence):
    // reaps expired `mcp_pending_authorizations`, spent/expired
    // `oauth_authorization_codes` (60s TTL — an hour of slack is plenty), and
    // long-expired `oauth_issued_tokens` (every refresh rotation writes 2 rows
    // and revokes 2, so the table grows steadily; rows are kept 30 days past
    // expiry so the admin Tokens tab's "expired" view stays meaningful).
    // Must iterate tenants under per-tenant RLS — all three tables FORCE RLS,
    // so a raw-pool DELETE without `app.tenant_id` set silently matches zero
    // rows.
    {
        let pool = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push(("mcp_oauth_cleanup", tokio::spawn(async move {
            // Stagger startup so the retention task wins the first round.
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(45)) => {}
            }
            loop {
                if token.is_cancelled() {
                    tracing::info!("oauth housekeeping sweeper: shutdown signalled, exiting");
                    break;
                }
                if let Some(leader_conn) =
                    leader::try_acquire_leader(&pool, leader::LOCK_MCP_OAUTH_CLEANUP).await
                {
                    let total = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                    let total_for_iter = total.clone();
                    let res = crate::db::tenant::for_each_tenant(&pool, |mut db| {
                        let total = total_for_iter.clone();
                        async move {
                            for sql in [
                                "DELETE FROM mcp_pending_authorizations WHERE expires_at < NOW()",
                                "DELETE FROM oauth_authorization_codes WHERE expires_at < NOW() - INTERVAL '1 hour'",
                                "DELETE FROM oauth_device_codes WHERE expires_at < NOW() - INTERVAL '1 hour'",
                                "DELETE FROM oauth_issued_tokens WHERE expires_at < NOW() - INTERVAL '30 days'",
                            ] {
                                match sqlx::query(sql).execute(db.conn()).await {
                                    Ok(out) => {
                                        total.fetch_add(
                                            out.rows_affected(),
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!(tenant_id = %db.tenant_uuid(), "oauth housekeeping sweeper: {e}");
                                    }
                                }
                            }
                            Ok(())
                        }
                    })
                    .await;
                    if let Err(e) = res {
                        tracing::error!("oauth housekeeping sweeper iterate tenants: {e}");
                    }
                    let n = total.load(std::sync::atomic::Ordering::Relaxed);
                    if n > 0 {
                        tracing::info!(
                            deleted = n,
                            "reaped expired OAuth rows (pending authorizations, codes, issued tokens)"
                        );
                    }
                    leader::release_leader(leader_conn, leader::LOCK_MCP_OAUTH_CLEANUP).await;
                }
                tokio::select! {
                    _ = token.cancelled() => {
                        tracing::info!("oauth housekeeping sweeper: shutdown signalled, exiting");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {}
                }
            }
        })));
    }

    // Model autosync worker — leader-elected. Wakes on a short cadence to check
    // leadership and per-server due-ness; only servers whose `last_auto_sync_at`
    // is past `MODEL_AUTOSYNC_INTERVAL_HOURS` are actually re-discovered and
    // mirrored. Each server syncs in its own transaction (failure-safe).
    {
        let pool = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push(("model_autosync", tokio::spawn(async move {
            // Stagger startup so retention / oauth-cleanup win the first round.
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
            loop {
                if token.is_cancelled() {
                    tracing::info!("model autosync worker: shutdown signalled, exiting");
                    break;
                }
                if let Some(leader_conn) =
                    leader::try_acquire_leader(&pool, leader::LOCK_MODEL_AUTOSYNC).await
                {
                    let interval_hours =
                        crate::settings::admin_settings().model_autosync_interval_hours as i64;
                    let res = crate::db::tenant::for_each_tenant(&pool, move |mut db| {
                        async move {
                            crate::routes::model_sync::run_tenant_autosync(&mut db, interval_hours)
                                .await;
                            Ok(())
                        }
                    })
                    .await;
                    if let Err(e) = res {
                        tracing::error!("model autosync worker iterate tenants: {e}");
                    }
                    leader::release_leader(leader_conn, leader::LOCK_MODEL_AUTOSYNC).await;
                }
                tokio::select! {
                    _ = token.cancelled() => {
                        tracing::info!("model autosync worker: shutdown signalled, exiting");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(900)) => {}
                }
            }
        })));
    }

    // Usage janitor — leader-elected. GCs elapsed-window fleet usage counters so
    // the tables don't grow unbounded. The merge itself is leader-free (handled
    // inline on each edge connection); only this GC needs single-runner election.
    {
        let pool = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push(("usage_janitor", tokio::spawn(async move {
            // Stagger startup so the other leader workers win the first round.
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(90)) => {}
            }
            loop {
                if token.is_cancelled() {
                    tracing::info!("usage janitor worker: shutdown signalled, exiting");
                    break;
                }
                if let Some(leader_conn) =
                    leader::try_acquire_leader(&pool, leader::LOCK_USAGE_JANITOR).await
                {
                    crate::usage_rollup::gc_elapsed_windows(&pool).await;
                    leader::release_leader(leader_conn, leader::LOCK_USAGE_JANITOR).await;
                }
                let interval = crate::settings::admin_settings().usage_janitor_interval_secs;
                tokio::select! {
                    _ = token.cancelled() => {
                        tracing::info!("usage janitor worker: shutdown signalled, exiting");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
                }
            }
        })));
    }

    // Appliance upgrade-check — leader-elected. Asks the Kairos host daemon for
    // a newer OS version and raises a deduped notification. Fully inert on every
    // non-appliance shape: when STOWAGE_HOST_SOCKET is unset it never acquires the
    // lock or calls the daemon, it just idles on the interval.
    {
        let pool = state.db.clone();
        let token = root_token.child_token();
        worker_handles.push(("appliance_upgrade_check", tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(120)) => {}
            }
            loop {
                if token.is_cancelled() {
                    break;
                }
                if crate::settings::admin_settings().is_appliance()
                    && let Some(leader_conn) =
                        leader::try_acquire_leader(&pool, leader::LOCK_APPLIANCE_UPGRADE).await
                {
                    if let Err(e) = crate::routes::appliance::check_upgrade_and_notify(&pool).await {
                        tracing::warn!("appliance upgrade check failed: {e:?}");
                    }
                    leader::release_leader(leader_conn, leader::LOCK_APPLIANCE_UPGRADE).await;
                }
                let interval =
                    crate::settings::admin_settings().appliance_upgrade_check_interval_secs;
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
                }
            }
        })));
    }

    // Alert dispatcher — leader-elected. Evaluates budget crossings into the
    // generic notifications table and delivers pending rows to the configured
    // channels (operator log today). Woken on demand by pg_notify('notify_pending').
    {
        let state = state.clone();
        let token = root_token.child_token();
        worker_handles.push((
            "alert_dispatcher",
            tokio::spawn(async move {
                alerts::alert_dispatcher(state, token).await;
            }),
        ));
    }

    // Response-class counters for the /metrics exposition; the handler also
    // reads pool/edge gauges straight off AdminState.
    let admin_metrics = Arc::new(metrics::AdminMetrics::new());
    let metrics_state = state.clone();

    let app = build_app(state.clone(), admin_metrics.clone());

    let port = crate::settings::admin_settings().port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {addr}");

    // Graceful shutdown: on SIGTERM/SIGINT, cancel the root token so every
    // background worker exits at its next iteration boundary, then return so
    // axum drains in-flight HTTP requests.
    let graceful = {
        let root_token = root_token.clone();
        async move {
            shutdown_signal().await;
            tracing::info!("signalling background workers to drain");
            root_token.cancel();
        }
    };

    // Dedicated Prometheus /metrics listener (METRICS_PORT, default off).
    // Separate port by design — the main port rides the public API vhost.
    // Normal boot only: the degraded MIGRATION_FAILED server exposes no
    // metrics (readiness already signals that state). Bound on the startup
    // path so a misconfigured port fails boot loudly.
    let metrics_port = crate::settings::admin_settings().metrics_port;
    if metrics_port > 0 {
        let metrics_router = Router::new()
            .route("/metrics", get(metrics::metrics_handler))
            .with_state((metrics_state, admin_metrics.clone()));
        let metrics_listener =
            streamscope_core::metrics::bind_metrics_listener(metrics_port).await?;
        tracing::info!("metrics listener on 0.0.0.0:{metrics_port}");
        tokio::spawn(streamscope_core::metrics::serve(
            metrics_listener,
            metrics_router,
            root_token.clone(),
        ));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        streamscope_core::net::without_nagle(listener),
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(graceful)
    .await?;

    // HTTP server has drained. Background workers were already signalled (the
    // root token is cancelled); await each one's voluntary exit, bounded so a
    // worker mid-heavy-cycle (agent analysis, retention purge) can't hang the
    // process. On timeout we proceed — process death auto-releases advisory
    // locks 737001-737004.
    tracing::info!("HTTP server drained; awaiting background workers");
    // Mutating requests whose caller hung up are still running: they finish
    // (their audit rows included) under the same bound as the workers.
    worker_handles.push((
        "abandoned requests",
        tokio::spawn(async {
            middleware::run_to_completion::DETACHED.close();
            middleware::run_to_completion::DETACHED.wait().await;
            middleware::security_audit::AUDIT_WRITES.close();
            middleware::security_audit::AUDIT_WRITES.wait().await;
        }),
    ));
    let join_all = async move {
        let results = futures::future::join_all(
            worker_handles
                .into_iter()
                .map(|(name, handle)| async move { (name, handle.await) }),
        )
        .await;
        for (name, result) in results {
            match result {
                Ok(()) => tracing::info!(worker = name, "background worker exited voluntarily"),
                Err(e) => tracing::warn!(worker = name, error = %e, "background worker join error"),
            }
        }
    };
    let drain_timeout = crate::settings::admin_settings().shutdown_drain_timeout;
    match tokio::time::timeout(drain_timeout, join_all).await {
        Ok(()) => tracing::info!("all background workers stopped cleanly"),
        Err(_) => tracing::warn!(
            timeout_secs = drain_timeout.as_secs(),
            "background workers did not all exit before timeout — proceeding \
             (process death auto-releases advisory locks 737001-737004)"
        ),
    }
    tracing::info!("graceful shutdown complete");

    Ok(())
}

/// Assemble the production HTTP surface: every router, its auth / audit /
/// authz middleware stack, and the global layers, in the exact order the
/// serving process uses. Kept a pure function of `AdminState` (no I/O, no
/// listener) so the in-process router tests drive the SAME construction the
/// binary serves — a middleware-order or mount regression fails in `cargo
/// test`, not only in the E2E run.
///
/// Two invariants constrain edits here:
///   - the `lint-audit-coverage.sh` lint traces this function textually — it
///     needs the `let <name> = routes::…()` bindings, their `.route_layer(…)`
///     audit middleware spelled out per binding, and the `let app =
///     Router::new()` … `.with_state(state)` mount chain to stay in this file.
///   - `.route_layer` runs innermost-last: the layer added LAST runs FIRST.
// The `app` binding below reads as redundant to clippy, but the audit-coverage
// gate locates the mount chain by grepping this file for that binding's opening
// and closing text; folding it into the return expression makes the gate exit 2.
// Keep the binding — and keep its exact opening/closing text out of prose in this
// file, since the gate takes the FIRST textual hit and a comment quoting it wins.
#[allow(clippy::let_and_return)]
fn build_app(state: Arc<AdminState>, admin_metrics: Arc<metrics::AdminMetrics>) -> Router {
    // CORS layer — derived per-request from the per-tenant allowlist
    // (`state.cors_allowlist`). `watch_cors_allowlist` refreshes the set
    // whenever any tenant's `admin_public_url` changes; the predicate reads the
    // current ArcSwap snapshot on every preflight. Empty allowlist =
    // fail-closed (operator must seed the SYSTEM default before any
    // browser origin can hit `/api/v1/*` cross-origin).
    let cors_state = state.clone();
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(
            move |origin: &HeaderValue, _req: &axum::http::request::Parts| {
                let Ok(value) = origin.to_str() else { return false };
                let trimmed = value.trim_end_matches('/');
                cors_state.cors_allowlist.load().contains(trimmed)
            },
        ))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    // Build router — admin routes get auth middleware. The audit middleware
    // sits between auth and the handler so it reads `AdminTenantCtx` from
    // request extensions; the request-ID middleware is applied globally to the
    // top-level Router (below) so EVERY request — admin, portal, auth, edge,
    // 404s, OAuth metadata — carries a correlation header.
    // `authz_mw` is the innermost route-layer on every admin router: it runs
    // after `admin_auth` (needs `AdminTenantCtx`) and after `admin_audit_mw` in
    // the request flow (so a read-only account's denied mutation is still
    // recorded), immediately before the handler. Applied uniformly so no
    // mutating admin route — tenant-scoped or super-admin — can bypass it.
    //
    // `automation_key_ip_rate_limit_mw` is the OUTERMOST layer on every guarded
    // router (admin + portal), added last so it runs first: an `ak-` prober past
    // its per-source failed-auth cap is refused BEFORE `admin_auth` /
    // `portal_auth` runs the O(tenants) key-resolve scan. Placing it inside the
    // auth layer would still throttle, but only after paying for the work it
    // exists to prevent. It ignores everything that is not an `ak-` bearer — see
    // the middleware's own docs for why session traffic must not be counted.
    let admin_routes = routes::admin_router()
        .merge(routes::auth_config::auth_config_router())
        .route_layer(axum::middleware::from_fn(authz_mw))
        // SYSTEM-tenant workload guard — denies the platform tenant any mutation
        // outside its platform/self-management allowlist. Inside `admin_audit_mw`
        // (so a denied SYSTEM mutation is still audited), after `admin_auth`.
        .route_layer(axum::middleware::from_fn(system_workload_guard))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_audit_mw,
        ))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::automation_key_ip_rate_limit_mw,
        ));

    // Super-admin-only tenant management routes.
    let tenant_routes = routes::tenants::tenant_router()
        .route_layer(axum::middleware::from_fn(authz_mw))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_audit_mw,
        ))
        .route_layer(axum::middleware::from_fn(super_admin_guard))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::automation_key_ip_rate_limit_mw,
        ));

    // Super-admin-only edge node management routes (global infrastructure).
    let edge_admin_routes = routes::edge_admin_router()
        .route_layer(axum::middleware::from_fn(authz_mw))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_audit_mw,
        ))
        .route_layer(axum::middleware::from_fn(super_admin_guard))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::automation_key_ip_rate_limit_mw,
        ));

    // Super-admin-only global routes (cross-tenant, raw pool). Mounted at
    // /api/v1/admin/global/* behind the super-admin middleware — one authz fence.
    let super_admin_global = routes::super_admin_global_router()
        .route_layer(axum::middleware::from_fn(authz_mw))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::admin_audit_mw,
        ))
        .route_layer(axum::middleware::from_fn(super_admin_guard))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), admin_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::automation_key_ip_rate_limit_mw,
        ));

    // Portal routes: user-identity auth (separate from admin). `portal_audit_mw`
    // is the inner layer (runs after `portal_auth`, so it reads `PortalUser`),
    // recording every mutating portal call to `portal_audit`.
    let portal_routes = routes::portal_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::portal_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), routes::portal_auth::portal_auth))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::automation_key_ip_rate_limit_mw,
        ));

    // Public / pre-auth surfaces. These routers authenticate inline, per
    // request, and carry two layers:
    //   - `security_audit_mw` (inner) — records every login, setup, OIDC
    //     exchange, invite acceptance, and MCP-OAuth grant/register attempt
    //     (success + failure) to the global `security_audit` table.
    //   - `pre_auth_ip_rate_limit_mw` (outer) — per-source-IP flood cap.
    // The IP limiter is the OUTERMOST layer (added last) so a throttled flood is
    // rejected before `security_audit_mw` buffers the body or writes a row — no
    // audit amplification, the same outcome the per-account limiter's 429s get
    // via the audit middleware's `rate_limit_exceeded` drop.
    //
    // Keep both `.route_layer`s spelled out per router — the audit-coverage gate
    // (`lint-audit-coverage.sh`) reads the `security_audit_mw` attachment
    // textually from each binding; factoring them behind a helper hides it and
    // trips the gate.
    let auth_routes = routes::auth_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw));
    // The claim exchange takes an identity on a caller's word, so it exists only
    // when a deployment turns it on, and then its OUTERMOST layer (added last)
    // is the service-secret check, as on the OIDC RP routes: anonymous traffic is
    // refused before the body is parsed or `security_audit` written.
    let claim_exchange_on = crate::settings::admin_settings().allow_oidc_claim_exchange;
    let header_auth = routes::admin_auth::auth_mode() == routes::admin_auth::AuthMode::Header;
    let claim_exchange_routes = if claim_exchange_on {
        routes::claim_exchange_router()
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw))
            .route_layer(axum::middleware::from_fn(routes::oidc_rp::internal_service_secret_mw))
    } else {
        Router::new()
    };
    let invite_routes = routes::tenants::invite_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw));
    let portal_auth_routes = routes::portal_auth_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw));
    // The per-request session checks carry NO per-IP cap: the browser tier makes
    // one for every console request, so a cap sized for anonymous sign-in traffic
    // throttles a single user refreshing a dashboard. `/auth/me` refuses a caller
    // without a validly signed session before any per-caller work (standard
    // auth); under header auth the forwarded identity headers ARE the
    // credential, and that deployment requires admin-api to be reachable only
    // through its authenticating proxy — a caller who can reach it directly can
    // name any user, which no rate cap would contain.
    //
    // `/portal/auth/header-me` is the portal's per-request check ONLY under
    // header auth. Under standard auth it is the secret-gated claim exchange
    // (`ALLOW_OIDC_CLAIM_EXCHANGE`), which mints sessions for named users and
    // nothing calls per request — so there it keeps the pre-auth cap.
    let auth_session_routes = routes::auth_session_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw));
    // Absent unless one of its two roles is on. As the claim exchange it is a
    // GET with no body, and the handler refuses an untrusted caller with the
    // same 404 before any per-caller work, so it needs no secret layer.
    let portal_header_session_routes = if routes::header_me_is_mounted(header_auth, claim_exchange_on) {
        routes::portal_header_session_router()
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::claim_exchange_ip_rate_limit_mw))
    } else {
        Router::new()
    };
    let mcp_oauth_routes = routes::mcp_oauth_public_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw));
    let cli_oauth_routes = routes::cli_oauth_public_router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw));
    // The OIDC login flow. The service-secret layer is added LAST, so it is the
    // outermost and runs first: this surface sits on the port the public vhost
    // reverse-proxies wholesale, and letting anonymous traffic reach the audit
    // layer would let an unauthenticated loop flood `security_audit`. Refusing
    // outside it means every row written is a real login attempt. The per-IP cap
    // is deliberately absent: the browser tier reads a refusal here as "sign-in
    // is not configured" or silently skips the provider logout, so a throttled
    // login wave behind one NAT would present as a broken configuration.
    let oidc_rp_routes = routes::oidc_rp::router()
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::security_audit_mw))
        .route_layer(axum::middleware::from_fn(routes::oidc_rp::internal_service_secret_mw));

    // OpenAPI spec + interactive docs (no auth — public reference). Gated by
    // API_DOCS_PUBLIC (default true): when false the routes are absent and both
    // 404, so a public deployment need not enumerate its API surface. Built as
    // a sub-router merged into the mount chain below so it inherits the same
    // CORS / request-id / panic layers.
    let docs_routes = if crate::settings::admin_settings().api_docs_public {
        let openapi = published_api_doc();
        Router::new()
            .route("/api/docs/openapi.json", get({
                let spec = openapi.clone();
                || async { axum::Json(spec) }
            }))
            .merge(Scalar::with_url("/api/docs", openapi))
    } else {
        Router::new()
    };

    let app = Router::new()
        .route("/health", get(liveness_check))
        .route("/ready", get(readiness_check))
        .merge(docs_routes)
        .nest("/api/v1/admin", admin_routes)
        .nest("/api/v1/admin", edge_admin_routes)
        .nest("/api/v1/admin/tenants", tenant_routes)
        .nest("/api/v1/admin/global", super_admin_global)
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/auth", claim_exchange_routes)
        .nest("/api/v1/auth", auth_session_routes)
        // Public endpoints (no auth) — per-source-IP flood cap (a GET, so
        // `security_audit_mw` would pass it through; the IP limiter alone applies).
        .nest("/api/v1/tenants", routes::auth_config::public_auth_info_router()
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw)))
        .nest("/api/v1/invites", invite_routes)
        // Internal endpoints (INTERNAL_SERVICE_SECRET only)
        .nest("/api/v1/internal/oidc", oidc_rp_routes)
        .nest("/api/v1/internal", routes::internal_platform::router())
        .nest("/api/v1/portal", portal_routes)
        .nest("/api/v1/portal", portal_auth_routes) // login (security_audit_mw only)
        .nest("/api/v1/portal", portal_header_session_routes)
        // Public MCP OAuth flow (RFC 8414/8707/9728). No admin/portal
        // middleware — endpoints authenticate the request inline (portal JWT
        // in Authorization for consent; PKCE for token; unauthenticated for
        // metadata). security_audit_mw records the grant/register attempts.
        .nest("/api/v1/mcp/oauth", mcp_oauth_routes)
        // Public CLI-provisioning OAuth flow — same gating model as the MCP
        // OAuth surface above (inline portal-JWT consent, PKCE token, public
        // metadata/revoke).
        .nest("/api/v1/cli/oauth", cli_oauth_routes)
        // Public CLI distribution (installer script / binary / version
        // manifest) — GET-only artifact serving; the per-IP flood cap is the
        // only gate, like the public auth-info reads above.
        .nest("/api/v1/cli", routes::cli_dist::router()
            .route_layer(axum::middleware::from_fn_with_state(state.clone(), middleware::pre_auth_ip_rate_limit_mw)))
        .layer(CatchPanicLayer::custom(handle_panic))
        // Outside the panic layer and every audit layer: a mutating request
        // runs on, its audit row included, after its caller hangs up.
        .layer(axum::middleware::from_fn(middleware::run_to_completion_mw))
        // Every body read past here is bounded in total time, counted from its
        // first read, and in size by the limit the console and portal audit
        // layers read under — so what they refuse and what a handler would are
        // one decision.
        .layer(axum::middleware::from_fn_with_state(
            streamscope_core::settings::core_settings().request_body_deadline,
            streamscope_core::middleware::body_deadline::bound_request_body,
        ))
        .layer(axum::extract::DefaultBodyLimit::max(middleware::audit_common::CONSOLE_BODY_LIMIT))
        // Nested after that layer, so outside it: an edge request is built to
        // be cancelled and sent again, and an abandoned sync must not go on to
        // record a prediction beside its own retry's.
        .nest("/api/v2/edge", edge_v2::edge_v2_router())
        // Every error leaves with the `ApiErrorResponse` envelope — extractor
        // rejections and the router's own 404/405 included.
        .layer(axum::middleware::from_fn(middleware::json_error_body_mw))
        .layer(cors)
        // Status-class counting for /metrics — wraps everything below
        // request_id so 404s and panic recoveries are counted too.
        .layer(axum::middleware::from_fn_with_state(
            admin_metrics.clone(),
            metrics::count_responses_mw,
        ))
        // request_id is the outermost layer — every request, including 404s,
        // panic recoveries, public endpoints (auth, invites, OAuth metadata,
        // OIDC, MCP-OAuth, edge sync), and the OpenAPI/health probes, gets a
        // correlation UUID echoed on the `X-Request-Id` response header.
        // Downstream middleware (admin_audit, portal_auth, …) reads it from
        // request extensions to stamp the same UUID onto audit rows + logs.
        .layer(axum::middleware::from_fn(middleware::request_id_mw))
        .with_state(state);

    app
}

/// Wait for SIGINT (Ctrl+C) or SIGTERM, then return so graceful shutdown begins.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT, starting graceful shutdown"),
        () = terminate => tracing::info!("received SIGTERM, starting graceful shutdown"),
    }
}

// Build the degraded-mode router. `/health` (liveness) stays 200 so an
// orchestrator's livenessProbe never restart-storms a pod that a restart can't
// fix; `/ready` (readiness) and every other route answer 503 with the canonical
// `ApiErrorResponse` envelope + `ApiErrorCode::MigrationFailed`, so:
//   - operators can `curl /ready | jq` to read the reason
//   - the admin-ui's typed `extractErrorCode()` recognizes the code
//   - the future Updates tab in the system tenant can branch on it
// CorsLayer + `request_id_mw` mirror the live router so browser preflight works
// and `X-Request-Id` propagates. `reason` is `&'static str` so the closures stay
// Copy. Extracted from `run_degraded_mode` so the probe contract is unit-testable
// without binding a socket.
fn build_degraded_router(reason: &'static str) -> Router {
    use routes::{ApiError, ApiErrorCode};

    // Permissive CORS for triage: degraded responses carry no sensitive data,
    // and the operator's browser may come from any origin (production UI,
    // local dev, kubectl port-forward…). Echo the requesting origin so the
    // admin-ui's `credentials: include` XHR is not blocked.
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|_, _| true))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    let degraded = move || async move {
        ApiError::service_unavailable(format!("admin-api is in degraded mode: {reason}"))
            .code(ApiErrorCode::MigrationFailed)
    };

    // Liveness stays 200 even while degraded: restarting a migration-failed pod
    // can't fix it (recovery is A/B rollback / a fixed image), so the
    // livenessProbe must not restart-storm. Captures nothing → Copy.
    let liveness = || async {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "alive" })),
        )
    };

    // The degraded closure captures only `&'static str` (Copy), so it's Copy
    // itself — no `.clone()` needed to share between /ready and the fallback.
    Router::new()
        .route("/health", get(liveness))
        .route("/ready", get(degraded))
        .fallback(degraded)
        .layer(axum::middleware::from_fn(middleware::json_error_body_mw))
        .layer(cors)
        .layer(axum::middleware::from_fn(middleware::request_id_mw))
}

// Degraded-mode HTTP server. Entered when any step of admin-api bring-up fails
// (Postgres unreachable, migration error, pool init, listener bind…). Binds the
// normal admin port and serves `build_degraded_router`. Graceful shutdown on
// SIGTERM is honored so `docker stop` is clean. A bind failure here is fatal —
// we return Err so the process exits and Docker reschedules (which clears any
// orphan-port collision); silent-sleeping with no HTTP endpoint would defeat the
// entire triage path.
async fn run_degraded_mode(reason: String) -> anyhow::Result<()> {
    let reason: &'static str = String::leak(reason);
    tracing::error!(
        reason = reason,
        "admin-api entering DEGRADED mode — liveness (/health) stays 200, readiness (/ready) + every other endpoint serve 503 + MigrationFailed"
    );

    let app = build_degraded_router(reason);

    let port = crate::settings::admin_settings().port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("degraded-mode bind {addr} failed: {e}"))?;
    tracing::info!("degraded-mode listener bound on {addr}");
    axum::serve(streamscope_core::net::without_nagle(listener), app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("degraded-mode server crashed: {e}"))?;
    tracing::info!("degraded-mode server exited cleanly");
    Ok(())
}

/// Liveness endpoint (`/health`) — always 200 while the process is running.
/// Deliberately checks NO dependencies: a transient Postgres outage must not
/// make an orchestrator restart the pod (a restart can't fix a sick database
/// and would cause a restart-storm). Readiness gating lives in
/// `readiness_check`; a migration-failed boot serves liveness 200 from degraded
/// mode too (restarting won't fix it — recovery is A/B rollback / a fixed image).
async fn liveness_check() -> impl axum::response::IntoResponse {
    // Body is a bare status — served unauthenticated on the public vhost, so it
    // carries no build version or infrastructure detail to fingerprint.
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "alive" })),
    )
}

/// Readiness endpoint (`/ready`) — 200 only when the service can do useful work:
/// Postgres reachable and this replica's edge config cache built (until then it
/// refuses every edge sync). 503 otherwise, so an orchestrator or load balancer
/// keeps the replica out of rotation during a dependency outage or slow startup.
/// Distinct from `/health` (liveness). A migration-failed boot serves this from
/// degraded mode as 503 + `MigrationFailed`; the VM host daemon's readiness gate
/// polls this.
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<Arc<AdminState>>,
) -> impl axum::response::IntoResponse {
    let pg = state.db.ping().await;
    if let Err(e) = &pg {
        tracing::warn!("readiness check: PostgreSQL query failed: {e}");
    }
    readiness(pg.is_ok(), edge_v2::sync::cache_ready().await)
}

/// The `/ready` answer. The body is a bare status — this is served
/// unauthenticated on the public vhost, so it must not leak the build version
/// or which dependency is down (fingerprinting / infra disclosure). Consumers
/// gate on the HTTP 200/503 status only, never the body shape.
fn readiness(postgres_up: bool, edge_cache_built: bool) -> (StatusCode, axum::Json<serde_json::Value>) {
    if postgres_up && edge_cache_built {
        (StatusCode::OK, axum::Json(serde_json::json!({ "status": "ready" })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({ "status": "not_ready" })))
    }
}

/// JWT-only auth middleware for admin routes.
///
/// Accepts `Authorization: Bearer <JWT>` — signed session token from admin login.
///
/// On success, attaches `AdminTenantCtx` to request extensions so that
/// `TenantConn` can extract the tenant_id for RLS scoping.
async fn admin_auth(
    axum::extract::State(state): axum::extract::State<Arc<AdminState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, routes::ApiError> {
    // JWT session token (per-tenant key derivation + active check). A session
    // the database could not be asked about is a 503, never a 401: the console
    // ends its session on a 401, and an outage proves nothing about it.
    let session = match routes::admin_auth::validate_session_token(req.headers(), &state.db).await {
        Ok(s) => s,
        Err(e) => return Ok(axum::response::IntoResponse::into_response(routes::ApiError::from(e))),
    };
    if let Some(claims) = session {
        let Some(tenant_id) = claims.aud.parse::<uuid::Uuid>().ok().map(db::tenant::TenantId::from_credential) else {
            return Err(routes::rejected_credential());
        };
        let Some(admin_account_id) = claims.sub.parse::<uuid::Uuid>().ok() else {
            return Err(routes::rejected_credential());
        };
        req.extensions_mut().insert(db::tenant::AdminTenantCtx {
            tenant_id,
            admin_account_id,
            is_super_admin: claims.is_super_admin,
            role: authz::AdminRole::parse(&claims.role),
            actor_key_id: None,
            key_scope: None,
        });
        return Ok(next.run(req).await);
    }

    // `ak-` admin automation key (long-lived, person-independent). Tried only
    // after the JWT path so a human session always wins. Fail-closed: any
    // unknown / revoked / expired / wrong-tenant key falls through to 401, never
    // a privilege fallback.
    //
    // The per-key ceiling is checked FIRST, so a flooding key never reaches the
    // cross-tenant scan behind `authenticate_admin_key`.
    if routes::admin_auth::automation_key_rate_limited(
        &state.automation_key_rate_limiter,
        req.headers(),
    ) {
        return Err(routes::ApiError::too_many_requests("automation key rate limit exceeded"));
    }
    // A key the database could not be asked about is a 503, never a 401 —
    // automation that rotates or alerts on a 401 would treat a live key as
    // revoked.
    let key_ctx = match routes::admin_auth::authenticate_admin_key(req.headers(), &state.db).await {
        Ok(ctx) => ctx,
        Err(e) => return Ok(middleware::AutomationKeyUnverified::response(e)),
    };
    if let Some(ctx) = key_ctx {
        routes::admin_auth::record_automation_key_use(
            &state.automation_key_rate_limiter,
            req.headers(),
        );
        req.extensions_mut().insert(ctx);
        return Ok(next.run(req).await);
    }

    // No header at all is `missing_auth_header`; a replica with no signing key
    // cannot have checked a session, so it says so rather than signing the
    // caller out — but an `ak-` key needs no signing key and was checked, so
    // its refusal stays a 401; any other refusal is one answer.
    Err(match routes::bearer_token(req.headers()) {
        Err(refusal) => refusal,
        Ok(token) if !token.starts_with("ak-") && routes::admin_auth::keyring().is_none() => {
            routes::no_signing_key()
        }
        Ok(_) => routes::rejected_credential(),
    })
}

/// Super-admin guard middleware. Must be applied after admin_auth.
/// Only allows requests from SYSTEM tenant super-admins.
async fn super_admin_guard(req: Request, next: Next) -> Result<Response, routes::ApiError> {
    // No context means the guard was mounted without `admin_auth` — a wiring
    // fault, never the caller's.
    let ctx = req.extensions().get::<db::tenant::AdminTenantCtx>().ok_or_else(|| {
        tracing::error!("super_admin_guard reached without AdminTenantCtx: admin_auth is not layered");
        routes::ApiError::internal("internal error")
    })?;
    if ctx.tenant_id != db::tenant::TenantId::SYSTEM || !ctx.is_super_admin {
        return Err(routes::ApiError::forbidden("platform super-admin only")
            .code(routes::ApiErrorCode::SuperAdminRequired));
    }
    Ok(next.run(req).await)
}

/// The matched route template with the `/api/v1/admin` mount prefix stripped
/// (`/api/v1/admin/servers/{id}` → `servers/{id}`), the form the authorization
/// allowlists are written in. `None` when no route matched.
fn admin_route_template(req: &Request) -> Option<&str> {
    req.extensions().get::<axum::extract::MatchedPath>().map(|m| {
        m.as_str()
            .strip_prefix("/api/v1/admin")
            .unwrap_or(m.as_str())
            .trim_start_matches('/')
    })
}

/// SYSTEM-tenant workload guard. Applied after `admin_auth` on the per-tenant
/// `admin_routes` router (NOT the super-admin routers, which already require
/// SYSTEM). The SYSTEM platform tenant runs no customer workloads, so it may not
/// **mutate** any admin route outside an explicit platform / self-management
/// allowlist ([`authz::SYSTEM_ALLOWED_MUTATIONS`]) — fail-closed: a new mutating
/// route is SYSTEM-forbidden until added there.
///
/// Safe-method reads pass for SYSTEM: every admin-router read is RLS-scoped to
/// the SYSTEM tenant's own (empty) workload, so it exposes nothing cross-tenant
/// (cross-tenant data lives behind the `/global/*` super-admin routers), and the
/// SYSTEM-visible console pages legitimately fire workload GETs. Every real
/// tenant passes through untouched. Layered *inside* `admin_audit_mw` (added
/// after it) so a denied SYSTEM mutation is still recorded on `admin_audit`.
async fn system_workload_guard(req: Request, next: Next) -> Response {
    use axum::response::IntoResponse;
    let Some(ctx) = req.extensions().get::<db::tenant::AdminTenantCtx>().cloned() else {
        return routes::ApiError::unauthorized("authentication required").into_response();
    };
    // Only the SYSTEM platform tenant is restricted; every real tenant passes.
    if ctx.tenant_id != db::tenant::TenantId::SYSTEM {
        return next.run(req).await;
    }
    // Reads are RLS-scoped to SYSTEM's empty workload — always allow.
    if authz::is_safe_method(req.method()) {
        return next.run(req).await;
    }
    // Absent template ⇒ deny (fail-closed).
    if admin_route_template(&req).is_some_and(authz::system_tenant_allows_mutation) {
        return next.run(req).await;
    }
    tracing::warn!(
        account = %ctx.admin_account_id,
        method = %req.method(),
        path = %req.uri().path(),
        "SYSTEM tenant denied mutation on a customer-workload route"
    );
    routes::ApiError::forbidden("not available on the platform (SYSTEM) tenant")
        .code(routes::ApiErrorCode::SystemTenantForbidden)
        .into_response()
}

/// Role-based authorization chokepoint. Applied after `admin_auth` (so the
/// `AdminTenantCtx` is present) on every admin router. It is the SINGLE place a
/// read-only account is blocked from mutating — never per-handler.
///
/// Layered *inside* `admin_audit_mw` so a denied mutation is still recorded:
/// the 403 bubbles back out through the audit layer, which captures the typed
/// `{code, message}` on the `admin_audit` row. Fail-closed: a missing context
/// is a 401, and the role was already parsed fail-closed in `admin_auth`.
async fn authz_mw(req: Request, next: Next) -> Response {
    use axum::response::IntoResponse;
    let Some(ctx) = req.extensions().get::<db::tenant::AdminTenantCtx>().cloned() else {
        return routes::ApiError::unauthorized("authentication required").into_response();
    };
    let decision = authz::evaluate(&authz::AccessContext {
        role: ctx.role,
        method: req.method(),
        key_scope: ctx.key_scope.as_deref(),
        route: admin_route_template(&req),
    });
    match decision {
        authz::Decision::Allow => next.run(req).await,
        authz::Decision::Deny { code, reason } => {
            tracing::warn!(
                tenant = %ctx.tenant_id,
                account = %ctx.admin_account_id,
                method = %req.method(),
                path = %req.uri().path(),
                "authz denied: {reason}"
            );
            routes::ApiError::forbidden(reason).code(code).into_response()
        }
    }
}

/// Ensure an edge node exists for the given token. Idempotent — skips if the
/// token hash already exists. This lets docker-compose deployments work without
/// manual `POST /admin/edge-nodes` provisioning.
///
/// Edge nodes are global infrastructure (no tenant_id, no RLS) — uses raw pool.
async fn auto_provision_edge_node(pool: &crate::db::Db, token: &str) {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let hash = hex::encode(hasher.finalize());

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM edge_nodes WHERE token_hash = $1)")
        .bind(&hash)
        .fetch_one(pool.global(crate::db::Global::Infra))
        .await
        .unwrap_or(false);

    if exists {
        tracing::info!("edge node already provisioned for EDGE_TOKEN");
        return;
    }

    let name = format!("edge-{}", &hash[..8]);
    match sqlx::query(
        "INSERT INTO edge_nodes (name, endpoint, token_hash, status) VALUES ($1, '', $2, 'active') ON CONFLICT DO NOTHING",
    )
    .bind(&name)
    .bind(&hash)
    .execute(pool.global(crate::db::Global::Infra))
    .await
    {
        Ok(_) => tracing::info!("auto-provisioned edge node from EDGE_TOKEN"),
        Err(e) => tracing::error!("failed to auto-provision edge node: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn panicking_handler() -> StatusCode {
        panic!("handler boom")
    }

    #[test]
    fn the_cors_allowlist_is_each_tenants_own_origin_or_the_default_it_inherits() {
        let (own, inherits) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
        let tenants = std::collections::HashMap::from([(own, Some("https://own.test".to_string())), (inherits, None)]);
        let with_default = CorsOrigins { system: Some("https://default.test".into()), tenants: tenants.clone() };
        assert_eq!(
            with_default.allowlist(),
            std::collections::HashSet::from(["https://own.test".to_string(), "https://default.test".to_string()])
        );
        let without_default = CorsOrigins { system: None, tenants };
        assert_eq!(
            without_default.allowlist(),
            std::collections::HashSet::from(["https://own.test".to_string()]),
            "a tenant with no origin and none to inherit adds nothing"
        );
    }

    #[test]
    fn a_replica_is_ready_only_with_postgres_up_and_its_edge_cache_built() {
        assert_eq!(readiness(true, true).0, StatusCode::OK);
        assert_eq!(
            readiness(true, false).0,
            StatusCode::SERVICE_UNAVAILABLE,
            "a replica that would refuse every edge sync is not ready"
        );
        assert_eq!(readiness(false, true).0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(readiness(false, false).1.0, serde_json::json!({ "status": "not_ready" }));
    }

    /// A panic inside a handler must be unwound by `CatchPanicLayer` into a
    /// sanitized 500 (`ApiErrorResponse` envelope) — the connection is kept,
    /// the panic payload never leaks.
    #[tokio::test]
    async fn panic_in_handler_returns_sanitized_500() {
        let app = Router::new()
            .route("/boom", get(panicking_handler))
            .layer(CatchPanicLayer::custom(handle_panic));

        let resp = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["type"], "internal_error");
        assert_eq!(body["error"]["code"], "internal_error");
    }

    /// A migration-failed boot must keep liveness (`/health`) at 200 so the pod
    /// is never restart-stormed, while readiness (`/ready`) — and every other
    /// route — fails with 503 + `MigrationFailed` so an orchestrator keeps the
    /// replica out of rotation and the VM watchdog rolls the bad version back.
    #[tokio::test]
    async fn degraded_router_liveness_200_readiness_503() {
        let app = build_degraded_router("migration 999 failed: boom");

        // Liveness stays 200 even while degraded.
        let live = app
            .clone()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);
        let live_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(live.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert_eq!(live_body["status"], "alive");

        // Readiness is 503 + MigrationFailed.
        let ready = app
            .clone()
            .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        let ready_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ready.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert_eq!(ready_body["error"]["code"], "migration_failed");

        // Any other route also fails closed with the same code.
        let other = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/settings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::SERVICE_UNAVAILABLE);
        let other_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(other.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        assert_eq!(other_body["error"]["code"], "migration_failed");
    }
}
