//! The config body of one tenant, built from rows.
//!
//! [`build_tenant_body`] is a pure function of the rows visible on `conn`: it
//! reads no clock and no process state except the signing ring (derived from
//! `AUTH_SECRET`, identical on every replica outside a rotation roll).
//! The caller owns the transaction, so the body and anything it is labelled
//! with come from one snapshot.
//!
//! [`BODY_TABLES`] is every table the build reads. A table read by the build
//! but missing from it is a config change that never reaches an edge, so the
//! list is checked against the scans each build actually made
//! ([`untracked_reads`]).

use std::collections::HashMap;

use streamscope_core::config::ProfileKind;
use streamscope_core::config::model_map::{ModelMap, UpstreamModel};

use crate::db::tenant::Scoped;
use crate::db::tenant::TenantId;
use streamscope_edge_api::config::{
    ConfigResponse, EdgeA2aAgent, EdgeApiKey, EdgeMcpUpstreamServer, EdgeMcpUserCredential,
    EdgeMcpVirtualRoute, EdgeMcpVirtualServer, EdgeModelMapping, EdgeTransformProgram,
};

/// Every table [`build_tenant_body`] reads, the shared loaders it calls
/// included. Must equal the tables carrying the change triggers
/// (the `lint-config-builder.sh` lint).
pub const BODY_TABLES: &[&str] = &[
    "a2a_upstream_agents",
    "api_keys",
    "apps",
    "cache_presets",
    "destination_lists",
    "downstream_providers",
    "downstream_routes",
    "guardrail_policies",
    "mcp_upstream_servers",
    "mcp_user_credentials",
    "mcp_virtual_routes",
    "mcp_virtual_servers",
    "model_catalog",
    "model_presets",
    "oauth_issued_tokens",
    "platform_egress",
    "platform_setting_overrides",
    "profiles",
    "qos_classes",
    "route_policies",
    "route_qos_classes",
    "system_settings",
    "tenants",
    "tool_field_profiles",
    "tool_policy_rules",
    "transform_programs",
    "upstream_model_endpoints",
    "upstream_models",
    "upstream_server_endpoints",
    "upstream_servers",
    "users",
    "web_destination_lists",
    "workspace_a2a_access",
    "workspace_downstream_access",
    "workspace_mcp_access",
    "workspace_profile_assignments",
    "workspace_rate_limits",
    "workspace_user_rate_limit_overrides",
    "workspaces",
];

/// Scans per table as `pg_stat_xact_user_tables` reports them on `conn`. The
/// view also carries a backend's counts from earlier transactions it has not
/// flushed yet, and those cannot flush inside a transaction — so the scans a
/// transaction made are the difference between a reading taken at its start
/// and one taken at its end.
pub type ScanCounts = HashMap<String, i64>;

pub async fn scan_counts(conn: &mut Scoped) -> Result<ScanCounts, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT relname::text, COALESCE(seq_scan, 0) + COALESCE(idx_scan, 0) FROM pg_stat_xact_user_tables",
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Tables scanned since `before` (taken first thing in the build's
/// transaction) that are neither in [`BODY_TABLES`] nor in `also_read` (what
/// the caller itself reads in that transaction, e.g. the change counters).
pub async fn untracked_reads(
    conn: &mut Scoped,
    before: &ScanCounts,
    also_read: &[&str],
) -> Result<Vec<String>, sqlx::Error> {
    let after = scan_counts(conn).await?;
    Ok(scanned_outside(before, &after, also_read))
}

fn scanned_outside(before: &ScanCounts, after: &ScanCounts, also_read: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = after
        .iter()
        .filter(|(t, n)| **n > before.get(*t).copied().unwrap_or(0))
        .map(|(t, _)| t.clone())
        .filter(|t| !BODY_TABLES.contains(&t.as_str()) && !also_read.contains(&t.as_str()))
        .collect();
    out.sort();
    out
}


/// One tenant's config body, read on `conn` (tenant-scoped, inside the
/// caller's REPEATABLE READ transaction).
pub async fn build_tenant_body(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    tenant_slug: String,
) -> Result<ConfigResponse, sqlx::Error> {
    // Fetch ALL enabled downstream routes (JOIN through models + servers + providers).
    // Multiple routes per alias support LB/failover on edge proxies.
    let model_mappings = sqlx::query_as::<_, EdgeModelMapping>(sqlx::AssertSqlSafe(
        &*crate::routes::with_catalog_join(
            concat!(r#"SELECT
                  r.id::text as id,
                  dp.tenant_id::text as tenant_id,
                  r.alias,
                  s.provider,
                  m.upstream_model,
                  r.priority,
                  r.weight,
                  r.cache_generation,
                  "#, live_route_sql!(), r#" as enabled,
                  s.encrypted_key as encrypted_credential,
                  -- Capabilities / window / format / healing are upstream-model truth
                  -- (the route is a pure pointer + preset), resolved model → catalog.
                  COALESCE(m.context_window, c.context_window) as context_window,
                  "#, resolved_max_output_sql!("m", "c"), r#" as max_output_tokens,
                  r.client_context_window,
                  COALESCE(m.upstream_api_format, s.upstream_api_format) as upstream_api_format,
                  s.chat_endpoint_path as chat_endpoint_path,
                  s.transport as transport,
                  s.scheduling_dialect as scheduling_dialect,
                  s.id::text as upstream_server_id,
                  dp.id::text as downstream_provider_id,
                  m.id::text as upstream_model_id,
                  COALESCE(m.supports_vision, c.supports_vision) as supports_vision,
                  COALESCE(m.supports_reasoning, c.supports_reasoning) as supports_reasoning,
                  COALESCE(m.supports_function_calling, c.supports_function_calling) as supports_function_calling,
                  COALESCE(m.supports_caching, c.supports_caching) as supports_caching,
                  COALESCE(m.supports_audio_input, c.supports_audio_input) as supports_audio_input,
                  COALESCE(m.supports_audio_output, c.supports_audio_output) as supports_audio_output,
                  COALESCE(m.supports_video_input, c.supports_video_input) as supports_video_input,
                  COALESCE(m.supports_pdf_input, c.supports_pdf_input) as supports_pdf_input,
                  COALESCE(m.supports_response_schema, c.supports_response_schema) as supports_response_schema,
                  COALESCE(m.supports_system_messages, c.supports_system_messages) as supports_system_messages,
                  (c.catalog_match_id IS NOT NULL) as catalog_matched,
                  m.healing_enabled,
                  -- Resolved invocation preset: the route's bound preset, else the
                  -- model's default preset. NULL/absent → '{}' (passthrough).
                  COALESCE(pr.settings, '{}'::jsonb) as preset_settings,
                  -- Resolved response-cache policy: the alias's cache preset,
                  -- flattened to values. All NULL when the route references none.
                  cp.mode as cache_mode,
                  cp.ttl_seconds as cache_ttl_seconds,
                  cp.threshold as cache_threshold,
                  cp.share_scope as cache_share_scope,
                  -- Resolved price list: this model's own map, else the map on
                  -- the catalog row of the SAME provider (the `catp` lateral is
                  -- provider-matched for exactly this reason — a borrowed price
                  -- is invisible once it lands in an audit row). NULL on both
                  -- means no price is known, which the proxy bills at a floor of
                  -- zero AND badges.
                  --
                  -- The override is whole-map by design: a price list is a set
                  -- quoted by one provider in one currency, so mixing half of the
                  -- operator's with half of the catalog's is the same borrowed-
                  -- price hazard one level down. `'{}'` is therefore distinct
                  -- from NULL — it is an operator stating that this model has no
                  -- price, and it does not fall through.
                  --
                  -- There is deliberately no `pricing_known` flag beside this.
                  -- Whether a request could be priced is a property of the
                  -- REQUEST, not the model: it is true when every unit that
                  -- request actually consumed carried a rate. A per-model flag
                  -- had to enumerate which rates counted as sufficient, and got
                  -- it wrong for every model billed in a unit the enumeration
                  -- missed.
                  COALESCE(m.rates, catp.rates, '{}'::jsonb) as rates
           FROM downstream_routes r
           JOIN downstream_providers dp ON dp.id = r.provider_id
           JOIN upstream_models m ON m.id = r.model_id
           JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
           LEFT JOIN model_presets pr
               ON pr.id = COALESCE(
                   r.preset_id,
                   (SELECT d.id FROM model_presets d WHERE d.model_id = m.id AND d.is_default)
               )
           LEFT JOIN cache_presets cp ON cp.id = r.cache_preset_id
           WHERE "#, live_route_sql!(), r#"
           ORDER BY r.alias, r.priority DESC, r.weight DESC, r.id"#),
            "m",
            "s",
        ),
    ))
    .fetch_all(&mut *conn)
    .await?;
    let model_mappings = bake_known_non_reasoners(model_mappings);

    // Group routes by downstream provider_id for per-key model_map building.
    // We need provider_id→route mapping. Re-query to get provider_id per route.
    let route_provider_ids: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT r.id::text, r.provider_id::text
           FROM downstream_routes r
           WHERE r.enabled = true"#,
    )
    .fetch_all(&mut *conn)
    .await?;

    let route_to_provider: HashMap<String, String> = route_provider_ids.into_iter().collect();
    let mut routes_by_provider: HashMap<String, Vec<&EdgeModelMapping>> = HashMap::new();
    for m in &model_mappings {
        if let Some(provider_id) = route_to_provider.get(&m.id) {
            routes_by_provider
                .entry(provider_id.clone())
                .or_default()
                .push(m);
        }
    }

    // Fetch every API key with its owning user and workspace. A key is bound
    // to (user, workspace) only — the workspace allowlist gates which providers
    // and MCP servers the key may reach, evaluated per request at the proxy.
    // EVERY workspace — Default and the Agent workspace included — resolves
    // through its explicit allowlist rows; there is no wildcard. The agent is a
    // normal keyed workspace (its reach is the Agent workspace's grants).
    // `forward_auth` projects the per-key flag (`vk-*` → `true`, `sk-*` → `false`)
    // so the key's `UserContext` lands on the mount the route layer expects:
    // `sk-*` on `/v1/*` + `/mcp/<slug>`, `vk-*` on `/fwd/{key}/...`.
    #[allow(clippy::type_complexity)]
    let api_key_rows: Vec<(String, uuid::Uuid, uuid::Uuid, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, uuid::Uuid, uuid::Uuid, bool, Option<f64>, Option<f64>, String, Option<uuid::Uuid>, Option<uuid::Uuid>, bool)> = sqlx::query_as(
        r#"SELECT k.key_hash,
                  u.id as user_id, u.tenant_id, u.email, u.display_name,
                  k.expires_at, k.id as key_id, k.workspace_id, k.forward_auth,
                  k.daily_budget, k.monthly_budget, k.budget_mode,
                  k.downstream_provider_id,
                  k.qos_class_id, k.qos_class_elevated
           FROM api_keys k
           JOIN users u ON u.id = k.user_id
           WHERE k.revoked_at IS NULL
             AND u.is_active = true
           ORDER BY k.created_at, k.id"#
    )
    .fetch_all(&mut *conn)
    .await?;

    // BYOK downstreams (byok=true) → their pass-through binding: the linked
    // keyless upstream's primary endpoint + protocol. A `vk-*` key bound to one
    // of these (and granted to its workspace) passes an unconfigured model
    // through to this endpoint with the client's own forwarded credential.
    // Only an ENABLED server's: a disabled pass-through does not exist for the
    // gateway, so a key bound to it — or a grant of it — reaches nothing.
    #[allow(clippy::type_complexity)]
    let byok_rows: Vec<(uuid::Uuid, Option<String>, String, String, Option<String>, String)> =
        sqlx::query_as(concat!(
            r#"SELECT dp.id, "#, server_url_sql!("s"), r#", s.upstream_api_format, s.provider,
                      s.chat_endpoint_path, s.transport
           FROM downstream_providers dp
           JOIN upstream_servers s ON s.id = dp.upstream_server_id
           WHERE dp.byok = true AND s.enabled = true"#,
        ))
        .fetch_all(&mut *conn)
        .await?;
    let mut byok_downstream_info: HashMap<
        uuid::Uuid,
        streamscope_core::config::model_map::ByokPassthrough,
    > = HashMap::new();
    for (dp_id, url, fmt, provider_str, chat_endpoint_path, transport) in byok_rows {
        // Every enabled server has an enabled endpoint (the endpoint writes
        // refuse to leave it none); one without could not pass through.
        let Some(upstream_url) = url else {
            continue;
        };
        byok_downstream_info.insert(
            dp_id,
            streamscope_core::config::model_map::ByokPassthrough {
                provider: provider_str.clone(),
                upstream_url,
                upstream_api_format: Some(fmt),
                chat_endpoint_path,
                transport: streamscope_core::config::upstream_transport::UpstreamTransport::from(
                    transport,
                ),
                downstream_provider_id: dp_id.to_string(),
            },
        );
    }

    // Per-workspace allowlists — which providers / MCP virtual servers each
    // workspace may reach. The Default workspace is a normal workspace: it
    // appears here only for what an operator explicitly granted it. Provider
    // grants are the live ones (a pass-through's counts only while its server
    // is on).
    // Each list below is sorted: it reaches the body (and the provider order a
    // key's model map breaks ties by), and query order is no order.
    let mut downstream_access_rows: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        crate::routes::LIVE_PROVIDER_GRANTS,
    )
    .fetch_all(&mut *conn)
    .await?;
    downstream_access_rows.sort();
    let mut providers_by_workspace: HashMap<uuid::Uuid, Vec<uuid::Uuid>> = HashMap::new();
    for (ws, pid) in downstream_access_rows {
        providers_by_workspace.entry(ws).or_default().push(pid);
    }

    let mcp_access_rows: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        "SELECT workspace_id, virtual_server_id FROM workspace_mcp_access ORDER BY workspace_id, virtual_server_id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut mcp_servers_by_workspace: HashMap<uuid::Uuid, Vec<uuid::Uuid>> = HashMap::new();
    for (ws, vsid) in mcp_access_rows {
        mcp_servers_by_workspace.entry(ws).or_default().push(vsid);
    }

    let a2a_access_rows: Vec<(uuid::Uuid, uuid::Uuid)> =
        sqlx::query_as("SELECT workspace_id, agent_id FROM workspace_a2a_access ORDER BY workspace_id, agent_id")
            .fetch_all(&mut *conn)
            .await?;
    let mut a2a_agents_by_workspace: HashMap<uuid::Uuid, Vec<uuid::Uuid>> = HashMap::new();
    for (ws, aid) in a2a_access_rows {
        a2a_agents_by_workspace.entry(ws).or_default().push(aid);
    }

    // Org-total ceiling — the tenant's OWN cap, not to be confused with the
    // tenant's default budget (`crate::limits`), which is only the value a
    // workspace inherits when it sets none. Both windows unset (or 0) ⇒ the tenant is uncapped and
    // no tenant-scope counter is ever created for it.
    let tenant_daily_budget: f64 = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = 'tenant_daily_budget'",
    )
    .fetch_optional(&mut *conn)
    .await?
    .and_then(|v| v.as_f64())
    .unwrap_or(0.0);
    let tenant_monthly_budget: f64 = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = 'tenant_monthly_budget'",
    )
    .fetch_optional(&mut *conn)
    .await?
    .and_then(|v| v.as_f64())
    .unwrap_or(0.0);
    let tenant_budget_alert_only: bool = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = 'tenant_budget_mode'",
    )
    .fetch_optional(&mut *conn)
    .await?
    .and_then(|v| v.as_str().map(|s| s == "alert_only"))
    .unwrap_or(false);
    let tenant_budget = (tenant_daily_budget > 0.0 || tenant_monthly_budget > 0.0).then(|| {
        streamscope_core::auth::RateLimitConfig::budget_only(
            tenant_daily_budget,
            tenant_monthly_budget,
            tenant_budget_alert_only,
        )
    });

    // Workspace pools, resolved for EVERY workspace: an unset rate is
    // unlimited, an unset budget inherits the tenant default budget whether or
    // not the workspace ever saved its limits. A workspace absent from the map
    // is unlimited.
    let workspace_rate_limits = crate::limits::load_pools(&mut *conn).await?;

    // Workspaces the org-total budget does not see. Their keys are baked with NO
    // `tenant_budget`, which is what makes the exclusion whole rather than
    // half-applied: `buckets()` then skips the tenant bucket for both the check
    // and the accrual, so such a workspace is neither charged to the org ceiling
    // nor blocked by it. The set also ships on the snapshot, because the
    // spec-OAuth path mints its `UserContext` at request time from the claim's
    // workspace and has no baked key to read.
    let workspaces_outside_tenant_budget: std::collections::BTreeSet<uuid::Uuid> = sqlx::query_scalar(
        "SELECT id FROM workspaces WHERE NOT counts_toward_tenant_budget",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();

    // Member limits: each workspace's default plus the per-member exceptions.
    // Resolved per key below through the one core resolver, and shipped as-is
    // on the snapshot for the spec-OAuth path, which resolves them the same way.
    let member_limit_defaults = crate::limits::load_defaults(&mut *conn).await?;
    let member_limit_exceptions = crate::limits::load_exceptions(&mut *conn).await?;

    // Replica endpoints: each enabled server's enabled endpoints once, and a
    // member list only for a model not every one of them serves.
    let upstream_endpoints = crate::routes::upstream_endpoints::load_endpoint_table(&mut *conn).await?;
    let qos = crate::qos::load_qos_table(&mut *conn).await?;
    let web_destinations = crate::routes::destination_lists::web_lists(&mut *conn).await?;

    // Per-(workspace, kind) profile choices — folded into the per-workspace map
    // the proxy resolves per request. Only workspaces with a row for a kind
    // appear; the rest inherit the kind's tenant default on the proxy. A NULL
    // `profile_id` is an explicit Off (kind disabled for that workspace). RLS-
    // scoped via the tenant connection.
    let workspace_profiles: Vec<(uuid::Uuid, ProfileKind, Option<uuid::Uuid>)> =
        sqlx::query_as::<_, (uuid::Uuid, String, Option<uuid::Uuid>)>(
            "SELECT workspace_id, kind, profile_id FROM workspace_profile_assignments",
        )
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .filter_map(|(ws, kind, pid)| Some((ws, stored_kind(&kind)?, pid)))
        .collect();

    // Each kind's default profile — the fallback for a workspace with no explicit
    // selection for that kind (the Default workspace included).
    let default_profiles: Vec<(ProfileKind, uuid::Uuid)> = sqlx::query_as::<_, (String, uuid::Uuid)>(
        "SELECT kind, id FROM profiles WHERE tenant_id = $1 AND is_default = true",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .filter_map(|(kind, id)| Some((stored_kind(&kind)?, id)))
    .collect();

    // Each profile's inheritance mode (Default-as-base): the proxy buckets a
    // Layered profile as `Default ⊕ own` and a Standalone as `own`.
    let profile_modes: Vec<(uuid::Uuid, ProfileKind, bool)> = sqlx::query_as::<_, (uuid::Uuid, String, bool)>(
        "SELECT id, kind, standalone FROM profiles WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .filter_map(|(id, kind, standalone)| Some((id, stored_kind(&kind)?, standalone)))
    .collect();

    // The tenant's Default workspace, surfaced as `default_workspace_id` on the
    // snapshot (bookmark-stable scope for the portal / agent).
    let default_workspace_id: Option<uuid::Uuid> = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM workspaces WHERE tenant_id = $1 AND role = 'default'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;

    // The tenant's Inline AI workspace (at most one): a key minted there is
    // baked with `inline_ai = true`, which is the ONLY credential the proxy
    // accepts on `POST /v1/analyze` — and, carrying no provider grants, it can
    // reach nothing else.
    let inline_ai_workspace_id: Option<uuid::Uuid> = sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM workspaces WHERE tenant_id = $1 AND role = 'inline'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;

    // Build a `ModelMap` from a set of routes. The proxy gates the requested
    // model against this map, so a workspace's allowlist is enforced simply by
    // which providers' routes are folded in here.
    let build_model_map = |routes: &[&EdgeModelMapping]| -> ModelMap {
        let mut model_map = ModelMap::default();
        for m in routes {
            let model = if m.upstream_model.is_empty() {
                m.alias.clone()
            } else {
                m.upstream_model.clone()
            };
            let server_id = m.upstream_server_id.clone();
            model_map.mappings
                .entry(m.alias.clone())
                .or_default()
                .push(UpstreamModel {
                    provider: m.provider.clone(),
                    model,
                    zdr: false,
                    has_credential: m.encrypted_credential.is_some(),
                    context_window: m.context_window,
                    max_output_tokens: m.max_output_tokens,
                    client_context_window: m.client_context_window,
                    upstream_api_format: m.upstream_api_format.clone(),
                    chat_endpoint_path: m.chat_endpoint_path.clone(),
                    transport: m.transport,
                    scheduling_dialect: m.scheduling_dialect,
                    upstream_server_id: server_id,
                    downstream_provider_id: m.downstream_provider_id.clone(),
                    upstream_model_id: m.upstream_model_id.clone(),
                    priority: m.priority,
                    weight: m.weight,
                    supports_vision: m.supports_vision,
                    supports_reasoning: m.supports_reasoning,
                    supports_function_calling: m.supports_function_calling,
                    supports_caching: m.supports_caching,
                    supports_audio_input: m.supports_audio_input,
                    supports_audio_output: m.supports_audio_output,
                    supports_video_input: m.supports_video_input,
                    supports_pdf_input: m.supports_pdf_input,
                    supports_response_schema: m.supports_response_schema,
                    supports_system_messages: m.supports_system_messages,
                    healing_enabled: m.healing_enabled,
                    preset_settings: m.preset_settings.clone(),
                    route_id: Some(m.id.clone()),
                    cache: streamscope_core::proxy::response_cache::CachePolicy::from_parts(
                        m.cache_mode.as_deref(),
                        m.cache_ttl_seconds,
                        m.cache_threshold,
                        m.cache_share_scope.as_deref(),
                    ),
                    pricing: m.rates.clone(),
                });
        }
        // Sort by priority DESC within each alias.
        for targets in model_map.mappings.values_mut() {
            targets.sort_by_key(|t| std::cmp::Reverse(t.priority));
        }
        model_map
    };

    // Build one per-key `UserContext`. A key spans both `/v1/*` and `/mcp/<slug>`
    // (or `/fwd/...` when `forward_auth`); the workspace allowlist baked here is
    // the per-request gate. EVERY keyed workspace — Default and the Agent
    // workspace included — resolves through its explicit allowlist rows; there is
    // no wildcard. The agent is governed exactly like a normal workspace.
    let api_keys: Vec<EdgeApiKey> = api_key_rows
        .into_iter()
        .map(
            |(key_hash, user_id, user_tenant_id, email, display_name, expires_at, key_id, workspace_id, forward_auth, key_daily_budget, key_monthly_budget, key_budget_mode, bound_downstream_id, qos_class_id, qos_class_elevated)| {
                let granted = providers_by_workspace
                    .get(&workspace_id)
                    .cloned()
                    .unwrap_or_default();
                #[allow(clippy::type_complexity)]
                let (allowed_provider_ids, allowed_virtual_server_ids, model_map, byok_passthrough): (
                    Vec<uuid::Uuid>,
                    Vec<uuid::Uuid>,
                    ModelMap,
                    Vec<streamscope_core::config::model_map::ByokPassthrough>,
                ) = if forward_auth {
                    // Forward-auth (`vk-*`) key. Its LLM access comes ONLY from
                    // granted BYOK downstreams (LLM pass-through); without a grant
                    // it has no LLM access (empty map). MCP grants always apply, so
                    // an unbound `vk-` key still works for MCP bring-your-own-token.
                    let mcp_ids = mcp_servers_by_workspace
                        .get(&workspace_id)
                        .cloned()
                        .unwrap_or_default();
                    match bound_downstream_id {
                        // A single bound downstream: pass through to just that
                        // provider, and honor any override routes curated in it.
                        Some(dp) => {
                            match byok_downstream_info.get(&dp).filter(|_| granted.contains(&dp)) {
                                Some(pt) => {
                                    let routes: Vec<&EdgeModelMapping> = routes_by_provider
                                        .get(&dp.to_string())
                                        .cloned()
                                        .unwrap_or_default();
                                    (vec![dp], mcp_ids, build_model_map(&routes), vec![pt.clone()])
                                }
                                // Bound to a pass-through that is off → no LLM
                                // access. (Deleting a downstream revokes the keys
                                // bound to it first: the FK would null the binding
                                // and land the key in the unbound arm below.)
                                None => (Vec::new(), mcp_ids, ModelMap::default(), Vec::new()),
                            }
                        }
                        // No binding → a multi-provider inline key: every granted
                        // built-in BYOK downstream is a pass-through target, picked
                        // per request by (protocol, origin host). Pure pass-through,
                        // so no curated model_map.
                        None => {
                            let mut passthroughs: Vec<_> = granted
                                .iter()
                                .filter_map(|dp| byok_downstream_info.get(dp).cloned())
                                .collect();
                            // Stable order so passthrough selection doesn't depend on
                            // grant iteration order. (`select_byok_passthrough` takes an
                            // origin host as final — a host naming no entry is refused,
                            // never rerouted — and without one resolves a single entry
                            // or a UNIQUE protocol; an ambiguous hostless request is
                            // refused, not silently first-picked.)
                            passthroughs.sort_by(|a, b| {
                                (&a.upstream_url, &a.downstream_provider_id).cmp(&(&b.upstream_url, &b.downstream_provider_id))
                            });
                            (Vec::new(), mcp_ids, ModelMap::default(), passthroughs)
                        }
                    }
                } else {
                    let provider_ids = granted.clone();
                    let mut routes: Vec<&EdgeModelMapping> = Vec::new();
                    for pid in &provider_ids {
                        if let Some(provider_routes) = routes_by_provider.get(&pid.to_string()) {
                            routes.extend(provider_routes.iter().copied());
                        }
                    }
                    let mcp_ids = mcp_servers_by_workspace
                        .get(&workspace_id)
                        .cloned()
                        .unwrap_or_default();
                    (provider_ids, mcp_ids, build_model_map(&routes), Vec::new())
                };

                // Workspace bucket: the workspace's configured cap, shared
                // across its members (enforced keyed by workspace_id).
                // A workspace with no cap row → unlimited.
                let rate_limit = workspace_rate_limits
                    .get(&workspace_id)
                    .cloned()
                    .unwrap_or_else(streamscope_core::auth::RateLimitConfig::unlimited);
                // Member bucket: the workspace's default member limit,
                // replaced per metric by this member's exception; absent when
                // nothing limits the member. Enforced keyed by the membership.
                let user_rate_override = streamscope_core::auth::member_limits::resolve_member_limit(
                    member_limit_defaults.get(&workspace_id),
                    member_limit_exceptions.get(&(workspace_id, user_id)),
                );
                // Per-key budget bucket: baked only when this key carries an
                // explicit daily/monthly cap; enforced keyed by key_id (budget
                // only — no RPM/TPM). `budget_mode` flips enforce vs alert-only.
                let key_budget = match (key_daily_budget, key_monthly_budget) {
                    (None, None) => None,
                    (daily, monthly) => Some(streamscope_core::auth::RateLimitConfig::budget_only(
                        daily.unwrap_or(0.0),
                        monthly.unwrap_or(0.0),
                        key_budget_mode == "alert_only",
                    )),
                };

                let ctx = streamscope_core::auth::UserContext {
                    user_id,
                    tenant_id: user_tenant_id,
                    email,
                    display_name,
                    real_api_key: String::new(),
                    model_map: model_map.into(),
                    rate_limit,
                    user_rate_override,
                    key_budget,
                    // Same ceiling on every key of the tenant — the bucket is
                    // keyed by `tenant_id`, so the copies share one counter.
                    // Absent on a workspace the organisation does not fund, which
                    // is how that exclusion reaches every enforcement site at once.
                    tenant_budget: (!workspaces_outside_tenant_budget.contains(&workspace_id))
                        .then(|| tenant_budget.clone())
                        .flatten(),
                    expires_at,
                    key_id: Some(key_id),
                    app_id: None,
                    session_id: None,
                    workspace_id,
                    allowed_provider_ids,
                    allowed_virtual_server_ids,
                    // A2A grants apply to credential (`sk-`) keys only — the
                    // BYOT analog for A2A (a `vk-` key carrying its own agent
                    // credential) is not wired yet.
                    allowed_a2a_agent_ids: if forward_auth {
                        Vec::new()
                    } else {
                        a2a_agents_by_workspace
                            .get(&workspace_id)
                            .cloned()
                            .unwrap_or_default()
                    },
                    // An `sk-`/`vk-` key is not a spec-OAuth token, so it is
                    // bounded by its workspace grants rather than by a scope.
                    mcp_scope: None,
                    // Projected from `api_keys.forward_auth` so the edge's copy
                    // matches the on-disk shape; the `/fwd/{key}/...` mount is
                    // the load-bearing gate and `authenticate_forward` rejects
                    // a non-forward key on it.
                    forward_auth,
                    byok_passthrough,
                    inline_ai: Some(workspace_id) == inline_ai_workspace_id,
                    // The key's own class, as written. Whether it applies is
                    // decided per request against the workspace's class, so
                    // re-ranking a class or moving a workspace re-bakes nothing.
                    qos_class_id,
                    qos_class_elevated,
                };
                EdgeApiKey { key_hash, user_context: ctx }
            },
        )
        .collect();

    // Load system settings for edge config sync. A key only admin-api reads
    // (`config_admin_only_setting`, which the bump trigger and the settings
    // API read too) is in no body: shipping one rewritten on a timer or every
    // release would push the body to every edge each time.
    let settings_rows = sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT key, value FROM system_settings WHERE NOT config_admin_only_setting(key) ORDER BY key",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut settings: HashMap<String, serde_json::Value> = settings_rows.into_iter().collect();

    // `tool_rules` is no longer a `system_settings` row — it's the
    // `tool_policy_rules` table. Inject it into the settings map under the same
    // key + shape the proxy already reads (`{"rules": [...]}`), so the wire format
    // is unchanged. A read failure ABORTS the whole snapshot build (the tenant
    // stays dirty for retry, the proxy keeps its last-good config): an omitted key
    // would make the proxy silently fall back to the built-in default rule set,
    // swapping the tenant's real enforcement for defaults with no visible signal.
    let tool_rules = crate::routes::tool_rules::load_rules(conn, tenant_id)
        .await
        .map_err(|_| {
            tracing::error!(%tenant_id, "load tool rules for config snapshot failed");
            sqlx::Error::Protocol("failed to load tool rules for config snapshot".into())
        })?;
    settings.insert(
        "tool_rules".to_string(),
        serde_json::json!({ "rules": tool_rules }),
    );

    // `guardrail_profiles` is no longer a `system_settings` row — it's the
    // `guardrail_policies` table (one row per profile). Inject it under the same
    // key + shape the proxy already reads (`{ "<profile_id>": <GuardrailPolicy> }`),
    // so the wire format is unchanged. A read failure ABORTS the snapshot build
    // (the tenant stays dirty for retry) rather than shipping an empty map that
    // would silently revert every profile to the default guardrail posture. An
    // empty result omits the key (the proxy treats absent as "all default", the
    // same as a tenant that has authored no policies).
    let guardrail_policies = crate::routes::guardrail::load_all_policies(conn, tenant_id)
        .await
        .map_err(|_| {
            tracing::error!(%tenant_id, "load guardrail policies for config snapshot failed");
            sqlx::Error::Protocol("failed to load guardrail policies for config snapshot".into())
        })?;
    if !guardrail_policies.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = guardrail_policies
            .into_iter()
            .filter_map(|(pid, p)| Some((pid.to_string(), serde_json::to_value(p).ok()?)))
            .collect();
        settings.insert(
            "guardrail_profiles".to_string(),
            serde_json::Value::Object(map),
        );
    }

    // `app_registry` is no longer a `system_settings` row — it's the `apps`
    // table. Inject it under the same key + shape the proxy reads (an array of
    // AppInfo) for request attribution. Best-effort: app attribution degrades
    // gracefully (it never blocks a request), so a load error / empty set just
    // omits the key rather than aborting the snapshot.
    let apps = crate::routes::analytics::load_apps_snapshot(conn, tenant_id).await;
    if !apps.is_empty()
        && let Ok(value) = serde_json::to_value(&apps)
    {
        settings.insert("app_registry".to_string(), value);
    }

    // `tool_field_profiles` is no longer a `system_settings` row — it's the
    // `tool_field_profiles` table. Inject it under the same key + shape the proxy
    // reads (a JSON array of FieldProfile). A read failure ABORTS the snapshot
    // build (the tenant stays dirty for retry) rather than shipping an empty set
    // that would silently drop the tenant's arg-field canonicalisation.
    let field_profiles =
        crate::routes::tool_field_profiles::load_profiles(conn, tenant_id)
            .await
            .map_err(|_| {
                tracing::error!(%tenant_id, "load tool field profiles for config snapshot failed");
                sqlx::Error::Protocol(
                    "failed to load tool field profiles for config snapshot".into(),
                )
            })?;
    if !field_profiles.is_empty()
        && let Ok(value) = serde_json::to_value(&field_profiles)
    {
        settings.insert("tool_field_profiles".to_string(), value);
    }

    // Fetch route policies and inject into settings as JSON.
    // Format: {"<downstream_provider_id>": [{"path_pattern": "...", ...}, ...]}
    // The proxy reads this from settings["route_policies"].
    let route_policy_rows: Vec<(sqlx::types::Uuid, String, bool, Option<i32>, i64, bool)> = sqlx::query_as(
        r#"SELECT downstream_id, path_pattern, enabled, rate_limit_rpm, max_body_bytes, audit_body
           FROM route_policies
           WHERE tenant_id = $1
           ORDER BY downstream_id, path_pattern"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    if !route_policy_rows.is_empty() {
        let mut by_downstream: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        for (downstream_id, path_pattern, enabled, rate_limit_rpm, max_body_bytes, audit_body) in route_policy_rows {
            by_downstream
                .entry(downstream_id.to_string())
                .or_default()
                .push(serde_json::json!({
                    "path_pattern": path_pattern,
                    "enabled": enabled,
                    "rate_limit_rpm": rate_limit_rpm,
                    "max_body_bytes": max_body_bytes,
                    "audit_body": audit_body,
                }));
        }
        settings.insert(
            "route_policies".to_string(),
            serde_json::to_value(by_downstream).unwrap_or_default(),
        );
    }

    // Fetch active transform programs, ordered by priority.
    let transform_programs = sqlx::query_as::<_, (String, String, String, String, String, i32, bool, i32, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>(
        r#"SELECT id::text, name, source, phase, scope, priority, enabled, version, model_filter, app_filter, trigger_regex, match_mode, profile_id::text
           FROM transform_programs
           WHERE enabled = true AND NOT suppressed
           ORDER BY priority, name"#,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|(id, name, source, phase, scope, priority, enabled, version, model_filter, app_filter, trigger_regex, match_mode, profile_id)| {
        EdgeTransformProgram { id, name, source, phase, scope, priority, enabled, version, model_filter, app_filter, trigger_regex, match_mode, profile_id }
    })
    .collect::<Vec<_>>();

    // ── MCP gateway tables — synced verbatim. ──────────────────────────────
    // RLS not yet set on this connection; the explicit `WHERE tenant_id = $1`
    // matches the pattern used elsewhere in this snapshot builder.
    let mcp_upstream_servers = sqlx::query_as::<_, EdgeMcpUpstreamServer>(
        r#"SELECT id, tenant_id, name, description, upstream_url, transport,
                  auth_mode, cred_version,
                  -- BYTEA holds the base64 ciphertext as UTF-8 bytes;
                  -- convert::TEXT to round-trip through the tenant body.
                  convert_from(encrypted_credential, 'UTF8') AS encrypted_credential,
                  -- OAuth client config. Endpoint URLs are plaintext;
                  -- the client secret is BYTEA holding base64-encoded ciphertext.
                  oauth_issuer_url,
                  oauth_authorization_url,
                  oauth_token_url,
                  oauth_revocation_url,
                  oauth_client_id,
                  convert_from(encrypted_oauth_client_secret, 'UTF8') AS encrypted_oauth_client_secret,
                  COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
                  enabled, connect_timeout_ms, request_timeout_ms
           FROM mcp_upstream_servers
           WHERE tenant_id = $1
           ORDER BY name"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    // Per-user OAuth credentials for this tenant. Encrypted at rest;
    // proxy decrypts on-use. We round-trip the BYTEA through `convert_from`
    // (same shape as `encrypted_credential`) so the tenant body is JSON-safe.
    let mcp_user_credentials = sqlx::query_as::<_, EdgeMcpUserCredential>(
        r#"SELECT tenant_id, user_id, upstream_server_id,
                  convert_from(encrypted_access_token,  'UTF8') AS encrypted_access_token,
                  convert_from(encrypted_refresh_token, 'UTF8') AS encrypted_refresh_token,
                  expires_at, scope
           FROM mcp_user_credentials
           WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    let mcp_virtual_servers = sqlx::query_as::<_, EdgeMcpVirtualServer>(
        r#"SELECT id, tenant_id, slug, name, description,
                  display_title, website_url,
                  enabled, oauth_enabled,
                  sampling_intercept_enabled,
                  -- BYTEA holds the base64 ciphertext as UTF-8 bytes;
                  -- convert::TEXT to round-trip through the tenant body.
                  convert_from(sampling_credential, 'UTF8') AS sampling_credential,
                  sampling_model_alias
           FROM mcp_virtual_servers
           WHERE tenant_id = $1
           ORDER BY slug"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    let mcp_virtual_routes = sqlx::query_as::<_, EdgeMcpVirtualRoute>(
        r#"SELECT id, tenant_id, virtual_server_id, upstream_server_id,
                  prefix, tools_filter, resources_filter, prompts_filter,
                  enabled, position
           FROM mcp_virtual_routes
           WHERE tenant_id = $1
           ORDER BY virtual_server_id, position"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    // ── A2A gateway tables — synced verbatim. ──────────────────────────────
    let a2a_agents = sqlx::query_as::<_, EdgeA2aAgent>(
        r#"SELECT id, tenant_id, name, description, slug, agent_url, agent_card,
                  card_fetched_at, auth_mode,
                  -- BYTEA holds the base64 ciphertext as UTF-8 bytes;
                  -- convert::TEXT to round-trip through the tenant body.
                  convert_from(encrypted_credential, 'UTF8') AS encrypted_credential,
                  credential_header, enabled
           FROM a2a_upstream_agents
           WHERE tenant_id = $1
           ORDER BY slug"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    // Every revoked MCP jti, expired or not: the proxy's validator rejects on
    // `exp` before it consults this set, so an expired entry is harmless, and
    // the issued-token cleanup bounds the list. No clock is read here — two
    // replicas building the same rows must ship the same body.
    let mcp_revoked_jtis: Vec<uuid::Uuid> = sqlx::query_scalar(
        r#"SELECT jti
           FROM oauth_issued_tokens
           WHERE tenant_id = $1
             AND surface = 'mcp'
             AND revoked_at IS NOT NULL
           ORDER BY jti"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await?;

    // The tenant's public verification keys, for every generation this replica's
    // ring carries. The proxy has no signing secret, so a token it should accept
    // is only acceptable if the generation that signed it appears here — which
    // is why this ships the whole ring rather than the active generation alone.
    //
    // Derived, not stored: the ring is a pure function of the process's
    // AUTH_SECRET, so there is no table to keep in step and no way for a
    // published key to outlive the secret behind it. The cost is that the set
    // reflects *this* replica's env, which is what the staged rotation in
    // `streamscope_mcp_auth::keys` exists to make safe across a rolling restart.
    // An absent ring ABORTS the build (the cache keeps the previous body and
    // the next refresh retries) rather than shipping an empty key set: an empty
    // list is indistinguishable, at the proxy, from "this tenant has no keys",
    // so it would silently disable MCP OAuth for the tenant, and the digest of
    // that body would stand until an unrelated config change. Unreachable today — `validate_env_secrets`
    // gates boot — which is exactly why it must fail loudly rather than degrade.
    let mcp_jwks = streamscope_mcp_auth::Keyring::from_env()
        .map(|ring| ring.public_jwks(&tenant_id.to_string()))
        .ok_or_else(|| {
            tracing::error!(
                tenant_id = %tenant_id,
                "AUTH_SECRET unavailable — aborting config snapshot build rather than \
                 publishing an empty MCP verification key set"
            );
            sqlx::Error::Protocol("AUTH_SECRET unavailable for MCP key publication".into())
        })?;

    // Resolve every public-facing URL with the SYSTEM-default-with-tenant-
    // override layering. The proxy never sees the raw layers — admin-api
    // collapses them here at snapshot time. `system_settings` is RLS-scoped
    // per tenant_id, so each layer is read under its own `app.tenant_id` GUC
    // on the existing tenant-scoped connection: the tenant's rows first, then
    // SYSTEM's (the defaults) in one borrow.
    const PUBLIC_URLS: [&str; 3] = ["proxy_public_url", "admin_public_url", "api_public_url"];
    let read_keys = async |conn: &mut Scoped,
                           scope: uuid::Uuid,
                           keys: &[&str]|
     -> Result<HashMap<String, serde_json::Value>, sqlx::Error> {
        let rows: Vec<(String, serde_json::Value)> =
            sqlx::query_as("SELECT key, value FROM system_settings WHERE tenant_id = $1 AND key = ANY($2)")
                .bind(scope)
                .bind(keys)
                .fetch_all(&mut *conn)
                .await?;
        Ok(rows.into_iter().collect())
    };
    let own = read_keys(&mut *conn, tenant_id, &PUBLIC_URLS).await?;
    let system = crate::db::tenant::with_system_scope(&mut *conn, async |c| {
        read_keys(c, TenantId::SYSTEM.as_uuid(), &PUBLIC_URLS).await
    })
    .await?;
    let pick = |v: Option<&serde_json::Value>| -> Option<String> {
        v.and_then(|x| x.as_str())
            .map(|s| s.trim_end_matches('/'))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let layered = |key: &str| pick(own.get(key)).or_else(|| pick(system.get(key)));
    let proxy_public_url = layered("proxy_public_url");
    let admin_public_url = layered("admin_public_url");
    let api_public_url = layered("api_public_url");

    tracing::debug!(
        model_mappings = model_mappings.len(),
        api_keys = api_keys.len(),
        settings = settings.len(),
        transform_programs = transform_programs.len(),
        mcp_upstream_servers = mcp_upstream_servers.len(),
        mcp_virtual_servers = mcp_virtual_servers.len(),
        mcp_virtual_routes = mcp_virtual_routes.len(),
        mcp_user_credentials = mcp_user_credentials.len(),
        a2a_agents = a2a_agents.len(),
        proxy_public_url = ?proxy_public_url,
        admin_public_url = ?admin_public_url,
        api_public_url = ?api_public_url,
        "built config snapshot"
    );

    let mut body = ConfigResponse {
        tenant_slug,
        model_mappings,
        api_keys,
        settings,
        transform_programs,
        mcp_upstream_servers,
        mcp_virtual_servers,
        mcp_virtual_routes,
        mcp_user_credentials,
        mcp_revoked_jtis,
        mcp_jwks,
        a2a_agents,
        workspace_rate_limits,
        tenant_budget,
        workspaces_outside_tenant_budget,
        member_limit_exceptions: member_limit_exceptions
            .into_iter()
            .map(|((workspace_id, user_id), limits)| {
                streamscope_core::auth::member_limits::MemberLimitException { workspace_id, user_id, limits }
            })
            .collect(),
        member_limit_defaults,
        upstream_endpoints,
        qos,
        web_destinations,
        proxy_public_url,
        admin_public_url,
        api_public_url,
        default_workspace_id,
        workspace_profiles,
        default_profiles,
        profile_modes,
    };
    body.canonicalize();
    Ok(body)
}

/// A stored profile `kind` this release knows and sends to an edge
/// ([`ProfileKind::on_edge`]). A row of another kind — left by a newer release,
/// read after a rollback — is not sent: an edge refuses a body naming a kind it
/// does not know. An unknown kind is logged once per kind per process: every
/// build reads the rows again.
fn stored_kind(kind: &str) -> Option<ProfileKind> {
    static LOGGED: std::sync::LazyLock<std::sync::Mutex<std::collections::BTreeSet<String>>> =
        std::sync::LazyLock::new(Default::default);
    let known = ProfileKind::parse(kind);
    if known.is_none() && LOGGED.lock().unwrap_or_else(|e| e.into_inner()).insert(kind.to_string()) {
        tracing::warn!(kind, "config body: profile rows of an unknown kind are left out");
    }
    known.filter(|k| k.on_edge())
}

/// A model the catalog carries without marking it as reasoning is baked as a
/// KNOWN non-reasoner (`ModelCapabilities::edge_reasoning_flag`); a model no
/// catalog row matched stays undeclared, and the proxy's translation sends
/// reasoning to it (`ModelCapabilities::accepts_reasoning`). An operator's
/// explicit value always wins — it is already in the COALESCE.
fn bake_known_non_reasoners(mut mappings: Vec<EdgeModelMapping>) -> Vec<EdgeModelMapping> {
    for m in &mut mappings {
        m.supports_reasoning =
            streamscope_core::proxy::routing::ModelCapabilities::edge_reasoning_flag(m.supports_reasoning, m.catalog_matched);
    }
    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tables_scanned_since_the_baseline_and_outside_the_lists_are_reported() {
        let before: ScanCounts = [("edge_nodes".into(), 3), ("users".into(), 1), ("config_bumps".into(), 0)].into();
        let after: ScanCounts = [
            ("edge_nodes".into(), 3),   // scanned before the build only
            ("users".into(), 2),        // a body table
            ("config_bumps".into(), 1), // read by the caller itself
            ("notifications".into(), 1),
            ("admin_accounts".into(), 4),
        ]
        .into();
        assert_eq!(scanned_outside(&before, &after, &["config_bumps"]), ["admin_accounts", "notifications"]);
        assert!(scanned_outside(&after, &after, &[]).is_empty());
    }
}
