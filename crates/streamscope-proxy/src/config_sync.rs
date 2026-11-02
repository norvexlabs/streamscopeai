//! Applies tenant config bodies to proxy state — the snapshot restored from disk
//! at boot, then each change a sync answer brings (`sync_v2`). A body carries
//! model mappings, API keys, transform programs, and tenant settings.
//! Each is unpacked into one [`TenantConfig`](streamscope_core::config::TenantConfig)
//! — keys and opened credentials included — published in the [`TenantRegistry`]
//! the proxy reads on every request. Pricing is carried on each model mapping entry.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use streamscope_core::config::model_map::{ModelMap, UpstreamModel};
use streamscope_core::config::{TenantId, TenantRegistry};

pub use streamscope_edge_api::config::{ConfigResponse, EdgeTransformProgram, MultiTenantConfigResponse};
#[cfg(test)]
use streamscope_edge_api::config::{EdgeApiKey, EdgeModelMapping};

/// Convert edge transform programs to core TransformProgram structs.
pub fn convert_transform_programs(
    programs: &[EdgeTransformProgram],
) -> Vec<streamscope_core::scripting::TransformProgram> {
    programs
        .iter()
        .map(|p| streamscope_core::scripting::TransformProgram {
            id: p.id.clone(),
            name: p.name.clone(),
            source: p.source.clone(),
            phase: p.phase.clone(),
            scope: p.scope.clone(),
            priority: p.priority,
            enabled: p.enabled,
            version_hash: format!("v{}", p.version),
            model_filter: p.model_filter.clone(),
            app_filter: p.app_filter.clone(),
            trigger_regex: p.trigger_regex.clone(),
            match_mode: p.match_mode.clone(),
            // A malformed profile id from the wire degrades to shared rather than
            // failing the whole snapshot (mirrors the tool-rule kind parse).
            profile_id: p
                .profile_id
                .as_deref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok()),
        })
        .collect()
}

/// Every stored upstream credential one tenant's snapshot carries, as (server
/// id, ciphertext): each routed model's server credential, and each read
/// server's from the endpoint table — which reaches a server none of whose
/// models is routed. Both name a server's credential by its id, so a server
/// carried by several models, or by both, lands once — and is decrypted once.
fn snapshot_credentials(resp: &ConfigResponse) -> HashMap<String, &str> {
    let routed = resp.model_mappings.iter().filter_map(|m| {
        Some((m.upstream_server_id.clone()?, m.encrypted_credential.as_deref()?))
    });
    let read = resp
        .upstream_endpoints
        .read_credentials
        .iter()
        .map(|(server, c)| (server.to_string(), c.encrypted.as_str()));
    routed.chain(read).collect()
}

/// The largest media blob cap a tenant may set, in MiB: the platform's
/// (`EDGE_BLOB_MAX_MB`). A blob the edge could capture but admin-api would
/// refuse would vanish from the audit trail, so a higher setting is held here
/// and a larger blob is recorded as stripped.
pub(crate) fn blob_max_mb() -> u64 {
    streamscope_core::settings::core_settings().edge_blob_max_mb
}

/// Parsed settings values held once for every tenant whose body carries the
/// same bytes: every tenant carries the same seeded builtins, and parsing them
/// per tenant would hold a thousand copies. Keyed by the value's digest; an
/// entry no tenant holds any more is dropped as the map grows.
struct Interned<T: ?Sized> {
    by_digest: std::sync::Mutex<std::collections::BTreeMap<streamscope_edge_api::digest::Digest, std::sync::Weak<T>>>,
}

impl<T: ?Sized> Interned<T> {
    const fn new() -> Self {
        Self { by_digest: std::sync::Mutex::new(std::collections::BTreeMap::new()) }
    }

    fn get_or_parse<P: Into<std::sync::Arc<T>>>(&self, value: &serde_json::Value, parse: impl FnOnce() -> P) -> std::sync::Arc<T> {
        let Ok(digest) = streamscope_edge_api::digest::digest_of(value) else {
            return parse().into();
        };
        let lock = || self.by_digest.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = lock().get(&digest).and_then(std::sync::Weak::upgrade) {
            return held;
        }
        // Parsed outside the lock; two tenants parsing one value at once keep
        // whichever lands last, and the other copy goes with its tenant.
        let parsed: std::sync::Arc<T> = parse().into();
        let mut map = lock();
        // A value no tenant holds any more is let go with each new one: a
        // dead entry keeps its allocation. Few values are distinct, so this
        // stays cheap.
        map.retain(|_, w| w.strong_count() > 0);
        map.insert(digest, std::sync::Arc::downgrade(&parsed));
        parsed
    }
}

static FIELD_PROFILES: Interned<streamscope_core::config::tool_rules::FieldProfileSet> = Interned::new();
static APP_PATTERNS: Interned<[streamscope_core::config::AppPattern]> = Interned::new();

/// Build a `TenantConfig` from a per-tenant `ConfigResponse`.
fn build_tenant_config(resp: &ConfigResponse) -> streamscope_core::config::TenantConfig {
    // Build model map from ALL mappings (no tenant_id filtering — each ConfigResponse
    // is already scoped to one tenant in the multi-tenant format).
    let mut mappings: HashMap<String, Vec<UpstreamModel>> = HashMap::new();
    for m in &resp.model_mappings {
        let model = if m.upstream_model.is_empty() {
            m.alias.clone()
        } else {
            m.upstream_model.clone()
        };
        let server_id = m.upstream_server_id.clone();
        mappings
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
    // Sort each alias's targets by priority DESC (highest first).
    for targets in mappings.values_mut() {
        targets.sort_by_key(|t| std::cmp::Reverse(t.priority));
    }
    let model_map = ModelMap { mappings };

    let s = &resp.settings;

    // Snapshot semantics: every `system_settings` row is shipped as a key in
    // `resp.settings`. A row that has been deleted is simply *absent*. The
    // proxy must treat absent keys as "reset to struct default" — falling
    // back to the previous `TenantConfig` would silently pin a deleted setting
    // to its last-pushed value forever. `defaults` is the single source of
    // truth for setting-driven fields.
    let defaults = streamscope_core::config::TenantConfig::default();

    // Build transform programs for this tenant.
    let transform_programs = convert_transform_programs(&resp.transform_programs);

    // Parse catch-all route policies from settings.
    // Stored as JSON: {"<downstream_provider_id>": [{"path_pattern": "...", ...}, ...]}
    let route_policies: HashMap<uuid::Uuid, Vec<streamscope_core::config::RoutePolicy>> = s
        .get("route_policies")
        .and_then(|v| {
            // Value might be a JSON string or already an object.
            let obj = if v.is_string() {
                serde_json::from_str(v.as_str()?).ok()
            } else {
                serde_json::from_value::<HashMap<String, Vec<streamscope_core::config::RoutePolicy>>>(v.clone()).ok()
            };
            obj.map(|map| {
                map.into_iter()
                    .filter_map(|(k, v)| {
                        uuid::Uuid::parse_str(&k).ok().map(|id| (id, v))
                    })
                    .collect()
            })
        })
        .unwrap_or_default();

    // Parse the tenant rule pool once so we can both store it and pre-bucket it
    // by profile for the per-request hot path.
    let tool_rules: Vec<streamscope_core::config::tool_rules::Rule> = s
        .get("tool_rules")
        .and_then(|v| v.get("rules"))
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| match serde_json::from_value::<streamscope_core::config::tool_rules::Rule>(v.clone()) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::warn!(error = %e, raw = %v, "skipping tool_rules rule that failed to deserialize");
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| defaults.tool_rules.clone());
    use streamscope_core::config::{ProfileKind, WorkspaceProfile};
    // Generic (workspace, kind) → choice and kind → default maps. A wire
    // `None` profile_id is an explicit Off; `Some` selects a profile.
    let workspace_profiles: std::collections::HashMap<(uuid::Uuid, ProfileKind), WorkspaceProfile> = resp
        .workspace_profiles
        .iter()
        .map(|(ws, kind, pid)| {
            let choice = match pid {
                Some(id) => WorkspaceProfile::Use(*id),
                None => WorkspaceProfile::Off,
            };
            ((*ws, *kind), choice)
        })
        .collect();
    let default_profiles: std::collections::HashMap<ProfileKind, uuid::Uuid> =
        resp.default_profiles.iter().map(|(kind, pid)| (*kind, *pid)).collect();

    // Profiles flagged Standalone (own content only; ignore the Default). Profile
    // ids are globally unique, so one set across kinds suffices for bucketing.
    // The Default profile is itself standalone (it is the base).
    let standalone_ids: std::collections::HashSet<uuid::Uuid> = resp
        .profile_modes
        .iter()
        .filter(|(_, _, standalone)| *standalone)
        .map(|(id, _, _)| *id)
        .collect();

    // Profiles of a given kind any workspace can resolve to: the ones explicitly
    // selected for that kind (Off contributes none) ∪ the kind's tenant default.
    let reachable_of_kind = |kind: ProfileKind| -> Vec<uuid::Uuid> {
        let mut ids: std::collections::HashSet<uuid::Uuid> = workspace_profiles
            .iter()
            .filter(|((_, k), _)| *k == kind)
            .filter_map(|(_, choice)| match choice {
                WorkspaceProfile::Use(p) => Some(*p),
                WorkspaceProfile::Off => None,
            })
            .collect();
        if let Some(d) = default_profiles.get(&kind) {
            ids.insert(*d);
        }
        ids.into_iter().collect()
    };

    // Tools: each reachable tool profile is bucketed Default-as-base — a Layered
    // profile gets the Default's rules ⊕ its own; a Standalone gets its own.
    let tool_rules_by_profile = streamscope_core::config::TenantConfig::build_profile_buckets(
        &tool_rules,
        &reachable_of_kind(ProfileKind::Tools),
        default_profiles.get(&ProfileKind::Tools).copied(),
        &standalone_ids,
    );

    // Transforms: same Default-as-base bucketing (the full flat list stays on
    // `transform_programs` for the script-engine warm-up).
    let transform_programs_by_profile =
        streamscope_core::config::TenantConfig::build_transform_buckets(
            &transform_programs,
            &reachable_of_kind(ProfileKind::Transform),
            default_profiles.get(&ProfileKind::Transform).copied(),
            &standalone_ids,
        );

    // Guardrail: the tenant-wide backend (`system_settings.guardrail`, a
    // `GuardrailBackendSettings`) folded with each reachable guardrail
    // profile's policy (`system_settings.guardrail_profiles[<id>]`, default when
    // absent) into one resolved `GuardrailSettings` per profile.
    let (guardrail_by_profile, guardrail_default) = {
        // Backend.
        let backend = s
            .get("guardrail")
            .and_then(|v| match serde_json::from_value::<
                streamscope_core::guardrail::GuardrailBackendSettings,
            >(v.clone())
            {
                Ok(b) => Some(b),
                Err(e) => {
                    tracing::warn!(error = %e, raw = %v, "skipping invalid guardrail backend settings");
                    None
                }
            })
            .unwrap_or_default();
        // Per-profile policy map (id → GuardrailPolicy); absent/invalid → none.
        let policies: std::collections::HashMap<uuid::Uuid, streamscope_core::guardrail::GuardrailPolicy> = s
            .get("guardrail_profiles")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| {
                        let id = uuid::Uuid::parse_str(k).ok()?;
                        match serde_json::from_value::<streamscope_core::guardrail::GuardrailPolicy>(v.clone()) {
                            Ok(p) => Some((id, p)),
                            Err(e) => {
                                tracing::warn!(error = %e, profile = %k, "skipping invalid guardrail policy");
                                None
                            }
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Resolve a profile's policy under the Default-as-base model. The Default
        // (and any Standalone) uses its own row, falling back to the default
        // policy when absent. A Layered profile with no own row INHERITS the
        // Default guardrail profile's policy (its diff is whole-policy: inherit, or
        // carry a full own row that overrides).
        let default_guardrail_id = default_profiles.get(&ProfileKind::Guardrail).copied();
        let policy_for = |pid: &uuid::Uuid| -> streamscope_core::guardrail::GuardrailPolicy {
            if let Some(own) = policies.get(pid) {
                return own.clone();
            }
            let is_layered =
                Some(*pid) != default_guardrail_id && !standalone_ids.contains(pid);
            if is_layered
                && let Some(did) = default_guardrail_id
                && let Some(def) = policies.get(&did)
            {
                return def.clone();
            }
            streamscope_core::guardrail::GuardrailPolicy::default()
        };
        // Bucket every reachable guardrail profile (default ∪ assigned), even if it
        // has no stored policy (→ inherited/default), mirroring tool buckets.
        let by_profile: std::collections::HashMap<uuid::Uuid, streamscope_core::guardrail::GuardrailSettings> =
            reachable_of_kind(ProfileKind::Guardrail)
                .iter()
                .map(|pid| {
                    (
                        *pid,
                        streamscope_core::guardrail::GuardrailSettings::resolve(&backend, &policy_for(pid)),
                    )
                })
                .collect();
        // Fallback for a workspace that resolves to no guardrail profile: backend
        // folded with the default profile's policy (or a default policy).
        let default = match default_guardrail_id {
            Some(pid) => streamscope_core::guardrail::GuardrailSettings::resolve(&backend, &policy_for(&pid)),
            None => streamscope_core::guardrail::GuardrailSettings::resolve(
                &backend,
                &streamscope_core::guardrail::GuardrailPolicy::default(),
            ),
        };
        (by_profile, default)
    };

    streamscope_core::config::TenantConfig {
        model_map,
        audit_enabled: setting_bool(s, "audit_enabled")
            .unwrap_or(defaults.audit_enabled),
        debug_mode: setting_bool(s, "debug_mode")
            .unwrap_or(defaults.debug_mode),
        healing_enabled: setting_bool(s, "healing_enabled")
            .unwrap_or(defaults.healing_enabled),
        stream_idle_timeout_secs: setting_u64(s, "stream_idle_timeout_secs")
            .unwrap_or(defaults.stream_idle_timeout_secs),
        content_logging_enabled: setting_bool(s, "content_logging_enabled")
            .unwrap_or(defaults.content_logging_enabled),
        sanitize_tool_names: setting_bool(s, "sanitize_tool_names")
            .unwrap_or(defaults.sanitize_tool_names),
        rhai_fail_mode: setting_str(s, "rhai_fail_mode")
            .unwrap_or_else(|| defaults.rhai_fail_mode.clone()),
        log_level: setting_str(s, "log_level")
            .unwrap_or_else(|| defaults.log_level.clone()),
        tool_rules,
        // `tool_field_profiles` ships as a flat JSON array (whatever the
        // admin shoves in `system_settings`). Same drop-bad-entries discipline
        // as rules — one malformed profile shouldn't break the whole tenant.
        tool_field_profiles: match s.get("tool_field_profiles").filter(|v| v.is_array()) {
            Some(v) => FIELD_PROFILES.get_or_parse(v, || {
                let parsed: Vec<streamscope_core::config::tool_rules::FieldProfile> = v
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| match serde_json::from_value::<streamscope_core::config::tool_rules::FieldProfile>(v.clone()) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            tracing::warn!(error = %e, raw = %v, "skipping tool_field_profile that failed to deserialize");
                            None
                        }
                    })
                    .collect();
                streamscope_core::config::tool_rules::FieldProfileSet::new(parsed)
            }),
            None => defaults.tool_field_profiles.clone(),
        },
        workspace_profiles,
        default_profiles,
        tool_rules_by_profile,
        app_patterns: match s.get("app_registry") {
            Some(v) => APP_PATTERNS.get_or_parse(v, || parse_app_patterns(v)),
            None => defaults.app_patterns.clone(),
        },
        transform_programs,
        transform_programs_by_profile,
        route_policies,
        media_blob_storage_enabled: setting_bool(s, "media_blob_storage_enabled")
            .unwrap_or(defaults.media_blob_storage_enabled),
        media_blob_max_size_mb: setting_u64(s, "media_blob_max_size_mb")
            .unwrap_or(defaults.media_blob_max_size_mb)
            .min(blob_max_mb()),
        mcp: build_mcp_config(resp),
        a2a: build_a2a_config(resp),
        tenant_slug: resp.tenant_slug.clone(),
        workspace_rate_limits: resp.workspace_rate_limits.clone(),
        tenant_budget: resp.tenant_budget.clone(),
        workspaces_outside_tenant_budget: resp.workspaces_outside_tenant_budget.iter().copied().collect(),
        member_limit_defaults: resp.member_limit_defaults.clone(),
        member_limit_exceptions: resp
            .member_limit_exceptions
            .iter()
            .map(|e| ((e.workspace_id, e.user_id), e.limits.clone()))
            .collect(),
        endpoints: resp.upstream_endpoints.clone(),
        qos: resp.qos.clone(),
        // `web` ships as one nested JSON object under the
        // `system_settings.web` key (same pattern as `tool_rules` /
        // `tool_field_profiles`). Single deserialize; bad / absent settings
        // fall back to the struct default so a malformed entry can't break
        // tenant routing and a deleted row doesn't pin the last-pushed value
        // forever.
        web: s
            .get("web")
            .and_then(|v| {
                match serde_json::from_value::<
                    streamscope_core::web::WebSettings,
                >(v.clone())
                {
                    Ok(ws) => Some(ws),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            raw = %v,
                            "skipping invalid web settings"
                        );
                        None
                    }
                }
            })
            .map(|mut ws| {
                // The attached destination lists ride beside the settings.
                ws.destinations = streamscope_core::web::WebDestinations::from_lists(&resp.web_destinations);
                ws
            })
            .unwrap_or_else(|| streamscope_core::web::WebSettings {
                destinations: streamscope_core::web::WebDestinations::from_lists(&resp.web_destinations),
                ..defaults.web.clone()
            }),
        // Tenant-wide response-cache settings, one nested JSON object under the
        // `system_settings.cache` key — same single-deserialize shape as `web`.
        // A malformed or absent entry falls back to the struct default rather
        // than breaking routing.
        cache: s
            .get("cache")
            .and_then(|v| {
                match serde_json::from_value::<
                    streamscope_core::proxy::response_cache::CacheSettings,
                >(v.clone())
                {
                    Ok(cs) => Some(cs),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            raw = %v,
                            "skipping invalid response-cache settings"
                        );
                        None
                    }
                }
            })
            .unwrap_or_else(|| defaults.cache.clone()),
        // Tenant accounting currency + the operator's conversion table, one
        // nested JSON object under the `system_settings.pricing` key — same
        // single-deserialize shape as `web` and `cache`. A malformed entry falls
        // back to the default (dollars, no conversions) rather than breaking
        // routing; a model quoted in a currency that then has no rate is billed
        // as unstated and badged, which is visible, where a broken fold that
        // guessed dollars would not be.
        pricing: s
            .get("pricing")
            .and_then(|v| {
                match serde_json::from_value::<streamscope_core::pricing::PricingSettings>(
                    v.clone(),
                ) {
                    Ok(ps) => Some(ps),
                    Err(e) => {
                        tracing::warn!(error = %e, raw = %v, "skipping invalid pricing settings");
                        None
                    }
                }
            })
            .unwrap_or_else(|| defaults.pricing.clone()),
        // Resolved per-guardrail-profile settings, pre-bucketed at fold-in
        // (computed above with the rest of the guardrail folding).
        guardrail_by_profile,
        guardrail_default,
        // The two public URLs ship as **resolved** values on `ConfigResponse`
        // — admin-api collapses the SYSTEM-default-with-tenant-override
        // layering at snapshot time so the proxy never has to think about
        // the split. `None` here = neither layer configured; dependent
        // surfaces (MCP CORS, spec-OAuth metadata) fail closed.
        proxy_public_url: resp.proxy_public_url.clone(),
        admin_public_url: resp.admin_public_url.clone(),
        api_public_url: resp.api_public_url.clone(),
        default_workspace_id: resp.default_workspace_id,
        keys: tenant_keys(resp),
        credentials: {
            let stored = snapshot_credentials(resp);
            if stored.is_empty() {
                streamscope_core::config::credentials::ServerCredentials::default()
            } else {
                streamscope_core::config::credentials::ServerCredentials::open(
                    stored,
                    streamscope_core::crypto::get_encryption_key().as_ref(),
                )
            }
        },
    }
}

/// A tenant's live keys, by the raw SHA-256 of the key; a body naming one by
/// anything but a hex SHA-256 is reported and the key left out. A body bakes
/// each key's routes into its own context, and every key of a workspace
/// carries the same ones: the maps are interned here by digest, so the tenant
/// holds each distinct route set once however many keys it has.
fn tenant_keys(resp: &ConfigResponse) -> HashMap<[u8; 32], Arc<streamscope_core::auth::UserContext>> {
    let mut route_sets: std::collections::BTreeMap<
        streamscope_edge_api::digest::Digest,
        Arc<streamscope_core::config::model_map::ModelMap>,
    > = std::collections::BTreeMap::new();
    resp.api_keys
        .iter()
        .filter_map(|k| {
            let mut id = [0u8; 32];
            if hex::decode_to_slice(&k.key_hash, &mut id).is_err() {
                tracing::error!(key_hash = %k.key_hash, "a configuration names an API key by something other than its SHA-256 — leaving it out");
                return None;
            }
            let mut user = k.user_context.clone();
            if let Ok(digest) = serde_json::to_value(&*user.model_map)
                .and_then(|v| streamscope_edge_api::digest::digest_of(&v))
            {
                user.model_map = route_sets.entry(digest).or_insert_with(|| user.model_map.clone()).clone();
            }
            Some((id, Arc::new(user)))
        })
        .collect()
}

/// Translate the per-tenant MCP rows from a `ConfigResponse` into the
/// proxy's hot-path `McpConfig` (slug index + ordered routes per virtual
/// server). Disabled rows and routes whose dependencies are missing are
/// dropped at this layer so the proxy never has to think about them.
fn build_mcp_config(resp: &ConfigResponse) -> streamscope_core::config::mcp::McpConfig {
    use streamscope_core::config::mcp::{
        McpAuthMode, McpRouteFilter, McpTransport, McpUpstreamServer, McpUserCredential,
        McpVirtualRoute, McpVirtualServer, SamplingInterceptConfig,
    };

    /// Project the three sampling-intercept columns into a typed
    /// [`SamplingInterceptConfig`]. Returns `None` if the master toggle is
    /// off, or either credential or alias is missing — the admin handler
    /// validates this combination at write time, but the proxy is defensive.
    fn build_sampling_intercept(
        enabled: bool,
        credential: Option<&str>,
        alias: Option<&str>,
    ) -> Option<SamplingInterceptConfig> {
        if !enabled { return None; }
        let credential = credential?.to_string();
        let alias = alias?.to_string();
        if credential.is_empty() || alias.is_empty() { return None; }
        Some(SamplingInterceptConfig { encrypted_credential: credential, model_alias: alias })
    }

    fn parse_transport(s: &str) -> McpTransport {
        match s {
            "sse" => McpTransport::Sse,
            _ => McpTransport::StreamableHttp,
        }
    }
    fn parse_auth_mode(s: &str) -> McpAuthMode {
        match s {
            "service_account" => McpAuthMode::ServiceAccount,
            "per_user_oauth" => McpAuthMode::PerUserOauth,
            "byot" => McpAuthMode::Byot,
            _ => McpAuthMode::NoAuth,
        }
    }
    fn parse_filter(v: Option<&serde_json::Value>) -> Option<McpRouteFilter> {
        match v {
            Some(value) if !value.is_null() => serde_json::from_value(value.clone()).ok(),
            _ => None,
        }
    }

    let upstreams = resp
        .mcp_upstream_servers
        .iter()
        .map(|u| McpUpstreamServer {
            id: u.id,
            tenant_id: u.tenant_id,
            name: u.name.clone(),
            description: u.description.clone(),
            upstream_url: u.upstream_url.clone(),
            transport: parse_transport(&u.transport),
            auth_mode: parse_auth_mode(&u.auth_mode),
            cred_version: u.cred_version,
            encrypted_credential: u.encrypted_credential.clone(),
            oauth_issuer_url: u.oauth_issuer_url.clone(),
            oauth_authorization_url: u.oauth_authorization_url.clone(),
            oauth_token_url: u.oauth_token_url.clone(),
            oauth_revocation_url: u.oauth_revocation_url.clone(),
            oauth_client_id: u.oauth_client_id.clone(),
            encrypted_oauth_client_secret: u.encrypted_oauth_client_secret.clone(),
            oauth_default_scopes: u.oauth_default_scopes.clone(),
            enabled: u.enabled,
            connect_timeout_ms: u.connect_timeout_ms,
            request_timeout_ms: u.request_timeout_ms,
        })
        .collect();

    let user_credentials = resp
        .mcp_user_credentials
        .iter()
        .map(|c| McpUserCredential {
            tenant_id: c.tenant_id,
            user_id: c.user_id,
            upstream_server_id: c.upstream_server_id,
            encrypted_access_token: c.encrypted_access_token.clone(),
            encrypted_refresh_token: c.encrypted_refresh_token.clone(),
            expires_at: c.expires_at,
            scope: c.scope.clone(),
        })
        .collect();

    let virtual_servers = resp
        .mcp_virtual_servers
        .iter()
        .map(|v| McpVirtualServer {
            id: v.id,
            tenant_id: v.tenant_id,
            slug: v.slug.clone(),
            name: v.name.clone(),
            description: v.description.clone(),
            display_title: v.display_title.clone(),
            website_url: v.website_url.clone(),
            enabled: v.enabled,
            oauth_enabled: v.oauth_enabled,
            sampling_intercept: build_sampling_intercept(
                v.sampling_intercept_enabled,
                v.sampling_credential.as_deref(),
                v.sampling_model_alias.as_deref(),
            ),
        })
        .collect();

    let routes = resp
        .mcp_virtual_routes
        .iter()
        .map(|r| McpVirtualRoute {
            id: r.id,
            tenant_id: r.tenant_id,
            virtual_server_id: r.virtual_server_id,
            upstream_server_id: r.upstream_server_id,
            prefix: r.prefix.clone(),
            tools_filter: parse_filter(r.tools_filter.as_ref()),
            resources_filter: parse_filter(r.resources_filter.as_ref()),
            prompts_filter: parse_filter(r.prompts_filter.as_ref()),
            enabled: r.enabled,
            position: r.position,
        })
        .collect();

    let mut cfg = streamscope_core::config::mcp::McpConfig::from_rows_with_credentials(
        upstreams,
        virtual_servers,
        routes,
        user_credentials,
    );
    cfg.revoked_jtis = resp.mcp_revoked_jtis.iter().copied().collect();
    cfg.jwks = resp.mcp_jwks.clone();
    // The generations this replica will accept MCP tokens from. Retiring a key
    // reaches the edge in a config body, not a restart, so without this line a
    // replica's key set is unobservable and an operator has no way to confirm a
    // rotation reached the data plane. Debug because it fires per tenant per
    // apply; the set is small and changes rarely.
    tracing::debug!(
        kids = ?cfg.jwks.iter().map(|k| k.kid.as_str()).collect::<Vec<_>>(),
        "applied MCP verification keys"
    );
    cfg
}

/// Translate the per-tenant A2A rows from a `ConfigResponse` into the
/// proxy's hot-path `A2aConfig` (slug index + workspace allowlist). Disabled
/// agents and grants referencing them are dropped at this layer.
fn build_a2a_config(resp: &ConfigResponse) -> streamscope_core::config::a2a::A2aConfig {
    use streamscope_core::config::a2a::{A2aAuthMode, A2aConfig, A2aUpstreamAgent};

    fn parse_auth_mode(s: &str) -> A2aAuthMode {
        match s {
            "service_account" => A2aAuthMode::ServiceAccount,
            _ => A2aAuthMode::NoAuth,
        }
    }

    let agents = resp
        .a2a_agents
        .iter()
        .map(|a| A2aUpstreamAgent {
            id: a.id,
            tenant_id: a.tenant_id,
            name: a.name.clone(),
            description: a.description.clone(),
            slug: a.slug.clone(),
            agent_url: a.agent_url.clone(),
            agent_card: a.agent_card.clone(),
            card_fetched_at: a.card_fetched_at,
            auth_mode: parse_auth_mode(&a.auth_mode),
            encrypted_credential: a.encrypted_credential.clone(),
            credential_header: a.credential_header.clone(),
            enabled: a.enabled,
        })
        .collect();

    A2aConfig::from_rows(agents)
}

/// Apply a multi-tenant config snapshot to the tenant registry.
///
/// Replaces the entire registry with configs for all active tenants from the snapshot.
/// Tenants not in the snapshot are removed (deactivated or deleted).
/// SYSTEM tenant is always preserved as a fallback entry.
pub fn apply_multi_tenant_snapshot(registry: &TenantRegistry, resp: &MultiTenantConfigResponse) {
    let default_config = streamscope_core::config::TenantConfig::default();
    let current_map = registry.load();

    let mut new_map: HashMap<TenantId, Arc<streamscope_core::config::TenantConfig>> = HashMap::new();

    for (tenant_uuid_str, config_response) in &resp.tenants {
        let tenant_id = match uuid::Uuid::parse_str(tenant_uuid_str) {
            Ok(uuid) => TenantId(uuid),
            Err(e) => {
                tracing::warn!(tenant = %tenant_uuid_str, "skipping tenant with invalid UUID: {e}");
                continue;
            }
        };

        let tenant_config = build_tenant_config(config_response);
        new_map.insert(tenant_id, Arc::new(tenant_config));
    }

    // Ensure SYSTEM tenant is always present (even if not in snapshot).
    new_map.entry(TenantId::SYSTEM).or_insert_with(|| {
        current_map
            .get(&TenantId::SYSTEM)
            .cloned()
            .unwrap_or_else(|| Arc::new(default_config))
    });

    install_egress(&resp.egress);

    // Apply global log level if provided.
    if let Some(log_level) = &resp.log_level {
        let current_log_level = crate::log_level::current();
        if log_level != current_log_level {
            tracing::info!(old = %current_log_level, new = %log_level, "changing log level (global)");
            crate::log_level::apply(log_level);
        }
    }

    let tenant_count = new_map.len();
    streamscope_core::config::publish(registry, streamscope_core::config::Registry::new(new_map));
    tracing::info!(tenants = tenant_count, "applied multi-tenant config snapshot");
}

/// Parse app registry entries from settings into AppPattern structs for attribution.
///
/// Every pattern is lowercased, trimmed and dropped when empty — the matchers
/// compare against a lowercased header or prompt, so a pattern typed as
/// `Mistral-Vibe/` would otherwise never match, and an empty one would match
/// every request. A prompt pattern shorter than
/// [`MIN_PROMPT_PATTERN_CHARS`](streamscope_core::middleware::attribution::MIN_PROMPT_PATTERN_CHARS)
/// is dropped as well: the registry refuses one, and this fold is the last
/// place that can keep a registry written some other way from claiming every
/// unclassified request.
fn parse_app_patterns(registry: &serde_json::Value) -> Vec<streamscope_core::config::AppPattern> {
    use streamscope_core::middleware::attribution::{MIN_PROMPT_PATTERN_CHARS, normalize_patterns};

    /// Minimal struct matching the AppInfo fields we need from the app_registry setting.
    #[derive(serde::Deserialize)]
    struct AppRegistryEntry {
        id: String,
        #[serde(default)]
        ua_patterns: Vec<String>,
        #[serde(default)]
        referer_patterns: Vec<String>,
        #[serde(default)]
        prompt_patterns: Vec<String>,
    }

    let entries: Vec<AppRegistryEntry> = serde_json::from_value(registry.clone()).unwrap_or_else(|e| {
        tracing::warn!("failed to deserialize app_registry for attribution: {e}");
        vec![]
    });

    entries
        .into_iter()
        .map(|e| streamscope_core::config::AppPattern {
            app_id: e.id,
            ua_patterns: normalize_patterns(&e.ua_patterns, 1),
            referer_patterns: normalize_patterns(&e.referer_patterns, 1),
            prompt_patterns: normalize_patterns(&e.prompt_patterns, MIN_PROMPT_PATTERN_CHARS),
        })
        .filter(|a| {
            !a.ua_patterns.is_empty() || !a.referer_patterns.is_empty() || !a.prompt_patterns.is_empty()
        })
        .collect()
}

/// Extract a boolean value from the settings map.
fn setting_bool(s: &HashMap<String, serde_json::Value>, key: &str) -> Option<bool> {
    s.get(key).and_then(|v| v.as_bool())
}

/// Extract a u64 value from the settings map.
fn setting_u64(s: &HashMap<String, serde_json::Value>, key: &str) -> Option<u64> {
    s.get(key).and_then(|v| v.as_u64())
}

/// Extract a string value from the settings map.
fn setting_str(s: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    s.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Collect all transform programs across all tenants in a multi-tenant response.
///
/// Returns a merged list of all enabled programs from all tenants.
pub fn collect_multi_tenant_programs(
    resp: &MultiTenantConfigResponse,
) -> Vec<streamscope_core::scripting::TransformProgram> {
    let mut all_programs = Vec::new();
    for config_response in resp.tenants.values() {
        all_programs.extend(convert_transform_programs(&config_response.transform_programs));
    }
    all_programs
}

/// Incremental config update — only changed/removed tenants, built from a
/// sync answer. Merged into the existing registry (does not replace it).
#[derive(Deserialize, Serialize, Clone)]
pub struct IncrementalConfigUpdate {
    pub updates: HashMap<String, ConfigResponse>,
    pub removed_tenants: Vec<String>,
    #[serde(default)]
    pub log_level: Option<String>,
    /// Global platform setting overrides — `None` = unchanged by this update,
    /// `Some` = the full replacement override set.
    #[serde(default)]
    pub runtime_overrides: Option<HashMap<String, String>>,
    /// The internal-egress allowlists — `None` = unchanged by this update,
    /// `Some` = the full replacement set.
    #[serde(default)]
    pub egress: Option<std::collections::BTreeMap<String, Vec<String>>>,
}

/// Make `lists` this process's internal-egress allowlists: the next outbound
/// connection on every surface reads them. A set that does not parse (never
/// written by a current admin-api, which validates every entry) leaves the
/// lists in force as they were, and says so.
pub fn install_egress(lists: &std::collections::BTreeMap<String, Vec<String>>) {
    match streamscope_mcp_auth::egress::Lists::from_entries(lists) {
        Ok(parsed) => {
            if *streamscope_mcp_auth::egress::current() != parsed {
                tracing::info!(surfaces = lists.len(), "applying the internal-egress allowlists");
            }
            streamscope_mcp_auth::egress::install(parsed);
        }
        Err((surface, e)) => tracing::error!(
            surface = surface.as_str(),
            "refusing the internal-egress allowlists: {e} — the previous lists stay in force"
        ),
    }
}

/// Everything an applied config change reaches in this process.
#[derive(Clone)]
pub struct ConfigTargets {
    pub tenant_registry: TenantRegistry,
    pub script_engine: Arc<streamscope_core::scripting::ScriptEngine>,
    pub active_programs: Arc<arc_swap::ArcSwap<Vec<streamscope_core::scripting::TransformProgram>>>,
    pub config_ready: Arc<std::sync::atomic::AtomicBool>,
    pub response_cache: Arc<streamscope_core::proxy::response_cache::ResponseCache>,
}

/// Apply a config change: one registry publish carries every changed tenant
/// whole — its keys, routes, endpoints and credentials together, so no request
/// meets a key of one version and the config it routes on of another — then
/// the merged transform programs. Readiness is the caller's to decide: one
/// change may be only part of the config.
pub fn apply_update(targets: &ConfigTargets, update: &IncrementalConfigUpdate) {
    if !apply_incremental_update(&targets.tenant_registry, update) {
        return;
    }

    let programs = collect_programs_from_registry(&targets.tenant_registry);
    tracing::info!(count = programs.len(), "applying transform programs (incremental)");
    targets.active_programs.store(Arc::new(programs));
    targets.script_engine.clear_cache();
}

/// Apply an incremental config update — only modify affected tenants.
///
/// Unlike `apply_multi_tenant_snapshot` which replaces the entire registry,
/// this merges changed tenants into the existing map and removes deleted ones —
/// the merge itself is O(changed tenants).
///
/// Publishing the result then rebuilds the registry's MCP slug and key-hash
/// indexes over every tenant, because each must be derived from the very map it
/// is swapped in with. That is deliberate: the rebuild is a per-swap cost on the
/// config path — O(slugs + keys of every tenant) — paid so the pre-auth MCP
/// lookups and authentication are O(1) on the request path. An update that
/// changes no tenant (the global resource alone) publishes nothing. Returns
/// whether it published.
pub fn apply_incremental_update(
    registry: &TenantRegistry,
    update: &IncrementalConfigUpdate,
) -> bool {
    let default_config = streamscope_core::config::TenantConfig::default();
    let current_map = registry.load();
    let mut new_map = (**current_map).clone();

    for (tenant_uuid_str, config_response) in &update.updates {
        let tenant_id = match uuid::Uuid::parse_str(tenant_uuid_str) {
            Ok(uuid) => TenantId(uuid),
            Err(e) => {
                tracing::warn!(tenant = %tenant_uuid_str, "skipping tenant with invalid UUID: {e}");
                continue;
            }
        };
        let tenant_config = build_tenant_config(config_response);
        new_map.insert(tenant_id, Arc::new(tenant_config));
    }

    for tenant_uuid_str in &update.removed_tenants {
        if let Ok(uuid) = uuid::Uuid::parse_str(tenant_uuid_str) {
            new_map.remove(&TenantId(uuid));
        }
    }

    if let Some(lists) = &update.egress {
        install_egress(lists);
    }

    // Apply global log level if changed.
    if let Some(log_level) = &update.log_level {
        // Against the level applied, not a registry entry: the global level
        // is not a tenant setting.
        let current_log_level = crate::log_level::current();
        if log_level != current_log_level {
            tracing::info!(old = %current_log_level, new = %log_level, "changing log level (incremental)");
            crate::log_level::apply(log_level);
        }
    }

    if update.updates.is_empty() && update.removed_tenants.is_empty() {
        return false;
    }

    // SYSTEM tenant always preserved.
    new_map.entry(TenantId::SYSTEM).or_insert_with(|| {
        current_map
            .get(&TenantId::SYSTEM)
            .cloned()
            .unwrap_or_else(|| Arc::new(default_config))
    });

    let total = new_map.len();
    streamscope_core::config::publish(registry, streamscope_core::config::Registry::new(new_map));
    tracing::info!(
        updated = update.updates.len(),
        removed = update.removed_tenants.len(),
        total,
        "applied incremental config update"
    );
    true
}

/// Collect all transform programs from the current tenant registry.
///
/// Used after incremental updates to rebuild the merged program list.
pub fn collect_programs_from_registry(
    registry: &TenantRegistry,
) -> Vec<streamscope_core::scripting::TransformProgram> {
    let map = registry.load();
    let mut all_programs = Vec::new();
    for config in map.values() {
        all_programs.extend(config.transform_programs.clone());
    }
    all_programs
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use streamscope_core::config::model_map::Provider;
    use streamscope_core::config::new_tenant_registry;

    /// SYSTEM tenant UUID string for tests.
    const TEST_SYSTEM_TENANT_STR: &str = "00000000-0000-0000-0000-000000000001";

    /// Helper to load the SYSTEM tenant config from the registry.
    fn load_system_config(registry: &TenantRegistry) -> Arc<streamscope_core::config::TenantConfig> {
        let map = registry.load();
        map.get(&TenantId::SYSTEM).cloned().unwrap()
    }

    #[test]
    fn a_registry_pattern_matches_whatever_case_it_was_typed_in() {
        use axum::http::{HeaderMap, HeaderValue};
        use streamscope_core::middleware::attribution::extract_attribution;

        let mut s = HashMap::new();
        s.insert(
            "app_registry".to_string(),
            serde_json::json!([
                {"id": "vibe", "ua_patterns": [" Mistral-Vibe/ "]},
                {"id": "goose", "prompt_patterns": ["AI agent called Goose", "", "too short"]},
                {"id": "blank", "ua_patterns": ["", "  "]},
            ]),
        );
        let patterns = parse_app_patterns(&s["app_registry"]);

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("Mistral-Vibe/2.15.0"));
        let attr = extract_attribution(&headers, uuid::Uuid::nil(), &patterns, false);
        assert_eq!(attr.app_id.as_deref(), Some("vibe"));

        let goose = patterns.iter().find(|p| p.app_id == "goose").unwrap();
        assert_eq!(goose.prompt_patterns, vec!["ai agent called goose".to_string()]);
        // An entry left with no usable pattern would match nothing; an empty one
        // kept would match every request.
        assert!(patterns.iter().all(|p| p.app_id != "blank"));
        let mut attr = extract_attribution(&HeaderMap::new(), uuid::Uuid::nil(), &patterns, false);
        attr.classify_by_system_prompt(Some("You are a helpful assistant."), &patterns);
        assert_eq!(attr.app_id, None);
    }

    /// Wrap a single ConfigResponse as a SYSTEM-tenant multi-tenant snapshot.
    fn wrap_system(resp: ConfigResponse) -> MultiTenantConfigResponse {
        let mut tenants = HashMap::new();
        tenants.insert(TEST_SYSTEM_TENANT_STR.to_string(), resp);
        MultiTenantConfigResponse {
            tenants,
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        }
    }

    /// A complete tenant body as admin-api serializes it, with `overrides`'s
    /// top-level fields put over it.
    pub(crate) fn body_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut body = serde_json::to_value(make_response(vec![])).unwrap();
        for (k, v) in overrides.as_object().unwrap() {
            body[k] = v.clone();
        }
        body
    }

    /// A route as admin-api serializes it, with `overrides` put over it.
    pub(crate) fn mapping_json(overrides: serde_json::Value) -> serde_json::Value {
        let mut m = serde_json::to_value(make_mapping("a", "openai", "m")).unwrap();
        for (k, v) in overrides.as_object().unwrap() {
            m[k] = v.clone();
        }
        m
    }

    fn make_response(model_mappings: Vec<EdgeModelMapping>) -> ConfigResponse {
        ConfigResponse {
            model_mappings,
            api_keys: vec![],
            settings: HashMap::new(),
            transform_programs: vec![],
            mcp_upstream_servers: vec![],
            mcp_virtual_servers: vec![],
            mcp_virtual_routes: vec![],
            mcp_user_credentials: vec![],
            mcp_revoked_jtis: vec![],
            mcp_jwks: vec![],
            a2a_agents: vec![],
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: Default::default(),
            member_limit_defaults: Default::default(),
            member_limit_exceptions: Default::default(),
            upstream_endpoints: Default::default(),
            qos: Default::default(),
            web_destinations: Default::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            workspace_profiles: Vec::new(),
            default_profiles: Vec::new(),
            profile_modes: Vec::new(),
        }
    }

    fn make_mapping(alias: &str, provider: &str, upstream_model: &str) -> EdgeModelMapping {
        EdgeModelMapping {
            id: String::new(),
            tenant_id: String::new(),
            catalog_matched: false,
            alias: alias.to_string(),
            provider: provider.to_string(),
            upstream_model: upstream_model.to_string(),
            priority: 0,
            enabled: true,
            cache_generation: 0,
            encrypted_credential: None,
            context_window: None,
            max_output_tokens: None,
            client_context_window: None,
            upstream_api_format: None,
            chat_endpoint_path: None,
            transport: Default::default(),
            scheduling_dialect: Default::default(),
            upstream_server_id: None,
            downstream_provider_id: None,
            upstream_model_id: None,
            weight: 1,
            supports_vision: None,
            supports_reasoning: None,
            supports_function_calling: None,
            supports_caching: None,
            supports_audio_input: None,
            supports_audio_output: None,
            supports_video_input: None,
            supports_pdf_input: None,
            supports_response_schema: None,
            supports_system_messages: None,
            healing_enabled: None,
            preset_settings: serde_json::Value::Null,
            cache_mode: None,
            cache_ttl_seconds: None,
            cache_threshold: None,
            cache_share_scope: None,
            rates: streamscope_core::pricing::Rates::unknown(),
        }
    }

    // --- Provider::from_str_relaxed tests ---

    #[test]
    fn provider_from_str_relaxed_snake_case() {
        assert_eq!(Provider::from_str_relaxed("open_ai"), Provider::OpenAi);
        assert_eq!(Provider::from_str_relaxed("anthropic"), Provider::Anthropic);
        assert_eq!(Provider::from_str_relaxed("azure_open_ai"), Provider::AzureOpenAi);
        assert_eq!(Provider::from_str_relaxed("deep_seek"), Provider::DeepSeek);
    }

    #[test]
    fn provider_from_str_relaxed_shorthand() {
        assert_eq!(Provider::from_str_relaxed("openai"), Provider::OpenAi);
        assert_eq!(Provider::from_str_relaxed("ollama"), Provider::Ollama);
        assert_eq!(Provider::from_str_relaxed("azure"), Provider::AzureOpenAi);
        assert_eq!(Provider::from_str_relaxed("bedrock"), Provider::AwsBedrock);
        assert_eq!(Provider::from_str_relaxed("vertex"), Provider::GoogleVertex);
        assert_eq!(Provider::from_str_relaxed("vllm"), Provider::Vllm);
    }

    #[test]
    fn provider_from_str_relaxed_case_insensitive() {
        assert_eq!(Provider::from_str_relaxed("OpenAI"), Provider::OpenAi);
        assert_eq!(Provider::from_str_relaxed("OLLAMA"), Provider::Ollama);
        assert_eq!(Provider::from_str_relaxed("DeepSeek"), Provider::DeepSeek);
    }

    #[test]
    fn provider_from_str_relaxed_unknown_falls_back_to_custom() {
        assert_eq!(Provider::from_str_relaxed("nonexistent"), Provider::Custom);
    }

    // --- model mappings ---

    #[test]
    fn snapshot_applies_model_mappings() {
        let registry = new_tenant_registry();
        let resp = make_response(vec![
                make_mapping("gpt-4o", "openai", "gpt-4o-2024-08-06"),
                EdgeModelMapping {
                    priority: 10,
                    ..make_mapping("local-llama", "ollama", "llama3")
                },
            ],
        );

        apply_multi_tenant_snapshot(&registry, &wrap_system(resp));

        let cfg = load_system_config(&registry);
        let gpt = cfg.model_map.resolve("gpt-4o").unwrap();
        assert_eq!(gpt.model, "gpt-4o-2024-08-06");
        assert_eq!(gpt.provider, "openai");

        let llama = cfg.model_map.resolve("local-llama").unwrap();
        assert_eq!(llama.model, "llama3");
        assert_eq!(llama.provider, "ollama");
        assert_eq!(llama.priority, 10);
    }

    #[test]
    fn snapshot_replaces_previous_mappings() {
        let registry = new_tenant_registry();

        apply_multi_tenant_snapshot(
            &registry,
            &wrap_system(make_response(vec![make_mapping("model-a", "openai", "gpt-4")])),
        );
        assert!(load_system_config(&registry).model_map.resolve("model-a").is_some());

        apply_multi_tenant_snapshot(
            &registry,
            &wrap_system(make_response(vec![make_mapping("model-b", "anthropic", "claude-3")])),
        );
        assert!(load_system_config(&registry).model_map.resolve("model-a").is_none());
        assert!(load_system_config(&registry).model_map.resolve("model-b").is_some());
    }

    #[test]
    fn empty_snapshot_clears_mappings() {
        let registry = new_tenant_registry();

        apply_multi_tenant_snapshot(
            &registry,
            &wrap_system(make_response(vec![make_mapping("test", "ollama", "llama3")])),
        );
        assert!(!load_system_config(&registry).model_map.mappings.is_empty());

        apply_multi_tenant_snapshot(&registry, &wrap_system(make_response(vec![])));
        assert!(load_system_config(&registry).model_map.mappings.is_empty());
    }

    // --- settings from admin UI ---

    #[test]
    fn snapshot_resets_setting_driven_fields_when_keys_absent() {
        // Snapshot semantics: if a `system_settings` row is deleted, the key
        // is absent from the next snapshot. The proxy must reset the field
        // to the struct default — not pin the last-pushed value forever.
        let registry = new_tenant_registry();

        {
            let mut cfg = (*load_system_config(&registry)).clone();
            cfg.debug_mode = true;
            cfg.stream_idle_timeout_secs = 60;
            let mut map = (**registry.load()).clone();
            map.insert(TenantId::SYSTEM, Arc::new(cfg));
            streamscope_core::config::publish(&registry, streamscope_core::config::Registry::new(map));
        }

        // Empty settings map — setting-driven fields reset to defaults.
        apply_multi_tenant_snapshot(&registry, &wrap_system(make_response(vec![])));

        let cfg = load_system_config(&registry);
        let defaults = streamscope_core::config::TenantConfig::default();
        assert_eq!(cfg.debug_mode, defaults.debug_mode);
        assert_eq!(cfg.stream_idle_timeout_secs, defaults.stream_idle_timeout_secs);
    }

    #[test]
    fn incremental_update_resets_setting_driven_fields_when_keys_absent() {
        // Same default-on-absent contract must hold for the incremental
        // (WS-pushed) path, not just full snapshots.
        let registry = new_tenant_registry();
        let tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

        let mut settings = HashMap::new();
        settings.insert("debug_mode".to_string(), serde_json::json!(true));
        let resp_with = ConfigResponse {
            model_mappings: vec![],
            api_keys: vec![],
            settings,
            transform_programs: vec![],
            mcp_upstream_servers: vec![],
            mcp_virtual_servers: vec![],
            mcp_virtual_routes: vec![],
            mcp_user_credentials: vec![],
            mcp_revoked_jtis: vec![],
            mcp_jwks: vec![],
            a2a_agents: vec![],
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: Default::default(),
            member_limit_defaults: Default::default(),
            member_limit_exceptions: Default::default(),
            upstream_endpoints: Default::default(),
            qos: Default::default(),
            web_destinations: Default::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            workspace_profiles: Vec::new(),
            default_profiles: Vec::new(),
            profile_modes: Vec::new(),
        };
        let mut updates = HashMap::new();
        updates.insert(tenant.to_string(), resp_with);
        apply_incremental_update(&registry, &IncrementalConfigUpdate {
            updates,
            removed_tenants: vec![],
            log_level: None,
            runtime_overrides: None,
            egress: None,
        });
        let tid = TenantId(uuid::Uuid::parse_str(tenant).unwrap());
        assert!(registry.load().get(&tid).unwrap().debug_mode);

        // Second incremental: same tenant, but with the keys absent.
        let mut updates = HashMap::new();
        updates.insert(tenant.to_string(), make_response(vec![]));
        apply_incremental_update(&registry, &IncrementalConfigUpdate {
            updates,
            removed_tenants: vec![],
            log_level: None,
            runtime_overrides: None,
            egress: None,
        });

        let cfg = registry.load().get(&tid).cloned().unwrap();
        let defaults = streamscope_core::config::TenantConfig::default();
        assert_eq!(cfg.debug_mode, defaults.debug_mode);
    }



    fn sealed(plaintext: &str) -> String {
        let key = streamscope_core::crypto::get_encryption_key().expect("ENCRYPTION_KEY is set");
        streamscope_core::crypto::encrypt(plaintext, &key).unwrap()
    }

    fn set_encryption_key() {
        // SAFETY: same value as every other ENCRYPTION_KEY setter in this binary.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-mcp-token-secret-very-long");
        }
    }

    #[test]
    fn a_read_servers_credential_is_opened_without_a_routed_model() {
        set_encryption_key();
        let server = uuid::Uuid::new_v4();
        // No model mapping: nothing routes to the server.
        let mut resp = make_response(vec![]);
        resp.upstream_endpoints.read_credentials.insert(
            server,
            streamscope_core::config::endpoints::ReadCredential {
                encrypted: sealed("read-key"),
                transport: Default::default(),
            },
        );
        assert_eq!(build_tenant_config(&resp).credentials.get(&server.to_string()), Ok("read-key"));

        // The server stops being read: its credential leaves with it.
        resp.upstream_endpoints.read_credentials.clear();
        assert_eq!(
            build_tenant_config(&resp).credentials.get(&server.to_string()),
            Err(streamscope_core::config::credentials::CredentialMiss::Absent)
        );
    }

    /// Keys whose routes are the same hold one map between them; a key with
    /// other routes keeps its own.
    #[test]
    fn keys_with_the_same_routes_share_one_map() {
        set_encryption_key();
        let servers = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let mut resp = key_and_routes(0, servers);
        let mut other = key_and_routes(1, servers).api_keys.remove(0);
        other.key_hash = streamscope_core::auth::virtual_key::hash_key("sk-other");
        resp.api_keys.push(other);
        let keys = tenant_keys(&resp);
        let map = |key: &str| keys[&streamscope_core::auth::virtual_key::key_digest(key)].model_map.clone();
        // `sk-k` and `sk-revoked` carry the same routes, `sk-other` another server's.
        assert!(Arc::ptr_eq(&map("sk-k"), &map("sk-revoked")), "identical routes are held once");
        assert!(!Arc::ptr_eq(&map("sk-k"), &map("sk-other")), "different routes are not merged");
    }

    /// One version of a tenant: key `sk-k` routes alias `m` to server
    /// `servers[version % 2]`, which the endpoint table and the credentials of
    /// that same version carry — and no other. From version 10 the tenant adds
    /// `sk-fresh` and revokes `sk-revoked`.
    fn key_and_routes(version: u64, servers: [uuid::Uuid; 2]) -> ConfigResponse {
        let server = servers[usize::from(version % 2 == 1)];
        let user_context = || {
            serde_json::from_value::<streamscope_core::auth::UserContext>(serde_json::json!({
                "user_id": uuid::Uuid::nil(),
                "tenant_id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "workspace_id": uuid::Uuid::nil(),
                "model_map": { "mappings": { "m": [{
                    "provider": "openai",
                    "model": "model",
                    "has_credential": true,
                    "upstream_server_id": server.to_string(),
                }] } },
                "rate_limit": streamscope_core::auth::RateLimitConfig::unlimited(),
                "tenant_budget": null,
            }))
            .unwrap()
        };
        let mut keys = vec!["sk-k"];
        keys.push(if version >= 10 { "sk-fresh" } else { "sk-revoked" });
        let mut resp = make_response(vec![]);
        resp.api_keys = keys
            .into_iter()
            .map(|key| EdgeApiKey {
                key_hash: streamscope_core::auth::virtual_key::hash_key(key),
                user_context: user_context(),
            })
            .collect();
        resp.upstream_endpoints.servers.insert(
            server,
            vec![streamscope_core::config::endpoints::EndpointConfig {
                id: server,
                url: format!("http://{server}"),
                weight: 1,
                max_in_flight: None,
                waiting_threshold: None,
                engine_metrics: false,
                adaptive_concurrency: false,
                adaptive_itl_target: Default::default(),
            }],
        );
        resp.upstream_endpoints.read_credentials.insert(
            server,
            streamscope_core::config::endpoints::ReadCredential {
                encrypted: sealed(&format!("credential-of-{server}")),
                transport: Default::default(),
            },
        );
        resp
    }

    /// A request reads its key and the configuration it routes on from ONE
    /// version: whatever a config change is doing, the key's route lands on an
    /// endpoint and a credential of the version the key came from — never a
    /// key of the new version on the old endpoint table (no serving endpoint),
    /// nor an old key on the new one, nor one server's credential sent to
    /// another. A key the change adds authenticates only with the config that
    /// carries its server, and a revoked one stops with the version that drops
    /// it.
    ///
    /// The reader runs on another worker for the whole sequence of changes,
    /// so an apply that publishes keys and routes separately is observed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_reads_its_key_and_the_config_it_routes_on_from_one_version() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        set_encryption_key();
        let tenant = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        let servers = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        let update = |version: u64| IncrementalConfigUpdate {
            updates: HashMap::from([(tenant.to_string(), key_and_routes(version, servers))]),
            removed_tenants: vec![],
            log_level: None,
            runtime_overrides: None,
            egress: None,
        };
        let registry = new_tenant_registry();
        apply_incremental_update(&registry, &update(0));

        let stop = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let mixed: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let reader = tokio::spawn({
            let (registry, stop, reads, mixed) = (registry.clone(), stop.clone(), reads.clone(), mixed.clone());
            async move {
                let lb = dashmap::DashMap::new();
                while !stop.load(Ordering::Relaxed) {
                    for key in ["sk-k", "sk-fresh", "sk-revoked"] {
                        let Ok(ctx) = streamscope_core::auth::authenticate_proxy(key, &registry.load()) else {
                            continue;
                        };
                        let routed = streamscope_core::proxy::routing::resolve_all_upstreams_by_model(
                            "m",
                            &ctx.user,
                            &ctx.config.credentials,
                            &lb,
                            None,
                            streamscope_core::api::sse::ApiVersion::ChatCompletions,
                            None,
                            &ctx.config.endpoints,
                            false,
                        );
                        match routed {
                            Ok(targets) if targets[0].api_key == format!("credential-of-{}", targets[0].upstream_server_id.as_deref().unwrap_or_default()) => {}
                            Ok(targets) => mixed.lock().unwrap().push(format!("{key}: {:?} with another server's credential", targets[0].upstream_server_id)),
                            Err(e) => mixed.lock().unwrap().push(format!("{key}: {e}")),
                        }
                    }
                    reads.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            }
        });

        for version in 1..=40 {
            apply_incremental_update(&registry, &update(version));
            tokio::task::yield_now().await;
        }
        stop.store(true, Ordering::Relaxed);
        reader.await.expect("reader task");

        assert!(reads.load(Ordering::Relaxed) > 0, "the reader must have observed the changes");
        assert_eq!(*mixed.lock().unwrap(), Vec::<String>::new(), "a request met a key and a config of different versions");
        let current = registry.load();
        assert!(streamscope_core::auth::authenticate_proxy("sk-fresh", &current).is_ok(), "the added key is live");
        assert!(streamscope_core::auth::authenticate_proxy("sk-revoked", &current).is_err(), "the revoked key is gone");
    }

    #[test]
    fn snapshot_resets_individual_key_after_removal() {
        // Two-step: push a snapshot setting `debug_mode = true`, then push
        // one without the key — second snapshot must revert to the default.
        let registry = new_tenant_registry();

        let mut settings = HashMap::new();
        settings.insert("debug_mode".to_string(), serde_json::json!(true));
        let resp_with = ConfigResponse {
            model_mappings: vec![],
            api_keys: vec![],
            settings,
            transform_programs: vec![],
            mcp_upstream_servers: vec![],
            mcp_virtual_servers: vec![],
            mcp_virtual_routes: vec![],
            mcp_user_credentials: vec![],
            mcp_revoked_jtis: vec![],
            mcp_jwks: vec![],
            a2a_agents: vec![],
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: Default::default(),
            member_limit_defaults: Default::default(),
            member_limit_exceptions: Default::default(),
            upstream_endpoints: Default::default(),
            qos: Default::default(),
            web_destinations: Default::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            workspace_profiles: Vec::new(),
            default_profiles: Vec::new(),
            profile_modes: Vec::new(),
        };
        apply_multi_tenant_snapshot(&registry, &wrap_system(resp_with));
        assert!(load_system_config(&registry).debug_mode);

        // Second snapshot: same shape but with both keys *absent*.
        apply_multi_tenant_snapshot(&registry, &wrap_system(make_response(vec![])));

        let cfg = load_system_config(&registry);
        let defaults = streamscope_core::config::TenantConfig::default();
        assert_eq!(cfg.debug_mode, defaults.debug_mode);
    }

    /// Two tenants whose bodies carry the same profiles and registry share
    /// one parse of each; a different value gets its own.
    #[test]
    fn identical_settings_values_are_parsed_once_for_every_tenant() {
        let body = |tool: &str| {
            let mut resp = make_response(vec![]);
            resp.settings.insert(
                "tool_field_profiles".to_string(),
                serde_json::json!([{ "tool_pattern": tool, "fields": {} }]),
            );
            resp.settings.insert("app_registry".to_string(), serde_json::json!([{ "id": "vibe", "ua_patterns": ["Vibe/"] }]));
            build_tenant_config(&resp)
        };
        let (a, b, c) = (body("Bash"), body("Bash"), body("Read"));
        assert!(std::sync::Arc::ptr_eq(&a.tool_field_profiles, &b.tool_field_profiles));
        assert!(!std::sync::Arc::ptr_eq(&a.tool_field_profiles, &c.tool_field_profiles));
        assert!(std::sync::Arc::ptr_eq(&a.app_patterns, &c.app_patterns));
        assert_eq!(a.app_patterns.len(), 1);
    }

    #[test]
    fn a_media_blob_cap_above_the_platforms_is_held_to_it() {
        let cap_of = |mb: u64| {
            let mut resp = make_response(vec![]);
            resp.settings.insert("media_blob_max_size_mb".to_string(), serde_json::json!(mb));
            build_tenant_config(&resp).media_blob_max_size_mb
        };
        let max = blob_max_mb();
        assert_eq!(cap_of(max - 1), max - 1, "below the ceiling: as set");
        assert_eq!(cap_of(max), max, "at the ceiling: as set");
        assert_eq!(cap_of(max + 1), max, "above the ceiling: held to it");
    }

    #[test]
    fn snapshot_applies_admin_settings() {
        let registry = new_tenant_registry();

        let mut settings = HashMap::new();
        settings.insert("debug_mode".to_string(), serde_json::json!(true));
        settings.insert("healing_enabled".to_string(), serde_json::json!(true));
        settings.insert("stream_idle_timeout_secs".to_string(), serde_json::json!(600));
        settings.insert("content_logging_enabled".to_string(), serde_json::json!(true));

        let resp = ConfigResponse {
            model_mappings: vec![],
            api_keys: vec![],
            settings,
            transform_programs: vec![],
            mcp_upstream_servers: vec![],
            mcp_virtual_servers: vec![],
            mcp_virtual_routes: vec![],
            mcp_user_credentials: vec![],
            mcp_revoked_jtis: vec![],
            mcp_jwks: vec![],
            a2a_agents: vec![],
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: Default::default(),
            member_limit_defaults: Default::default(),
            member_limit_exceptions: Default::default(),
            upstream_endpoints: Default::default(),
            qos: Default::default(),
            web_destinations: Default::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            workspace_profiles: Vec::new(),
            default_profiles: Vec::new(),
            profile_modes: Vec::new(),
        };

        apply_multi_tenant_snapshot(&registry, &wrap_system(resp));

        let cfg = load_system_config(&registry);
        assert!(cfg.debug_mode);
        assert!(cfg.healing_enabled);
        assert_eq!(cfg.stream_idle_timeout_secs, 600);
        assert!(cfg.content_logging_enabled);
    }

    #[test]
    fn snapshot_settings_override_env_defaults() {
        let registry = new_tenant_registry();

        // Simulate env var setting debug_mode = true at startup
        {
            let mut cfg = (*load_system_config(&registry)).clone();
            cfg.debug_mode = true;
            let mut map = (**registry.load()).clone();
            map.insert(TenantId::SYSTEM, Arc::new(cfg));
            streamscope_core::config::publish(&registry, streamscope_core::config::Registry::new(map));
        }

        // Admin UI sets debug_mode = false
        let mut settings = HashMap::new();
        settings.insert("debug_mode".to_string(), serde_json::json!(false));

        let resp = ConfigResponse {
            model_mappings: vec![],
            api_keys: vec![],
            settings,
            transform_programs: vec![],
            mcp_upstream_servers: vec![],
            mcp_virtual_servers: vec![],
            mcp_virtual_routes: vec![],
            mcp_user_credentials: vec![],
            mcp_revoked_jtis: vec![],
            mcp_jwks: vec![],
            a2a_agents: vec![],
            tenant_slug: String::new(),
            workspace_rate_limits: HashMap::new(),
            tenant_budget: None,
            workspaces_outside_tenant_budget: Default::default(),
            member_limit_defaults: Default::default(),
            member_limit_exceptions: Default::default(),
            upstream_endpoints: Default::default(),
            qos: Default::default(),
            web_destinations: Default::default(),
            proxy_public_url: None,
            admin_public_url: None,
            api_public_url: None,
            default_workspace_id: None,
            workspace_profiles: Vec::new(),
            default_profiles: Vec::new(),
            profile_modes: Vec::new(),
        };

        apply_multi_tenant_snapshot(&registry, &wrap_system(resp));

        let cfg = load_system_config(&registry);
        assert!(!cfg.debug_mode); // Admin UI wins
    }

    // --- Multi-tenant snapshot ---

    #[test]
    fn multi_tenant_snapshot_applies_multiple_tenants() {
        let registry = new_tenant_registry();
        let tenant_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let tenant_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

        let mut tenants = HashMap::new();
        tenants.insert(
            tenant_a.to_string(),
            make_response(vec![make_mapping("gpt-4o", "openai", "gpt-4o-2024-08-06")]),
        );
        tenants.insert(
            tenant_b.to_string(),
            make_response(vec![make_mapping("claude-3", "anthropic", "claude-3-opus")]),
        );

        let resp = MultiTenantConfigResponse {
            tenants,
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        };

        apply_multi_tenant_snapshot(&registry, &resp);

        let map = registry.load();
        // Both tenants present.
        let tid_a = TenantId(uuid::Uuid::parse_str(tenant_a).unwrap());
        let tid_b = TenantId(uuid::Uuid::parse_str(tenant_b).unwrap());
        assert!(map.get(&tid_a).unwrap().model_map.resolve("gpt-4o").is_some());
        assert!(map.get(&tid_b).unwrap().model_map.resolve("claude-3").is_some());
        // SYSTEM always present.
        assert!(map.contains_key(&TenantId::SYSTEM));
    }

    #[test]
    fn multi_tenant_snapshot_removes_stale_tenants() {
        let registry = new_tenant_registry();
        let tenant_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let tenant_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

        // First snapshot: tenant A and B.
        let mut tenants = HashMap::new();
        tenants.insert(tenant_a.to_string(), make_response(vec![]));
        tenants.insert(tenant_b.to_string(), make_response(vec![]));
        apply_multi_tenant_snapshot(&registry, &MultiTenantConfigResponse {
            tenants,
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        });

        let tid_a = TenantId(uuid::Uuid::parse_str(tenant_a).unwrap());
        let tid_b = TenantId(uuid::Uuid::parse_str(tenant_b).unwrap());
        assert!(registry.load().contains_key(&tid_a));
        assert!(registry.load().contains_key(&tid_b));

        // Second snapshot: only tenant A (B deactivated).
        let mut tenants = HashMap::new();
        tenants.insert(tenant_a.to_string(), make_response(vec![]));
        apply_multi_tenant_snapshot(&registry, &MultiTenantConfigResponse {
            tenants,
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        });

        assert!(registry.load().contains_key(&tid_a));
        assert!(!registry.load().contains_key(&tid_b));
        // SYSTEM always present.
        assert!(registry.load().contains_key(&TenantId::SYSTEM));
    }

    #[test]
    fn multi_tenant_snapshot_preserves_system_fallback() {
        let registry = new_tenant_registry();
        // Empty snapshot — no tenants at all.
        apply_multi_tenant_snapshot(&registry, &MultiTenantConfigResponse {
            tenants: HashMap::new(),
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        });
        // SYSTEM still present.
        assert!(registry.load().contains_key(&TenantId::SYSTEM));
    }

    #[test]
    fn multi_tenant_snapshot_skips_invalid_uuid() {
        let registry = new_tenant_registry();
        let mut tenants = HashMap::new();
        tenants.insert("not-a-uuid".to_string(), make_response(vec![]));
        tenants.insert(
            TEST_SYSTEM_TENANT_STR.to_string(),
            make_response(vec![make_mapping("test", "openai", "gpt-4")]),
        );
        apply_multi_tenant_snapshot(&registry, &MultiTenantConfigResponse {
            tenants,
            log_level: None,
            runtime_overrides: HashMap::new(),
            egress: Default::default(),
        });
        // Only SYSTEM should be in the map (invalid UUID skipped).
        let map = registry.load();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&TenantId::SYSTEM));
        assert!(map.get(&TenantId::SYSTEM).unwrap().model_map.resolve("test").is_some());
    }

    // --- ConfigResponse JSON parsing ---

    #[test]
    fn config_response_deserializes_from_json() {
        let json = body_json(serde_json::json!({
            "version": 42,
            "tenant_slug": "acme",
            "model_mappings": [mapping_json(serde_json::json!({ "id": "r1", "alias": "gpt-4o" }))],
            "api_keys": [{
                "key_hash": "abc123",
                "user_context": {
                    "user_id": "00000000-0000-0000-0000-000000000001",
                    "tenant_id": "00000000-0000-0000-0000-000000000001",
                    "workspace_id": "00000000-0000-0000-0000-000000000002",
                    "model_map": {"mappings": {}},
                    "rate_limit": {"requests_per_minute": 60, "tokens_per_minute": 100000, "daily_budget": 0.0, "monthly_budget": 0.0, "exempt": false},
                    "tenant_budget": null,
                },
            }],
        }));

        let resp: ConfigResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.model_mappings.len(), 1);
        assert_eq!(resp.model_mappings[0].alias, "gpt-4o");
        assert_eq!(resp.api_keys.len(), 1);
        assert_eq!(resp.api_keys[0].key_hash, "abc123");
    }

    /// Only an `Option` field may be absent from a body: serde reads it as
    /// `None`. Every other field the builder always writes, so a body missing
    /// one is malformed, never read as empty.
    #[test]
    fn a_body_may_omit_only_its_optional_fields() {
        let mut json = body_json(serde_json::json!({ "tenant_slug": "acme" }));
        json.as_object_mut().unwrap().retain(|_, v| !v.is_null());
        let resp: ConfigResponse = serde_json::from_value(json.clone()).unwrap();
        assert!(resp.proxy_public_url.is_none());
        for field in ["settings", "qos", "upstream_endpoints", "workspace_profiles"] {
            let mut missing = json.clone();
            missing.as_object_mut().unwrap().remove(field);
            match serde_json::from_value::<ConfigResponse>(missing) {
                Ok(_) => panic!("a body with no {field} must not deserialize"),
                Err(e) => assert!(e.to_string().contains(field), "expected {field}, got: {e}"),
            }
        }
    }

    /// The published key set is the proxy's ONLY way to verify an MCP token, so
    /// its absence from a body must be an error rather than an empty set —
    /// otherwise "this admin-api didn't send keys" silently becomes "this tenant
    /// has none" and every MCP token 401s with nothing to point at.
    #[test]
    fn a_snapshot_without_published_keys_is_rejected() {
        let mut json = body_json(serde_json::json!({ "tenant_slug": "acme" }));
        json.as_object_mut().unwrap().remove("mcp_jwks");
        // `expect_err` would need `ConfigResponse: Debug`, which the type does
        // not carry and should not gain for a test's benefit.
        match serde_json::from_value::<ConfigResponse>(json) {
            Ok(_) => panic!("a snapshot with no mcp_jwks key must not deserialize"),
            Err(e) => assert!(
                e.to_string().contains("mcp_jwks"),
                "expected the error to name the missing field, got: {e}"
            ),
        }
    }

    /// A profile kind the edge does not know fails the body — it is never
    /// dropped, which would silently resolve that kind's workspaces to nothing.
    #[test]
    fn a_body_naming_an_unknown_profile_kind_is_refused() {
        let ws = "00000000-0000-0000-0000-00000000000a";
        let known = body_json(serde_json::json!({ "workspace_profiles": [[ws, "tools", null]] }));
        assert!(serde_json::from_value::<ConfigResponse>(known).is_ok());
        let unknown = body_json(serde_json::json!({ "workspace_profiles": [[ws, "retention", null]] }));
        assert!(serde_json::from_value::<ConfigResponse>(unknown).is_err());
    }

    // --- MultiTenantConfigResponse JSON parsing ---

    #[test]
    fn multi_tenant_response_deserializes_from_json() {
        let json = serde_json::json!({
            "version": 5,
            "log_level": "debug",
            "runtime_overrides": {},
            "egress": {},
            "tenants": {
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa": body_json(serde_json::json!({
                    "version": 3,
                    "tenant_slug": "acme",
                    "model_mappings": [mapping_json(serde_json::json!({ "id": "r1", "alias": "gpt-4o" }))],
                }))
            }
        });

        let resp: MultiTenantConfigResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.log_level.as_deref(), Some("debug"));
        assert_eq!(resp.tenants.len(), 1);
        let tenant_cfg = resp.tenants.get("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(tenant_cfg.model_mappings.len(), 1);
    }

    #[test]
    fn multi_tenant_response_deserializes_without_log_level() {
        let json = serde_json::json!({
            "version": 1,
            "tenants": {},
            "runtime_overrides": {},
            "egress": {}
        });

        let resp: MultiTenantConfigResponse = serde_json::from_value(json).unwrap();
        assert!(resp.log_level.is_none());
        assert!(resp.tenants.is_empty());
    }
}
