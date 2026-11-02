//! Config snapshot persistence for offline cold start.
//!
//! Saves the full multi-tenant config to disk after each successful sync so the
//! proxy can start serving requests even when admin-api is unreachable. Uses
//! atomic write (write to `.tmp`, then rename) to prevent corruption from crashes.

use crate::config_sync::MultiTenantConfigResponse;

/// Save a multi-tenant config snapshot to `{data_dir}/config_snapshot_mt.json`.
///
/// Uses atomic write (write to .tmp, then rename) to avoid corruption.
pub fn save_snapshot(
    data_dir: &str,
    config: &MultiTenantConfigResponse,
) -> Result<(), anyhow::Error> {
    let path = format!("{data_dir}/config_snapshot_mt.json");
    let tmp_path = format!("{path}.tmp");
    let json = serde_json::to_string(config)?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, &path)?;
    tracing::debug!(path = %path, "saved config snapshot to disk");
    Ok(())
}

/// Load config snapshot from disk. Returns `None` if no snapshot file exists.
pub fn load_snapshot(
    data_dir: &str,
) -> Result<Option<MultiTenantConfigResponse>, anyhow::Error> {
    let path = format!("{data_dir}/config_snapshot_mt.json");
    match std::fs::read_to_string(&path) {
        Ok(json) => {
            // A snapshot written by a different build can fail to parse when the
            // wire shape gains a required field. Callers treat that as "no
            // snapshot" and wait for the first sync answer, which is the right
            // behaviour — but say so, because the alternative is a replica that
            // silently comes up unable to serve until admin-api answers and
            // nothing in the log explains why.
            // Read under the edge link's bound, as the bodies it was saved
            // from were: a snapshot deep enough to need it must reload.
            let snapshot: MultiTenantConfigResponse =
                streamscope_core::edge_wire::from_str_bounded(&json).inspect_err(|e| {
                    tracing::warn!(
                        path = %path,
                        "discarding unreadable config snapshot ({e}) — serving nothing \
                         until the first sync answer arrives"
                    );
                })?;
            Ok(Some(snapshot))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Merge an incremental config update into the persisted disk snapshot.
///
/// Loads the current snapshot, applies tenant changes, and saves back atomically.
/// If no snapshot exists on disk, creates a new one from the updates.
pub fn merge_incremental_update(
    data_dir: &str,
    update: &crate::config_sync::IncrementalConfigUpdate,
) -> Result<(), anyhow::Error> {
    // An unreadable snapshot is replaced, not merged into: the held set was
    // discarded with it at load, so every body is being sent again.
    let mut snapshot = load_snapshot(data_dir)
        .unwrap_or_else(|e| {
            tracing::warn!("replacing an unreadable config snapshot: {e}");
            None
        })
        .unwrap_or_else(|| MultiTenantConfigResponse {
            tenants: std::collections::HashMap::new(),
            log_level: None,
            runtime_overrides: std::collections::HashMap::new(),
            egress: std::collections::BTreeMap::new(),
        });

    for (tid, config) in &update.updates {
        snapshot.tenants.insert(tid.clone(), config.clone());
    }
    for tid in &update.removed_tenants {
        snapshot.tenants.remove(tid);
    }
    if let Some(level) = &update.log_level {
        snapshot.log_level = Some(level.clone());
    }
    if let Some(overrides) = &update.runtime_overrides {
        snapshot.runtime_overrides = overrides.clone();
    }
    if let Some(lists) = &update.egress {
        snapshot.egress = lists.clone();
    }

    save_snapshot(data_dir, &snapshot)
}

/// Persist the global runtime-override set to `{data_dir}/runtime_overrides.json`.
///
/// This is the file `streamscope_core::settings::read_runtime_overrides` reads
/// at process startup to apply central overrides. Atomic write (`.tmp` then
/// rename) to avoid corruption from crashes.
pub fn save_runtime_overrides(
    data_dir: &str,
    overrides: &std::collections::HashMap<String, String>,
) -> Result<(), anyhow::Error> {
    let path = streamscope_core::settings::runtime_overrides_path(data_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(overrides)?)?;
    std::fs::rename(&tmp, &path)?;
    tracing::debug!(path = %path.display(), "saved runtime overrides to disk");
    Ok(())
}

/// Persist the pushed runtime-override set to the dedicated file
/// `streamscope_core::settings::read_runtime_overrides` reads at startup, and
/// log when a restart is needed to apply a change.
pub fn persist_runtime_overrides(
    data_dir: &str,
    overrides: &std::collections::HashMap<String, String>,
) {
    if let Err(e) = save_runtime_overrides(data_dir, overrides) {
        // Loud, not a debug aside: a failed persist (typically a FULL data
        // partition — ENOSPC) silently drops central platform overrides such
        // as CUSTOM_CA_BUNDLE_PEM. The override stays applied on the admin
        // side (so the upstream-add probe still passes) but never reaches
        // this edge's on-disk override file, so it is NOT applied on the next
        // restart either — the change appears to "not take" no matter how
        // many times the operator reboots. Surface it at error level with the
        // most likely cause so a full disk is diagnosable from the proxy log.
        tracing::error!(
            error = %e,
            data_dir = %data_dir,
            "FAILED to persist runtime overrides to disk — central settings \
             (e.g. custom CA bundle) will NOT survive a restart. Most likely \
             the data partition is full; free space or enlarge the disk."
        );
        return;
    }
    let core = streamscope_core::settings::core_settings();
    let proxy = crate::settings::proxy_settings();
    let mut loaded = core.loaded_overrides.clone();
    loaded.extend(proxy.loaded_overrides.clone());
    if loaded != *overrides {
        tracing::info!(
            pending = overrides.len(),
            "runtime override change received — restart the edge to apply"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_sync::ConfigResponse;

    #[test]
    fn roundtrip_snapshot() {
        let dir = std::env::temp_dir().join(format!("streamscope_snap_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let data_dir = dir.to_str().unwrap();

        let tenant_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string();
        let mut tenants = std::collections::HashMap::new();
        tenants.insert(
            tenant_id.clone(),
            ConfigResponse {
                model_mappings: vec![streamscope_edge_api::config::EdgeModelMapping {
                    id: String::new(),
                    tenant_id: tenant_id.clone(),
                    catalog_matched: false,
                    alias: "claude-3".to_string(),
                    provider: "anthropic".to_string(),
                    upstream_model: "claude-3-opus".to_string(),
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
                }],
                api_keys: vec![],
                settings: std::collections::HashMap::new(),
                transform_programs: vec![],
                mcp_upstream_servers: vec![],
                mcp_virtual_servers: vec![],
                mcp_virtual_routes: vec![],
                mcp_user_credentials: vec![],
                mcp_revoked_jtis: vec![],
                mcp_jwks: vec![],
                a2a_agents: vec![],
                tenant_slug: String::new(),
                workspace_rate_limits: std::collections::HashMap::new(),
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
            },
        );

        let config = MultiTenantConfigResponse {
            tenants,
            log_level: Some("debug".to_string()),
            runtime_overrides: std::collections::HashMap::new(),
            egress: Default::default(),
        };

        save_snapshot(data_dir, &config).unwrap();
        let loaded = load_snapshot(data_dir).unwrap().unwrap();
        assert_eq!(loaded.log_level.as_deref(), Some("debug"));
        assert_eq!(loaded.tenants.len(), 1);
        let tenant_cfg = loaded.tenants.get(&tenant_id).unwrap();
        assert_eq!(tenant_cfg.model_mappings[0].alias, "claude-3");
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = std::env::temp_dir().join(format!("streamscope_snap_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = load_snapshot(dir.to_str().unwrap()).unwrap();
        assert!(result.is_none());
    }
}
