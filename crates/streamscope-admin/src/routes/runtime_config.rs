//! Platform runtime-config endpoints — the super-admin Advanced settings tab.
//!
//! `GET / PATCH /api/v1/admin/global/runtime-config`. The settings catalog
//! (`streamscope_core::settings_catalog`) is the single source of truth; this
//! module joins it with the `platform_setting_overrides` table (the *desired*
//! override set) and the per-edge heartbeat reports (the *actual* running
//! state). Overrides for the ~80 edge/proxy settings are centrally editable
//! and pushed to edges; admin-api's own settings are display-only.

use crate::db::{Db, Global};
use std::collections::HashMap;
use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use streamscope_core::settings_catalog::{
    SETTINGS_CATALOG, SettingDescriptor, SettingGroup, SettingKind,
};

use crate::AdminState;
use crate::db::tenant::AdminTenantCtx;
use crate::edge_nodes::EdgeNodeMetadata;
use crate::routes::{ApiError, ApiErrorResponse};
use crate::settings::admin_settings;

/// `GET /api/v1/admin/global/runtime-config` response — the catalog plus
/// desired (override) and actual (per-edge) state.
#[derive(Serialize, ToSchema)]
pub struct RuntimeConfigResponse {
    /// Every catalog entry, with its current desired override (if set).
    pub catalog: Vec<SettingDescriptor>,
    /// admin-api process effective values, keyed by token (Admin-group only).
    pub admin_values: HashMap<String, String>,
    /// Secret / bootstrap token → whether it is set in the admin-api process.
    /// The value itself is never serialized.
    pub secrets_present: HashMap<String, bool>,
    /// Per-edge actual running state.
    pub edges: Vec<EdgeRuntimeStatus>,
}

/// One edge node's actual runtime-config state.
#[derive(Serialize, ToSchema)]
pub struct EdgeRuntimeStatus {
    pub node_id: uuid::Uuid,
    pub node_name: String,
    pub connected: bool,
    /// RFC3339 timestamp of the most recent heartbeat, if any.
    pub reported_at: Option<String>,
    /// Token → actual running value reported by this edge (core + proxy).
    /// Empty when the edge has not reported a runtime block yet.
    pub effective: HashMap<String, String>,
    /// Overridable tokens whose desired override differs from what the edge
    /// booted with — the edge must restart to converge.
    pub restart_pending: Vec<String>,
}

/// `PATCH /api/v1/admin/global/runtime-config` request — a partial override map.
#[derive(Deserialize, ToSchema)]
pub struct UpdateRuntimeConfigRequest {
    /// Token → new override value, or `null` to clear the override.
    pub overrides: HashMap<String, Option<String>>,
}

/// Read the platform override set (token → value) from the global table.
pub async fn read_platform_overrides(
    pool: &Db,
) -> Result<HashMap<String, String>, sqlx::Error> {
    let rows =
        sqlx::query_as::<_, (String, String)>("SELECT token, value FROM platform_setting_overrides")
            .fetch_all(pool.global(Global::Infra))
            .await?;
    Ok(rows.into_iter().collect())
}

/// Some settings as each gateway runs them.
pub struct FleetSettings {
    /// One map per connected gateway NODE that reported, token → value — or,
    /// when none has, the single set a gateway would start with (the platform
    /// override, else the catalog default). Never empty. Kept per node so two
    /// settings that combine are combined as one node runs them. A node's
    /// replicas share its configuration and the node keeps one report (its
    /// latest writer's), so replicas of one node that disagree — mid rolling
    /// restart — are seen as whichever reported last.
    pub gateways: Vec<HashMap<&'static str, String>>,
    /// `true` when read from what connected gateways report running.
    pub reported: bool,
}

/// What the connected gateways run for `tokens`. A gateway reports its
/// effective settings on every heartbeat, which is the only source that sees a
/// value set in a gateway's own environment; the desired half (override, else
/// default) stands in only while no gateway has reported.
pub async fn fleet_settings(db: &Db, tokens: &[&'static str]) -> Result<FleetSettings, sqlx::Error> {
    // Nodes with a replica seen within the connected-gateway window: an
    // instance row outlives its process until it is reaped.
    let rows = sqlx::query_as::<_, (uuid::Uuid, Option<serde_json::Value>)>(
        "SELECT n.id, n.metadata FROM edge_nodes n \
         WHERE EXISTS (SELECT 1 FROM edge_instances i WHERE i.edge_node_id = n.id \
                         AND i.last_seen_at >= now() - make_interval(secs => $1))",
    )
    .bind(crate::routes::upstream_endpoints::connected_within_secs() as f64)
    .fetch_all(db.global(Global::Infra))
    .await?;
    let gateways: Vec<HashMap<&'static str, String>> = rows
        .into_iter()
        .filter_map(|(_, metadata)| {
            let effective = serde_json::from_value::<EdgeNodeMetadata>(metadata?).ok()?.runtime?.effective;
            let values: HashMap<&'static str, String> =
                tokens.iter().filter_map(|t| effective.get(*t).map(|v| (*t, v.clone()))).collect();
            (values.len() == tokens.len()).then_some(values)
        })
        .collect();
    if !gateways.is_empty() {
        return Ok(FleetSettings { gateways, reported: true });
    }
    let overrides = read_platform_overrides(db).await?;
    let desired = tokens
        .iter()
        .map(|t| {
            let v = overrides.get(*t).cloned().unwrap_or_else(|| {
                streamscope_core::settings_catalog::lookup(t).map(|m| m.default.to_string()).unwrap_or_default()
            });
            (*t, v)
        })
        .collect();
    Ok(FleetSettings { gateways: vec![desired], reported: false })
}

/// Validate an override value against the setting's declared kind.
fn validate_value(kind: SettingKind, value: &str) -> Result<(), String> {
    match kind {
        SettingKind::Integer => value
            .parse::<u64>()
            .map(|_| ())
            .map_err(|_| "expected a non-negative integer".to_string()),
        SettingKind::Bool => value
            .parse::<bool>()
            .map(|_| ())
            .map_err(|_| "expected `true` or `false`".to_string()),
        SettingKind::Text | SettingKind::Url => {
            if value.trim().is_empty() {
                Err("expected a non-empty value".to_string())
            } else {
                Ok(())
            }
        }
        SettingKind::Secret => Err("secrets cannot be set via this endpoint".to_string()),
    }
}

async fn build_response(pool: &Db) -> Result<RuntimeConfigResponse, ApiError> {
    let overrides = read_platform_overrides(pool).await.map_err(|e| {
        tracing::error!("runtime-config: read overrides: {e}");
        ApiError::internal("failed to load runtime config")
    })?;

    let catalog: Vec<SettingDescriptor> = SETTINGS_CATALOG
        .iter()
        .map(|meta| meta.to_descriptor(overrides.get(meta.token).cloned()))
        .collect();

    let admin_values = admin_settings().effective_values();

    let secrets_present: HashMap<String, bool> = SETTINGS_CATALOG
        .iter()
        .filter(|m| m.group == SettingGroup::Secret)
        .map(|m| {
            let present = std::env::var(m.token).map(|v| !v.is_empty()).unwrap_or(false);
            (m.token.to_string(), present)
        })
        .collect();

    let sync = crate::edge_v2::status::node_sync(pool).await.map_err(|e| {
        tracing::error!("runtime-config: read edge instance state: {e}");
        ApiError::internal("failed to load runtime config")
    })?;
    let rows = sqlx::query_as::<_, (uuid::Uuid, String, Option<serde_json::Value>)>(
        "SELECT id, name, metadata FROM edge_nodes ORDER BY created_at",
    )
    .fetch_all(pool.global(Global::Infra))
    .await
    .map_err(|e| {
        tracing::error!("runtime-config: list edge nodes: {e}");
        ApiError::internal("failed to load runtime config")
    })?;

    let edges: Vec<EdgeRuntimeStatus> = rows
        .into_iter()
        .map(|(id, name, metadata)| {
            let meta = metadata.and_then(|v| serde_json::from_value::<EdgeNodeMetadata>(v).ok());
            let reported_at = meta.as_ref().and_then(|m| m.stats_updated_at.clone());
            // The edge report is the *actual* half; diff it against the
            // *desired* override set to surface "restart pending".
            let (effective, restart_pending) = match meta.and_then(|m| m.runtime) {
                Some(report) => {
                    let mut pending: Vec<String> = SETTINGS_CATALOG
                        .iter()
                        .filter(|m| m.overridable)
                        .filter(|m| {
                            overrides.get(m.token) != report.loaded_overrides.get(m.token)
                        })
                        .map(|m| m.token.to_string())
                        .collect();
                    pending.sort();
                    (report.effective, pending)
                }
                None => (HashMap::new(), Vec::new()),
            };
            EdgeRuntimeStatus {
                node_id: id,
                node_name: name,
                connected: sync.get(&id).is_some_and(|s| s.live_instances > 0),
                reported_at,
                effective,
                restart_pending,
            }
        })
        .collect();

    Ok(RuntimeConfigResponse {
        catalog,
        admin_values,
        secrets_present,
        edges,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/runtime-config",
    tag = "Settings",
    responses(
        (status = 200, description = "Runtime config catalog + per-edge state", body = RuntimeConfigResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_runtime_config(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<RuntimeConfigResponse>, ApiError> {
    build_response(&state.db).await.map(Json)
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/global/runtime-config",
    tag = "Settings",
    request_body = UpdateRuntimeConfigRequest,
    responses(
        (status = 200, description = "Updated runtime config", body = RuntimeConfigResponse),
        (status = 400, description = "Unknown token, non-overridable setting, or invalid value", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn patch_runtime_config(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AdminTenantCtx>,
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<UpdateRuntimeConfigRequest>,
) -> Result<Json<RuntimeConfigResponse>, ApiError> {
    if body.overrides.is_empty() {
        return Err(ApiError::bad_request("no overrides supplied"));
    }

    // Snapshot the effective runtime config before the write for the audit diff.
    let before = build_response(&state.db).await.ok();

    // Validate every token + value before applying any of them.
    for (token, value) in &body.overrides {
        let meta = streamscope_core::settings_catalog::lookup(token)
            .ok_or_else(|| ApiError::bad_request(format!("unknown setting token: {token}")))?;
        if !meta.overridable {
            return Err(ApiError::bad_request(format!(
                "setting {token} cannot be centrally overridden"
            )));
        }
        if let Some(v) = value {
            validate_value(meta.kind, v)
                .map_err(|msg| ApiError::bad_request(format!("invalid value for {token}: {msg}")))?;
            // The custom CA bundle must actually parse as PEM, or it is silently
            // ignored when the proxy builds its outbound client (system roots
            // only) and the internal upstream stays untrusted. Reject a broken
            // paste here, immediately, with a reason — same parser the proxy uses.
            if token == "CUSTOM_CA_BUNDLE_PEM" {
                streamscope_core::tls::validate_ca_bundle(v).map_err(|msg| {
                    ApiError::bad_request(format!("invalid value for {token}: {msg}"))
                })?;
            }
        }
    }

    // Apply the whole batch in one transaction — a mid-loop failure must not
    // leave a partially-applied override set that a later push would ship.
    let mut tx = state.db.begin_global(Global::Infra).await.map_err(|e| {
        tracing::error!("runtime-config: begin transaction: {e}");
        ApiError::internal("failed to save runtime config")
    })?;
    for (token, value) in &body.overrides {
        let result = match value {
            Some(v) => {
                sqlx::query(
                    "INSERT INTO platform_setting_overrides (token, value, updated_at, updated_by)
                     VALUES ($1, $2, now(), $3)
                     ON CONFLICT (token)
                     DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by",
                )
                .bind(token)
                .bind(v)
                .bind(ctx.admin_account_id)
                .execute(&mut *tx)
                .await
            }
            None => {
                sqlx::query("DELETE FROM platform_setting_overrides WHERE token = $1")
                    .bind(token)
                    .execute(&mut *tx)
                    .await
            }
        };
        result.map_err(|e| {
            tracing::error!("runtime-config: persist override {token}: {e}");
            ApiError::internal("failed to save runtime config")
        })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("runtime-config: commit transaction: {e}");
        ApiError::internal("failed to save runtime config")
    })?;


    // Refresh admin-api's own outbound-client trust store in-process so a custom
    // CA import takes effect immediately (probe/discovery/OIDC/etc.) without a
    // restart. Edges pick it up on their next restart via the pushed override.
    crate::custom_ca::refresh_from_db(&state.db).await;

    let after = build_response(&state.db).await?;
    audit_sink.record(before.as_ref(), Some(&after));
    Ok(Json(after))
}
