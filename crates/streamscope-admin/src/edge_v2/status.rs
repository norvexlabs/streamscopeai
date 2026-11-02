//! `GET /api/v1/admin/global/edge-sync` — whether every edge instance holds the
//! current config, and how much it still has to ship.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use streamscope_edge_api::digest::Digest;
use streamscope_edge_api::sync::{Held, ResourceName};
use utoipa::ToSchema;

use crate::AdminState;
use crate::db::Global;
use crate::routes::{ApiError, ApiErrorResponse};

/// An instance is live while its last sync is this recent.
const LIVE_SECS: f64 = streamscope_edge_api::ingest::INSTANCE_LIVE_SECS as f64;

#[derive(Serialize, ToSchema)]
pub struct EdgeInstanceSync {
    pub instance_id: uuid::Uuid,
    pub edge_node_id: uuid::Uuid,
    pub edge_node_name: String,
    /// The instance's own id, as it states it on every request.
    pub instance_key: String,
    pub last_sync_at: chrono::DateTime<chrono::Utc>,
    pub live: bool,
    /// Rows the instance still had buffered for ingest at its last sync.
    pub outbox_pending: i64,
    /// When admin-api last merged every counter of a usage report from the
    /// instance. The edge reports every counter it holds each usage interval,
    /// so the second stamp after a moment covers every counter it had accrued
    /// by then — not a request whose accrual was still to come (a stream's
    /// audit task; wait for `outbox_pending` to drain first), nor a delta the
    /// edge itself dropped while admin-api was unreachable.
    pub usage_merged_at: Option<chrono::DateTime<chrono::Utc>>,
    /// What the instance's last request said it holds — once no answer is
    /// in flight or unreported ([`settled_held`]) — carries the current digest
    /// of every resource this replica serves, as its cache has it (at most one
    /// `EDGE_SYNC_REFRESH_MS` behind the database; the tenant status reads
    /// the database itself).
    pub synced: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EdgeSyncStatus {
    /// Every instance that has used the v2 sync, most recent first.
    pub instances: Vec<EdgeInstanceSync>,
    /// Tables a config build on the answering replica read that carry no
    /// change triggers — a change to one never reaches an edge. Empty is the
    /// only correct value.
    pub untracked_tables: Vec<String>,
    /// False until the answering replica has built its config cache (it starts
    /// at boot); while false, no instance is reported synced — ask again.
    pub ready: bool,
}

/// Whether `held` carries `current`'s digest for every resource of `current`.
fn holds_current(held: &BTreeMap<ResourceName, Digest>, current: &BTreeMap<ResourceName, Digest>) -> bool {
    current.iter().all(|(r, d)| held.get(r) == Some(d))
}

fn held_map(held: Option<serde_json::Value>) -> BTreeMap<ResourceName, Digest> {
    held.and_then(|v| serde_json::from_value::<Vec<Held>>(v).ok())
        .map(|hs| hs.into_iter().map(|h| (h.resource, h.digest)).collect())
        .unwrap_or_default()
}

/// What an instance can be said to hold, per resource: the digest its last
/// request stated (`confirmed`), where that is also the digest the admin
/// predicted after its last answer (`held`). Where they differ an answer for
/// that resource is in flight, or applied but not yet reported — the edge may
/// already serve a body newer than the one it last stated, so the stated digest
/// proves nothing (a body changed back to an earlier digest would match it) and
/// the resource is not held. Per resource, so a busy fleet whose other bodies
/// are always moving still settles each one.
fn settled_held(confirmed: Option<serde_json::Value>, predicted: Option<serde_json::Value>) -> BTreeMap<ResourceName, Digest> {
    let predicted = held_map(predicted);
    held_map(confirmed).into_iter().filter(|(r, d)| predicted.get(r) == Some(d)).collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/edge-sync",
    tag = "Edge Nodes",
    responses(
        (status = 200, description = "Edge instance sync state", body = EdgeSyncStatus),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn edge_sync_status(State(state): State<Arc<AdminState>>) -> Result<Json<EdgeSyncStatus>, ApiError> {
    type Row = (uuid::Uuid, uuid::Uuid, String, String, chrono::DateTime<chrono::Utc>, bool, Option<i64>, Option<chrono::DateTime<chrono::Utc>>, Option<serde_json::Value>, Option<serde_json::Value>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.id, i.edge_node_id, n.name, i.instance_key, i.last_sync_at, \
                i.last_sync_at > now() - make_interval(secs => $1), i.outbox_pending, i.usage_merged_at, \
                CASE WHEN i.last_sync_at > now() - make_interval(secs => $1) THEN i.confirmed END, CASE WHEN i.last_sync_at > now() - make_interval(secs => $1) THEN i.held END \
           FROM edge_instances i JOIN edge_nodes n ON n.id = i.edge_node_id \
          WHERE i.last_sync_at IS NOT NULL \
          ORDER BY i.last_sync_at DESC",
    )
    .bind(LIVE_SECS)
    .fetch_all(state.db.global(Global::Infra))
    .await
    .map_err(|e| {
        tracing::error!("edge sync status: {e}");
        ApiError::internal("Failed to read edge sync status")
    })?;

    // Until this replica has built its cache, `ready` is false and no instance
    // can be reported synced against it.
    let current = super::sync::current_digests().await;
    let instances = rows
        .into_iter()
        .map(|(instance_id, edge_node_id, edge_node_name, instance_key, last_sync_at, live, pending, usage_merged_at, confirmed, predicted)| {
            let held = settled_held(confirmed, predicted);
            EdgeInstanceSync {
                instance_id,
                edge_node_id,
                edge_node_name,
                instance_key,
                last_sync_at,
                live,
                outbox_pending: pending.unwrap_or(0),
                usage_merged_at,
                synced: current.as_ref().is_some_and(|c| holds_current(&held, c)),
            }
        })
        .collect();

    Ok(Json(EdgeSyncStatus {
        instances,
        untracked_tables: super::sync::untracked_tables(),
        ready: current.is_some(),
    }))
}

#[derive(Serialize, ToSchema)]
pub struct TenantEdgeSync {
    pub node_id: uuid::Uuid,
    pub node_name: String,
    /// Some replica of this edge has synced recently. `all_synced` counts only
    /// these, so an edge that never connected cannot read as lagging.
    pub is_connected: bool,
    /// Every live replica holds the tenant's current config.
    pub synced: bool,
}

#[derive(Serialize, ToSchema)]
pub struct TenantSyncStatus {
    /// Every live replica of every edge holds this tenant's current config
    /// and the current global config, read from the database now; false when
    /// no replica is live.
    pub all_synced: bool,
    pub nodes: Vec<TenantEdgeSync>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/config-sync/tenant-status",
    tag = "Edge Nodes",
    responses(
        (status = 200, description = "Whether the edge fleet holds this tenant's current config", body = TenantSyncStatus),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn tenant_sync_status(
    State(state): State<Arc<AdminState>>,
    ctx: axum::extract::Extension<crate::db::tenant::AdminTenantCtx>,
) -> Result<Json<TenantSyncStatus>, ApiError> {
    let fail = |e: sqlx::Error| {
        tracing::error!(tenant_id = %ctx.tenant_id.as_uuid(), "tenant sync status: {e}");
        ApiError::internal("Failed to read edge sync status")
    };
    type Row = (uuid::Uuid, String, Option<bool>, Option<serde_json::Value>, Option<serde_json::Value>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT n.id, n.name, i.last_sync_at > now() - make_interval(secs => $1), \
                CASE WHEN i.last_sync_at > now() - make_interval(secs => $1) THEN i.confirmed END, CASE WHEN i.last_sync_at > now() - make_interval(secs => $1) THEN i.held END \
           FROM edge_nodes n LEFT JOIN edge_instances i ON i.edge_node_id = n.id AND i.last_sync_at IS NOT NULL \
          ORDER BY n.created_at, n.id",
    )
    .bind(LIVE_SECS)
    .fetch_all(state.db.global(Global::Infra))
    .await
    .map_err(fail)?;
    // Read as an answer would send them, so a change committed a moment ago
    // is never reported held before an edge could have been sent it.
    // SYSTEM carries no workload config: edges hold only `global` for it.
    let mut wanted = vec![ResourceName::Global];
    if ctx.tenant_id != crate::db::tenant::TenantId::SYSTEM {
        wanted.push(ResourceName::Tenant(ctx.tenant_id.as_uuid()));
    }
    let current = super::sync::fresh_digests(&state.db, wanted.clone()).await.map_err(fail)?;
    let rows = rows
        .into_iter()
        .map(|(id, name, live, confirmed, predicted)| (id, name, live == Some(true), settled_held(confirmed, predicted)));
    let (nodes, all_synced) = fold_nodes(rows, &wanted, &current);
    Ok(Json(TenantSyncStatus { all_synced, nodes }))
}

/// Fold one row per (node, instance) — rows of a node adjacent, a node with
/// no instance as one row that is not live — into per-node status and the
/// fleet verdict: a node is connected when one of its instances is live and
/// synced when every live one holds `current` for every `wanted` resource;
/// the fleet is synced when some node is connected and every connected one is
/// synced. A `wanted` resource missing from `current` (not buildable now) is
/// never held.
fn fold_nodes(
    rows: impl Iterator<Item = (uuid::Uuid, String, bool, BTreeMap<ResourceName, Digest>)>,
    wanted: &[ResourceName],
    current: &BTreeMap<ResourceName, Digest>,
) -> (Vec<TenantEdgeSync>, bool) {
    let built = wanted.iter().all(|r| current.contains_key(r));
    let mut nodes: Vec<TenantEdgeSync> = Vec::new();
    for (node_id, node_name, live, held) in rows {
        if nodes.last().is_none_or(|n| n.node_id != node_id) {
            nodes.push(TenantEdgeSync { node_id, node_name, is_connected: false, synced: true });
        }
        let Some(n) = nodes.last_mut() else { continue };
        if live {
            n.is_connected = true;
            n.synced &= built && holds_current(&held, current);
        }
    }
    for n in &mut nodes {
        n.synced &= n.is_connected;
    }
    let all_synced = nodes.iter().any(|n| n.is_connected) && nodes.iter().filter(|n| n.is_connected).all(|n| n.synced);
    (nodes, all_synced)
}

/// One logical edge's instances, as the edge-node list shows them.
#[derive(Default)]
pub(crate) struct NodeSync {
    pub live_instances: i64,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Some instance is live and every live one holds the current config.
    pub synced: bool,
}

/// [`NodeSync`] per edge node, by the same liveness and digest comparison as
/// [`edge_sync_status`]. A node with no instance is absent. The held sets are
/// read for live instances only — a fleet keeps every replaced pod's row until
/// retention reaps it.
pub(crate) async fn node_sync(db: &crate::db::Db) -> Result<std::collections::HashMap<uuid::Uuid, NodeSync>, sqlx::Error> {
    type Row = (uuid::Uuid, chrono::DateTime<chrono::Utc>, bool, Option<serde_json::Value>, Option<serde_json::Value>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT edge_node_id, last_sync_at, last_sync_at > now() - make_interval(secs => $1), \
                CASE WHEN last_sync_at > now() - make_interval(secs => $1) THEN confirmed END, CASE WHEN last_sync_at > now() - make_interval(secs => $1) THEN held END \
           FROM edge_instances WHERE last_sync_at IS NOT NULL",
    )
    .bind(LIVE_SECS)
    .fetch_all(db.global(Global::Infra))
    .await?;
    let current = super::sync::current_digests().await;
    let mut nodes: std::collections::HashMap<uuid::Uuid, NodeSync> = std::collections::HashMap::new();
    let mut stale: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    for (node, last_sync_at, live, confirmed, predicted) in rows {
        let n = nodes.entry(node).or_default();
        n.last_sync_at = n.last_sync_at.max(Some(last_sync_at));
        if !live {
            continue;
        }
        n.live_instances += 1;
        let held = settled_held(confirmed, predicted);
        if !current.as_ref().is_some_and(|c| holds_current(&held, c)) {
            stale.insert(node);
        }
    }
    for (id, n) in &mut nodes {
        n.synced = n.live_instances > 0 && !stale.contains(id);
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fleet_is_synced_only_when_every_live_replica_holds_every_wanted_resource() {
        let t = ResourceName::Tenant(uuid::Uuid::from_bytes([1; 16]));
        let d = |s: &str| Digest::of(s.as_bytes());
        let wanted = [ResourceName::Global, t];
        let current: BTreeMap<_, _> = [(ResourceName::Global, d("g")), (t, d("1"))].into();
        let stale: BTreeMap<_, _> = [(ResourceName::Global, d("g")), (t, d("old"))].into();
        let (a, b) = (uuid::Uuid::from_bytes([10; 16]), uuid::Uuid::from_bytes([11; 16]));
        let row = |n: uuid::Uuid, live: bool, held: &BTreeMap<ResourceName, Digest>| (n, "n".to_string(), live, held.clone());
        let fold = |rows: Vec<_>, current: &BTreeMap<ResourceName, Digest>| fold_nodes(rows.into_iter(), &wanted, current);

        let (nodes, all) = fold(vec![row(a, true, &current), row(a, true, &current)], &current);
        assert!(all && nodes.len() == 1 && nodes[0].synced, "every live replica current: synced");
        let (nodes, all) = fold(vec![row(a, true, &current), row(a, true, &stale)], &current);
        assert!(!all && !nodes[0].synced, "one stale live replica holds its node back");
        let (_, all) = fold(vec![row(a, true, &current), row(a, false, &stale)], &current);
        assert!(all, "a replica that is not live does not gate");
        let (nodes, all) = fold(vec![row(a, true, &current), row(b, false, &BTreeMap::new())], &current);
        assert!(all && !nodes[1].is_connected && !nodes[1].synced, "a node never connected does not gate, and is not synced");
        let (_, all) = fold(vec![row(a, false, &current)], &current);
        assert!(!all, "no live replica anywhere: not synced");
        let unbuilt: BTreeMap<_, _> = [(ResourceName::Global, d("g"))].into();
        let (_, all) = fold(vec![row(a, true, &current)], &unbuilt);
        assert!(!all, "a wanted resource that cannot be built is never held");
    }

    #[test]
    fn a_stated_set_counts_only_once_the_admin_predicted_nothing_newer() {
        let t = ResourceName::Tenant(uuid::Uuid::from_bytes([1; 16]));
        let set = |d: &str| serde_json::json!([{ "resource": t.to_string(), "digest": Digest::of(d.as_bytes()).to_hex() }]);
        let u = ResourceName::Tenant(uuid::Uuid::from_bytes([2; 16]));
        let two = |a: &str, b: &str| serde_json::json!([
            { "resource": t.to_string(), "digest": Digest::of(a.as_bytes()).to_hex() },
            { "resource": u.to_string(), "digest": Digest::of(b.as_bytes()).to_hex() },
        ]);
        let held: BTreeMap<_, _> = [(t, Digest::of(b"a"))].into();
        assert_eq!(settled_held(Some(set("a")), Some(set("a"))), held, "stated = predicted: held");
        // Stated A, sent B since: the edge may already serve B. A current body
        // equal to A again (a change undone) must not read as held.
        assert!(settled_held(Some(set("a")), Some(set("b"))).is_empty(), "an answer unreported: not held");
        assert!(settled_held(None, Some(set("a"))).is_empty(), "never stated: nothing held");
        // Another resource in flight does not unsettle this one.
        assert_eq!(settled_held(Some(two("a", "x")), Some(two("a", "y"))), held, "settled per resource");
    }

    #[test]
    fn synced_means_every_current_digest_is_held() {
        let t = |n: u8| ResourceName::Tenant(uuid::Uuid::from_bytes([n; 16]));
        let d = |s: &str| Digest::of(s.as_bytes());
        let current: BTreeMap<_, _> = [(ResourceName::Global, d("g")), (t(1), d("1"))].into();
        assert!(holds_current(&current.clone(), &current));
        let mut extra = current.clone();
        extra.insert(t(9), d("9"));
        assert!(holds_current(&extra, &current), "holding more than current is still synced");
        let stale: BTreeMap<_, _> = [(ResourceName::Global, d("g")), (t(1), d("old"))].into();
        assert!(!holds_current(&stale, &current));
        let missing: BTreeMap<_, _> = [(ResourceName::Global, d("g"))].into();
        assert!(!holds_current(&missing, &current));
    }
}
