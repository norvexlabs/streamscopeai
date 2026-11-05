//! Replica endpoints of an upstream server.
//!
//! A server is reached at one or more ENDPOINTS — replicas of one engine that
//! share the server's credential, provider, protocol and transport. The first
//! enabled endpoint by `(position, created_at, id)` is the PRIMARY.
//!
//! The endpoints are the only place a server's URLs are stored. The server
//! API's own `upstream_url` is the primary's URL: read through
//! `server_url_sql!`, written through [`write_primary_url`]. Every server has an
//! enabled endpoint from its creation on — the writes here refuse to leave it
//! none.
//!
//! What an endpoint serves: one that has never answered discovery
//! (`listed = false`) serves every model of its server and has no membership
//! rows; a listed one serves its rows in `upstream_model_endpoints`
//! ([`super::model_fusion`] decides them). [`effective_members`] is the one
//! reading of that rule.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_core::config::upstream_transport::UpstreamTransport;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};
use crate::AdminState;

/// How recently a gateway instance must have reached admin-api for it to count
/// as connected, in whole seconds
/// ([`crate::settings::AdminSettings::edge_connected_window`]). An instance
/// whose process is gone stops counting within it rather than when its row is
/// reaped.
pub(crate) fn connected_within_secs() -> i64 {
    crate::settings::admin_settings().edge_connected_window().num_seconds()
}

/// Gateway replicas connected now: an instance whose last request to admin-api
/// is within the connected-gateway window. An instance row outlives its process
/// until it is reaped, and counting it would double the fleet. A failed read is
/// an error, never a count: 0 would read as one gateway and suggest an N-times
/// over-commit.
pub(crate) async fn connected_gateway_replicas(db: &crate::db::Db) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM edge_instances WHERE last_seen_at >= now() - make_interval(secs => $1)",
    )
    .bind(connected_within_secs() as f64)
    .fetch_one(db.global(crate::db::Global::Infra))
    .await
    .map_err(|e| {
        tracing::error!("connected gateway replicas: {e}");
        ApiError::internal("failed to count the connected gateways")
    })
}

/// Every connected gateway's current stand on each enabled endpoint, one row
/// per (endpoint, gateway), with columns `endpoint_id`, `server_id`,
/// `edge_instance_id`, `out_of_rotation`, `session_started_at` (when the
/// gateway's current process epoch began). A gateway has a stand on an endpoint
/// while it routes there — it has sent there within `health::ROUTES_TO_WINDOW`
/// — and it is out of rotation while that gateway's breaker holds it out. A
/// gateway with no stand does not route to the endpoint and has no say in its
/// health.
///
/// Stands are restated with every instance-state report
/// (`upstream_endpoint_stands`), so one counts only while restated: from a
/// gateway seen now, stated in its current process epoch (`epoch_started_at`,
/// matched by equality), within the connected window of that gateway's LATEST
/// written report (`state_written_at`) — a report that stopped restating it
/// retires it — and only while that report is itself within the window: a
/// gateway whose reports stopped landing has no current stand, so nothing it
/// said before is shown as current. An older stand is from a process or a
/// route that is gone. A disabled endpoint takes no traffic, so it has no
/// stands. The only text spliced in is an integer, whose `Display` can emit
/// nothing but digits.
fn endpoint_stands_sql() -> String {
    let live = connected_within_secs();
    format!(
        "SELECT st.endpoint_id, e.server_id, st.edge_instance_id, st.out_of_rotation, \
                i.epoch_started_at AS session_started_at \
         FROM upstream_endpoint_stands st \
         JOIN upstream_server_endpoints e ON e.id = st.endpoint_id \
         JOIN edge_instances i ON i.id = st.edge_instance_id \
         WHERE e.enabled AND st.session_started_at = i.epoch_started_at \
           AND st.stated_at >= i.state_written_at - make_interval(secs => {live}) \
           AND i.state_written_at >= now() - make_interval(secs => {live}) \
           AND i.last_seen_at >= now() - make_interval(secs => {live})"
    )
}

/// The endpoints a connected gateway has out of rotation right now — its
/// breaker for the endpoint is open — one row per (endpoint, gateway), with
/// columns `endpoint_id`, `server_id`, `edge_instance_id`, `changed_at`,
/// `reason`. The last two come from that gateway's breaker event of its
/// current connection — when the outage began, and why — and are NULL when
/// that event was lost: the stand decides, the event only describes, and an
/// event from before the connection describes an earlier outage.
///
/// Out of rotation is ONE fact — a current stand with `out_of_rotation` from
/// [`endpoint_stands_sql`] — which this adds the detail to for the endpoint
/// table, and which [`server_health_columns_sql`] counts for the server list,
/// the server dashboard and the attention queue: change it there, never here,
/// or the views disagree about whether a server is down.
pub(crate) fn endpoints_out_of_rotation_sql() -> String {
    format!(
        "SELECT r.endpoint_id, r.server_id, r.edge_instance_id, h.changed_at, h.reason \
         FROM ({}) r \
         LEFT JOIN upstream_endpoint_health h \
           ON h.endpoint_id = r.endpoint_id AND h.edge_instance_id = r.edge_instance_id AND h.status = 'down' \
          AND h.reported_at >= r.session_started_at \
         WHERE r.out_of_rotation",
        endpoint_stands_sql()
    )
}

/// Per-server health counts for a query over `upstream_servers s`: the
/// server's enabled endpoints (`endpoints_enabled`), how many of them some
/// connected gateway has out of rotation (`endpoints_down`), and how many are
/// out on EVERY connected gateway that routes to them (`endpoints_out`). Read
/// into [`ServerHealth::of`].
///
/// A breaker is per gateway process, so one replica losing its path to an
/// engine takes the engine out of ITS rotation only; the others keep serving.
/// "Out everywhere" is the fact that makes a server unable to serve, and it is
/// judged over the gateways that route to the endpoint — the ones with a stand
/// on it ([`endpoint_stands_sql`]): one that never sends there has no say, or a
/// server nobody's traffic can reach would stay "degraded" behind every idle
/// gateway; one that serves through it states so on every beat, so it keeps
/// the server up. An endpoint no gateway has a stand on is not out.
pub(crate) fn server_health_columns_sql() -> String {
    let stands = endpoint_stands_sql();
    format!(
        "(SELECT COUNT(*) FROM upstream_server_endpoints e WHERE e.server_id = s.id AND e.enabled) \
           AS endpoints_enabled, \
         (SELECT COUNT(DISTINCT r.endpoint_id) FROM ({stands}) r \
            WHERE r.server_id = s.id AND r.out_of_rotation) AS endpoints_down, \
         (SELECT COUNT(*) FROM (SELECT r.endpoint_id FROM ({stands}) r WHERE r.server_id = s.id \
            GROUP BY r.endpoint_id \
            HAVING bool_and(r.out_of_rotation)) o) \
           AS endpoints_out"
    )
}

/// Whether an upstream server can serve traffic right now, as the connected
/// gateways report it.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ServerHealth {
    /// Every enabled endpoint is in rotation on every connected gateway.
    Healthy,
    /// Some gateway has some endpoint out of rotation; the rest carry the
    /// traffic.
    Degraded,
    /// No gateway can reach any enabled endpoint — every one is out of
    /// rotation on every gateway that routes to it: requests routed here fail
    /// over or fail.
    Down,
    /// Turned off by an operator.
    Disabled,
}

impl ServerHealth {
    /// A server's health from its counts ([`server_health_columns_sql`]):
    /// its enabled endpoints, those out of rotation on some gateway, and those
    /// out on every gateway that routes to them. A server with no enabled
    /// endpoint has no per-replica health to judge: it is not down on that
    /// account.
    pub fn of(enabled: bool, endpoints_enabled: i64, endpoints_down: i64, endpoints_out: i64) -> Self {
        if !enabled {
            Self::Disabled
        } else if endpoints_enabled > 0 && endpoints_out >= endpoints_enabled {
            Self::Down
        } else if endpoints_down > 0 {
            Self::Degraded
        } else {
            Self::Healthy
        }
    }
}

/// Columns of [`EndpointRow`], in its field order.
const ENDPOINT_COLUMNS: &str = "id, server_id, url, enabled, weight, position, listed, \
     last_discovery_at, last_discovery_status, max_in_flight, waiting_threshold, created_at";

/// One stored endpoint.
#[derive(sqlx::FromRow, Clone, Debug)]
pub(crate) struct EndpointRow {
    pub id: Uuid,
    pub server_id: Uuid,
    pub url: String,
    pub enabled: bool,
    pub weight: i32,
    pub position: i32,
    pub listed: bool,
    pub last_discovery_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_discovery_status: Option<serde_json::Value>,
    #[sqlx(default)]
    pub max_in_flight: Option<i32>,
    #[sqlx(default)]
    pub waiting_threshold: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A server's endpoints, primary order: `(position, created_at, id)`.
pub(crate) async fn load_endpoints(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Vec<EndpointRow>, sqlx::Error> {
    sqlx::query_as::<_, EndpointRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {ENDPOINT_COLUMNS} FROM upstream_server_endpoints \
         WHERE server_id = $1 ORDER BY position, created_at, id"
    )))
    .bind(server_id)
    .fetch_all(conn)
    .await
}

/// Lock a server's row for the rest of the transaction.
///
/// Lock order, for every write touching a server's endpoints: the SERVER row
/// first, then its endpoint rows. A server edit updates the server row and then
/// its primary endpoint; a sync or an endpoint write that took its endpoints
/// first and the server row after would deadlock against it.
pub(crate) async fn lock_server(conn: &mut Scoped, server_id: Uuid) -> Result<(), sqlx::Error> {
    // NO KEY UPDATE: it serialises these writers against each other without
    // blocking the key-share check a foreign-key insert takes (a model or a
    // membership row pointing at the server).
    sqlx::query("SELECT 1 FROM upstream_servers WHERE id = $1 FOR NO KEY UPDATE")
        .bind(server_id)
        .fetch_optional(conn)
        .await?;
    Ok(())
}

/// A server's endpoints, primary order, row-locked (after the server row —
/// see [`lock_server`]) for the rest of the transaction: a write that checks
/// "is this the last enabled endpoint?" must hold every row it counts, or two
/// concurrent disables each see a sibling still enabled and together leave
/// none.
pub(crate) async fn load_endpoints_for_update(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Vec<EndpointRow>, sqlx::Error> {
    lock_server(&mut *conn, server_id).await?;
    sqlx::query_as::<_, EndpointRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {ENDPOINT_COLUMNS} FROM upstream_server_endpoints \
         WHERE server_id = $1 ORDER BY position, created_at, id FOR NO KEY UPDATE"
    )))
    .bind(server_id)
    .fetch_all(conn)
    .await
}

/// Set the primary endpoint's URL: the server create/update `upstream_url`. A
/// server being created gets its first endpoint here. A primary whose URL
/// changes starts over as never answered — its membership rows and breaker
/// reports described the previous host. Returns the URL as stored (canonical),
/// and the unique violation raw so the caller can answer 409.
pub(crate) async fn write_primary_url(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    url: &str,
) -> Result<String, sqlx::Error> {
    let canonical = canonical_url(url);
    let url = canonical.as_str();
    lock_server(&mut *conn, server_id).await?;
    let primary: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, url FROM upstream_server_endpoints \
         WHERE server_id = $1 AND enabled ORDER BY position, created_at, id LIMIT 1",
    )
    .bind(server_id)
    .fetch_optional(&mut *conn)
    .await?;
    match primary {
        None => {
            sqlx::query(
                "INSERT INTO upstream_server_endpoints (tenant_id, server_id, url, position) \
                 VALUES ($1, $2, $3, COALESCE((SELECT MIN(position) - 1 FROM upstream_server_endpoints \
                                               WHERE server_id = $2), 0))",
            )
            .bind(tenant_id)
            .bind(server_id)
            .bind(url)
            .execute(&mut *conn)
            .await?;
        }
        Some((id, current)) if current != url => reset_endpoint_url(conn, id, url).await?,
        Some(_) => {}
    }
    Ok(canonical)
}

/// Give every ENABLED model no endpoint serves an assumed membership on each
/// listed endpoint of its server — `server_id` `None` = every server of the
/// tenant. Such a model has no rows on a server whose endpoints have all
/// answered: one re-enabled after a sync retired it (its rows went with the
/// retirement). Without this the snapshot
/// ships it with no member, and every request for it is refused. The next
/// answer from each endpoint confirms or removes the assumption. Returns the
/// rows written.
pub(crate) async fn assume_unserved_models(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Option<Uuid>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "INSERT INTO upstream_model_endpoints (tenant_id, model_id, endpoint_id, server_id, kind) \
         SELECT $1, m.id, e.id, m.server_id, 'assumed' \
           FROM upstream_models m \
           JOIN upstream_server_endpoints e ON e.server_id = m.server_id AND e.listed \
          WHERE m.tenant_id = $1 AND m.enabled AND ($2::uuid IS NULL OR m.server_id = $2) \
            AND NOT EXISTS (SELECT 1 FROM upstream_server_endpoints u \
                             WHERE u.server_id = m.server_id AND NOT u.listed) \
            AND NOT EXISTS (SELECT 1 FROM upstream_model_endpoints me WHERE me.model_id = m.id) \
         ON CONFLICT (tenant_id, model_id, endpoint_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(server_id)
    .execute(conn)
    .await?
    .rows_affected())
}

/// Point an endpoint at another URL, starting it over as never answered.
///
/// The models' advertised facts are NOT re-folded here: the endpoint stays in
/// rotation, assumed to serve every model with limits nobody has read yet, so
/// the stored — narrower — window and capabilities stand until the new host
/// answers. Only a REMOVAL re-folds.
async fn reset_endpoint_url(
    conn: &mut Scoped,
    endpoint_id: Uuid,
    url: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE upstream_server_endpoints SET url = $2, listed = false, \
         last_discovery_at = NULL, last_discovery_status = NULL, last_answer_at = NULL WHERE id = $1",
    )
    .bind(endpoint_id)
    .bind(url)
    .execute(&mut *conn)
    .await?;
    // Everything recorded about the endpoint described the previous host.
    for table in [
        "upstream_model_endpoints",
        "upstream_endpoint_health",
        "upstream_endpoint_stands",
        "upstream_endpoint_mismatches",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table} WHERE endpoint_id = $1")))
            .bind(endpoint_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Which endpoints serve which models of a server, as `(model_id, endpoint_id)`
/// pairs, strictly by the record: an endpoint that has never answered serves
/// every model; a listed one serves its rows. Disabled endpoints are included
/// — disabling one takes it out of traffic, not out of what it serves. A model
/// with no row on a fully listed server is served by none.
pub(crate) async fn effective_members(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT m.id, e.id FROM upstream_models m \
         JOIN upstream_server_endpoints e ON e.server_id = m.server_id \
         WHERE m.server_id = $1 \
           AND (NOT e.listed OR EXISTS (SELECT 1 FROM upstream_model_endpoints me \
                                        WHERE me.model_id = m.id AND me.endpoint_id = e.id))",
    )
    .bind(server_id)
    .fetch_all(conn)
    .await
}

/// Give a model added by hand an assumed membership on every LISTED endpoint of
/// its server — without one it would be served only by the endpoints that have
/// never answered, and by none at all on a fully listed server. The next answer
/// from each endpoint confirms or removes it.
pub(crate) async fn assume_on_listed_endpoints(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    model_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO upstream_model_endpoints (tenant_id, model_id, endpoint_id, server_id, kind) \
         SELECT $1, $3, e.id, $2, 'assumed' FROM upstream_server_endpoints e \
         WHERE e.server_id = $2 AND e.listed \
         ON CONFLICT (tenant_id, model_id, endpoint_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(server_id)
    .bind(model_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// The config snapshot's endpoint table for the tenant `conn` is scoped to:
/// the enabled endpoints of every enabled server, primary first; and, for each
/// model NOT served by all of them, the ones that do serve it (an empty list:
/// none does). A model every enabled endpoint serves ships no entry, so a
/// single-endpoint server adds only its endpoint to the snapshot.
pub(crate) async fn load_endpoint_table(
    conn: &mut Scoped,
) -> Result<streamscope_core::config::endpoints::EndpointTable, sqlx::Error> {
    use streamscope_core::config::endpoints::{EndpointConfig, EndpointTable, ReadCredential};
    // The capacity knobs are RESOLVED here — the endpoint's own value, else its
    // server's — so the proxy reads one number per endpoint and never has to
    // look a server up to find out what it may send.
    /// id, server, url, weight, the two resolved capacity knobs, whether the
    /// server asks for its engines' metrics, whether it learns its limit, and
    /// that limit's token-latency target (its figure and mode).
    type EndpointCapacityRow = (Uuid, Uuid, String, i32, Option<i32>, Option<i32>, bool, bool, Option<i32>, String);
    let rows: Vec<EndpointCapacityRow> = sqlx::query_as(
        "SELECT e.id, e.server_id, e.url, e.weight, \
                COALESCE(e.max_in_flight, s.max_in_flight), \
                COALESCE(e.waiting_threshold, s.waiting_threshold), \
                s.engine_metrics, s.adaptive_concurrency, s.adaptive_itl_target_ms, s.adaptive_itl_target_mode \
         FROM upstream_server_endpoints e \
         JOIN upstream_servers s ON s.id = e.server_id \
         WHERE e.enabled AND s.enabled \
         ORDER BY e.server_id, e.position, e.created_at, e.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut table = EndpointTable::default();
    for (id, server_id, url, weight, max_in_flight, waiting_threshold, engine_metrics, adaptive, itl_ms, itl_mode) in rows {
        table.servers.entry(server_id).or_default().push(EndpointConfig {
            id,
            url,
            weight: u32::try_from(weight).unwrap_or(1).max(1),
            max_in_flight: max_in_flight.and_then(|v| u32::try_from(v).ok()).filter(|v| *v > 0),
            // A learned limit replaces the queue bound: the API refuses to
            // store the two together, in the transaction of either write.
            waiting_threshold: waiting_threshold.and_then(|v| u32::try_from(v).ok()),
            engine_metrics,
            adaptive_concurrency: adaptive,
            adaptive_itl_target: crate::routes::upstreams::itl_target_of(&itl_mode, itl_ms),
        });
    }
    let subsets: Vec<(Uuid, Option<Vec<Uuid>>)> = sqlx::query_as(
        "SELECT m.id, \
                array_agg(e.id ORDER BY e.position, e.created_at, e.id) \
                    FILTER (WHERE NOT e.listed OR me.model_id IS NOT NULL) \
         FROM upstream_models m \
         JOIN upstream_server_endpoints e ON e.server_id = m.server_id AND e.enabled \
         LEFT JOIN upstream_model_endpoints me ON me.model_id = m.id AND me.endpoint_id = e.id \
         WHERE m.enabled \
         GROUP BY m.tenant_id, m.id \
         HAVING bool_or(e.listed AND me.model_id IS NULL)",
    )
    .fetch_all(&mut *conn)
    .await?;
    for (model_id, members) in subsets {
        table.model_members.insert(model_id, members.unwrap_or_default());
    }
    // The stored credential of every server whose engine is read, routed or
    // not: a server's credential otherwise reaches the edge only through its
    // routed models, and the engine poll must present the same key the admin's
    // engine probe does from the moment the server is read. Only a
    // default-transport credential ships: the poll presents nothing else, and a
    // cloud transport's stored document (a service-account key) must not reach
    // the edge for a reading that never uses it.
    let read_servers: Vec<Uuid> = table
        .servers
        .iter()
        .filter(|(_, eps)| eps.iter().any(EndpointConfig::engine_read))
        .map(|(id, _)| *id)
        .collect();
    if !read_servers.is_empty() {
        let credentials: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id, encrypted_key, transport FROM upstream_servers \
             WHERE id = ANY($1) AND encrypted_key IS NOT NULL AND transport = 'default'",
        )
        .bind(&read_servers)
        .fetch_all(&mut *conn)
        .await?;
        for (id, encrypted, transport) in credentials {
            table.read_credentials.insert(
                id,
                ReadCredential {
                    encrypted,
                    transport: streamscope_core::config::upstream_transport::UpstreamTransport::from(transport),
                },
            );
        }
    }
    Ok(table)
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// What an endpoint is taken to serve.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EndpointMembership {
    /// Discovery has answered: the endpoint serves the models it listed (plus
    /// any kept without that evidence, shown on the membership matrix).
    Listed,
    /// Discovery has never answered: the endpoint is assumed to serve every
    /// model of its server.
    Assumed,
}

/// The last discovery attempt against an endpoint.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Default)]
pub struct EndpointDiscoveryStatus {
    /// Whether the endpoint answered with a model list.
    pub ok: bool,
    /// How many models the answer named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed: Option<u32>,
    /// Why the models the answer did not name were kept rather than removed:
    /// `first_answer`, `server_first_sync` or `short_answer`. Absent when the
    /// answer was trusted to remove them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept: Option<String>,
    /// Why the endpoint did not answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Runtime health of an endpoint as the connected gateways report it.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EndpointHealthStatus {
    /// No connected gateway has its breaker open for this endpoint.
    Healthy,
    /// At least one connected gateway took the endpoint out of rotation.
    BreakerOpen,
}

/// The breaker state each connected gateway reported for an endpoint.
///
/// Only reports from gateways connected now, made since their current process
/// began (`epoch_started_at`), count: an older report is from a process that
/// restarted with every breaker closed. A disabled endpoint takes no traffic,
/// so its breaker is not shown.
#[derive(Serialize, ToSchema, Clone, Debug)]
pub struct EndpointHealth {
    pub status: EndpointHealthStatus,
    /// Connected gateways whose breaker for this endpoint is open.
    pub down_gateways: i64,
    /// When the earliest of those breakers opened.
    pub down_since: Option<chrono::DateTime<chrono::Utc>>,
    /// The most recent reason a breaker opened.
    pub reason: Option<String>,
}

#[derive(Serialize, ToSchema, Clone, Debug)]
pub struct EndpointResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub url: String,
    pub enabled: bool,
    /// Relative share of new sessions (≥ 1).
    pub weight: i32,
    pub position: i32,
    /// The first enabled endpoint, whose URL is the server's `upstream_url`.
    pub primary: bool,
    pub membership: EndpointMembership,
    /// Models the endpoint serves.
    pub model_count: i64,
    pub last_discovery_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_discovery: Option<EndpointDiscoveryStatus>,
    pub health: EndpointHealth,
    /// Models this endpoint answered "model not found" for since its last
    /// discovery answer — it was assumed or listed to serve them and does not.
    pub mismatched_models: i64,
    /// This replica's own capacity, when it overrides its server's. `null` =
    /// it uses the server's value.
    pub max_in_flight: Option<i32>,
    pub waiting_threshold: Option<i32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Build the responses for a server's endpoints, primary order preserved.
pub(crate) async fn endpoint_responses(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Vec<EndpointResponse>, sqlx::Error> {
    let endpoints = load_endpoints(conn, server_id).await?;
    let model_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstream_models WHERE server_id = $1")
        .bind(server_id)
        .fetch_one(&mut *conn)
        .await?;
    let row_counts: HashMap<Uuid, i64> = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT endpoint_id, COUNT(*) FROM upstream_model_endpoints WHERE server_id = $1 GROUP BY endpoint_id",
    )
    .bind(server_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let health = load_health(conn, server_id).await?;
    let mismatches: HashMap<Uuid, i64> = sqlx::query_as::<_, (Uuid, i64)>(sqlx::AssertSqlSafe(format!(
        "SELECT x.endpoint_id, COUNT(*) FROM upstream_endpoint_mismatches x \
         JOIN upstream_server_endpoints e ON e.id = x.endpoint_id \
         WHERE e.server_id = $1 AND {CURRENT_MISMATCH} GROUP BY x.endpoint_id"
    )))
    .bind(server_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let primary = endpoints.iter().find(|e| e.enabled).map(|e| e.id);
    Ok(endpoints
        .into_iter()
        .map(|e| {
            let health = health.get(&e.id).cloned().unwrap_or(EndpointHealth {
                status: EndpointHealthStatus::Healthy,
                down_gateways: 0,
                down_since: None,
                reason: None,
            });
            EndpointResponse {
                id: e.id,
                server_id: e.server_id,
                primary: Some(e.id) == primary,
                membership: if e.listed { EndpointMembership::Listed } else { EndpointMembership::Assumed },
                model_count: if e.listed { row_counts.get(&e.id).copied().unwrap_or(0) } else { model_count },
                last_discovery: e
                    .last_discovery_status
                    .and_then(|v| serde_json::from_value::<EndpointDiscoveryStatus>(v).ok()),
                url: e.url,
                enabled: e.enabled,
                weight: e.weight,
                position: e.position,
                last_discovery_at: e.last_discovery_at,
                health,
                mismatched_models: mismatches.get(&e.id).copied().unwrap_or(0),
                max_in_flight: e.max_in_flight,
                waiting_threshold: e.waiting_threshold,
                created_at: e.created_at,
            }
        })
        .collect())
}

/// A mismatch report (`x`) still stands when the endpoint (`e`) has not
/// ANSWERED discovery since: a later answer supersedes it; a failed attempt
/// does not.
const CURRENT_MISMATCH: &str = "(e.last_answer_at IS NULL OR x.last_seen_at >= e.last_answer_at)";

/// Breaker reports per endpoint of a server, counting only gateways connected
/// now and reports made since they connected (see [`EndpointHealth`]).
async fn load_health(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<HashMap<Uuid, EndpointHealth>, sqlx::Error> {
    type DownRow = (Uuid, i64, Option<chrono::DateTime<chrono::Utc>>, Option<String>);
    let rows: Vec<DownRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT d.endpoint_id, COUNT(*), MIN(d.changed_at), \
                (array_agg(d.reason ORDER BY d.changed_at DESC) FILTER (WHERE d.reason IS NOT NULL))[1] \
         FROM ({}) d WHERE d.server_id = $1 GROUP BY d.endpoint_id",
        endpoints_out_of_rotation_sql()
    )))
    .bind(server_id)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, down, since, reason)| {
            (id, EndpointHealth { status: EndpointHealthStatus::BreakerOpen, down_gateways: down, down_since: since, reason })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// What an endpoint write needs to know about its server.
#[derive(sqlx::FromRow)]
struct ServerFacts {
    provider: String,
    upstream_api_format: String,
    chat_endpoint_path: Option<String>,
    transport: String,
    encrypted_key: Option<String>,
    byok: bool,
    auto_sync_enabled: bool,
    enabled: bool,
}

async fn server_facts(conn: &mut Scoped, server_id: Uuid) -> Result<ServerFacts, ApiError> {
    sqlx::query_as::<_, ServerFacts>(
        "SELECT s.provider, s.upstream_api_format, s.chat_endpoint_path, s.transport, s.encrypted_key, \
                EXISTS(SELECT 1 FROM downstream_providers d WHERE d.upstream_server_id = s.id AND d.byok) AS byok, \
                s.auto_sync_enabled, s.enabled \
         FROM upstream_servers s WHERE s.id = $1",
    )
    .bind(server_id)
    .fetch_optional(conn)
    .await
    .map_err(|e| {
        tracing::error!("endpoint: read server: {e}");
        ApiError::internal("failed to read the server")
    })?
    .ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))
}

/// A server may have several endpoints only when an endpoint is a replica: a
/// default-transport server that is not a bring-your-own-key pass-through.
/// The cloud transports address a deployment, and a pass-through server is
/// matched by its one host.
fn refuse_unless_replicable(facts: &ServerFacts) -> Result<(), ApiError> {
    let transport = UpstreamTransport::from_str_relaxed(&facts.transport);
    if facts.byok {
        return Err(ApiError::bad_request(
            "A bring-your-own-key pass-through server has exactly one endpoint",
        )
        .code(ApiErrorCode::EndpointsUnsupported));
    }
    if transport != UpstreamTransport::Default {
        return Err(ApiError::bad_request(
            "Only a server on the default transport can have several endpoints — \
             a cloud transport addresses one deployment",
        )
        .code(ApiErrorCode::EndpointsUnsupported));
    }
    Ok(())
}

/// The stored form of an endpoint URL: trimmed, without a trailing slash (the
/// forward appends the protocol path). Every writer of an endpoint's URL goes
/// through it, so two spellings of one host cannot pass the `(server_id, url)`
/// uniqueness as two endpoints.
pub(crate) fn canonical_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

/// An endpoint URL from a request: an absolute http(s) URL with a host, in its
/// [`canonical_url`] form.
fn normalize_endpoint_url(raw: &str) -> Result<String, ApiError> {
    let canonical = canonical_url(raw);
    let trimmed = canonical.as_str();
    let parsed = url::Url::parse(trimmed).map_err(|_| {
        ApiError::bad_request("Enter the endpoint's full URL, e.g. http://vllm-2:8000")
            .code(ApiErrorCode::EndpointInvalid)
    })?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(ApiError::bad_request("An endpoint URL must be http:// or https:// with a host")
            .code(ApiErrorCode::EndpointInvalid));
    }
    super::upstreams::provider_url_refusal(trimmed)?;
    Ok(trimmed.to_string())
}

fn db_error(context: &'static str) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |e| {
        tracing::error!("{context}: {e}");
        ApiError::internal(context)
    }
}

/// Map an endpoint INSERT/UPDATE failure: the only unique index a caller can
/// land on is `(server_id, url)`.
fn url_write_error(e: sqlx::Error) -> ApiError {
    if super::is_unique_violation(&e) {
        return ApiError::conflict("Another endpoint of this server already has that URL", ApiErrorCode::EndpointUrlTaken);
    }
    tracing::error!("endpoint write: {e}");
    ApiError::internal("failed to save the endpoint")
}

/// Probe a new endpoint URL the way a server's own URL is probed on save.
async fn probe_endpoint(facts: &ServerFacts, url: &str) -> Result<(), ApiError> {
    let transport = UpstreamTransport::from_str_relaxed(&facts.transport);
    if !super::upstreams::probe_is_worth_making(&facts.provider, transport) {
        return Ok(());
    }
    let key = super::upstreams::decrypt_server_key(facts.encrypted_key.clone())?;
    super::upstreams::probe_upstream_liveness(
        url,
        &facts.upstream_api_format,
        key.as_deref(),
        facts.chat_endpoint_path.as_deref(),
        transport,
    )
    .await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/servers/{id}/endpoints",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID"), PageQuery),
    responses(
        (status = 200, description = "The server's endpoints, primary first", body = OffsetPage<EndpointResponse>),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_endpoints(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<EndpointResponse>>, ApiError> {
    server_facts(db.conn(), server_id).await?;
    let (limit, offset) = page.resolve();
    let all = endpoint_responses(db.conn(), server_id).await.map_err(db_error("failed to list endpoints"))?;
    let rows: Vec<EndpointResponse> = all.into_iter().skip(offset as usize).take(limit as usize + 1).collect();
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateEndpointRequest {
    /// The replica's base URL, e.g. `http://vllm-2:8000`.
    pub url: String,
    /// Relative share of new sessions (≥ 1). Default 1.
    #[serde(default)]
    pub weight: Option<i32>,
    /// Default true.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Skip the reachability probe ("Save anyway").
    #[serde(default)]
    pub force: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/endpoints",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = CreateEndpointRequest,
    responses(
        (status = 201, description = "Endpoint added", body = EndpointResponse),
        (status = 400, description = "Invalid URL or weight, or the server cannot have several endpoints", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 409, description = "Another endpoint of this server already has that URL", body = ApiErrorResponse),
        (status = 502, description = "The endpoint did not answer the reachability probe", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_endpoint(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateEndpointRequest>,
) -> Result<(StatusCode, Json<EndpointResponse>), ApiError> {
    let facts = server_facts(db.conn(), server_id).await?;
    refuse_unless_replicable(&facts)?;
    let url = normalize_endpoint_url(&req.url)?;
    let weight = validate_weight(req.weight.unwrap_or(1))?;
    if !req.force {
        crate::custom_ca::refresh_from_conn(db.conn()).await;
        probe_endpoint(&facts, &url).await?;
    }

    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(db_error("failed to add the endpoint"))?;
    lock_server(&mut tx, server_id).await.map_err(db_error("failed to add the endpoint"))?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO upstream_server_endpoints (tenant_id, server_id, url, weight, enabled, position) \
         VALUES ($1, $2, $3, $4, $5, COALESCE((SELECT MAX(position) + 1 FROM upstream_server_endpoints \
                                               WHERE server_id = $2), 0)) \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(server_id)
    .bind(&url)
    .bind(weight)
    .bind(req.enabled.unwrap_or(true))
    .fetch_one(&mut *tx)
    .await
    .map_err(url_write_error)?;
    tx.commit().await.map_err(db_error("failed to add the endpoint"))?;

    // Learn what the new replica serves now rather than at the next autosync
    // tick. Its first answer retires nothing; it keeps the replica off the
    // models another endpoint lists and it omits. Best-effort, like a new
    // server's first sync: until it answers, the endpoint is assumed to serve
    // every model.
    if facts.auto_sync_enabled
        && facts.enabled
        && !req.force
        && let Err(e) = super::model_sync::run_sync(db.conn(), tenant_id, server_id, None).await
    {
        let reason = e.reason();
        tracing::warn!(%server_id, "sync after adding an endpoint: {reason}");
        // Record WHY, or the server's page keeps showing the previous
        // SUCCESSFUL run and nothing says this one failed. Not an
        // attempt (`false`): the worker's due window is what picks the
        // server back up, and stamping it would close that window.
        let _ = super::model_sync::record_sync_failure(db.conn(), server_id, &reason, false).await;
    }

    let created = endpoint_responses(db.conn(), server_id)
        .await
        .map_err(db_error("failed to read the endpoint"))?
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| ApiError::internal("failed to read the endpoint"))?;
    Ok((StatusCode::CREATED, Json(created)))
}

fn validate_weight(weight: i32) -> Result<i32, ApiError> {
    if !(1..=1000).contains(&weight) {
        return Err(ApiError::bad_request("weight must be between 1 and 1000").code(ApiErrorCode::EndpointInvalid));
    }
    Ok(weight)
}

#[derive(Deserialize, ToSchema)]
pub struct PatchEndpointRequest {
    /// A new base URL. The endpoint then starts over as never answered: it is
    /// assumed to serve every model until discovery answers from the new host.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub weight: Option<i32>,
    /// Take the endpoint out of traffic (false) or put it back (true). The last
    /// enabled endpoint of a server cannot be disabled.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// This replica's own capacity, overriding its server's. Present and
    /// `null` goes back to the server's value; absent leaves it unchanged.
    /// Replicas of one server are rarely identical machines, which is why the
    /// override exists at all.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub max_in_flight: Option<Option<i32>>,
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub waiting_threshold: Option<Option<i32>>,
    /// Skip the reachability probe of a new URL.
    #[serde(default)]
    pub force: bool,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/servers/{id}/endpoints/{endpoint_id}",
    tag = "Servers",
    params(
        ("id" = Uuid, Path, description = "Server ID"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint ID"),
    ),
    request_body = PatchEndpointRequest,
    responses(
        (status = 200, description = "Endpoint updated", body = EndpointResponse),
        (status = 400, description = "Invalid URL or weight", body = ApiErrorResponse),
        (status = 404, description = "Server or endpoint not found", body = ApiErrorResponse),
        (status = 409, description = "URL taken, or the last enabled endpoint would be disabled", body = ApiErrorResponse),
        (status = 502, description = "The new URL did not answer the reachability probe", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn patch_endpoint(
    mut db: TenantConn,
    Path((server_id, endpoint_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<PatchEndpointRequest>,
) -> Result<Json<EndpointResponse>, ApiError> {
    let facts = server_facts(db.conn(), server_id).await?;
    // A server that cannot have replicas changes its one URL through the
    // server's own edit, which applies its transport's URL rules.
    if req.url.is_some() {
        refuse_unless_replicable(&facts)?;
    }
    let url = req.url.as_deref().map(normalize_endpoint_url).transpose()?;
    let weight = req.weight.map(validate_weight).transpose()?;
    if let Some(url) = &url
        && !req.force
    {
        crate::custom_ca::refresh_from_conn(db.conn()).await;
        probe_endpoint(&facts, url).await?;
    }

    let mut tx = db.conn().begin().await.map_err(db_error("failed to update the endpoint"))?;
    let endpoints = load_endpoints_for_update(&mut tx, server_id).await.map_err(db_error("failed to update the endpoint"))?;
    let current = endpoints
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| ApiError::not_found("endpoint not found", ApiErrorCode::EndpointNotFound))?;
    if req.enabled == Some(false) && current.enabled && endpoints.iter().filter(|e| e.enabled).count() == 1 {
        return Err(last_enabled_error());
    }
    if let Some(url) = &url
        && *url != current.url
    {
        reset_endpoint_url(&mut tx, endpoint_id, url).await.map_err(url_write_error)?;
    }
    if req.max_in_flight.flatten().is_some_and(|v| v < 1)
        || req.waiting_threshold.flatten().is_some_and(|v| v < 0)
    {
        return Err(ApiError::bad_request("capacity values are out of range")
            .code(ApiErrorCode::EndpointInvalid));
    }
    // The server row is locked (`load_endpoints_for_update`), and a server edit
    // that turns the learned limit on checks the same pair under that lock.
    if req.waiting_threshold.flatten().is_some() {
        let adaptive: bool = sqlx::query_scalar("SELECT adaptive_concurrency FROM upstream_servers WHERE id = $1")
            .bind(server_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error("failed to update the endpoint"))?;
        if adaptive {
            return Err(crate::routes::upstreams::adaptive_with_queue_bound());
        }
    }
    sqlx::query(
        "UPDATE upstream_server_endpoints SET weight = COALESCE($2, weight), \
           enabled = COALESCE($3, enabled), \
           max_in_flight = CASE WHEN $4 THEN $5 ELSE max_in_flight END, \
           waiting_threshold = CASE WHEN $6 THEN $7 ELSE waiting_threshold END \
         WHERE id = $1",
    )
    .bind(endpoint_id)
    .bind(weight)
    .bind(req.enabled)
    .bind(req.max_in_flight.is_some())
    .bind(req.max_in_flight.flatten())
    .bind(req.waiting_threshold.is_some())
    .bind(req.waiting_threshold.flatten())
    .execute(&mut *tx)
    .await
    .map_err(db_error("failed to update the endpoint"))?;
    tx.commit().await.map_err(db_error("failed to update the endpoint"))?;

    let updated = endpoint_responses(db.conn(), server_id)
        .await
        .map_err(db_error("failed to read the endpoint"))?
        .into_iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| ApiError::internal("failed to read the endpoint"))?;
    Ok(Json(updated))
}

fn last_enabled_error() -> ApiError {
    ApiError::conflict(
        "This is the server's last enabled endpoint — disable the server itself to take it out of traffic",
        ApiErrorCode::EndpointLastEnabled,
    )
}

/// What removing an endpoint did (or, on a dry run, would do).
#[derive(Serialize, ToSchema)]
pub struct EndpointRemovalResponse {
    pub dry_run: bool,
    /// Models only this endpoint served, retired by the removal.
    pub retired_models: Vec<String>,
    /// Retired models deleted outright (nothing curated referenced them).
    pub models_removed: u32,
    /// Automatic routes of the retired models, deleted.
    pub routes_deleted: u32,
    /// Hand-built routes of the retired models, disabled and flagged.
    pub routes_disabled: u32,
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/servers/{id}/endpoints/{endpoint_id}",
    tag = "Servers",
    params(
        ("id" = Uuid, Path, description = "Server ID"),
        ("endpoint_id" = Uuid, Path, description = "Endpoint ID"),
        super::key_lifecycle::DryRunQuery,
    ),
    responses(
        (status = 200, description = "Endpoint removed (or the removal previewed)", body = EndpointRemovalResponse),
        (status = 404, description = "Server or endpoint not found", body = ApiErrorResponse),
        (status = 409, description = "The server's last enabled endpoint", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_endpoint(
    // First: a preview is marked before any other extractor can refuse it.
    crate::middleware::DryRun(dry_run): crate::middleware::DryRun,
    mut db: TenantConn,
    Path((server_id, endpoint_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<EndpointRemovalResponse>, ApiError> {
    server_facts(db.conn(), server_id).await?;
    // The preview IS the removal, rolled back — so what it reports cannot
    // drift from what the removal does.
    let mut tx = db.conn().begin().await.map_err(db_error("failed to remove the endpoint"))?;
    let endpoints = load_endpoints_for_update(&mut tx, server_id).await.map_err(db_error("failed to remove the endpoint"))?;
    let target = endpoints
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| ApiError::not_found("endpoint not found", ApiErrorCode::EndpointNotFound))?;
    if target.enabled && endpoints.iter().filter(|e| e.enabled).count() == 1 {
        return Err(last_enabled_error());
    }

    let served_before: HashSet<Uuid> = effective_members(&mut tx, server_id)
        .await
        .map_err(db_error("failed to remove the endpoint"))?
        .into_iter()
        .map(|(model, _)| model)
        .collect();
    sqlx::query("DELETE FROM upstream_server_endpoints WHERE id = $1")
        .bind(endpoint_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error("failed to remove the endpoint"))?;
    let served_after: HashSet<Uuid> = effective_members(&mut tx, server_id)
        .await
        .map_err(db_error("failed to remove the endpoint"))?
        .into_iter()
        .map(|(model, _)| model)
        .collect();

    // An operator's removal is not evidence a model vanished, but a model no
    // remaining endpoint serves can no longer be routed: it retires exactly as
    // a vanished one does (and is reinstated if an endpoint lists it again).
    // Only a model that is serving: a disabled one was retired already, or
    // taken out by its operator — neither is this removal's to retire.
    let mut orphaned: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, upstream_model FROM upstream_models WHERE server_id = $1 AND enabled ORDER BY upstream_model",
    )
    .bind(server_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error("failed to remove the endpoint"))?;
    orphaned.retain(|(id, _)| served_before.contains(id) && !served_after.contains(id));

    let mut resp = EndpointRemovalResponse {
        dry_run,
        retired_models: Vec::with_capacity(orphaned.len()),
        models_removed: 0,
        routes_deleted: 0,
        routes_disabled: 0,
    };
    for (model_id, name) in orphaned {
        let counts = super::model_sync::retire_model_soft(&mut tx, model_id)
            .await
            .map_err(super::model_sync::sync_error_to_api)?;
        resp.routes_deleted += counts.routes_deleted;
        resp.routes_disabled += counts.routes_disabled;
        resp.models_removed += u32::from(counts.model_removed);
        resp.retired_models.push(name);
    }
    // The advertised window and capabilities follow the members that remain.
    super::model_sync::refold_server(&mut tx, server_id)
        .await
        .map_err(super::model_sync::sync_error_to_api)?;

    if dry_run {
        tx.rollback().await.map_err(db_error("failed to preview the removal"))?;
    } else {
        tx.commit().await.map_err(db_error("failed to remove the endpoint"))?;
    }
    Ok(Json(resp))
}

#[derive(Deserialize, ToSchema)]
pub struct ReorderEndpointsRequest {
    /// Every endpoint of the server, in the new order. The first enabled one
    /// becomes the primary.
    pub endpoint_ids: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/endpoints/actions/reorder",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = ReorderEndpointsRequest,
    responses(
        (status = 200, description = "Endpoints reordered", body = ActionResponse),
        (status = 400, description = "The list is not exactly the server's endpoints", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reorder_endpoints(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(server_id): Path<Uuid>,
    Json(req): Json<ReorderEndpointsRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    server_facts(db.conn(), server_id).await?;
    let mut tx = db.conn().begin().await.map_err(db_error("failed to reorder the endpoints"))?;
    let endpoints = load_endpoints_for_update(&mut tx, server_id).await.map_err(db_error("failed to reorder the endpoints"))?;
    let stored: BTreeSet<Uuid> = endpoints.iter().map(|e| e.id).collect();
    let requested: BTreeSet<Uuid> = req.endpoint_ids.iter().copied().collect();
    if requested.len() != req.endpoint_ids.len() || requested != stored {
        return Err(ApiError::bad_request("List every endpoint of the server exactly once")
            .code(ApiErrorCode::EndpointInvalid));
    }
    for (position, id) in req.endpoint_ids.iter().enumerate() {
        sqlx::query("UPDATE upstream_server_endpoints SET position = $2 WHERE id = $1")
            .bind(id)
            .bind(position as i32)
            .execute(&mut *tx)
            .await
            .map_err(db_error("failed to reorder the endpoints"))?;
    }
    tx.commit().await.map_err(db_error("failed to reorder the endpoints"))?;
    audit_sink.set(
        serde_json::json!({ "order": endpoints.iter().map(|e| e.id).collect::<Vec<_>>() }),
        serde_json::json!({ "order": req.endpoint_ids }),
    );
    Ok(Json(ActionResponse::ok().with_message("Endpoints reordered")))
}

#[derive(Deserialize, ToSchema)]
pub struct DiscoverEndpointRequest {
    /// The URL to ask, with this server's credential.
    pub url: String,
}

/// How a model an endpoint listed relates to the server's current models.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PreviewModelStatus {
    /// The server already has it.
    Matches,
    /// Adding the endpoint would add it to the server.
    New,
}

#[derive(Serialize, ToSchema)]
pub struct PreviewModel {
    pub upstream_model: String,
    pub status: PreviewModelStatus,
    pub context_window: Option<i64>,
}

/// What an endpoint at a URL would contribute, asked before it is saved.
#[derive(Serialize, ToSchema)]
pub struct EndpointDiscoveryPreview {
    /// Whether the URL answered with a model list. When it did not, it would be
    /// assumed to serve every model of the server.
    pub answered: bool,
    /// Why it did not answer.
    pub reason: Option<String>,
    /// What it listed.
    pub models: Vec<PreviewModel>,
    /// The server's models it did not list.
    pub not_listed: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/endpoints/actions/discover",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = DiscoverEndpointRequest,
    responses(
        (status = 200, description = "What the URL lists, compared with the server's models (nothing is saved)", body = EndpointDiscoveryPreview),
        (status = 400, description = "Invalid URL", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn discover_endpoint(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Json(req): Json<DiscoverEndpointRequest>,
) -> Result<Json<EndpointDiscoveryPreview>, ApiError> {
    let facts = server_facts(db.conn(), server_id).await?;
    let url = normalize_endpoint_url(&req.url)?;
    let existing: BTreeSet<String> =
        sqlx::query_scalar::<_, String>("SELECT upstream_model FROM upstream_models WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(db.conn())
            .await
            .map_err(db_error("failed to read the server's models"))?
            .into_iter()
            .collect();
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    let key = super::upstreams::decrypt_server_key(facts.encrypted_key.clone())?;
    let answer = super::upstreams::call_discover_models(
        &facts.provider,
        &url,
        key.as_deref(),
        facts.chat_endpoint_path.as_deref(),
        UpstreamTransport::from_str_relaxed(&facts.transport),
    )
    .await;
    Ok(Json(match answer {
        Ok(list) => {
            let named: BTreeSet<&str> = list.iter().map(|m| m.id.as_str()).collect();
            EndpointDiscoveryPreview {
                answered: true,
                reason: None,
                models: list
                    .iter()
                    .map(|m| PreviewModel {
                        upstream_model: m.id.clone(),
                        status: if existing.contains(&m.id) { PreviewModelStatus::Matches } else { PreviewModelStatus::New },
                        context_window: m.context_window,
                    })
                    .collect(),
                not_listed: existing.iter().filter(|n| !named.contains(n.as_str())).cloned().collect(),
            }
        }
        Err(e) => EndpointDiscoveryPreview { answered: false, reason: Some(e.message), models: Vec::new(), not_listed: Vec::new() },
    }))
}

/// What one endpoint's engine said when asked for its metrics just now.
#[derive(Serialize, ToSchema)]
pub struct EngineProbe {
    pub endpoint_id: Uuid,
    pub url: String,
    /// Where the metrics were asked for: the endpoint's server root.
    pub metrics_url: String,
    /// Whether a document with an engine's queue gauges came back.
    pub answered: bool,
    /// Why not, in the terms an operator fixes.
    pub reason: Option<String>,
    /// Whether the server's credential was presented with the read.
    pub credential_presented: bool,
    pub waiting: Option<i64>,
    /// `null` when the engine does not publish the gauge.
    pub running: Option<i64>,
    pub kv_usage: Option<f64>,
    /// Tokens the engine's KV cache holds (blocks × block size), when it says.
    pub kv_capacity_tokens: Option<i64>,
    /// The most this engine has run while requests waited behind it — seven
    /// days of readings and this probe: what it sustained while queueing, not
    /// a capacity. `null` until it has been seen queueing.
    pub observed_peak_running: Option<i64>,
    /// This engine's own per-gateway in-flight limit: its peak divided by the
    /// gateway replicas — what to set on THIS endpoint when its engine differs
    /// from its siblings (another GPU, other engine settings).
    pub suggested_max_in_flight: Option<i64>,
}

/// An engine check for every endpoint of a server, and what the history says
/// its concurrency is.
#[derive(Serialize, ToSchema)]
pub struct EngineProbeResponse {
    pub endpoints: Vec<EngineProbe>,
    /// The SMALLEST of the engines' observed peaks: the limit applies to every
    /// endpoint of the server, so the engine that fills first decides it.
    /// `null` until EVERY enabled engine has been seen queueing.
    pub observed_peak_running: Option<i64>,
    /// Gateway replicas connected now. The in-flight limit applies per gateway
    /// replica, so an engine can receive this many times it.
    pub gateway_replicas: i64,
    /// A per-gateway in-flight limit that keeps the total at the observed
    /// peak: the peak divided by the gateway replicas, at least 1.
    pub suggested_max_in_flight: Option<i64>,
}

/// The most requests an engine was seen running while it still kept a queue
/// of its own: what it sustained while queueing — not a capacity, since an
/// engine queues on its token budget per step as well as on its memory or its
/// batch cap. Read from ONE reading at a time — the
/// gateway's `running_queued_peak`, the most running in any reading that also
/// queued since its previous beat — never from the beat's separate running and
/// waiting peaks, which may come from different readings; a beat stored
/// before that peak falls back to its instant, when that instant queued. An aggregate over
/// `upstream_load_samples l`. The ONE definition: the engine probe reads it
/// here, the server dashboard inside its load-history scan.
pub(crate) const QUEUEING_RUNNING_SQL: &str = "MAX(COALESCE(l.engine_running_queued_peak, \
     CASE WHEN l.engine_waiting > 0 THEN l.engine_running END))";

/// Per endpoint of a server, [`QUEUEING_RUNNING_SQL`] over the last 7 days.
/// Absent for an engine never seen queueing.
pub(crate) async fn observed_queueing_running(db: &mut TenantConn, server_id: Uuid) -> Result<HashMap<Uuid, i32>, ApiError> {
    let sql = format!(
        "SELECT l.endpoint_id, {QUEUEING_RUNNING_SQL} AS queueing_at FROM upstream_load_samples l \
         WHERE l.tenant_id = $1 AND l.server_id = $2 AND l.sampled_at >= now() - INTERVAL '7 days' \
         GROUP BY l.endpoint_id"
    );
    Ok(sqlx::query_as::<_, (Uuid, Option<i32>)>(sqlx::AssertSqlSafe(&*sql))
        .bind(db.tenant_uuid())
        .bind(server_id)
        .fetch_all(db.conn())
        .await
        .map_err(db_error("failed to read the server's load history"))?
        .into_iter()
        .filter_map(|(endpoint, queueing)| queueing.map(|q| (endpoint, q)))
        .collect())
}

/// The per-gateway in-flight limit that keeps N gateways together at the
/// engine's observed peak. Rounded down: over-committing puts the overflow in
/// the engine's own queue, where priority is lost.
pub(crate) fn suggested_max_in_flight(peak_running: Option<i64>, gateway_replicas: i64) -> Option<i64> {
    let peak = peak_running.filter(|p| *p > 0)?;
    Some((peak / gateway_replicas.max(1)).max(1))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/actions/probe-engine",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    responses(
        (status = 200, description = "What each endpoint's engine reports now (nothing is saved)", body = EngineProbeResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn probe_engine(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
) -> Result<Json<EngineProbeResponse>, ApiError> {
    use streamscope_core::proxy::qos_metrics::{engine_metrics_url, parse_engine_metrics, METRICS_BODY_CAP};
    let facts = server_facts(db.conn(), server_id).await?;
    let endpoints: Vec<(Uuid, String)> = sqlx::query_as(
        // Enabled only: the suggestion is for the engines that take traffic.
        "SELECT id, url FROM upstream_server_endpoints WHERE server_id = $1 AND enabled \
         ORDER BY position, created_at, id",
    )
    .bind(server_id)
    .fetch_all(db.conn())
    .await
    .map_err(db_error("failed to read the server's endpoints"))?;
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    // Presented the way the gateways present it: the server's own credential,
    // as a bearer token, on the default transport only — a cloud transport
    // signs per request and fronts no engine publishing these gauges.
    let credential = if UpstreamTransport::from_str_relaxed(&facts.transport) == UpstreamTransport::Default {
        super::upstreams::decrypt_server_key(facts.encrypted_key.clone())?
    } else {
        None
    };
    let client = super::upstreams::upstream_probe_client().map_err(|e| {
        tracing::error!("build engine-probe client: {e}");
        ApiError::bad_gateway("The gateway could not build an HTTPS client for the engine probe.")
    })?;
    let timeout = streamscope_core::settings::core_settings().upstream_probe_timeout;
    let probes = futures::future::join_all(endpoints.into_iter().map(|(endpoint_id, url)| {
        let client = client.clone();
        let credential = credential.clone();
        async move {
            let metrics_url = engine_metrics_url(&url);
            let refused = matches!(
                streamscope_core::proxy::client::check_provider_url(&metrics_url),
                Err(streamscope_mcp_auth::ssrf::SsrfError::InternalAddress)
            );
            let mut probe = EngineProbe {
                endpoint_id,
                url,
                metrics_url: metrics_url.clone(),
                answered: false,
                reason: None,
                credential_presented: credential.as_deref().is_some_and(|c| !c.trim().is_empty()),
                waiting: None,
                running: None,
                kv_usage: None,
                kv_capacity_tokens: None,
                observed_peak_running: None,
                suggested_max_in_flight: None,
            };
            if refused {
                probe.reason = Some("is internal and not on the platform's llm egress list".to_string());
                return probe;
            }
            let mut request = client.get(&metrics_url).timeout(timeout);
            if let Some(c) = credential.as_deref().filter(|c| !c.trim().is_empty()) {
                request = request.bearer_auth(c);
            }
            let response = match request.send().await {
                Ok(r) => r,
                Err(e) if streamscope_mcp_auth::ssrf::refusal(&e).is_some() => {
                    probe.reason = Some("was refused by the platform's egress policy".to_string());
                    return probe;
                }
                Err(_) => {
                    probe.reason = Some("could not be reached".to_string());
                    return probe;
                }
            };
            if !response.status().is_success() {
                probe.reason = Some(format!("refused the read with HTTP {}", response.status().as_u16()));
                return probe;
            }
            let text = match streamscope_core::http_body::read_body_capped(response, METRICS_BODY_CAP).await {
                Ok(body) => String::from_utf8_lossy(&body).into_owned(),
                Err(_) => {
                    probe.reason = Some("answered with a body that could not be read".to_string());
                    return probe;
                }
            };
            match parse_engine_metrics(&text) {
                Some(reading) => {
                    probe.answered = true;
                    probe.waiting = Some(i64::from(reading.waiting));
                    probe.running = reading.running.map(i64::from);
                    probe.kv_usage = reading.kv_usage;
                    probe.kv_capacity_tokens =
                        reading.info.kv_capacity_tokens().and_then(|t| i64::try_from(t).ok());
                }
                None => {
                    probe.reason =
                        Some("answered without the queue gauges — is this a vLLM engine?".to_string());
                }
            }
            probe
        }
    }))
    .await;

    let history = observed_queueing_running(&mut db, server_id).await?;
    let mut probes = probes;
    for p in &mut probes {
        let now_queueing = p.running.filter(|_| p.waiting.is_some_and(|w| w > 0));
        p.observed_peak_running = history.get(&p.endpoint_id).map(|v| i64::from(*v)).into_iter().chain(now_queueing).max();
    }
    // The limit applies to every engine, so it is only suggested once every one
    // has been seen queueing: an engine never seen queueing may sustain far
    // fewer than a sibling that was.
    let observed_peak_running = probes
        .iter()
        .map(|p| p.observed_peak_running)
        .collect::<Option<Vec<i64>>>()
        .and_then(|peaks| peaks.into_iter().min());
    let gateway_replicas = connected_gateway_replicas(&state.db).await?;
    for p in &mut probes {
        p.suggested_max_in_flight = suggested_max_in_flight(p.observed_peak_running, gateway_replicas);
    }
    Ok(Json(EngineProbeResponse {
        endpoints: probes,
        observed_peak_running,
        gateway_replicas,
        suggested_max_in_flight: suggested_max_in_flight(observed_peak_running, gateway_replicas),
    }))
}

/// One cell of the membership matrix.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    /// The endpoint's last answer named the model.
    Listed,
    /// Served without that evidence: the endpoint never answered, the model
    /// was added by hand, or an answer that omitted it was not trusted to remove.
    Assumed,
    /// The endpoint does not serve the model.
    NotServed,
}

#[derive(Serialize, ToSchema)]
pub struct MembershipCell {
    pub endpoint_id: Uuid,
    pub state: MembershipState,
    /// The context window this endpoint reported for the model.
    pub context_window: Option<i64>,
    /// What the engine says it serves under this name (vLLM `root`).
    pub identity: Option<String>,
    /// The endpoint answered "model not found" for this model since its last
    /// discovery answer: this many reports, the last at `model_missing_at`.
    pub model_missing_reports: Option<i64>,
    pub model_missing_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, ToSchema)]
pub struct MembershipModel {
    pub model_id: Uuid,
    pub upstream_model: String,
    pub enabled: bool,
    /// The window the gateway advertises: the smallest any member reported.
    pub context_window: Option<i32>,
    /// The base model when this is an adapter (vLLM `parent`).
    pub parent: Option<String>,
    /// One cell per endpoint, in the endpoint order of the response.
    pub cells: Vec<MembershipCell>,
    /// Members report different context windows.
    pub window_mismatch: bool,
    /// Members report different identities — possibly different weights under
    /// one name; the operator decides.
    pub identity_mismatch: bool,
}

#[derive(Serialize, ToSchema)]
pub struct MembershipEndpoint {
    pub id: Uuid,
    pub url: String,
    pub enabled: bool,
    pub primary: bool,
    pub membership: EndpointMembership,
}

/// Which endpoint serves which model of a server.
#[derive(Serialize, ToSchema)]
pub struct ServerMembershipResponse {
    pub endpoints: Vec<MembershipEndpoint>,
    pub models: Vec<MembershipModel>,
}

/// What one endpoint reported for one model, as stored on its membership row.
/// The fold over a model's members reads the same fields.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub(crate) struct ReportedFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, bool>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/servers/{id}/membership",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    responses(
        (status = 200, description = "Models × endpoints", body = ServerMembershipResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_membership(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
) -> Result<Json<ServerMembershipResponse>, ApiError> {
    server_facts(db.conn(), server_id).await?;
    let endpoints = load_endpoints(db.conn(), server_id).await.map_err(db_error("failed to read the endpoints"))?;
    let models: Vec<(Uuid, String, bool, Option<i32>)> = sqlx::query_as(
        "SELECT id, upstream_model, enabled, context_window FROM upstream_models \
         WHERE server_id = $1 ORDER BY upstream_model",
    )
    .bind(server_id)
    .fetch_all(db.conn())
    .await
    .map_err(db_error("failed to read the models"))?;
    type MemberRow = (Uuid, Uuid, String, Option<serde_json::Value>, Option<String>, Option<String>);
    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT model_id, endpoint_id, kind, discovered, discovered_identity, discovered_parent \
         FROM upstream_model_endpoints WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(db.conn())
    .await
    .map_err(db_error("failed to read the memberships"))?;
    // (kind, what the endpoint reported, identity, parent) per (model, endpoint).
    type CellFacts = (String, ReportedFacts, Option<String>, Option<String>);
    let mut by_cell: HashMap<(Uuid, Uuid), CellFacts> = HashMap::new();
    for (model, endpoint, kind, discovered, identity, parent) in rows {
        let facts = discovered.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
        by_cell.insert((model, endpoint), (kind, facts, identity, parent));
    }

    let missing: HashMap<(Uuid, String), (i64, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as::<_, (Uuid, String, i64, chrono::DateTime<chrono::Utc>)>(sqlx::AssertSqlSafe(format!(
            "SELECT x.endpoint_id, x.upstream_model, x.reports, x.last_seen_at \
             FROM upstream_endpoint_mismatches x JOIN upstream_server_endpoints e ON e.id = x.endpoint_id \
             WHERE e.server_id = $1 AND {CURRENT_MISMATCH}"
        )))
        .bind(server_id)
        .fetch_all(db.conn())
        .await
        .map_err(db_error("failed to read the mismatch reports"))?
        .into_iter()
        .map(|(e, m, n, at)| ((e, m), (n, at)))
        .collect();

    let primary = endpoints.iter().find(|e| e.enabled).map(|e| e.id);
    let resp_models = models
        .into_iter()
        .map(|(model_id, name, enabled, window)| {
            let mut parent = None;
            let cells: Vec<MembershipCell> = endpoints
                .iter()
                .map(|e| {
                    let report = missing.get(&(e.id, name.clone()));
                    let mut cell = MembershipCell {
                        endpoint_id: e.id,
                        state: MembershipState::Assumed,
                        context_window: None,
                        identity: None,
                        model_missing_reports: report.map(|r| r.0),
                        model_missing_at: report.map(|r| r.1),
                    };
                    if !e.listed {
                        return cell;
                    }
                    match by_cell.get(&(model_id, e.id)) {
                        Some((kind, facts, identity, p)) => {
                            if parent.is_none() {
                                parent.clone_from(p);
                            }
                            cell.state = if kind == "listed" { MembershipState::Listed } else { MembershipState::Assumed };
                            cell.context_window = facts.context_window;
                            cell.identity.clone_from(identity);
                        }
                        None => cell.state = MembershipState::NotServed,
                    }
                    cell
                })
                .collect();
            let windows: BTreeSet<i64> = cells.iter().filter_map(|c| c.context_window).collect();
            let identities: BTreeSet<&str> = cells.iter().filter_map(|c| c.identity.as_deref()).collect();
            MembershipModel {
                window_mismatch: windows.len() > 1,
                identity_mismatch: identities.len() > 1,
                model_id,
                upstream_model: name,
                enabled,
                context_window: window,
                parent,
                cells,
            }
        })
        .collect();
    Ok(Json(ServerMembershipResponse {
        endpoints: endpoints
            .into_iter()
            .map(|e| MembershipEndpoint {
                primary: Some(e.id) == primary,
                membership: if e.listed { EndpointMembership::Listed } else { EndpointMembership::Assumed },
                id: e.id,
                url: e.url,
                enabled: e.enabled,
            })
            .collect(),
        models: resp_models,
    }))
}

#[cfg(test)]
mod tests {
    use super::suggested_max_in_flight;

    #[test]
    fn the_suggested_limit_splits_the_engines_peak_between_the_gateways() {
        assert_eq!(suggested_max_in_flight(None, 2), None, "never seen queueing: nothing to suggest");
        assert_eq!(suggested_max_in_flight(Some(0), 2), None);
        assert_eq!(suggested_max_in_flight(Some(24), 1), Some(24));
        // Rounded down: 2 × 12 = 24 reaches the peak, 2 × 13 would overshoot it.
        assert_eq!(suggested_max_in_flight(Some(25), 2), Some(12));
        // Never below one, and no division by a fleet nobody reported.
        assert_eq!(suggested_max_in_flight(Some(1), 4), Some(1));
        assert_eq!(suggested_max_in_flight(Some(8), 0), Some(8));
    }

    use super::ServerHealth;

    #[test]
    fn a_server_is_down_only_when_every_enabled_endpoint_is_out_everywhere() {
        // The boundary on both sides: one endpoint short of all is degraded,
        // all of them out on every gateway is down.
        assert_eq!(ServerHealth::of(true, 3, 3, 2), ServerHealth::Degraded);
        assert_eq!(ServerHealth::of(true, 3, 3, 3), ServerHealth::Down);
        assert_eq!(ServerHealth::of(true, 1, 1, 1), ServerHealth::Down);
    }

    #[test]
    fn an_endpoint_out_on_one_gateway_only_degrades_the_server() {
        // One replica lost its path to the engine; the others still serve it.
        assert_eq!(ServerHealth::of(true, 1, 1, 0), ServerHealth::Degraded);
        assert_eq!(ServerHealth::of(true, 3, 1, 0), ServerHealth::Degraded);
    }

    #[test]
    fn a_server_with_nothing_out_of_rotation_is_healthy() {
        assert_eq!(ServerHealth::of(true, 3, 0, 0), ServerHealth::Healthy);
        assert_eq!(ServerHealth::of(true, 1, 0, 0), ServerHealth::Healthy);
    }

    #[test]
    fn a_server_with_no_endpoint_rows_is_not_down() {
        // The last enabled endpoint cannot be disabled, so a server with none
        // has no endpoint rows at all: the gateways route to its own URL, and
        // nothing about any replica says it is down.
        assert_eq!(ServerHealth::of(true, 0, 0, 0), ServerHealth::Healthy);
        // The control: one enabled endpoint out everywhere is down.
        assert_eq!(ServerHealth::of(true, 1, 1, 1), ServerHealth::Down);
    }

    #[test]
    fn a_disabled_server_is_disabled_whatever_its_endpoints_report() {
        assert_eq!(ServerHealth::of(false, 2, 2, 2), ServerHealth::Disabled);
        assert_eq!(ServerHealth::of(false, 2, 0, 0), ServerHealth::Disabled);
    }
}
