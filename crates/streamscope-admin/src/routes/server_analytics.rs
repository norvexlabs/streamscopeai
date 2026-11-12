//! The server dashboard: each LLM upstream server's traffic, latency,
//! scheduling and live load.
//!
//! Traffic comes from the audit rows, which name the server a request was sent
//! to — or whose pool refused it — and the replica endpoint that answered, and
//! list every attempt the request moved on from before that one
//! (`moved_on_from`): each is counted at its own server. Live
//! load comes from `upstream_load_samples`, the gauges each gateway replica
//! reports for the endpoints it gates on every heartbeat.
//!
//! Upstream LATENCY here excludes the time a request waited for capacity: the
//! engine did not take that long, the queue in front of it did. The wait is
//! reported on its own. A refusal is not an error of the server's: `errors`
//! counts failed requests the gate let through, `refusals` the ones it did not.
//! Refusals and waits are recorded from the release that added this dashboard
//! on; earlier rows carry neither.
//!
//! Configuration and health (name, bounds, which endpoints are out of rotation)
//! are NOT repeated here — the server and endpoint resources carry them, and
//! the page joins the two by id.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, Query};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use streamscope_core::proxy::adaptive_concurrency::AdaptiveState;
use streamscope_core::proxy::dispatch_gate::max_opt;
use uuid::Uuid;

use super::analytics::{bucket_interval, build_bucket_axis, UsageQuery, DEFAULT_USAGE_DAYS};
use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::audit_store::analytics::servers as servers_store;
use crate::db::tenant::TenantConn;
use crate::retention::load_sample_horizon_days;

/// What a server — or one endpoint, class or time bucket of it — handled,
/// counted over ATTEMPTS: the attempt each request ended with, and each one it
/// moved on from (refused by this server's pool, or sent here and failed, then
/// tried elsewhere). A server that fails every request a fallback then answers
/// is failing, and says so here.
#[derive(Serialize, ToSchema, sqlx::FromRow, Debug, Clone, Default)]
pub struct ServerTraffic {
    /// Attempts at this server: requests sent to it or refused by its pool,
    /// once per attempt. A request that moved on counts here and at the
    /// target it moved to.
    pub requests: i64,
    /// Attempts sent here that the server failed — no answer, an error answer,
    /// a stream that broke or went quiet — the request's last, or one it moved
    /// on from (`failed_over`). Neither a refusal nor a failure that is not the
    /// server's (the client hanging up, the gateway's own fault) is one: the
    /// share failed is `errors / (requests - refusals)`, over what was sent.
    pub errors: i64,
    /// Of `errors`, the ones the request moved on from, to another replica or
    /// another target.
    pub failed_over: i64,
    /// Attempts this server's pool refused — for want of capacity, or a
    /// waiting copy replaced by the same request sent again (`superseded`) —
    /// the request's last, or one it moved on from (`passed_on`).
    pub refusals: i64,
    /// Of `refusals`, the ones the request moved on from.
    pub passed_on: i64,
    /// Attempts that waited for capacity at this server's pool and were then
    /// sent to it. One that waited and was refused is a refusal
    /// (`queue_timeout`), not counted here.
    pub queued: i64,
    /// Everything the attempts spent waiting at this server's pool — the
    /// refused ones' waits included: that time was spent all the same.
    pub wait_ms_total: i64,
    /// Requests moved to another replica of the server because theirs had no
    /// room. Per endpoint: the ones moved TO it.
    pub spilled: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    /// Upstream latency of the requests served here, excluding any wait for
    /// capacity and the time spent on the attempts before this one. `null`
    /// when none was.
    pub latency_p50_ms: Option<f64>,
    pub latency_p95_ms: Option<f64>,
    pub latency_p99_ms: Option<f64>,
    /// Time to first token of the CHAT requests served here, excluding any
    /// wait. A media or pass-through call records its whole duration there,
    /// which is no first token of anything.
    pub ttft_p95_ms: Option<f64>,
    /// The wait at this server's pool of the attempts that waited and were
    /// sent to it. `null` when none did.
    pub queue_wait_p50_ms: Option<f64>,
    pub queue_wait_p95_ms: Option<f64>,
}

/// The live load of a server, from the newest reading each gateway replica
/// sent for each of its gated endpoints.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq)]
pub struct ServerLive {
    /// When the newest reading was taken.
    pub sampled_at: DateTime<Utc>,
    /// Gateway replicas reporting.
    pub replicas: i64,
    /// Whether any of the server's endpoints is gated. Only a gated endpoint's
    /// requests are counted; one read only for its engine metrics is not.
    pub gated: bool,
    /// Requests in flight at the server's gated endpoints, across replicas.
    pub in_flight: i64,
    /// How many the replicas may have in flight there — `null` unless every
    /// reported endpoint declares an in-flight bound.
    pub capacity: Option<i64>,
    /// Requests the replicas are holding for want of capacity.
    pub held: i64,
    /// The same, per priority class, most held first. Empty from a gateway
    /// that does not report classes.
    pub held_by_class: Vec<ClassHeldLive>,
    /// Endpoints whose engine gauges the gateway reads that declare a queue
    /// bound (or learn their limit) and that some replica has stopped hearing
    /// from — that replica is not applying the bound, whatever the others see.
    /// An engine read only for the dashboards and gone quiet is not counted
    /// here: nothing depends on it but its charts (see
    /// `EndpointLive::queue_bounded`).
    pub engines_silent: i64,
    /// The largest automatic token-latency target among the server's engines
    /// (`AdaptiveLive::auto_itl_target_ms`), in milliseconds — the slowest
    /// engine's. `null` until an engine has taught one.
    pub auto_itl_target_ms: Option<f64>,
}

/// Requests held for a server, of one class.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq)]
pub struct ClassHeldLive {
    /// `null` for a tenant with no classes.
    pub qos_class_id: Option<Uuid>,
    pub held: i64,
}

/// The live load of one endpoint.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq)]
pub struct EndpointLive {
    pub sampled_at: DateTime<Utc>,
    pub replicas: i64,
    /// Whether the gateway counts this endpoint's requests (it declares a
    /// bound). `in_flight` and `capacity` mean nothing when it does not.
    pub gated: bool,
    pub in_flight: i64,
    pub capacity: Option<i64>,
    /// Whether the gateway reads this engine's own gauges.
    pub engine_read: bool,
    /// Whether a queue bound depends on that reading. A silent engine with
    /// one is not applying it; without one, only its charts are missing.
    pub queue_bounded: bool,
    /// The engine's own gauges, from the most recent reading any replica took.
    /// `null` when it is not read, or no replica hears from it.
    pub engine: Option<EngineLive>,
    /// Replicas that read this engine and have stopped hearing from it: each
    /// is not applying its queue bound, whatever the others see.
    pub engine_silent_replicas: i64,
    /// Where the learned in-flight limit stands, when the limit is learned.
    pub adaptive: Option<AdaptiveLive>,
}

/// A learned in-flight limit across the replicas that report it.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq)]
pub struct AdaptiveLive {
    /// The limits the replicas apply now, summed — `null` while any of them
    /// applies none (its engine unheard and no ceiling set).
    pub limit: Option<i64>,
    /// The most pressing state any replica reports (`AdaptiveState::pressure`).
    pub state: AdaptiveState,
    /// The engine's time between tokens while it ran one or two requests per
    /// rank, in milliseconds: the slowest figure any replica learned. `null`
    /// until one has.
    pub low_load_itl_ms: Option<f64>,
    /// What an automatic token-latency target holds this engine to:
    /// `AUTO_ITL_TARGET_RATIO` times `low_load_itl_ms` — the figure each
    /// replica applies is its own, and this one the slowest. `null` until
    /// EVERY replica reporting the engine has learned its own: a replica still
    /// learning holds nothing. Reported whatever the server's setting.
    pub auto_itl_target_ms: Option<f64>,
}

/// An engine's own gauges.
#[derive(Serialize, ToSchema, Debug, Clone, PartialEq)]
pub struct EngineLive {
    pub waiting: i64,
    /// `null` when the engine does not publish the gauge — never a zero.
    pub running: Option<i64>,
    /// KV-cache use, a fraction in `[0, 1]`; `null` when not published.
    pub kv_usage: Option<f64>,
}

#[derive(Serialize, ToSchema)]
pub struct ServerFleetEntry {
    pub server_id: Uuid,
    pub traffic: ServerTraffic,
    /// Attempts per bucket, aligned with [`ServerFleetResponse::bucket_starts`].
    pub buckets: Vec<i64>,
    /// `null` when no replica has reported a reading lately — the server is
    /// not gated, or no gateway is connected.
    pub live: Option<ServerLive>,
}

#[derive(Serialize, ToSchema)]
pub struct ServerFleetResponse {
    /// `"hour"` for a window up to 48 hours, `"day"` beyond.
    pub interval: String,
    pub bucket_starts: Vec<DateTime<Utc>>,
    /// Every existing server with traffic in the window or a live reading now.
    /// A server absent here had neither, or has been deleted.
    pub servers: Vec<ServerFleetEntry>,
    /// How far back live load readings reach for this tenant: seven days, or
    /// its retention window if that is shorter.
    pub live_history_days: i64,
}

#[derive(Serialize, ToSchema)]
pub struct RefusalCount {
    /// Why the gate gave no capacity: `shed`, `queue_timeout`,
    /// `gateway_saturated`, `shutting_down` or `superseded` (the same request
    /// was sent again while this copy waited). Counted at the pool that
    /// refused, including the refusals a request then moved on from.
    pub reason: String,
    pub count: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ServerEndpointEntry {
    pub endpoint_id: Uuid,
    /// A URL the rows recorded for this endpoint — what names an endpoint
    /// since removed. A current endpoint is named by its own resource.
    pub url: Option<String>,
    pub traffic: ServerTraffic,
    pub live: Option<EndpointLive>,
}

#[derive(Serialize, ToSchema)]
pub struct ServerClassEntry {
    /// `null` for requests of a tenant with no classes.
    pub qos_class_id: Option<Uuid>,
    pub traffic: ServerTraffic,
    pub refusals: Vec<RefusalCount>,
}

#[derive(Serialize, ToSchema)]
pub struct ServerWaiter {
    pub user_id: Uuid,
    /// Display name, else email, else the id.
    pub label: String,
    pub email: Option<String>,
    /// This user's attempts at this server (see [`ServerTraffic::requests`]).
    pub requests: i64,
    /// Attempts that waited and were then sent.
    pub queued: i64,
    /// Everything this user's requests spent waiting at this server's pool, in
    /// total — including a wait that ended in a refusal here, or in an attempt
    /// the request then moved on from: that time was spent all the same.
    pub wait_ms_total: i64,
    /// The wait of the attempts that waited and were then sent.
    pub queue_wait_p95_ms: Option<f64>,
}

/// One endpoint's gauges per bucket: each bucket's PEAK, and its mean beside
/// it. A replica reports, on each heartbeat, the instant and the highest value
/// since its previous beat; the mean of the instants dilutes a burst by the
/// length of the bucket — a minute at 100% KV reads under 2% over an hour —
/// and an instant misses a burst between two beats, while the peak keeps it.
/// `null` for a bucket with no reading.
#[derive(Serialize, ToSchema)]
pub struct EndpointGaugeSeries {
    pub endpoint_id: Uuid,
    /// Requests in flight across the gateway replicas: summed across replicas
    /// within each 60 s window (each holds one beat of every live replica, a
    /// beat carrying its replica's highest count since the one before), and
    /// the highest such window in the bucket — the fleet's peak. A pod and the
    /// one replacing it are added only in the one window that can hold the
    /// old pod's last beat and the new one's first, never across the bucket.
    pub in_flight: Vec<Option<f64>>,
    /// The same windows' sums, averaged over the bucket's windows.
    pub in_flight_mean: Vec<Option<f64>>,
    /// The learned in-flight limit: each replica's, summed across replicas per
    /// window, averaged over the bucket — what the gateways together let through.
    /// `null` where the limit is not learned.
    pub learned_limit: Vec<Option<f64>>,
    /// The engine's own gauges: its highest reading in the bucket, from any
    /// replica — they all read the same engine. `null` where it was not read.
    pub engine_waiting: Vec<Option<f64>>,
    pub engine_running: Vec<Option<f64>>,
    pub engine_kv_usage: Vec<Option<f64>>,
    /// The same gauges' mean over every reading in the bucket.
    pub engine_waiting_mean: Vec<Option<f64>>,
    pub engine_running_mean: Vec<Option<f64>>,
    pub engine_kv_usage_mean: Vec<Option<f64>>,
}

impl EndpointGaugeSeries {
    fn empty(endpoint_id: Uuid, len: usize) -> Self {
        Self {
            endpoint_id,
            in_flight: vec![None; len],
            in_flight_mean: vec![None; len],
            learned_limit: vec![None; len],
            engine_waiting: vec![None; len],
            engine_running: vec![None; len],
            engine_kv_usage: vec![None; len],
            engine_waiting_mean: vec![None; len],
            engine_running_mean: vec![None; len],
            engine_kv_usage_mean: vec![None; len],
        }
    }
}

/// One endpoint's live load over the window, per bucket.
#[derive(Serialize, ToSchema)]
pub struct EndpointLoadSeries {
    #[serde(flatten)]
    pub gauges: EndpointGaugeSeries,
    /// The most the engine was seen running while it kept a queue of its own,
    /// over the period. Not a capacity: an engine queues on its token budget
    /// per step as well as on its memory or batch cap. `null` when it did not
    /// queue in the period.
    pub engine_queueing_at: Option<i64>,
    /// Derived from the engine's own cumulative counters: the change between
    /// consecutive readings of one gateway replica (a fall is an engine
    /// restart, counted from zero), averaged across the replicas that read it —
    /// they all read the same engine. `null` where it was not read, or does not
    /// publish the counter.
    pub engine_prompt_tokens_per_s: Vec<Option<f64>>,
    pub engine_generation_tokens_per_s: Vec<Option<f64>>,
    /// Requests the engine preempted (evicted from its KV cache to recompute
    /// later), per minute.
    pub engine_preemptions_per_min: Vec<Option<f64>>,
    /// Prompt tokens the engine did not recompute — found in its prefix cache,
    /// or loaded back from its CPU tier — as a fraction of those looked up.
    pub engine_prefix_hit_rate: Vec<Option<f64>>,
    /// Mean time a request spent in the engine's own waiting queue, and to its
    /// first token, in milliseconds.
    pub engine_queue_time_ms: Vec<Option<f64>>,
    pub engine_ttft_ms: Vec<Option<f64>>,
    /// Prompt tokens the engine computed — looked up in its prefix cache and
    /// found neither there nor in its CPU tier — per second: a recomputed
    /// history shows here, not in the prompt tokens served.
    pub engine_computed_prompt_tokens_per_s: Vec<Option<f64>>,
    /// Mean time between two output tokens of one request, in milliseconds —
    /// what a learned limit's token-latency target is held against.
    pub engine_itl_ms: Vec<Option<f64>>,
    /// What the learned limits did in the bucket, summed over the replicas
    /// (each runs its own): windows raised, stepped down for a round of token
    /// latency above the target, and back-offs by cause. `null` where the
    /// limit is not learned.
    pub adaptive_grew: Vec<Option<f64>>,
    pub adaptive_stepped_down: Vec<Option<f64>>,
    pub adaptive_cut_preemption: Vec<Option<f64>>,
    pub adaptive_cut_kv_full: Vec<Option<f64>>,
}

impl EndpointLoadSeries {
    fn from_gauges(gauges: EndpointGaugeSeries, len: usize) -> Self {
        Self {
            gauges,
            engine_queueing_at: None,
            engine_prompt_tokens_per_s: vec![None; len],
            engine_generation_tokens_per_s: vec![None; len],
            engine_preemptions_per_min: vec![None; len],
            engine_prefix_hit_rate: vec![None; len],
            engine_queue_time_ms: vec![None; len],
            engine_ttft_ms: vec![None; len],
            engine_computed_prompt_tokens_per_s: vec![None; len],
            engine_itl_ms: vec![None; len],
            adaptive_grew: vec![None; len],
            adaptive_stepped_down: vec![None; len],
            adaptive_cut_preemption: vec![None; len],
            adaptive_cut_kv_full: vec![None; len],
        }
    }
}

/// Requests held at the gateway for one class, per bucket: summed across
/// replicas within each 60 s window, as `EndpointGaugeSeries::in_flight` is —
/// the highest window (`held`), and the mean over the bucket's windows
/// (`held_mean`). A bucket with no beat is `null`.
#[derive(Serialize, ToSchema)]
pub struct ClassHeldSeries {
    /// `null` for a tenant with no classes.
    pub qos_class_id: Option<Uuid>,
    pub held: Vec<Option<f64>>,
    pub held_mean: Vec<Option<f64>>,
}

/// One class's attempts at this server, per bucket.
#[derive(Serialize, ToSchema)]
pub struct ClassTrafficSeries {
    /// `null` for requests of a tenant with no classes.
    pub qos_class_id: Option<Uuid>,
    /// Aligned with `bucket_starts`; a bucket with no attempt of the class is
    /// all zeros.
    pub series: Vec<ServerTraffic>,
}

#[derive(Serialize, ToSchema)]
pub struct ServerDashboardResponse {
    pub server_id: Uuid,
    /// `"hour"` for a window up to 8 days, `"day"` beyond
    /// ([`server_bucket_interval`]).
    pub interval: String,
    pub bucket_starts: Vec<DateTime<Utc>>,
    pub traffic: ServerTraffic,
    /// Per bucket, aligned with `bucket_starts`.
    pub series: Vec<ServerTraffic>,
    /// Per endpoint that answered in the window or reports live load.
    pub endpoints: Vec<ServerEndpointEntry>,
    pub classes: Vec<ServerClassEntry>,
    /// Each class's attempts per bucket.
    pub class_series: Vec<ClassTrafficSeries>,
    pub refusals: Vec<RefusalCount>,
    /// The users whose requests waited longest in total.
    pub top_waiters: Vec<ServerWaiter>,
    pub live: Option<ServerLive>,
    /// Live load per endpoint over the window (the part of it within
    /// `live_history_days`).
    pub load_series: Vec<EndpointLoadSeries>,
    /// Requests held at the gateway, per class (holds a gateway reported with
    /// no class breakdown as their own series). Empty when nothing was held.
    pub class_held_series: Vec<ClassHeldSeries>,
    pub live_history_days: i64,
}

/// One server's gauges over the last few minutes, one bucket per TWO
/// heartbeats ([`recent_bucket_secs`]), each beat carrying its interval's peak. The
/// same figures as the dashboard's load series (peak and mean per bucket),
/// whatever the dashboard's period.
#[derive(Serialize, ToSchema)]
pub struct ServerRecentLoadResponse {
    pub server_id: Uuid,
    /// Seconds per bucket.
    pub bucket_secs: i64,
    /// Seconds the window covers, ending now.
    pub window_secs: i64,
    pub bucket_starts: Vec<DateTime<Utc>>,
    /// Each endpoint's gauges, and the rates derived from its engine's
    /// counters and its learned limit's decisions, per bucket — the
    /// dashboard's load series at this grain.
    pub load_series: Vec<EndpointLoadSeries>,
    /// Requests held at the gateway, per class, as on the dashboard.
    pub class_held_series: Vec<ClassHeldSeries>,
    /// The server's load now — the same as the dashboard's `live` — so a figure
    /// labelled "now" beside these charts moves with them.
    pub live: Option<ServerLive>,
    /// Each endpoint's load now.
    pub endpoints_live: Vec<EndpointLiveEntry>,
}

/// One endpoint's load now.
#[derive(Serialize, ToSchema)]
pub struct EndpointLiveEntry {
    pub endpoint_id: Uuid,
    pub live: EndpointLive,
}

/// `GROUPING(bucket, endpoint, class, refusal, user)` of each set: a bit is
/// set for each key the row is NOT grouped by.
const GRAIN_TOTAL: i32 = 0b11111;
const GRAIN_BUCKET: i32 = 0b01111;
const GRAIN_ENDPOINT: i32 = 0b10111;
const GRAIN_CLASS: i32 = 0b11011;
const GRAIN_CLASS_REFUSAL: i32 = 0b11001;
const GRAIN_USER: i32 = 0b11110;
const GRAIN_BUCKET_CLASS: i32 = 0b01011;

/// The newest reading one replica sent for one endpoint.
#[derive(sqlx::FromRow, Debug, Clone)]
pub(crate) struct LoadRow {
    server_id: Uuid,
    endpoint_id: Uuid,
    edge_instance_id: Uuid,
    sampled_at: DateTime<Utc>,
    in_flight: i32,
    server_held: i32,
    engine_read: bool,
    engine_waiting: Option<i32>,
    engine_running: Option<i32>,
    engine_kv_usage: Option<f64>,
    /// How old the engine reading was when the replica sent it.
    engine_age_ms: Option<i32>,
    /// The endpoint's in-flight bound as configured now (its own, else its
    /// server's).
    max_in_flight: Option<i32>,
    /// Its engine-queue bound as configured now, resolved the same way.
    waiting_threshold: Option<i32>,
    /// Whether the replica counted this endpoint's requests.
    gated: bool,
    /// `server_held` per class, as the replica reported it.
    server_held_by_class: sqlx::types::Json<Vec<streamscope_core::proxy::qos_metrics::ClassHeld>>,
    /// The replica's learned limit, its state and the engine's low-load time
    /// between tokens it learned; the state is `None` where the limit is not
    /// learned.
    adaptive_limit: Option<i32>,
    adaptive_state: Option<String>,
    adaptive_low_load_itl_us: Option<i32>,
}

fn db_error(what: &'static str) -> impl FnOnce(sqlx::Error) -> ApiError {
    move |e| {
        tracing::error!("server analytics {what}: {e}");
        ApiError::internal("database query failed")
    }
}

/// Each connected replica's latest written beat, one row per endpoint of this
/// tenant it reported there (`edge_instances.state_beat_id`) — only while that
/// beat is of the current process epoch and within the connected window. An
/// endpoint the replica left out of that beat — its bound removed, say — is not
/// live, however recent its older row; a replica whose latest beat reported
/// nothing here contributes nothing; and one whose beats stopped landing shows
/// nothing rather than an old reading as live: every figure on a card
/// describes the same, current beat. `server` narrows to one server.
pub(crate) async fn latest_load(db: &mut TenantConn, server: Option<Uuid>) -> Result<Vec<LoadRow>, ApiError> {
    let live = crate::routes::upstream_endpoints::connected_within_secs();
    sqlx::query_as::<_, LoadRow>(
        "SELECT l.server_id, l.endpoint_id, l.edge_instance_id, l.sampled_at, l.in_flight, \
                l.server_held, l.engine_read, l.engine_waiting, l.engine_running, l.engine_kv_usage, \
                l.engine_age_ms, COALESCE(e.max_in_flight, s.max_in_flight) AS max_in_flight, \
                COALESCE(e.waiting_threshold, s.waiting_threshold) AS waiting_threshold, l.gated, \
                l.server_held_by_class, l.adaptive_limit, l.adaptive_state, l.adaptive_low_load_itl_us \
         FROM upstream_load_samples l \
         JOIN edge_instances i ON i.id = l.edge_instance_id AND i.state_beat_id = l.beat_id \
         LEFT JOIN upstream_server_endpoints e ON e.id = l.endpoint_id \
         LEFT JOIN upstream_servers s ON s.id = l.server_id \
         WHERE l.tenant_id = $1 AND l.sampled_at >= now() - make_interval(secs => $2) \
           AND i.state_written_at >= now() - make_interval(secs => $2) \
           AND i.state_written_at >= i.epoch_started_at \
           AND i.last_seen_at >= now() - make_interval(secs => $2) \
           AND ($3::uuid IS NULL OR l.server_id = $3)",
    )
    .bind(db.tenant_uuid())
    .bind(live as f64)
    .bind(server)
    .fetch_all(db.conn())
    .await
    .map_err(db_error("live load"))
}

/// Refusal counts by reason, most frequent first.
fn refusal_counts(counts: HashMap<String, i64>) -> Vec<RefusalCount> {
    let mut refusals: Vec<RefusalCount> =
        counts.into_iter().map(|(reason, count)| RefusalCount { reason, count }).collect();
    refusals.sort_by(|a, b| b.count.cmp(&a.count).then(a.reason.cmp(&b.reason)));
    refusals
}

/// Fold the newest readings into per-server and per-endpoint live load.
///
/// The rules, each a way to get the answer wrong: gateway counts (in flight,
/// held) are per replica, so they SUM across replicas; `server_held` is
/// repeated on every endpoint row of one replica, so it is taken ONCE per
/// replica; the engine's gauges describe one engine that every replica reads,
/// so they are never summed — the reading TAKEN most recently stands, judged by
/// when the replica read the engine (`sampled_at - engine_age_ms`), not by when
/// its heartbeat went out. Silence is per replica: one that has stopped hearing
/// from the engine is not applying its bound even while another replica still
/// reads it. A capacity is only stated when every reading has a bound: a
/// partial sum would read as a limit the fleet does not have. `rows` are one
/// beat per replica ([`latest_load`]).
pub(crate) fn summarize_live(rows: &[LoadRow]) -> (HashMap<Uuid, ServerLive>, HashMap<Uuid, EndpointLive>) {
    let mut endpoints: HashMap<Uuid, (EndpointLive, Option<DateTime<Utc>>)> = HashMap::new();
    // Endpoints with a replica whose learned limit has no low-load figure yet:
    // that replica applies no automatic target, so the engine has none to show.
    let mut still_learning: HashSet<Uuid> = HashSet::new();
    for r in rows {
        let entry = endpoints.entry(r.endpoint_id).or_insert_with(|| {
            (
                EndpointLive {
                    sampled_at: r.sampled_at,
                    replicas: 0,
                    gated: false,
                    in_flight: 0,
                    capacity: Some(0),
                    engine_read: false,
                    queue_bounded: false,
                    engine: None,
                    engine_silent_replicas: 0,
                    adaptive: None,
                },
                None,
            )
        });
        let (live, engine_at) = entry;
        live.sampled_at = live.sampled_at.max(r.sampled_at);
        live.replicas += 1;
        if r.gated {
            live.gated = true;
            live.in_flight += i64::from(r.in_flight);
        }
        // A learned limit is what the replica applies; the configured
        // in-flight value is only its ceiling.
        // Read with the wire's own vocabulary: a state a newer gateway wrote
        // is `Unknown`, still a learned limit.
        let adaptive = r.adaptive_state.as_deref().map(AdaptiveState::from_stored);
        let bound = if adaptive.is_some() { r.adaptive_limit } else { r.max_in_flight };
        live.capacity = match (live.capacity, bound) {
            (Some(total), Some(max)) => Some(total + i64::from(max)),
            _ => None,
        };
        if let Some(state) = adaptive {
            let itl = r.adaptive_low_load_itl_us.map(|us| f64::from(us) / 1000.0);
            if itl.is_none() {
                still_learning.insert(r.endpoint_id);
            }
            live.adaptive = Some(match live.adaptive.take() {
                None => AdaptiveLive {
                    limit: r.adaptive_limit.map(i64::from),
                    state,
                    low_load_itl_ms: itl,
                    // Derived once the replicas are folded (below).
                    auto_itl_target_ms: None,
                },
                Some(a) => AdaptiveLive {
                    limit: a.limit.zip(r.adaptive_limit).map(|(t, l)| t + i64::from(l)),
                    state: if state.pressure() > a.state.pressure() { state } else { a.state },
                    low_load_itl_ms: max_opt(a.low_load_itl_ms, itl),
                    auto_itl_target_ms: None,
                },
            });
        }
        live.engine_read |= r.engine_read;
        live.queue_bounded |= r.waiting_threshold.is_some();
        // A reading is present when the gate's own gauge (waiting) is; the
        // other two are shown when the engine publishes them.
        match r.engine_waiting {
            Some(waiting) => {
                let read_at = r.sampled_at - chrono::Duration::milliseconds(i64::from(r.engine_age_ms.unwrap_or(0)));
                if engine_at.is_none_or(|at| read_at > at) {
                    *engine_at = Some(read_at);
                    live.engine = Some(EngineLive {
                        waiting: i64::from(waiting),
                        running: r.engine_running.map(i64::from),
                        kv_usage: r.engine_kv_usage,
                    });
                }
            }
            None if r.engine_read => live.engine_silent_replicas += 1,
            None => {}
        }
    }

    // Each engine's automatic target, from its slowest replica's figure — once
    // every replica reporting it has learned its own: each applies only its
    // own, so one still learning holds nothing, and a target shown then would
    // claim a hold part of the fleet does not apply.
    for (endpoint_id, (live, _)) in endpoints.iter_mut() {
        if let Some(a) = live.adaptive.as_mut() {
            a.auto_itl_target_ms = if still_learning.contains(endpoint_id) {
                None
            } else {
                a.low_load_itl_ms.and_then(auto_itl_target)
            };
        }
    }
    let server_of: HashMap<Uuid, Uuid> = rows.iter().map(|r| (r.endpoint_id, r.server_id)).collect();
    let mut servers: HashMap<Uuid, ServerLive> = HashMap::new();
    for (endpoint_id, (live, _)) in &endpoints {
        let Some(server_id) = server_of.get(endpoint_id) else { continue };
        let s = servers.entry(*server_id).or_insert_with(|| ServerLive {
            sampled_at: live.sampled_at,
            replicas: 0,
            gated: false,
            in_flight: 0,
            capacity: Some(0),
            held: 0,
            held_by_class: Vec::new(),
            engines_silent: 0,
            auto_itl_target_ms: None,
        });
        s.sampled_at = s.sampled_at.max(live.sampled_at);
        if live.gated {
            s.gated = true;
            s.in_flight += live.in_flight;
            s.capacity = match (s.capacity, live.capacity) {
                (Some(total), Some(cap)) => Some(total + cap),
                _ => None,
            };
        }
        s.auto_itl_target_ms = max_opt(s.auto_itl_target_ms, live.adaptive.as_ref().and_then(|a| a.auto_itl_target_ms));
        if live.engine_read {
            // A learned limit that is not applied — its engine unheard, or
            // heard without the KV-cache gauge — is as silent as a queue bound
            // that is not: neither is doing what it was set to do.
            let adaptive_unapplied = live.adaptive.as_ref().is_some_and(|a| a.state == AdaptiveState::NoReading);
            if ((live.queue_bounded || live.adaptive.is_some()) && live.engine_silent_replicas > 0) || adaptive_unapplied {
                s.engines_silent += 1;
            }
        }
    }
    // Replicas and held, once per (server, replica): `server_held` is
    // repeated on every endpoint row of the replica's one beat.
    let mut held: HashMap<(Uuid, Uuid), &LoadRow> = HashMap::new();
    for r in rows {
        held.entry((r.server_id, r.edge_instance_id)).or_insert(r);
    }
    let mut replicas: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    let mut by_class: HashMap<Uuid, HashMap<Option<Uuid>, i64>> = HashMap::new();
    for ((server_id, instance), r) in held {
        if let Some(s) = servers.get_mut(&server_id) {
            s.held += i64::from(r.server_held);
        }
        for c in &r.server_held_by_class.0 {
            *by_class.entry(server_id).or_default().entry(c.class_id).or_default() += i64::from(c.held);
        }
        replicas.entry(server_id).or_default().insert(instance);
    }
    for (server_id, classes) in by_class {
        if let Some(s) = servers.get_mut(&server_id) {
            s.held_by_class = classes
                .into_iter()
                .filter(|(_, held)| *held > 0)
                .map(|(qos_class_id, held)| ClassHeldLive { qos_class_id, held })
                .collect();
            s.held_by_class.sort_by(|a, b| b.held.cmp(&a.held).then(a.qos_class_id.cmp(&b.qos_class_id)));
        }
    }
    for (server_id, set) in replicas {
        if let Some(s) = servers.get_mut(&server_id) {
            s.replicas = i64::try_from(set.len()).unwrap_or(i64::MAX);
        }
    }
    // Slots belong to counted endpoints only: a server nothing gates has none.
    for s in servers.values_mut().filter(|s| !s.gated) {
        s.capacity = None;
    }
    (servers, endpoints.into_iter().map(|(id, (live, _))| (id, live)).collect())
}

/// The automatic token-latency target of an engine whose time between tokens
/// at low load is `itl_ms`, in milliseconds to a tenth — the gateway's own
/// formula (`adaptive_concurrency::auto_itl_target`), so the console shows
/// what the gateway applies.
fn auto_itl_target(itl_ms: f64) -> Option<f64> {
    streamscope_core::proxy::adaptive_concurrency::auto_itl_target(itl_ms / 1000.0).map(|s| (s * 10_000.0).round() / 10.0)
}

/// Index of each bucket start, for placing grouped rows on the shared axis.
fn axis_index(axis: &[DateTime<Utc>]) -> HashMap<DateTime<Utc>, usize> {
    axis.iter().enumerate().map(|(i, ts)| (*ts, i)).collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/servers",
    tag = "Analytics",
    params(UsageQuery),
    responses(
        (status = 200, description = "Per-server traffic, latency, refusals and live load for the server dashboard's fleet list", body = ServerFleetResponse),
        (status = 400, description = "Invalid time window", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn server_fleet(
    mut db: TenantConn,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ServerFleetResponse>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope_filter = query.scope();
    let interval = bucket_interval(start, end);
    let tenant_id = db.tenant_uuid();
    let fleet_rows = servers_store::fleet_rows(db.conn(), tenant_id, (start, end), interval, &scope_filter)
        .await
        .map_err(db_error("fleet figures"))?;

    let (live, _) = summarize_live(&latest_load(&mut db, None).await?);

    let bucket_starts = build_bucket_axis(start, end, interval);
    let index = axis_index(&bucket_starts);
    let mut servers: HashMap<Uuid, ServerFleetEntry> = HashMap::new();
    let blank = |server_id: Uuid| ServerFleetEntry {
        server_id,
        traffic: ServerTraffic::default(),
        buckets: vec![0; bucket_starts.len()],
        live: None,
    };
    for row in fleet_rows {
        let entry = servers.entry(row.server_id).or_insert_with(|| blank(row.server_id));
        match row.bucket.filter(|_| row.by_bucket == 0) {
            Some(bucket) => {
                if let Some(&i) = index.get(&bucket) {
                    entry.buckets[i] = row.traffic.requests;
                }
            }
            None => entry.traffic = row.traffic,
        }
    }
    for (server_id, reading) in live {
        servers.entry(server_id).or_insert_with(|| blank(server_id)).live = Some(reading);
    }
    // The servers that exist: one deleted since keeps its rows (the audit log
    // and the traffic breakdowns still name it), but has no page to open.
    let existing: HashSet<Uuid> = sqlx::query_scalar("SELECT id FROM upstream_servers")
        .fetch_all(db.conn())
        .await
        .map_err(db_error("fleet servers"))?
        .into_iter()
        .collect();
    servers.retain(|id, _| existing.contains(id));
    let mut servers: Vec<ServerFleetEntry> = servers.into_values().collect();
    servers.sort_by(|a, b| b.traffic.requests.cmp(&a.traffic.requests).then(a.server_id.cmp(&b.server_id)));

    Ok(Json(ServerFleetResponse {
        interval: interval.to_string(),
        bucket_starts,
        servers,
        live_history_days: load_sample_horizon_days(db.conn()).await,
    }))
}

/// The server page's bucket: an hour for a window up to 8 days, a day beyond.
/// Finer than the other dashboards' 48 h: its load charts plot each bucket's
/// PEAK, and a day's peak of a busy engine is "full" every day — a flat line
/// that says nothing — while its load history is kept 7 days anyway.
fn server_bucket_interval(start: DateTime<Utc>, end: DateTime<Utc>) -> &'static str {
    if (end - start).num_hours() <= 8 * 24 { "hour" } else { "day" }
}

/// The tenant's own server, or 404: the read is RLS-scoped, so another
/// tenant's id is indistinguishable from one that never existed.
async fn ensure_server(db: &mut TenantConn, server_id: Uuid) -> Result<(), ApiError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM upstream_servers WHERE id = $1)")
        .bind(server_id)
        .fetch_one(db.conn())
        .await
        .map_err(db_error("server lookup"))?;
    if exists { Ok(()) } else { Err(ApiError::not_found("server not found", ApiErrorCode::ServerNotFound)) }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/servers/{id}/recent-load",
    tag = "Analytics",
    params(("id" = Uuid, Path, description = "Upstream server id")),
    responses(
        (status = 200, description = "One server's gauges over the last minutes, one bucket per two gateway heartbeats", body = ServerRecentLoadResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn server_recent_load(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
) -> Result<Json<ServerRecentLoadResponse>, ApiError> {
    ensure_server(&mut db, server_id).await?;
    let end = Utc::now();
    let start = end - chrono::Duration::seconds(RECENT_LOAD_WINDOW_SECS);
    let secs = recent_bucket_secs();
    let settled = settled_until(&mut db, server_id, end).await?;
    let bucket_starts = recent_bucket_axis(start, settled, secs);
    let index = axis_index(&bucket_starts);
    // From the first bucket's start to the last one's end, so every bucket on
    // the axis holds all its readings and the open one is not read.
    let from = bucket_starts.first().copied().unwrap_or(start);
    let end = bucket_starts.last().map_or(end, |last| *last + chrono::Duration::seconds(secs));
    let grain = LoadGrain::Recent(secs);
    let len = index.len();
    let LoadHistory { series: gauges, .. } = load_history(&mut db, server_id, from, end, grain, &index).await?;
    let mut load_series: Vec<EndpointLoadSeries> =
        gauges.into_iter().map(|g| EndpointLoadSeries::from_gauges(g, len)).collect();
    engine_history(&mut db, server_id, from, end, grain, &index, &mut load_series).await?;
    let class_held_series = class_held_history(&mut db, server_id, from, end, grain, &index).await?;
    let (mut live_servers, live_endpoints) = summarize_live(&latest_load(&mut db, Some(server_id)).await?);
    let mut endpoints_live: Vec<EndpointLiveEntry> =
        live_endpoints.into_iter().map(|(endpoint_id, live)| EndpointLiveEntry { endpoint_id, live }).collect();
    endpoints_live.sort_by_key(|e| e.endpoint_id);
    Ok(Json(ServerRecentLoadResponse {
        server_id,
        bucket_secs: secs,
        window_secs: RECENT_LOAD_WINDOW_SECS,
        bucket_starts,
        load_series,
        class_held_series,
        live: live_servers.remove(&server_id),
        endpoints_live,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/servers/{id}",
    tag = "Analytics",
    params(("id" = Uuid, Path, description = "Upstream server id"), UsageQuery),
    responses(
        (status = 200, description = "One server's traffic over time, per endpoint and per class, its refusals, the users who waited longest, and its live load", body = ServerDashboardResponse),
        (status = 400, description = "Invalid time window", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn server_dashboard(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ServerDashboardResponse>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope_filter = query.scope();
    ensure_server(&mut db, server_id).await?;

    let interval = server_bucket_interval(start, end);
    let tenant_id = db.tenant_uuid();
    let grain_rows = servers_store::grain_rows(db.conn(), tenant_id, server_id, (start, end), interval, &scope_filter)
        .await
        .map_err(db_error("server figures"))?;

    let bucket_starts = build_bucket_axis(start, end, interval);
    let index = axis_index(&bucket_starts);
    let mut traffic = ServerTraffic::default();
    let mut series = vec![ServerTraffic::default(); bucket_starts.len()];
    let mut endpoint_rows: Vec<(Uuid, Option<String>, ServerTraffic)> = Vec::new();
    let mut class_rows: Vec<(Option<Uuid>, ServerTraffic)> = Vec::new();
    let mut refusals: HashMap<String, i64> = HashMap::new();
    let mut class_refusals: HashMap<Option<Uuid>, HashMap<String, i64>> = HashMap::new();
    let mut user_rows: Vec<(Uuid, ServerTraffic)> = Vec::new();
    let mut class_buckets: HashMap<Option<Uuid>, Vec<ServerTraffic>> = HashMap::new();
    for row in grain_rows {
        match row.grain {
            GRAIN_TOTAL => traffic = row.traffic,
            GRAIN_BUCKET => {
                if let Some(i) = row.bucket.and_then(|b| index.get(&b).copied()) {
                    series[i] = row.traffic;
                }
            }
            // Attempts naming no endpoint (a refusal reached none) are the
            // server's, not any endpoint's.
            GRAIN_ENDPOINT => {
                if let Some(endpoint_id) = row.endpoint_id {
                    endpoint_rows.push((endpoint_id, row.url, row.traffic));
                }
            }
            GRAIN_CLASS => class_rows.push((row.qos_class_id, row.traffic)),
            GRAIN_BUCKET_CLASS => {
                if let Some(i) = row.bucket.and_then(|b| index.get(&b).copied()) {
                    class_buckets
                        .entry(row.qos_class_id)
                        .or_insert_with(|| vec![ServerTraffic::default(); bucket_starts.len()])[i] = row.traffic;
                }
            }
            // A NULL reason is the class's attempts that were not refused.
            GRAIN_CLASS_REFUSAL => {
                if let Some(reason) = row.refusal {
                    *refusals.entry(reason.clone()).or_default() += row.traffic.refusals;
                    *class_refusals.entry(row.qos_class_id).or_default().entry(reason).or_default() +=
                        row.traffic.refusals;
                }
            }
            GRAIN_USER => {
                if let Some(user_id) = row.user_id
                    && row.traffic.wait_ms_total > 0
                {
                    user_rows.push((user_id, row.traffic));
                }
            }
            _ => {}
        }
    }
    user_rows.sort_by_key(|(user_id, t)| (std::cmp::Reverse(t.wait_ms_total), *user_id));
    user_rows.truncate(TOP_WAITERS);
    let top_waiters = name_waiters(&mut db, user_rows).await?;
    let refusals = refusal_counts(refusals);
    let mut classes: Vec<ServerClassEntry> = class_rows
        .into_iter()
        .map(|(qos_class_id, traffic)| ServerClassEntry {
            qos_class_id,
            traffic,
            refusals: refusal_counts(class_refusals.remove(&qos_class_id).unwrap_or_default()),
        })
        .collect();
    classes.sort_by_key(|c| (std::cmp::Reverse(c.traffic.requests), c.qos_class_id));
    // In the order of the class list, so a class keeps its colour across panels.
    let class_series: Vec<ClassTrafficSeries> = classes
        .iter()
        .filter_map(|c| {
            class_buckets
                .remove(&c.qos_class_id)
                .map(|series| ClassTrafficSeries { qos_class_id: c.qos_class_id, series })
        })
        .collect();

    let (mut live_servers, mut live_endpoints) = summarize_live(&latest_load(&mut db, Some(server_id)).await?);
    let mut endpoints: Vec<ServerEndpointEntry> = endpoint_rows
        .into_iter()
        .map(|(endpoint_id, url, traffic)| ServerEndpointEntry {
            live: live_endpoints.remove(&endpoint_id),
            endpoint_id,
            url,
            traffic,
        })
        .collect();
    // An endpoint that reports load but answered nothing in the window.
    endpoints.extend(live_endpoints.into_iter().map(|(endpoint_id, live)| ServerEndpointEntry {
        endpoint_id,
        url: None,
        traffic: ServerTraffic::default(),
        live: Some(live),
    }));
    endpoints.sort_by(|a, b| b.traffic.requests.cmp(&a.traffic.requests).then(a.endpoint_id.cmp(&b.endpoint_id)));

    let grain = LoadGrain::Period(interval);
    let len = bucket_starts.len();
    let LoadHistory { series: gauges, queueing_at } =
        load_history(&mut db, server_id, start, end, grain, &index).await?;
    let mut load_series: Vec<EndpointLoadSeries> = gauges
        .into_iter()
        .map(|g| {
            let queueing = queueing_at.get(&g.endpoint_id).copied();
            EndpointLoadSeries { engine_queueing_at: queueing, ..EndpointLoadSeries::from_gauges(g, len) }
        })
        .collect();
    engine_history(&mut db, server_id, start, end, grain, &index, &mut load_series).await?;
    let class_held_series = class_held_history(&mut db, server_id, start, end, grain, &index).await?;

    Ok(Json(ServerDashboardResponse {
        server_id,
        interval: interval.to_string(),
        bucket_starts,
        traffic,
        series,
        endpoints,
        classes,
        class_series,
        refusals,
        top_waiters,
        live: live_servers.remove(&server_id),
        load_series,
        class_held_series,
        live_history_days: load_sample_horizon_days(db.conn()).await,
    }))
}

/// How many of the users who waited longest the page names.
const TOP_WAITERS: usize = 10;

/// Name the users who waited longest, in the order given. The few that survive
/// the cut are looked up afterwards — joining `users` into the aggregate lets a
/// misestimated audit row count cascade into a nested loop over the side table
/// (see `usage_breakdown`).
async fn name_waiters(db: &mut TenantConn, rows: Vec<(Uuid, ServerTraffic)>) -> Result<Vec<ServerWaiter>, ApiError> {
    let ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();
    let names: HashMap<Uuid, (String, Option<String>)> = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT id, COALESCE(display_name, email, id::text), email FROM users WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(db.conn())
    .await
    .map_err(db_error("server waiters"))?
    .into_iter()
    .map(|(id, label, email)| (id, (label, email)))
    .collect();
    Ok(rows
        .into_iter()
        .map(|(user_id, t)| {
            let (label, email) = names.get(&user_id).cloned().unwrap_or_else(|| (user_id.to_string(), None));
            ServerWaiter {
                user_id,
                label,
                email,
                requests: t.requests,
                queued: t.queued,
                wait_ms_total: t.wait_ms_total,
                queue_wait_p95_ms: t.queue_wait_p95_ms,
            }
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct LoadBucket {
    bucket: DateTime<Utc>,
    endpoint_id: Uuid,
    in_flight: Option<f64>,
    in_flight_mean: Option<f64>,
    learned_limit: Option<f64>,
    waiting: Option<f64>,
    waiting_mean: Option<f64>,
    running: Option<f64>,
    running_mean: Option<f64>,
    kv: Option<f64>,
    kv_mean: Option<f64>,
    queueing_at: Option<f64>,
}

/// The window the recent-load view covers, ending now.
const RECENT_LOAD_WINDOW_SECS: i64 = 15 * 60;

/// Up to when the recent view can be drawn: the oldest LATEST written beat
/// among the gateway replicas CONNECTED now that report this server. A bucket
/// that ends before it holds every one of those replicas' beats; a later one
/// may still be waiting for a beat in a writer's queue, and drawn now would
/// dip to idle. A replica that is gone — replaced in a rollout, stopped —
/// holds nothing back, at once (the same connected test `latest_load` reads);
/// with none reporting, `now`. Not covered: a writer minutes behind, whose
/// replica's latest WRITTEN beat is older than the window, and a new pod whose
/// first beat is still queued — either draws a bucket short of that replica
/// until the next poll.
async fn settled_until(db: &mut TenantConn, server_id: Uuid, now: DateTime<Utc>) -> Result<DateTime<Utc>, ApiError> {
    let live = crate::routes::upstream_endpoints::connected_within_secs();
    let oldest_latest: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MIN(latest) FROM ( \
             SELECT MAX(l.sampled_at) AS latest FROM upstream_load_samples l \
             JOIN edge_instances i ON i.id = l.edge_instance_id \
             WHERE l.tenant_id = $1 AND l.server_id = $2 AND l.sampled_at >= now() - make_interval(secs => $3) \
               AND i.last_seen_at >= now() - make_interval(secs => $3) \
             GROUP BY l.edge_instance_id \
         ) r",
    )
    .bind(db.tenant_uuid())
    .bind(server_id)
    .bind(live as f64)
    .fetch_one(db.conn())
    .await
    .map_err(db_error("recent load settled"))?;
    Ok(oldest_latest.map_or(now, |t| t.min(now)))
}

/// Seconds per bucket of the recent-load view: TWO heartbeats. Each beat
/// carries the peak since the previous one, so nothing finer than a heartbeat
/// can be drawn; and a beat is stamped when admin receives it, so with
/// heartbeat-long buckets latency jitter puts two beats in one bucket and none
/// in the next — an empty bucket that would read as idle. Two heartbeats hold
/// at least one beat of every connected replica.
fn recent_bucket_secs() -> i64 {
    let beat = crate::settings::admin_settings().edge_heartbeat_interval_secs.clamp(1, 300);
    i64::try_from(beat * 2).unwrap_or(60)
}

/// The window the gateway replicas' counts are summed in: a fleet total exists
/// only at a moment, and a window holds one beat of every live replica while
/// it spans two heartbeats. A fixed 60 s — what two of the default 30 s beats
/// span — so stored history is read the same way whatever the setting is now;
/// stretched to two heartbeats only for a longer interval. History written
/// under a longer heartbeat than the window's half under-sums its replicas.
fn fleet_window_secs() -> i64 {
    recent_bucket_secs().max(60)
}

/// The origin every recent-load bucket is aligned to, in SQL and on the axis.
/// The Unix epoch: any bucket length divides the distance to it.
const RECENT_LOAD_ORIGIN: &str = "1970-01-01 00:00:00+00";

/// How load samples are put in buckets: the dashboard period's hour or day,
/// or the recent-load view's few seconds. Every query over the samples takes
/// its bucket from here, so the axis and the rows always agree.
#[derive(Clone, Copy)]
enum LoadGrain {
    /// `"hour"` or `"day"`, from `server_bucket_interval`.
    Period(&'static str),
    /// Buckets of this many seconds ([`recent_bucket_secs`]).
    Recent(i64),
}

impl LoadGrain {
    /// The window the replicas' counts are summed in. On the recent grain its
    /// own bucket — two heartbeats, holding each live replica's beat; a window
    /// of another length would cut a bucket where one replica's beat sits on
    /// one side and another's on the other. On a period grain the fixed
    /// [`fleet_window_secs`], inside each sample's own bucket.
    fn fleet_window_sql(self, col: &'static str) -> String {
        match self {
            Self::Recent(_) => self.bucket_sql(col),
            Self::Period(_) => Self::Recent(fleet_window_secs()).bucket_sql(col),
        }
    }

    /// The SQL bucket of `col`. `date_bin` bins from [`RECENT_LOAD_ORIGIN`],
    /// the same instant [`recent_bucket_axis`] aligns to, so its buckets match
    /// the axis whatever their length.
    fn bucket_sql(self, col: &'static str) -> String {
        match self {
            Self::Period(interval) => format!("date_trunc('{interval}', {col})"),
            // An integer, spliced: safe by type.
            Self::Recent(secs) => format!(
                "date_bin(make_interval(secs => {secs}), {col}, TIMESTAMPTZ '{RECENT_LOAD_ORIGIN}')"
            ),
        }
    }
}

/// The recent-load axis: `secs`-long buckets aligned to the epoch, from the
/// one holding `start` up to the last that has ENDED by `end`. The bucket still
/// filling is left off: until every replica's beat for it lands, it would read
/// as a dip to idle at the right edge.
fn recent_bucket_axis(start: DateTime<Utc>, end: DateTime<Utc>, secs: i64) -> Vec<DateTime<Utc>> {
    let secs = secs.max(1);
    let first = start.timestamp() - start.timestamp().rem_euclid(secs);
    let open = end.timestamp() - end.timestamp().rem_euclid(secs);
    (first..open)
        .step_by(usize::try_from(secs).unwrap_or(1))
        .filter_map(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
        .collect()
}

/// One server's gauges between `start` and `end`, per bucket of `grain` and
/// endpoint: each bucket's peak and its mean (see [`EndpointGaugeSeries`]).
///
/// Gateway counts are per replica, and a fleet total exists only at a moment:
/// summing each replica's peak over a whole bucket would add the peak of a pod
/// that left to that of the pod that replaced it (a rollout renames the
/// instance) as if they had run together — at most one window can still hold
/// both. So the fleet is summed per WINDOW
/// ([`fleet_window_secs`], which holds each live replica's beat), and a
/// bucket's peak is its
/// highest window, its mean the mean of its windows. The engine's gauges
/// describe one engine every replica reads: never summed, highest reading /
/// mean of readings. Held requests are read per class by
/// [`class_held_history`].
async fn load_history(
    db: &mut TenantConn,
    server_id: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    grain: LoadGrain,
    index: &HashMap<DateTime<Utc>, usize>,
) -> Result<LoadHistory, ApiError> {
    use crate::routes::upstream_endpoints::QUEUEING_RUNNING_SQL;
    let tenant_id = db.tenant_uuid();
    let window = grain.fleet_window_sql("l.sampled_at");
    // Each sample's bucket is its OWN: a window that straddles a bucket's
    // boundary is split there, so a beat is never charged to the bucket
    // before the one it happened in (a window length need not divide an hour).
    let bucket = grain.bucket_sql("l.sampled_at");
    // A beat's peak is the highest its replica saw since the previous beat
    // (`*_peak`; an engine gauge's is NULL where the engine does not publish it);
    // a mean is over the beats' instants — evenly spaced, so unbiased. Held
    // requests are read per class by `class_held_history`.
    let sql = format!(
        "WITH per_replica AS ( \
             SELECT {bucket} AS bucket, {window} AS w, l.endpoint_id, l.edge_instance_id, \
                    MAX(l.in_flight_peak) FILTER (WHERE l.gated)::float8 AS in_flight, \
                    AVG(l.in_flight) FILTER (WHERE l.gated)::float8 AS in_flight_mean, \
                    AVG(l.adaptive_limit)::float8 AS learned_limit, \
                    MAX(COALESCE(l.engine_waiting_peak, l.engine_waiting))::float8 AS waiting, \
                    AVG(l.engine_waiting)::float8 AS waiting_mean, \
                    MAX(COALESCE(l.engine_running_peak, l.engine_running))::float8 AS running, \
                    AVG(l.engine_running)::float8 AS running_mean, \
                    MAX(COALESCE(l.engine_kv_usage_peak, l.engine_kv_usage))::float8 AS kv, \
                    AVG(l.engine_kv_usage)::float8 AS kv_mean, \
                    ({QUEUEING_RUNNING_SQL})::float8 AS queueing_at \
             FROM upstream_load_samples l \
             WHERE l.tenant_id = $1 AND l.server_id = $2 AND l.sampled_at >= $3 AND l.sampled_at < $4 \
             GROUP BY 1, 2, 3, 4 \
         ), per_window AS ( \
             SELECT bucket, w, endpoint_id, \
                    SUM(in_flight) AS in_flight, SUM(in_flight_mean) AS in_flight_mean, \
                    SUM(learned_limit) AS learned_limit, \
                    MAX(waiting) AS waiting, AVG(waiting_mean) AS waiting_mean, \
                    MAX(running) AS running, AVG(running_mean) AS running_mean, \
                    MAX(kv) AS kv, AVG(kv_mean) AS kv_mean, MAX(queueing_at) AS queueing_at \
             FROM per_replica GROUP BY 1, 2, 3 \
         ) \
         SELECT bucket, endpoint_id, \
                MAX(in_flight)::float8 AS in_flight, AVG(in_flight_mean)::float8 AS in_flight_mean, \
                AVG(learned_limit)::float8 AS learned_limit, \
                MAX(waiting)::float8 AS waiting, AVG(waiting_mean)::float8 AS waiting_mean, \
                MAX(running)::float8 AS running, AVG(running_mean)::float8 AS running_mean, \
                MAX(kv)::float8 AS kv, AVG(kv_mean)::float8 AS kv_mean, MAX(queueing_at)::float8 AS queueing_at \
         FROM per_window GROUP BY 1, 2"
    );
    let rows = sqlx::query_as::<_, LoadBucket>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(server_id)
        .bind(start)
        .bind(end)
        .fetch_all(db.conn())
        .await
        .map_err(db_error("load history"))?;

    let len = index.len();
    let mut by_endpoint: HashMap<Uuid, EndpointGaugeSeries> = HashMap::new();
    let mut queueing_at: HashMap<Uuid, i64> = HashMap::new();
    for row in rows {
        let Some(&i) = index.get(&row.bucket) else { continue };
        let endpoint_id = row.endpoint_id;
        if let Some(f) = row.queueing_at {
            // A count, carried as float8 by the aggregate; rounding is exact.
            let f = f.round() as i64;
            queueing_at.entry(endpoint_id).and_modify(|v| *v = (*v).max(f)).or_insert(f);
        }
        let s = by_endpoint.entry(endpoint_id).or_insert_with(|| EndpointGaugeSeries::empty(endpoint_id, len));
        s.in_flight[i] = row.in_flight;
        s.in_flight_mean[i] = row.in_flight_mean;
        s.learned_limit[i] = row.learned_limit;
        s.engine_waiting[i] = row.waiting;
        s.engine_waiting_mean[i] = row.waiting_mean;
        s.engine_running[i] = row.running;
        s.engine_running_mean[i] = row.running_mean;
        s.engine_kv_usage[i] = row.kv;
        s.engine_kv_usage_mean[i] = row.kv_mean;
    }
    let mut series: Vec<EndpointGaugeSeries> = by_endpoint.into_values().collect();
    series.sort_by_key(|s| s.endpoint_id);
    Ok(LoadHistory { series, queueing_at })
}

/// What [`load_history`] reads: each endpoint's gauge series, and each
/// endpoint's [`QUEUEING_RUNNING_SQL`](crate::routes::upstream_endpoints::QUEUEING_RUNNING_SQL)
/// over the whole window (absent where it was never seen queueing).
struct LoadHistory {
    series: Vec<EndpointGaugeSeries>,
    queueing_at: HashMap<Uuid, i64>,
}

#[derive(sqlx::FromRow)]
struct EngineBucket {
    bucket: DateTime<Utc>,
    endpoint_id: Uuid,
    prompt_per_s: Option<f64>,
    generation_per_s: Option<f64>,
    preemptions_per_min: Option<f64>,
    prefix_hit_rate: Option<f64>,
    queue_time_ms: Option<f64>,
    ttft_ms: Option<f64>,
    computed_per_s: Option<f64>,
    itl_ms: Option<f64>,
    grew: Option<f64>,
    stepped_down: Option<f64>,
    cut_preemption: Option<f64>,
    cut_kv_full: Option<f64>,
}

/// The engine's own counters over the window, as rates per bucket, written
/// into each endpoint's series.
///
/// Each gateway replica reads the same engine, so each replica's samples are a
/// complete series of their own: consecutive samples of ONE replica are
/// differenced (an interval over which a counter fell is skipped — see `d`),
/// rates are taken over the time those samples cover, and the replicas' rates
/// are then averaged. Summing across replicas would count the engine's
/// work once per gateway. Samples up to ten minutes before the window give the
/// first bucket a predecessor.
async fn engine_history(
    db: &mut TenantConn,
    server_id: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    grain: LoadGrain,
    index: &HashMap<DateTime<Utc>, usize>,
    series: &mut Vec<EndpointLoadSeries>,
) -> Result<(), ApiError> {
    let tenant_id = db.tenant_uuid();
    let bucket = grain.bucket_sql("sampled_at");
    /// One counter's change since the replica's previous sample (`p_<col>`).
    /// A fall is not a delta: the counter is a SUM over the engine's series
    /// (models, data-parallel ranks), so it falls when the engine restarts OR
    /// when one series goes away — and counting the whole remaining total as
    /// that interval's work would draw a spike of every token the engine ever
    /// served. The interval is skipped; the next one differences normally.
    fn d(col: &'static str) -> String {
        format!(
            "CASE WHEN {col} IS NULL OR p_{col} IS NULL OR {col} < p_{col} THEN NULL \
                  ELSE {col} - p_{col} END"
        )
    }
    /// The two halves of a ratio (hits over queries, a histogram's sum over its
    /// count), each differenced like `d` but skipped TOGETHER: an interval kept
    /// for one half and dropped for the other would skew the ratio, even past 1.
    fn d_pair(a: &'static str, b: &'static str) -> (String, String) {
        let skip = format!(
            "{a} IS NULL OR p_{a} IS NULL OR {a} < p_{a} OR {b} IS NULL OR p_{b} IS NULL OR {b} < p_{b}"
        );
        (
            format!("CASE WHEN {skip} THEN NULL ELSE {a} - p_{a} END"),
            format!("CASE WHEN {skip} THEN NULL ELSE {b} - p_{b} END"),
        )
    }
    /// The counter and its predecessor on the same (endpoint, replica).
    fn lagged(col: &'static str) -> String {
        format!("l.{col}, LAG(l.{col}) OVER w AS p_{col}")
    }
    const COUNTERS: [&str; 15] = [
        "engine_prompt_tokens",
        "engine_generation_tokens",
        "engine_preemptions",
        "engine_prefix_queries",
        "engine_prefix_hits",
        "engine_queue_time_sum",
        "engine_queue_time_count",
        "engine_ttft_sum",
        "engine_ttft_count",
        "engine_itl_sum",
        "engine_itl_count",
        "adaptive_grew",
        "adaptive_stepped_down",
        "adaptive_cut_preemption",
        "adaptive_cut_kv_full",
    ];
    let lags = COUNTERS.map(lagged).join(", ");
    // More hits than lookups over an interval is no hit rate — a series of
    // hits that joined mid-life (the CPU tier's, folded in by a newer
    // gateway) jumps by its whole history once — so such an interval is
    // skipped for both halves, as a fall is.
    let prefix = {
        let (q, h) = d_pair("engine_prefix_queries", "engine_prefix_hits");
        let over = format!("({h}) > ({q})");
        (format!("CASE WHEN {over} THEN NULL ELSE {q} END"), format!("CASE WHEN {over} THEN NULL ELSE {h} END"))
    };
    let queue = d_pair("engine_queue_time_sum", "engine_queue_time_count");
    let ttft = d_pair("engine_ttft_sum", "engine_ttft_count");
    let itl = d_pair("engine_itl_sum", "engine_itl_count");
    let sql = format!(
        "WITH ordered AS ( \
             SELECT l.endpoint_id, l.edge_instance_id, l.sampled_at, \
                    LAG(l.sampled_at) OVER w AS p_sampled_at, {lags} \
             FROM upstream_load_samples l \
             WHERE l.tenant_id = $1 AND l.server_id = $2 \
               AND l.sampled_at >= $3 - INTERVAL '10 minutes' AND l.sampled_at < $4 \
             WINDOW w AS (PARTITION BY l.endpoint_id, l.edge_instance_id ORDER BY l.sampled_at) \
         ), deltas AS ( \
             SELECT {bucket} AS bucket, endpoint_id, edge_instance_id, \
                    EXTRACT(EPOCH FROM sampled_at - p_sampled_at)::float8 AS dt, \
                    {pt} AS d_pt, {gt} AS d_gt, {pre} AS d_pre, {pq} AS d_pq, {ph} AS d_ph, \
                    {qs} AS d_qs, {qc} AS d_qc, {ts} AS d_ts, {tc} AS d_tc, \
                    {is_} AS d_is, {ic} AS d_ic, {ag} AS d_ag, {asd} AS d_asd, {acp} AS d_acp, {ack} AS d_ack \
             FROM ordered \
             WHERE p_sampled_at IS NOT NULL AND sampled_at >= $3 \
               AND sampled_at - p_sampled_at <= make_interval(secs => $5) \
         ), per_replica AS ( \
             SELECT bucket, endpoint_id, edge_instance_id, \
                    SUM(d_pt) / NULLIF(SUM(dt) FILTER (WHERE d_pt IS NOT NULL), 0) AS prompt_per_s, \
                    SUM(d_gt) / NULLIF(SUM(dt) FILTER (WHERE d_gt IS NOT NULL), 0) AS generation_per_s, \
                    SUM(d_pre) * 60 / NULLIF(SUM(dt) FILTER (WHERE d_pre IS NOT NULL), 0) AS preemptions_per_min, \
                    SUM(d_ph) / NULLIF(SUM(d_pq), 0) AS prefix_hit_rate, \
                    SUM(d_qs) * 1000 / NULLIF(SUM(d_qc), 0) AS queue_time_ms, \
                    SUM(d_ts) * 1000 / NULLIF(SUM(d_tc), 0) AS ttft_ms, \
                    (SUM(d_pq) - SUM(d_ph)) / NULLIF(SUM(dt) FILTER (WHERE d_pq IS NOT NULL), 0) \
                        AS computed_per_s, \
                    SUM(d_is) * 1000 / NULLIF(SUM(d_ic), 0) AS itl_ms, \
                    SUM(d_ag) AS grew, SUM(d_asd) AS stepped_down, SUM(d_acp) AS cut_preemption, SUM(d_ack) AS cut_kv_full \
             FROM deltas GROUP BY 1, 2, 3 \
         ) \
         SELECT bucket, endpoint_id, AVG(prompt_per_s)::float8 AS prompt_per_s, \
                AVG(generation_per_s)::float8 AS generation_per_s, \
                AVG(preemptions_per_min)::float8 AS preemptions_per_min, \
                AVG(prefix_hit_rate)::float8 AS prefix_hit_rate, \
                AVG(queue_time_ms)::float8 AS queue_time_ms, AVG(ttft_ms)::float8 AS ttft_ms, \
                AVG(computed_per_s)::float8 AS computed_per_s, AVG(itl_ms)::float8 AS itl_ms, \
                SUM(grew)::float8 AS grew, SUM(stepped_down)::float8 AS stepped_down, SUM(cut_preemption)::float8 AS cut_preemption, \
                SUM(cut_kv_full)::float8 AS cut_kv_full \
         FROM per_replica GROUP BY 1, 2",
        pt = d("engine_prompt_tokens"),
        gt = d("engine_generation_tokens"),
        pre = d("engine_preemptions"),
        pq = prefix.0,
        ph = prefix.1,
        qs = queue.0,
        qc = queue.1,
        ts = ttft.0,
        tc = ttft.1,
        is_ = itl.0,
        ic = itl.1,
        ag = d("adaptive_grew"),
        asd = d("adaptive_stepped_down"),
        acp = d("adaptive_cut_preemption"),
        ack = d("adaptive_cut_kv_full"),
    );
    // A predecessor further back than the connected-gateway window is not the
    // previous beat: the engine went unread (switched off, a replica gone), and
    // its work over that gap cannot be placed in any one bucket.
    let max_gap = crate::routes::upstream_endpoints::connected_within_secs() as f64;
    let rows = sqlx::query_as::<_, EngineBucket>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(server_id)
        .bind(start)
        .bind(end)
        .bind(max_gap)
        .fetch_all(db.conn())
        .await
        .map_err(db_error("engine history"))?;
    let len = index.len();
    for row in rows {
        let Some(&i) = index.get(&row.bucket) else { continue };
        let s = match series.iter_mut().position(|s| s.gauges.endpoint_id == row.endpoint_id) {
            Some(at) => &mut series[at],
            None => {
                series.push(EndpointLoadSeries::from_gauges(EndpointGaugeSeries::empty(row.endpoint_id, len), len));
                series.last_mut().expect("just pushed")
            }
        };
        s.engine_prompt_tokens_per_s[i] = row.prompt_per_s;
        s.engine_generation_tokens_per_s[i] = row.generation_per_s;
        s.engine_preemptions_per_min[i] = row.preemptions_per_min;
        s.engine_prefix_hit_rate[i] = row.prefix_hit_rate;
        s.engine_queue_time_ms[i] = row.queue_time_ms;
        s.engine_ttft_ms[i] = row.ttft_ms;
        s.engine_computed_prompt_tokens_per_s[i] = row.computed_per_s;
        s.engine_itl_ms[i] = row.itl_ms;
        s.adaptive_grew[i] = row.grew;
        s.adaptive_stepped_down[i] = row.stepped_down;
        s.adaptive_cut_preemption[i] = row.cut_preemption;
        s.adaptive_cut_kv_full[i] = row.cut_kv_full;
    }
    series.sort_by_key(|s| s.gauges.endpoint_id);
    Ok(())
}

#[derive(sqlx::FromRow)]
struct ClassHeldBucket {
    bucket: DateTime<Utc>,
    class_id: Option<Uuid>,
    held: Option<f64>,
    held_mean: Option<f64>,
}

/// Requests held per class over the window. `server_held_by_class` is repeated
/// on every endpoint row of one beat (one insert, one `sampled_at`), so each
/// beat is read once — a hash group with `any_value`, not a sort. A class a
/// beat does not list held nothing then, so
/// a replica's mean divides by ALL its beats in the window, not only those
/// naming the class, and a bucket's mean by all its windows; a peak is the
/// highest any one beat saw since the previous (`held_peak`).
async fn class_held_history(
    db: &mut TenantConn,
    server_id: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    grain: LoadGrain,
    index: &HashMap<DateTime<Utc>, usize>,
) -> Result<Vec<ClassHeldSeries>, ApiError> {
    let window = grain.fleet_window_sql("l.sampled_at");
    // Each beat's bucket is its own, as in `load_history`.
    let bucket = grain.bucket_sql("l.sampled_at");
    // Per window of two heartbeats, as in `load_history`: a replica's peak and
    // mean over its beats in the window, summed across replicas; a bucket's
    // peak is its highest window, its mean the mean of its windows.
    let sql = format!(
        "WITH beats AS ( \
             SELECT {bucket} AS bucket, {window} AS w, l.edge_instance_id, l.beat_id, \
                    any_value(l.server_held_by_class) AS server_held_by_class \
             FROM upstream_load_samples l \
             WHERE l.tenant_id = $1 AND l.server_id = $2 AND l.sampled_at >= $3 AND l.sampled_at < $4 \
             GROUP BY 1, 2, 3, 4 \
         ), per_replica_beats AS ( \
             SELECT bucket, w, edge_instance_id, count(*)::float8 AS beats FROM beats GROUP BY 1, 2, 3 \
         ), per_beat_class AS ( \
             SELECT b.bucket, b.w, b.edge_instance_id, b.beat_id, NULLIF(c->>'class_id', '')::uuid AS class_id, \
                    SUM((c->>'held')::float8) AS held, SUM((c->>'held_peak')::float8) AS peak \
             FROM beats b, jsonb_array_elements(b.server_held_by_class) c \
             GROUP BY 1, 2, 3, 4, 5 \
         ), per_replica_class AS ( \
             SELECT bucket, w, edge_instance_id, class_id, MAX(peak) AS peak, SUM(held) AS held \
             FROM per_beat_class GROUP BY 1, 2, 3, 4 \
         ), per_window AS ( \
             SELECT c.bucket, c.w, c.class_id, SUM(c.peak) AS peak, SUM(c.held / r.beats) AS held \
             FROM per_replica_class c \
             JOIN per_replica_beats r \
               ON r.bucket = c.bucket AND r.w = c.w AND r.edge_instance_id = c.edge_instance_id \
             GROUP BY 1, 2, 3 \
         ), windows AS ( \
             SELECT bucket, count(DISTINCT w)::float8 AS n FROM per_replica_beats GROUP BY 1 \
         ) \
         SELECT p.bucket, p.class_id, MAX(p.peak)::float8 AS held, \
                (SUM(p.held) / MAX(n.n))::float8 AS held_mean \
         FROM per_window p JOIN windows n ON n.bucket = p.bucket \
         GROUP BY 1, 2"
    );
    let rows = sqlx::query_as::<_, ClassHeldBucket>(sqlx::AssertSqlSafe(&*sql))
        .bind(db.tenant_uuid())
        .bind(server_id)
        .bind(start)
        .bind(end)
        .fetch_all(db.conn())
        .await
        .map_err(db_error("class held history"))?;
    let len = index.len();
    let mut by_class: HashMap<Option<Uuid>, ClassHeldSeries> = HashMap::new();
    for row in rows {
        let Some(&i) = index.get(&row.bucket) else { continue };
        let s = by_class.entry(row.class_id).or_insert_with(|| ClassHeldSeries {
            qos_class_id: row.class_id,
            held: vec![None; len],
            held_mean: vec![None; len],
        });
        s.held[i] = row.held;
        s.held_mean[i] = row.held_mean;
    }
    let mut out: Vec<ClassHeldSeries> = by_class.into_values().collect();
    out.sort_by_key(|s| s.qos_class_id);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_page_is_hourly_up_to_eight_days_and_daily_beyond() {
        let end = DateTime::<Utc>::from_timestamp(1_800_000_000, 0).expect("ts");
        let hours = |h: i64| end - chrono::Duration::hours(h);
        assert_eq!(server_bucket_interval(hours(24), end), "hour");
        assert_eq!(server_bucket_interval(hours(8 * 24), end), "hour", "the boundary is hourly");
        assert_eq!(server_bucket_interval(hours(8 * 24 + 1), end), "day");
        assert_eq!(server_bucket_interval(hours(30 * 24), end), "day");
    }

    #[test]
    fn the_recent_axis_is_epoch_aligned_and_covers_the_window() {
        // `date_bin` buckets from `RECENT_LOAD_ORIGIN`; the axis must start each
        // bucket on the same instants, or every row misses its index. Lengths
        // that do not divide a later origin (7, 11, 600) included.
        let origin = DateTime::parse_from_rfc3339(&RECENT_LOAD_ORIGIN.replace(' ', "T").replace("+00", "+00:00"))
            .expect("origin");
        for secs in [1, 2, 5, 7, 10, 11, 60, 600] {
            assert_eq!(origin.timestamp() % secs, 0, "the SQL origin is on every grid");
            for offset in [0, 1, secs - 1, secs, secs + 1] {
                let end = DateTime::<Utc>::from_timestamp(1_800_000_000 + offset, 0).expect("ts");
                let start = end - chrono::Duration::seconds(RECENT_LOAD_WINDOW_SECS);
                let axis = recent_bucket_axis(start, end, secs);
                assert!(axis.iter().all(|t| t.timestamp() % secs == 0), "{secs}s, offset {offset}");
                let first = axis.first().expect("non-empty");
                assert!(*first <= start && start - *first < chrono::Duration::seconds(secs));
                // Every bucket has ended; the one holding `end` is not drawn.
                let last = axis.last().expect("non-empty");
                assert!(*last + chrono::Duration::seconds(secs) <= end, "{secs}s, offset {offset}: open bucket drawn");
                assert!(end - (*last + chrono::Duration::seconds(secs)) < chrono::Duration::seconds(secs));
                let buckets = (RECENT_LOAD_WINDOW_SECS / secs) as usize;
                assert!(axis.len().abs_diff(buckets) <= 1, "{secs}s, offset {offset}: {}", axis.len());
            }
        }
    }

    fn row(server: u128, endpoint: u128, replica: u128, secs: i64) -> LoadRow {
        LoadRow {
            server_id: Uuid::from_u128(server),
            endpoint_id: Uuid::from_u128(endpoint),
            edge_instance_id: Uuid::from_u128(replica),
            sampled_at: DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).expect("ts"),
            in_flight: 0,
            server_held: 0,
            engine_read: false,
            engine_waiting: None,
            engine_running: None,
            engine_kv_usage: None,
            engine_age_ms: None,
            max_in_flight: Some(1),
            waiting_threshold: None,
            gated: true,
            server_held_by_class: sqlx::types::Json(Vec::new()),
            adaptive_limit: None,
            adaptive_state: None,
            adaptive_low_load_itl_us: None,
        }
    }

    fn reading(waiting: i32, age_ms: i32, base: LoadRow) -> LoadRow {
        LoadRow {
            engine_read: true,
            engine_waiting: Some(waiting),
            engine_running: Some(1),
            engine_kv_usage: Some(0.5),
            engine_age_ms: Some(age_ms),
            ..base
        }
    }

    #[test]
    fn the_reading_taken_last_stands_whatever_heartbeat_carried_it() {
        // Replica 10's beat at t=9 carries a reading taken 8 s earlier (t=1);
        // replica 11's beat at t=5 carries one taken at t=5. The engine said 2
        // most recently, whichever beat left later.
        let rows = vec![reading(30, 8000, row(1, 100, 10, 9)), reading(2, 0, row(1, 100, 11, 5))];
        let (_, endpoints) = summarize_live(&rows);
        assert_eq!(endpoints[&Uuid::from_u128(100)].engine.clone().expect("read").waiting, 2);
    }

    #[test]
    fn a_replica_that_stopped_hearing_the_engine_is_silent_while_another_still_reads_it() {
        // The silent report is the newest beat, and the other replica's
        // reading is still shown: both facts stand, neither hides the other.
        let rows = vec![
            LoadRow { engine_read: true, waiting_threshold: Some(0), ..row(1, 100, 10, 9) },
            LoadRow { waiting_threshold: Some(0), ..reading(1, 0, row(1, 100, 11, 5)) },
        ];
        let (servers, endpoints) = summarize_live(&rows);
        let e = &endpoints[&Uuid::from_u128(100)];
        assert!(e.engine.is_some(), "the replica that reads it still shows its gauges");
        assert_eq!(e.engine_silent_replicas, 1);
        assert_eq!(servers[&Uuid::from_u128(1)].engines_silent, 1);
    }

    #[test]
    fn held_is_counted_once_per_replica_and_summed_across_replicas() {
        // Replica 10 holds 3 for server 1 and says so on both of its endpoint
        // rows; replica 11 holds 2.
        let rows = vec![
            LoadRow { server_held: 3, ..row(1, 100, 10, 0) },
            LoadRow { server_held: 3, ..row(1, 101, 10, 0) },
            LoadRow { server_held: 2, ..row(1, 100, 11, 0) },
            LoadRow { server_held: 2, ..row(1, 101, 11, 0) },
        ];
        let (servers, _) = summarize_live(&rows);
        let s = &servers[&Uuid::from_u128(1)];
        assert_eq!(s.held, 5);
        assert_eq!(s.replicas, 2);
    }

    #[test]
    fn held_per_class_is_counted_once_per_replica_and_summed_across_replicas() {
        use streamscope_core::proxy::qos_metrics::ClassHeld;
        let (interactive, background) = (Some(Uuid::from_u128(7)), Some(Uuid::from_u128(8)));
        let classes = |i: u32, b: u32| {
            sqlx::types::Json(vec![
                ClassHeld { class_id: interactive, held: i, held_peak: i },
                ClassHeld { class_id: background, held: b, held_peak: b },
            ])
        };
        // Each replica repeats its per-class counts on both endpoint rows.
        let rows = vec![
            LoadRow { server_held: 3, server_held_by_class: classes(1, 2), ..row(1, 100, 10, 0) },
            LoadRow { server_held: 3, server_held_by_class: classes(1, 2), ..row(1, 101, 10, 0) },
            LoadRow { server_held: 4, server_held_by_class: classes(0, 4), ..row(1, 100, 11, 0) },
            LoadRow { server_held: 4, server_held_by_class: classes(0, 4), ..row(1, 101, 11, 0) },
        ];
        let (servers, _) = summarize_live(&rows);
        let s = &servers[&Uuid::from_u128(1)];
        assert_eq!(s.held, 7);
        assert_eq!(
            s.held_by_class,
            vec![
                ClassHeldLive { qos_class_id: background, held: 6 },
                ClassHeldLive { qos_class_id: interactive, held: 1 },
            ],
            "most held first; a class held by one replica only still counts"
        );
    }

    #[test]
    fn in_flight_and_capacity_sum_across_replicas_and_endpoints() {
        let rows = vec![
            LoadRow { in_flight: 1, ..row(1, 100, 10, 0) },
            LoadRow { in_flight: 1, ..row(1, 100, 11, 0) },
            LoadRow { in_flight: 0, ..row(1, 101, 10, 0) },
        ];
        let (servers, endpoints) = summarize_live(&rows);
        assert_eq!(servers[&Uuid::from_u128(1)].in_flight, 2);
        assert_eq!(servers[&Uuid::from_u128(1)].capacity, Some(3));
        let e = &endpoints[&Uuid::from_u128(100)];
        assert_eq!((e.in_flight, e.capacity, e.replicas), (2, Some(2), 2));
    }

    #[test]
    fn one_unbounded_reading_leaves_the_capacity_unstated() {
        let rows = vec![row(1, 100, 10, 0), LoadRow { max_in_flight: None, ..row(1, 101, 10, 0) }];
        let (servers, endpoints) = summarize_live(&rows);
        assert_eq!(servers[&Uuid::from_u128(1)].capacity, None);
        // The bounded endpoint keeps its own.
        assert_eq!(endpoints[&Uuid::from_u128(100)].capacity, Some(1));
        assert_eq!(endpoints[&Uuid::from_u128(101)].capacity, None);
    }

    #[test]
    fn the_engine_is_the_freshest_reading_never_a_sum() {
        let read = |secs, waiting| LoadRow {
            engine_read: true,
            engine_waiting: Some(waiting),
            engine_running: Some(4),
            engine_kv_usage: Some(0.5),
            ..row(1, 100, 10 + secs as u128, secs)
        };
        let (_, endpoints) = summarize_live(&[read(5, 7), read(9, 2), read(1, 30)]);
        let engine = endpoints[&Uuid::from_u128(100)].engine.clone().expect("read");
        assert_eq!((engine.waiting, engine.running), (2, Some(4)));
    }

    #[test]
    fn a_read_engine_with_no_gauges_is_silent_and_an_unread_one_is_not() {
        let rows = vec![
            LoadRow { engine_read: true, waiting_threshold: Some(0), ..row(1, 100, 10, 0) },
            LoadRow { engine_read: false, ..row(1, 101, 10, 0) },
            LoadRow {
                engine_read: true,
                waiting_threshold: Some(0),
                engine_waiting: Some(0),
                engine_running: Some(0),
                engine_kv_usage: Some(0.0),
                ..row(1, 102, 10, 0)
            },
        ];
        let (servers, endpoints) = summarize_live(&rows);
        // Silence is counted only where the engine is read at all.
        assert_eq!(endpoints[&Uuid::from_u128(100)].engine_silent_replicas, 1);
        assert_eq!(endpoints[&Uuid::from_u128(101)].engine_silent_replicas, 0);
        let s = &servers[&Uuid::from_u128(1)];
        assert_eq!(s.engines_silent, 1);
    }

    #[test]
    fn an_endpoint_the_gateway_does_not_count_contributes_no_in_flight() {
        // An endpoint read only for its engine metrics takes the ungated fast
        // path: its reported 0 is not a count.
        let rows = vec![
            LoadRow { in_flight: 3, gated: true, ..row(1, 100, 10, 0) },
            LoadRow { in_flight: 0, gated: false, max_in_flight: None, ..row(1, 101, 10, 0) },
            LoadRow { in_flight: 2, gated: true, ..row(1, 100, 11, 0) },
        ];
        let (servers, endpoints) = summarize_live(&rows);
        assert!(!endpoints[&Uuid::from_u128(101)].gated);
        assert!(endpoints[&Uuid::from_u128(100)].gated);
        let s = &servers[&Uuid::from_u128(1)];
        assert!(s.gated);
        assert_eq!(s.in_flight, 5);
        // The uncounted endpoint's missing bound does not erase the capacity
        // of the ones that are counted.
        assert_eq!(s.capacity, Some(2));
        let (servers, _) = summarize_live(&[LoadRow { gated: false, max_in_flight: None, ..row(2, 200, 10, 0) }]);
        let ungated = &servers[&Uuid::from_u128(2)];
        assert!(!ungated.gated, "a server read only for its metrics is not gated");
        assert_eq!((ungated.in_flight, ungated.capacity), (0, None), "and states no slots");
    }

    #[test]
    fn an_engine_read_only_for_its_charts_is_not_counted_silent_for_the_server() {
        // The same silence on two engines: one with a queue bound, which is
        // then not applied, and one read only for the dashboards, whose charts
        // simply have a gap. Only the first is the server's problem.
        let rows = vec![
            LoadRow { engine_read: true, waiting_threshold: Some(2), ..row(1, 100, 10, 0) },
            LoadRow { engine_read: true, waiting_threshold: None, ..row(1, 101, 10, 0) },
        ];
        let (servers, endpoints) = summarize_live(&rows);
        let (bounded, charts) = (&endpoints[&Uuid::from_u128(100)], &endpoints[&Uuid::from_u128(101)]);
        assert!(bounded.queue_bounded && !charts.queue_bounded);
        // Both are unheard, and each endpoint says so.
        assert_eq!((bounded.engine_silent_replicas, charts.engine_silent_replicas), (1, 1));
        let s = &servers[&Uuid::from_u128(1)];
        assert_eq!(s.engines_silent, 1);
    }

    #[test]
    fn a_learned_limit_is_the_capacity_and_the_most_pressing_state_stands() {
        let adaptive = |replica, limit: Option<i32>, state: &str, itl_us: Option<i32>| LoadRow {
            adaptive_limit: limit,
            adaptive_state: Some(state.to_string()),
            adaptive_low_load_itl_us: itl_us,
            max_in_flight: Some(100),
            ..reading(0, 0, row(1, 100, replica, 0))
        };
        let (servers, endpoints) = summarize_live(&[
            adaptive(10, Some(12), "probing", None),
            adaptive(11, Some(8), "engine_queueing", Some(21_000)),
        ]);
        let live = endpoints[&Uuid::from_u128(100)].adaptive.clone().expect("learned");
        assert_eq!(live.limit, Some(20), "the windows, not the ceilings");
        assert_eq!(live.state, AdaptiveState::EngineQueueing);
        assert_eq!(live.low_load_itl_ms, Some(21.0), "the one replica that learned it");
        assert_eq!(servers[&Uuid::from_u128(1)].capacity, Some(20));

        // One replica that applies no limit leaves the total unstated.
        let (_, endpoints) = summarize_live(&[
            adaptive(10, Some(12), "probing", None),
            LoadRow { engine_waiting: None, ..adaptive(11, None, "no_reading", None) },
        ]);
        let live = endpoints[&Uuid::from_u128(100)].adaptive.clone().expect("learned");
        assert_eq!((live.limit, live.state), (None, AdaptiveState::NoReading));
        assert_eq!(endpoints[&Uuid::from_u128(100)].capacity, None);
    }

    #[test]
    fn the_automatic_target_is_three_times_each_engines_slowest_low_load_figure() {
        let learned = |server, endpoint, replica, itl_us: Option<i32>| LoadRow {
            adaptive_limit: Some(8),
            adaptive_state: Some("probing".to_string()),
            adaptive_low_load_itl_us: itl_us,
            ..row(server, endpoint, replica, 0)
        };
        let (servers, endpoints) = summarize_live(&[
            // One engine, two replicas: the slower figure stands for it, in
            // either order.
            learned(1, 100, 10, Some(18_000)),
            learned(1, 100, 11, Some(20_000)),
            learned(1, 101, 11, Some(25_400)),
            learned(1, 101, 10, Some(25_000)),
            // An engine still learning has no target.
            learned(1, 102, 10, None),
            // Nor one any of whose replicas is still learning — slower than
            // every other engine here, so the server's figure shows it left out.
            learned(1, 103, 10, Some(30_000)),
            learned(1, 103, 11, None),
            // A server whose engines taught nothing has none.
            learned(2, 200, 10, None),
        ]);
        let auto = |e: u128| endpoints[&Uuid::from_u128(e)].adaptive.as_ref().and_then(|a| a.auto_itl_target_ms);
        assert_eq!(auto(100), Some(60.0), "3 × 20 ms, its own slowest replica");
        assert_eq!(auto(101), Some(76.2), "3 × 25.4 ms, to a tenth of a millisecond");
        assert_eq!(auto(102), None, "learning");
        assert_eq!(auto(103), None, "one replica learned, the other still learning: no target");
        assert_eq!(
            endpoints[&Uuid::from_u128(103)].adaptive.as_ref().and_then(|a| a.low_load_itl_ms),
            Some(30.0),
            "the figure a replica learned is still shown"
        );
        // The server's is its slowest engine's that has one: not 103's 90 ms.
        assert_eq!(servers[&Uuid::from_u128(1)].auto_itl_target_ms, Some(76.2));
        assert_eq!(servers[&Uuid::from_u128(2)].auto_itl_target_ms, None);
    }

    #[test]
    fn an_unheard_engine_with_a_learned_limit_degrades_its_server() {
        let (servers, _) = summarize_live(&[LoadRow {
            engine_read: true,
            adaptive_state: Some("no_reading".to_string()),
            ..row(1, 100, 10, 0)
        }]);
        assert_eq!(servers[&Uuid::from_u128(1)].engines_silent, 1);
    }

    #[test]
    fn servers_are_kept_apart() {
        let rows = vec![
            LoadRow { in_flight: 4, server_held: 1, ..row(1, 100, 10, 0) },
            LoadRow { in_flight: 6, server_held: 9, ..row(2, 200, 10, 0) },
        ];
        let (servers, _) = summarize_live(&rows);
        assert_eq!((servers[&Uuid::from_u128(1)].in_flight, servers[&Uuid::from_u128(1)].held), (4, 1));
        assert_eq!((servers[&Uuid::from_u128(2)].in_flight, servers[&Uuid::from_u128(2)].held), (6, 9));
    }
}
