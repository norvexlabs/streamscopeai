//! The dispatch gate — who gets the next free slot on a saturated model.
//!
//! An engine schedules what it has been handed; it cannot know that one user
//! sent a thousand requests and another sent two. So the gateway holds a request
//! back while every endpoint that could serve it is busy, and releases held
//! requests in an order it decides: the most important class first, and within a
//! class the user who has consumed the least, weighted by their workspace's
//! share. That is weighted max-min fairness, engaged only under saturation — an
//! unsaturated pool never queues anything and costs one atomic read. A request
//! goes to the engine its session prefers: a turn sent elsewhere re-reads its
//! whole history into a cold cache, and the allocation evicts what that
//! engine's own paused sessions had cached. So a request whose engine is full
//! waits for it for a short grace ([`AFFINITY_GRACE`]) even while another
//! engine has room — held, or arriving — and within a class the request whose
//! engine just freed goes first. Never ahead of a more important class: what
//! a more important request turned down for its own engine, nobody behind it
//! takes.
//!
//! Two independent facts say an endpoint is busy: the gateway's own count of
//! requests in flight there, and the engine's own waiting queue, read from its
//! metrics. The second is shared truth across gateway replicas, which is what
//! keeps N replicas from each filling the same engine. A metrics read that fails
//! is NOT read as "busy" — that would stall a healthy pool — it simply leaves
//! the in-flight count as the only bound.
//!
//! Every counter here is LOCAL to this process. A dispatch decision is local by
//! nature: it orders the requests this replica is holding right now, and merging
//! that across the fleet would both lag and multiply the idle-return lift. Spend
//! and quota stay on the fleet-convergent counters, which is where they belong.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use uuid::Uuid;

use super::adaptive_concurrency::{AdaptiveDecisions, AdaptiveState, AdaptiveWindow, ItlTarget, Observation};

/// What the gate was asked for, and what it decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// Dispatched with no wait — the common case.
    Immediate,
    /// Held until an endpoint freed up.
    Held,
}

/// Why a request will not be dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// The class is sheddable and the pool is saturated: refused at once rather
    /// than held.
    Shed,
    /// Held until its deadline without a slot coming free.
    Timeout,
    /// The gateway is holding as many requests as it may.
    Overloaded,
    /// The process is shutting down and will not start new upstream work.
    ShuttingDown,
    /// The same request arrived again while this copy waited: its client gave
    /// up on it and sent it again, and the re-send waits in its place
    /// ([`GateRequest::resend_key`]).
    Superseded,
}

impl GateRefusal {
    /// The word an audit row and an operator see.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shed => "shed",
            Self::Timeout => "queue_timeout",
            Self::Overloaded => "gateway_saturated",
            Self::ShuttingDown => "shutting_down",
            Self::Superseded => "superseded",
        }
    }
}

/// What a caller must tell the gate about the request.
#[derive(Debug, Clone)]
pub struct GateRequest {
    /// The endpoints that could serve this request, in the order routing chose.
    pub endpoints: Vec<GateEndpoint>,
    /// The replica routing put first for this request's session — where its
    /// cache is — named by id, so no reordering of `endpoints` can change
    /// which one it is. `None` once that one has failed the request (it is
    /// gone from `endpoints`), and ignored when it is not one the gate bounds:
    /// the request then has no engine of its own to wait for.
    pub preferred: Option<Uuid>,
    /// The class's rank; `None` when the tenant has no classes.
    pub rank: Option<i32>,
    /// The class itself, so what is held can be reported per class. Decides
    /// nothing: the order is the rank's.
    pub class_id: Option<Uuid>,
    /// A sheddable class is refused instead of held.
    pub sheddable: bool,
    /// The fairness identity: one user inside one workspace.
    pub scope: (Uuid, Uuid),
    /// The workspace's share of the pool (≥ 1).
    pub weight: u32,
    /// Input tokens, charged at admission so a long prompt does not dispatch
    /// free.
    pub input_tokens: u32,
    /// What an output token costs relative to an input token for this model.
    pub output_weight: f64,
    /// How long this request may be held.
    pub ttl: Duration,
    /// What makes another request the same one sent again
    /// ([`super::content::request_key`]). A request with the same key waiting
    /// in this request's own pool for at least
    /// [`GateSettings::resend_min_age`] is a copy its client gave up on: the
    /// arrival takes its place in the queue and the copy is refused
    /// [`GateRefusal::Superseded`]. A copy already dispatched, or waiting for
    /// another pool, is never touched. Per process: a re-send reaching another
    /// replica finds nothing to replace. `None` replaces nothing.
    pub resend_key: Option<[u8; 32]>,
}

/// One endpoint a request may be dispatched to, with the capacity it declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateEndpoint {
    pub id: Uuid,
    /// How many requests the gateway may have in flight here.
    pub max_in_flight: Option<u32>,
    /// How long the engine's own queue may grow before we stop releasing.
    pub waiting_threshold: Option<u32>,
    /// Whether the in-flight limit is LEARNED from the engine's readings
    /// ([`super::adaptive_concurrency`]). `max_in_flight` is then its ceiling.
    pub adaptive: bool,
}

impl GateEndpoint {
    /// An endpoint that declares no bound, fixed or learned, is not gated.
    fn gated(&self) -> bool {
        self.max_in_flight.is_some() || self.waiting_threshold.is_some() || self.adaptive
    }
}

/// What one endpoint's engine last reported about itself.
///
/// A dispatch decision reads the queue length directly, against the
/// endpoint's queue bound. Everything here also steers a learned in-flight
/// limit, one control step per reading ([`AdaptiveWindow::observe`]), and rides
/// the live load report ([`DispatchGate::snapshot`]), which drops a reading
/// once it is too old to act on — so none of it can stand as a stale figure.
#[derive(Debug, Clone, Copy)]
pub struct EndpointLoad {
    pub waiting: u32,
    /// Requests the engine is running now, when it publishes that gauge.
    pub running: Option<u32>,
    /// The engine's KV-cache use, a fraction in `[0, 1]`, when published.
    pub kv_usage: Option<f64>,
    pub read_at: Instant,
    /// The engine's own cumulative counters: preemptions, first tokens,
    /// inter-token latency and the finished requests' prompt and answer tokens
    /// steer a learned limit; all of them, prefix-cache hits included, reach
    /// the live load report.
    pub counters: super::qos_metrics::EngineCounters,
    /// The endpoint's cumulative dispatch count when this reading was taken.
    /// What the gate has sent since is `dispatched - mark`, capped by what is
    /// still in flight: a request that has finished is in neither the engine's
    /// queue nor this estimate, and a reading taken while a poll was still
    /// collecting must not forget the dispatches that happened in between.
    pub mark: u64,
    /// Data-parallel ranks the engine reported (≥ 1), for the batch-cap advice.
    pub ranks: u32,
}

/// Cumulative counters and live gauges, in the shape every other subsystem here
/// reports: counters only ever rise, gauges are read as they are.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateStats {
    pub held_total: u64,
    pub shed_total: u64,
    pub timeout_total: u64,
    pub overloaded_total: u64,
    pub superseded_total: u64,
    pub queue_depth: u64,
    pub in_flight: u64,
}

/// What the gate holds right now, for the live load report. Gauges, read as
/// they are — except each learned window's decisions, which are its own
/// cumulative counts.
#[derive(Debug, Clone, Default)]
pub struct GateSnapshot {
    /// Requests in flight at each endpoint the gate has dispatched to.
    pub in_flight: HashMap<Uuid, u32>,
    /// Each endpoint's engine reading that the gate is still applying, with its
    /// age. A reading too old to act on is absent, exactly as the dispatch
    /// decision treats it.
    pub engine: HashMap<Uuid, (EndpointLoad, Duration)>,
    /// How many requests are held, per set of endpoints that could serve them
    /// and per class (`None`: a tenant with no classes). Every endpoint of one
    /// set belongs to one server: a set is the replicas of one route target.
    pub held: Vec<HeldCount>,
    /// Each endpoint whose in-flight limit is learned, and where it stands.
    pub adaptive: HashMap<Uuid, AdaptiveStatus>,
    /// The highest each gauge reached since the previous report: filled only by
    /// [`DispatchGate::report_snapshot`], which also starts the next interval.
    pub peaks: GatePeaks,
}

/// The highest value each gauge reached over one reporting interval. A report
/// reads instants once per heartbeat; the gate counts on every dispatch and
/// hears the engine every few seconds, so these keep what happened in between.
/// Each is at least the instant the same snapshot reports.
#[derive(Debug, Clone, Default)]
pub struct GatePeaks {
    pub in_flight: HashMap<Uuid, u32>,
    /// Requests held, per pool (the sorted endpoint set) and in total.
    pub held_pool: HashMap<Vec<Uuid>, u32>,
    /// The same per pool and class.
    pub held_class: HashMap<(Vec<Uuid>, Option<Uuid>), u32>,
    /// The engine's highest gauges over the readings taken in the interval.
    pub engine: HashMap<Uuid, EnginePeak>,
}

/// One engine's highest readings over an interval; a gauge it does not publish
/// stays `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EnginePeak {
    pub waiting: u32,
    pub running: Option<u32>,
    pub kv_usage: Option<f64>,
    /// The most running in any ONE reading that also had a queue: what the
    /// engine sustained while it kept requests waiting — not a capacity, since
    /// an engine queues on its per-step token budget as well as on its memory
    /// or batch cap. Not `running` filtered by `waiting` afterwards — the two
    /// peaks may come from different readings.
    pub running_queued: Option<u32>,
}

impl EnginePeak {
    fn fold(&mut self, load: &EndpointLoad) {
        self.waiting = self.waiting.max(load.waiting);
        self.running = max_opt(self.running, load.running);
        self.kv_usage = max_opt(self.kv_usage, load.kv_usage);
        if load.waiting > 0 {
            self.running_queued = max_opt(self.running_queued, load.running);
        }
    }
}

/// A time between tokens in whole microseconds: what the heartbeat carries.
fn itl_micros(seconds: f64) -> u32 {
    // `as` saturates: a figure beyond u32 microseconds (over an hour a token)
    // is reported as the most it can say, never wrapped.
    (seconds * 1e6).round() as u32
}

/// The larger of two optional readings; one that is absent defers to the other.
pub fn max_opt<T: PartialOrd + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b > a { b } else { a }),
        (a, b) => a.or(b),
    }
}

/// Where one endpoint's learned in-flight limit stands. Also what a replica
/// reports on its heartbeat (`EndpointLoadReport::adaptive`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdaptiveStatus {
    /// The limit applied now: the window while its engine reading is fresh,
    /// else [`AdaptiveWindow::unheard_limit`] (`None`: nothing is bounded).
    pub limit: Option<u32>,
    pub state: AdaptiveState,
    /// The engine's time between tokens at low load, in microseconds
    /// ([`AdaptiveWindow::low_load_itl`]); what an automatic token-latency
    /// target is a multiple of. `None` until learned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_load_itl_us: Option<u32>,
    /// What the window has done since it was created, cumulative. `None`
    /// from a gateway that does not report it, and before a window exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisions: Option<AdaptiveDecisions>,
}

/// Requests held for one pool, of one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCount {
    /// The pool: the endpoints that could serve them, sorted.
    pub endpoints: Vec<Uuid>,
    pub class_id: Option<Uuid>,
    pub count: u32,
}

/// One endpoint's bounds as the configuration states them
/// ([`DispatchGate::adopt_configuration`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointBounds {
    /// Whether the gate bounds the endpoint at all
    /// (`EndpointConfig::gated`, the one definition).
    pub gated: bool,
    /// The fixed in-flight limit, or — when `adaptive` — the learned one's ceiling.
    pub max_in_flight: Option<u32>,
    pub waiting_threshold: Option<u32>,
    pub adaptive: bool,
    /// The token-latency target a learned window keeps its engine within (its
    /// server's setting).
    pub itl_target: ItlTarget,
    /// Where the endpoint is: a learned window is about one machine.
    pub url: String,
    /// Whether the metrics poller reads its engine
    /// (`EndpointConfig::engine_read`, the one definition).
    pub engine_read: bool,
}

/// Where the configuration places an endpoint, relative to where it was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Still there (or no configuration adopted yet).
    Here,
    /// Configured elsewhere now: what was read there is about another machine.
    Moved,
    /// No longer configured at all.
    Dropped,
}

/// Operator-owned bounds.
#[derive(Debug, Clone, Copy)]
pub struct GateSettings {
    /// How long an engine's own reading is worth acting on. A reading that
    /// stops being refreshed — the engine restarted, its metrics port went
    /// away, the network broke — must EXPIRE rather than stand: a stale
    /// "busy" is otherwise the permanent answer for an endpoint that is idle,
    /// and every request for it would be held and then refused for ever.
    pub load_max_age: Duration,
    /// The hold a class that names no TTL of its own gets.
    pub default_ttl: Duration,
    /// The longest hold anything may ask for: how long a caller's connection
    /// may sit with nothing sent on it. Shutdown does not depend on it —
    /// [`DispatchGate::begin_shutdown`] refuses every hold at once.
    pub max_ttl: Duration,
    /// How many requests this process may hold at once.
    pub max_held: usize,
    /// And how many of those one pool may take, so a single saturated engine
    /// cannot consume the whole budget and refuse everyone else's.
    pub max_held_per_pool: usize,
    /// How long a request must have waited before the same request arriving
    /// again supersedes it ([`GateRequest::resend_key`]). A client that gave
    /// up has waited its own timeout first; identical requests sent together —
    /// sampling several answers, a fixed-body load test — arrive within
    /// milliseconds of each other and are all held. Not an operator setting.
    pub resend_min_age: Duration,
}

impl Default for GateSettings {
    fn default() -> Self {
        Self {
            load_max_age: Duration::from_secs(30),
            default_ttl: Duration::from_secs(10),
            // The proxy's own default (`QOS_QUEUE_TTL_MAX_MS`): keep in step.
            max_ttl: Duration::from_secs(540),
            max_held: 512,
            max_held_per_pool: 128,
            resend_min_age: Duration::from_secs(1),
        }
    }
}

/// A dispatched request's hold on an endpoint slot. Releasing it — on drop, by
/// any path, including a panic — hands the slot to the next waiter.
#[derive(Debug)]
pub struct GatePermit {
    gate: Option<Arc<DispatchGate>>,
    endpoint: Uuid,
    scope: (Uuid, Uuid),
    weight: u32,
    output_weight: f64,
    pub outcome: GateOutcome,
    pub waited: Duration,
}

impl GatePermit {
    /// A permit for a pool the gate does not manage: costs nothing and releases
    /// nothing.
    pub fn ungated() -> Self {
        Self {
            gate: None,
            endpoint: Uuid::nil(),
            scope: (Uuid::nil(), Uuid::nil()),
            weight: 1,
            output_weight: 2.0,
            outcome: GateOutcome::Immediate,
            waited: Duration::ZERO,
        }
    }

    /// The endpoint this request was admitted to, when the gate chose one.
    pub fn endpoint(&self) -> Option<Uuid> {
        self.gate.as_ref().map(|_| self.endpoint)
    }

    /// Charge the output this request produced, so the next decision between
    /// this user and another accounts for what they actually consumed.
    pub fn charge_output(&self, tokens: u32) {
        if let Some(gate) = &self.gate {
            gate.charge(self.scope, f64::from(tokens) * self.output_weight / f64::from(self.weight));
        }
    }
}

impl Drop for GatePermit {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            gate.release(self.endpoint, self.scope);
        }
    }
}

/// A slot a release handed to a waiter, which frees itself if the waiter never
/// takes it.
///
/// `oneshot::Sender::send` succeeds while the receiver still EXISTS, not when it
/// is read — and a caller whose client disconnected is dropped without ever
/// polling. Sending the reservation itself, rather than an endpoint id the
/// receiver was trusted to convert, is what makes the count correct on that
/// path: the value's own `Drop` runs in the caller's task and gives the slot
/// back. Without it a cancelled caller leaked one slot per release, and a
/// replica's in-flight count climbed to its limit and stayed there.
struct SlotGrant {
    gate: Option<Arc<DispatchGate>>,
    endpoint: Uuid,
    scope: (Uuid, Uuid),
    /// What the waiter was charged when the slot was reserved for it. Returned
    /// with the slot if it never takes it: a request that did not run must not
    /// cost its caller, or a client that keeps disconnecting while queued falls
    /// behind for work no engine ever did.
    charge: f64,
}

impl SlotGrant {
    /// Take the slot, disarming the release on drop.
    fn claim(mut self) -> Uuid {
        self.gate = None;
        self.endpoint
    }

    /// Give the slot back WITHOUT going through `release` — for the one path
    /// that undoes a reservation while already holding the gate's lock.
    fn defuse(&mut self) {
        self.gate = None;
    }
}

impl Drop for SlotGrant {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            gate.refund(self.scope, self.charge);
            gate.release(self.endpoint, self.scope);
        }
    }
}

/// How long a request whose session's engine is full waits for that engine
/// rather than going to another with room ([`Inner::next_release`]): about the
/// time a busy engine takes to free a slot, set against re-reading a long
/// history into a cold cache. It runs from the first time another engine
/// COULD have taken it, however long it had waited before that — under
/// saturation most waiters have waited longer than any grace — and never into
/// the last stretch of its hold ([`affinity_ends`]), so waiting for its engine
/// is never what runs it out.
pub const AFFINITY_GRACE: Duration = Duration::from_secs(5);

/// The last instant a request held from `started` for `ttl` may still wait
/// for its session's engine rather than take another: its deadline less the
/// grace, or less half its hold when that is shorter.
fn affinity_ends(started: Instant, ttl: Duration) -> Instant {
    // A hold too long to be an instant (an operator's "never refuse") waits
    // for its engine not at all, rather than panicking under the gate lock.
    started.checked_add(ttl - AFFINITY_GRACE.min(ttl / 2)).unwrap_or(started)
}

/// A caller's place in the queue, given up if the caller is dropped while it
/// still holds it ([`DispatchGate::acquire`]).
struct QueuedGuard<'a> {
    gate: &'a Arc<DispatchGate>,
    seq: u64,
    /// The queue it waits in: the only one looked through for it.
    key: Vec<Uuid>,
    armed: bool,
}

impl Drop for QueuedGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Not found ⇒ a release took it first: the slot is in the channel,
            // and the grant's own drop gives it back.
            self.gate.forget_waiter(&self.key, self.seq);
        }
    }
}

/// A waiter's place in the release order, lowest first: its class rank,
/// whether it would miss its session's endpoint, its caller's weighted
/// consumption, and its place in arrival order ([`Waiter::place`],
/// [`Inner::next_release`]).
type ReleaseOrder = (i32, bool, f64, u64);

/// A waiter's place in the give-way order, highest first: its class rank, its
/// caller's weighted consumption, and its place in arrival order
/// ([`Inner::least_important_waiter`]).
type GiveWayOrder = (i32, f64, u64);

/// One waiting request.
struct Waiter {
    rank: i32,
    class_id: Option<Uuid>,
    scope: (Uuid, Uuid),
    /// The endpoints that can serve it, in the order routing chose.
    order: Vec<Uuid>,
    /// The one its session prefers ([`GateRequest::preferred`]), when it is
    /// among them — where its earlier turns ran, and so where their prefix is
    /// cached. `None`: it has no engine of its own to wait for.
    preferred: Option<Uuid>,
    /// Until when it may still wait for its own engine rather than take another
    /// ([`affinity_ends`]).
    affinity_ends: Instant,
    /// When another engine could first have taken it — it turned that engine
    /// down for its own, or a waiter of its class that keeps its own engine
    /// went instead: the grace runs from here.
    passed_over_at: Option<Instant>,
    /// What this request costs its user the moment it is DISPATCHED. Held here
    /// rather than charged at enqueue: a request that is refused or gives up
    /// never ran, so charging it would put its user behind for work nobody did,
    /// and queueing ten requests would look like consuming ten.
    charge: f64,
    /// The waiter's identity — unique, never inherited: its own deadline, its
    /// caller's drop and the release look it up by this.
    seq: u64,
    /// Its place in arrival order, which breaks a tie between two users on the
    /// same counter: its own `seq`, or the place of the copy it superseded, so
    /// a re-send is not sent to the back for its client's impatience.
    place: u64,
    /// [`GateRequest::resend_key`].
    resend_key: Option<[u8; 32]>,
    /// When it joined the queue.
    since: Instant,
    /// The slot a release hands it, or the refusal that took its place away.
    tx: oneshot::Sender<Result<SlotGrant, GateRefusal>>,
}

impl Waiter {
    /// Whether, sent to `endpoint`, it would miss its own engine while it may
    /// still wait for it: it has one, `endpoint` is not it, and its grace has
    /// not run out.
    fn misses(&self, endpoint: Uuid, now: Instant) -> bool {
        self.preferred.is_some_and(|p| p != endpoint)
            && now < self.affinity_ends
            && self.passed_over_at.is_none_or(|t| now < t + AFFINITY_GRACE)
    }

    /// Where it would go now: its own engine when that has room, else the
    /// first in its routing order that does.
    fn endpoint_in(&self, room: &HashMap<Uuid, bool>) -> Option<Uuid> {
        let has_room = |id: &Uuid| room.get(id).copied().unwrap_or(false);
        self.preferred.filter(has_room).or_else(|| self.order.iter().copied().find(has_room))
    }
}

/// A user's weighted consumption — the one figure the release order, the
/// give-way order and the pass-over test all read; never a different one.
fn consumption(counters: &HashMap<(Uuid, Uuid), Counter>, scope: (Uuid, Uuid)) -> f64 {
    counters.get(&scope).map_or(0.0, |c| c.weighted)
}

/// What one user has consumed here, in weighted tokens.
#[derive(Debug, Clone, Copy, Default)]
struct Counter {
    weighted: f64,
    /// How many of this user's requests are in flight. A user with none is
    /// idle, and an idle user's counter is lifted to the floor on return rather
    /// than banking credit for the wait.
    active: u32,
}

#[derive(Default)]
struct Inner {
    /// Copied from the settings so the headroom checks, which only see `Inner`,
    /// can age a reading out.
    load_max_age: Duration,
    /// Requests this gateway has in flight at each endpoint.
    in_flight: HashMap<Uuid, u32>,
    /// How many this gateway has ever dispatched to each endpoint. Monotonic:
    /// a reading records the value it was taken at, and the difference is what
    /// the engine's own gauge has not seen yet.
    dispatched: HashMap<Uuid, u64>,
    /// The bounds each endpoint declared when it was last asked for. The
    /// configuration is re-read on every request, so this follows an operator's
    /// edit without the gate subscribing to anything.
    limits: HashMap<Uuid, u32>,
    thresholds: HashMap<Uuid, u32>,
    /// The learned window of each endpoint that declares one; `limits` is then
    /// its ceiling.
    windows: HashMap<Uuid, AdaptiveWindow>,
    /// The URL each window was learned against.
    window_urls: HashMap<Uuid, String>,
    /// Endpoints whose bounds the configuration last stated
    /// (`adopt_configuration`), with the URL it stated for each and whether
    /// their engine is read: their bounds are read from `limits` /
    /// `thresholds`, never from a request.
    configured: HashMap<Uuid, (String, bool)>,
    /// Whether any configuration has been adopted: from then on a reading is
    /// recorded only for an endpoint, and a URL, the configuration states.
    adopted: bool,
    /// Adaptive endpoints a request found full since their last reading — the
    /// only thing that lets a window grow.
    limited: std::collections::HashSet<Uuid>,
    /// What each endpoint's engine last said about itself.
    load: HashMap<Uuid, EndpointLoad>,
    /// Waiters, by the set of endpoints that can serve them. Keyed by the
    /// endpoint ids so two aliases on one engine queue together, which is what
    /// makes the fairness between them real.
    queues: HashMap<Vec<Uuid>, Vec<Waiter>>,
    /// Weighted consumption per (workspace, user).
    counters: HashMap<(Uuid, Uuid), Counter>,
    held: usize,
    seq: u64,
    shutting_down: bool,
    /// The current reporting interval's peaks ([`GatePeaks`]). Raised where the
    /// gauge rises — a dispatch, an enqueue, a reading — and restarted from the
    /// instant values by [`DispatchGate::report_snapshot`].
    peaks: GatePeaks,
    /// The earliest grace a waiter waiting for its own engine started or
    /// renewed in the current pump ([`Inner::next_release`]): when the queue
    /// must be looked at again, though no slot frees and no reading lands.
    grace_wake: Option<Instant>,
    /// When the gate's own timer will next look at the queue
    /// ([`DispatchGate::arm_wake`]); `None` when no timer is set.
    wake_at: Option<Instant>,
}

/// The gate itself: one per proxy process, held on `AppState`.
#[derive(Debug)]
pub struct DispatchGate {
    inner: Mutex<Inner>,
    settings: GateSettings,
    held_total: AtomicU64,
    shed_total: AtomicU64,
    timeout_total: AtomicU64,
    overloaded_total: AtomicU64,
    superseded_total: AtomicU64,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("in_flight", &self.in_flight.len())
            .field("queues", &self.queues.len())
            .field("held", &self.held)
            .finish()
    }
}

impl DispatchGate {
    pub fn new(settings: GateSettings) -> Self {
        Self {
            inner: Mutex::new(Inner {
                load_max_age: settings.load_max_age,
                ..Inner::default()
            }),
            settings,
            held_total: AtomicU64::new(0),
            shed_total: AtomicU64::new(0),
            timeout_total: AtomicU64::new(0),
            overloaded_total: AtomicU64::new(0),
            superseded_total: AtomicU64::new(0),
        }
    }

    pub fn settings(&self) -> &GateSettings {
        &self.settings
    }

    /// How many requests this gateway has dispatched to an endpoint, ever.
    ///
    /// Read at the instant a reading is taken and stored on it, so what the
    /// engine's gauge has not seen yet can be worked out from the difference.
    pub fn dispatch_mark(&self, endpoint: Uuid) -> u64 {
        self.lock().dispatched.get(&endpoint).copied().unwrap_or(0)
    }

    /// Record what an endpoint's engine reports about itself.
    #[cfg(test)]
    pub(crate) fn record_load(self: &Arc<Self>, endpoint: Uuid, load: EndpointLoad) {
        let mut inner = self.lock();
        self.record_locked(&mut inner, endpoint, load);
    }

    /// Where the configuration last adopted places `endpoint`, relative to
    /// `url`, the place it was read at.
    pub fn placement(&self, endpoint: Uuid, url: &str) -> Placement {
        self.lock().placement(endpoint, url)
    }

    /// [`Self::record_load`] for a reading the poller took from `url`, unless
    /// the configuration has since moved the endpoint elsewhere or dropped it:
    /// a pass reads the targets of the configuration it started under, and
    /// what it heard from the old machine (or about an endpoint since dropped)
    /// must not stand. Records it only where [`Placement::Here`], and returns
    /// the placement. Before any configuration is adopted, every reading is.
    pub fn record_read(self: &Arc<Self>, endpoint: Uuid, url: &str, load: EndpointLoad) -> Placement {
        let mut inner = self.lock();
        let placement = inner.placement(endpoint, url);
        if placement == Placement::Here {
            self.record_locked(&mut inner, endpoint, load);
        }
        placement
    }

    fn record_locked(self: &Arc<Self>, inner: &mut Inner, endpoint: Uuid, load: EndpointLoad) {
        // A window whose readings had gone stale resumes from scratch: what it
        // last compared with is from before the silence.
        if !inner.fresh(endpoint)
            && let Some(window) = inner.windows.get_mut(&endpoint)
        {
            window.resume();
        }
        inner.load.insert(endpoint, load);
        inner.peaks.engine.entry(endpoint).or_default().fold(&load);
        let adaptive = inner.observe(endpoint, &load);
        // Its queue may have drained, or its window grown, since the last
        // read: serve whoever this makes room for rather than waiting for the
        // next release. Only a reading some bound depends on can make room —
        // one taken for the dashboards alone releases nothing, so it does not
        // scan the queues.
        if adaptive || inner.thresholds.contains_key(&endpoint) {
            self.pump(inner);
        }
    }

    /// Reconsider the queue.
    ///
    /// Releases and new readings pump on their own, but neither covers an
    /// endpoint whose reading simply EXPIRES: nothing is released (a
    /// queue-gated endpoint holds no in-flight count of ours) and no reading
    /// arrives. Without a periodic nudge the requests already waiting sit out
    /// their deadline while anything arriving after the expiry goes straight
    /// out — the same pool answering two callers differently for no reason
    /// either can see. The metrics poller calls this every tick.
    pub fn reconsider(self: &Arc<Self>) {
        let mut inner = self.lock();
        self.pump(&mut inner);
    }

    /// Forget every endpoint the configuration no longer has.
    ///
    /// An endpoint with work still in flight is kept whatever the configuration
    /// says: its permits will come back and must find their counter. Everything
    /// else is per-endpoint state that would otherwise accumulate for the life
    /// of the process, and a stale reading kept under an id that is later reused
    /// would be read as that new endpoint's.
    pub fn retain_endpoints(
        &self,
        live: &std::collections::HashSet<Uuid>,
        gated: &std::collections::HashSet<Uuid>,
    ) {
        let mut inner = self.lock();
        let busy: std::collections::HashSet<Uuid> = inner.busy();
        let keep = |id: &Uuid| live.contains(id) || busy.contains(id);
        inner.load.retain(|id, _| keep(id));
        inner.limited.retain(|id| keep(id));
        inner.in_flight.retain(|id, _| keep(id));
        inner.dispatched.retain(|id, _| keep(id));
        inner.peaks.in_flight.retain(|id, _| keep(id));
        inner.peaks.engine.retain(|id, _| keep(id));
        // An endpoint the configuration still has, but which declares no
        // capacity any more, is not gated: its old bounds must not go on being
        // applied to whoever is already queued on it, because the release path
        // reads these and a new request now takes the ungated fast path without
        // ever coming back to correct them. One the configuration has DROPPED is
        // the opposite case — what it was admitted under is the only description
        // of it left, so a busy one keeps its bounds until it is idle.
        let declared = |id: &Uuid| {
            if live.contains(id) { gated.contains(id) } else { busy.contains(id) }
        };
        inner.limits.retain(|id, _| declared(id));
        inner.thresholds.retain(|id, _| declared(id));
        inner.windows.retain(|id, _| declared(id));
        let Inner { windows, window_urls, .. } = &mut *inner;
        window_urls.retain(|id, _| windows.contains_key(id));
    }

    /// Apply the configuration's bounds to every live endpoint. From then on
    /// the gate reads an endpoint's bounds from here, never from a request —
    /// which carries a routing snapshot that may be a change behind — so this
    /// is the ONE owner of them: the fixed limit (or, when learned, the
    /// ceiling), the engine-queue bound, and the learned window. An endpoint
    /// whose limit is learned gets a window here, and starts learning from its
    /// engine before the first request; one whose limit no longer is, or whose
    /// URL changed (another machine: what was learned is about the old one),
    /// loses it. A switch of any kind therefore applies to whoever is already
    /// queued. An endpoint the configuration dropped keeps what it was
    /// admitted under ([`Self::retain_endpoints`] decides when that goes).
    ///
    /// Returns the endpoints the configuration now asks a reading of that the
    /// gate does not have: one whose engine is read and which it states for the
    /// first time, at another URL, or with its engine read where it was not; or
    /// one it gives a learned window. The caller reads those engines then rather
    /// than at its next pass. An endpoint stated for the first time or at
    /// another URL also loses its peaks and "found full" mark — about another
    /// machine, or from before it was dropped — and its reading too unless work
    /// is in flight or waiting on it: a reading is what holds its queue back,
    /// and forgetting it would release the whole queue to an engine never read
    /// (the new machine's reading replaces it as soon as it is taken).
    pub fn adopt_configuration(&self, bounds: &HashMap<Uuid, EndpointBounds>) -> std::collections::HashSet<Uuid> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let mut unread = std::collections::HashSet::new();
        for (id, b) in bounds {
            match inner.configured.get(id) {
                Some((url, was_read)) if *url == b.url => {
                    if b.engine_read && !was_read {
                        unread.insert(*id);
                    }
                }
                _ => {
                    if !inner.busy().contains(id) {
                        inner.load.remove(id);
                    }
                    inner.peaks.engine.remove(id);
                    inner.limited.remove(id);
                    if b.engine_read {
                        unread.insert(*id);
                    }
                }
            }
        }
        inner.adopted = true;
        inner.configured = bounds.iter().map(|(id, b)| (*id, (b.url.clone(), b.engine_read))).collect();
        let window_urls = &inner.window_urls;
        inner.windows.retain(|id, _| {
            bounds.get(id).is_none_or(|b| b.adaptive && window_urls.get(id) == Some(&b.url))
        });
        for (id, b) in bounds {
            if b.adaptive {
                match inner.windows.get_mut(id) {
                    Some(window) => window.set_latency_target(b.itl_target),
                    None => {
                        let mut window = AdaptiveWindow::new(b.max_in_flight);
                        window.set_latency_target(b.itl_target);
                        inner.windows.insert(*id, window);
                        inner.window_urls.insert(*id, b.url.clone());
                        unread.insert(*id);
                    }
                }
            }
            match b.max_in_flight {
                Some(max) => inner.limits.insert(*id, max),
                None => inner.limits.remove(id),
            };
            match b.waiting_threshold {
                Some(threshold) => inner.thresholds.insert(*id, threshold),
                None => inner.thresholds.remove(id),
            };
        }
        let Inner { windows, window_urls, .. } = inner;
        window_urls.retain(|id, _| windows.contains_key(id));
        unread
    }

    /// Refuse everything that would have to WAIT, and hold nothing further: a
    /// request held past the shutdown grace period is a request nobody ever
    /// answers. What can be dispatched right now still is — the replica is
    /// still in rotation for a few seconds, and refusing work it could do would
    /// make every rolling restart an outage for the callers in flight.
    pub fn begin_shutdown(&self) {
        let mut inner = self.lock();
        inner.shutting_down = true;
        inner.queues.clear();
        inner.held = 0;
    }

    pub fn stats(&self) -> GateStats {
        let inner = self.lock();
        GateStats {
            held_total: self.held_total.load(Ordering::Relaxed),
            shed_total: self.shed_total.load(Ordering::Relaxed),
            timeout_total: self.timeout_total.load(Ordering::Relaxed),
            overloaded_total: self.overloaded_total.load(Ordering::Relaxed),
            superseded_total: self.superseded_total.load(Ordering::Relaxed),
            queue_depth: inner.held as u64,
            in_flight: inner.in_flight.values().map(|v| u64::from(*v)).sum(),
        }
    }

    /// What this process holds right now. Leaves the reporting interval alone:
    /// its `peaks` are empty ([`Self::report_snapshot`] is the one reader).
    pub fn snapshot(&self) -> GateSnapshot {
        self.lock().snapshot()
    }

    /// What the live load report sends on a heartbeat: [`Self::snapshot`] plus
    /// the peaks since the previous call, which this call ends — the next
    /// interval starts from the instants reported here, so a peak is never
    /// below its own beat's instant and never carries over a burst already
    /// reported. A heartbeat that is lost loses its interval's peaks, as it
    /// loses its instants.
    pub fn report_snapshot(&self) -> GateSnapshot {
        let mut inner = self.lock();
        let mut snapshot = inner.snapshot();
        // What is true now: the floor of this interval's peaks, and where the
        // next interval starts — built once, under the one lock.
        let now = Inner::interval_start(&snapshot);
        let mut peaks = std::mem::replace(&mut inner.peaks, now.clone());
        for (id, n) in now.in_flight {
            let p = peaks.in_flight.entry(id).or_insert(0);
            *p = (*p).max(n);
        }
        for (key, n) in now.held_class {
            let c = peaks.held_class.entry(key).or_insert(0);
            *c = (*c).max(n);
        }
        for (pool, n) in now.held_pool {
            let p = peaks.held_pool.entry(pool).or_insert(0);
            *p = (*p).max(n);
        }
        // An engine reading too old to report has no peak to report either;
        // the engine's next interval starts at its next reading.
        peaks.engine.retain(|id, _| snapshot.engine.contains_key(id));
        for (id, (load, _)) in &snapshot.engine {
            peaks.engine.entry(*id).or_default().fold(load);
        }
        snapshot.peaks = peaks;
        snapshot
    }

    /// Ask for a slot, holding the request if every endpoint is busy.
    pub async fn acquire(
        self: &Arc<Self>,
        req: GateRequest,
    ) -> Result<GatePermit, GateRefusal> {
        let gated: Vec<GateEndpoint> = req.endpoints.iter().copied().filter(|e| e.gated()).collect();
        if gated.is_empty() {
            // Nothing declares capacity: this pool is not gated, so the request
            // goes straight out and no state is touched.
            return Ok(GatePermit::ungated());
        }

        let started = Instant::now();
        let ttl = req.ttl.min(self.settings.max_ttl);
        let (mut rx, seq, key) = {
            let mut inner = self.lock();
            inner.remember(&gated);
            // What the request costs its user when it goes out: the prompt, at
            // admission, so a long one is not free until its answer exists.
            let charge = f64::from(req.input_tokens) / f64::from(req.weight.max(1));

            // Sorted: the key names a SET of endpoints, and routing hands them
            // over in a per-request order (session affinity, round-robin, the
            // breaker's health reorder). Keyed as given, one pool would split
            // into a queue per ordering — each with its own share of the hold
            // budget, which is the very thing that share exists to bound.
            let order: Vec<Uuid> = gated.iter().map(|e| e.id).collect();
            let mut queue_key = order.clone();
            queue_key.sort_unstable();
            let preferred = req.preferred.filter(|p| order.contains(p));
            // Shutting down refuses what would have to WAIT, not what can go out
            // now: the replica stays in its load balancer's rotation for some
            // seconds after SIGTERM, and turning away requests it could serve
            // would make an ordinary rolling restart look like an outage. A
            // sheddable class is refused instead of held.
            let may_wait = !inner.shutting_down && !req.sheddable;
            // A copy of this request still waiting is one its client gave up
            // on: refused here, before anything is measured, so the re-send
            // takes its place rather than being refused for the room the copy
            // holds — or put behind it.
            let inherited = req
                .resend_key
                .filter(|_| may_wait)
                .and_then(|k| inner.supersede(&queue_key, k, started.checked_sub(self.settings.resend_min_age)));
            if inherited.is_some() {
                self.superseded_total.fetch_add(1, Ordering::Relaxed);
            }

            let picked = inner.pick(&gated);
            // Every adaptive endpoint passed over was full: its window was
            // pressed against, which is what lets it grow — while its reading
            // is fresh. Unheard, the window is not what refused.
            let passed_over = picked.map_or(gated.len(), |(index, _)| index);
            for e in &gated[..passed_over] {
                if inner.window_is_full(e.id) {
                    inner.limited.insert(e.id);
                }
            }
            // A request goes out at once only when nobody is held for these
            // endpoints — held requests are released in their order
            // ([`Inner::next_release`]), never overtaken by an arrival — and
            // when it would land on its own engine: one whose engine is full
            // while another has room waits for its own, for the same grace as
            // a held one ([`AFFINITY_GRACE`]). A request that may not wait has
            // no engine of its own to wait for.
            // A queue is removed with its last waiter (`take_waiter`), so a key
            // present is a pool someone waits in.
            let queued = inner.queues.keys().any(|k| k.iter().any(|id| order.contains(id)));
            let misses = may_wait && picked.is_some_and(|(_, e)| preferred.is_some_and(|p| p != e));
            if let Some((_, endpoint)) = picked.filter(|_| !queued && !misses) {
                inner.charge_scope(req.scope, charge);
                inner.start(endpoint, req.scope);
                inner.raise_in_flight_peak(endpoint);
                return Ok(self.permit(endpoint, &req, GateOutcome::Immediate, Duration::ZERO));
            }
            if picked.is_none() && !may_wait {
                return Err(self.unwaited_refusal(inner.shutting_down));
            }
            // Two bounds, because one is not enough. The process-wide budget is
            // what stops the gateway holding more than it can afford; the
            // per-pool share is what stops ONE saturated pool taking all of it,
            // which would turn another tenant's momentary busy endpoint into an
            // immediate refusal through a knob they cannot see.
            //
            // A full budget refuses the least important request this POOL holds
            // rather than the one arriving: released by class, it would
            // otherwise be ADMITTED by arrival, and a long-holding Background
            // burst that filled the pool would turn every Interactive request
            // after it into an immediate refusal. Only a strictly less
            // important waiter gives way, so between equals the one already
            // waiting keeps its place. Only one waiting on an engine this
            // request could use (its own pool, or one a retry narrowed or
            // widened, sharing an endpoint with it), even when only the
            // process-wide budget is full: an endpoint is one tenant's, and a
            // class rank is that tenant's own number, so reaching further would
            // let one tenant refuse another's requests.
            //
            // When the pool's own share is what is full, only a waiter of that
            // pool makes room in it: one taken from an overlapping pool would
            // leave this one over its share.
            //
            // Applied once the request has had a turn: one the pump releases at
            // once never held anything, so a pool full of waiters waiting out
            // their own engines refuses no arrival an idle engine takes, and
            // nobody gives way for it. A request that may not wait is never
            // held, so it takes no hold budget.
            let rank = req.rank.unwrap_or(0);
            let (tx, mut rx) = oneshot::channel();
            inner.seq += 1;
            let seq = inner.seq;
            // Whether it may be held at all, measured before it joins.
            let pool_full = inner.queues.get(&queue_key).map_or(0, Vec::len) >= self.settings.max_held_per_pool;
            let budget_full = may_wait && (pool_full || inner.held >= self.settings.max_held);
            inner.held += 1;
            inner.queues.entry(queue_key.clone()).or_default().push(Waiter {
                rank,
                class_id: req.class_id,
                scope: req.scope,
                preferred: preferred.filter(|_| may_wait && !budget_full),
                order,
                affinity_ends: affinity_ends(started, ttl),
                passed_over_at: inherited.and_then(|(_, passed_over_at)| passed_over_at),
                charge,
                seq,
                place: inherited.map_or(seq, |(place, _)| place),
                resend_key: req.resend_key,
                since: started,
                tx,
            });
            // A slot a pump handed it: it never waited, the grant is in the
            // channel already.
            let granted = |rx: &mut oneshot::Receiver<Result<SlotGrant, GateRefusal>>| match rx.try_recv() {
                Ok(Ok(grant)) => Some(grant),
                _ => None,
            };
            let own_index = |inner: &Inner| inner.queues.get(&queue_key).and_then(|w| w.iter().position(|w| w.seq == seq));
            let leave = |inner: &mut Inner| {
                if let Some(index) = own_index(inner) {
                    inner.take_waiter(&queue_key, index);
                }
            };
            // Its turn may be now: an engine with room that no more important
            // waiter turned down. One that may not be held — it may not wait,
            // or the budget is full — has no engine of its own to wait for: an
            // idle engine takes it rather than it being refused for the sake of
            // its own full one, and it starts nobody's grace. One that may be
            // held starts its own grace here if it waits for its engine.
            self.pump(&mut inner);
            if let Some(grant) = granted(&mut rx) {
                return Ok(self.permit(grant.claim(), &req, GateOutcome::Immediate, Duration::ZERO));
            }
            if !may_wait {
                leave(&mut inner);
                return Err(self.unwaited_refusal(inner.shutting_down));
            }
            // Measured again: the pump may have released others and freed the
            // budget it was full of.
            let pool_full = inner.queues.get(&queue_key).map_or(0, |w| w.len().saturating_sub(1)) >= self.settings.max_held_per_pool;
            if budget_full && (pool_full || inner.held.saturating_sub(1) >= self.settings.max_held) {
                self.overloaded_total.fetch_add(1, Ordering::Relaxed);
                let Some((key, index)) = inner.least_important_waiter(&queue_key, pool_full, rank) else {
                    leave(&mut inner);
                    return Err(GateRefusal::Overloaded);
                };
                inner.give_way(&key, index, GateRefusal::Overloaded);
                // Held now, it waits for its own engine as any held request
                // does; the one refused may have been closing engines.
                if let Some(w) = own_index(&inner).and_then(|i| inner.queues.get_mut(&queue_key)?.get_mut(i)) {
                    w.preferred = preferred;
                }
                self.pump(&mut inner);
                if let Some(grant) = granted(&mut rx) {
                    return Ok(self.permit(grant.claim(), &req, GateOutcome::Immediate, Duration::ZERO));
                }
            }
            let queue = inner.queues.get(&queue_key).map(Vec::as_slice).unwrap_or_default();
            let pool = u32::try_from(queue.len()).unwrap_or(u32::MAX);
            let of_class = u32::try_from(queue.iter().filter(|w| w.class_id == req.class_id).count()).unwrap_or(u32::MAX);
            // Under the gate lock: allocate a key only for a pool or class the
            // interval has not seen yet.
            let peaks = &mut inner.peaks;
            match peaks.held_pool.get_mut(&queue_key) {
                Some(p) => *p = (*p).max(pool),
                None => {
                    peaks.held_pool.insert(queue_key.clone(), pool);
                }
            }
            let key = queue_key.clone();
            let class_key = (queue_key, req.class_id);
            match peaks.held_class.get_mut(&class_key) {
                Some(c) => *c = (*c).max(of_class),
                None => {
                    peaks.held_class.insert(class_key, of_class);
                }
            }
            self.held_total.fetch_add(1, Ordering::Relaxed);
            (rx, seq, key)
        };

        // A caller dropped while still queued — its client disconnected, and
        // axum drops the request future with this one inside it — takes its
        // place out of the queue with it. Left there, it would count against
        // the hold budgets until a release happened to reach it, which under a
        // steady stream of more important work is never: its own deadline
        // went with the future.
        let mut queued = QueuedGuard { gate: self, seq, key, armed: true };

        // The deadline and a release can land at the same instant. Rather than
        // dropping the receiver on a timeout — which would let a slot be handed
        // to a caller that is no longer listening, and leak it — the deadline
        // takes the queue lock and asks whether this waiter is still IN the
        // queue. Removal and release happen under that one lock, so exactly one
        // of them wins: still queued ⇒ nothing was sent and nothing can be;
        // already gone ⇒ the slot is ours and the value is waiting in the
        // channel.
        tokio::select! {
            biased;
            received = &mut rx => {
                // Out of the queue either way: released, given way, or the
                // queue cleared.
                queued.armed = false;
                match received {
                    Ok(Ok(grant)) => {
                        Ok(self.permit(grant.claim(), &req, GateOutcome::Held, started.elapsed()))
                    }
                    // A more important request took its place.
                    Ok(Err(refusal)) => Err(refusal),
                    // The sender went away without sending: the gate is shutting down.
                    Err(_) => Err(GateRefusal::ShuttingDown),
                }
            },
            _ = tokio::time::sleep(ttl) => {
                queued.armed = false;
                if self.forget_waiter(&queued.key, seq) {
                    self.timeout_total.fetch_add(1, Ordering::Relaxed);
                    return Err(GateRefusal::Timeout);
                }
                match rx.await {
                    Ok(Ok(grant)) => {
                        Ok(self.permit(grant.claim(), &req, GateOutcome::Held, started.elapsed()))
                    }
                    Ok(Err(refusal)) => Err(refusal),
                    Err(_) => Err(GateRefusal::ShuttingDown),
                }
            }
        }
    }

    /// Why a request that may not wait is refused: the replica is shutting
    /// down, or its class is shed rather than held (counted).
    fn unwaited_refusal(&self, shutting_down: bool) -> GateRefusal {
        if shutting_down {
            return GateRefusal::ShuttingDown;
        }
        self.shed_total.fetch_add(1, Ordering::Relaxed);
        GateRefusal::Shed
    }

    fn permit(
        self: &Arc<Self>,
        endpoint: Uuid,
        req: &GateRequest,
        outcome: GateOutcome,
        waited: Duration,
    ) -> GatePermit {
        GatePermit {
            gate: Some(self.clone()),
            endpoint,
            scope: req.scope,
            weight: req.weight.max(1),
            output_weight: req.output_weight,
            outcome,
            waited,
        }
    }

    /// A dispatched request finished: free its slot and serve the next waiter.
    /// This runs on every exit path, including a panic, because the permit's
    /// `Drop` calls it — a slot that leaked would shrink the pool for good.
    fn release(self: &Arc<Self>, endpoint: Uuid, scope: (Uuid, Uuid)) {
        let mut inner = self.lock();
        inner.finish(endpoint, scope);
        self.pump(&mut inner);
        // Consumption counters describe ONE busy period. With nothing in flight
        // and nobody waiting there is no contention to be fair about, and
        // keeping the numbers would let a user's past follow them into an
        // unrelated busy period hours later — served last for something nobody
        // is competing over any more.
        if inner.queues.is_empty() && inner.in_flight.values().all(|n| *n == 0) {
            inner.counters.clear();
        }
    }

    fn charge(&self, scope: (Uuid, Uuid), amount: f64) {
        let mut inner = self.lock();
        inner.charge_scope(scope, amount);
    }

    /// Give back what was charged for a request that never ran.
    fn refund(&self, scope: (Uuid, Uuid), amount: f64) {
        let mut inner = self.lock();
        inner.refund_scope(scope, amount);
    }

    /// Drop the waiter that gave up, by its own identity — never by its scope,
    /// which one caller may hold several of: removing "the oldest of that
    /// scope" would take a sibling request that is still waiting and leave its
    /// caller queued with nobody able to release it.
    ///
    /// Returns whether it was still queued. `false` means a release already
    /// took it, and the slot it names is the caller's.
    ///
    /// The queue is pumped after: the waiter gone may have been one waiting
    /// for its own engine, which kept the engines it turned down closed to
    /// those behind it ([`Inner::next_release`]).
    fn forget_waiter(self: &Arc<Self>, key: &[Uuid], seq: u64) -> bool {
        let mut inner = self.lock();
        let Some(index) = inner.queues.get(key).and_then(|waiters| waiters.iter().position(|w| w.seq == seq)) else {
            return false;
        };
        let taken = inner.take_waiter(key, index).is_some();
        self.pump(&mut inner);
        taken
    }

    /// Hand every free slot to the waiter that should have it.
    fn pump(self: &Arc<Self>, inner: &mut Inner) {
        // Read once per pump: a hand-over changes only the room of the
        // endpoint it went to, which is read again right after.
        let mut room = inner.room();
        // Engines a waiter turned down for its own stay closed for the whole
        // pump: a release only takes room, so nothing in it reopens them.
        let mut closed = std::collections::HashSet::new();
        loop {
            let Some((queue_key, index, endpoint)) = inner.next_release(Instant::now(), &room, &mut closed) else {
                self.arm_wake(inner);
                return;
            };
            let waiter = inner.take_waiter(&queue_key, index).expect("waiter named by next_release");
            let (scope, charge) = (waiter.scope, waiter.charge);
            // Reserve the slot before handing it over, so no other waiter is
            // offered it in between.
            inner.charge_scope(scope, charge);
            inner.start(endpoint, scope);
            let grant = SlotGrant { gate: Some(self.clone()), endpoint, scope, charge };
            match waiter.tx.send(Ok(grant)) {
                // Counted toward the peak only once it is handed over: a slot
                // reserved for a caller already gone never reached the engine.
                Ok(()) => inner.raise_in_flight_peak(endpoint),
                Err(unsent) => {
                    // The caller is already gone. Undo the reservation in place —
                    // letting the grant's own `Drop` do it here would re-enter
                    // this lock — and offer the slot to the next waiter.
                    if let Ok(mut grant) = unsent {
                        grant.defuse();
                    }
                    inner.refund_scope(scope, charge);
                    inner.finish(endpoint, scope);
                }
            }
            room.insert(endpoint, inner.headroom_for_id(endpoint));
        }
    }

    /// Look at the queue again when the earliest grace this pump saw ends
    /// ([`Inner::grace_wake`]): a waiter that turned an idle engine down for
    /// its own may take it then, and nothing else may happen there to pump —
    /// an idle engine frees no slot. One timer per earliest instant; a later
    /// one already set stays and pumps for nothing. Outside a runtime (a
    /// synchronous caller) there is nothing to arm; the next release or
    /// reading pumps instead.
    fn arm_wake(self: &Arc<Self>, inner: &mut Inner) {
        let Some(at) = inner.grace_wake.take() else { return };
        let now = Instant::now();
        if inner.wake_at.is_some_and(|armed| armed > now && armed <= at) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        inner.wake_at = Some(at);
        let gate = Arc::downgrade(self);
        runtime.spawn(async move {
            tokio::time::sleep_until(at.into()).await;
            if let Some(gate) = gate.upgrade() {
                let mut inner = gate.lock();
                if inner.wake_at == Some(at) {
                    inner.wake_at = None;
                }
                gate.pump(&mut inner);
            }
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a panic while the gate was being updated. The
        // state is a set of counters, none of which can be left in a shape that
        // makes a later decision unsafe, so recovering is strictly better than
        // refusing every request for the life of the process.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Inner {
    /// Endpoints with work in flight or WAITING on them. Their reading is what
    /// holds their queue back: forgetting it would make one look free and
    /// release the whole queue to an engine nobody read.
    fn placement(&self, endpoint: Uuid, url: &str) -> Placement {
        if !self.adopted {
            return Placement::Here;
        }
        match self.configured.get(&endpoint) {
            Some((at, _)) if at == url => Placement::Here,
            Some(_) => Placement::Moved,
            None => Placement::Dropped,
        }
    }

    fn busy(&self) -> std::collections::HashSet<Uuid> {
        self.in_flight
            .iter()
            .filter(|(_, n)| **n > 0)
            .map(|(id, _)| *id)
            .chain(self.queues.keys().flatten().copied())
            .collect()
    }

    /// The peaks an interval starts from: the gate's counts as `snapshot` has
    /// them now. The engine's start empty — its peak is over the readings
    /// taken in the interval, and the report folds the instant it sends.
    fn interval_start(snapshot: &GateSnapshot) -> GatePeaks {
        let mut held_pool: HashMap<Vec<Uuid>, u32> = HashMap::new();
        for h in &snapshot.held {
            *held_pool.entry(h.endpoints.clone()).or_insert(0) += h.count;
        }
        GatePeaks {
            in_flight: snapshot.in_flight.clone(),
            held_pool,
            held_class: snapshot.held.iter().map(|h| ((h.endpoints.clone(), h.class_id), h.count)).collect(),
            engine: HashMap::new(),
        }
    }

    /// What the gate holds now, with no peaks ([`DispatchGate::snapshot`]).
    fn snapshot(&self) -> GateSnapshot {
        GateSnapshot {
            in_flight: self.in_flight.clone(),
            engine: self
                .load
                .iter()
                .filter_map(|(id, load)| {
                    let age = load.read_at.elapsed();
                    (age <= self.load_max_age).then_some((*id, (*load, age)))
                })
                .collect(),
            held: {
                let mut counts: HashMap<(&Vec<Uuid>, Option<Uuid>), u32> = HashMap::new();
                for (endpoints, waiters) in &self.queues {
                    for w in waiters {
                        let n = counts.entry((endpoints, w.class_id)).or_insert(0);
                        *n = n.saturating_add(1);
                    }
                }
                counts
                    .into_iter()
                    .map(|((endpoints, class_id), count)| HeldCount {
                        endpoints: endpoints.clone(),
                        class_id,
                        count,
                    })
                    .collect()
            },
            adaptive: self
                .windows
                .iter()
                .map(|(id, window)| {
                    let applied = self.window_applies(*id);
                    (
                        *id,
                        AdaptiveStatus {
                            limit: self.limit_of(*id, self.limits.get(id).copied()),
                            state: if applied {
                                window.state()
                            } else if window.blind() || (self.load.contains_key(id) && !self.fresh(*id)) {
                                AdaptiveState::NoReading
                            } else {
                                AdaptiveState::Starting
                            },
                            low_load_itl_us: window.low_load_itl().map(itl_micros),
                            decisions: Some(window.decisions()),
                        },
                    )
                })
                .collect(),
            peaks: GatePeaks::default(),
        }
    }

    /// The first endpoint with room for one more request, in routing order,
    /// and its position.
    fn pick(&self, endpoints: &[GateEndpoint]) -> Option<(usize, Uuid)> {
        endpoints.iter().position(|e| self.has_headroom(e)).map(|i| (i, endpoints[i].id))
    }

    fn has_headroom(&self, e: &GateEndpoint) -> bool {
        let (max, threshold) = self.bounds_of(e);
        if let Some(max) = self.limit_of(e.id, max)
            && self.in_flight.get(&e.id).copied().unwrap_or(0) >= max
        {
            return false;
        }
        self.queue_ok(e.id, threshold)
    }

    /// An endpoint's fixed limit (or ceiling) and queue bound: the
    /// configuration's as the poller last applied it, never a request's own
    /// snapshot, which may be a change behind — except for an endpoint the
    /// poller has not seen yet.
    fn bounds_of(&self, e: &GateEndpoint) -> (Option<u32>, Option<u32>) {
        if self.configured.contains_key(&e.id) {
            (self.limits.get(&e.id).copied(), self.thresholds.get(&e.id).copied())
        } else {
            (e.max_in_flight, e.waiting_threshold)
        }
    }

    /// Whether the learned window is what refused a request here: it applies,
    /// and what is in flight has reached it. Only that is pressure on it.
    fn window_is_full(&self, id: Uuid) -> bool {
        self.window_applies(id)
            && self
                .limit_of(id, self.limits.get(&id).copied())
                .is_some_and(|limit| self.in_flight.get(&id).copied().unwrap_or(0) >= limit)
    }

    /// Whether this endpoint's engine reading is recent enough to act on.
    fn fresh(&self, id: Uuid) -> bool {
        self.load.get(&id).is_some_and(|l| l.read_at.elapsed() <= self.load_max_age)
    }

    /// The in-flight limit that applies to an endpoint now: its learned window
    /// while its engine is heard, else [`AdaptiveWindow::unheard_limit`] — the
    /// operator's ceiling, else the last learned window, else none.
    fn limit_of(&self, id: Uuid, ceiling: Option<u32>) -> Option<u32> {
        match self.windows.get(&id) {
            Some(window) if self.window_applies(id) => Some(window.limit(ceiling)),
            Some(window) => window.unheard_limit(ceiling),
            None => ceiling,
        }
    }

    /// Whether an endpoint's learned window is the limit now: it has a fresh
    /// reading and has taken a first reading with the KV gauge
    /// ([`AdaptiveWindow::steerable`]). Otherwise it is as good as unheard.
    fn window_applies(&self, id: Uuid) -> bool {
        self.windows.get(&id).is_some_and(AdaptiveWindow::steerable) && self.fresh(id)
    }

    /// Run one control step of an adaptive endpoint's window on a new reading.
    /// Returns whether the endpoint is adaptive.
    fn observe(&mut self, id: Uuid, load: &EndpointLoad) -> bool {
        if !self.windows.contains_key(&id) {
            return false;
        }
        // Pressed since the last reading, or still: a request queued for it
        // while the window — not some bound it had before — is full.
        let limited = self.limited.remove(&id)
            || (self.queues.iter().any(|(k, waiters)| !waiters.is_empty() && k.contains(&id))
                && self.window_is_full(id));
        let observation = Observation {
            waiting: load.waiting,
            running: load.running,
            kv_usage: load.kv_usage,
            counters: load.counters,
            in_flight: self.in_flight.get(&id).copied().unwrap_or(0),
            limited,
            ranks: load.ranks,
            at: load.read_at,
        };
        let ceiling = self.limits.get(&id).copied();
        if let Some(window) = self.windows.get_mut(&id) {
            window.observe(&observation, ceiling);
        }
        true
    }

    /// Whether the engine's own queue allows one more, as far as this replica
    /// knows. A reading that is missing OR too old is not an answer: the
    /// in-flight count remains the bound, because treating silence as "busy"
    /// would stall a healthy pool over a metrics outage — the failure this
    /// whole path exists to avoid.
    fn queue_ok(&self, id: Uuid, threshold: Option<u32>) -> bool {
        let Some(threshold) = threshold else {
            return true;
        };
        match self.load.get(&id) {
            Some(load) if load.read_at.elapsed() <= self.load_max_age => {
                // Dispatched since the reading, capped by what is still out:
                // a request that has finished sits in neither the engine's
                // queue nor this estimate, and one held in reserve and never
                // taken up was never there at all.
                let since = self
                    .dispatched
                    .get(&id)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(load.mark);
                let in_flight = u64::from(self.in_flight.get(&id).copied().unwrap_or(0));
                u64::from(load.waiting).saturating_add(since.min(in_flight))
                    <= u64::from(threshold)
            }
            _ => true,
        }
    }

    /// Remember what these endpoints declare, for the release path — which sees
    /// only the ids a queue was keyed by.
    fn remember(&mut self, endpoints: &[GateEndpoint]) {
        for e in endpoints {
            // What the configuration states is recorded by the poller alone
            // (see `adopt_configuration`); a request fills in only an endpoint
            // the poller has not seen yet.
            if self.configured.contains_key(&e.id) {
                continue;
            }
            match e.max_in_flight {
                Some(max) => {
                    self.limits.insert(e.id, max);
                }
                None => {
                    self.limits.remove(&e.id);
                }
            }
            match e.waiting_threshold {
                Some(threshold) => {
                    self.thresholds.insert(e.id, threshold);
                }
                None => {
                    self.thresholds.remove(&e.id);
                }
            }
        }
    }

    fn start(&mut self, endpoint: Uuid, scope: (Uuid, Uuid)) {
        *self.in_flight.entry(endpoint).or_insert(0) += 1;
        self.counters.entry(scope).or_default().active += 1;
        // Monotonic, and never reset: a reading records the value it was taken
        // at, so the difference is what reached the engine after it answered —
        // the estimate that stands in for a gauge that has not caught up.
        *self.dispatched.entry(endpoint).or_insert(0) += 1;
    }

    /// Raise the interval's in-flight peak to what is in flight now. Called
    /// where a slot is handed to a caller — never on a reservation that may
    /// still be undone.
    fn raise_in_flight_peak(&mut self, endpoint: Uuid) {
        let now = self.in_flight.get(&endpoint).copied().unwrap_or(0);
        let peak = self.peaks.in_flight.entry(endpoint).or_insert(0);
        *peak = (*peak).max(now);
    }

    /// The inverse of [`Self::start`]: the request is over, by any path.
    ///
    /// The dispatch counter is NOT wound back — it is a monotonic mark, not a
    /// gauge. What stops a finished request counting against the engine's queue
    /// is the in-flight cap in [`Self::queue_ok`], which also covers a
    /// reservation the caller never took up.
    fn finish(&mut self, endpoint: Uuid, scope: (Uuid, Uuid)) {
        if let Some(n) = self.in_flight.get_mut(&endpoint) {
            *n = n.saturating_sub(1);
        }
        if let Some(counter) = self.counters.get_mut(&scope) {
            counter.active = counter.active.saturating_sub(1);
        }
    }

    /// Charge a user, lifting an idle user to the floor first.
    fn charge_scope(&mut self, scope: (Uuid, Uuid), amount: f64) {
        let floor = self.active_floor();
        let counter = self.counters.entry(scope).or_default();
        // With nobody working there is nothing to catch up to, and `floor` is
        // then infinite — lifting to it would put this user permanently out of
        // reach of every comparison that follows.
        if counter.active == 0 && floor.is_finite() {
            // Returning from idle: start level with the users who kept working,
            // never below them. Without this, a user who paused would arrive
            // with a long-banked credit and starve everyone else while they
            // spend it.
            counter.weighted = counter.weighted.max(floor);
        }
        counter.weighted += amount;
    }

    /// Undo a charge. Never below zero: the floor lift can have moved the
    /// counter up in between, and a negative counter would hand its owner every
    /// slot until it climbed back.
    fn refund_scope(&mut self, scope: (Uuid, Uuid), amount: f64) {
        if let Some(counter) = self.counters.get_mut(&scope) {
            counter.weighted = (counter.weighted - amount).max(0.0);
        }
    }

    /// The lowest counter among users with something in flight, or infinity
    /// when none of them is working.
    fn active_floor(&self) -> f64 {
        self.counters
            .values()
            .filter(|c| c.active > 0)
            .map(|c| c.weighted)
            .fold(f64::INFINITY, f64::min)
    }


    /// The waiter that gives way when a full budget admits a request of class
    /// `rank` for `pool`: among the waiters of `pool` alone (`own_pool_only`,
    /// when its share is what is full) or of every pool sharing an endpoint
    /// with it, the least important class, then the caller who has consumed
    /// the most, then the newest arrival — the release order without its
    /// affinity tie-break, which depends on which engine frees next and so
    /// says nothing yet. Only a waiter of a strictly less important class is a
    /// candidate.
    fn least_important_waiter(&self, pool: &[Uuid], own_pool_only: bool, rank: i32) -> Option<(Vec<Uuid>, usize)> {
        let mut last: Option<(GiveWayOrder, &Vec<Uuid>, usize)> = None;
        let eligible = |k: &Vec<Uuid>| if own_pool_only { k.as_slice() == pool } else { k.iter().any(|id| pool.contains(id)) };
        for (key, waiters) in self.queues.iter().filter(|(k, _)| eligible(k)) {
            for (i, w) in waiters.iter().enumerate() {
                let place = (w.rank, consumption(&self.counters, w.scope), w.place);
                if w.rank > rank && last.is_none_or(|(p, ..)| place > p) {
                    last = Some((place, key, i));
                }
            }
        }
        last.map(|(_, key, index)| (key.clone(), index))
    }

    /// Refuse a waiter to make room for another request: out of the queue,
    /// out of the hold budget, and told why.
    /// Returns the place it held and when it was first passed over.
    fn give_way(&mut self, key: &[Uuid], index: usize, refusal: GateRefusal) -> Option<(u64, Option<Instant>)> {
        let waiter = self.take_waiter(key, index)?;
        // A caller already gone has nobody to tell.
        let _ = waiter.tx.send(Err(refusal));
        Some((waiter.place, waiter.passed_over_at))
    }

    /// Refuse the waiting copy of a request sent again
    /// ([`GateRequest::resend_key`]): a waiter with the same key that joined
    /// `pool` — the re-send's own — no later than `joined_by`. Only there does
    /// the copy's place free the room the re-send takes; a copy waiting for
    /// another pool is another attempt. `None` for `joined_by` (the monotonic
    /// clock is younger than the minimum age) matches nothing. Returns the copy's place
    /// and when it was first passed over, for the re-send to keep.
    fn supersede(&mut self, pool: &[Uuid], key: [u8; 32], joined_by: Option<Instant>) -> Option<(u64, Option<Instant>)> {
        let joined_by = joined_by?;
        let index = self
            .queues
            .get(pool)?
            .iter()
            .position(|w| w.resend_key == Some(key) && w.since <= joined_by)?;
        self.give_way(pool, index, GateRefusal::Superseded)
    }

    /// Whether each endpoint a waiter names has room now. Room is a property
    /// of the endpoint, so it is read once per endpoint, not once per waiter.
    fn room(&self) -> HashMap<Uuid, bool> {
        let mut room = HashMap::new();
        for id in self.queues.keys().flatten() {
            room.entry(*id).or_insert_with(|| self.headroom_for_id(*id));
        }
        room
    }

    /// Take a waiter out of its queue and out of the hold budget — the one
    /// way any waiter leaves (released, given up, or giving way). An emptied
    /// queue goes with it: left behind, its key would keep naming its
    /// endpoints as waited on — busy to `retain_endpoints`, pressed to a
    /// learned window — long after the last waiter left.
    fn take_waiter(&mut self, key: &[Uuid], index: usize) -> Option<Waiter> {
        let waiters = self.queues.get_mut(key)?;
        if index >= waiters.len() {
            return None;
        }
        let waiter = waiters.remove(index);
        if waiters.is_empty() {
            self.queues.remove(key);
        }
        self.held = self.held.saturating_sub(1);
        Some(waiter)
    }

    /// The next waiter to release, and the endpoint it goes to, if any
    /// endpoint has room for it: the most important class first; within it,
    /// a waiter that would go to the endpoint its session prefers before one
    /// that would land on another engine's cold cache ([`Waiter::misses`]);
    /// then the user who has consumed the least.
    ///
    /// A waiter that would miss is not sent elsewhere within its
    /// [`AFFINITY_GRACE`]: when it is the one that would go, it waits for its
    /// own engine instead, its grace starts if it had not, and every engine it
    /// could have taken stays closed to the waiters behind it for this pass —
    /// class order is never traded for a cache, so nobody less important (and
    /// no heavier user of its class) takes what it turned down. An engine may
    /// therefore stand idle while requests are held for others, for at most a
    /// grace each: the grace runs from the first time another engine could
    /// have taken the waiter, never into the last stretch of its hold
    /// ([`affinity_ends`]), and [`Self::grace_wake`] names when the earliest
    /// one ends, so the queue is looked at again then without a slot freeing.
    /// A waiter that would have gone first but for a waiter of its class
    /// keeping its own engine is marked passed over, which starts its grace
    /// too.
    ///
    /// A waiter goes to the first endpoint in its own routing order that has
    /// room, never to the first in the queue key — that is sorted by id, and
    /// would send every session to whichever replica's id sorts lowest.
    ///
    /// A linear scan, deliberately: the key it sorts by is the caller's WEIGHTED
    /// CONSUMPTION, which every dispatch and every refund moves, so an ordered
    /// structure would have to be re-keyed more often than it is read. The work
    /// is bounded by `max_held` — the gateway never holds more waiters than
    /// that, across every queue — times the endpoints a waiter can turn down,
    /// and it runs only when a slot frees, a reading lands or a grace ends.
    fn next_release(
        &mut self,
        now: Instant,
        room: &HashMap<Uuid, bool>,
        closed: &mut std::collections::HashSet<Uuid>,
    ) -> Option<(Vec<Uuid>, usize, Uuid)> {
        // Engines a more important waiter turned down in this pump (`closed`)
        // are closed to everyone after it — except a waiter in the last
        // stretch of its own hold ([`affinity_ends`]): another's wait for its
        // engine must not run it out either. Each round closes at least one
        // more engine, so this ends.
        // Copied only once something is closed: most pumps close nothing.
        let mut closed_view: Option<HashMap<Uuid, bool>> = (!closed.is_empty()).then(|| {
            let mut open = room.clone();
            open.extend(closed.iter().map(|id| (*id, false)));
            open
        });
        loop {
            let open = closed_view.as_ref().unwrap_or(room);
            let mut best: Option<(ReleaseOrder, &Vec<Uuid>, usize, Uuid)> = None;
            for (key, waiters) in &self.queues {
                for (i, w) in waiters.iter().enumerate() {
                    let view = if now < w.affinity_ends { open } else { room };
                    let Some(endpoint) = w.endpoint_in(view) else { continue };
                    let order = (w.rank, w.misses(endpoint, now), consumption(&self.counters, w.scope), w.place);
                    if best.as_ref().is_none_or(|(b, ..)| order < *b) {
                        best = Some((order, key, i, endpoint));
                    }
                }
            }
            // Cloned only for the winner: at 512 waiters, cloning per candidate
            // is a quarter of a million allocations per burst, every one of
            // them under the gate's own lock.
            let (winner, key, index, endpoint) = best.map(|(o, k, i, e)| (o, k.clone(), i, e))?;
            if winner.1 {
                let w = self.queues.get_mut(&key).and_then(|waiters| waiters.get_mut(index))?;
                let since = *w.passed_over_at.get_or_insert(now);
                let ends = (since + AFFINITY_GRACE).min(w.affinity_ends);
                self.grace_wake = Some(self.grace_wake.map_or(ends, |t| t.min(ends)));
                let closing = w.order.clone();
                // Whoever these engines could take now, but for the closing,
                // is woken when its own hold reaches its last stretch (which
                // the closing no longer holds back). One that would take one
                // away from its own engine starts its grace now too: a queue
                // behind a waiting head waits one grace in all, not one per
                // place.
                let Inner { queues, grace_wake, .. } = self;
                for w in queues.values_mut().flat_map(|waiters| waiters.iter_mut()) {
                    let Some(e) = w.endpoint_in(open) else { continue };
                    if !closing.contains(&e) || now >= w.affinity_ends {
                        continue;
                    }
                    if w.passed_over_at.is_none() && w.misses(e, now) {
                        w.passed_over_at = Some(now);
                    }
                    let wake = w.passed_over_at.map_or(w.affinity_ends, |t| (t + AFFINITY_GRACE).min(w.affinity_ends));
                    *grace_wake = Some(grace_wake.map_or(wake, |t| t.min(wake)));
                }
                let view = closed_view.get_or_insert_with(|| room.clone());
                for id in closing {
                    closed.insert(id);
                    view.insert(id, false);
                }
                continue;
            }
            // Whoever would have taken this same engine first, but for the
            // winner keeping its own engine there, has now been passed over
            // once: its grace runs from the first time. A waiter headed for
            // another engine — another pool's, another tenant's — was not
            // passed over at all. Marked before the hand-over is known to land:
            // one that fails offers the same slot again in the same pump, so a
            // marked waiter is either served there or passed over again at once.
            let Inner { queues, counters, .. } = self;
            // Only the pools that name this engine can hold such a waiter; the
            // endpoint check below decides, this only spares the other pools'
            // scan.
            let candidates = queues
                .iter_mut()
                .filter(|(k, _)| k.contains(&endpoint))
                .flat_map(|(_, waiters)| waiters.iter_mut())
                .filter(|w| w.passed_over_at.is_none());
            for w in candidates {
                let view = if now < w.affinity_ends { open } else { room };
                if w.endpoint_in(view) != Some(endpoint) || !w.misses(endpoint, now) {
                    continue;
                }
                if (w.rank, false, consumption(counters, w.scope), w.place) < winner {
                    w.passed_over_at = Some(now);
                }
            }
            return Some((key, index, endpoint));
        }
    }

    /// Headroom for an endpoint named by a queue, where the caller no longer
    /// holds the endpoint's declared bounds. What the waiter declared is what
    /// admitted it to this queue, so the live in-flight count against the last
    /// known limit is what decides now.
    fn headroom_for_id(&self, id: Uuid) -> bool {
        let in_flight = self.in_flight.get(&id).copied().unwrap_or(0);
        let limit = self.limit_of(id, self.limits.get(&id).copied());
        self.queue_ok(id, self.thresholds.get(&id).copied())
            && limit.is_none_or(|max| in_flight < max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn endpoint(max: u32) -> GateEndpoint {
        GateEndpoint { id: Uuid::new_v4(), max_in_flight: Some(max), waiting_threshold: None, adaptive: false }
    }

    fn request(endpoints: &[GateEndpoint], scope: (Uuid, Uuid), rank: i32) -> GateRequest {
        GateRequest {
            endpoints: endpoints.to_vec(),
            preferred: endpoints.first().map(|e| e.id),
            rank: Some(rank),
            class_id: None,
            sheddable: false,
            scope,
            weight: 1,
            input_tokens: 0,
            output_weight: 2.0,
            ttl: Duration::from_millis(200),
            resend_key: None,
        }
    }

    fn user() -> (Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4())
    }

    fn gate() -> Arc<DispatchGate> {
        Arc::new(DispatchGate::new(GateSettings::default()))
    }

    /// A gate whose re-sends supersede a copy at once, for the tests about
    /// what a supersede does rather than when.
    fn resend_gate(settings: GateSettings) -> Arc<DispatchGate> {
        Arc::new(DispatchGate::new(GateSettings { resend_min_age: Duration::ZERO, ..settings }))
    }

    #[tokio::test]
    async fn an_endpoint_that_declares_no_capacity_is_not_gated() {
        let gate = gate();
        let ep = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: None, adaptive: false };
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
        // Nothing was counted, so nothing can leak.
        assert_eq!(permit.endpoint(), None);
        assert_eq!(gate.stats().in_flight, 0);
    }

    #[tokio::test]
    async fn a_request_waits_for_a_slot_and_takes_it_when_one_frees() {
        let gate = gate();
        let ep = endpoint(1);
        let first = gate.acquire(request(&[ep], user(), 0)).await.expect("first dispatched");
        assert_eq!(gate.stats().in_flight, 1);

        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|p| p.outcome) }
        });
        // Let the second request reach the queue before the slot frees.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1);
        drop(first);

        assert_eq!(waiting.await.expect("task"), Ok(GateOutcome::Held));
        assert_eq!(gate.stats().held_total, 1);
    }

    fn resend(endpoints: &[GateEndpoint], scope: (Uuid, Uuid), key: u8, ttl: Duration) -> GateRequest {
        GateRequest { resend_key: Some([key; 32]), ttl, ..request(endpoints, scope, 0) }
    }

    #[tokio::test]
    async fn a_resend_takes_its_waiting_copys_place_and_the_copy_is_superseded() {
        let gate = resend_gate(GateSettings::default());
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let (caller, other) = (user(), user());
        let hold = Duration::from_secs(5);
        let copy = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 7, hold)).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Arrived after the copy, before the re-send: equal rank, equal counter.
        let later = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(GateRequest { ttl: hold, ..request(&[ep], other, 0) }).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let again = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 7, hold)).await }
        });
        // Refused at the re-send's arrival, not at its own deadline.
        let refused = tokio::time::timeout(Duration::from_millis(500), copy).await.expect("refused at once");
        assert_eq!(refused.expect("task"), Err(GateRefusal::Superseded));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 2, "the copy's place is the re-send's, and nothing else moved");
        assert_eq!(gate.stats().superseded_total, 1);
        // The slot frees: the re-send goes first, in the copy's place — ahead of
        // the request that arrived after the copy but before the re-send.
        drop(busy);
        let permit = tokio::time::timeout(Duration::from_secs(1), again)
            .await
            .expect("the later arrival was served instead")
            .expect("task")
            .expect("the re-send is served first");
        assert!(!later.is_finished(), "the later arrival overtook the re-send");
        drop(permit);
        later.await.expect("task").expect("then the later arrival");
    }

    #[tokio::test]
    async fn the_copys_own_deadline_never_removes_the_resend() {
        let gate = resend_gate(GateSettings::default());
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let caller = user();
        let copy = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 3, Duration::from_millis(300))).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let again = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 3, Duration::from_secs(5))).await }
        });
        assert_eq!(copy.await.expect("task"), Err(GateRefusal::Superseded));
        // Well past the copy's deadline: the re-send is its own waiter, not the copy's.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(gate.stats().queue_depth, 1);
        drop(busy);
        assert_eq!(again.await.expect("task").expect("served").outcome, GateOutcome::Held);
    }

    #[tokio::test]
    async fn a_full_pool_still_takes_the_resend_in_its_copys_place() {
        let gate = resend_gate(GateSettings { max_held_per_pool: 1, ..GateSettings::default() });
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let caller = user();
        let copy = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 5, Duration::from_secs(5))).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // The control: the pool is full, so another request of the same rank is refused.
        assert_eq!(gate.acquire(request(&[ep], user(), 0)).await.map(drop), Err(GateRefusal::Overloaded));
        let again = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 5, Duration::from_secs(5))).await }
        });
        assert_eq!(copy.await.expect("task"), Err(GateRefusal::Superseded));
        drop(busy);
        assert!(again.await.expect("task").is_ok(), "the re-send was refused for the room its copy held");
    }

    #[tokio::test]
    async fn a_running_copy_another_key_or_another_pool_is_never_superseded() {
        let gate = resend_gate(GateSettings::default());
        let (ep, elsewhere) = (endpoint(1), endpoint(1));
        let caller = user();
        // Running, not waiting: the re-send waits behind it.
        let running = gate.acquire(resend(&[ep], caller, 1, Duration::from_secs(5))).await.expect("dispatched");
        let _blocker = gate.acquire(request(&[elsewhere], user(), 0)).await.expect("dispatched");
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 1, Duration::from_secs(5))).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Another body, and the same body waiting for another pool.
        let other_key = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[ep], caller, 2, Duration::from_secs(5))).await }
        });
        let other_pool = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(resend(&[elsewhere], caller, 1, Duration::from_secs(5))).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!((gate.stats().queue_depth, gate.stats().superseded_total), (3, 0));
        assert!(!waiting.is_finished() && !other_key.is_finished() && !other_pool.is_finished());
        drop(running);
        drop(_blocker);
        for task in [waiting, other_key, other_pool] {
            let permit = task.await.expect("task").expect("served");
            drop(permit);
        }
    }

    #[tokio::test]
    async fn identical_requests_sent_together_are_all_held() {
        // Several answers sampled from one prompt, a fixed-body load test:
        // none of them gave up, so none replaces another.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            resend_min_age: Duration::from_millis(300),
            ..GateSettings::default()
        }));
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let caller = user();
        let send = || {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire(resend(&[ep], caller, 9, Duration::from_secs(5))).await.map(drop) })
        };
        let together = [send(), send(), send()];
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!((gate.stats().queue_depth, gate.stats().superseded_total), (3, 0));
        // The control: once the copies are older than the minimum age, the same
        // request arriving again does supersede the oldest.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let late = send();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!((gate.stats().queue_depth, gate.stats().superseded_total), (3, 1));
        drop(busy);
        let mut outcomes = Vec::new();
        for task in together.into_iter().chain([late]) {
            outcomes.push(task.await.expect("task"));
        }
        assert_eq!(outcomes.iter().filter(|o| **o == Err(GateRefusal::Superseded)).count(), 1, "{outcomes:?}");
    }

    #[tokio::test]
    async fn the_snapshot_reads_what_is_in_flight_and_held_where() {
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let _on_a = gate.acquire(request(&[a], user(), 0)).await.expect("dispatched");
        let _on_b = gate.acquire(request(&[b], user(), 0)).await.expect("dispatched");
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[a, b], user(), 0)).await.map(|p| p.outcome) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let snapshot = gate.snapshot();
        assert_eq!(snapshot.in_flight.get(&a.id), Some(&1));
        assert_eq!(snapshot.in_flight.get(&b.id), Some(&1));
        // One request waits, for either endpoint: one queue, keyed by both.
        let mut key = vec![a.id, b.id];
        key.sort();
        assert_eq!(snapshot.held, vec![HeldCount { endpoints: key, class_id: None, count: 1 }]);
        drop(_on_a);
        assert_eq!(held.await.expect("task"), Ok(GateOutcome::Held));
        assert!(gate.snapshot().held.is_empty(), "an empty queue is not reported as held");
    }

    #[tokio::test]
    async fn a_report_keeps_the_peak_between_two_beats_and_starts_the_next_from_now() {
        let gate = gate();
        let ep = endpoint(1);
        // One in flight, two more held, then all drained before the beat.
        let first = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let held: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                tokio::spawn(async move { gate.acquire(request(&[ep], user(), 0)).await.map(drop) })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 2);
        drop(first);
        for h in held {
            assert_eq!(h.await.expect("task"), Ok(()));
        }
        assert_eq!(gate.stats().in_flight, 0);
        assert_eq!(gate.stats().queue_depth, 0);

        let beat = gate.report_snapshot();
        // The instants say idle; the peaks say what the interval held.
        assert_eq!(beat.in_flight.get(&ep.id).copied().unwrap_or(0), 0);
        assert!(beat.held.is_empty());
        assert_eq!(beat.peaks.in_flight.get(&ep.id), Some(&1));
        assert_eq!(beat.peaks.held_pool.get(&vec![ep.id]), Some(&2));
        assert_eq!(beat.peaks.held_class.get(&(vec![ep.id], None)), Some(&2));

        // The next interval starts from what is true now, not from the burst.
        let next = gate.report_snapshot();
        assert_eq!(next.peaks.in_flight.get(&ep.id).copied().unwrap_or(0), 0);
        assert_eq!(next.peaks.held_pool.get(&vec![ep.id]).copied().unwrap_or(0), 0);
        // A plain snapshot neither reports nor ends an interval.
        assert!(gate.snapshot().peaks.in_flight.is_empty());
    }

    #[test]
    fn where_the_engine_queues_is_read_from_one_reading_never_two_peaks() {
        // Queued while running 3, then running 12 with no queue: it was never
        // seen queueing at 12, and saying so would suggest over-committing it.
        let gate = gate();
        let id = Uuid::new_v4();
        let reading = |waiting: u32, running: u32| EndpointLoad {
            ranks: 1, waiting, running: Some(running), kv_usage: Some(0.5), read_at: Instant::now(), mark: 0,
            counters: Default::default(),
        };
        gate.record_load(id, reading(1, 3));
        gate.record_load(id, reading(0, 12));
        let peak = gate.report_snapshot().peaks.engine[&id];
        assert_eq!((peak.waiting, peak.running, peak.running_queued), (1, Some(12), Some(3)));
    }

    #[test]
    fn the_low_load_time_per_token_is_reported_in_microseconds() {
        // The window learns seconds; the heartbeat carries whole microseconds,
        // which admin reads back as milliseconds.
        assert_eq!(itl_micros(0.020_5), 20_500);
        assert_eq!(itl_micros(0.000_000_4), 0);
        assert_eq!(itl_micros(1e9), u32::MAX, "saturated, never wrapped");
    }

    #[test]
    fn a_report_keeps_the_engines_highest_reading_and_never_one_below_the_instant() {
        let gate = gate();
        let id = Uuid::new_v4();
        let reading = |kv: f64, running: u32, waiting: u32| EndpointLoad {
            ranks: 1,
            waiting,
            running: Some(running),
            kv_usage: Some(kv),
            read_at: Instant::now(),
            mark: 0,
            counters: Default::default(),
        };
        gate.record_load(id, reading(0.9, 7, 3));
        gate.record_load(id, reading(0.1, 1, 0));
        let beat = gate.report_snapshot();
        assert_eq!(beat.engine[&id].0.kv_usage, Some(0.1), "the instant is the last reading");
        assert_eq!(
            beat.peaks.engine[&id],
            EnginePeak { waiting: 3, running: Some(7), kv_usage: Some(0.9), running_queued: Some(7) }
        );
        // No reading since: the peak is the instant still reported, not the
        // burst already reported, and not absent.
        let next = gate.report_snapshot();
        assert_eq!(
            next.peaks.engine[&id],
            EnginePeak { waiting: 0, running: Some(1), kv_usage: Some(0.1), running_queued: None }
        );
    }

    #[tokio::test]
    async fn what_is_held_is_counted_per_class_within_one_pool() {
        let gate = gate();
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let (interactive, background) = (Uuid::new_v4(), Uuid::new_v4());
        let classed = |class_id, rank| GateRequest { class_id: Some(class_id), ..request(&[ep], user(), rank) };
        let waiters: Vec<_> = [(interactive, 0), (background, 20), (background, 20)]
            .into_iter()
            .map(|(class_id, rank)| {
                let gate = gate.clone();
                let req = classed(class_id, rank);
                tokio::spawn(async move { gate.acquire(req).await.map(|p| p.outcome) })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut held = gate.snapshot().held;
        held.sort_by_key(|h| h.count);
        assert_eq!(
            held,
            vec![
                HeldCount { endpoints: vec![ep.id], class_id: Some(interactive), count: 1 },
                HeldCount { endpoints: vec![ep.id], class_id: Some(background), count: 2 },
            ],
            "one pool, two classes: two counts, never one lump and never a class the queue does not hold"
        );
        for w in waiters {
            // Nothing frees the slot, so each gives up at its deadline.
            assert_eq!(w.await.expect("task"), Err(GateRefusal::Timeout));
        }
    }

    #[test]
    fn the_snapshot_carries_a_reading_only_while_the_gate_applies_it() {
        let gate = Arc::new(DispatchGate::new(GateSettings {
            load_max_age: Duration::from_millis(40),
            ..GateSettings::default()
        }));
        let fresh = Uuid::new_v4();
        gate.record_load(
            fresh,
            EndpointLoad { ranks: 1, waiting: 3, running: Some(2), kv_usage: Some(0.25), read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let (load, age) = gate.snapshot().engine[&fresh];
        assert_eq!((load.waiting, load.running, load.kv_usage), (3, Some(2), Some(0.25)));
        assert!(age <= Duration::from_millis(40));
        // Past its shelf life the gate no longer acts on it, so neither does
        // the report: a stale "busy" must not stand as a live figure.
        std::thread::sleep(Duration::from_millis(60));
        assert!(gate.snapshot().engine.is_empty());
    }

    #[tokio::test]
    async fn a_sheddable_class_is_refused_at_once_instead_of_held() {
        let gate = gate();
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let mut req = request(&[ep], user(), 20);
        req.sheddable = true;
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Shed);
        assert_eq!(gate.stats().shed_total, 1);
    }

    #[tokio::test]
    async fn a_hold_that_outlives_its_ttl_is_refused_with_a_timeout() {
        let gate = gate();
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);
        // The waiter that gave up is gone from the queue, not left to be
        // handed a slot nobody is waiting on.
        assert_eq!(gate.stats().queue_depth, 0);
        assert_eq!(gate.stats().timeout_total, 1);
    }

    #[tokio::test]
    async fn the_more_important_class_is_released_first() {
        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");

        // Queue background first, then interactive: arrival order must not win.
        // Each task HOLDS its permit, as a real request does while it is being
        // answered — releasing it here would free the slot the next assertion is
        // about.
        let background = tokio::spawn({
            let (gate, scope) = (gate.clone(), user());
            async move { gate.acquire(request(&[ep], scope, 20)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let interactive = tokio::spawn({
            let (gate, scope) = (gate.clone(), user());
            async move { gate.acquire(request(&[ep], scope, 0)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 2);

        drop(busy);
        // The interactive request is served by the freed slot; background waits
        // for the one after it.
        let permit = interactive.await.expect("task").expect("interactive released first");
        assert_eq!(gate.stats().queue_depth, 1);
        // Nothing else frees a slot while that permit is held, so background
        // waits out its deadline.
        assert_eq!(background.await.expect("task").unwrap_err(), GateRefusal::Timeout);
        drop(permit);
    }

    #[tokio::test]
    async fn the_user_who_has_consumed_least_is_released_first() {
        // Two users working side by side on a two-slot engine. One has consumed
        // far more than the other; when a slot frees, it goes to the one who has
        // consumed less, whatever order they queued in.
        let gate = gate();
        let ep = endpoint(2);
        let (heavy, light) = (user(), user());
        let heavy_running = gate.acquire(request(&[ep], heavy, 10)).await.expect("dispatched");
        let light_running = gate.acquire(request(&[ep], light, 10)).await.expect("dispatched");
        heavy_running.charge_output(10_000);

        // The heavy user queues FIRST, so arrival order would serve it first.
        let heavy_wait = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], heavy, 10)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let light_wait = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], light, 10)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 2);

        drop(heavy_running);
        let permit = light_wait.await.expect("task").expect("the light user goes first");
        assert_eq!(heavy_wait.await.expect("task").unwrap_err(), GateRefusal::Timeout);
        drop(permit);
        drop(light_running);
    }

    #[tokio::test]
    async fn an_engine_whose_own_queue_is_too_long_takes_nothing_more() {
        let gate = gate();
        let ep = GateEndpoint {
            id: Uuid::new_v4(),
            max_in_flight: None,
            waiting_threshold: Some(2),
            adaptive: false,
        };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 5, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);

        // The queue drains: the next request goes out with no wait.
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 0, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn a_reading_that_stops_being_refreshed_stops_being_believed() {
        // An engine reports a long queue and then goes quiet — its metrics port
        // died, it restarted, the network broke. The last "busy" reading must
        // EXPIRE: standing for ever would hold and then refuse every request for
        // an endpoint that is idle, with nothing to ever clear it.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            load_max_age: Duration::from_millis(50),
            ..GateSettings::default()
        }));
        let ep = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: Some(2), adaptive: false };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 9, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(20);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);

        // Nothing new arrives; the reading ages out and the in-flight count is
        // the only bound again.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn a_caller_that_vanishes_before_taking_its_turn_gives_the_slot_back() {
        // The window is narrow and entirely real: a release hands the slot over
        // while the caller still EXISTS, and the caller is then dropped without
        // polling again — which is what axum does the moment a client
        // disconnects. Driven by hand so the order is exact, not raced.
        use std::task::{Context, Poll};

        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");

        // Boxed and owned, so dropping it really drops the future (a `pin!`
        // binding is a reference — dropping that drops nothing).
        let mut waiting = Box::pin(gate.acquire(request(&[ep], user(), 0)));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Pending), "it queues");
        assert_eq!(gate.stats().queue_depth, 1);

        // The slot frees and is handed to that waiter — which never comes back
        // for it.
        drop(busy);
        assert_eq!(gate.stats().queue_depth, 0);
        assert_eq!(gate.stats().in_flight, 1, "reserved for the waiter");

        drop(waiting);
        assert_eq!(gate.stats().in_flight, 0, "the unclaimed slot came back");

        // And the endpoint still takes work.
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn a_caller_dropped_while_queued_gives_its_place_back_at_once() {
        // Its client disconnected before any slot came free. The deadline that
        // would have taken it out of the queue lived in the dropped future, so
        // nothing else ever would: under a steady stream of more important
        // work, a release never reaches it, and it holds a share of the hold
        // budget for good.
        use std::assert_matches;
        use std::task::{Context, Poll};

        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 1,
            ..GateSettings::default()
        }));
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");

        let mut waiting = Box::pin(gate.acquire(request(&[ep], user(), 0)));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_matches!(waiting.as_mut().poll(&mut cx), Poll::Pending, "it queues");
        assert_eq!(gate.stats().queue_depth, 1);

        drop(waiting);
        assert_eq!(gate.stats().queue_depth, 0, "the place went with the caller");
        assert!(gate.snapshot().held.is_empty());
        // The pool's one share is free: the next caller is held, not refused.
        let mut next = request(&[ep], user(), 0);
        next.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(next).await.unwrap_err(), GateRefusal::Timeout);
    }


    /// Ask for a slot of class `rank` on `endpoints`, willing to wait a minute.
    fn spawn_acquire(
        gate: &Arc<DispatchGate>,
        endpoints: &[GateEndpoint],
        rank: i32,
    ) -> tokio::task::JoinHandle<Result<GatePermit, GateRefusal>> {
        let (gate, endpoints) = (gate.clone(), endpoints.to_vec());
        tokio::spawn(async move {
            let mut req = request(&endpoints, user(), rank);
            req.ttl = Duration::from_secs(60);
            gate.acquire(req).await
        })
    }

    /// Wait until the gate holds `n` requests.
    async fn until_held(gate: &Arc<DispatchGate>, n: u64) {
        for _ in 0..200 {
            if gate.stats().queue_depth >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(gate.stats().queue_depth, n);
    }

    /// Queue `n` requests of class `rank` on `endpoints`, each willing to wait
    /// a minute, and wait until they are all held.
    async fn hold(
        gate: &Arc<DispatchGate>,
        endpoints: &[GateEndpoint],
        rank: i32,
        n: usize,
    ) -> Vec<tokio::task::JoinHandle<Result<GatePermit, GateRefusal>>> {
        let before = gate.stats().queue_depth;
        let handles = (0..n).map(|_| spawn_acquire(gate, endpoints, rank)).collect::<Vec<_>>();
        until_held(gate, before + n as u64).await;
        handles
    }

    #[tokio::test]
    async fn a_full_pool_makes_room_for_a_more_important_request() {
        // Background fills its pool's share of the hold budget and holds for
        // minutes. An interactive request then arrives: released by class, it
        // must not be ADMITTED by arrival — the newest background request gives
        // way instead, and the oldest keeps its place.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 2,
            ..GateSettings::default()
        }));
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let mut background = hold(&gate, &[ep], 20, 1).await;
        background.extend(hold(&gate, &[ep], 20, 1).await);

        // An equal or lesser class finds the pool full and is refused itself.
        let mut same = request(&[ep], user(), 20);
        same.ttl = Duration::from_secs(60);
        assert_eq!(gate.acquire(same).await.unwrap_err(), GateRefusal::Overloaded);
        assert_eq!(gate.stats().queue_depth, 2, "nobody gave way to an equal");

        let interactive = spawn_acquire(&gate, &[ep], 0);
        let newest = background.pop().expect("two held");
        assert_eq!(newest.await.expect("task").unwrap_err(), GateRefusal::Overloaded, "the newest gave way");
        assert_eq!(gate.stats().queue_depth, 2);

        drop(busy);
        let permit = interactive.await.expect("task").expect("served first");
        assert_eq!(permit.outcome, GateOutcome::Held);
        drop(permit);
        background.pop().expect("one left").await.expect("task").expect("the oldest is still served");
    }

    #[tokio::test]
    async fn a_full_pool_refuses_the_waiter_fairness_would_serve_last() {
        // A heavy user's background flood fills the pool before a light user's
        // one request, the newest, arrives. An interactive request takes a
        // place: the heavy user's newest gives way — not the light user's,
        // whom the release order would serve first.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 3,
            ..GateSettings::default()
        }));
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let (heavy, light) = (user(), user());
        gate.lock().charge_scope(heavy, 10_000.0);
        let background = |scope| {
            let gate = gate.clone();
            tokio::spawn(async move {
                let mut req = request(&[ep], scope, 20);
                req.ttl = Duration::from_secs(60);
                gate.acquire(req).await
            })
        };
        let mut flood = Vec::new();
        for n in 1..=2 {
            flood.push(background(heavy));
            until_held(&gate, n).await;
        }
        let _light = background(light);
        until_held(&gate, 3).await;

        let _interactive = spawn_acquire(&gate, &[ep], 0);
        let newest_heavy = flood.pop().expect("two held");
        assert_eq!(newest_heavy.await.expect("task").unwrap_err(), GateRefusal::Overloaded);
        assert_eq!(gate.stats().queue_depth, 3, "the light user and the oldest heavy one wait on");
    }

    #[tokio::test]
    async fn a_full_gateway_makes_room_only_in_the_arriving_requests_own_pool() {
        // The process-wide budget is full of background work on engine A. A
        // more important request for A takes one of those places; one for
        // ANOTHER engine — another tenant's, as like as not, whose class ranks
        // are its own numbers — takes nobody's.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 2,
            max_held_per_pool: 8,
            ..GateSettings::default()
        }));
        let (a, b) = (endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a], user(), 0)).await.expect("dispatched");
        let _busy_b = gate.acquire(request(&[b], user(), 0)).await.expect("dispatched");
        let mut background = hold(&gate, &[a], 20, 2).await;
        let mut elsewhere = request(&[b], user(), 0);
        elsewhere.ttl = Duration::from_secs(60);
        assert_eq!(gate.acquire(elsewhere).await.unwrap_err(), GateRefusal::Overloaded);
        // An equal class on A takes nobody's place either.
        let mut equal = request(&[a], user(), 20);
        equal.ttl = Duration::from_secs(60);
        assert_eq!(gate.acquire(equal).await.unwrap_err(), GateRefusal::Overloaded);
        assert_eq!(gate.stats().queue_depth, 2);

        let _standard = spawn_acquire(&gate, &[a], 10);
        let newest = background.pop().expect("two held");
        assert_eq!(newest.await.expect("task").unwrap_err(), GateRefusal::Overloaded);
        assert_eq!(gate.stats().queue_depth, 2);
    }


    #[tokio::test]
    async fn a_full_pool_share_is_made_room_in_only_by_its_own_waiters() {
        // {A}'s share (two) is full of Standard; a Background waiter sits on
        // {A, B}. An interactive request for {A} takes a Standard place — the
        // Background one in the other pool would leave {A} over its share.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 2,
            ..GateSettings::default()
        }));
        let (a, b) = (endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a], user(), 0)).await.expect("dispatched");
        let _busy_b = gate.acquire(request(&[b], user(), 0)).await.expect("dispatched");
        let _background = hold(&gate, &[a, b], 20, 1).await;
        let mut standard = hold(&gate, &[a], 10, 2).await;
        let _interactive = spawn_acquire(&gate, &[a], 0);
        let newest = standard.pop().expect("two held");
        assert_eq!(newest.await.expect("task").unwrap_err(), GateRefusal::Overloaded);
        let held = gate.snapshot().held;
        let in_pool = |pool: Vec<Uuid>| held.iter().filter(|h| h.endpoints == pool).map(|h| h.count).sum::<u32>();
        let mut both = vec![a.id, b.id];
        both.sort_unstable();
        assert_eq!((in_pool(vec![a.id]), in_pool(both)), (2, 1), "{{A}} at its share; the Background waiter kept its place");
    }

    #[tokio::test]
    async fn a_request_on_a_narrower_slot_still_makes_room_on_its_engine() {
        // Background waits on {A, B}; a retry of an interactive request whose
        // slot no longer names B asks for {A} alone — another queue key, the
        // same engine A. Its place comes from those waiters all the same.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 2,
            max_held_per_pool: 8,
            ..GateSettings::default()
        }));
        let (a, b) = (endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a], user(), 0)).await.expect("dispatched");
        let _busy_b = gate.acquire(request(&[b], user(), 0)).await.expect("dispatched");
        let mut background = hold(&gate, &[a, b], 20, 2).await;
        let _interactive = spawn_acquire(&gate, &[a], 0);
        let newest = background.pop().expect("two held");
        assert_eq!(newest.await.expect("task").unwrap_err(), GateRefusal::Overloaded);
        assert_eq!(gate.stats().queue_depth, 2);
    }

    #[tokio::test]
    async fn a_held_session_goes_to_its_own_engine_when_that_one_frees() {
        // Two engines, each full. One user's session lives on A, another's on
        // B; the one on A has consumed less. B frees: the turn whose history
        // is cached on B takes it, and the one on A waits for A — rather than
        // the lighter user being sent to B to re-read its history there.
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let busy_b = gate.acquire(request(&[b, a], user(), 0)).await.expect("dispatched");
        assert_eq!((busy_a.endpoint(), busy_b.endpoint()), (Some(a.id), Some(b.id)));
        let (light, heavy) = (user(), user());
        gate.lock().charge_scope(heavy, 10_000.0);

        let held = |order: [GateEndpoint; 2], scope| {
            let gate = gate.clone();
            let mut req = request(&order, scope, 0);
            req.ttl = Duration::from_secs(5);
            tokio::spawn(async move { gate.acquire(req).await.map(|p| (p.endpoint(), p)) })
        };
        let on_a = held([a, b], light);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let on_b = held([b, a], heavy);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 2);

        drop(busy_b);
        let (endpoint, _permit_b) = on_b.await.expect("task").expect("released");
        assert_eq!(endpoint, Some(b.id), "B went to the session cached on B");
        assert_eq!(gate.stats().queue_depth, 1, "the session on A still waits for A");

        drop(busy_a);
        let (endpoint, _permit_a) = on_a.await.expect("task").expect("released");
        assert_eq!(endpoint, Some(a.id));
    }


    #[tokio::test]
    async fn a_request_with_no_engine_of_its_own_waits_for_none() {
        // The light user's retry is held on A and B with no engine of its own:
        // its session's replica failed it (no preference left), or that
        // replica is one the gate does not bound. B frees: fairness decides,
        // as if there were no affinity at all.
        let unbounded = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: None, adaptive: false };
        for (light_endpoints, light_preferred) in [(vec![], None), (vec![unbounded], Some(unbounded.id))] {
            let gate = gate();
            let (a, b) = (endpoint(1), endpoint(1));
            let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
            let busy_b = gate.acquire(request(&[b, a], user(), 0)).await.expect("dispatched");
            let (light, heavy) = (user(), user());
            gate.lock().charge_scope(heavy, 10_000.0);
            let held = |order: Vec<GateEndpoint>, scope, preferred| {
                let gate = gate.clone();
                let mut req = request(&order, scope, 0);
                req.ttl = Duration::from_secs(30);
                req.preferred = preferred;
                tokio::spawn(async move { gate.acquire(req).await.map(|p| (p.endpoint(), p)) })
            };
            let retry = held([light_endpoints.clone(), vec![a, b]].concat(), light, light_preferred);
            until_held(&gate, 1).await;
            let on_b = held(vec![b, a], heavy, Some(b.id));
            until_held(&gate, 2).await;

            drop(busy_b);
            let (endpoint, _permit) = retry.await.expect("task").expect("released");
            assert_eq!(endpoint, Some(b.id), "the lighter user goes first, to B ({light_preferred:?})");
            assert_eq!(gate.stats().queue_depth, 1);
            drop(busy_a);
            let _ = on_b.await;
        }
    }

    #[tokio::test]
    async fn an_arrival_whose_engine_is_full_waits_for_it_rather_than_take_another() {
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        assert_eq!(busy_a.endpoint(), Some(a.id));
        // Its session lives on A, which is full; B is free. It is held.
        let turn = spawn_acquire(&gate, &[a, b], 0);
        until_held(&gate, 1).await;
        drop(busy_a);
        let permit = turn.await.expect("task").expect("released");
        assert_eq!((permit.endpoint(), permit.outcome), (Some(a.id), GateOutcome::Held), "A freed: it went home");
        // With no engine of its own, the same arrival takes B at once.
        let mut req = request(&[a, b], user(), 0);
        req.preferred = None;
        let other = gate.acquire(req).await.expect("dispatched");
        assert_eq!((other.endpoint(), other.outcome), (Some(b.id), GateOutcome::Immediate));
    }

    #[tokio::test]
    async fn a_grace_that_ends_releases_the_waiter_though_no_slot_frees() {
        // B stays idle and A stays full: nothing frees, nothing is read. The
        // gate's own timer releases the waiter to B when its wait ends — here
        // the last stretch of a two-second hold, one second in.
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let started = Instant::now();
        let turn = {
            let gate = gate.clone();
            let mut req = request(&[a, b], user(), 0);
            req.ttl = Duration::from_secs(2);
            tokio::spawn(async move { gate.acquire(req).await })
        };
        until_held(&gate, 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(gate.stats().queue_depth, 1, "within its wait it keeps waiting for A");
        let permit = turn.await.expect("task").expect("released");
        assert_eq!((permit.endpoint(), permit.outcome), (Some(b.id), GateOutcome::Held));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_secs(1) && waited < Duration::from_millis(1800), "released at its wait's end, not its deadline: {waited:?}");
    }

    #[tokio::test]
    async fn an_earlier_grace_end_is_not_hidden_by_a_later_timer() {
        // A long hold's wait for A ends five seconds from now; a more important
        // turn with a two-second hold arrives after it, and its wait for A ends
        // one second after it arrived. The timer the first wait set is later:
        // the second must get its own, and take B when its wait ends — not
        // time out waiting for the first timer.
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let long = spawn_acquire(&gate, &[a, b], 0);
        until_held(&gate, 1).await;
        let started = Instant::now();
        let short = {
            let gate = gate.clone();
            let mut req = request(&[a, b], user(), -1);
            req.ttl = Duration::from_secs(2);
            tokio::spawn(async move { gate.acquire(req).await })
        };
        let permit = short.await.expect("task").expect("released at its wait's end");
        assert_eq!(permit.endpoint(), Some(b.id));
        assert!(started.elapsed() < Duration::from_millis(1800), "{:?}", started.elapsed());
        long.abort();
    }

    #[tokio::test]
    async fn an_arrival_never_takes_an_engine_a_more_important_waiter_turned_down() {
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let busy_b = gate.acquire(request(&[b, a], user(), 0)).await.expect("dispatched");
        // An interactive turn of a session on A is held; B frees and it turns
        // B down for A.
        let interactive = spawn_acquire(&gate, &[a, b], 0);
        until_held(&gate, 1).await;
        drop(busy_b);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1, "B is free, the interactive turn waits for A");
        // A background turn of a session on B arrives: B is free and its own,
        // but a more important turn is waiting — it queues behind it.
        let background = spawn_acquire(&gate, &[b, a], 20);
        until_held(&gate, 2).await;
        // A frees: the interactive turn goes home, and only then the
        // background one takes B.
        drop(busy_a);
        let first = interactive.await.expect("task").expect("released");
        assert_eq!(first.endpoint(), Some(a.id));
        let second = background.await.expect("task").expect("released");
        assert_eq!(second.endpoint(), Some(b.id));
    }

    #[tokio::test]
    async fn an_arrival_whose_turn_is_now_goes_out_and_is_never_counted_held() {
        // An interactive turn waits for A and turns B down; an arrival more
        // important than it, whose own engine is B, goes through the queue —
        // and out to B in that same pass: it never waited.
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let interactive = spawn_acquire(&gate, &[a, b], 0);
        until_held(&gate, 1).await;
        let held_before = gate.stats().held_total;
        let urgent = gate.acquire(request(&[b, a], user(), -1)).await.expect("its turn");
        assert_eq!((urgent.endpoint(), urgent.outcome, urgent.waited), (Some(b.id), GateOutcome::Immediate, Duration::ZERO));
        assert_eq!(gate.stats().held_total, held_before, "not counted as held");
        drop(busy_a);
        assert_eq!(interactive.await.expect("task").expect("released").endpoint(), Some(a.id));
    }

    #[tokio::test]
    async fn a_full_hold_budget_never_refuses_what_an_idle_engine_takes() {
        // The process-wide budget is full (another pool holds its one
        // waiter). An arrival whose own engine A is full could wait for it —
        // but may not be held; B is idle, so it takes B rather than being
        // refused.
        let gate = Arc::new(DispatchGate::new(GateSettings { max_held: 1, ..GateSettings::default() }));
        let (a, b, other) = (endpoint(1), endpoint(1), endpoint(1));
        let _busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        let _busy_other = gate.acquire(request(&[other], user(), 0)).await.expect("dispatched");
        let elsewhere = spawn_acquire(&gate, &[other], 0);
        until_held(&gate, 1).await;
        let permit = gate.acquire(request(&[a, b], user(), 0)).await.expect("not refused while B is idle");
        assert_eq!((permit.endpoint(), permit.outcome), (Some(b.id), GateOutcome::Immediate));
        // Positive control: with no engine free it is refused.
        let mut req = request(&[a, b], user(), 0);
        req.ttl = Duration::from_millis(50);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Overloaded);
        elsewhere.abort();
    }

    #[tokio::test]
    async fn a_request_that_may_not_wait_takes_any_free_engine_in_its_turn_or_is_refused() {
        let sheddable = |order: &[GateEndpoint]| {
            let mut req = request(order, user(), 30);
            req.sheddable = true;
            req
        };
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let busy_a = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        // Nobody held: a sheddable turn whose engine is full takes the free
        // one at once — it cannot wait for its own.
        let shed_ok = gate.acquire(sheddable(&[a, b])).await.expect("dispatched");
        assert_eq!((shed_ok.endpoint(), shed_ok.outcome), (Some(b.id), GateOutcome::Immediate));
        drop(shed_ok);
        // A more important turn waits for A and turns B down: the sheddable
        // turn, behind it, may not take B and may not wait — refused.
        let interactive = spawn_acquire(&gate, &[a, b], 0);
        until_held(&gate, 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.acquire(sheddable(&[b, a])).await.unwrap_err(), GateRefusal::Shed);
        assert_eq!(gate.stats().queue_depth, 1, "the refused turn left nothing queued");
        // Positive control: a sheddable turn MORE important than the waiter
        // takes the engine it turned down, at once.
        let mut urgent = sheddable(&[b, a]);
        urgent.rank = Some(-1);
        let urgent = gate.acquire(urgent).await.expect("its turn");
        assert_eq!((urgent.endpoint(), urgent.outcome), (Some(b.id), GateOutcome::Immediate));
        drop(busy_a);
        assert_eq!(interactive.await.expect("task").expect("released").endpoint(), Some(a.id));
    }

    /// Two endpoints of limit one, `lo` sorting before `hi`, each with room or
    /// not, and nothing queued yet.
    fn two_endpoints(room_lo: bool, room_hi: bool) -> (Inner, Uuid, Uuid) {
        let (x, y) = (Uuid::new_v4(), Uuid::new_v4());
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        let mut inner = Inner { load_max_age: Duration::from_secs(30), ..Inner::default() };
        for (id, room) in [(lo, room_lo), (hi, room_hi)] {
            inner.limits.insert(id, 1);
            inner.in_flight.insert(id, u32::from(!room));
        }
        (inner, lo, hi)
    }

    fn waiter(rank: i32, scope: (Uuid, Uuid), order: &[Uuid], affinity_ends: Instant, seq: u64) -> Waiter {
        Waiter {
            rank,
            class_id: None,
            scope,
            order: order.to_vec(),
            preferred: order.first().copied(),
            affinity_ends,
            passed_over_at: None,
            charge: 0.0,
            seq,
            place: seq,
            resend_key: None,
            since: Instant::now(),
            tx: oneshot::channel().0,
        }
    }

    fn consumed(inner: &mut Inner, scope: (Uuid, Uuid), weighted: f64) {
        inner.counters.insert(scope, Counter { weighted, active: 0 });
    }

    #[test]
    fn a_waiter_goes_to_its_own_endpoint_not_the_one_whose_id_sorts_first() {
        let (mut inner, lo, hi) = two_endpoints(true, true);
        let now = Instant::now();
        inner.queues.insert(vec![lo, hi], vec![waiter(0, user(), &[hi, lo], now + Duration::from_secs(60), 1)]);
        assert_eq!(released(&mut inner, now).map(|(_, e)| e), Some(hi));
    }

    /// `lo` full, `hi` with room; the lighter user's session is on `lo`, the
    /// heavier one's on `hi`; both may wait for minutes.
    fn light_on_lo_heavy_on_hi(now: Instant, light_ends: Instant) -> (Inner, Uuid, Uuid) {
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let (light, heavy) = (user(), user());
        consumed(&mut inner, light, 10.0);
        consumed(&mut inner, heavy, 500.0);
        inner.queues.insert(
            vec![lo, hi],
            vec![
                waiter(0, light, &[lo, hi], light_ends, 1),
                waiter(0, heavy, &[hi, lo], now + Duration::from_secs(600), 2),
            ],
        );
        (inner, lo, hi)
    }

    fn released(inner: &mut Inner, at: Instant) -> Option<(usize, Uuid)> {
        let room = inner.room();
        inner.next_release(at, &room, &mut std::collections::HashSet::new()).map(|(_, i, e)| (i, e))
    }

    #[test]
    fn a_passed_over_waiter_keeps_its_engine_for_one_grace_then_takes_any() {
        // However long either has waited, the first release that could take
        // the lighter user elsewhere does not: the grace starts there.
        let now = Instant::now();
        let (mut inner, lo, hi) = light_on_lo_heavy_on_hi(now, now + Duration::from_secs(600));
        assert_eq!(released(&mut inner, now), Some((1, hi)), "the session cached on `hi` goes first");
        let passed = |inner: &Inner| inner.queues[&vec![lo, hi]].iter().map(|w| w.passed_over_at).collect::<Vec<_>>();
        assert_eq!(passed(&inner), [Some(now), None], "the lighter one was passed over; the heavier one was not");
        let later = now + AFFINITY_GRACE - Duration::from_millis(1);
        assert_eq!(released(&mut inner, later), Some((1, hi)), "still within its grace");
        assert_eq!(passed(&inner), [Some(now), None], "the grace runs from the FIRST pass");
        assert_eq!(released(&mut inner, now + AFFINITY_GRACE), Some((0, hi)), "after it, the lighter user goes first");
    }


    #[test]
    fn only_a_winner_on_its_own_engine_passes_over_and_only_for_that_engine() {
        let now = Instant::now();
        let far = now + Duration::from_secs(600);
        let sorted = |a: Uuid, b: Uuid| if a < b { (a, b) } else { (b, a) };
        let mut inner = Inner { load_max_age: Duration::from_secs(30), ..Inner::default() };
        // Two pools — two tenants' engines, as like as not — each with a full
        // `lo` and an `hi` with room.
        let mut pools = Vec::new();
        for _ in 0..2 {
            let (lo, hi) = sorted(Uuid::new_v4(), Uuid::new_v4());
            for (id, busy) in [(lo, 1), (hi, 0)] {
                inner.limits.insert(id, 1);
                inner.in_flight.insert(id, busy);
            }
            pools.push((lo, hi));
        }
        let [(lo1, hi1), (lo2, hi2)] = [pools[0], pools[1]];
        let (heavy, lighter, lightest) = (user(), user(), user());
        consumed(&mut inner, heavy, 500.0);
        consumed(&mut inner, lighter, 50.0);
        consumed(&mut inner, lightest, 5.0);
        // Pool 1: the heavy user's session is on `hi1` and keeps its engine;
        // the lighter one's is on the full `lo1`. Pool 2: the lightest user's
        // session is on the full `lo2`, headed for `hi2`.
        inner.queues.insert(vec![lo1, hi1], vec![waiter(0, heavy, &[hi1, lo1], far, 1), waiter(0, lighter, &[lo1, hi1], far, 2)]);
        inner.queues.insert(vec![lo2, hi2], vec![waiter(0, lightest, &[lo2, hi2], far, 3)]);
        let passed = |inner: &Inner, key: Vec<Uuid>| inner.queues[&key].iter().map(|w| w.passed_over_at).collect::<Vec<_>>();

        assert_eq!(released(&mut inner, now), Some((0, hi1)), "the heavy user keeps its engine");
        assert_eq!(passed(&inner, vec![lo1, hi1]), [None, Some(now)], "passed over for `hi1`: the lighter one");
        assert_eq!(passed(&inner, vec![lo2, hi2]), [None], "headed for `hi2`, nobody passed it over");

        // Both would miss: the lighter one, which would have gone, waits for
        // its own engine and starts its grace; the heavier one, behind it, is
        // not sent to the engine it turned down either, and its grace starts
        // at the same moment — the engine could have taken it too.
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let (a, b) = (user(), user());
        consumed(&mut inner, a, 5.0);
        consumed(&mut inner, b, 50.0);
        inner.queues.insert(vec![lo, hi], vec![waiter(0, a, &[lo, hi], far, 1), waiter(0, b, &[lo, hi], far, 2)]);
        assert_eq!(released(&mut inner, now), None, "both miss: `hi` stays free for one grace");
        assert_eq!(passed(&inner, vec![lo, hi]), [Some(now), Some(now)], "both graces start: one grace in all");
        assert_eq!(released(&mut inner, now + AFFINITY_GRACE), Some((0, hi)), "then the lighter takes it");

        // Three replicas in one pool: `lo` full, `y` and `hi` with room. The
        // heavy user keeps `hi`; the lighter one, whose own `lo` is full, is
        // headed for `y` — not passed over for `hi`, which it was not going to.
        let y = Uuid::new_v4();
        let (mut inner, lo, hi) = two_endpoints(false, true);
        inner.limits.insert(y, 1);
        inner.in_flight.insert(y, 0);
        let mut key = vec![lo, y, hi];
        key.sort_unstable();
        let (light, heavy) = (user(), user());
        consumed(&mut inner, light, 5.0);
        consumed(&mut inner, heavy, 500.0);
        inner.queues.insert(key.clone(), vec![waiter(0, heavy, &[hi, lo, y], far, 1), waiter(0, light, &[lo, y, hi], far, 2)]);
        assert_eq!(released(&mut inner, now), Some((0, hi)), "the heavy user keeps its engine");
        assert_eq!(passed(&inner, key), [None, None], "the lighter one was headed for `y`");
    }

    #[test]
    fn in_the_last_stretch_of_its_hold_a_waiter_takes_any_engine() {
        let now = Instant::now();
        let (mut inner, _, hi) = light_on_lo_heavy_on_hi(now, now + Duration::from_millis(1));
        assert_eq!(released(&mut inner, now), Some((1, hi)), "a millisecond before, it still waits for its own");
        let (mut inner, _, hi) = light_on_lo_heavy_on_hi(now, now);
        assert_eq!(released(&mut inner, now), Some((0, hi)), "from then on, it takes the first engine free");
    }

    #[test]
    fn the_grace_never_reaches_into_the_last_stretch_of_a_hold() {
        let t = Instant::now();
        // A long hold gives up its engine one grace before its deadline …
        assert_eq!(affinity_ends(t, Duration::from_secs(12)), t + Duration::from_secs(7));
        // … a short one at half its hold, so the grace never outweighs the hold.
        assert_eq!(affinity_ends(t, Duration::from_secs(8)), t + Duration::from_secs(4));
        assert_eq!(affinity_ends(t, AFFINITY_GRACE * 2), t + AFFINITY_GRACE);
        // A hold too long to be an instant waits for its engine not at all —
        // and does not panic.
        assert_eq!(affinity_ends(t, Duration::MAX), t);
    }

    #[test]
    fn no_cache_puts_a_lesser_class_ahead() {
        // The interactive turn's engine is full; the background turn's has
        // room. The interactive one waits for its own engine for a grace, and
        // the background one does not take the engine it turned down; after
        // the grace the interactive one goes first — to the other engine.
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let now = Instant::now();
        let later = now + Duration::from_secs(600);
        inner.queues.insert(
            vec![lo, hi],
            vec![waiter(20, user(), &[hi, lo], later, 1), waiter(0, user(), &[lo, hi], later, 2)],
        );
        assert_eq!(released(&mut inner, now), None);
        assert_eq!(released(&mut inner, now + AFFINITY_GRACE - Duration::from_millis(1)), None);
        assert_eq!(released(&mut inner, now + AFFINITY_GRACE), Some((1, hi)));
    }

    #[test]
    fn a_waiter_whose_engine_is_full_leaves_an_idle_engine_idle_for_one_grace_then_takes_it() {
        let now = Instant::now();
        let (mut inner, lo, hi) = two_endpoints(false, true);
        inner.queues.insert(vec![lo, hi], vec![waiter(0, user(), &[lo, hi], now + Duration::from_secs(600), 1)]);
        assert_eq!(released(&mut inner, now), None, "`lo` is its engine: it waits for it");
        assert_eq!(inner.grace_wake, Some(now + AFFINITY_GRACE), "and the queue is looked at again when the grace ends");
        let held_since = |inner: &Inner| inner.queues[&vec![lo, hi]][0].passed_over_at;
        assert_eq!(held_since(&inner), Some(now));
        inner.grace_wake = None;
        let just_before = now + AFFINITY_GRACE - Duration::from_millis(1);
        assert_eq!(released(&mut inner, just_before), None);
        assert_eq!(held_since(&inner), Some(now), "the grace runs from the first time, not from the latest");
        assert_eq!(released(&mut inner, now + AFFINITY_GRACE), Some((0, hi)));
        // Its own engine freeing within the grace serves it there.
        let (mut inner, lo, hi) = two_endpoints(true, true);
        inner.queues.insert(vec![lo, hi], vec![waiter(0, user(), &[lo, hi], now + Duration::from_secs(600), 1)]);
        assert_eq!(released(&mut inner, now), Some((0, lo)));
        // A short hold waits only until its last stretch begins.
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let ends = now + Duration::from_secs(2);
        inner.queues.insert(vec![lo, hi], vec![waiter(0, user(), &[lo, hi], ends, 1)]);
        assert_eq!(released(&mut inner, now), None);
        assert_eq!(inner.grace_wake, Some(ends), "the wake is the earlier of the grace and the last stretch");
        assert_eq!(released(&mut inner, ends), Some((0, hi)));
    }

    #[test]
    fn another_waiters_wait_never_runs_a_waiter_out() {
        // The interactive turn waits for its full `lo` and closes `hi`; the
        // background turn's own engine is `hi`. Until the last stretch of its
        // hold it waits behind the interactive one; in it, it takes `hi`.
        let now = Instant::now();
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let background_ends = now + Duration::from_secs(2);
        inner.queues.insert(
            vec![lo, hi],
            vec![waiter(0, user(), &[lo, hi], now + Duration::from_secs(600), 1), waiter(20, user(), &[hi, lo], background_ends, 2)],
        );
        assert_eq!(released(&mut inner, now), None, "class order: it waits behind the interactive turn");
        assert_eq!(inner.grace_wake, Some(background_ends.min(now + AFFINITY_GRACE)), "woken for its last stretch");
        assert_eq!(released(&mut inner, background_ends), Some((1, hi)), "its last stretch is not spent waiting");
    }

    #[test]
    fn a_waiter_with_no_engine_of_its_own_takes_any_at_once() {
        let now = Instant::now();
        let (mut inner, lo, hi) = two_endpoints(false, true);
        let mut w = waiter(0, user(), &[lo, hi], now + Duration::from_secs(600), 1);
        w.preferred = None;
        inner.queues.insert(vec![lo, hi], vec![w]);
        assert_eq!(released(&mut inner, now), Some((0, hi)));
        assert_eq!(inner.grace_wake, None);
    }

    #[test]
    fn what_a_waiter_turns_down_closes_only_its_own_engines() {
        // Pool 1's interactive turn waits for its full `lo1` and turns `hi1`
        // down; a background turn of another pool, on other engines, still
        // goes to its own free one.
        let now = Instant::now();
        let far = now + Duration::from_secs(600);
        let (mut inner, lo1, hi1) = two_endpoints(false, true);
        let other = Uuid::new_v4();
        inner.limits.insert(other, 1);
        inner.in_flight.insert(other, 0);
        inner.queues.insert(vec![lo1, hi1], vec![waiter(0, user(), &[lo1, hi1], far, 1)]);
        inner.queues.insert(vec![other], vec![waiter(20, user(), &[other], far, 2)]);
        assert_eq!(released(&mut inner, now).map(|(_, e)| e), Some(other));
    }

    proptest! {
        /// Whatever waits, on whatever engine: a release is of the most
        /// important class waiting, to an endpoint with room — its own when its
        /// own has room — and never sends a waiter away from its own engine
        /// within its grace. Nothing is released exactly when every waiter of
        /// that class is still waiting for its own full engine. NOT claimed:
        /// anything about pools that share no engine (each is its own order).
        #[test]
        fn a_release_keeps_the_class_order_and_waits_for_the_sessions_engine(
            room in prop_oneof![Just((true, false)), Just((false, true)), Just((true, true))],
            waiters in proptest::collection::vec((0i32..3, any::<bool>(), 0u32..1000, any::<bool>()), 1..12),
        ) {
            let (mut inner, lo, hi) = two_endpoints(room.0, room.1);
            let now = Instant::now() + Duration::from_secs(60);
            let mut queue = Vec::new();
            for (seq, (rank, on_lo, used, grace_over)) in waiters.iter().copied().enumerate() {
                let scope = user();
                consumed(&mut inner, scope, f64::from(used));
                let order = if on_lo { [lo, hi] } else { [hi, lo] };
                let mut w = waiter(rank, scope, &order, now + Duration::from_secs(600), seq as u64);
                if grace_over {
                    w.passed_over_at = Some(now - AFFINITY_GRACE);
                }
                queue.push(w);
            }
            let has_room = |id: Uuid| if id == lo { room.0 } else { room.1 };
            let would_miss = |w: &Waiter| !has_room(w.order[0]) && w.passed_over_at.is_none_or(|t| now < t + AFFINITY_GRACE);
            let top = queue.iter().map(|w| w.rank).min().expect("non-empty");
            let top_all_miss = queue.iter().filter(|w| w.rank == top).all(would_miss);
            inner.queues.insert(vec![lo, hi], queue);

            let released = released(&mut inner, now);
            prop_assert_eq!(released.is_none(), top_all_miss);
            if let Some((index, endpoint)) = released {
                let w = &inner.queues[&vec![lo, hi]][index];
                prop_assert_eq!(w.rank, top);
                prop_assert!(has_room(endpoint));
                if has_room(w.order[0]) {
                    prop_assert_eq!(endpoint, w.order[0]);
                }
                prop_assert!(!would_miss(w));
            }
        }
    }

    #[tokio::test]
    async fn one_reading_does_not_let_a_whole_backlog_out() {
        // A reading is a snapshot. An endpoint bounded only by its engine's own
        // queue would otherwise empty the gateway's entire backlog into it on
        // the strength of one "there is room" — burying the bound the operator
        // set until the next poll notices.
        let gate = gate();
        // "Send nothing while anything is waiting there" — the strictest
        // setting an operator can give, and the one that shows the accounting.
        let ep = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: Some(0), adaptive: false };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 0, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );

        // The engine's queue is empty, so one goes out.
        let first = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(first.outcome, GateOutcome::Immediate);
        // And now it is not empty any more, whatever the last reading said.
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);

        // A fresh reading replaces the estimate with what the engine says. Taken
        // the way the poller takes one: the mark is read at the same instant,
        // so what went out before it is the engine's business, not ours.
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1,
                waiting: 0,
                running: None,
                kv_usage: None,
                read_at: Instant::now(),
                mark: gate.dispatch_mark(ep.id),
                counters: Default::default(),
            },
        );
        let next = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(next.outcome, GateOutcome::Immediate);
        drop(first);
        drop(next);
    }

    #[tokio::test]
    async fn one_pool_cannot_take_every_hold_the_gateway_has() {
        // The process-wide budget is a shared resource; a single saturated pool
        // filling it would refuse another tenant's briefly-busy endpoint through
        // a knob that tenant cannot see.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 1,
            ..GateSettings::default()
        }));
        let (hog, other) = (endpoint(1), endpoint(1));
        let _busy_hog = gate.acquire(request(&[hog], user(), 0)).await.expect("dispatched");
        let _busy_other = gate.acquire(request(&[other], user(), 0)).await.expect("dispatched");

        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[hog], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // That pool has taken its share and refuses more...
        let mut more_of_the_same = request(&[hog], user(), 0);
        more_of_the_same.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(more_of_the_same).await.unwrap_err(), GateRefusal::Overloaded);
        // ...while the other pool can still hold one, which is the point.
        let mut elsewhere = request(&[other], user(), 0);
        elsewhere.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(elsewhere).await.unwrap_err(), GateRefusal::Timeout);
        let _ = held.await;
    }

    #[tokio::test]
    async fn one_pool_is_one_queue_whatever_order_its_endpoints_arrive_in() {
        // Routing hands the same replicas over in a per-request order — session
        // affinity, weighted round-robin, the breaker's health reorder. Keyed as
        // given, one pool would split into a queue per permutation, each taking
        // its own share of the process-wide hold budget: the bound would be
        // worth as many holds as the pool can be spelled.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 8,
            max_held_per_pool: 1,
            ..GateSettings::default()
        }));
        let (a, b) = (endpoint(1), endpoint(1));
        let both = [a, b];
        let _busy_a = gate.acquire(request(&both, user(), 0)).await.expect("dispatched");
        let _busy_b = gate.acquire(request(&[b, a], user(), 0)).await.expect("dispatched");

        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&both, user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // The pool has taken its one share. Named the other way round, it is the
        // same pool and has still taken it.
        let mut reversed = request(&[b, a], user(), 0);
        reversed.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(reversed).await.unwrap_err(), GateRefusal::Overloaded);
        let _ = held.await;
    }

    #[tokio::test]
    async fn a_request_that_is_over_stops_counting_against_the_engines_queue() {
        // The provisional charge stands in for a request that has reached the
        // engine but not yet the gauge that reports it. Once it is over it is in
        // neither, so it comes back off. Left standing, a gateway busy between
        // two polls would read an idle engine as over its threshold and hold
        // everything until the next reading.
        let gate = gate();
        let ep = GateEndpoint {
            id: Uuid::new_v4(),
            max_in_flight: Some(1),
            waiting_threshold: Some(0),
            adaptive: false,
        };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 0, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );

        let first = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        drop(first);
        // Same reading, and the engine is idle again on both counts.
        let next = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(next.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn an_endpoint_with_requests_waiting_on_it_is_not_forgotten() {
        // Taking a replica out of the configuration while requests wait on it
        // must not make it look free: releasing that queue would send the flood
        // straight at the engine the operator just disabled.
        let gate = gate();
        let ep = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: Some(0), adaptive: false };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 5, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1);

        gate.retain_endpoints(&std::collections::HashSet::new(), &std::collections::HashSet::new());
        gate.reconsider();
        assert_eq!(gate.stats().queue_depth, 1, "the waiter was not released to a dropped endpoint");
        let _ = waiting.await;
    }

    #[tokio::test]
    async fn a_bound_an_operator_cleared_stops_being_applied_to_whoever_is_queued() {
        // Nothing brings a queued request back to the gate to be re-judged: a
        // later request for the same endpoint now takes the ungated fast path,
        // which touches no state at all. So the release path would go on
        // measuring the waiter against a limit that no longer exists, and it
        // would sit out its whole deadline beside requests going straight out.
        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1);

        // The endpoint is still there; what it declares is not.
        let live: std::collections::HashSet<Uuid> = [ep.id].into_iter().collect();
        gate.retain_endpoints(&live, &std::collections::HashSet::new());
        gate.reconsider();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            gate.stats().queue_depth,
            0,
            "the waiter is still being judged by a bound that is gone"
        );
        drop(busy);
        let _ = held.await;
    }

    #[tokio::test]
    async fn an_endpoint_that_has_never_reported_is_bounded_by_in_flight_alone() {
        // A metrics read that never arrived must not read as "no headroom" —
        // that would stall a healthy pool over a monitoring outage.
        let gate = gate();
        let ep = GateEndpoint {
            id: Uuid::new_v4(),
            max_in_flight: Some(1),
            waiting_threshold: Some(0),
            adaptive: false,
        };
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn a_second_endpoint_takes_what_the_first_cannot() {
        let gate = gate();
        let (a, b) = (endpoint(1), endpoint(1));
        let first = gate.acquire(request(&[a, b], user(), 0)).await.expect("dispatched");
        // No engine of its own to wait for (one whose own engine is full waits
        // for it first: `an_arrival_whose_engine_is_full_waits_for_it_rather_than_take_another`).
        let mut req = request(&[a, b], user(), 0);
        req.preferred = None;
        let second = gate.acquire(req).await.expect("dispatched");
        assert_eq!(first.endpoint(), Some(a.id));
        assert_eq!((second.endpoint(), second.outcome), (Some(b.id), GateOutcome::Immediate), "the full endpoint is skipped");
    }

    #[tokio::test]
    async fn a_caller_that_gives_up_does_not_take_a_sibling_out_of_the_queue() {
        // One user, two requests waiting. The first gives up at its own deadline;
        // the second must still be released when a slot frees. Identifying a
        // waiter by its scope rather than by itself would remove the sibling
        // here, leaving a caller queued that nothing can ever release.
        let gate = gate();
        let ep = endpoint(1);
        let scope = user();
        let busy = gate.acquire(request(&[ep], scope, 10)).await.expect("dispatched");

        // The patient one queues FIRST, so the one that gives up is not the
        // oldest of its scope — which is exactly the case a scope-keyed removal
        // gets wrong.
        let patient = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], scope, 10)).await }
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        let impatient = tokio::spawn({
            let gate = gate.clone();
            async move {
                let mut req = request(&[ep], scope, 10);
                req.ttl = Duration::from_millis(40);
                gate.acquire(req).await.map(|_| ())
            }
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(gate.stats().queue_depth, 2);

        // The first deadline passes with the slot still held.
        assert_eq!(impatient.await.expect("task").unwrap_err(), GateRefusal::Timeout);
        assert_eq!(gate.stats().queue_depth, 1, "the sibling is still queued");

        drop(busy);
        let permit = patient.await.expect("task").expect("the sibling is released");
        drop(permit);
    }

    #[test]
    fn every_refusal_says_which_one_it_was() {
        // The word reaches the audit row's category and the operator's log. Two
        // refusals that read the same are two outages that cannot be told apart.
        let words: Vec<&str> = [
            GateRefusal::Shed,
            GateRefusal::Timeout,
            GateRefusal::Overloaded,
            GateRefusal::ShuttingDown,
            GateRefusal::Superseded,
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        assert_eq!(words, ["shed", "queue_timeout", "gateway_saturated", "shutting_down", "superseded"]);
    }

    #[tokio::test]
    async fn output_is_charged_by_what_it_costs_and_by_the_workspaces_share() {
        // Generating is the scarce work, so an output token counts for more than
        // an input one; a workspace with a bigger share pays proportionally less
        // for the same work. Both factors decide who waits, so both are pinned.
        let gate = gate();
        let ep = endpoint(4);
        let scope = user();
        let mut req = request(&[ep], scope, 10);
        req.weight = 2;
        req.output_weight = 3.0;
        req.input_tokens = 100;
        let permit = gate.acquire(req).await.expect("dispatched");
        // Admission: 100 input tokens over a share of 2.
        assert_eq!(gate.lock().counters.get(&scope).expect("counted").weighted, 50.0);
        permit.charge_output(20);
        // Plus 20 output tokens at 3× an input token, over the same share.
        assert_eq!(gate.lock().counters.get(&scope).expect("counted").weighted, 80.0);
        drop(permit);
    }

    #[tokio::test]
    async fn a_caller_gone_before_its_turn_comes_does_not_wedge_the_release() {
        // The other cancellation order: the caller is already gone when the slot
        // frees. Its place went with it, so the release finds nobody to hand
        // the slot to — and must neither deadlock nor lose the endpoint.
        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiting.abort();
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(busy);
        assert_eq!(gate.stats().in_flight, 0);
        assert_eq!(gate.stats().queue_depth, 0);
        // The gate still works: it neither deadlocked nor lost the endpoint.
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn a_slot_offered_to_a_receiver_already_gone_goes_back_without_deadlocking() {
        // A caller's place leaves the queue with it (`QueuedGuard`), so a
        // hand-over to a receiver that is gone takes a waiter put there by
        // hand. It must still be undone where it was made — inside the gate's
        // own lock, where the grant's own release would deadlock.
        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        {
            let mut inner = gate.lock();
            inner.seq += 1;
            let seq = inner.seq;
            inner.held += 1;
            inner.queues.entry(vec![ep.id]).or_default().push(waiter(0, user(), &[ep.id], Instant::now(), seq));
        }
        drop(busy);
        assert_eq!((gate.stats().in_flight, gate.stats().queue_depth), (0, 0));
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
    }

    #[tokio::test]
    async fn an_endpoint_the_configuration_dropped_is_forgotten_unless_it_is_busy() {
        let gate = gate();
        let (gone, kept) = (endpoint(1), endpoint(1));
        let running = gate.acquire(request(&[gone], user(), 0)).await.expect("dispatched");
        gate.record_load(
            kept.id,
            EndpointLoad { ranks: 1, waiting: 1, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let _ = gate.acquire(request(&[kept], user(), 0)).await.expect("dispatched");

        // Neither is in the configuration any more — but one still has work in
        // flight, and its permit will come back looking for its counter.
        gate.retain_endpoints(&std::collections::HashSet::new(), &std::collections::HashSet::new());
        {
            let inner = gate.lock();
            assert!(inner.in_flight.contains_key(&gone.id), "the busy endpoint is kept");
            assert!(!inner.load.contains_key(&kept.id), "the idle one is forgotten");
        }
        drop(running);
        gate.retain_endpoints(&std::collections::HashSet::new(), &std::collections::HashSet::new());
        assert!(gate.lock().in_flight.is_empty(), "and forgotten once it is idle");
    }

    #[tokio::test]
    async fn a_queue_held_against_an_expired_reading_is_looked_at_again() {
        // The endpoint is gated by the engine's own queue alone, so there is no
        // in-flight count of ours to release and no new reading arriving — the
        // two things that normally reconsider the queue. Without a periodic
        // nudge the waiters sit out their deadline while anything arriving
        // after the expiry goes straight out.
        let gate = Arc::new(DispatchGate::new(GateSettings {
            load_max_age: Duration::from_millis(40),
            ..GateSettings::default()
        }));
        let ep = GateEndpoint { id: Uuid::new_v4(), max_in_flight: None, waiting_threshold: Some(1), adaptive: false };
        gate.record_load(
            ep.id,
            EndpointLoad { ranks: 1, waiting: 9, running: None, kv_usage: None, read_at: Instant::now(), mark: 0, counters: Default::default() },
        );
        let waiting = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|p| p.outcome) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1);

        // The reading ages out and nobody reports anything new.
        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.reconsider();
        assert_eq!(waiting.await.expect("task"), Ok(GateOutcome::Held));
    }

    #[tokio::test]
    async fn the_mark_a_reading_carries_counts_what_has_been_sent() {
        // A reading is only worth the count it is measured against: if the mark
        // does not move with dispatches, the difference between it and the live
        // counter is not what the engine's gauge has yet to see — it is a
        // constant, and the provisional accounting silently stops working.
        let gate = gate();
        let ep = endpoint(4);
        assert_eq!(gate.dispatch_mark(ep.id), 0);
        let first = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(gate.dispatch_mark(ep.id), 1);
        let second = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(gate.dispatch_mark(ep.id), 2);
        // And it does not wind back: it marks what was sent, not what is still
        // out — which is what the in-flight cap is for.
        drop(first);
        drop(second);
        assert_eq!(gate.dispatch_mark(ep.id), 2);
    }

    #[tokio::test]
    async fn an_idle_users_counter_is_not_the_floor_an_arrival_is_lifted_to() {
        // The floor exists so a caller arriving from idle starts level with the
        // people who kept working. Measured across everyone the gate REMEMBERS
        // rather than everyone currently working, it would be the lowest
        // counter of anyone who has ever been here — so an arrival would be
        // lifted to nothing and go ahead of the caller it should queue behind.
        let gate = gate();
        let ep = endpoint(4);
        let (quiet, working, arriving) = (user(), user(), user());

        // Someone cheap goes out first, so the expensive one is not lifted to
        // their level: that leaves a low counter beside a high one.
        let done = gate.acquire(request(&[ep], quiet, 0)).await.expect("dispatched");
        let mut heavy = request(&[ep], working, 0);
        heavy.input_tokens = 1_000;
        let _busy = gate.acquire(heavy).await.expect("dispatched");
        // The cheap one stops. Its counter stays — someone else is still
        // working, so the gateway is not quiet and nothing is cleared.
        drop(done);

        // The newcomer starts level with the one still working.
        let _new = gate.acquire(request(&[ep], arriving, 0)).await.expect("dispatched");
        assert_eq!(
            gate.lock().counters.get(&arriving).map(|c| c.weighted),
            Some(1_000.0),
            "lifted to the counter of someone idle instead of someone working"
        );
    }

    #[tokio::test]
    async fn a_request_that_never_ran_costs_its_caller_nothing() {
        // Refusals and give-ups charge nothing: the work was never done, and a
        // caller who was turned away must not fall behind for it.
        let gate = gate();
        let ep = endpoint(1);
        let (running, refused) = (user(), user());
        let busy = gate.acquire(request(&[ep], running, 10)).await.expect("dispatched");

        let mut shed = request(&[ep], refused, 20);
        shed.sheddable = true;
        shed.input_tokens = 10_000;
        assert_eq!(gate.acquire(shed).await.unwrap_err(), GateRefusal::Shed);

        let mut timed_out = request(&[ep], refused, 10);
        timed_out.input_tokens = 10_000;
        timed_out.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(timed_out).await.unwrap_err(), GateRefusal::Timeout);

        assert_eq!(gate.lock().counters.get(&refused).map(|c| c.weighted), None);
        drop(busy);
    }

    #[tokio::test]
    async fn a_refused_wait_leaves_no_slot_behind() {
        let gate = gate();
        let ep = endpoint(1);
        let busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);
        // The engine is still holding exactly the one request that is running.
        assert_eq!(gate.stats().in_flight, 1);
        drop(busy);
        assert_eq!(gate.stats().in_flight, 0);
    }

    #[tokio::test]
    async fn the_gateway_refuses_rather_than_holding_more_than_it_may() {
        let gate = Arc::new(DispatchGate::new(GateSettings {
            max_held: 1,
            ..GateSettings::default()
        }));
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(30);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Overloaded);
        let _ = held.await;
    }

    #[tokio::test]
    async fn shutting_down_still_serves_what_it_can_serve_now() {
        // The replica stays in its load balancer's rotation for a few seconds
        // after SIGTERM. Refusing a request the pool has room for would make an
        // ordinary rolling restart look like an outage to everyone in flight.
        let gate = gate();
        let ep = endpoint(1);
        gate.begin_shutdown();
        let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        assert_eq!(permit.outcome, GateOutcome::Immediate);
        // ...but the next one, which would have to wait, is turned away at once.
        assert_eq!(
            gate.acquire(request(&[ep], user(), 0)).await.unwrap_err(),
            GateRefusal::ShuttingDown
        );
        drop(permit);
    }

    #[tokio::test]
    async fn a_waiter_that_never_takes_its_slot_is_not_charged_for_it() {
        // The charge happens when the slot is handed over, so the caller that
        // vanishes in between must get it back — otherwise a client that keeps
        // disconnecting while queued falls behind for work nobody did.
        use std::task::{Context, Poll};

        let gate = gate();
        let ep = endpoint(1);
        let (running, ghost) = (user(), user());
        let busy = gate.acquire(request(&[ep], running, 0)).await.expect("dispatched");

        let mut waiting = Box::pin(async {
            let mut req = request(&[ep], ghost, 0);
            req.input_tokens = 5_000;
            gate.acquire(req).await.map(|_| ())
        });
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Pending));

        drop(busy);
        drop(waiting);
        let counted = gate.lock().counters.get(&ghost).map(|c| c.weighted).unwrap_or(0.0);
        assert_eq!(counted, 0.0, "the request never ran, so it costs nothing");
    }

    #[tokio::test]
    async fn shutting_down_refuses_every_hold_instead_of_outliving_the_process() {
        let gate = gate();
        let ep = endpoint(1);
        let _busy = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate.begin_shutdown();
        assert_eq!(held.await.expect("task").unwrap_err(), GateRefusal::ShuttingDown);
        assert_eq!(
            gate.acquire(request(&[ep], user(), 0)).await.unwrap_err(),
            GateRefusal::ShuttingDown
        );
    }

    #[tokio::test]
    async fn a_user_arriving_beside_a_heavy_one_banks_no_credit() {
        // A user who was not here while someone else worked does not arrive with
        // a credit to spend: they start level with the users who kept working.
        let gate = gate();
        let ep = endpoint(2);
        let (heavy, newcomer) = (user(), user());
        let running = gate.acquire(request(&[ep], heavy, 10)).await.expect("dispatched");
        running.charge_output(5_000);

        let permit = gate.acquire(request(&[ep], newcomer, 10)).await.expect("dispatched");
        {
            let inner = gate.lock();
            let newcomer = inner.counters.get(&newcomer).expect("counted").weighted;
            let heavy = inner.counters.get(&heavy).expect("counted").weighted;
            assert_eq!(newcomer, heavy, "the newcomer starts level, not ahead");
        }
        drop(permit);
        drop(running);
    }

    #[tokio::test]
    async fn a_slot_nobody_took_gives_back_both_the_charge_and_the_slot() {
        // The hand-over reserves before it sends: the waiter's scope is charged
        // and the slot started, then the grant goes out. A grant that is never
        // claimed — the caller disappeared between the two — must undo BOTH.
        // Left behind, the charge orders every later request against work that
        // never ran, and the slot stays out of service for the life of the
        // process.
        let gate = gate();
        let ep = endpoint(1);

        // Someone else keeps working throughout: consumption is dropped
        // wholesale once the gateway goes quiet, which would answer the
        // question without the refund ever running.
        let other = gate.acquire(request(&[endpoint(1)], user(), 0)).await.expect("dispatched");
        other.charge_output(5_000);

        let scope = user();
        let floor = gate.lock().active_floor();
        assert!(floor > 0.0, "the other caller has consumed something to come back to");
        {
            let mut inner = gate.lock();
            inner.charge_scope(scope, 12.0);
            inner.start(ep.id, scope);
        }
        assert_eq!(gate.lock().counters[&scope].weighted, floor + 12.0, "charged on reservation");
        assert_eq!(gate.stats().in_flight, 2);

        drop(SlotGrant { gate: Some(gate.clone()), endpoint: ep.id, scope, charge: 12.0 });

        assert_eq!(
            gate.lock().counters[&scope].weighted,
            floor,
            "the charge for a request that never ran is given back, and only that"
        );
        assert_eq!(gate.stats().in_flight, 1, "and the slot goes back to whoever is next");
        drop(other);
    }

    #[tokio::test]
    async fn consumption_is_kept_while_anything_is_still_running() {
        // The busy period ends when the gateway holds NOTHING — not when the
        // queue happens to be empty. Forgetting while requests are in flight
        // would reset the order mid-flight and hand the next slot to whoever
        // asked most recently.
        let gate = gate();
        let ep = endpoint(2);
        let (heavy, other) = (user(), user());
        let running = gate.acquire(request(&[ep], heavy, 10)).await.expect("dispatched");
        running.charge_output(5_000);
        let second = gate.acquire(request(&[ep], other, 10)).await.expect("dispatched");

        // One finishes; nobody is waiting, but the other is still running.
        drop(second);
        assert!(
            gate.lock().counters.get(&heavy).is_some_and(|c| c.weighted > 0.0),
            "what the running caller consumed is still counted"
        );
        drop(running);
        assert!(gate.lock().counters.is_empty(), "and forgotten once nothing is left");
    }

    #[tokio::test]
    async fn what_a_user_consumed_is_forgotten_once_the_gateway_goes_quiet() {
        let gate = gate();
        let ep = endpoint(1);
        let (heavy, later) = (user(), user());
        let running = gate.acquire(request(&[ep], heavy, 10)).await.expect("dispatched");
        running.charge_output(10_000);
        drop(running);

        // Nothing is in flight and nobody is waiting: that busy period is over.
        assert!(gate.lock().counters.is_empty());

        // So the next one starts level for everyone.
        let a = gate.acquire(request(&[ep], heavy, 10)).await.expect("dispatched");
        let inner_heavy = gate.lock().counters.get(&heavy).expect("counted").weighted;
        drop(a);
        let b = gate.acquire(request(&[ep], later, 10)).await.expect("dispatched");
        let inner_later = gate.lock().counters.get(&later).expect("counted").weighted;
        drop(b);
        assert_eq!(inner_heavy, inner_later);
    }

    proptest! {
        /// Between two users who are both backlogged, the gate never serves one
        /// arbitrarily far ahead of the other: the difference in what they have
        /// consumed stays bounded by one request's charge. That is the property
        /// a fairness scheduler exists to hold — dropping it silently would look
        /// exactly like a busy pool.
        #[test]
        fn two_backlogged_users_stay_within_one_request_of_each_other(
            charges in prop::collection::vec(1u32..500, 20..60),
        ) {
            let mut inner = Inner::default();
            let (a, b) = ((Uuid::from_u128(1), Uuid::from_u128(2)),
                          (Uuid::from_u128(1), Uuid::from_u128(3)));
            // Both users are always backlogged: one request each is in flight
            // for the whole run, so neither is ever idle-lifted.
            inner.counters.entry(a).or_default().active = 1;
            inner.counters.entry(b).or_default().active = 1;
            let max_charge = f64::from(*charges.iter().max().expect("non-empty"));

            for charge in charges {
                // The gate always serves whoever has consumed less; that user
                // then pays for the request it was given.
                let ca = inner.counters.get(&a).map(|c| c.weighted).unwrap_or(0.0);
                let cb = inner.counters.get(&b).map(|c| c.weighted).unwrap_or(0.0);
                let next = if ca <= cb { a } else { b };
                inner.charge_scope(next, f64::from(charge));
            }

            let ca = inner.counters.get(&a).map(|c| c.weighted).unwrap_or(0.0);
            let cb = inner.counters.get(&b).map(|c| c.weighted).unwrap_or(0.0);
            prop_assert!(
                (ca - cb).abs() <= max_charge,
                "service difference {} exceeded one request's charge {max_charge}",
                (ca - cb).abs()
            );
        }
    }

    fn adaptive(ceiling: Option<u32>) -> GateEndpoint {
        GateEndpoint { id: Uuid::new_v4(), max_in_flight: ceiling, waiting_threshold: None, adaptive: true }
    }

    /// What the metrics poller does from the configuration on every pass.
    fn adopt(gate: &DispatchGate, ep: GateEndpoint) {
        gate.adopt_configuration(&[(ep.id, bounds(ep.max_in_flight, ep.adaptive))].into());
    }

    fn bounds(max_in_flight: Option<u32>, adaptive: bool) -> EndpointBounds {
        EndpointBounds {
            gated: max_in_flight.is_some() || adaptive,
            max_in_flight,
            waiting_threshold: None,
            adaptive,
            itl_target: ItlTarget::Off,
            url: "http://engine".to_string(),
            engine_read: adaptive,
        }
    }

    fn reading(kv: f64, preemptions: f64) -> EndpointLoad {
        EndpointLoad { ranks: 1,
            waiting: 0,
            running: Some(0),
            kv_usage: Some(kv),
            read_at: Instant::now(),
            mark: 0,
            counters: super::super::qos_metrics::EngineCounters { preemptions: Some(preemptions), ..Default::default() },
        }
    }

    async fn fill(gate: &Arc<DispatchGate>, ep: GateEndpoint, n: usize) -> Vec<GatePermit> {
        let mut permits = Vec::new();
        for _ in 0..n {
            let permit = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
            assert_eq!(permit.outcome, GateOutcome::Immediate);
            permits.push(permit);
        }
        permits
    }

    #[tokio::test]
    async fn adopting_asks_for_a_reading_only_when_what_was_read_no_longer_applies() {
        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let id = Uuid::new_v4();
        let at = |url: &str, threshold: Option<u32>, adaptive: bool| {
            HashMap::from([(
                id,
                EndpointBounds {
                    gated: threshold.is_some() || adaptive,
                    max_in_flight: Some(4),
                    waiting_threshold: threshold,
                    adaptive,
                    itl_target: ItlTarget::Off,
                    url: url.to_string(),
                    engine_read: threshold.is_some() || adaptive,
                },
            )])
        };
        assert!(gate.adopt_configuration(&at("http://a", None, false)).is_empty(), "an endpoint nothing reads needs no reading");
        assert_eq!(gate.adopt_configuration(&at("http://a", Some(2), false)), [id].into(), "a queue bound just added needs its engine read");
        gate.record_load(id, reading(0.1, 0.0));
        assert!(gate.snapshot().engine.contains_key(&id));
        assert!(gate.adopt_configuration(&at("http://a", Some(2), false)).is_empty(), "unchanged: what was read still applies");
        assert!(gate.snapshot().engine.contains_key(&id), "an unchanged endpoint keeps its reading");
        assert_eq!(gate.adopt_configuration(&at("http://b", Some(2), false)), [id].into(), "moved: the new machine is unread");
        assert!(!gate.snapshot().engine.contains_key(&id), "the old machine's reading is dropped");
        gate.record_load(id, reading(0.1, 0.0));
        assert_eq!(gate.adopt_configuration(&at("http://b", Some(2), true)), [id].into(), "a learned window just created is unread");
        assert!(gate.adopt_configuration(&at("http://b", Some(2), true)).is_empty(), "an existing window on the same machine is read");
    }

    #[tokio::test]
    async fn a_busy_endpoint_that_moves_keeps_its_reading_until_the_new_machine_is_read() {
        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let id = Uuid::new_v4();
        let at = |url: &str| {
            HashMap::from([(
                id,
                EndpointBounds { waiting_threshold: Some(2), engine_read: true, url: url.to_string(), ..bounds(Some(4), false) },
            )])
        };
        gate.adopt_configuration(&at("http://a"));
        assert_eq!(gate.record_read(id, "http://a", reading(0.1, 0.0)), Placement::Here);
        let ep = GateEndpoint { id, max_in_flight: Some(4), waiting_threshold: Some(2), adaptive: false };
        let running = gate.acquire(request(&[ep], user(), 0)).await.expect("dispatched");
        // Moved while work runs on it: the reading is what holds its queue
        // back, so it stays until the new machine's replaces it.
        gate.adopt_configuration(&at("http://b"));
        assert!(gate.snapshot().engine.contains_key(&id), "a busy endpoint keeps its reading across a move");
        assert_eq!(gate.record_read(id, "http://b", reading(0.2, 0.0)), Placement::Here, "the new machine's reading replaces it");
        drop(running);
        // Positive control: moved while idle, the reading goes.
        gate.adopt_configuration(&at("http://c"));
        assert!(!gate.snapshot().engine.contains_key(&id), "an idle endpoint's reading goes with the move");
    }

    #[tokio::test]
    async fn a_reading_of_where_an_endpoint_no_longer_is_is_not_recorded() {
        let gate = Arc::new(DispatchGate::new(GateSettings::default()));
        let (id, gone) = (Uuid::new_v4(), Uuid::new_v4());
        let read_at = |url: &str| EndpointBounds { waiting_threshold: Some(2), engine_read: true, url: url.to_string(), ..bounds(Some(4), false) };
        gate.adopt_configuration(&HashMap::from([(id, read_at("http://a")), (gone, read_at("http://g"))]));
        // A pass begun under that configuration; the endpoint moves and the
        // other is dropped before its readings come back.
        gate.adopt_configuration(&HashMap::from([(id, read_at("http://b"))]));
        assert_eq!(gate.record_read(id, "http://a", reading(0.1, 0.0)), Placement::Moved, "the old machine's reading");
        assert_eq!(gate.record_read(gone, "http://g", reading(0.1, 0.0)), Placement::Dropped, "a dropped endpoint's reading");
        assert!(gate.snapshot().engine.is_empty());
        // Every endpoint dropped: still nothing is recorded.
        gate.adopt_configuration(&HashMap::new());
        assert_eq!(gate.record_read(id, "http://b", reading(0.1, 0.0)), Placement::Dropped, "with no endpoint configured at all");
        gate.adopt_configuration(&HashMap::from([(id, read_at("http://b"))]));
        // Positive control: a reading of where it is now is recorded.
        assert_eq!(gate.record_read(id, "http://b", reading(0.1, 0.0)), Placement::Here);
        assert!(gate.snapshot().engine.contains_key(&id));
    }

    #[tokio::test]
    async fn a_learned_limit_applies_only_while_its_engine_is_heard() {
        let gate = Arc::new(DispatchGate::new(GateSettings {
            load_max_age: Duration::from_millis(80),
            ..GateSettings::default()
        }));
        let ep = adaptive(Some(6));
        adopt(&gate, ep);
        // Unheard: the ceiling is the limit.
        let permits = fill(&gate, ep, 6).await;
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(10);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout, "the ceiling holds");
        drop(permits);

        // Heard: the window (four to start) is the limit, below the ceiling.
        gate.record_load(ep.id, reading(0.1, 0.0));
        let permits = fill(&gate, ep, 4).await;
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(10);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout, "the window holds");
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(4));

        // The reading ages out: back to the ceiling, and the window is kept.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (Some(6), AdaptiveState::NoReading));
        let more = fill(&gate, ep, 2).await;
        drop((permits, more));
    }

    #[tokio::test]
    async fn a_pressed_window_grows_on_the_next_reading_and_releases_what_it_held() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 4).await;
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[ep], user(), 0)).await.map(|p| p.outcome) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1);

        // The engine has room and the window was pressed: it doubles, and the
        // held request goes out without waiting for a release.
        gate.record_load(ep.id, reading(0.2, 0.0));
        assert_eq!(held.await.expect("task"), Ok(GateOutcome::Held));
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (Some(8), AdaptiveState::Probing));
    }

    #[tokio::test]
    async fn the_engines_token_mix_reaches_the_window_and_counts_what_runs_at_its_end() {
        // Four running at 0.4 of the cache, 0.1 each by the gauge, pressed. An
        // engine whose requests finished with answer tokens only: a running
        // request holds twice the average by its end, 0.2 — the four
        // commit 0.8, not one more fits below the target, and the window
        // holds. Without token counters (the positive control) the gauge alone
        // says, and it doubles.
        for (counted, expected) in [(true, (Some(4), AdaptiveState::MemoryBound)), (false, (Some(8), AdaptiveState::Probing))] {
            let gate = gate();
            let ep = adaptive(None);
            adopt(&gate, ep);
            let with_tokens = |load: EndpointLoad, answer: f64| {
                if !counted {
                    return load;
                }
                let counters = super::super::qos_metrics::EngineCounters {
                    finished_prompt_tokens: Some(0.0),
                    finished_generation_tokens: Some(answer),
                    ..load.counters
                };
                EndpointLoad { counters, ..load }
            };
            gate.record_load(ep.id, with_tokens(reading(0.1, 0.0), 0.0));
            let permits = fill(&gate, ep, 4).await;
            let held = tokio::spawn({
                let gate = gate.clone();
                async move { gate.acquire(request(&[ep], user(), 0)).await.map(drop) }
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            gate.record_load(ep.id, with_tokens(EndpointLoad { running: Some(4), ..reading(0.4, 0.0) }, 4_000.0));
            let status = gate.snapshot().adaptive[&ep.id];
            assert_eq!((status.limit, status.state), expected, "token counters: {counted}");
            drop(permits);
            held.await.expect("task").expect("released");
        }
    }

    #[tokio::test]
    async fn an_unpressed_window_does_not_grow() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 3).await;
        gate.record_load(ep.id, reading(0.1, 0.0));
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (Some(4), AdaptiveState::Steady));
    }

    #[tokio::test]
    async fn a_spill_past_a_full_adaptive_endpoint_presses_its_window() {
        let gate = gate();
        let (a, b) = (adaptive(None), endpoint(10));
        adopt(&gate, a);
        gate.record_load(a.id, reading(0.1, 0.0));
        let _on_a = fill(&gate, a, 4).await;
        let mut req = request(&[a, b], user(), 0);
        req.preferred = None;
        let spilled = gate.acquire(req).await.expect("dispatched");
        assert_eq!((spilled.endpoint(), spilled.outcome), (Some(b.id), GateOutcome::Immediate));
        gate.record_load(a.id, reading(0.1, 0.0));
        assert_eq!(gate.snapshot().adaptive[&a.id].limit, Some(8));
    }

    #[tokio::test]
    async fn a_switch_to_a_fixed_limit_applies_to_whoever_is_queued() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 4).await;
        let queued: Vec<_> = (0..4)
            .map(|_| {
                let gate = gate.clone();
                tokio::spawn(async move { gate.acquire(request(&[ep], user(), 0)).await.map(|p| p.outcome) })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 4);
        // Switched to a fixed limit of 5: exactly one more goes out, not all.
        gate.adopt_configuration(&[(ep.id, bounds(Some(5), false))].into());
        gate.reconsider();
        assert_eq!((gate.stats().in_flight, gate.stats().queue_depth), (5, 3));
        drop(queued);
    }

    #[tokio::test]
    async fn a_request_a_change_behind_cannot_set_an_adaptive_ceiling() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        // Routed on the snapshot before the switch: it still says a fixed 1.
        let stale = GateEndpoint { max_in_flight: Some(1), ..ep };
        let _first = gate.acquire(request(&[stale], user(), 0)).await.expect("dispatched");
        let second = gate.acquire(request(&[stale], user(), 0)).await.expect("the window, not the stale 1");
        assert_eq!(second.outcome, GateOutcome::Immediate);
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(4));
    }

    #[tokio::test]
    async fn a_window_is_about_one_machine() {
        let gate = gate();
        let ep = adaptive(None);
        let at = |url: &str| EndpointBounds { url: url.to_string(), ..bounds(None, true) };
        gate.adopt_configuration(&[(ep.id, at("http://a"))].into());
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 4).await;
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(10);
        let _ = gate.acquire(req).await;
        gate.record_load(ep.id, reading(0.1, 0.0));
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(8), "learned on host a");
        // Re-pointed at another machine: what was learned is about the old one.
        gate.adopt_configuration(&[(ep.id, at("http://b"))].into());
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (None, AdaptiveState::Starting));
    }

    #[tokio::test]
    async fn a_queue_bound_the_configuration_cleared_stops_applying_to_whoever_waits() {
        let gate = gate();
        let bounded = GateEndpoint { id: Uuid::new_v4(), max_in_flight: Some(1), waiting_threshold: Some(0), adaptive: false };
        gate.record_load(bounded.id, EndpointLoad { waiting: 5, ..reading(0.1, 0.0) });
        let held = tokio::spawn({
            let gate = gate.clone();
            async move { gate.acquire(request(&[bounded], user(), 0)).await.map(|p| p.outcome) }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.stats().queue_depth, 1, "held by the engine's queue");
        // Switched to a learned limit: the queue bound is gone for the waiter too.
        gate.adopt_configuration(&[(bounded.id, bounds(None, true))].into());
        gate.reconsider();
        assert_eq!(held.await.expect("task"), Ok(GateOutcome::Held));
    }

    #[tokio::test]
    async fn a_waiter_that_gave_up_leaves_no_pressure_behind() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 4).await;
        let mut req = request(&[ep], user(), 0);
        req.ttl = Duration::from_millis(10);
        assert_eq!(gate.acquire(req).await.unwrap_err(), GateRefusal::Timeout);
        assert!(gate.snapshot().held.is_empty(), "no queue is left for a waiter that is gone");
        // The refusal pressed the window once …
        gate.record_load(ep.id, reading(0.1, 0.0));
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(8));
        // … and nothing presses it after that.
        gate.record_load(ep.id, reading(0.1, 0.0));
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (Some(8), AdaptiveState::Steady));
    }

    #[tokio::test]
    async fn a_window_applies_only_from_its_first_reading() {
        // Created while its engine already has a fresh reading: until the
        // window has seen what is in flight, the ceiling (here none) applies.
        let gate = gate();
        let ep = adaptive(None);
        gate.record_load(ep.id, reading(0.5, 0.0));
        let _permits = fill(&gate, ep, 10).await;
        adopt(&gate, ep);
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, None);
        gate.record_load(ep.id, reading(0.5, 0.0));
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(10), "seeded from what is in flight");
    }

    #[tokio::test]
    async fn a_preemption_shrinks_the_window_below_what_is_in_flight() {
        let gate = gate();
        let ep = adaptive(None);
        adopt(&gate, ep);
        gate.record_load(ep.id, reading(0.1, 0.0));
        let _permits = fill(&gate, ep, 4).await;
        gate.record_load(ep.id, reading(0.6, 2.0));
        let status = gate.snapshot().adaptive[&ep.id];
        assert_eq!((status.limit, status.state), (Some(2), AdaptiveState::BackingOff));
    }

    #[tokio::test]
    async fn a_window_is_adopted_from_configuration_and_dropped_with_it() {
        let gate = gate();
        let ep = adaptive(Some(8));
        gate.adopt_configuration(&[(ep.id, bounds(Some(8), true))].into());
        gate.record_load(ep.id, reading(0.1, 0.0));
        assert_eq!(gate.snapshot().adaptive[&ep.id].state, AdaptiveState::Starting, "learning before any request");
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(4));
        gate.adopt_configuration(&[(ep.id, bounds(Some(2), true))].into());
        assert_eq!(gate.snapshot().adaptive[&ep.id].limit, Some(2), "a lowered ceiling applies before any request");
        gate.adopt_configuration(&[(ep.id, bounds(None, false))].into());
        assert!(gate.snapshot().adaptive.is_empty(), "switched back to a fixed limit");
    }
}
