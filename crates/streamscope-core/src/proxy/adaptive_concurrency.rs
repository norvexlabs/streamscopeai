//! The adaptive in-flight limit: how many requests one gateway replica may have
//! running on one engine, learned from what the engine says about its KV cache.
//!
//! A fixed in-flight limit is a guess at a number that moves with the traffic:
//! the same engine fits two hundred short chats or twenty long agent contexts.
//! Set too low, the engine's batch runs half empty; set too high, the engine
//! admits more than its KV cache holds and PREEMPTS — evicts a running request
//! and recomputes it later — which burns the GPU on work it already did, and
//! the queue moves into the engine, where no priority or fairness applies.
//!
//! So the limit is a congestion window, run the way TCP runs one (additive
//! increase, multiplicative decrease), on the engine's own signals — the
//! approach of CONCUR (arXiv 2601.22705), which drives an AIMD window from KV
//! usage and prefix-cache hit rate. This window reads KV usage and not the
//! hit rate (see the token-latency target below). Each engine reading is one
//! control step:
//!
//! - **Back off** (to what is actually in flight × [`DECREASE_FACTOR`]) when
//!   the engine preempted since the last reading, or when its KV cache is at
//!   [`KV_CEILING`] — about to preempt. A cut that would not lower the window
//!   is no cut.
//! - **Hold** while the engine keeps a waiting queue of its own although its
//!   cache has room: something other than memory admits no more — its token
//!   budget per step, whole-prompt admission, or its batch cap — and more sent
//!   there would only wait in the engine, out of the gateway's priority order.
//!   Which of them binds is not readable from the engine's metrics (it
//!   publishes none of their settings), so the window names the queue, not a
//!   cause. It neither grows nor shrinks — shrinking would hand the engine to
//!   whatever ELSE keeps its queue full (another gateway still on a fixed
//!   limit, a direct client) and drive this replica to one.
//! - **Grow** only while requests were actually limited by the window and the
//!   cache is below [`KV_TARGET`], by no more requests than fit below it (see
//!   below): doubling until the first back-off (slow start), then
//!   [`ADDITIVE_STEP`] — one step per round trip, not per reading. A
//!   request's prompt reaches the cache only once its prefill is
//!   done, seconds after it was admitted, so a window grown on every reading
//!   outruns its own signal and floods the engine before the cache shows any
//!   of it. The round trip is the engine's mean time to first token since the
//!   last growth, [`PACE_MAX`] at most; an engine that publishes none is
//!   grown per reading.
//!
//! Every raise is capped by what it costs in memory ([`AdaptiveWindow::fit`]),
//! counted from what this replica has in flight ([`AdaptiveWindow::room`]);
//! where not one more request fits, the window holds
//! ([`AdaptiveState::MemoryBound`]). A request is counted at its END size: the
//! KV gauge counts only what running requests hold now, and each keeps growing
//! until it ends — the rest of its prefill, then every output token, ten
//! thousand of them on a reasoning turn — so requests admitted with the cache
//! at 0.85 reach the ceiling on their own. The gauge per running request is
//! what requests part-way through hold on average — a prompt and half an
//! answer — and the prompt and answer tokens of the requests the engine
//! finished say how much more one holds by its end
//! ([`AdaptiveWindow::growth`]): a ratio of the
//! engine's figures, so the end size is in the gauge's units, whatever a token
//! costs that engine in memory. The average is the larger of the recent one
//! and the run's, so requests just admitted, still filling their prompts, do
//! not dilute it. The memory committed is the larger of the gauge and the
//! running requests at their end size.
//!
//! The window holds the engine to a token-latency target
//! ([`AdaptiveWindow::set_latency_target`], [`ItlTarget`]): a larger batch does
//! more work but makes every request generate more slowly. By default the
//! target is automatic — [`AUTO_ITL_TARGET_RATIO`] times the engine's own
//! median gap between tokens at low load ([`AdaptiveWindow::low_load_itl`]), one or two
//! running per rank and none waiting, whoever sent them — so it means the same
//! on any engine. That figure is learned on every low-load interval, the
//! recent ones most, so it follows what changes the engine's speed without a
//! restart (another tenant of the GPU, a power cap); a restart — any of its
//! counters fell, which a change of its settings or model takes — forgets it,
//! and it is learned again. Until it is learned there is no target, and an
//! engine never at low load is never held to one. An operator may set the
//! target in milliseconds instead, or turn it off. Under a target, every raise
//! is one [`ADDITIVE_STEP`], and none is taken while the last judged
//! token-latency round ended above it. Rounds follow one another, each lasting
//! the pacing round trip — so a raise is not held for a round of its own: on a
//! prefill-bound engine a round long enough for long prompts to finish would
//! judge their prompt work. Each ends judged on the
//! engine's median gap between tokens over it ([`GapHistogram`] — never the
//! mean, which on a prefill-bound engine is mostly the stalls new prompts
//! cause, and no limit bounds those), against the target as it then
//! stands; one above it steps the window down to a step below what is in
//! flight, never more than halfway nor less than one step
//! ([`AdaptiveState::LatencyBound`]). Without one, the window does as much work
//! as memory holds — and the KV gauge cannot see what that costs an agent
//! workload: vLLM counts a finished request's cached blocks as free, so the
//! history of paused sessions is evicted at any gauge level as more requests
//! run, and comes back as recompute. A target bounds that too, since time per
//! token rises with the recompute, and nothing else in the window does: the
//! eviction starts wherever the running requests and the paused history no
//! longer fit together — no fixed gauge level marks it — and a falling
//! prefix-cache hit rate does not tell it from new content.
//!
//! A window nothing presses against never grows, so a quiet hour cannot wind
//! it up for the next burst; and one nothing has used for [`IDLE_RESTART`]
//! restarts from [`INITIAL_WINDOW`] (or below, where a cut left it) in slow
//! start — TCP's restart after idle (RFC 5681 §4.1). What the last burst taught
//! is about an engine state that has gone, and a burst after a quiet spell sent
//! out at it would land in the engine's own queue, where no class order
//! applies. As TCP keeps its slow-start threshold, slow start then ends at the
//! window it restarted from; beyond that the window grows by
//! [`ADDITIVE_STEP`]. Pressure that arrives while a step waits for its round
//! trip is kept for that step, not lost.
//!
//! A cut takes effect as the work above the new window finishes, and the
//! signal usually outlasts that (the admitted work still holds the cache). So
//! after a cut the window is not cut again until what is in flight has fallen
//! to it: a signal that persists THEN is a window genuinely too large. Cutting
//! on every reading while the flight drains would compound one overload into a
//! window a fraction of the engine's capacity.
//!
//! A replica with nothing in flight at the engine cuts nothing: the pressure is
//! someone else's (another replica, another consumer of the engine), and
//! cutting an idle window would only throttle this replica's next burst. The
//! first reading of a window — a new one, or one resuming after its readings
//! went stale — starts it from what is already in flight, never below: a window
//! adopted on a busy engine must not drop the limit under the work it finds.
//!
//! vLLM counts a cached block nobody references as FREE (it stays in the free
//! queue until evicted), so `kv_cache_usage_perc` is the memory running requests
//! hold — exactly what decides a preemption.
//!
//! Deliberately NOT claimed: that the window converges to one value (it
//! oscillates around the engine's capacity, as every AIMD window does), or that
//! N gateway replicas split an engine evenly (each runs its own window on the
//! same shared signals, which bounds the total but not the split), or that the
//! memory cap keeps the cache below its ceiling: the end size is a mean, a
//! request longer than it still grows past it, and that growth is caught only
//! by the [`KV_CEILING`] cut. Three things make it read low, and the cut
//! catches them too: requests still in their prefill hold less than a prompt,
//! which lowers the gauge's average (the run's too, while it is young); a
//! prompt prefix shared between requests is held once but counted in each
//! prompt, which lowers the growth; and the growth is a mean over requests
//! while the running set is weighted by how long each runs, so on a mixed
//! workload the long answers that dominate it grow by more than the mean (a
//! request the engine aborted is not counted at all). Two make it read high,
//! which errs on the side of memory: a sliding-window layer stops growing past
//! its window, and a hybrid model's state is a fixed cost. And
//! counting every running request at its end at once is conservative: run
//! staggered, they hold about the average together, so an answer-heavy
//! workload settles with the gauge near `KV_TARGET / growth`. Nor
//! is a mix claimed before a request has finished: until then the gauge alone
//! says. Nor that an automatic target is the best one for an engine: the
//! ratio is a starting point that held an agent workload's recompute down, and
//! the low-load figure counts the prompts computed in the same steps, so a
//! workload whose prompts are recomputed at low load as well would raise it.
//! Where this window held requests back, the figure is learned at one running
//! request per rank only, so a target holding it at two does not teach it its
//! own batch; another replica's window held there, or another consumer's
//! load, still does.
//! The window is per replica, like the static limit it replaces; so is what
//! it learns, read from the same engine.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::qos_metrics::{EngineCounters, GapHistogram, GapInterval};

/// Where a window starts, before any reading has said anything.
pub const INITIAL_WINDOW: f64 = 4.0;
/// Never below one request: a window of zero would hold everything for ever.
pub const MIN_WINDOW: f64 = 1.0;
/// The largest window without an operator ceiling.
pub const MAX_WINDOW: f64 = 1024.0;
/// Growth per round trip once slow start has ended, and the step down of a
/// round above the token-latency target.
pub const ADDITIVE_STEP: f64 = 2.0;
/// What a back-off keeps of the requests in flight.
pub const DECREASE_FACTOR: f64 = 0.5;
/// The window grows only while the memory committed is below this.
pub const KV_TARGET: f64 = 0.90;
/// At or above this KV use the engine is about to preempt: back off first.
pub const KV_CEILING: f64 = 0.97;
/// The slowest the workload's figures follow each sample ([`Workload`]):
/// their plain mean until there are this many over one (twenty), then an EWMA
/// — recent enough to follow a change of workload within some sixty readings
/// (two minutes at a two-second poll), long enough that one interval's burst of prompts or admissions
/// does not swing them.
pub const WORKLOAD_ALPHA: f64 = 0.05;
/// The most requests an engine may run per data-parallel rank (its running
/// count over its ranks: the engine balances them by count), in both
/// readings of an interval, for that interval's time per token to count as the
/// engine's low-load figure ([`AdaptiveWindow::low_load_itl`]).
pub const LOW_LOAD_RUNNING: u32 = 2;
/// Output tokens the low-load intervals must have generated, since the engine
/// was first heard or last restarted, before their time per token is a figure:
/// a handful of tokens is noise.
pub const LOW_LOAD_MIN_TOKENS: f64 = 200.0;
/// An [`ItlTarget::Auto`] target is this many times the engine's own low-load
/// time per token: a ratio, so it means the same on any engine, not a measured
/// optimum.
pub const AUTO_ITL_TARGET_RATIO: f64 = 3.0;
/// How long a window must go unused — nothing in flight here, nothing held
/// at it — before it restarts from [`INITIAL_WINDOW`].
pub const IDLE_RESTART: Duration = Duration::from_secs(30);
/// The longest a growth step, or a token-latency round, waits for the engine's
/// first tokens. An engine whose prefills all run long must not freeze the
/// window for ever.
pub const PACE_MAX: Duration = Duration::from_secs(60);

/// The token-latency target a learned limit keeps its engine within (its
/// server's setting), in seconds once applied
/// ([`AdaptiveWindow::set_latency_target`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItlTarget {
    /// [`AUTO_ITL_TARGET_RATIO`] times the engine's own time per token at low
    /// load, as the window has learned it by now
    /// ([`AdaptiveWindow::low_load_itl`]); no target until it has.
    #[default]
    Auto,
    /// The operator's own figure, in milliseconds between two tokens.
    Fixed { ms: u32 },
    /// No target: the limit grows as far as the engine's memory holds.
    Off,
}

/// The automatic token-latency target of an engine whose time between tokens
/// at low load is `low_load` seconds: [`AUTO_ITL_TARGET_RATIO`] times it.
/// `None` below one millisecond — a figure of next to nothing (an exporter
/// whose first bucket holds every gap reads as half its bound) would hold
/// the engine at one request.
/// The one formula the gateway applies and the console shows.
pub fn auto_itl_target(low_load: f64) -> Option<f64> {
    let target = low_load * AUTO_ITL_TARGET_RATIO;
    (target.is_finite() && target >= 0.001).then_some(target)
}

/// What the window did on the latest reading, as an operator reads it.
///
/// It rides the heartbeat and is stored as text, so a state this build does
/// not know reads as `Unknown` rather than failing the whole report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveState {
    /// Nothing asked for more, or nothing said to change.
    Steady,
    /// No reading has been compared with another yet.
    Starting,
    /// Requests were limited and the cache has room: the window grew, or will
    /// once the engine has shown what its last growth admitted.
    Probing,
    /// Requests were limited, but the memory committed is at [`KV_TARGET`],
    /// or one more request — at what each running one will hold — would take
    /// it past it: the window holds.
    MemoryBound,
    /// Requests were limited and the cache has room, but the window is at the
    /// operator's ceiling: raising the ceiling is what would let it grow.
    AtCeiling,
    /// The engine's inter-token latency is above the operator's target: the
    /// window holds, or stepped down.
    LatencyBound,
    /// The engine keeps requests waiting although its cache has room.
    EngineQueueing,
    /// The engine preempted, or its cache is full.
    BackingOff,
    /// No fresh reading — or one without the KV-cache gauge, which the window
    /// cannot be steered by: the ceiling, or the last learned limit, applies.
    NoReading,
    /// A state this build does not know.
    #[serde(other)]
    Unknown,
}

impl AdaptiveState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Steady => "steady",
            Self::Starting => "starting",
            Self::Probing => "probing",
            Self::MemoryBound => "memory_bound",
            Self::AtCeiling => "at_ceiling",
            Self::LatencyBound => "latency_bound",
            Self::EngineQueueing => "engine_queueing",
            Self::BackingOff => "backing_off",
            Self::NoReading => "no_reading",
            Self::Unknown => "unknown",
        }
    }

    /// The inverse of [`Self::as_str`], for a state stored as text. A word this
    /// build does not know is `Unknown`, as on the wire.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "steady" => Self::Steady,
            "starting" => Self::Starting,
            "probing" => Self::Probing,
            "memory_bound" => Self::MemoryBound,
            "at_ceiling" => Self::AtCeiling,
            "latency_bound" => Self::LatencyBound,
            "engine_queueing" => Self::EngineQueueing,
            "backing_off" => Self::BackingOff,
            "no_reading" => Self::NoReading,
            _ => Self::Unknown,
        }
    }

    /// How much an operator needs to see this state: a view over several
    /// replicas shows the one that ranks highest. An unknown state says the
    /// least.
    pub fn pressure(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Steady => 1,
            Self::Starting => 2,
            Self::Probing => 3,
            Self::AtCeiling => 4,
            Self::LatencyBound => 5,
            Self::MemoryBound => 6,
            Self::EngineQueueing => 7,
            Self::BackingOff => 8,
            Self::NoReading => 9,
        }
    }
}

/// What one window has done since it was created, as cumulative counts: they
/// only rise, so a reader differences two reports (a fall is a new window — a
/// restarted process, or a limit switched off and on — and the interval is
/// skipped).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
// A kind a report does not carry reads as none, rather than failing the whole
// report — and the edge's outbox resends a record as it was stored.
#[serde(default)]
pub struct AdaptiveDecisions {
    /// The window was raised.
    pub grew: u64,
    /// The window stepped down: a round ended above the token-latency target.
    pub stepped_down: u64,
    /// Back-offs, by what caused them: the engine preempted, or its KV cache
    /// was at [`KV_CEILING`].
    pub cut_preemption: u64,
    pub cut_kv_full: u64,
}

/// One engine reading, and what this replica did at the engine since the last.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub waiting: u32,
    pub running: Option<u32>,
    pub kv_usage: Option<f64>,
    pub counters: EngineCounters,
    /// Requests this replica has in flight at the engine now.
    pub in_flight: u32,
    /// Whether a request found the window full since the last reading.
    pub limited: bool,
    /// Data-parallel ranks the engine reported `running` for (≥ 1): `running`
    /// is their sum.
    pub ranks: u32,
    /// When the reading was taken.
    pub at: Instant,
}

/// What a reading is compared against.
#[derive(Debug, Clone, Copy)]
struct Previous {
    waiting: u32,
    running: Option<u32>,
    ranks: u32,
    counters: EngineCounters,
}

/// A point a pacing round is measured from: when, and the engine's first-token
/// counters then. The latest growth is one — what the next growth is paced
/// against — and so is the start of a token-latency round.
#[derive(Debug, Clone, Copy)]
struct Growth {
    at: Instant,
    ttft_sum: Option<f64>,
    ttft_count: Option<f64>,
}

impl Growth {
    fn at(obs: &Observation) -> Self {
        Self { at: obs.at, ttft_sum: obs.counters.ttft_sum, ttft_count: obs.counters.ttft_count }
    }
}

/// A token-latency round under way: where it started, and the engine's
/// inter-token histogram then.
#[derive(Debug, Clone, Copy)]
struct LatencyRound {
    start: Growth,
    gaps: Option<GapHistogram>,
}

impl LatencyRound {
    fn at(obs: &Observation) -> Self {
        Self { start: Growth::at(obs), gaps: obs.counters.itl_gaps }
    }
}

/// What a request running at the engine holds of its KV cache, summed over
/// the readings since the window last moved ([`AdaptiveWindow::fit`]): KV use
/// over requests running. With data-parallel ranks the KV is the fullest
/// rank's and the count the mean per rank (at least one: the fullest rank
/// holds what the gauge shows), and the room is the fullest rank's
/// alone: the engine balances its ranks by request count, not by memory, so
/// a new request may land on the fullest.
#[derive(Debug, Clone, Copy, Default)]
struct Footprint {
    kv: f64,
    running: f64,
}

impl Footprint {
    /// What one request holds at this reading, where requests run and the KV
    /// gauge says something.
    fn of(obs: &Observation) -> Option<Self> {
        let kv = obs.kv_usage?;
        let running = obs.running.filter(|r| *r > 0)?;
        // The fullest rank holds what the gauge shows, so at least one
        // request: fewer running than ranks is not a fraction of one there.
        Some(Self { kv, running: (f64::from(running) / f64::from(obs.ranks.max(1))).max(1.0) })
    }

    fn add(&mut self, obs: &Observation) {
        if let Some(reading) = Self::of(obs) {
            self.kv += reading.kv;
            self.running += reading.running;
        }
    }

    /// KV per running request; NaN with nothing summed.
    fn per_request(self) -> f64 {
        self.kv / self.running
    }
}

/// What the engine's workload says — about one request, and about the
/// engine's speed — each figure the plain mean of its first samples, then an
/// EWMA ([`WORKLOAD_ALPHA`]).
///
/// - `tokens`: the prompt and answer tokens of the requests that finished
///   between two consecutive readings (the engine's per-request counts, each taken once
///   its request ended — never the token flow, which counts a prompt whole when
///   its prefill ends and an answer a token at a time, and so reads all prompt
///   through every climb). A request holds its prompt once prefilled and grows
///   by every answer token until it ends, so while it runs it holds, on
///   average, its prompt and half its answer, and by its end
///   `(prompt + answer) / (prompt + answer / 2)` times that: between one (all
///   prompt) and two (all answer) ([`AdaptiveWindow::growth`]).
/// - `gauge`: the KV gauge per running request, as a ratio of sums over the
///   readings (a busy reading counts for its requests, as in [`Footprint`]).
///   A reading taken just after admissions
///   counts requests still in their prefill, holding a fraction of their
///   prompt; this figure is not diluted by one such burst, where the figure
///   since the window last moved is.
/// - `low_load`: the engine's median gap between tokens over the intervals in
///   which it ran 1 to [`LOW_LOAD_RUNNING`] requests per rank with none
///   waiting, at both ends ([`AdaptiveWindow::low_load_itl`]).
///
/// Each figure is a pair of per-interval sums (prompt and answer tokens, KV
/// and requests, the median gap times the gaps and the gaps), each a
/// mean-then-EWMA, read as their
/// ratio: it weighs every interval by what it counted, the recent ones most. The gauge and token
/// figures, being ratios of the engine's own figures, make an end size in the
/// gauge's units whatever a token costs the engine in memory, and count the
/// requests the gauge counts — every consumer's, each round of a gateway-run
/// tool loop as the engine request it is. They are the workload's, not the
/// window's, so nothing the window does resets them — not a raise (raises come
/// one round trip apart and long requests rarely end within one, so a figure
/// measured since the last raise would be young through every climb, where it
/// is needed), and not an idle restart (the climb back after a quiet spell is
/// the fastest there is). After a change of workload, or of what the engine
/// does at low load (another tenant of the GPU, a power cap), they follow at
/// the EWMA's pace, erring on the side of memory where requests turn lighter.
/// An engine restart — any of its counts fell, however long it went unheard
/// — forgets them all: the engine behind the endpoint may run other settings,
/// or another model.
#[derive(Debug, Clone, Copy, Default)]
struct Workload {
    /// Prompt and answer tokens of the requests finished per interval.
    tokens: Option<(f64, f64)>,
    intervals: u32,
    /// KV use and requests running per rank, each a mean-then-EWMA over the
    /// readings: their ratio is the figure.
    gauge: Option<(f64, f64)>,
    readings: u32,
    /// The median gap times the gaps, and the gaps, per low-load interval.
    low_load: Option<(f64, f64)>,
    low_load_intervals: u32,
    /// Tokens the low-load intervals generated, in all.
    low_load_tokens: f64,
    /// The last value each counter a restart is read from had — kept through
    /// readings that went stale or lacked it, so a restart behind them is
    /// still seen as one ([`Counters::of`]).
    seen: Counters,
    /// A restart was read at the latest reading: the interval from it says
    /// nothing either — were the fall one scrape short of a series, its
    /// return would read as that series' whole lifetime in one interval.
    after_restart: bool,
}

/// The engine's cumulative counts a restart is read from: tokens finished, and
/// the inter-token and first-token histograms' counts — whole numbers all,
/// never a histogram's sum of seconds, which can dip without a restart (summed
/// across processes in another order); a restart takes these down with it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Counters([Option<f64>; 4]);

impl Counters {
    fn of(c: &EngineCounters) -> Self {
        Self([c.finished_prompt_tokens, c.finished_generation_tokens, c.itl_count, c.ttft_count])
    }

    /// These, where a reading has them, else the last ones seen.
    fn or(self, last: Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i].or(last.0[i])))
    }

    /// Whether any counter fell below the last value it had.
    fn fell_from(&self, last: &Self) -> bool {
        self.0.iter().zip(&last.0).any(|(now, last)| matches!((now, last), (Some(now), Some(last)) if now < last))
    }
}

impl Workload {
    /// KV per running request over the readings; `None` with none.
    fn held(&self) -> Option<f64> {
        self.gauge.map(|(kv, running)| kv / running)
    }
}

/// Learn one interval's sums into a ratio figure: each a mean-then-EWMA step.
fn learn_pair(figure: &mut Option<(f64, f64)>, n: &mut u32, x: (f64, f64)) {
    *n = n.saturating_add(1);
    let (a, b) = figure.unzip();
    *figure = Some((learn(a, *n, x.0, WORKLOAD_ALPHA), learn(b, *n, x.1, WORKLOAD_ALPHA)));
}

/// One step of a plain-mean-then-EWMA figure: the `n`th sample `x` moves it
/// `1/n` of the way while that is more than `alpha`, then `alpha`.
fn learn(figure: Option<f64>, n: u32, x: f64, alpha: f64) -> f64 {
    let alpha = (1.0 / f64::from(n)).max(alpha);
    let mean = figure.unwrap_or(x);
    mean + alpha * (x - mean)
}

/// One engine's window at one gateway replica.
#[derive(Debug, Clone)]
pub struct AdaptiveWindow {
    window: f64,
    /// Doubling until the first back-off.
    slow_start: bool,
    previous: Option<Previous>,
    /// The latest growth, which the next one is paced against. `None` after a
    /// restart: the first growth of a busy period is not held back.
    grown: Option<Growth>,
    /// Since when nothing has been in flight here and nothing held at the
    /// window — the reading that started the idle spell.
    idle_since: Option<Instant>,
    /// Where slow start ends — TCP's `ssthresh`: the window an idle restart
    /// set back, or the one a cut left. `None` doubles until the first
    /// back-off.
    slow_start_threshold: Option<f64>,
    /// The window has restarted in the current idle spell: every later idle
    /// reading of the spell leaves it, and its threshold, alone.
    restarted: bool,
    /// The window was pressed against at a reading whose growth step was
    /// still waiting for its round trip: the next paced reading grows on it.
    pressed_unpaced: bool,
    state: AdaptiveState,
    /// Whether the window has ever been set by the engine's own behaviour — a
    /// control step that moved it, or a first reading that found work in
    /// flight. Until then it is only the starting guess.
    learned: bool,
    /// Whether the latest reading LACKED the KV-cache gauge. Such a reading is
    /// no reading to the window: it cannot grow on it, nor tell a full cache
    /// from an empty one, so it compares nothing, moves nothing and teaches
    /// nothing — and the reading after it that has the gauge seeds afresh.
    blind: bool,
    /// A cut has not yet taken effect: what is in flight is still above the
    /// window. Until it falls to it, a lasting signal cuts nothing more.
    cut_pending: bool,
    /// What one running request holds, since the window last moved.
    footprint: Footprint,
    /// What the engine's workload says about one request.
    workload: Workload,
    /// The token-latency target, as its server sets it
    /// ([`Self::latency_target`] is what applies now).
    latency_setting: ItlTarget,
    /// The token-latency round under way, while a target applies.
    latency_round: Option<LatencyRound>,
    /// The last round that ended measured the engine above the target: no
    /// raise until one ends within it.
    over_target: bool,
    /// The engine publishes its inter-token figures, as the last round that
    /// ended found (or the reading a round started at): only then does a
    /// verdict hold a raise, and only then is every raise a step
    /// ([`Self::grown_window`]).
    latency_measurable: bool,
    decisions: AdaptiveDecisions,
}

/// Whether a round started at `g` — what a growth admitted reaching the cache,
/// or a token-latency round — is done by this reading: as long has passed as
/// the engine's mean time to first token over the requests that got one since.
/// None getting one since means nothing admitted has shown up yet.
/// [`PACE_MAX`] ends any wait; an engine publishing no first-token figures —
/// or whose counters fell, a restart — ends every round at once.
///
/// Deliberately the mean of what showed since, not of every request the round
/// admitted: the quick first tokens end a round before a long prompt it let in
/// is done. A round held until then judges, on an engine whose prompts stall
/// its decodes, the prompt work alone — under a token-latency target it holds
/// the window at one request, and the queue behind it times out.
fn round_trip_done(g: Growth, obs: &Observation) -> bool {
    let elapsed = obs.at.saturating_duration_since(g.at);
    if elapsed >= PACE_MAX {
        return true;
    }
    match (rise(g.ttft_count, obs.counters.ttft_count), rise(g.ttft_sum, obs.counters.ttft_sum)) {
        (Some(count), Some(sum)) => {
            if count == 0.0 {
                return false;
            }
            elapsed.as_secs_f64() >= sum / count
        }
        _ => true,
    }
}

/// The largest the window may be: the operator's ceiling (whatever it is —
/// capping it silently would report "at ceiling" below the one they set), else
/// [`MAX_WINDOW`].
fn cap(ceiling: Option<u32>) -> f64 {
    ceiling.map_or(MAX_WINDOW, |c| f64::from(c.max(1)))
}

/// Not one more request fits below [`KV_TARGET`] ([`AdaptiveWindow::fit`]):
/// the memory, not the window, is what holds it.
fn none_fits(fit: Option<f64>) -> bool {
    fit.is_some_and(|f| f < 1.0)
}

/// How much a cumulative counter rose between two readings. `None` when either
/// is missing, or it FELL — the engine restarted, and the interval says nothing.
fn rise(previous: Option<f64>, current: Option<f64>) -> Option<f64> {
    match (previous, current) {
        (Some(p), Some(c)) if c >= p => Some(c - p),
        _ => None,
    }
}

impl AdaptiveWindow {
    /// A window with no token-latency target until it follows its server's
    /// setting ([`Self::set_latency_target`], which the dispatch gate calls as
    /// it adopts the window): a figure it was not given is not assumed.
    pub fn new(ceiling: Option<u32>) -> Self {
        Self {
            window: INITIAL_WINDOW.min(cap(ceiling)),
            slow_start: true,
            previous: None,
            grown: None,
            idle_since: None,
            slow_start_threshold: None,
            restarted: false,
            pressed_unpaced: false,
            state: AdaptiveState::Starting,
            learned: false,
            blind: false,
            cut_pending: false,
            footprint: Footprint::default(),
            workload: Workload::default(),
            latency_setting: ItlTarget::Off,
            latency_round: None,
            over_target: false,
            latency_measurable: false,
            decisions: AdaptiveDecisions::default(),
        }
    }

    /// Follow its server's token-latency target ([`ItlTarget`]). A changed
    /// setting starts its rounds afresh — what the last round measured was
    /// judged against another figure — and, on a window that has learned
    /// anything, ends slow start: that window was found under the old rule,
    /// and doubling from it (a target turned off) would send a batch the
    /// engine was never shown. A new window keeps its slow start. An
    /// [`ItlTarget::Auto`] target moving with what the window learns is no
    /// change of setting: a round is judged against the target as it stands
    /// when the round ends.
    pub fn set_latency_target(&mut self, target: ItlTarget) {
        if self.latency_setting != target {
            self.latency_setting = target;
            self.latency_round = None;
            self.over_target = false;
            self.latency_measurable = false;
            if self.learned {
                self.slow_start = false;
            }
        }
    }

    /// The token-latency target that applies now, in seconds: the operator's
    /// figure, or [`AUTO_ITL_TARGET_RATIO`] times the engine's low-load time
    /// per token once learned ([`auto_itl_target`]). `None`: no target —
    /// none set, a zero one, or an automatic one still learning.
    pub fn latency_target(&self) -> Option<f64> {
        match self.latency_setting {
            ItlTarget::Off => None,
            ItlTarget::Fixed { ms } => (ms > 0).then(|| f64::from(ms) / 1000.0),
            ItlTarget::Auto => self.low_load_itl().and_then(auto_itl_target),
        }
    }

    /// Whether a target holds the window: one applies, and the engine
    /// publishes the inter-token figures it is held against, as the last round
    /// that ended found (or the reading a round started at).
    fn latency_gates(&self) -> bool {
        self.latency_measurable && self.latency_target().is_some()
    }

    /// What the window has done since it was created ([`AdaptiveDecisions`]).
    pub fn decisions(&self) -> AdaptiveDecisions {
        self.decisions
    }

    /// The engine's median gap between tokens, in seconds, over the intervals
    /// in which it ran 1 to [`LOW_LOAD_RUNNING`] requests per rank with none
    /// waiting — whoever sent them — each interval's median weighted by the
    /// gaps it made, the recent intervals most ([`Workload`], [`GapHistogram`]). `None` until those intervals have
    /// generated [`LOW_LOAD_MIN_TOKENS`]; forgotten at an engine restart.
    /// Learned whatever the target setting: it is what an automatic target is.
    pub fn low_load_itl(&self) -> Option<f64> {
        let w = &self.workload;
        let (sum, count) = w.low_load?;
        (w.low_load_tokens >= LOW_LOAD_MIN_TOKENS && count > 0.0).then(|| sum / count)
    }

    /// The limit while the engine is NOT heard: the last learned window within
    /// the ceiling — releasing more onto an engine whose metrics stopped
    /// answering (often because it is overloaded) would drop priority and
    /// fairness at the worst moment — else, with nothing ever learned, the
    /// ceiling, else no limit: an engine never heard is not held to a starting
    /// guess. After an idle restart that is the restarted window: a burst whose
    /// engine goes unheard must not go out at the size the restart took back.
    /// Deliberately, at the price of a low limit for as long as an outage that
    /// begins right after a restart lasts — the engine is not heard, so nothing
    /// can show that more would be safe.
    pub fn unheard_limit(&self, ceiling: Option<u32>) -> Option<u32> {
        if self.learned { Some(self.limit(ceiling)) } else { ceiling }
    }

    /// The readings went stale: the next one is a first reading again, compared
    /// with nothing and starting from what is in flight then.
    pub fn resume(&mut self) {
        self.previous = None;
    }

    /// Whether the latest reading lacked the KV-cache gauge.
    pub fn blind(&self) -> bool {
        self.blind
    }

    /// Whether the window is a limit: it has taken a first reading WITH the
    /// KV-cache gauge. Before that it has not seen what is in flight, and
    /// applying it could put the limit under work already out; and without
    /// the gauge it could never grow — an engine publishing only its queue
    /// would sit at a guess for ever.
    pub fn steerable(&self) -> bool {
        self.previous.is_some()
    }

    /// How many requests may be in flight now: the window, within the ceiling.
    pub fn limit(&self, ceiling: Option<u32>) -> u32 {
        // Truncation is the intent: a window of 5.9 admits five. The value is
        // within [1, cap(ceiling)] and the cap is a u32 or MAX_WINDOW, so the
        // cast cannot saturate.
        (self.window.min(cap(ceiling)).floor() as u32).max(1)
    }

    pub fn state(&self) -> AdaptiveState {
        self.state
    }

    /// One control step, on a reading the window has not seen before.
    pub fn observe(&mut self, obs: &Observation, ceiling: Option<u32>) {
        self.blind = obs.kv_usage.is_none();
        if self.blind {
            // Not a reading the window can use (see `blind`): the next one
            // with the gauge is a first reading again.
            self.resume();
            self.state = AdaptiveState::NoReading;
            return;
        }
        let previous = self.previous.replace(Previous {
            waiting: obs.waiting,
            running: obs.running,
            ranks: obs.ranks,
            counters: obs.counters,
        });
        let kv = obs.kv_usage;
        self.learn_workload(previous.as_ref(), obs);

        let preempted = previous
            .and_then(|p| rise(p.counters.preemptions, obs.counters.preemptions))
            .is_some_and(|d| d > 0.0);
        let cache_full = kv.is_some_and(|k| k >= KV_CEILING);

        // Taken now whatever this reading does, so it is never carried twice.
        let carried = std::mem::take(&mut self.pressed_unpaced);
        let flight = f64::from(obs.in_flight);
        if previous.is_none() {
            // A first reading only seeds: never below the work already out
            // there (see the module comment), and nothing to compare with.
            // Whatever it shows is acted on at the next reading. Only work
            // above the starting guess teaches anything.
            self.moved();
            self.footprint.add(obs);
            // A new round from here; a verdict stands until one is judged —
            // readings that went stale say nothing about the latency.
            self.latency_round = None;
            self.learned |= flight > self.window;
            self.window = self.window.max(flight).clamp(MIN_WINDOW, cap(ceiling));
            self.idle_since = None;
            self.restarted = false;
            self.state = AdaptiveState::Starting;
            return;
        }
        self.restart_if_idle(obs);
        self.footprint.add(obs);
        let round_over = self.time_latency(obs);
        // Pressure a reading could not act on, waiting for its round trip,
        // counts at the next one — while there is still work out. With nothing
        // in flight nothing presses the window: the pressure ended with it.
        let pressed = obs.limited || (carried && obs.in_flight > 0);
        let before = self.window;
        if flight <= self.window {
            self.cut_pending = false;
        }
        if preempted || cache_full {
            // Half of what is in flight, never half of an unused window — and
            // never below MIN_WINDOW. Nothing more while an earlier cut has not
            // taken effect (see the module comment). A cut that would not lower
            // the window is no cut: nothing is counted, and nothing waits on
            // it. Nothing in flight here: the pressure is not this replica's
            // to relieve.
            let to = (flight * DECREASE_FACTOR).max(MIN_WINDOW);
            if obs.in_flight > 0 && to < self.window && !self.cut_pending {
                self.window = to;
                self.moved();
                self.slow_start = false;
                // TCP's `ssthresh` after a loss: what a restart's slow start
                // stops at, should this window go idle before it has grown
                // past the guess again.
                self.slow_start_threshold = Some(self.window.max(MIN_WINDOW));
                self.cut_pending = true;
                // Named by the loss first: a preemption on a full cache is a
                // preemption cut.
                let cause = if preempted {
                    &mut self.decisions.cut_preemption
                } else {
                    &mut self.decisions.cut_kv_full
                };
                *cause += 1;
            }
            self.state = if obs.in_flight > 0 { AdaptiveState::BackingOff } else { AdaptiveState::Steady };
        } else if round_over && obs.in_flight > 0 {
            // A whole round above the token-latency target: a step below what
            // runs, never more than halfway down from the window and never
            // less than one step — an oversized window would otherwise admit
            // the next burst whole, and one round of latency (perhaps another
            // consumer's) must not drop a window in a lull to what happens to
            // run. Once the last step has taken effect, so a step never
            // compounds while the flight drains to it, and only where there is
            // a step to take (at one request the window holds). Before the
            // engine's own queue: a queueing engine running slower than the
            // target is still sent fewer. Nothing in flight here: the latency
            // is someone else's.
            if flight <= self.window.floor() && self.window.floor() > MIN_WINDOW {
                let window = self.window.floor();
                self.window = (window - ADDITIVE_STEP)
                    .min((flight - ADDITIVE_STEP).max(window * DECREASE_FACTOR))
                    .max(MIN_WINDOW);
                self.moved();
                self.slow_start = false;
                self.decisions.stepped_down += 1;
            }
            self.state = AdaptiveState::LatencyBound;
        } else if let Some(p) = previous
            && obs.waiting > 0
            && p.waiting > 0
            && kv.is_some_and(|k| k < KV_TARGET)
        {
            // The engine is holding a queue of its own with memory to spare:
            // hold (see the module comment).
            self.state = AdaptiveState::EngineQueueing;
        } else if pressed && kv.is_some_and(|k| k < KV_TARGET) {
            self.grow_if_paced(obs, ceiling);
        } else if pressed {
            self.state = AdaptiveState::MemoryBound;
        } else {
            self.state = AdaptiveState::Steady;
        }
        // Learned is what the ENGINE moved; a ceiling clamp below teaches nothing.
        self.learned |= self.window != before;
        self.window = self.window.clamp(MIN_WINDOW, cap(ceiling));
    }

    /// One growth step on a reading pressed with room: none where not one more
    /// request fits below [`KV_TARGET`] ([`Self::fit`]), none while the last
    /// judged token-latency round ended above the target, none at the ceiling,
    /// none before what the last step admitted has had its round trip (the
    /// pressure waits for it), else [`Self::grown_window`] within what fits,
    /// and the next step paced against this one.
    fn grow_if_paced(&mut self, obs: &Observation, ceiling: Option<u32>) {
        let fit = self.fit(obs);
        let room = self.room(obs, fit, f64::from(obs.waiting));
        // Memory first: a window at its ceiling, or over its latency target,
        // with no room either would grow no further for either.
        if none_fits(fit) {
            self.state = AdaptiveState::MemoryBound;
        } else if self.over_target && self.latency_gates() {
            self.state = AdaptiveState::LatencyBound;
        } else if self.window >= cap(ceiling) {
            self.state = AdaptiveState::AtCeiling;
        } else if self.room(obs, fit, 0.0).is_some_and(|r| r < 1.0) {
            // More would fit, but the window's open slots already hold it:
            // nothing in flight runs in them, and nothing to raise.
            self.state = AdaptiveState::Steady;
        } else if room.is_some_and(|r| r < 1.0) {
            // What waits in the engine's queue takes the room: it holds
            // nothing yet, but will.
            self.state = AdaptiveState::MemoryBound;
        } else if !self.paced(obs) {
            self.pressed_unpaced = true;
            self.state = AdaptiveState::Probing;
        } else {
            let to = Self::within(self.window, self.grown_window(), room);
            self.grow_to(to);
            self.raised(obs);
            self.state = AdaptiveState::Probing;
        }
    }

    /// How many more requests fit below [`KV_TARGET`], each counted at what it
    /// will hold by its end.
    ///
    /// What one running request holds is the KV gauge per running request:
    /// the larger of this reading's and the mean over the readings since the
    /// window last moved ([`Footprint`]) — a raise, a cut, a step down — so a
    /// workload that changed while it held is not averaged into the next raise
    /// for longer than that. A shift to longer requests shows in the reading
    /// before the mean, which would otherwise admit them at the short ones'
    /// size. That is what requests part-way through hold on average, and a
    /// request keeps growing until it ends: the gauge counts it only as far as
    /// it has got. Its END size is the larger of that and the run's figure
    /// ([`Workload`] — which requests just admitted and still in their
    /// prefill, holding a fraction of their prompt, do not dilute), times the
    /// engine's growth ([`Self::growth`]), in the gauge's own units. The
    /// memory committed is the larger of the gauge and the running requests at
    /// the end size — the engine's count where it publishes one, else this
    /// replica's own — so requests still growing are counted at their end.
    /// Being the run's, the end size follows a shift to lighter requests only
    /// as its EWMA does, which errs on the side of memory.
    ///
    /// Before a finished request has taught the mix there is no end size, and
    /// the gauge as it stands says. `None` where nothing measured
    /// says — no request seen running, or none holding memory yet — and the
    /// raise is not capped. Whole requests, never below none.
    fn fit(&self, obs: &Observation) -> Option<f64> {
        let kv = obs.kv_usage?;
        let now = Footprint::of(obs);
        let held = now.map_or(f64::NAN, Footprint::per_request).max(self.footprint.per_request());
        // `f64::max` takes the other side of a NaN: a figure missing is no
        // figure, and with neither the end size is NaN too, which caps nothing.
        let end = self.growth().map(|growth| held.max(self.workload.held().unwrap_or(f64::NAN)) * growth);
        let per_request = end.unwrap_or(held);
        if !(per_request.is_finite() && per_request > 0.0) {
            return None;
        }
        // The gauge already counts what running requests hold now; only the
        // end size says what they will hold. An engine that publishes no
        // running count still runs this replica's own (those not waiting in
        // its queue); one that does is believed — a request between the rounds
        // of a gateway-run tool loop holds a slot here and nothing there.
        let running = match now {
            Some(f) => f.running,
            None => (f64::from(obs.in_flight) - f64::from(obs.waiting)).max(0.0) / f64::from(obs.ranks.max(1)),
        };
        let committed = kv.max(running * end.unwrap_or(0.0));
        Some(((KV_TARGET - committed) / per_request).floor().max(0.0))
    }

    /// How much more a running request holds by its end than requests
    /// running hold on average ([`Workload`]): between one and two. `None`
    /// before an interval has taught the mix.
    fn growth(&self) -> Option<f64> {
        let (prompt, answer) = self.workload.tokens?;
        let whole = prompt + answer;
        (whole > 0.0).then(|| whole / (prompt + answer / 2.0))
    }

    /// Learn the workload from a reading ([`Workload`]): what running requests
    /// hold, where requests run and the gauge says something; and, from the
    /// counters' rise since the PREVIOUS reading — two readings a scrape apart,
    /// never across readings that went stale, whose one rise would weigh
    /// minutes of traffic as one interval — the token mix of the requests that
    /// finished, the time per token at low load, and the time to first token.
    /// An interval with nothing to count says nothing, nor one with a counter
    /// missing. A counter that fell below the last value it had is an engine
    /// restart — however many readings ago that value was taken, so a restart
    /// that outlasts the readings' freshness is still seen where its counters
    /// have not yet climbed past the old ones — and what the workload taught is
    /// forgotten first: the engine behind the endpoint may run other settings,
    /// or another model.
    fn learn_workload(&mut self, previous: Option<&Previous>, obs: &Observation) {
        let now = Counters::of(&obs.counters);
        let last = self.workload.seen;
        // A reading without a counter keeps its last value: one partial
        // scrape must not hide the restart behind it.
        self.workload.seen = now.or(last);
        let after_restart = std::mem::take(&mut self.workload.after_restart);
        let restarted = now.fell_from(&last);
        if restarted {
            self.workload = Workload { seen: now, after_restart: true, ..Workload::default() };
        }
        if let Some(f) = Footprint::of(obs) {
            let w = &mut self.workload;
            w.readings = w.readings.saturating_add(1);
            let (k, r) = w.gauge.unzip();
            w.gauge = Some((learn(k, w.readings, f.kv, WORKLOAD_ALPHA), learn(r, w.readings, f.running, WORKLOAD_ALPHA)));
        }
        // An interval across a restart, or the one after it, says nothing.
        let Some(p) = previous.filter(|_| !restarted && !after_restart) else {
            return;
        };
        // Low load is one or two running per rank and nothing waiting, at both
        // ends: an engine that keeps a queue is held back by prompts it has not
        // yet admitted, and its time per token is not the low-load figure. A
        // prompt admitted at once still shares its steps with the running
        // decodes, and is counted — as a target would see it. Where this
        // window held requests back, only one running per rank counts: a
        // target holding it at two would otherwise teach the figure its own
        // batch and raise itself, while one alone batches nothing — and a
        // window a too-tight target held at one learns the engine's real
        // figure there, and is let go.
        let most = if obs.limited { 1 } else { LOW_LOAD_RUNNING };
        let low_load = |r: Option<u32>, waiting: u32, ranks: u32| {
            waiting == 0 && r.is_some_and(|r| (1..=most.saturating_mul(ranks.max(1))).contains(&r))
        };
        if low_load(p.running, p.waiting, p.ranks)
            && low_load(obs.running, obs.waiting, obs.ranks)
            && let (Some(before), Some(now)) = (p.counters.itl_gaps, obs.counters.itl_gaps)
            && let Some(GapInterval { gaps, median: Some(median) }) = now.since(&before)
        {
            // Each interval's median, weighed by the gaps it made.
            let w = &mut self.workload;
            learn_pair(&mut w.low_load, &mut w.low_load_intervals, (median * gaps, gaps));
            w.low_load_tokens += gaps;
        }
        let before = (p.counters.finished_prompt_tokens, p.counters.finished_generation_tokens);
        let after = (obs.counters.finished_prompt_tokens, obs.counters.finished_generation_tokens);
        let (Some(prompt), Some(answer)) = (rise(before.0, after.0), rise(before.1, after.1)) else {
            return;
        };
        if !(prompt.is_finite() && answer.is_finite() && prompt + answer > 0.0) {
            return;
        }
        let w = &mut self.workload;
        learn_pair(&mut w.tokens, &mut w.intervals, (prompt, answer));
    }

    /// The whole requests the window may add: what this replica has in flight
    /// plus `fit` ([`Self::fit`]), above the window's limit — less `waiting`
    /// in the engine's own queue, which holds nothing yet but will once it
    /// runs (counted whole, whoever sent it). A slot the window holds open
    /// while nothing runs in it is not room either: the KV gauge counts only
    /// what runs, so it would be counted free and filled on top of what fits.
    /// `None` where nothing caps a raise.
    fn room(&self, obs: &Observation, fit: Option<f64>, waiting: f64) -> Option<f64> {
        let running_here = (f64::from(obs.in_flight) - waiting).max(0.0);
        fit.map(|f| (running_here + f - self.window.floor()).max(0.0))
    }

    /// A raise of `window` to `to`, capped at the room ([`Self::room`]).
    fn within(window: f64, to: f64, room: Option<f64>) -> f64 {
        room.map_or(to, |r| to.min(window.floor() + r))
    }

    /// The window was raised at this reading: counted, the next growth paced
    /// against it, and what one request holds measured afresh from here.
    fn raised(&mut self, obs: &Observation) {
        self.decisions.grew += 1;
        self.grown = Some(Growth::at(obs));
        self.moved();
    }

    /// The window moved, or starts afresh: what one running request holds is
    /// measured again from here — the requests a move admits or sheds change
    /// it. What the workload says is kept ([`Workload`]).
    fn moved(&mut self) {
        self.footprint = Footprint::default();
    }

    /// End the token-latency round under way once its round trip is done
    /// ([`round_trip_done`]), and judge it: its median gap between tokens against
    /// the target as it stands now. A round in which no token was generated,
    /// or whose counters fell, says nothing: the last verdict stands, and
    /// nothing steps down. A histogram no longer published drops the verdict:
    /// the window runs as without a target until a round measures again. Returns whether a round just ended
    /// above the target. With no target applying — none set, or an automatic
    /// one still learning — nothing is timed, and no earlier verdict stands.
    fn time_latency(&mut self, obs: &Observation) -> bool {
        let Some(target) = self.latency_target() else {
            // A target that held the window and went (an automatic one whose
            // engine restarted) ends slow start, as a setting turned off
            // does: the window was found under it.
            if self.latency_measurable && self.learned {
                self.slow_start = false;
            }
            self.latency_round = None;
            self.over_target = false;
            self.latency_measurable = false;
            return false;
        };
        let Some(round) = self.latency_round else {
            // Whether the target can hold is settled per round, not per
            // scrape: one reading short of a counter changes nothing. Not
            // measurable, the window runs as without a target until a round
            // measures again, so a verdict kept across stale readings goes
            // with it, as when the histogram goes mid-round.
            self.latency_measurable = obs.counters.itl_gaps.is_some();
            self.over_target &= self.latency_measurable;
            self.latency_round = Some(LatencyRound::at(obs));
            return false;
        };
        if !round_trip_done(round.start, obs) {
            return false;
        }
        self.latency_round = Some(LatencyRound::at(obs));
        match (round.gaps, obs.counters.itl_gaps) {
            // The histogram missing now: the engine is not publishing what the
            // target is held against, and the window runs as without one until
            // a round measures again — so the last verdict goes with it.
            (_, None) => {
                self.latency_measurable = false;
                self.over_target = false;
                false
            }
            (Some(before), Some(now)) => match now.since(&before) {
                Some(interval) => {
                    self.latency_measurable = true;
                    // A round with no gap says nothing: the last verdict stands.
                    let Some(median) = interval.median else {
                        return false;
                    };
                    self.over_target = median > target;
                    self.over_target
                }
                // Counts that fell (a restart), or other bounds: the round
                // says nothing, and the standing is kept for the next.
                None => false,
            },
            // Missing at the round's start only: the next round measures.
            (None, Some(_)) => false,
        }
    }

    /// TCP's restart after idle (RFC 5681 §4.1): a window nothing has used for
    /// [`IDLE_RESTART`] goes back to [`INITIAL_WINDOW`] in slow start. An idle
    /// window says nothing about the engine, so this is no cut.
    fn restart_if_idle(&mut self, obs: &Observation) {
        // A learned window has no engine-queue bound beside it, so a request
        // held for this endpoint is held by its window — `limited`.
        if obs.in_flight > 0 || obs.limited {
            self.idle_since = None;
            self.restarted = false;
            return;
        }
        let since = *self.idle_since.get_or_insert(obs.at);
        if self.restarted || obs.at.saturating_duration_since(since) < IDLE_RESTART {
            return;
        }
        self.restarted = true;
        // Slow start ends at the window it restarts from when that had grown
        // past the guess. One at or below it keeps the threshold it had: a
        // cut's, so a window an overload left small grows additively as it did
        // before the spell; or none, so a window that never learned anything
        // doubles as any new one does.
        if self.window > INITIAL_WINDOW {
            self.slow_start_threshold = Some(self.window);
        }
        self.window = self.window.min(INITIAL_WINDOW);
        self.slow_start = true;
        self.cut_pending = false;
        self.grown = None;
        self.pressed_unpaced = false;
        // A latency verdict from before the spell is about an engine state that
        // has gone, as the window is.
        self.latency_round = None;
        self.over_target = false;
        self.moved();
    }

    /// The window one growth step makes: doubled in slow start, up to the
    /// slow-start threshold where one is set (reaching it ends slow start,
    /// [`Self::grow_to`]), else — or under a token-latency target —
    /// [`ADDITIVE_STEP`] more.
    fn grown_window(&self) -> f64 {
        // Under a latency target every raise is a step: a doubling judged
        // within the target can land at twice the batch that met it, and the
        // way back is a step per round. An engine that publishes no
        // inter-token figures is run as without one.
        if !self.slow_start || self.latency_gates() {
            return self.window + ADDITIVE_STEP;
        }
        let doubled = self.window * 2.0;
        match self.slow_start_threshold {
            Some(threshold) if doubled >= threshold => {
                if threshold > self.window { threshold } else { self.window + ADDITIVE_STEP }
            }
            _ => doubled,
        }
    }

    /// Take a raise to `to` — a [`Self::grown_window`], perhaps capped by the
    /// room. Slow start ends where the raise reaches its threshold, not where
    /// memory stopped it short: the threshold is still the window to return to
    /// once there is room.
    fn grow_to(&mut self, to: f64) {
        if self.slow_start && self.slow_start_threshold.is_some_and(|t| to >= t) {
            self.slow_start = false;
            self.slow_start_threshold = None;
        }
        self.window = to;
    }

    /// Whether the work the latest growth admitted can have reached the cache
    /// ([`round_trip_done`]).
    fn paced(&self, obs: &Observation) -> bool {
        self.grown.is_none_or(|g| round_trip_done(g, obs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn obs(kv: f64, in_flight: u32, limited: bool) -> Observation {
        Observation {
            waiting: 0,
            running: Some(in_flight),
            kv_usage: Some(kv),
            counters: EngineCounters { preemptions: Some(0.0), ..EngineCounters::default() },
            in_flight,
            limited,
            ranks: 1,
            at: Instant::now(),
        }
    }

    /// The reading with many small requests running at the engine (another
    /// consumer's): one more always fits below the KV target, so the memory
    /// cap never binds.
    fn light(o: Observation) -> Observation {
        Observation { running: Some(10_000), ..o }
    }

    fn with_preemptions(o: Observation, n: f64) -> Observation {
        Observation { counters: EngineCounters { preemptions: Some(n), ..o.counters }, ..o }
    }

    /// A window after one baseline reading, so the next one is a control step.
    fn primed(ceiling: Option<u32>) -> AdaptiveWindow {
        let mut w = AdaptiveWindow::new(ceiling);
        w.observe(&obs(0.1, 0, false), ceiling);
        assert_eq!(w.state(), AdaptiveState::Starting);
        w
    }

    #[test]
    fn the_first_reading_changes_nothing_it_cannot_compare() {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&obs(0.1, 4, true), None);
        assert_eq!(w.limit(None), 4);
        assert_eq!(w.state(), AdaptiveState::Starting);
    }

    #[test]
    fn a_limited_window_doubles_in_slow_start_then_grows_by_a_step() {
        let mut w = primed(None);
        w.observe(&obs(0.2, 4, true), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::Probing));
        w.observe(&obs(0.3, 8, true), None);
        assert_eq!(w.limit(None), 16);
        // One back-off ends slow start …
        w.observe(&with_preemptions(obs(0.5, 16, true), 1.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::BackingOff));
        // … and growth is additive from there.
        w.observe(&with_preemptions(obs(0.5, 8, true), 1.0), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::Probing));
    }

    #[test]
    fn a_window_nothing_presses_against_does_not_grow() {
        let mut w = primed(None);
        for _ in 0..10 {
            w.observe(&obs(0.1, 1, false), None);
        }
        assert_eq!((w.limit(None), w.state()), (4, AdaptiveState::Steady));
    }

    #[test]
    fn growth_stops_at_the_kv_target_on_both_sides() {
        // Many small requests running (another consumer's), so one more fits
        // anywhere below the target: the target alone decides.
        let mut below = pressed_with(KV_TARGET - 0.01, 400);
        assert_eq!(below.limit(None), 8, "just below the target grows");
        below.observe(&Observation { running: Some(400), ..obs(KV_TARGET, 8, true) }, None);
        assert_eq!((below.limit(None), below.state()), (8, AdaptiveState::MemoryBound), "at the target holds, and says why");
        // An engine that publishes no running count says nothing of what a
        // request holds, so nothing caps a raise: the target alone holds it.
        let mut uncounted = primed(None);
        uncounted.observe(&Observation { running: None, ..obs(KV_TARGET, 4, true) }, None);
        assert_eq!((uncounted.limit(None), uncounted.state()), (4, AdaptiveState::MemoryBound));
        uncounted.observe(&Observation { running: None, ..obs(KV_TARGET - 0.01, 4, true) }, None);
        assert_eq!(uncounted.limit(None), 8, "below it, uncapped");
    }

    /// A primed KV-fill window pressed at `kv`, with `running` requests at
    /// the engine (four of them this replica's).
    fn pressed_with(kv: f64, running: u32) -> AdaptiveWindow {
        let mut w = primed(None);
        w.observe(&Observation { running: Some(running), ..obs(kv, 4, true) }, None);
        w
    }

    #[test]
    fn a_raise_admits_only_the_requests_that_fit_below_the_target_on_both_sides() {
        // Twelve requests hold 0.75, 0.0625 each: 0.15 of room is two more, so
        // slow start's doubling to eight stops at six.
        let w = pressed_with(0.75, 12);
        assert_eq!((w.limit(None), w.state()), (6, AdaptiveState::Probing));
        // Thirteen requests: one more needs kv / 13. Just under the room it
        // leaves, one fits; just over, none — the window holds, and says why.
        let w = pressed_with(0.8357, 13);
        assert_eq!((w.limit(None), w.state()), (5, AdaptiveState::Probing), "room for one");
        let w = pressed_with(0.8358, 13);
        assert_eq!((w.limit(None), w.state()), (4, AdaptiveState::MemoryBound), "room for none");
        // Small requests: 0.03 each leaves room for twenty — the doubling is
        // not touched.
        let w = pressed_with(0.27, 9);
        assert_eq!(w.limit(None), 8);
    }

    #[test]
    fn a_raise_counts_what_is_in_flight_not_the_windows_empty_slots() {
        // A window of 20 with only ten in flight at the reading, 0.05 each at
        // 0.5: eight more fit on top of the ten — 18, under the window — so
        // the window holds; counted from the window, it would go to 22 and
        // the next burst would send 22 requests into 1.1 of the cache. Not the
        // memory holding it, though: its open slots already hold what fits.
        let at = |kv: f64, in_flight: u32| {
            let mut w = primed(None);
            w.window = 20.0;
            w.slow_start = false;
            w.observe(&obs(kv, in_flight, true), None);
            (w.limit(None), w.state())
        };
        assert_eq!(at(0.5, 10), (20, AdaptiveState::Steady));
        // Twenty in flight, four of them waiting in the engine's queue: those
        // hold nothing yet but will, so the two that fit at 0.8 are theirs.
        let mut waiting = primed(None);
        waiting.window = 20.0;
        waiting.slow_start = false;
        waiting.observe(&Observation { waiting: 4, running: Some(16), ..obs(0.8, 20, true) }, None);
        assert_eq!((waiting.limit(None), waiting.state()), (20, AdaptiveState::MemoryBound), "the waiting four take the room");
        // The positive control: twenty in flight at 0.03 each leave room for
        // ten more, and the window takes its step.
        assert_eq!(at(0.6, 20), (22, AdaptiveState::Probing));
    }

    #[test]
    fn a_raise_memory_stops_short_keeps_slow_start_and_its_threshold() {
        // Regrowing toward 32: room for six of the doubling's sixteen. The
        // window takes six and stays in slow start, still heading for 32.
        let mut w = primed(None);
        w.window = 16.0;
        w.slow_start_threshold = Some(32.0);
        w.observe(&Observation { running: Some(12), ..obs(0.6, 16, true) }, None);
        assert_eq!((w.limit(None), w.slow_start, w.slow_start_threshold), (22, true, Some(32.0)));
        // Room again: the next doubling reaches 32, and slow start ends there.
        w.observe(&obs(0.44, 22, true), None);
        assert_eq!((w.limit(None), w.slow_start, w.slow_start_threshold), (32, false, None));
    }

    #[test]
    fn a_window_at_its_ceiling_without_room_names_the_memory() {
        // At a ceiling of 12 with no room for one more, a higher ceiling would
        // not let it grow: the memory is what is named. With room, the ceiling.
        let at = |kv: f64| {
            let mut w = primed(Some(12));
            w.window = 12.0;
            w.observe(&obs(kv, 12, true), Some(12));
            w.state()
        };
        assert_eq!(at(0.85), AdaptiveState::MemoryBound);
        assert_eq!(at(0.5), AdaptiveState::AtCeiling);
    }

    #[test]
    fn with_data_parallel_ranks_the_room_is_the_fullest_ranks() {
        // Four running over two ranks, the fuller at 0.5: two a rank, 0.25
        // each, and 0.4 of room on the fuller — one more, since a new request
        // may land there. Read as one rank, the same gauges would admit three.
        let mut w = primed(None);
        w.observe(&Observation { ranks: 2, ..obs(0.5, 4, true) }, None);
        assert_eq!(w.limit(None), 5);
        let mut one = primed(None);
        one.observe(&obs(0.5, 4, true), None);
        assert_eq!(one.limit(None), 7);
    }

    #[test]
    fn what_one_request_holds_is_measured_since_the_window_last_grew() {
        // Light requests before the raise (0.05 each), heavier since (0.1,
        // then 0.0815): the 0.085 of room left fits one more at the mean of
        // every reading (0.0825) and at the last reading alone, none at the
        // mean since the raise (0.0897) — which is what counts.
        let mut w = pressed_with(0.2, 4);
        assert_eq!(w.limit(None), 8);
        w.observe(&obs(0.8, 8, false), None);
        w.observe(&Observation { running: Some(10), ..obs(0.815, 8, true) }, None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::MemoryBound));
    }

    #[test]
    fn what_one_request_holds_is_measured_afresh_after_a_cut() {
        // Heavy requests (0.1 each) until a preemption cuts the window, then
        // light ones (0.02 each): the room is read at the light ones' size,
        // not averaged with the heavy ones the cut answered.
        let mut w = primed(None);
        w.window = 16.0;
        for _ in 0..3 {
            w.observe(&obs(0.8, 8, false), None);
        }
        w.observe(&with_preemptions(obs(0.8, 8, false), 1.0), None);
        assert_eq!(w.state(), AdaptiveState::BackingOff);
        let light = Observation { running: Some(25), ..with_preemptions(obs(0.5, 4, false), 1.0) };
        w.observe(&light, None);
        assert_eq!(w.fit(&light), Some(20.0));
    }

    #[test]
    fn a_shift_to_longer_requests_is_read_before_the_mean_follows() {
        // Since the raise, light requests (0.025 each), then six holding 0.6:
        // 0.1 each now, against a mean of 0.045. The 0.3 of room is three
        // more at what they hold now — not six at the mean.
        let mut w = pressed_with(0.2, 4);
        assert_eq!(w.limit(None), 8);
        w.observe(&obs(0.2, 8, false), None);
        w.observe(&obs(0.2, 8, false), None);
        w.observe(&Observation { running: Some(6), ..obs(0.6, 8, true) }, None);
        assert_eq!(w.limit(None), 11);
    }

    #[test]
    fn a_full_cache_backs_off_on_both_sides_of_the_ceiling() {
        let mut below = primed(None);
        below.observe(&obs(KV_CEILING - 0.01, 4, false), None);
        assert_eq!(below.state(), AdaptiveState::Steady);
        let mut at = primed(None);
        at.observe(&obs(KV_CEILING, 4, false), None);
        assert_eq!((at.limit(None), at.state()), (2, AdaptiveState::BackingOff));
    }

    #[test]
    fn a_back_off_halves_what_is_in_flight_not_an_unused_window() {
        let mut w = wide_open();
        w.observe(&with_preemptions(obs(0.6, 10, false), 3.0), None);
        assert_eq!(w.limit(None), 5);
    }

    /// A window of 128 with nothing yet learned of the workload, so the next
    /// reading's cut is the only thing that moves it.
    fn wide_open() -> AdaptiveWindow {
        let mut w = primed(None);
        for _ in 0..5 {
            w.observe(&light(obs(0.1, 4, true)), None);
        }
        assert_eq!(w.limit(None), 128);
        w
    }

    #[test]
    fn a_full_cache_alone_halves_what_is_in_flight() {
        let mut w = wide_open();
        w.observe(&obs(0.99, 20, false), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::BackingOff));
        assert_eq!(w.decisions().cut_kv_full, 1);
    }

    #[test]
    fn a_full_cache_with_one_request_out_keeps_one() {
        let mut w = wide_open();
        w.observe(&obs(0.99, 1, false), None);
        assert_eq!((w.window, w.state()), (MIN_WINDOW, AdaptiveState::BackingOff));
        // A cut that cannot lower the window is no cut: the count stays at the
        // one that did.
        for _ in 0..3 {
            w.observe(&obs(0.99, 1, false), None);
            assert_eq!((w.window, w.state()), (MIN_WINDOW, AdaptiveState::BackingOff));
        }
        assert_eq!(w.decisions().cut_kv_full, 1);
    }

    #[test]
    fn a_full_cache_under_a_window_already_below_half_cuts_nothing() {
        // A window of 9 with 20 in flight: half the flight, 10, is no cut, and
        // a real one is not held behind it once the flight drains.
        let mut w = wide_open();
        w.window = 9.0;
        w.observe(&obs(0.98, 20, false), None);
        assert_eq!((w.limit(None), w.decisions().cut_kv_full), (9, 0));
        w.observe(&obs(0.99, 16, false), None);
        assert_eq!((w.limit(None), w.decisions().cut_kv_full), (8, 1));
    }

    #[test]
    fn a_full_cache_that_preempted_is_cut_by_half() {
        let mut w = wide_open();
        w.observe(&with_preemptions(obs(0.99, 20, false), 1.0), None);
        assert_eq!(w.limit(None), 10);
        assert_eq!(w.decisions().cut_preemption, 1);
    }

    #[test]
    fn a_counter_that_fell_is_a_restart_not_a_preemption() {
        let mut w = primed(None);
        w.observe(&with_preemptions(obs(0.1, 4, true), 50.0), None);
        assert_eq!(w.state(), AdaptiveState::BackingOff);
        let before = w.limit(None);
        w.observe(&with_preemptions(obs(0.1, 2, true), 0.0), None);
        assert_eq!(w.state(), AdaptiveState::Probing);
        assert!(w.limit(None) > before);
    }

    #[test]
    fn an_engine_queue_with_memory_to_spare_holds_the_window() {
        let mut w = primed(None);
        let queued = |running| Observation { waiting: 5, running: Some(running), ..obs(0.3, 40, true) };
        for _ in 0..4 {
            w.observe(&light(obs(0.1, 4, true)), None);
        }
        w.observe(&queued(32), None);
        assert_eq!(w.state(), AdaptiveState::Probing, "one queued reading is an arrival, not a queue held");
        // 4 → 64 on light readings; then forty in flight, five of them waiting
        // in the engine, and room for 64 more at 0.3 over 32 running: 99.
        assert_eq!(w.limit(None), 99);
        w.observe(&queued(32), None);
        assert_eq!(w.state(), AdaptiveState::EngineQueueing);
        assert_eq!(w.limit(None), 99, "neither grown nor cut");
    }

    #[test]
    fn an_engine_queue_is_named_while_the_running_count_moves() {
        let mut w = primed(None);
        w.observe(&Observation { waiting: 5, running: Some(30), ..obs(0.3, 40, true) }, None);
        w.observe(&Observation { waiting: 5, running: Some(32), ..obs(0.3, 40, true) }, None);
        assert_eq!(w.state(), AdaptiveState::EngineQueueing);
    }

    #[test]
    fn an_engine_queue_at_the_kv_target_is_memory_not_a_batch_cap() {
        let mut w = primed(None);
        let full = Observation { waiting: 5, running: Some(32), ..obs(KV_TARGET, 40, true) };
        w.observe(&full, None);
        w.observe(&full, None);
        assert_eq!(w.state(), AdaptiveState::MemoryBound);
    }

    #[test]
    fn the_ceiling_bounds_the_window_and_a_lowered_one_applies_at_once() {
        let mut w = primed(Some(10));
        for _ in 0..6 {
            w.observe(&obs(0.1, 10, true), Some(10));
        }
        assert_eq!(w.limit(Some(10)), 10);
        assert_eq!(w.limit(Some(3)), 3, "the limit reads the ceiling as it is now");
    }

    #[test]
    fn a_first_reading_starts_from_what_is_already_in_flight() {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&obs(0.95, 200, false), None);
        assert_eq!((w.limit(None), w.state()), (200, AdaptiveState::Starting));
        // Within the ceiling all the same.
        let mut capped = AdaptiveWindow::new(Some(50));
        capped.observe(&obs(0.95, 200, false), Some(50));
        assert_eq!(capped.limit(Some(50)), 50);
    }

    #[test]
    fn a_lasting_signal_does_not_compound_the_cut() {
        let mut w = wide_open();
        // The cache stays full for several readings while 60 are still out.
        for _ in 0..6 {
            w.observe(&obs(0.98, 60, false), None);
            assert_eq!((w.limit(None), w.state()), (30, AdaptiveState::BackingOff));
        }
    }

    #[test]
    fn a_cut_waits_for_the_flight_to_drain_before_the_next() {
        let mut w = wide_open();
        w.observe(&obs(0.98, 60, false), None);
        assert_eq!(w.limit(None), 30);
        // The cache stays full while the work above the window finishes.
        for in_flight in [50, 40, 31] {
            w.observe(&obs(0.98, in_flight, false), None);
            assert_eq!((w.limit(None), w.state()), (30, AdaptiveState::BackingOff), "{in_flight} in flight");
        }
        // Drained to the window and still full: the window is too large.
        w.observe(&obs(0.98, 30, false), None);
        assert_eq!(w.limit(None), 15);
    }

    #[test]
    fn a_window_at_its_ceiling_says_so_instead_of_probing() {
        let mut w = primed(Some(8));
        w.observe(&obs(0.1, 4, true), Some(8));
        assert_eq!((w.limit(Some(8)), w.state()), (8, AdaptiveState::Probing));
        w.observe(&obs(0.1, 8, true), Some(8));
        assert_eq!((w.limit(Some(8)), w.state()), (8, AdaptiveState::AtCeiling));
    }

    #[test]
    fn a_reading_without_the_kv_gauge_moves_and_teaches_nothing() {
        let mut w = AdaptiveWindow::new(None);
        let blind = |in_flight, preemptions| Observation {
            kv_usage: None,
            ..with_preemptions(obs(0.0, in_flight, true), preemptions)
        };
        w.observe(&blind(10, 0.0), None);
        w.observe(&blind(10, 5.0), None);
        assert!(!w.steerable() && w.blind());
        assert_eq!((w.limit(None), w.state()), (4, AdaptiveState::NoReading));
        assert_eq!(w.unheard_limit(None), None, "nothing was learned");
        // The gauge comes back with 100 out: a first reading, seeded from it.
        w.observe(&obs(0.5, 100, false), None);
        assert!(w.steerable());
        assert_eq!((w.limit(None), w.state()), (100, AdaptiveState::Starting));
        // A steered window losing the gauge compares nothing across the gap.
        w.observe(&blind(100, 0.0), None);
        w.observe(&with_preemptions(obs(0.5, 100, false), 50.0), None);
        assert_eq!((w.limit(None), w.state()), (100, AdaptiveState::Starting));
    }

    #[test]
    fn a_first_reading_below_the_starting_guess_teaches_nothing() {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&obs(0.1, 3, false), None);
        assert_eq!(w.unheard_limit(None), None);
        let mut w = AdaptiveWindow::new(None);
        w.observe(&obs(0.1, INITIAL_WINDOW as u32, false), None);
        assert_eq!(w.unheard_limit(None), None, "exactly the starting guess teaches nothing either");
        let mut w = AdaptiveWindow::new(None);
        w.observe(&obs(0.1, 5, false), None);
        assert_eq!(w.unheard_limit(None), Some(5));
    }

    #[test]
    fn a_first_reading_on_a_full_cache_only_seeds() {
        let mut w = AdaptiveWindow::new(None);
        assert!(!w.steerable());
        w.observe(&with_preemptions(obs(0.98, 40, false), 3.0), None);
        assert_eq!((w.limit(None), w.state()), (40, AdaptiveState::Starting));
        assert!(w.steerable());
        assert_eq!(w.unheard_limit(None), Some(40), "work found in flight is learned");
        // The next reading acts on it.
        w.observe(&with_preemptions(obs(0.98, 40, false), 3.0), None);
        assert_eq!((w.limit(None), w.state()), (20, AdaptiveState::BackingOff));
    }

    #[test]
    fn a_resumed_window_compares_with_nothing_and_starts_from_its_flight() {
        let mut w = primed(None);
        w.observe(&with_preemptions(obs(0.5, 4, false), 0.0), None);
        w.resume();
        // A counter that rose across the silence is not a preemption now.
        w.observe(&with_preemptions(obs(0.5, 30, false), 99.0), None);
        assert_eq!((w.limit(None), w.state()), (30, AdaptiveState::Starting));
    }

    #[test]
    fn an_unheard_engine_takes_the_ceiling_else_what_was_learned_else_nothing() {
        let mut w = AdaptiveWindow::new(None);
        assert_eq!(w.unheard_limit(Some(9)), Some(9));
        assert_eq!(w.unheard_limit(None), None, "a starting guess is not a limit");
        w.observe(&obs(0.1, 0, false), None);
        assert_eq!(w.unheard_limit(None), None, "an idle first reading teaches nothing");
        w.observe(&obs(0.1, 1, false), None);
        assert_eq!((w.state(), w.unheard_limit(None)), (AdaptiveState::Steady, None), "nor does a step that moved nothing");
        w.observe(&obs(0.1, 4, true), None);
        assert_eq!(w.unheard_limit(None), Some(8));
        assert_eq!(w.unheard_limit(Some(3)), Some(3), "within the ceiling");
        assert_eq!(w.unheard_limit(Some(64)), Some(8), "never the ceiling above what was learned");
    }

    #[test]
    fn a_ceiling_clamp_teaches_nothing() {
        let mut w = primed(None);
        w.observe(&obs(0.1, 1, false), Some(2));
        assert_eq!(w.limit(Some(2)), 2);
        assert_eq!(w.unheard_limit(None), None, "the clamp was the operator's, not the engine's");
    }

    #[test]
    fn a_ceiling_above_the_default_maximum_is_the_operators() {
        let mut w = primed(Some(2000));
        for _ in 0..10 {
            w.observe(&light(obs(0.1, 4, true)), Some(2000));
        }
        assert!(w.limit(Some(2000)) > 1024);
    }

    #[test]
    fn a_replica_with_nothing_in_flight_cuts_nothing_for_someone_elses_pressure() {
        let mut w = primed(None);
        for _ in 0..3 {
            w.observe(&obs(0.1, 4, true), None);
        }
        let before = w.limit(None);
        w.observe(&with_preemptions(obs(0.99, 0, false), 5.0), None);
        assert_eq!((w.limit(None), w.state()), (before, AdaptiveState::Steady));
        let queued = Observation { waiting: 3, running: Some(20), ..obs(0.3, 0, false) };
        w.observe(&queued, None);
        w.observe(&queued, None);
        assert_eq!(w.state(), AdaptiveState::EngineQueueing, "the queue is still named");
        assert_eq!(w.limit(None), before);
        // With something in flight, an engine queue still cuts nothing: it
        // may be someone else's traffic keeping it full.
        w.observe(&Observation { in_flight: 10, ..queued }, None);
        assert_eq!(w.limit(None), before);
    }

    fn close(a: Option<f64>, b: f64) -> bool {
        a.is_some_and(|a| (a - b).abs() < 1e-9)
    }

    #[test]
    fn a_queue_that_drained_is_not_a_batch_cap() {
        let mut w = primed(None);
        w.observe(&Observation { waiting: 5, running: Some(30), ..obs(0.3, 30, true) }, None);
        w.observe(&Observation { waiting: 0, running: Some(30), ..obs(0.3, 30, true) }, None);
        assert_eq!(w.state(), AdaptiveState::Probing);
    }

    #[test]
    fn every_state_reads_back_as_itself_from_storage() {
        for state in [
            AdaptiveState::Steady,
            AdaptiveState::Starting,
            AdaptiveState::LatencyBound,
            AdaptiveState::Probing,
            AdaptiveState::MemoryBound,
            AdaptiveState::AtCeiling,
            AdaptiveState::EngineQueueing,
            AdaptiveState::BackingOff,
            AdaptiveState::NoReading,
            AdaptiveState::Unknown,
        ] {
            assert_eq!(AdaptiveState::from_stored(state.as_str()), state);
        }
        assert_eq!(AdaptiveState::from_stored("draining"), AdaptiveState::Unknown);
    }

    #[test]
    fn a_memory_bound_replica_outranks_one_at_its_ceiling() {
        // Folded over replicas sharing an engine, the memory is what to show:
        // shown "at ceiling", an operator raises a ceiling that only lets the
        // window overshoot memory.
        assert!(AdaptiveState::MemoryBound.pressure() > AdaptiveState::AtCeiling.pressure());
    }

    #[test]
    fn a_report_missing_a_decision_kind_reads_it_as_none() {
        let read: AdaptiveDecisions = serde_json::from_str(r#"{"grew":3,"cut_kv_full":1}"#).expect("readable");
        assert_eq!(read, AdaptiveDecisions { grew: 3, cut_kv_full: 1, ..AdaptiveDecisions::default() });
    }

    #[test]
    fn a_report_carrying_a_decision_kind_this_build_does_not_know_still_reads() {
        // The edge's outbox resends a record as it was stored: one written by
        // an older process must not stall it.
        let read: AdaptiveDecisions = serde_json::from_str(r#"{"grew":3,"cut_prefix":2}"#).expect("readable");
        assert_eq!(read, AdaptiveDecisions { grew: 3, ..AdaptiveDecisions::default() });
    }

    #[test]
    fn a_state_from_a_newer_gateway_reads_as_unknown_not_as_a_failure() {
        let read: AdaptiveState = serde_json::from_str("\"draining\"").expect("readable");
        assert_eq!(read, AdaptiveState::Unknown);
        for state in [AdaptiveState::Steady, AdaptiveState::BackingOff, AdaptiveState::NoReading] {
            let wire = serde_json::to_string(&state).expect("serialises");
            assert_eq!(wire, format!("\"{}\"", state.as_str()));
        }
        assert!(AdaptiveState::NoReading.pressure() > AdaptiveState::BackingOff.pressure());
        assert!(AdaptiveState::Unknown.pressure() < AdaptiveState::Steady.pressure());
    }

    fn at(o: Observation, at: Instant) -> Observation {
        Observation { at, ..o }
    }

    fn with_ttft(o: Observation, count: f64, sum: f64) -> Observation {
        Observation { counters: EngineCounters { ttft_count: Some(count), ttft_sum: Some(sum), ..o.counters }, ..o }
    }

    /// A window grown to 64 by limited readings at `t0`.
    fn grown_to_64(t0: Instant) -> AdaptiveWindow {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&at(obs(0.1, 0, false), t0), None);
        for in_flight in [4, 8, 16, 32] {
            w.observe(&at(obs(0.1, in_flight, true), t0), None);
        }
        assert_eq!(w.limit(None), 64);
        w
    }

    #[test]
    fn a_window_nothing_used_for_the_idle_spell_restarts_from_the_starting_guess() {
        let t0 = Instant::now();
        let mut w = grown_to_64(t0);
        let idle = |s: u64, ms: u64| at(obs(0.1, 0, false), t0 + Duration::from_secs(s) + Duration::from_millis(ms));
        w.observe(&idle(1, 0), None);
        w.observe(&idle(1 + IDLE_RESTART.as_secs() - 1, 999), None);
        assert_eq!(w.limit(None), 64, "one millisecond short of the idle spell");
        w.observe(&idle(1 + IDLE_RESTART.as_secs(), 0), None);
        assert_eq!((w.limit(None), w.state()), (INITIAL_WINDOW as u32, AdaptiveState::Steady));
        // Unheard, the restarted window is the limit: a burst whose engine goes
        // quiet must not go out at the size the restart took back.
        assert_eq!(w.unheard_limit(None), Some(INITIAL_WINDOW as u32));
        // The restart is once per spell: a later idle reading of the same spell
        // leaves the window and where slow start ends alone.
        w.observe(&idle(3 + IDLE_RESTART.as_secs(), 0), None);
        assert_eq!(w.limit(None), INITIAL_WINDOW as u32);
        // Slow start again, up to the window it restarted from, then additive.
        let burst = |s: u64, in_flight| at(obs(0.1, in_flight, true), t0 + Duration::from_secs(120 + s));
        for (s, expect) in [(0, 8), (2, 16), (4, 32), (6, 64), (8, 66)] {
            w.observe(&burst(s, expect / 2), None);
            assert_eq!((w.limit(None), w.state()), (expect, AdaptiveState::Probing), "at +{s}s");
        }
    }

    #[test]
    fn a_window_that_never_learned_restarts_into_a_full_slow_start() {
        // Created at the guess, idle from the start (the poller reads it
        // before any request): its restart sets no threshold, so the first
        // burst doubles it as it would a new window's.
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&at(obs(0.1, 0, false), t0), None);
        w.observe(&at(obs(0.1, 0, false), t0 + Duration::from_secs(1)), None);
        w.observe(&at(obs(0.1, 0, false), t0 + Duration::from_secs(1) + IDLE_RESTART), None);
        for expect in [8, 16, 32, 64] {
            w.observe(&at(obs(0.1, expect / 2, true), t0 + Duration::from_secs(60)), None);
            assert_eq!(w.limit(None), expect, "slow start");
        }
    }

    #[test]
    fn a_window_cut_below_the_guess_restarts_where_it_is() {
        // Cut to 3 by an overload, then idle: a restart never RAISES a window,
        // and the cut window is its own threshold, so it grows additively as
        // it did before the spell — not by doubling, which would flood the
        // engine that just showed it cannot take more.
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&at(obs(0.1, 4, false), t0), None);
        w.observe(&at(with_preemptions(obs(0.6, 6, false), 1.0), t0), None);
        assert_eq!(w.limit(None), 3);
        w.observe(&at(obs(0.1, 0, false), t0 + Duration::from_secs(1)), None);
        w.observe(&at(obs(0.1, 0, false), t0 + Duration::from_secs(1) + IDLE_RESTART), None);
        assert_eq!(w.limit(None), 3);
        let mut in_flight = 3;
        for expect in [5, 7, 9, 11] {
            w.observe(&at(obs(0.1, in_flight, true), t0 + Duration::from_secs(60)), None);
            assert_eq!(w.limit(None), expect, "additive from the cut window");
            in_flight = expect;
        }
    }

    #[test]
    fn carried_pressure_ends_with_the_work_that_made_it() {
        // Pressed at a reading whose step still waits for its round trip, then
        // traffic stops: an idle reading carries nothing, so the window does
        // not grow with nothing pressing it — nor double right after a restart.
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.1, 4, true), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.2, 8, true), t0 + Duration::from_secs(2)), 101.0, 510.0), None);
        assert_eq!(w.limit(None), 8, "pressure kept for the round trip");
        w.observe(&with_ttft(at(obs(0.2, 0, false), t0 + Duration::from_secs(10)), 102.0, 520.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::Steady), "paced, but nothing is out any more");
        // Idle through the spell: the restart is not followed by a doubling.
        w.observe(&with_ttft(at(obs(0.2, 0, false), t0 + Duration::from_secs(41)), 102.0, 520.0), None);
        assert_eq!((w.limit(None), w.state()), (INITIAL_WINDOW as u32, AdaptiveState::Steady));
    }

    #[test]
    fn pressure_waits_out_the_round_trip_instead_of_being_lost() {
        // Pressed at a reading whose step still waits for its round trip; by
        // the paced reading the queue has gone (the request spilled elsewhere,
        // or gave up). The pressure counts there all the same.
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.1, 4, true), t0), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 8);
        w.observe(&with_ttft(at(obs(0.2, 8, true), t0 + Duration::from_secs(2)), 101.0, 510.0), None);
        assert_eq!(w.limit(None), 8, "pressed, but 2 s is short of a 10 s round trip");
        w.observe(&with_ttft(at(obs(0.2, 8, false), t0 + Duration::from_secs(10)), 102.0, 520.0), None);
        assert_eq!((w.limit(None), w.state()), (16, AdaptiveState::Probing));
        // Used once: the next unpressed reading grows nothing.
        w.observe(&with_ttft(at(obs(0.2, 8, false), t0 + Duration::from_secs(30)), 104.0, 540.0), None);
        assert_eq!((w.limit(None), w.state()), (16, AdaptiveState::Steady));
    }

    #[test]
    fn work_in_flight_keeps_the_window_however_long_it_lasts() {
        let t0 = Instant::now();
        let mut w = grown_to_64(t0);
        for minute in 1..=10 {
            w.observe(&at(obs(0.1, 1, false), t0 + Duration::from_secs(60 * minute)), None);
        }
        assert_eq!(w.limit(None), 64);
        // One busy reading starts the idle spell over.
        let t1 = t0 + Duration::from_secs(700);
        w.observe(&at(obs(0.1, 0, false), t1), None);
        w.observe(&at(obs(0.1, 1, false), t1 + Duration::from_secs(20)), None);
        w.observe(&at(obs(0.1, 0, false), t1 + Duration::from_secs(21)), None);
        w.observe(&at(obs(0.1, 0, false), t1 + Duration::from_secs(21) + IDLE_RESTART - Duration::from_millis(1)), None);
        assert_eq!(w.limit(None), 64, "the spell counts from the last busy reading");
        w.observe(&at(obs(0.1, 0, false), t1 + Duration::from_secs(21) + IDLE_RESTART), None);
        assert_eq!(w.limit(None), INITIAL_WINDOW as u32);
    }

    #[test]
    fn growth_waits_for_the_engines_round_trip() {
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t0), 100.0, 500.0), None);
        // The first growth of a busy period is not held back.
        w.observe(&with_ttft(at(obs(0.1, 4, true), t0), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 8);
        // Five first tokens since, averaging 10 s: no growth before 10 s.
        let after = |ms: u64| t0 + Duration::from_millis(ms);
        w.observe(&with_ttft(at(obs(0.2, 8, true), after(9_999)), 105.0, 550.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::Probing), "a millisecond short of the round trip");
        w.observe(&with_ttft(at(obs(0.2, 8, true), after(10_000)), 105.0, 550.0), None);
        assert_eq!(w.limit(None), 16, "one round trip on");
    }

    #[test]
    fn growth_waits_for_a_first_token_at_most_the_longest_pace() {
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.1, 4, true), t0), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 8);
        // Nothing has reached its first token since that growth.
        w.observe(&with_ttft(at(obs(0.2, 8, true), t0 + PACE_MAX - Duration::from_millis(1)), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 8, "nothing admitted has shown up yet");
        w.observe(&with_ttft(at(obs(0.2, 8, true), t0 + PACE_MAX), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 16, "the longest pace ends the wait");
    }

    #[test]
    fn a_restarted_first_token_counter_paces_nothing() {
        let t0 = Instant::now();
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.1, 4, true), t0), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.2, 8, true), t0 + Duration::from_secs(1)), 3.0, 1.0), None);
        assert_eq!(w.limit(None), 16);
    }

    #[test]
    fn a_burst_after_idle_restarts_paces_and_cuts_without_compounding() {
        let t0 = Instant::now();
        let mut w = grown_to_64(t0);
        let t = |s: u64| t0 + Duration::from_secs(s);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t(1)), 100.0, 500.0), None);
        w.observe(&with_ttft(at(obs(0.1, 0, false), t(31)), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 4, "restarted");
        // The burst: 4 out, pressed. The first growth goes at once.
        w.observe(&with_ttft(at(obs(0.2, 4, true), t(60)), 100.0, 500.0), None);
        assert_eq!(w.limit(None), 8);
        // Two first tokens at 5 s each: 2 s is too soon, 6 s is not.
        w.observe(&with_ttft(at(light(obs(0.4, 8, true)), t(62)), 102.0, 510.0), None);
        assert_eq!(w.limit(None), 8);
        w.observe(&with_ttft(at(light(obs(0.5, 8, true)), t(66)), 104.0, 520.0), None);
        assert_eq!(w.limit(None), 16);
        // The cache fills as the answers grow: one cut, then none until the
        // flight has drained to it.
        w.observe(&with_ttft(at(obs(0.98, 16, false), t(68)), 110.0, 550.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::BackingOff));
        w.observe(&with_ttft(at(obs(0.98, 12, false), t(70)), 112.0, 560.0), None);
        assert_eq!(w.limit(None), 8, "the cut has not taken effect yet");
        w.observe(&with_ttft(at(obs(0.98, 8, false), t(72)), 114.0, 570.0), None);
        assert_eq!(w.limit(None), 4, "drained to the window and still full");
    }


    fn arbitrary_observation() -> impl Strategy<Value = Observation> {
        (
            0u32..64,
            proptest::option::of(0u32..512),
            proptest::option::of(0.0f64..=1.0),
            proptest::option::of(0.0f64..1e6),
            0u32..2048,
            any::<bool>(),
            proptest::option::of((0.0f64..1e7, 0.0f64..1e7)),
            proptest::option::of((0.0f64..1e5, 0.0f64..1e6)),
            proptest::option::of((0.0f64..1e3, 0.0f64..1e6, proptest::collection::vec((0.0f64..0.3, 0.0f64..1e4), 0..4))),
            proptest::option::of((0.0f64..1e7, 0.0f64..1e7)),
        )
            .prop_map(|(waiting, running, kv_usage, preemptions, in_flight, limited, prefix, ttft, itl, tokens)| Observation {
                waiting,
                running,
                kv_usage,
                counters: EngineCounters {
                    preemptions,
                    prefix_queries: prefix.map(|(q, _)| q),
                    prefix_hits: prefix.map(|(_, h)| h),
                    ttft_count: ttft.map(|(c, _)| c),
                    ttft_sum: ttft.map(|(_, s)| s),
                    itl_sum: itl.as_ref().map(|(s, _, _)| *s),
                    itl_count: itl.as_ref().map(|(_, c, _)| *c),
                    itl_gaps: itl.as_ref().map(|(_, _, batches)| {
                        let mut h = test_gaps();
                        for (seconds, n) in batches {
                            h.record(*seconds, *n);
                        }
                        h
                    }),
                    finished_prompt_tokens: tokens.map(|(p, _)| p),
                    finished_generation_tokens: tokens.map(|(_, a)| a),
                    ..EngineCounters::default()
                },
                in_flight,
                limited,
                ranks: 1,
                at: Instant::now(),
            })
    }

    fn arbitrary_target() -> impl Strategy<Value = ItlTarget> {
        prop_oneof![Just(ItlTarget::Auto), Just(ItlTarget::Off), (0u32..500).prop_map(|ms| ItlTarget::Fixed { ms })]
    }

    /// Readings an arbitrary gap apart (up to a minute, so idle restarts and
    /// paced growth both happen), in order.
    fn timed_readings(len: std::ops::Range<usize>) -> impl Strategy<Value = Vec<Observation>> {
        proptest::collection::vec((arbitrary_observation(), 0u64..60_000), len).prop_map(|readings| {
            let mut t = Instant::now();
            readings
                .into_iter()
                .map(|(o, gap_ms)| {
                    t += Duration::from_millis(gap_ms);
                    Observation { at: t, ..o }
                })
                .collect()
        })
    }

    // ── A synthetic engine ─────────────────────────────────────────────

    /// A synthetic engine read every two seconds: it generates `g(in flight)`
    /// tokens per second, each `itl(in flight)` seconds after the one before,
    /// and gives one first token per second, each taking `t(in flight)`
    /// seconds. Whatever the window admits is in flight, each request holding
    /// `per_request` of the KV cache.
    struct Engine {
        at: Instant,
        generation: f64,
        ttft_sum: f64,
        ttft_count: f64,
        itl_sum: f64,
        gaps: GapHistogram,
        per_request: f64,
        itl: fn(u32) -> f64,
        /// Each reading one request of this many prompt and answer tokens
        /// finishes; `None` publishes no per-request counts.
        finishing: Option<(f64, f64)>,
        finished: (f64, f64),
    }

    impl Engine {
        fn new() -> Self {
            Self {
                at: Instant::now(),
                generation: 0.0,
                ttft_sum: 0.0,
                ttft_count: 0.0,
                itl_sum: 0.0,
                gaps: test_gaps(),
                per_request: 0.02,
                itl: |_| 0.03,
                finishing: None,
                finished: (0.0, 0.0),
            }
        }

        fn reading(&mut self, in_flight: u32, limited: bool, g: &dyn Fn(u32) -> f64, t: &dyn Fn(u32) -> f64) -> Observation {
            self.at += Duration::from_secs(2);
            let generated = g(in_flight) * 2.0;
            self.generation += generated;
            self.itl_sum += generated * (self.itl)(in_flight);
            record_gaps(&mut self.gaps, (self.itl)(in_flight), generated);
            self.ttft_count += 2.0;
            self.ttft_sum += t(in_flight) * 2.0;
            if let Some((prompt, answer)) = self.finishing {
                self.finished = (self.finished.0 + prompt, self.finished.1 + answer);
            }
            Observation {
                waiting: 0,
                running: Some(in_flight),
                kv_usage: Some((self.per_request * f64::from(in_flight)).min(1.0)),
                counters: EngineCounters {
                    preemptions: Some(0.0),
                    generation_tokens: Some(self.generation),
                    finished_prompt_tokens: self.finishing.map(|_| self.finished.0),
                    finished_generation_tokens: self.finishing.map(|_| self.finished.1),
                    ttft_sum: Some(self.ttft_sum),
                    ttft_count: Some(self.ttft_count),
                    itl_sum: Some(self.itl_sum),
                    itl_count: Some(self.generation),
                    itl_gaps: Some(self.gaps),
                    ..EngineCounters::default()
                },
                in_flight,
                limited,
                ranks: 1,
                at: self.at,
            }
        }
    }

    #[test]
    fn the_window_counts_its_growth_and_its_back_offs_by_cause() {
        let mut w = primed(None);
        w.observe(&obs(0.2, 4, true), None);
        assert_eq!(w.decisions().grew, 1);
        w.observe(&with_preemptions(obs(0.5, 8, true), 1.0), None);
        w.observe(&obs(0.98, 2, true), None);
        let d = w.decisions();
        assert_eq!((d.grew, d.cut_preemption, d.cut_kv_full), (1, 1, 1), "{d:?}");
    }

    // ── End size ──────────────────────────────────────────────────────────

    /// The reading with the engine's finished requests having counted
    /// `prompt` and `answer` tokens so far.
    fn with_tokens(o: Observation, prompt: f64, answer: f64) -> Observation {
        Observation {
            counters: EngineCounters {
                finished_prompt_tokens: Some(prompt),
                finished_generation_tokens: Some(answer),
                ..o.counters
            },
            ..o
        }
    }

    /// A primed window whose engine finished requests of `prompt` and `answer`
    /// tokens between two readings, then four running requests holding 0.1 each by
    /// the gauge (0.4 in all): the limit and state after that pressed reading.
    fn pressed_with_mix(prompt: f64, answer: f64) -> (u32, AdaptiveState) {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_tokens(obs(0.1, 0, false), 0.0, 0.0), None);
        w.observe(&with_tokens(obs(0.4, 4, true), prompt, answer), None);
        (w.limit(None), w.state())
    }

    #[test]
    fn a_raise_counts_each_request_at_its_end_size_on_both_sides() {
        // By the gauge alone five more fit, and slow start doubles to 8; an
        // engine that counted only prompt tokens says the same — a request
        // holding its whole prompt grows no further.
        assert_eq!(pressed_with_mix(0.0, 0.0), (8, AdaptiveState::Probing), "no token counted");
        assert_eq!(pressed_with_mix(1_000.0, 0.0), (8, AdaptiveState::Probing), "all prompt");
        // As many answer as prompt tokens: a request ends at 4/3 of the
        // average, 0.133 each; the four commit 0.533, and the rest fits two.
        assert_eq!(pressed_with_mix(1_000.0, 1_000.0), (6, AdaptiveState::Probing), "half and half");
        // The edge is a growth of 1.8 — eight answer tokens to one prompt:
        // just under it one more fits, just over it none.
        assert_eq!(pressed_with_mix(1_000.0, 7_900.0), (5, AdaptiveState::Probing), "room for one");
        assert_eq!(pressed_with_mix(1_000.0, 8_100.0), (4, AdaptiveState::MemoryBound), "room for none");
        // All answer: twice the average, 0.2 each, 0.8 committed.
        assert_eq!(pressed_with_mix(0.0, 1_000.0), (4, AdaptiveState::MemoryBound), "all answer");
    }

    #[test]
    fn the_end_size_is_not_diluted_by_requests_still_in_their_prefill() {
        // Nine running at 0.093 each over the run, on prompts alone (a growth
        // of one). A preemption cuts the window, and the next reading is
        // taken just after admissions: eight running at 0.624, 0.078 each —
        // requests still filling their prompts. The end size is the run's
        // 0.093: eight commit 0.744, and one more fits. Without finished requests
        // (the positive control) there is no end size, and the gauge as it
        // stands fits three.
        for (counted, expected) in [(true, 1.0), (false, 3.0)] {
            let mut w = AdaptiveWindow::new(None);
            let mut prompt = 0.0;
            let mut reading = |o: Observation| {
                prompt += 10_000.0;
                if counted { with_tokens(o, prompt, 0.0) } else { o }
            };
            for _ in 0..10 {
                w.observe(&reading(obs(0.837, 9, false)), None);
            }
            w.observe(&reading(with_preemptions(obs(0.837, 9, false), 1.0)), None);
            assert_eq!(w.state(), AdaptiveState::BackingOff);
            assert!(close(w.workload.held(), 0.093), "{:?}", w.workload.held());
            let diluted = reading(Observation { running: Some(8), ..with_preemptions(obs(0.624, 8, true), 1.0) });
            assert_eq!(w.fit(&diluted), Some(expected), "token counters: {counted}");
        }
    }

    #[test]
    fn the_growth_is_learned_from_finished_requests_only_where_their_counters_rose() {
        let mut w = AdaptiveWindow::new(None);
        // A first reading compares nothing: no interval, no mix.
        w.observe(&with_tokens(obs(0.1, 0, false), 1_000.0, 1_000.0), None);
        assert_eq!(w.growth(), None);
        // An interval in which nothing finished, or a counter missing, says
        // nothing.
        w.observe(&with_tokens(obs(0.1, 0, false), 1_000.0, 1_000.0), None);
        assert_eq!((w.growth(), w.workload.intervals), (None, 0), "nothing finished");
        w.observe(&obs(0.1, 0, false), None);
        assert_eq!(w.growth(), None, "no counters");
        w.observe(&with_tokens(obs(0.1, 0, false), 5_000.0, 5_000.0), None);
        assert_eq!(w.growth(), None, "nothing to compare with");
        // The positive control: 1 000 of each finished, a growth of 4/3.
        w.observe(&with_tokens(obs(0.1, 0, false), 6_000.0, 6_000.0), None);
        assert!(close(w.growth(), 4.0 / 3.0), "{:?}", w.growth());
        assert_eq!(w.workload.intervals, 1);
        // Readings that went stale: the rise across them is minutes of traffic
        // in one interval, and teaches nothing.
        w.resume();
        w.observe(&with_tokens(obs(0.1, 0, false), 1_006_000.0, 26_000.0), None);
        assert!(close(w.growth(), 4.0 / 3.0), "{:?}", w.growth());
        // The flow of tokens is not the mix: an engine counting prompts and
        // answer tokens as it makes them, with nothing finished, teaches
        // nothing.
        let flowing = |p: f64, a: f64| Observation {
            counters: EngineCounters { prompt_tokens: Some(p), generation_tokens: Some(a), ..with_tokens(obs(0.1, 0, false), 1_006_000.0, 26_000.0).counters },
            ..obs(0.1, 0, false)
        };
        w.observe(&flowing(0.0, 0.0), None);
        w.observe(&flowing(50_000.0, 100.0), None);
        assert!(close(w.growth(), 4.0 / 3.0), "{:?}", w.growth());
    }

    #[test]
    fn an_engine_restart_forgets_what_the_workload_taught() {
        // Requests holding 0.08 each, half prompt and half answer; then the
        // engine's counters fall — another model behind the endpoint, perhaps.
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_tokens(obs(0.4, 5, false), 0.0, 0.0), None);
        w.observe(&with_tokens(obs(0.4, 5, false), 1_000.0, 1_000.0), None);
        assert!(w.growth().is_some() && w.workload.held().is_some());
        // The restart's reading teaches its own figure, and nothing of the mix.
        w.observe(&with_tokens(obs(0.1, 10, false), 10.0, 10.0), None);
        assert_eq!(w.growth(), None, "the mix forgotten");
        assert!(close(w.workload.held(), 0.01), "{:?}", w.workload.held());
        // A restart that outlasts the readings' freshness: the window resumes
        // as on a first reading, and the fall is still seen.
        let mut stale = AdaptiveWindow::new(None);
        stale.observe(&with_tokens(obs(0.4, 5, false), 0.0, 0.0), None);
        stale.observe(&with_tokens(obs(0.4, 5, false), 1_000.0, 1_000.0), None);
        stale.resume();
        stale.observe(&with_tokens(obs(0.1, 10, false), 10.0, 10.0), None);
        assert_eq!(stale.growth(), None, "forgotten across a stale gap");
        assert!(close(stale.workload.held(), 0.01), "{:?}", stale.workload.held());
        // An engine publishing only its answer counter: that one falling is
        // a restart too.
        let answers_only = |kv: f64, running: u32, answer: f64| Observation {
            counters: EngineCounters { finished_generation_tokens: Some(answer), ..obs(kv, running, false).counters },
            ..obs(kv, running, false)
        };
        let mut one = AdaptiveWindow::new(None);
        one.observe(&answers_only(0.4, 5, 1_000.0), None);
        one.observe(&answers_only(0.1, 10, 10.0), None);
        assert!(close(one.workload.held(), 0.01), "{:?}", one.workload.held());
        // Without a fall (the positive control) both are kept.
        let mut kept = AdaptiveWindow::new(None);
        kept.observe(&with_tokens(obs(0.4, 5, false), 0.0, 0.0), None);
        kept.observe(&with_tokens(obs(0.4, 5, false), 1_000.0, 1_000.0), None);
        kept.observe(&with_tokens(obs(0.1, 10, false), 1_000.0, 1_000.0), None);
        assert!(close(kept.growth(), 4.0 / 3.0), "{:?}", kept.growth());
        // A ratio of sums: 0.9 of KV over 20 requests across the readings.
        assert!(close(kept.workload.held(), 0.9 / 20.0), "{:?}", kept.workload.held());
    }

    #[test]
    fn the_low_load_time_per_token_counts_only_intervals_running_one_or_two() {
        let itl = Itl::default();
        // Without a target: the figure is learned all the same.
        let reading = |running: u32, sum: f64, count: f64| itl.at(obs(0.2, running, false), sum, count);
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(2, 0.0, 0.0), None);
        // 100 tokens at 20 ms with two running at both ends.
        w.observe(&reading(2, 2.0, 100.0), None);
        // Three running at one end, then at the other: neither counts — two
        // is the most a low-load interval runs.
        w.observe(&reading(3, 10.0, 200.0), None);
        w.observe(&reading(1, 18.0, 300.0), None);
        // Nothing running at one end: no count either.
        w.observe(&reading(0, 19.0, 310.0), None);
        w.observe(&reading(1, 20.0, 320.0), None);
        // 300 tokens at 40 ms with one running at both ends.
        w.observe(&reading(1, 32.0, 620.0), None);
        // Weighted by tokens: (2 + 12) / 400 = 35 ms.
        assert!(close(w.low_load_itl(), 0.035), "{:?}", w.low_load_itl());
        // One running with requests waiting, at either end: the engine is
        // computing prompts in the same steps, so neither counts.
        let queued = |waiting: u32, sum: f64, count: f64| Observation { waiting, ..reading(1, sum, count) };
        w.observe(&queued(4, 100.0, 700.0), None);
        w.observe(&queued(0, 200.0, 800.0), None);
        w.observe(&queued(0, 201.0, 850.0), None);
        // Only the last interval, waiting none at both ends: (14 + 1) / 450.
        assert!(close(w.low_load_itl(), 15.0 / 450.0), "{:?}", w.low_load_itl());
    }

    #[test]
    fn the_low_load_time_per_token_waits_for_enough_tokens() {
        let itl = Itl::default();
        let reading = |sum: f64, count: f64| itl.at(obs(0.2, 1, false), sum, count);
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(0.0, 0.0), None);
        w.observe(&reading(0.02 * (LOW_LOAD_MIN_TOKENS - 1.0), LOW_LOAD_MIN_TOKENS - 1.0), None);
        assert_eq!(w.low_load_itl(), None, "one token short");
        w.observe(&reading(0.02 * LOW_LOAD_MIN_TOKENS, LOW_LOAD_MIN_TOKENS), None);
        assert!(close(w.low_load_itl(), 0.02), "{:?}", w.low_load_itl());
    }

    #[test]
    fn an_engine_restart_forgets_the_low_load_time_per_token() {
        let itl = Itl::default();
        let reading = |sum: f64, count: f64, finished: f64| {
            with_tokens(itl.at(obs(0.2, 1, false), sum, count), finished, finished)
        };
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(0.0, 0.0, 100.0), None);
        w.observe(&reading(10.0, 500.0, 200.0), None);
        assert!(w.low_load_itl().is_some());
        // The finished counters fall: another engine, perhaps another model.
        w.observe(&reading(0.1, 5.0, 10.0), None);
        assert_eq!(w.low_load_itl(), None);
        // Nor is the interval after it learned: back at the old values it was
        // a series missing from one scrape, and its rise is a lifetime.
        let mut dip = AdaptiveWindow::new(None);
        dip.observe(&reading(0.0, 0.0, 100.0), None);
        dip.observe(&reading(10.0, 500.0, 200.0), None);
        dip.observe(&reading(0.1, 5.0, 10.0), None);
        dip.observe(&reading(10.5, 510.0, 210.0), None);
        assert_eq!(dip.low_load_itl(), None, "the lifetime is not an interval");
        // A fallen time-between-tokens count is a restart too, the finished
        // counters standing still: 20 ms was learned before it, 40 ms after,
        // and only the 40 ms stands.
        for (count_after, sum_after) in [(50.0, 1.0), (50.0, 12.0)] {
            let mut fell = AdaptiveWindow::new(None);
            fell.observe(&reading(0.0, 0.0, 100.0), None);
            fell.observe(&reading(10.0, 500.0, 100.0), None);
            fell.observe(&reading(sum_after, count_after, 100.0), None);
            assert_eq!(fell.low_load_itl(), None, "forgotten at the fall to ({count_after}, {sum_after})");
            // The interval after the fall is not learned; the one after that is.
            fell.observe(&reading(sum_after + 1.0, count_after + 10.0, 100.0), None);
            fell.observe(&reading(sum_after + 9.0, count_after + 210.0, 100.0), None);
            assert!(close(fell.low_load_itl(), 0.04), "{:?}", fell.low_load_itl());
        }
        // And behind a stale gap, where the reading before it is not the
        // previous one.
        let mut stale = AdaptiveWindow::new(None);
        stale.observe(&reading(0.0, 0.0, 100.0), None);
        stale.observe(&reading(10.0, 500.0, 100.0), None);
        stale.resume();
        stale.observe(&reading(1.0, 50.0, 100.0), None);
        assert_eq!(stale.low_load_itl(), None, "forgotten across a stale gap");
        // And behind a reading that lacked the counters: their last values
        // are kept through it.
        let mut partial = AdaptiveWindow::new(None);
        partial.observe(&reading(0.0, 0.0, 100.0), None);
        partial.observe(&reading(10.0, 500.0, 100.0), None);
        partial.observe(&with_tokens(obs(0.2, 1, false), 100.0, 100.0), None);
        partial.observe(&reading(1.0, 50.0, 100.0), None);
        assert_eq!(partial.low_load_itl(), None, "forgotten behind a partial scrape");
    }

    #[test]
    fn the_mix_is_a_mean_then_follows_a_change_of_workload_slowly() {
        // Twenty intervals of 1 000 prompt tokens: their mean. Then one of
        // 21 000 moves it a twentieth of the way — not the plain mean of 21, a
        // lifetime average that would never follow a change.
        let mut w = AdaptiveWindow::new(None);
        let (mut prompt, mut answer) = (0.0, 0.0);
        let mut interval = |w: &mut AdaptiveWindow, p: f64, a: f64| {
            prompt += p;
            answer += a;
            w.observe(&with_tokens(obs(0.1, 0, false), prompt, answer), None);
        };
        interval(&mut w, 0.0, 0.0);
        for _ in 0..20 {
            interval(&mut w, 1_000.0, 1_000.0);
        }
        assert_eq!(w.workload.tokens, Some((1_000.0, 1_000.0)));
        interval(&mut w, 21_000.0, 1_000.0);
        assert!(close(w.workload.tokens.map(|t| t.0), 2_000.0), "{:?}", w.workload.tokens);
        // Forty more at 21 000: most of the way there.
        for _ in 0..40 {
            interval(&mut w, 21_000.0, 1_000.0);
        }
        assert!(w.workload.tokens.is_some_and(|t| t.0 > 18_000.0), "{:?}", w.workload.tokens);
    }

    #[test]
    fn without_a_running_count_this_replicas_own_requests_are_counted() {
        // Four seen running at 0.1 each, and an engine counting only answer
        // tokens (each ends at 0.2). The next reading publishes no running
        // count: this replica's own requests not waiting in the engine's queue
        // run there — four commit 0.8, and nothing fits.
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_tokens(obs(0.1, 0, false), 0.0, 0.0), None);
        w.observe(&with_tokens(obs(0.4, 4, false), 0.0, 1_000.0), None);
        assert_eq!(w.state(), AdaptiveState::Steady);
        let unpublished = |waiting| Observation { running: None, waiting, ..obs(0.4, 4, true) };
        assert_eq!(w.fit(&unpublished(0)), Some(0.0), "this replica's own four");
        // Positive control: two of the four still waiting run nowhere yet —
        // two at 0.2 commit 0.4, and two more fit.
        assert_eq!(w.fit(&unpublished(2)), Some(2.0), "two queued");
        // An engine that does publish its running count is believed: two
        // running though four are in flight here (the other two between the
        // rounds of a tool loop).
        assert_eq!(w.fit(&Observation { running: Some(2), ..obs(0.2, 4, true) }), Some(2.0));
        // With no request ever seen running, nothing says what one holds.
        let fresh = AdaptiveWindow::new(None);
        assert_eq!(fresh.fit(&unpublished(0)), None, "nothing measured");
    }

    #[test]
    fn with_data_parallel_ranks_the_end_size_is_one_ranks() {
        // Two ranks, eight running (four a rank), the fullest at 0.4: 0.1 a
        // request on its rank, ending at 4/3 of that. Four at 0.133 commit
        // 0.533 of that rank, and two more fit. Read against the summed eight
        // none would fit; with the figure divided by the ranks twice, seven.
        let mut w = AdaptiveWindow::new(None);
        let ranked = |o: Observation| Observation { running: Some(8), ranks: 2, ..o };
        w.observe(&with_tokens(obs(0.1, 0, false), 0.0, 0.0), None);
        w.observe(&with_tokens(ranked(obs(0.4, 8, false)), 1_000.0, 1_000.0), None);
        assert_eq!(w.fit(&ranked(obs(0.4, 8, true))), Some(2.0));
        // One request on eight ranks, its rank at 0.05: it holds 0.05, not
        // 0.05 over an eighth of a request.
        let mut low = AdaptiveWindow::new(None);
        let alone = |limited| Observation { running: Some(1), ranks: 8, ..obs(0.05, 1, limited) };
        low.observe(&alone(false), None);
        assert!(close(low.workload.held(), 0.05), "{:?}", low.workload.held());
        // The window's own figure too: seventeen more fit beside it at 0.05
        // each — not two at 0.4.
        assert_eq!(low.fit(&alone(true)), Some(17.0));
    }

    #[test]
    fn the_mix_is_kept_through_moves_and_quiet_spells() {
        let mut w = AdaptiveWindow::new(None);
        w.observe(&with_tokens(obs(0.1, 0, false), 0.0, 0.0), None);
        w.observe(&with_tokens(obs(0.1, 0, false), 1_000.0, 1_000.0), None);
        let mix = w.workload.tokens;
        assert!(mix.is_some());
        // A preemption cuts the window: the workload is the same after it.
        w.observe(&with_preemptions(obs(0.4, 4, false), 1.0), None);
        assert_eq!(w.state(), AdaptiveState::BackingOff);
        assert_eq!(w.workload.tokens, mix, "kept through the cut");
        // A quiet spell restarts the window, and the climb back is the fastest
        // there is: the mix is kept through it too.
        let t0 = Instant::now();
        let idle = |s: u64| at(with_preemptions(obs(0.0, 0, false), 1.0), t0 + Duration::from_secs(s));
        w.observe(&idle(1), None);
        w.observe(&idle(1 + IDLE_RESTART.as_secs()), None);
        assert!(w.restarted, "restarted");
        assert_eq!(w.workload.tokens, mix, "kept through the idle restart");
        assert!(w.workload.held().is_some(), "the gauge figure kept through the idle restart");
    }

    // ── Token-latency target ─────────────────────────────────────────────

    /// The histogram bounds these tests read: every millisecond to 60 ms,
    /// then 100 and 200 ms.
    fn test_gaps() -> GapHistogram {
        let mut h = GapHistogram::default();
        for ms in (1..=60).chain([100, 200]) {
            h.add(f64::from(ms) / 1000.0, 0.0);
        }
        h.add(f64::INFINITY, 0.0);
        h
    }

    /// `n` gaps of `seconds` each, half in its bucket and half just above, so
    /// that their median alone is `seconds` exactly where it is a bound.
    fn record_gaps(h: &mut GapHistogram, seconds: f64, n: f64) {
        let ms = (seconds * 1000.0).round();
        let seconds = if (seconds * 1000.0 - ms).abs() < 1e-6 { ms / 1000.0 } else { seconds };
        h.record(seconds, n / 2.0);
        h.record(seconds + 1e-9, n / 2.0);
    }

    /// An engine's inter-token figures stated as it publishes the mean's
    /// halves — a cumulative sum of seconds and count of gaps — with the
    /// histogram they imply: each interval's gaps all at the interval's mean,
    /// so that its median is its mean. A count that falls starts the
    /// histogram afresh, as a restarted engine does.
    #[derive(Default)]
    struct Itl(std::cell::Cell<Option<(f64, f64, GapHistogram)>>);

    impl Itl {
        fn at(&self, o: Observation, sum: f64, count: f64) -> Observation {
            let (sum_before, count_before, mut h) = match self.0.get() {
                Some((s, c, h)) if count >= c => (s, c, h),
                _ => (0.0, 0.0, test_gaps()),
            };
            if count > count_before {
                record_gaps(&mut h, ((sum - sum_before) / (count - count_before)).max(0.0), count - count_before);
            }
            self.0.set(Some((sum, count, h)));
            Observation {
                counters: EngineCounters { itl_sum: Some(sum), itl_count: Some(count), itl_gaps: Some(h), ..o.counters },
                ..o
            }
        }
    }

    /// A window of 10 out of slow start, with a 50 ms target, its round
    /// started at the reading it was primed on. The engine publishes no
    /// first-token figures, so every reading ends a round.
    fn latency_window() -> AdaptiveWindow {
        let itl = Itl::default();
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        w.observe(&itl.at(light(obs(0.3, 0, false)), 0.0, 0.0), None);
        w.window = 10.0;
        w.slow_start = false;
        w.observe(&itl.at(light(obs(0.3, 10, false)), 0.0, 0.0), None);
        w
    }

    #[test]
    fn a_round_is_judged_on_its_median_gap_so_prefill_stalls_alone_do_not_step_down() {
        // A round of 1 000 gaps: 900 at 40 ms, 100 stalled 6 s behind a new
        // prompt's prefill. Their mean is 636 ms; their median, 40 ms, is
        // within the 50 ms target, and the pressed window grows.
        let stalled = |h: &mut GapHistogram, decode: f64| {
            record_gaps(h, decode, 900.0);
            record_gaps(h, 6.0, 100.0);
        };
        let mut w = latency_window();
        let mut gaps = test_gaps();
        stalled(&mut gaps, 0.04);
        let reading = |gaps: GapHistogram| Observation {
            counters: EngineCounters { itl_gaps: Some(gaps), ..light(obs(0.3, 10, true)).counters },
            ..light(obs(0.3, 10, true))
        };
        w.observe(&reading(gaps), None);
        assert_eq!((w.limit(None), w.state()), (12, AdaptiveState::Probing), "within, stalls and all");
        // The positive control: the decode itself at 60 ms is above it.
        let mut w = latency_window();
        let mut gaps = test_gaps();
        stalled(&mut gaps, 0.06);
        w.observe(&reading(gaps), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "the batch is slow");
    }

    #[test]
    fn the_low_load_figure_is_the_median_gap_not_the_mean() {
        // One running, 300 gaps at 20 ms and 20 stalled 5 s each interval.
        let mut w = AdaptiveWindow::new(None);
        let mut gaps = test_gaps();
        let reading = |gaps: GapHistogram| Observation {
            counters: EngineCounters { itl_gaps: Some(gaps), ..obs(0.2, 1, false).counters },
            ..obs(0.2, 1, false)
        };
        w.observe(&reading(gaps), None);
        for _ in 0..2 {
            record_gaps(&mut gaps, 0.02, 300.0);
            record_gaps(&mut gaps, 5.0, 20.0);
            w.observe(&reading(gaps), None);
        }
        // Within the 20 ms bucket's millisecond; the mean would be 330 ms.
        let figure = w.low_load_itl().expect("learned");
        assert!((0.02..0.021).contains(&figure), "{figure}");
    }

    #[test]
    fn a_round_above_the_latency_target_steps_down_on_both_sides() {
        let itl = Itl::default();
        // Exactly the target: within it, and the pressed window grows.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 50.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (12, AdaptiveState::Probing), "at the target");
        // Just above: one step down.
        let itl = Itl::default();
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 50.1, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "above it");
        // Still above while the flight drains to 8: no further step — nor a
        // "step" from a flight still above the window, which would raise it …
        w.observe(&itl.at(light(obs(0.3, 11, true)), 100.2, 2000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "the step has not taken effect");
        // … then one more once it has.
        w.observe(&itl.at(light(obs(0.3, 8, true)), 150.3, 3000.0), None);
        assert_eq!((w.limit(None), w.state()), (6, AdaptiveState::LatencyBound));
        // A round back within the target grows again.
        w.observe(&itl.at(light(obs(0.3, 6, true)), 160.0, 4000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::Probing));
        // Two steps down, counted; the hold between them is not one.
        assert_eq!(w.decisions().stepped_down, 2);
    }

    #[test]
    fn at_one_request_a_round_above_the_target_holds_and_counts_nothing() {
        let itl = Itl::default();
        // A target the engine misses even at one request: the window holds
        // there — no step to take, none counted, nothing measured afresh.
        let mut w = latency_window();
        w.window = 1.0;
        w.footprint = Footprint { kv: 0.3, running: 1.0 };
        w.observe(&itl.at(light(obs(0.3, 1, true)), 100.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (1, AdaptiveState::LatencyBound));
        assert_eq!(w.decisions().stepped_down, 0);
        assert!(w.footprint.running > 1.0, "the footprint kept its readings");
    }

    #[test]
    fn a_round_above_the_target_steps_down_a_window_whose_engine_is_queueing_too() {
        let itl = Itl::default();
        // The engine keeps a queue of its own on two readings with memory to
        // spare and runs slower than the target: the
        // window still steps down, so it stops keeping that queue full.
        let mut w = latency_window();
        w.observe(&itl.at(Observation { waiting: 3, ..light(obs(0.3, 10, true)) }, 10.0, 1000.0), None);
        w.observe(&itl.at(Observation { waiting: 3, ..light(obs(0.3, 10, true)) }, 110.0, 2000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound));
    }

    #[test]
    fn a_step_down_halves_an_oversized_window_toward_its_flight_and_never_for_someone_elses_latency() {
        let itl = Itl::default();
        // Four in flight under a window of 10: halfway, to 5 — not to the
        // four that happen to run (minus a step), nor one step from 10 that
        // would admit the next burst nearly whole.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 4, false)), 60.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (5, AdaptiveState::LatencyBound));
        // Nine in flight under 10: a step below what runs, 7.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 9, false)), 60.0, 1000.0), None);
        assert_eq!(w.limit(None), 7);
        // Nothing in flight here: the latency is someone else's.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 0, false)), 60.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::Steady));
    }

    #[test]
    fn a_raise_waits_for_a_round_within_the_latency_target() {
        let itl = Itl::default();
        // First-token counters that do not move: a round ends only at
        // PACE_MAX. One ends above the target; until the next ends, a pressed
        // window with room holds.
        let t0 = Instant::now();
        let t = |s: u64| t0 + Duration::from_secs(s);
        let r = |s: u64, in_flight: u32, limited: bool, itl_sum: f64, itl_count: f64| {
            itl.at(with_ttft(at(light(obs(0.3, in_flight, limited)), t(s)), 10.0, 10.0), itl_sum, itl_count)
        };
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        w.observe(&r(0, 0, false, 0.0, 0.0), None);
        w.window = 10.0;
        w.slow_start = false;
        w.observe(&r(1, 10, false, 0.0, 0.0), None);
        w.observe(&r(61, 10, false, 60.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound));
        w.observe(&r(62, 8, true, 61.0, 1010.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "mid-round, still above");
        w.observe(&r(121, 8, true, 70.0, 2000.0), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::Probing), "a round within it");
    }

    #[test]
    fn a_round_with_no_tokens_generated_says_nothing() {
        let itl = Itl::default();
        // With no verdict yet, nothing holds the raise.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 0.0, 0.0), None);
        assert_eq!((w.limit(None), w.state()), (12, AdaptiveState::Probing));
        // After a round above the target, a round with no tokens leaves that
        // verdict standing: no raise, and no further step either.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert_eq!(w.limit(None), 8);
        w.observe(&itl.at(light(obs(0.3, 8, true)), 100.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "no tokens");
        // Nor does one whose counters fell (an engine restart) …
        w.observe(&itl.at(light(obs(0.3, 8, true)), 1.0, 10.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound), "counters fell");
        // … and the next judged round, within the target, lets it grow.
        w.observe(&itl.at(light(obs(0.3, 8, true)), 2.0, 1010.0), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::Probing));
    }

    #[test]
    fn under_a_latency_target_every_raise_is_a_step() {
        let itl = Itl::default();
        // In slow start, pressed with room and within the target: two more,
        // not a doubling that could land at twice the batch that met it. The
        // positive control — an engine that publishes no inter-token figures,
        // the same window doubles — is
        // `a_target_on_an_engine_without_inter_token_figures_is_no_target`.
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        w.observe(&itl.at(light(obs(0.3, 0, false)), 0.0, 0.0), None);
        w.observe(&itl.at(light(obs(0.3, 4, true)), 10.0, 1000.0), None);
        assert!(w.slow_start);
        assert_eq!((w.limit(None), w.state()), (6, AdaptiveState::Probing));
    }

    #[test]
    fn a_target_on_an_engine_without_inter_token_figures_is_no_target() {
        // No inter-token counters published: the target can judge nothing, so
        // slow start doubles as without one.
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        w.observe(&light(obs(0.3, 0, false)), None);
        w.observe(&light(obs(0.3, 4, true)), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::Probing));
    }

    #[test]
    fn a_verdict_stops_holding_once_the_engine_stops_publishing_its_figures() {
        let itl = Itl::default();
        // Above the target, then the engine's inter-token counters vanish (a
        // restart on a build without them): the next round that ends finds
        // nothing to hold the target against, and the window runs as without
        // one — it grows.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound));
        w.observe(&light(obs(0.3, 8, true)), None);
        assert_eq!((w.limit(None), w.state()), (10, AdaptiveState::Probing));
    }

    #[test]
    fn one_scrape_short_of_the_counters_mid_round_changes_nothing() {
        let itl = Itl::default();
        // First-token counters that do not move: the round does not end. A
        // reading in it without the inter-token counters leaves the window a
        // measured one — under the target, every raise stays a step.
        let t0 = Instant::now();
        let r = |s: u64, published: bool| {
            let o = with_ttft(at(light(obs(0.3, 4, true)), t0 + Duration::from_secs(s)), 10.0, 10.0);
            if published { itl.at(o, 0.0, 0.0) } else { o }
        };
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        w.observe(&r(0, true), None);
        w.observe(&r(1, true), None);
        assert_eq!(w.limit(None), 6, "a step, measured");
        w.observe(&r(2, false), None);
        assert!(w.latency_measurable, "one scrape short changes nothing");
    }

    #[test]
    fn stale_readings_leave_a_latency_verdict_standing() {
        let itl = Itl::default();
        // Above the target, then the readings go stale: the reading after
        // them seeds the window, and the verdict still holds the raise — a
        // metrics hiccup says nothing about the latency.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert_eq!(w.limit(None), 8);
        w.resume();
        w.observe(&itl.at(light(obs(0.3, 8, true)), 100.0, 1000.0), None);
        assert_eq!(w.state(), AdaptiveState::Starting);
        w.observe(&itl.at(light(obs(0.3, 8, true)), 100.0, 1000.0), None);
        assert_eq!((w.limit(None), w.state()), (8, AdaptiveState::LatencyBound));
    }

    #[test]
    fn a_changed_target_ends_the_slow_start_of_a_learned_window() {
        // A window that has learned something, still in slow start: a target
        // set, or cleared, ends it — the window was found under the other
        // rule, and doubling from it would send a batch the engine was never
        // shown.
        let mut w = AdaptiveWindow::new(None);
        w.learned = true;
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        assert!(!w.slow_start, "set");
        w.slow_start = true;
        w.set_latency_target(ItlTarget::Fixed { ms: 50 });
        assert!(w.slow_start, "unchanged: nothing ends");
        w.set_latency_target(ItlTarget::Off);
        assert!(!w.slow_start, "cleared");
        // A new window keeps its slow start: nothing found yet to protect.
        let mut fresh = AdaptiveWindow::new(None);
        fresh.set_latency_target(ItlTarget::Fixed { ms: 50 });
        assert!(fresh.slow_start);
    }

    #[test]
    fn an_idle_restart_forgets_a_latency_verdict() {
        let itl = Itl::default();
        // Above the target, then a quiet spell: the burst after it is not held
        // to a verdict about an engine state that has gone.
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert!(w.over_target);
        let t0 = Instant::now();
        let quiet = |s: u64| at(itl.at(light(obs(0.3, 0, false)), 100.0, 1000.0), t0 + Duration::from_secs(s));
        w.observe(&quiet(1), None);
        w.observe(&quiet(1 + IDLE_RESTART.as_secs()), None);
        assert!(!w.over_target, "the verdict went with the spell");
    }

    /// The engine stops publishing its inter-token histogram: the window runs
    /// as without a target until a round measures again — so the verdict of
    /// the last measured round goes too, and nothing claims the window is over
    /// a target it is no longer held to.
    #[test]
    fn a_missing_histogram_drops_the_latency_verdict() {
        let itl = Itl::default();
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert!(w.over_target);
        w.observe(&light(obs(0.3, 10, true)), None);
        assert!(!w.latency_measurable);
        assert!(!w.over_target, "a verdict on figures the engine no longer publishes");
    }

    /// The same where the histogram is missing at the reading a round STARTS
    /// on — the first after readings went stale, which keep the verdict: the
    /// window then runs as without a target, so the verdict goes, and a window
    /// still claiming to be over its target never grows.
    #[test]
    fn a_round_started_without_the_histogram_drops_the_latency_verdict() {
        let itl = Itl::default();
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 100.0, 1000.0), None);
        assert!(w.over_target);
        w.resume();
        w.observe(&light(obs(0.3, 10, true)), None);
        assert!(w.over_target, "stale readings say nothing about the latency");
        let before = w.window;
        w.observe(&light(obs(0.3, 10, true)), None);
        assert!(!w.latency_measurable);
        assert!(!w.over_target, "a verdict on figures the engine no longer publishes");
        assert!(w.window > before, "run as without a target: pressed with room, it grows");
    }

    #[test]
    fn a_changed_latency_target_starts_its_rounds_afresh() {
        let itl = Itl::default();
        let mut w = latency_window();
        w.observe(&itl.at(light(obs(0.3, 10, true)), 60.0, 1000.0), None);
        assert!(w.over_target);
        w.set_latency_target(ItlTarget::Fixed { ms: 100 });
        assert!(!w.over_target && w.latency_round.is_none());
        w.set_latency_target(ItlTarget::Fixed { ms: 100 });
        w.set_latency_target(ItlTarget::Fixed { ms: 0 });
        assert_eq!(w.latency_target(), None, "a zero target is none");
    }

    #[test]
    fn an_automatic_target_is_three_times_the_low_load_figure_once_learned() {
        let itl = Itl::default();
        let low = |sum: f64, count: f64| itl.at(obs(0.2, 1, false), sum, count);
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Auto);
        w.observe(&low(0.0, 0.0), None);
        w.observe(&low(0.02 * (LOW_LOAD_MIN_TOKENS - 1.0), LOW_LOAD_MIN_TOKENS - 1.0), None);
        assert_eq!(w.latency_target(), None, "learning: one token short");
        w.observe(&low(0.02 * LOW_LOAD_MIN_TOKENS, LOW_LOAD_MIN_TOKENS), None);
        assert!(close(w.latency_target(), 0.06), "{:?}", w.latency_target());
        // Held to it: a round at 61 ms is above it, one at 59 ms within.
        // A first busy reading, not yet pressed, starts the round.
        let busy = |sum: f64, count: f64, limited: bool| itl.at(light(obs(0.3, 4, limited)), sum, count);
        let base = 0.02 * LOW_LOAD_MIN_TOKENS;
        let mut over = w.clone();
        over.observe(&busy(base, LOW_LOAD_MIN_TOKENS, false), None);
        over.observe(&busy(base + 61.0, LOW_LOAD_MIN_TOKENS + 1000.0, true), None);
        assert_eq!(over.state(), AdaptiveState::LatencyBound, "61 ms");
        let mut within = w.clone();
        within.observe(&busy(base, LOW_LOAD_MIN_TOKENS, false), None);
        within.observe(&busy(base + 59.0, LOW_LOAD_MIN_TOKENS + 1000.0, true), None);
        assert_eq!((within.state(), within.limit(None)), (AdaptiveState::Probing, 6), "59 ms");
        // The operator's figure, or none, wins over what was learned.
        w.set_latency_target(ItlTarget::Fixed { ms: 100 });
        assert!(close(w.latency_target(), 0.1));
        w.set_latency_target(ItlTarget::Off);
        assert_eq!(w.latency_target(), None);
    }

    #[test]
    fn an_automatic_target_still_learning_holds_nothing() {
        let itl = Itl::default();
        // Busy from the first reading: no low-load interval, so no target —
        // the window runs as without one (slow start doubles), and says so.
        let mut auto = AdaptiveWindow::new(None);
        auto.set_latency_target(ItlTarget::Auto);
        let mut off = AdaptiveWindow::new(None);
        off.set_latency_target(ItlTarget::Off);
        for (i, in_flight) in [0u32, 4, 8, 16].into_iter().enumerate() {
            let o = itl.at(light(obs(0.3, in_flight, in_flight > 0)), i as f64 * 100.0, i as f64 * 1000.0);
            auto.observe(&o, None);
            off.observe(&o, None);
            assert_eq!((auto.limit(None), auto.state()), (off.limit(None), off.state()));
        }
        assert_eq!(auto.limit(None), 32);
        assert_eq!(auto.latency_target(), None);
    }

    #[test]
    fn the_low_load_figure_follows_the_engine_recent_intervals_most() {
        let itl = Itl::default();
        // Forty intervals at 20 ms, then forty at 40 ms: the plain mean of
        // them all would say 30 ms; the figure is near the recent 40 ms.
        let mut w = AdaptiveWindow::new(None);
        let (mut sum, mut count) = (0.0, 0.0);
        w.observe(&itl.at(obs(0.2, 1, false), sum, count), None);
        for gap in [0.02; 40].into_iter().chain([0.04; 40]) {
            sum += 100.0 * gap;
            count += 100.0;
            w.observe(&itl.at(obs(0.2, 1, false), sum, count), None);
        }
        let figure = w.low_load_itl().expect("learned");
        assert!(figure > 0.037 && figure < 0.04, "{figure}");
        // Its first twenty intervals are their plain mean: nineteen at 20 ms
        // and one at 40 ms are 21 ms.
        let mut young = AdaptiveWindow::new(None);
        let (mut sum, mut count) = (0.0, 0.0);
        young.observe(&itl.at(obs(0.2, 1, false), sum, count), None);
        for gap in [0.02; 19].into_iter().chain([0.04]) {
            sum += 100.0 * gap;
            count += 100.0;
            young.observe(&itl.at(obs(0.2, 1, false), sum, count), None);
        }
        assert!(close(young.low_load_itl(), 0.021), "{:?}", young.low_load_itl());
    }

    #[test]
    fn low_load_is_one_or_two_running_per_data_parallel_rank() {
        let itl = Itl::default();
        let reading = |running: u32, sum: f64, count: f64| {
            Observation { ranks: 4, ..itl.at(obs(0.2, running, false), sum, count) }
        };
        // Eight running over four ranks, at both ends: low load.
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(8, 0.0, 0.0), None);
        w.observe(&reading(8, 6.0, 300.0), None);
        assert!(close(w.low_load_itl(), 0.02), "{:?}", w.low_load_itl());
        // Nine at one end: not.
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(8, 0.0, 0.0), None);
        w.observe(&reading(9, 6.0, 300.0), None);
        assert_eq!(w.low_load_itl(), None);
    }

    #[test]
    fn a_window_holding_requests_back_learns_the_low_load_figure_at_one_running_only() {
        let itl = Itl::default();
        // Two running, none waiting, because this window held requests back:
        // a target holding it at two must not teach the figure its own batch.
        // The same intervals unheld are learned (the positive control) — and
        // so is one running held back: a window a too-tight target trapped at
        // one learns the engine's real figure there.
        let reading = |running: u32, sum: f64, count: f64, limited: bool| itl.at(obs(0.2, running, limited), sum, count);
        let learned = |running: u32, limited: bool| {
            let mut w = AdaptiveWindow::new(None);
            w.observe(&reading(running, 0.0, 0.0, limited), None);
            w.observe(&reading(running, 6.0, 300.0, limited), None);
            w.low_load_itl()
        };
        assert_eq!(learned(2, true), None, "two, held back");
        assert!(close(learned(2, false), 0.02), "two, free");
        assert!(close(learned(1, true), 0.02), "one, held back");
    }

    #[test]
    fn a_sum_that_dips_alone_is_not_an_engine_restart() {
        let itl = Itl::default();
        // The time-between-tokens sum falls while its count climbs: no
        // restart, so the figure stands — and the interval, which says
        // nothing, is not learned. The positive control, a fallen count, is
        // `an_engine_restart_forgets_the_low_load_time_per_token`.
        // The histogram goes on counting gaps of 20 ms.
        let reading = |sum: f64, count: f64| {
            let o = itl.at(obs(0.2, 1, false), 0.02 * count, count);
            Observation { counters: EngineCounters { itl_sum: Some(sum), ..o.counters }, ..o }
        };
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(0.0, 0.0), None);
        w.observe(&reading(10.0, 500.0), None);
        w.observe(&reading(9.999, 600.0), None);
        w.observe(&reading(9.998, 700.0), None);
        assert!(close(w.low_load_itl(), 0.02), "{:?}", w.low_load_itl());
        assert_eq!(w.workload.low_load_intervals, 3, "every interval learned");
    }

    #[test]
    fn an_automatic_target_of_nothing_is_no_target() {
        assert!(auto_itl_target(0.0).is_none(), "a sum that never moved");
        assert!(auto_itl_target(0.000_333).is_none(), "just under a millisecond");
        assert!(auto_itl_target(0.000_334).is_some_and(|t| (t - 0.001_002).abs() < 1e-12), "just over");
        assert!(auto_itl_target(f64::NAN).is_none());
        // Nor is one learned from an engine's histogram applied: every gap
        // under its first bound, a tenth of a millisecond, reads as half it.
        let mut gaps = GapHistogram::default();
        for bound in [0.000_1, f64::INFINITY] {
            gaps.add(bound, 0.0);
        }
        let reading = |gaps: GapHistogram| Observation {
            counters: EngineCounters { itl_count: Some(0.0), itl_gaps: Some(gaps), ..obs(0.2, 1, false).counters },
            ..obs(0.2, 1, false)
        };
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Auto);
        w.observe(&reading(gaps), None);
        gaps.record(0.0, LOW_LOAD_MIN_TOKENS);
        w.observe(&reading(gaps), None);
        assert!(close(w.low_load_itl(), 0.000_05), "{:?}", w.low_load_itl());
        assert_eq!(w.latency_target(), None);
    }

    #[test]
    fn an_automatic_target_that_goes_ends_the_slow_start_of_a_learned_window() {
        let itl = Itl::default();
        // A window grown step by step under an automatic target, still in
        // slow start: its engine restarts and the target goes with the
        // figure. The window was found under the target and must not double
        // from it.
        let low = |sum: f64, count: f64, finished: f64| with_tokens(itl.at(obs(0.2, 1, false), sum, count), finished, finished);
        let mut w = AdaptiveWindow::new(None);
        w.set_latency_target(ItlTarget::Auto);
        w.observe(&low(0.0, 0.0, 100.0), None);
        w.observe(&low(4.0, 200.0, 200.0), None);
        w.observe(&low(8.0, 400.0, 300.0), None);
        assert!(w.latency_gates(), "a target applies and is measured");
        w.learned = true;
        assert!(w.slow_start);
        // The finished counts fall: a restart.
        w.observe(&low(0.1, 5.0, 10.0), None);
        assert_eq!(w.latency_target(), None);
        assert!(!w.slow_start, "slow start ended with the target");
        // A window never held by a target keeps its slow start through the
        // same restart (the positive control).
        let mut plain = AdaptiveWindow::new(None);
        plain.set_latency_target(ItlTarget::Auto);
        plain.learned = true;
        plain.observe(&low(0.0, 0.0, 100.0), None);
        plain.observe(&low(0.1, 5.0, 10.0), None);
        assert!(plain.slow_start);
    }

    #[test]
    fn a_fallen_first_token_counter_is_an_engine_restart_too() {
        let itl = Itl::default();
        let reading = |ttft: f64| with_ttft(itl.at(obs(0.2, 1, false), ttft * 0.02 * 100.0, ttft * 100.0), ttft, ttft * 2.0);
        let mut w = AdaptiveWindow::new(None);
        w.observe(&reading(1.0), None);
        w.observe(&reading(10.0), None);
        assert!(w.low_load_itl().is_some());
        // Every counter climbs on but the first-token count, which falls.
        let fell = Observation { counters: EngineCounters { ttft_count: Some(5.0), ..reading(20.0).counters }, ..reading(20.0) };
        w.observe(&fell, None);
        assert_eq!(w.low_load_itl(), None, "forgotten");
    }

    proptest! {
        /// Whatever the engine says, in whatever order — restarts, missing
        /// gauges, nonsense counters, any mix of tokens, a latency target or
        /// none — the limit stays within [1, ceiling].
        #[test]
        fn the_limit_never_leaves_its_bounds(
            ceiling in proptest::option::of(1u32..2048),
            target in arbitrary_target(),
            readings in proptest::collection::vec((arbitrary_observation(), 0u64..60_000), 1..64),
        ) {
            let mut w = AdaptiveWindow::new(ceiling);
            w.set_latency_target(target);
            let mut t = Instant::now();
            for (o, gap_ms) in readings {
                t += Duration::from_millis(gap_ms);
                w.observe(&Observation { at: t, ..o }, ceiling);
                let limit = w.limit(ceiling);
                prop_assert!(limit >= 1);
                prop_assert!(f64::from(limit) <= cap(ceiling));
            }
        }

        /// A control step grows the window only when something pressed against
        /// it and the cache had room — never on a preemption, never on a full
        /// cache. (A FIRST reading may raise it to what is in flight: that is
        /// not a control step, and is its own test.)
        #[test]
        fn the_window_grows_only_when_pressed_with_room(
            readings in timed_readings(2..64),
        ) {
            let mut w = AdaptiveWindow::new(None);
            let mut last_preemptions: Option<f64> = None;
            // A reading after none, or after one without the KV gauge, is a
            // first reading: it seeds.
            let mut seeding = true;
            for o in &readings {
                let before = w.window;
                // Pressure an earlier reading kept for its round trip counts.
                let carried = w.pressed_unpaced;
                let preempted = matches!((last_preemptions, o.counters.preemptions), (Some(p), Some(c)) if c > p);
                w.observe(o, None);
                let was_seeding = seeding;
                seeding = o.kv_usage.is_none();
                if !was_seeding && w.window > before {
                    prop_assert!(o.limited || carried);
                    prop_assert!(o.kv_usage.is_some_and(|k| k < KV_TARGET));
                    prop_assert!(!preempted);
                }
                last_preemptions = o.counters.preemptions;
            }
        }

        /// A preemption always leaves no more than half of what this replica
        /// had in flight (never below one).
        #[test]
        fn a_preemption_always_halves_the_flight(
            first in arbitrary_observation(),
            second in arbitrary_observation(),
            extra in 1.0f64..100.0,
        ) {
            let mut w = AdaptiveWindow::new(None);
            let first = Observation {
                counters: EngineCounters { preemptions: Some(10.0), ..first.counters },
                kv_usage: Some(first.kv_usage.unwrap_or(0.5)),
                ..first
            };
            w.observe(&first, None);
            let second = Observation {
                counters: EngineCounters { preemptions: Some(10.0 + extra), ..second.counters },
                in_flight: second.in_flight.max(1),
                kv_usage: Some(second.kv_usage.unwrap_or(0.5)),
                ..second
            };
            w.observe(&second, None);
            prop_assert_eq!(w.state(), AdaptiveState::BackingOff);
            prop_assert!(w.window <= (f64::from(second.in_flight.max(1)) * DECREASE_FACTOR).max(MIN_WINDOW));
        }

        /// A full cache cuts the window to half the flight, never below one —
        /// and never raises a window already below that.
        #[test]
        fn a_full_cache_halves_the_flight(
            first in arbitrary_observation(),
            second in arbitrary_observation(),
            kv in KV_CEILING..=1.0f64,
        ) {
            let mut w = AdaptiveWindow::new(None);
            let first = Observation {
                counters: EngineCounters { preemptions: Some(10.0), ..first.counters },
                kv_usage: Some(first.kv_usage.unwrap_or(0.5)),
                ..first
            };
            w.observe(&first, None);
            let before = w.window;
            let second = Observation {
                counters: EngineCounters { preemptions: Some(10.0), ..second.counters },
                in_flight: second.in_flight.max(1),
                kv_usage: Some(kv),
                ..second
            };
            w.observe(&second, None);
            let flight = f64::from(second.in_flight);
            let to = (flight * DECREASE_FACTOR).max(MIN_WINDOW);
            prop_assert_eq!(w.state(), AdaptiveState::BackingOff);
            prop_assert_eq!(w.window, before.min(to));
        }

        /// Against an engine whose every request holds the same memory — this
        /// replica alone at it, every reading pressed — a raise never takes
        /// the window past what fits below the KV target, from slow start's
        /// doubling to the additive steps. The engine holds the starting
        /// window within the target: a window that never fitted is the ceiling
        /// cut's to answer, not a raise's.
        #[test]
        fn a_raise_never_admits_more_than_fits_below_the_target(
            per_request in 0.002f64..(KV_TARGET / INITIAL_WINDOW),
            readings in 2usize..400,
        ) {
            let mut w = AdaptiveWindow::new(None);
            let mut engine = Engine { per_request, ..Engine::new() };
            for _ in 0..readings {
                let before = w.limit(None);
                let o = engine.reading(before, true, &|n| 100.0 * f64::from(n), &|_| 1.0);
                w.observe(&o, None);
                let after = w.limit(None);
                if after > before {
                    prop_assert!(
                        f64::from(after) * per_request <= KV_TARGET + 1e-9,
                        "{before} -> {after} at {per_request} a request"
                    );
                }
            }
        }

        /// The same where each request grows after the gauge reads it: the
        /// gauge shows each running request at `held`, and the requests that
        /// finish are of `prompt` and `answer` tokens. A raise never takes the
        /// window past what fits below the KV target at the END size, held ×
        /// (prompt + answer) / (prompt + answer / 2) — computed here from the
        /// engine's inputs, not read back from the window.
        #[test]
        fn a_raise_never_admits_more_than_fits_at_the_end_size(
            held in 0.002f64..(KV_TARGET / INITIAL_WINDOW),
            prompt in 0.0f64..10_000.0,
            answer in 0.0f64..10_000.0,
            readings in 2usize..400,
        ) {
            prop_assume!(prompt + answer > 1.0);
            let end = held * (prompt + answer) / (prompt + answer / 2.0);
            // A start already past what fits never raises, and checks nothing.
            prop_assume!(INITIAL_WINDOW * end <= KV_TARGET);
            let mut w = AdaptiveWindow::new(None);
            let mut engine = Engine { per_request: held, finishing: Some((prompt, answer)), ..Engine::new() };
            for _ in 0..readings {
                let before = w.limit(None);
                let o = engine.reading(before, true, &|n| 100.0 * f64::from(n), &|_| 1.0);
                w.observe(&o, None);
                let after = w.limit(None);
                if after > before {
                    prop_assert!(
                        f64::from(after) * end <= KV_TARGET + 1e-9,
                        "{before} -> {after} at {end} a request"
                    );
                }
            }
        }

        /// With a latency target — the operator's, or one learned — the window
        /// never grows on a reading after which the last round stands above
        /// it.
        #[test]
        fn a_window_over_its_latency_target_never_grows(
            target in arbitrary_target(),
            readings in timed_readings(2..64),
        ) {
            let mut w = AdaptiveWindow::new(None);
            w.set_latency_target(target);
            for o in &readings {
                let before = w.window;
                let seeding = w.previous.is_none();
                w.observe(o, None);
                if !seeding && w.over_target {
                    prop_assert!(w.window <= before, "{before} -> {}", w.window);
                }
            }
        }

        /// A target set and then turned off before the window has run leaves
        /// one that does exactly what one never given a target does, reading
        /// for reading. (Turned off on a learned window, slow start ends:
        /// `a_changed_target_ends_the_slow_start_of_a_learned_window`.)
        #[test]
        fn a_target_turned_off_is_no_target(
            target in arbitrary_target(),
            readings in timed_readings(2..64),
        ) {
            let mut plain = AdaptiveWindow::new(None);
            plain.set_latency_target(ItlTarget::Off);
            let mut cleared = AdaptiveWindow::new(None);
            cleared.set_latency_target(target);
            cleared.set_latency_target(ItlTarget::Off);
            for o in &readings {
                plain.observe(o, None);
                cleared.observe(o, None);
                prop_assert_eq!((plain.limit(None), plain.state()), (cleared.limit(None), cleared.state()));
            }
        }

        /// The window does not read the prefix cache: the same readings with
        /// other prefix-cache counters, or none, move it identically.
        #[test]
        fn the_window_never_reads_the_prefix_cache(
            readings in timed_readings(2..64),
            scrambled in proptest::collection::vec(proptest::option::of((0.0f64..1e7, 0.0f64..1e7)), 64),
        ) {
            let mut kept = AdaptiveWindow::new(Some(64));
            let mut other = AdaptiveWindow::new(Some(64));
            for (o, prefix) in readings.iter().zip(&scrambled) {
                let mut p = *o;
                p.counters.prefix_queries = prefix.map(|(q, _)| q);
                p.counters.prefix_hits = prefix.map(|(_, h)| h);
                kept.observe(o, Some(64));
                other.observe(&p, Some(64));
                prop_assert_eq!((kept.limit(Some(64)), kept.state()), (other.limit(Some(64)), other.state()));
                prop_assert_eq!(kept.decisions(), other.decisions());
            }
        }
    }
}
