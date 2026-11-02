//! Per-upstream-server passive circuit breaker for the proxy data plane.
//!
//! Failover is reactive — a dead upstream still costs the *first* request of
//! every routing decision a connect-timeout before the proxy fails over. This
//! breaker makes that cost transient: it counts consecutive transport-level
//! failures (no HTTP response) per upstream server and, once a threshold trips,
//! deprioritizes that server during target selection so a healthy sibling is
//! tried first. Recovery is lazy and traffic-driven — after a cooldown the next
//! selection promotes the server to a single half-open trial; a reachable
//! response closes the breaker, another failure reopens it (same episode).
//!
//! Invariants (keep these when editing):
//! - **Fail-open**: the breaker only *reorders* candidates; it never removes the
//!   last target for an alias. [`CircuitBreaker::order_targets`] returns a
//!   permutation of every index, so an all-tripped alias keeps its original
//!   order. A false-negative can never zero out an alias.
//! - **Transport-only**: an HTTP error status (incl. 5xx) means the server
//!   answered — it counts as [`record_reachable`](CircuitBreaker::record_reachable)
//!   and does NOT trip the breaker (reactive retry already handles it). Only
//!   connect / DNS / TLS / timeout failures count as
//!   [`record_failure`](CircuitBreaker::record_failure). The caller classifies.
//! - **One half-open trial in flight** per server, claimed atomically — a second
//!   concurrent selection sees the server as `Down` until the trial resolves.
//! - **One operator event per outage episode**: only the Closed→Open edge emits
//!   a `down`, only an Open/HalfOpen→Closed edge emits an `up`; a failed
//!   half-open trial reopens the *same* episode silently.
//!
//! The half-open trial is promoted to the *front* of the candidate list so it
//! receives traffic even when a healthy sibling exists (otherwise a survivor
//! always serves first and the recovering server never gets a trial). The caller
//! validates capabilities and builds the upstream body against the first target,
//! so trial promotion assumes a **homogeneous failover pool** (the redundant-route
//! norm — same model/protocol behind one alias). In a heterogeneous pool a trial
//! request is still validated/translated against the recovering target; if that
//! target lacks a capability the request needs it may error rather than fail over
//! — bounded to roughly one request per cooldown until the pool's primary next
//! fails over and recovers the target through the fail-open path.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// A breaker health transition worth surfacing to operators. Emitted by the
/// proxy on a breaker edge, forwarded to admin over the edge channel as the
/// `health_transition_event` message, where it becomes an operator notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthTransitionEvent {
    pub tenant_id: uuid::Uuid,
    /// UUID of the `upstream_servers` row when the target carries one; `None`
    /// for keyless pass-through / default-upstream targets (keyed by URL host),
    /// in which case the notification cannot deep-link to a specific server.
    pub upstream_server_id: Option<String>,
    /// The replica endpoint whose breaker moved — each replica trips on its
    /// own. `None` for a pass-through target, which has no endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<uuid::Uuid>,
    /// That endpoint's URL, for the notification text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    /// Provider + model of the target that tripped/recovered (for the message).
    pub provider: String,
    pub model: String,
    /// `"down"` when the breaker opened, `"up"` when it closed.
    pub new_status: String,
    /// Short human reason (the transport error on `down`, "recovered" on `up`).
    pub reason: String,
    /// Wall-clock second the breaker OPENED for this episode — shared by the
    /// `down` + `up` events so admin dedups them as one outage episode.
    pub episode_epoch: i64,
}

/// A replica endpoint answered that it does not serve a model it was sent
/// (the engine's "model not found"). The request moved on to another endpoint
/// of the model; admin counts these so the server page can flag an endpoint
/// assumed — or listed — to serve a model it does not. Forwarded to admin as
/// the `endpoint_model_missing` message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointModelMissing {
    pub tenant_id: uuid::Uuid,
    pub endpoint_id: uuid::Uuid,
    /// The endpoint's URL when it refused: admin records the report only
    /// while the endpoint still points there.
    pub url: String,
    /// The upstream model name the endpoint refused.
    pub model: String,
}

/// What the proxy reports to admin about upstream health, one channel for both.
#[derive(Clone, Debug)]
pub enum EdgeHealthEvent {
    Transition(HealthTransitionEvent),
    ModelMissing(EndpointModelMissing),
}

/// How long after its last attempt a replica endpoint still counts as one this
/// gateway routes to. Admin counts a server down only when every gateway that
/// routes to an endpoint has it out of rotation; a gateway that stopped
/// sending there this long ago has no say.
pub const ROUTES_TO_WINDOW: Duration = Duration::from_secs(600);

/// One replica endpoint this gateway routes to — an attempt within
/// [`ROUTES_TO_WINDOW`], answered or not — and whether its breaker holds it out
/// of rotation. Sent in full on every heartbeat (`endpoint_states`), so admin's
/// view is at most one beat behind whatever was dropped, reordered or edited in
/// between — a URL change, a lost event, a reconnect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointState {
    pub tenant_id: uuid::Uuid,
    pub endpoint_id: uuid::Uuid,
    /// The URL it was last reached at: admin records the state only while the
    /// endpoint still points there.
    pub url: String,
    /// The breaker is open: this gateway has the endpoint out of rotation.
    pub out: bool,
}

/// The last attempt this gateway made at a replica endpoint.
#[derive(Clone, Debug)]
struct Reached {
    tenant_id: uuid::Uuid,
    endpoint_id: uuid::Uuid,
    url: String,
    at: Instant,
}

impl EdgeHealthEvent {
    /// The edge→admin message type and payload. Each kind has its own type, so
    /// an admin that does not know `endpoint_model_missing` ignores it.
    pub fn into_message(self) -> (&'static str, serde_json::Value) {
        match self {
            EdgeHealthEvent::Transition(e) => {
                ("health_transition_event", serde_json::to_value(e).unwrap_or_default())
            }
            EdgeHealthEvent::ModelMissing(e) => {
                ("endpoint_model_missing", serde_json::to_value(e).unwrap_or_default())
            }
        }
    }
}

/// Build the breaker key for a target: its upstream-server UUID when present,
/// else the URL host (so keyless pass-through / default-upstream targets still
/// trip as a unit). The key only needs to be stable per physical upstream.
pub fn target_key(upstream_server_id: Option<&str>, url: &str) -> String {
    if let Some(id) = upstream_server_id {
        return id.to_string();
    }
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    format!("url:{host}")
}

#[derive(Debug)]
enum State {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant, episode_epoch: i64 },
    /// A half-open trial was claimed at `claimed_at`. It resolves to Closed/Open
    /// when the trial request records its outcome — but a request can early-return
    /// (capability/translation failure) after claiming and before forwarding, so a
    /// trial older than `cooldown` is treated as stale and re-promoted to a fresh
    /// trial by `peek` / `try_claim_trial`. Without that self-heal a leaked claim
    /// would strand the server in `Down` forever and it would never recover.
    HalfOpen { claimed_at: Instant, episode_epoch: i64 },
}

struct Entry {
    state: State,
}

/// Where a target sits in selection preference for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    /// Closed — fully healthy.
    Healthy,
    /// Open and cooldown elapsed — eligible to claim the single half-open trial.
    TrialEligible,
    /// Open and still cooling, or a half-open trial already in flight.
    Down,
}

/// The transition a `record_*` call produced, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// Closed → Open (the breaker tripped). Carries the episode epoch for dedup.
    Opened { episode_epoch: i64 },
    /// Open / HalfOpen → Closed (the server recovered).
    Recovered { episode_epoch: i64 },
}

/// Lock-free per-server circuit breaker. Cheap to share behind an `Arc`; every
/// method takes `&self` and shards on the key via [`DashMap`].
pub struct CircuitBreaker {
    entries: DashMap<String, Entry>,
    /// The last attempt at each replica endpoint, by breaker key — what
    /// [`Self::endpoint_states`] reports. Independent of `enabled`: a gateway
    /// that keeps no breaker still routes to what it reaches.
    reached: DashMap<String, Reached>,
    enabled: bool,
    failure_threshold: u32,
    cooldown: Duration,
}

impl CircuitBreaker {
    pub fn new(enabled: bool, failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            reached: DashMap::new(),
            enabled,
            // A zero threshold would trip with no margin; clamp to at least one.
            failure_threshold: failure_threshold.max(1),
            cooldown,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// `keys` reordered healthy first, WITHOUT claiming a half-open trial —
    /// for a caller that records no outcome (the response cache's embedding
    /// call), which must never hold a trial it will not resolve. Fail-open
    /// like [`Self::order_targets`]: nothing is dropped.
    pub fn healthy_first(&self, keys: &[String]) -> Vec<usize> {
        if !self.enabled {
            return (0..keys.len()).collect();
        }
        let now = Instant::now();
        let (mut healthy, mut rest): (Vec<usize>, Vec<usize>) =
            (0..keys.len()).partition(|&i| matches!(self.peek(&keys[i], now), Slot::Healthy));
        healthy.append(&mut rest);
        healthy
    }

    /// Whether the breaker for `key` holds its target out of rotation: open,
    /// or open with a single half-open trial in flight.
    fn is_out(&self, key: &str) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| matches!(e.state, State::Open { .. } | State::HalfOpen { .. }))
    }

    /// Note an attempt at replica endpoint `endpoint_id`, under breaker `key`,
    /// that reached it — answered or not.
    pub fn note_reached(&self, key: &str, tenant_id: uuid::Uuid, endpoint_id: uuid::Uuid, url: &str) {
        let now = Instant::now();
        // Updated under the guard `get_mut` holds: an `insert` while it is
        // alive would wait on the same shard lock for ever.
        if let Some(mut r) = self.reached.get_mut(key) {
            if r.url == url && r.tenant_id == tenant_id {
                // The hot path: one attempt after another at the same replica.
                r.at = now;
            } else {
                *r = Reached { tenant_id, endpoint_id, url: url.to_string(), at: now };
            }
            return;
        }
        self.reached.insert(key.to_string(), Reached { tenant_id, endpoint_id, url: url.to_string(), at: now });
    }

    /// Every replica endpoint this gateway routes to — reached within
    /// `window`, stretched to twice the breaker's cooldown so an endpoint held
    /// out is still stated while it cools — with whether the breaker ITSELF
    /// holds it out (never the report bookkeeping, which can lag it). Endpoints
    /// reached longer ago are forgotten here, an open breaker's included:
    /// nothing has tried it since its cooldown ended (not even a half-open
    /// trial, which a request to its route would claim), so this gateway no
    /// longer routes there and has no say — rather than holding a server
    /// "down" for ever after its route was removed, or its endpoint disabled
    /// and re-enabled.
    pub fn endpoint_states(&self, window: Duration) -> Vec<EndpointState> {
        let now = Instant::now();
        let window = window.max(self.cooldown.saturating_mul(2));
        self.reached.retain(|_, r| now.duration_since(r.at) <= window);
        self.reached
            .iter()
            .map(|r| EndpointState {
                tenant_id: r.tenant_id,
                endpoint_id: r.endpoint_id,
                url: r.url.clone(),
                out: self.is_out(r.key()),
            })
            .collect()
    }

    /// Reorder target indices by health for one request, claiming at most one
    /// half-open trial. Returns a permutation of `0..keys.len()` ordered
    /// `[claimed-trial?, healthy.., down..]`, stable within each band. Fail-open:
    /// every index is present, so an all-down alias keeps its original order.
    pub fn order_targets(&self, keys: &[String]) -> Vec<usize> {
        if !self.enabled {
            return (0..keys.len()).collect();
        }
        let now = Instant::now();
        let mut trial: Option<usize> = None;
        let mut healthy = Vec::new();
        let mut down = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            match self.peek(key, now) {
                Slot::Healthy => healthy.push(i),
                Slot::Down => down.push(i),
                Slot::TrialEligible => {
                    if trial.is_none() && self.try_claim_trial(key, now) {
                        trial = Some(i);
                    } else {
                        down.push(i);
                    }
                }
            }
        }
        let mut out = Vec::with_capacity(keys.len());
        out.extend(trial);
        out.append(&mut healthy);
        out.append(&mut down);
        out
    }

    fn peek(&self, key: &str, now: Instant) -> Slot {
        match self.entries.get(key) {
            None => Slot::Healthy,
            Some(e) => match &e.state {
                State::Closed { .. } => Slot::Healthy,
                // An Open whose cooldown elapsed, or a HalfOpen whose trial never
                // resolved within a cooldown (a claim leaked by an early-return),
                // is eligible for a fresh trial.
                State::Open { opened_at, .. } if now.duration_since(*opened_at) >= self.cooldown => {
                    Slot::TrialEligible
                }
                State::HalfOpen { claimed_at, .. }
                    if now.duration_since(*claimed_at) >= self.cooldown =>
                {
                    Slot::TrialEligible
                }
                // Open and still cooling, or a half-open trial in flight.
                State::Open { .. } | State::HalfOpen { .. } => Slot::Down,
            },
        }
    }

    /// Atomically claim the single half-open trial — promoting an eligible `Open`,
    /// or re-claiming a `HalfOpen` whose prior trial leaked (older than cooldown).
    /// Returns `true` only for the caller that won the claim (others see `Down`).
    fn try_claim_trial(&self, key: &str, now: Instant) -> bool {
        let Some(mut e) = self.entries.get_mut(key) else {
            return false;
        };
        let episode = match e.state {
            State::Open { opened_at, episode_epoch }
                if now.duration_since(opened_at) >= self.cooldown =>
            {
                episode_epoch
            }
            State::HalfOpen { claimed_at, episode_epoch }
                if now.duration_since(claimed_at) >= self.cooldown =>
            {
                episode_epoch
            }
            _ => return false,
        };
        e.state = State::HalfOpen { claimed_at: now, episode_epoch: episode };
        true
    }

    /// Record that `key` returned an HTTP response — reachable, whether a success
    /// or an error status. Resets the failure streak and closes the breaker if it
    /// was open. Returns `Some(Recovered)` only on an Open/HalfOpen→Closed edge.
    pub fn record_reachable(&self, key: &str) -> Option<Transition> {
        if !self.enabled {
            return None;
        }
        let mut e = self
            .entries
            .entry(key.to_string())
            .or_insert_with(|| Entry { state: State::Closed { consecutive_failures: 0 } });
        match e.state {
            State::Closed { consecutive_failures } => {
                if consecutive_failures != 0 {
                    e.state = State::Closed { consecutive_failures: 0 };
                }
                None
            }
            State::Open { episode_epoch, .. } | State::HalfOpen { episode_epoch, .. } => {
                e.state = State::Closed { consecutive_failures: 0 };
                Some(Transition::Recovered { episode_epoch })
            }
        }
    }

    /// Record a transport-level failure (no HTTP response). Trips the breaker on
    /// the `failure_threshold`-th consecutive failure. A failed half-open trial
    /// reopens the *same* episode silently (returns `None`). Returns
    /// `Some(Opened)` only on the Closed→Open edge.
    pub fn record_failure(&self, key: &str) -> Option<Transition> {
        if !self.enabled {
            return None;
        }
        let now = Instant::now();
        let mut e = self
            .entries
            .entry(key.to_string())
            .or_insert_with(|| Entry { state: State::Closed { consecutive_failures: 0 } });
        match e.state {
            State::Closed { consecutive_failures } => {
                let n = consecutive_failures + 1;
                if n >= self.failure_threshold {
                    let episode_epoch = unix_now();
                    e.state = State::Open { opened_at: now, episode_epoch };
                    Some(Transition::Opened { episode_epoch })
                } else {
                    e.state = State::Closed { consecutive_failures: n };
                    None
                }
            }
            State::HalfOpen { episode_epoch, .. } => {
                // Trial failed → reopen the SAME episode (restart cooldown), no
                // new operator event — one `down` per outage, not per trial.
                e.state = State::Open { opened_at: now, episode_epoch };
                None
            }
            // Already open: a fail-open last-resort attempt failed. No edge.
            State::Open { .. } => None,
        }
    }

    /// Test-only: backdate an open/half-open entry's clock so cooldown is
    /// considered elapsed without sleeping.
    #[cfg(test)]
    fn backdate(&self, key: &str, by: Duration) {
        if let Some(mut e) = self.entries.get_mut(key) {
            match &mut e.state {
                State::Open { opened_at, .. } => {
                    *opened_at = opened_at.checked_sub(by).unwrap_or(*opened_at);
                }
                State::HalfOpen { claimed_at, .. } => {
                    *claimed_at = claimed_at.checked_sub(by).unwrap_or(*claimed_at);
                }
                State::Closed { .. } => {}
            }
        }
    }
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    const COOLDOWN: Duration = Duration::from_secs(30);

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(true, 3, COOLDOWN)
    }

    /// A gateway states every endpoint it routes to — reached within the
    /// window — at the URL it last reached, with whether its breaker holds it
    /// out; one reached longer ago is not stated at all, an open breaker's
    /// included once its cooldown is well past.
    #[test]
    fn a_gateway_states_what_it_routes_to_and_what_it_holds_out() {
        // No cooldown, so the window is the one asked for.
        let b = CircuitBreaker::new(true, 3, Duration::ZERO);
        let t = uuid::Uuid::new_v4();
        let (reached, open_idle, forgotten) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        b.note_reached("reached", t, reached, "http://old");
        // The URL an endpoint is reached at now is the one stated.
        b.note_reached("reached", t, reached, "http://new");
        b.note_reached("forgotten", t, forgotten, "http://f");
        b.note_reached("open-idle", t, open_idle, "http://o");
        for _ in 0..3 {
            b.record_failure("open-idle");
        }
        std::thread::sleep(Duration::from_millis(30));
        b.note_reached("reached", t, reached, "http://new");
        assert_eq!(
            b.endpoint_states(Duration::from_millis(20)),
            vec![EndpointState { tenant_id: t, endpoint_id: reached, url: "http://new".into(), out: false }],
            "neither the idle endpoint nor the idle open breaker is still routed to"
        );
        // Tripped while routing there: stated once, and out.
        for _ in 0..3 {
            b.record_failure("reached");
        }
        let states = b.endpoint_states(Duration::from_secs(60));
        assert_eq!(states.iter().filter(|s| s.endpoint_id == reached).map(|s| s.out).collect::<Vec<_>>(), [true]);
        // Answered again: in rotation.
        b.record_reachable("reached");
        assert!(b.endpoint_states(Duration::from_secs(60)).iter().all(|s| s.endpoint_id != reached || !s.out));
    }

    /// An endpoint held out is stated for as long as it cools, however long
    /// that is: the window stretches to cover the cooldown.
    #[test]
    fn an_endpoint_held_out_is_stated_while_it_cools() {
        let b = CircuitBreaker::new(true, 1, Duration::from_secs(3600));
        let t = uuid::Uuid::new_v4();
        let e = uuid::Uuid::new_v4();
        b.note_reached("e", t, e, "http://e");
        b.record_failure("e");
        std::thread::sleep(Duration::from_millis(30));
        let states = b.endpoint_states(Duration::from_millis(20));
        assert_eq!(states.iter().map(|s| (s.endpoint_id, s.out)).collect::<Vec<_>>(), [(e, true)]);
    }

    #[test]
    fn healthy_first_puts_a_tripped_key_last_and_claims_no_trial() {
        // No cooldown: the tripped key is immediately eligible for its trial.
        let b = CircuitBreaker::new(true, 3, Duration::ZERO);
        for _ in 0..3 {
            b.record_failure("down");
        }
        let keys = vec!["down".to_string(), "up".to_string()];
        assert_eq!(b.healthy_first(&keys), vec![1, 0]);
        // Still eligible: the trial is left for a caller that records its outcome.
        assert!(matches!(b.peek("down", Instant::now()), Slot::TrialEligible));
    }

    #[test]
    fn trips_open_after_threshold_consecutive_failures() {
        let b = breaker();
        assert_eq!(b.record_failure("s1"), None);
        assert_eq!(b.record_failure("s1"), None);
        assert_matches!(
            b.record_failure("s1"),
            Some(Transition::Opened { .. })
        );
    }

    #[test]
    fn reachable_resets_the_failure_streak() {
        let b = breaker();
        b.record_failure("s1");
        b.record_failure("s1");
        assert_eq!(b.record_reachable("s1"), None); // reset, still Closed
        // Streak reset: two more failures must not yet trip.
        assert_eq!(b.record_failure("s1"), None);
        assert_eq!(b.record_failure("s1"), None);
        assert_matches!(
            b.record_failure("s1"),
            Some(Transition::Opened { .. })
        );
    }

    #[test]
    fn open_target_is_pushed_to_the_back_while_cooling() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        // [a=open-cooling, b=healthy] → healthy first, open last.
        let order = b.order_targets(&["a".into(), "b".into()]);
        assert_eq!(order, vec![1, 0]);
    }

    #[test]
    fn cooldown_promotes_a_single_half_open_trial_to_the_front() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", COOLDOWN); // cooldown now elapsed
        // a is trial-eligible → claimed → front, ahead of healthy b.
        let order = b.order_targets(&["a".into(), "b".into()]);
        assert_eq!(order, vec![0, 1]);
        // A second concurrent selection sees the trial already in flight → a back.
        let order2 = b.order_targets(&["a".into(), "b".into()]);
        assert_eq!(order2, vec![1, 0]);
    }

    #[test]
    fn half_open_trial_success_recovers_the_route() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", COOLDOWN);
        b.order_targets(&["a".into()]); // claim the trial
        assert_matches!(
            b.record_reachable("a"),
            Some(Transition::Recovered { .. })
        );
        // Closed again: targets in original order, no trial.
        assert_eq!(b.order_targets(&["a".into(), "b".into()]), vec![0, 1]);
    }

    #[test]
    fn half_open_trial_failure_reopens_same_episode_without_a_new_event() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", COOLDOWN);
        b.order_targets(&["a".into()]); // claim trial → HalfOpen
        // Trial fails: reopen, no new `Opened` event.
        assert_eq!(b.record_failure("a"), None);
        // Still recoverable later under the same episode.
        b.backdate("a", COOLDOWN);
        b.order_targets(&["a".into()]);
        assert_matches!(
            b.record_reachable("a"),
            Some(Transition::Recovered { .. })
        );
    }

    #[test]
    fn a_leaked_half_open_trial_self_heals_after_cooldown() {
        // A trial can be claimed (order_targets) but never resolved if the
        // request early-returns before forwarding. Such a stale HalfOpen must be
        // re-promoted so the server can still recover — otherwise it strands Down.
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", COOLDOWN);
        b.order_targets(&["a".into()]); // claim trial → HalfOpen, never resolved
        // While fresh, the leaked trial keeps the server out of rotation.
        assert_eq!(b.order_targets(&["a".into(), "b".into()]), vec![1, 0]);
        // Once the trial is older than a cooldown, it is re-promoted to a fresh
        // trial at the front rather than stranding the server forever.
        b.backdate("a", COOLDOWN);
        assert_eq!(b.order_targets(&["a".into(), "b".into()]), vec![0, 1]);
    }

    #[test]
    fn down_up_share_one_episode_epoch() {
        let b = breaker();
        b.record_failure("a");
        b.record_failure("a");
        let opened = b.record_failure("a");
        let Some(Transition::Opened { episode_epoch: e_open }) = opened else {
            panic!("expected Opened, got {opened:?}");
        };
        b.backdate("a", COOLDOWN);
        b.order_targets(&["a".into()]);
        let recovered = b.record_reachable("a");
        let Some(Transition::Recovered { episode_epoch: e_rec }) = recovered else {
            panic!("expected Recovered, got {recovered:?}");
        };
        assert_eq!(e_open, e_rec);
    }

    #[test]
    fn all_down_keeps_original_order_fail_open() {
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        for _ in 0..3 {
            b.record_failure("b");
        }
        // Both cooling → both Down → original order preserved, nothing dropped.
        assert_eq!(b.order_targets(&["a".into(), "b".into()]), vec![0, 1]);
    }

    #[test]
    fn disabled_is_identity_and_records_nothing() {
        let b = CircuitBreaker::new(false, 3, COOLDOWN);
        for _ in 0..10 {
            assert_eq!(b.record_failure("a"), None);
        }
        assert_eq!(b.record_reachable("a"), None);
        assert_eq!(b.order_targets(&["a".into(), "b".into()]), vec![0, 1]);
    }
    /// Half a cooldown: unambiguously short of the threshold whatever real time
    /// the test itself takes, so the "still cooling" side never flakes.
    const HALF_COOLDOWN: Duration = Duration::from_secs(15);

    #[test]
    fn an_open_target_stays_down_until_the_cooldown_actually_elapses() {
        // The other side of `cooldown_promotes_a_single_half_open_trial`. Without
        // it, a guard that promoted a target the instant it opened would pass
        // every existing case: they all advance the clock first, so none of them
        // can tell "eligible after the cooldown" from "eligible immediately".
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", HALF_COOLDOWN);
        assert_eq!(b.peek("a", Instant::now()), Slot::Down);
        assert!(!b.try_claim_trial("a", Instant::now()));
        // And the boundary on the other side: a full cooldown IS eligible.
        b.backdate("a", HALF_COOLDOWN);
        assert_eq!(b.peek("a", Instant::now()), Slot::TrialEligible);
        assert!(b.try_claim_trial("a", Instant::now()));
    }

    #[test]
    fn a_fresh_half_open_trial_is_not_reclaimed_before_the_cooldown() {
        // Same boundary for the leaked-trial self-heal: a trial still in flight
        // must hold the single claim, or two concurrent requests both probe a
        // server that is already being probed.
        let b = breaker();
        for _ in 0..3 {
            b.record_failure("a");
        }
        b.backdate("a", COOLDOWN);
        assert!(b.try_claim_trial("a", Instant::now())); // → HalfOpen
        b.backdate("a", HALF_COOLDOWN);
        assert_eq!(b.peek("a", Instant::now()), Slot::Down);
        assert!(!b.try_claim_trial("a", Instant::now()));
        // Past a full cooldown the stale claim is re-promoted.
        b.backdate("a", HALF_COOLDOWN);
        assert_eq!(b.peek("a", Instant::now()), Slot::TrialEligible);
        assert!(b.try_claim_trial("a", Instant::now()));
    }

    #[test]
    fn target_key_separates_distinct_upstreams_and_folds_one_host() {
        // The key is what keeps one server's outage off another's breaker. A key
        // derivation that returned any constant would trip every upstream at
        // once, and every other test in this file uses hand-written keys, so
        // nothing else here would notice.
        assert_ne!(
            target_key(Some("srv-a"), "https://a.example/v1"),
            target_key(Some("srv-b"), "https://b.example/v1")
        );
        assert_ne!(
            target_key(None, "https://a.example/v1"),
            target_key(None, "https://b.example/v1")
        );
        // The server id wins over the URL when present...
        assert_eq!(
            target_key(Some("srv-a"), "https://a.example/v1"),
            target_key(Some("srv-a"), "https://elsewhere.example/v2")
        );
        // ...and without one, every path on a host trips as a single unit.
        assert_eq!(
            target_key(None, "https://a.example/v1/chat"),
            target_key(None, "https://a.example/v2/messages")
        );
    }

    #[test]
    fn enabled_reports_the_configured_setting() {
        assert!(breaker().enabled());
        assert!(!CircuitBreaker::new(false, 3, COOLDOWN).enabled());
    }

    #[test]
    fn the_episode_epoch_is_a_wall_clock_second() {
        // `down_up_share_one_episode_epoch` only asserts the two events AGREE,
        // which a constant satisfies. Admin dedups an outage episode by this
        // value across restarts, so it has to be a real timestamp.
        let b = breaker();
        b.record_failure("a");
        b.record_failure("a");
        let Some(Transition::Opened { episode_epoch }) = b.record_failure("a") else {
            panic!("expected Opened");
        };
        // Any moment after 2023-11-14, i.e. long before this code existed.
        assert!(
            episode_epoch > 1_700_000_000,
            "episode epoch {episode_epoch} is not a wall-clock second"
        );
    }
}
