//! Fleet-convergent usage counters — a generic distributed counter primitive.
//!
//! No single edge sees the fleet's total. Each edge keeps a monotonic
//! *cumulative* component per counter and reports it to admin over the
//! heartbeat. Admin merges via a watermark/delta rule into a global total — a
//! grow-only counter (G-Counter): `total = Σ over edges of each edge's
//! cumulative` — then pushes the authoritative total back down. Edges enforce
//! against `authoritative_total + their own unreported delta`.
//!
//! The merge is a SUM and the wired [`UsageMetric`]s are budget spend (integer
//! micro-dollars, day/month windows) and per-minute request/token rate (RPM/TPM,
//! minute window). The `(scope_kind, metric, window_kind)` shape is the seam for further
//! metrics and non-SUM merges.
//!
//! Enforcement is intentionally an estimate: convergence lags one heartbeat and
//! overshoot is bounded by one interval of one edge's spend. State is fail-safe
//! — on an admin disconnect the edge keeps accumulating its local delta against
//! the last-known authoritative total and still trips the limit; it never
//! resets to zero, and a restart re-receives the persisted total on reconnect.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DAY_MS: u64 = 86_400_000;
/// Monthly window is a rolling ~30-day epoch-aligned window, not a calendar
/// month.
pub const MONTH_MS: u64 = 30 * DAY_MS;

/// Current wall-clock in ms since the UNIX epoch (0 on a pre-epoch clock).
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageScopeKind {
    /// The whole tenant — the org-total ceiling every workspace's spend rolls
    /// into. Budget only (no RPM/TPM), and the one scope whose `scope_id` is
    /// its own `tenant_id`.
    Tenant,
    Workspace,
    User,
    /// A single API key — budget only (no RPM/TPM). Capped tighter than its
    /// workspace/user buckets when an operator sets a per-key ceiling.
    Key,
}

impl UsageScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Workspace => "workspace",
            Self::User => "user",
            Self::Key => "key",
        }
    }
}

pub const MINUTE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageWindowKind {
    Minute,
    Daily,
    Monthly,
}

impl UsageWindowKind {
    pub fn window_ms(self) -> u64 {
        match self {
            Self::Minute => MINUTE_MS,
            Self::Daily => DAY_MS,
            Self::Monthly => MONTH_MS,
        }
    }
    /// How long after its start a window's counters are kept: the usage
    /// janitor deletes them past it, and a report for a window this old is
    /// settled without merging — its watermark may be gone, and merging
    /// without one would add the whole cumulative again.
    pub fn kept_for_ms(self) -> u64 {
        match self {
            Self::Minute => 5 * MINUTE_MS,
            Self::Daily => 2 * DAY_MS,
            Self::Monthly => 40 * DAY_MS,
        }
    }
    /// UTC-aligned start of the window containing `now_ms`.
    pub fn window_start_ms(self, now_ms: u64) -> u64 {
        now_ms - (now_ms % self.window_ms())
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Daily => "daily",
            Self::Monthly => "monthly",
        }
    }
}

/// Integer counter units per whole unit of the tenant's accounting currency, for
/// [`UsageMetric::BudgetMicros`].
///
/// The counter is a `u64` of whole units, so this is the resolution at which
/// spend can be recorded at all: anything under one unit rounds away and accrues
/// NOTHING. That makes the choice a correctness constraint rather than a matter
/// of taste — at cent resolution a request costing a tenth of a cent (an ordinary
/// short prompt on a cheap model) contributes zero, so a workload made of such
/// requests can run indefinitely against a budget that never advances. Micros
/// carry every cost the gateway can compute down to one millionth of a unit.
///
/// A `u64` of micros holds ~18 trillion units, so overflow is not reachable.
///
/// Spend and the cap it is compared against are both converted into the tenant's
/// accounting currency before they reach the counter, so the counter itself is
/// currency-agnostic — it counts millionths of whatever that currency is.
pub const BUDGET_UNITS_PER_CURRENCY_UNIT: f64 = 1_000_000.0;

/// Metric a counter tracks. SUM-merged. Budget spend (integer millionths of the
/// tenant's accounting currency, see [`BUDGET_UNITS_PER_CURRENCY_UNIT`]) uses the
/// day/month windows; the per-minute request/token rates use the minute window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageMetric {
    BudgetMicros,
    /// Requests in the current minute window (RPM enforcement).
    RequestsPerMinute,
    /// Tokens in the current minute window (TPM enforcement).
    TokensPerMinute,
}

impl UsageMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            // The stored metric name carries the unit, so a counter recorded at
            // one resolution can never be read as another: changing the unit
            // means changing this string, which starts fresh counters instead of
            // reinterpreting existing rows by a factor of 10 000.
            Self::BudgetMicros => "budget_micros",
            Self::RequestsPerMinute => "rpm",
            Self::TokensPerMinute => "tpm",
        }
    }
}

/// A counter's scope, minus the time window — the stable identity an accrue /
/// check site refers to. The tracker derives the window internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UsageScope {
    pub tenant_id: Uuid,
    pub scope_kind: UsageScopeKind,
    pub scope_id: Uuid,
    pub metric: UsageMetric,
}

/// Fully identifies one convergent counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsageCounterKey {
    pub tenant_id: Uuid,
    pub scope_kind: UsageScopeKind,
    pub scope_id: Uuid,
    pub metric: UsageMetric,
    pub window_kind: UsageWindowKind,
    /// UTC-aligned window start, ms since epoch.
    pub window_start_ms: u64,
}

/// Edge→admin: this edge's monotonic cumulative for a counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCounterReport {
    #[serde(flatten)]
    pub key: UsageCounterKey,
    pub cumulative: u64,
}

/// Admin→edge: authoritative global total for a counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCounterAuthoritative {
    #[serde(flatten)]
    pub key: UsageCounterKey,
    pub total: u64,
}

/// Per-edge fleet-counter state. Cheap to clone the `Arc`; all maps are
/// interior-mutable and lock-free-ish (sharded).
#[derive(Default)]
pub struct UsageTracker {
    /// This edge's monotonic cumulative per counter (its G-Counter component).
    cumulative: DashMap<UsageCounterKey, u64>,
    /// Value admin last answered for — used to estimate the unreported delta.
    /// Set only by [`UsageTracker::answered`]: a report admin has not merged is
    /// still this edge's own unreported spend.
    reported: DashMap<UsageCounterKey, u64>,
    /// Authoritative global total last received from admin.
    authoritative: DashMap<UsageCounterKey, u64>,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(scope: UsageScope, window_kind: UsageWindowKind, now_ms: u64) -> UsageCounterKey {
        UsageCounterKey {
            tenant_id: scope.tenant_id,
            scope_kind: scope.scope_kind,
            scope_id: scope.scope_id,
            metric: scope.metric,
            window_kind,
            window_start_ms: window_kind.window_start_ms(now_ms),
        }
    }

    /// Accrue `amount` to a counter's cumulative for the current window.
    pub fn accrue(&self, scope: UsageScope, window_kind: UsageWindowKind, now_ms: u64, amount: u64) {
        if amount == 0 {
            return;
        }
        let key = Self::key(scope, window_kind, now_ms);
        *self.cumulative.entry(key).or_insert(0) += amount;
    }

    /// Best-effort global estimate for a counter in the current window:
    /// `authoritative (all edges, last sync) + this edge's unreported delta`.
    pub fn estimate(&self, scope: UsageScope, window_kind: UsageWindowKind, now_ms: u64) -> u64 {
        let key = Self::key(scope, window_kind, now_ms);
        let auth = self.authoritative.get(&key).map(|v| *v).unwrap_or(0);
        let cum = self.cumulative.get(&key).map(|v| *v).unwrap_or(0);
        let rep = self.reported.get(&key).map(|v| *v).unwrap_or(0);
        auth + cum.saturating_sub(rep)
    }

    /// Snapshot every counter's cumulative to report up.
    ///
    /// A window that has since elapsed still gets ONE final report before its
    /// key is pruned: requests/spend accrued in the window's last report-interval
    /// (after the previous drain, before the boundary) would otherwise be lost,
    /// leaving the central historical total short — the RPM/TPM minute windows
    /// roll every 60s, so dropping that tail is a visible undercount, not a
    /// rounding artifact. The caller keeps restating that final cumulative until
    /// admin answers for it; the admin-side watermark/delta merge makes every
    /// restatement idempotent.
    pub fn drain_report(&self, now_ms: u64) -> Vec<UsageCounterReport> {
        let stale: Vec<UsageCounterKey> = self
            .cumulative
            .iter()
            .filter(|e| e.key().window_start_ms != e.key().window_kind.window_start_ms(now_ms))
            .map(|e| e.key().clone())
            .collect();

        let out = self
            .cumulative
            .iter()
            .map(|e| UsageCounterReport { key: e.key().clone(), cumulative: *e.value() })
            .collect();

        // Prune elapsed-window keys only after their final cumulative is queued
        // for report above, so the tail delta reaches the central merge.
        for k in &stale {
            self.cumulative.remove(k);
            self.reported.remove(k);
            self.authoritative.remove(k);
        }

        out
    }

    /// Admin answered for a counter this edge reported at `cumulative`: merged
    /// into the fleet-wide `total`, or settled without a total (a counter that
    /// can never merge). The cumulative stops counting as unreported. A key no
    /// longer held — its window elapsed and was pruned — is ignored, so an
    /// answer never brings a pruned window back.
    pub fn answered(&self, key: &UsageCounterKey, cumulative: u64, total: Option<u64>) {
        if !self.cumulative.contains_key(key) {
            return;
        }
        let mut reported = self.reported.entry(key.clone()).or_insert(0);
        *reported = (*reported).max(cumulative);
        drop(reported);
        if let Some(total) = total {
            self.authoritative.insert(key.clone(), total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> UsageScope {
        UsageScope {
            tenant_id: Uuid::nil(),
            scope_kind: UsageScopeKind::Workspace,
            scope_id: Uuid::from_u128(1),
            metric: UsageMetric::BudgetMicros,
        }
    }

    #[test]
    fn estimate_adds_local_unreported_to_authoritative() {
        let t = UsageTracker::new();
        let now = 1_000_000_000_000;
        // This edge reported 20; admin says the fleet total is 500.
        t.accrue(scope(), UsageWindowKind::Daily, now, 20);
        let report = t.drain_report(now);
        t.answered(&report[0].key, 20, Some(500));
        // This edge spent 30 more, unreported.
        t.accrue(scope(), UsageWindowKind::Daily, now, 30);
        assert_eq!(t.estimate(scope(), UsageWindowKind::Daily, now), 530);
    }

    #[test]
    fn a_report_stays_unreported_until_admin_answers_for_it() {
        let t = UsageTracker::new();
        let now = 1_000_000_000_000;
        t.accrue(scope(), UsageWindowKind::Daily, now, 42);
        let report = t.drain_report(now);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].cumulative, 42);
        // Sent but not answered: still this edge's own spend.
        assert_eq!(t.estimate(scope(), UsageWindowKind::Daily, now), 42);
        // Merged into a fleet total of 100 (this edge's 42 included), then 8 more.
        t.answered(&report[0].key, 42, Some(100));
        t.accrue(scope(), UsageWindowKind::Daily, now, 8);
        assert_eq!(t.estimate(scope(), UsageWindowKind::Daily, now), 108);
    }

    #[test]
    fn a_settled_counter_stops_counting_as_unreported_without_a_total() {
        let t = UsageTracker::new();
        let now = 1_000_000_000_000;
        t.accrue(scope(), UsageWindowKind::Daily, now, 42);
        let report = t.drain_report(now);
        t.answered(&report[0].key, 42, None);
        assert_eq!(t.estimate(scope(), UsageWindowKind::Daily, now), 0);
    }

    #[test]
    fn an_answer_for_a_pruned_window_is_not_kept() {
        let t = UsageTracker::new();
        t.accrue(scope(), UsageWindowKind::Daily, 0, 10);
        let report = t.drain_report(100 * DAY_MS);
        assert_eq!(report.len(), 1);
        t.answered(&report[0].key, 10, Some(10));
        assert!(t.authoritative.is_empty());
        assert!(t.reported.is_empty());
    }

    #[test]
    fn elapsed_window_emits_final_report_then_prunes() {
        let t = UsageTracker::new();
        t.accrue(scope(), UsageWindowKind::Daily, 0, 10);
        // A drain after the window elapsed emits ONE final report (the tail
        // delta) for the caller to restate until answered, then prunes the key.
        let report = t.drain_report(100 * DAY_MS);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].cumulative, 10);
        // The key is gone, so a subsequent drain reports nothing new.
        let report2 = t.drain_report(100 * DAY_MS);
        assert!(report2.is_empty());
    }
}
