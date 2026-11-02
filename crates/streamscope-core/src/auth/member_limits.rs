//! What one member may use inside one workspace — the **member** bucket.
//!
//! A workspace may set a DEFAULT member limit, which applies to every member,
//! and an EXCEPTION for one member, which REPLACES the default for that member
//! (higher or lower). Replacement is per metric: an exception field left unset
//! inherits the default for that metric only, so an exception can raise the
//! request rate while keeping the default daily budget. The workspace pool, the
//! organisation ceiling and a key's own budget are separate buckets and always
//! apply as well — replacement happens only WITHIN the member bucket.
//!
//! [`resolve_member_limit`] is the single place this is decided. The key bake,
//! the spec-OAuth path (which mints its context per request from a token claim)
//! and the admin budget evaluation all call it, so the limit a member is held
//! to, the one a token is held to and the one the dashboards report cannot
//! disagree.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::RateLimitConfig;

/// Namespace of the derived member scope id — see [`member_scope_id`].
/// Never change it: counters recorded under one namespace are not found under
/// another, which would reset every member's usage.
const MEMBER_SCOPE_NAMESPACE: Uuid = Uuid::from_u128(0x6d3f_4a0e_52b1_4c7e_9b0a_d1e8_2f47_c613);

/// The fleet-counter scope id of one MEMBERSHIP — a user inside one workspace.
///
/// A user who belongs to two workspaces holds two memberships with separate
/// limits, so their usage is counted separately: keying the counter by the user
/// alone would charge spend in one workspace against the limit in the other.
/// The counter keeps the `user` scope kind — only the id is derived — because a
/// new kind would be undecodable to an admin of the previous release, which
/// would then drop whole usage batches during a mixed-version rollout.
///
/// Derived from the TEXT `"{workspace_id}:{user_id}"` (not the raw bytes) so a
/// consumer outside Rust reproduces it with a stock UUIDv5 over a string.
pub fn member_scope_id(workspace_id: Uuid, user_id: Uuid) -> Uuid {
    Uuid::new_v5(&MEMBER_SCOPE_NAMESPACE, format!("{workspace_id}:{user_id}").as_bytes())
}

/// Member limits as stored, one field per metric.
///
/// On a workspace DEFAULT, `None` (or `0`) means no default for that metric.
/// On a member EXCEPTION, `None` means "inherit the default for this metric",
/// `Some(0)` means explicitly unlimited, and a positive value is the member's
/// own limit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemberLimits {
    #[serde(default)]
    pub requests_per_minute: Option<u32>,
    #[serde(default)]
    pub tokens_per_minute: Option<u32>,
    #[serde(default)]
    pub daily_budget: Option<f64>,
    #[serde(default)]
    pub monthly_budget: Option<f64>,
    /// Budget enforcement mode. On an exception it applies only when the
    /// exception sets a budget cap of its own (a positive value); otherwise the
    /// default's mode does — an exception that only makes a budget unlimited
    /// has no cap for a mode to govern, so it must not change how the default's
    /// other, inherited budget acts.
    #[serde(default)]
    pub budget_alert_only: bool,
}

impl MemberLimits {
    fn sets_a_budget_cap(&self) -> bool {
        [self.daily_budget, self.monthly_budget].into_iter().flatten().any(|v| v > 0.0)
    }
}

/// The member bucket for one membership, or `None` when nothing limits the
/// member (no default and no exception, or every metric resolves unlimited) —
/// no counter is created for a scope that is never enforced.
pub fn resolve_member_limit(
    default: Option<&MemberLimits>,
    exception: Option<&MemberLimits>,
) -> Option<RateLimitConfig> {
    let none = MemberLimits::default();
    let d = default.unwrap_or(&none);
    let e = exception.unwrap_or(&none);
    let rpm = e.requests_per_minute.or(d.requests_per_minute).unwrap_or(0);
    let tpm = e.tokens_per_minute.or(d.tokens_per_minute).unwrap_or(0);
    let daily = e.daily_budget.or(d.daily_budget).unwrap_or(0.0).max(0.0);
    let monthly = e.monthly_budget.or(d.monthly_budget).unwrap_or(0.0).max(0.0);
    if rpm == 0 && tpm == 0 && daily <= 0.0 && monthly <= 0.0 {
        return None;
    }
    let budget_alert_only = if e.sets_a_budget_cap() { e.budget_alert_only } else { d.budget_alert_only };
    Some(RateLimitConfig {
        requests_per_minute: rpm,
        tokens_per_minute: tpm,
        daily_budget: daily,
        monthly_budget: monthly,
        budget_alert_only,
        exempt: false,
    })
}

/// One member exception on the config snapshot (a JSON map cannot key on a
/// pair, so the snapshot carries a list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberLimitException {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub limits: MemberLimits,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim(rpm: Option<u32>, daily: Option<f64>) -> MemberLimits {
        MemberLimits { requests_per_minute: rpm, daily_budget: daily, ..Default::default() }
    }

    /// Every (exception state × default state) cell for one metric:
    /// exception ∈ {inherit, unlimited, value} × default ∈ {none, value}.
    #[test]
    fn each_exception_state_against_each_default_state() {
        let rpm = |d: Option<u32>, e: Option<Option<u32>>| {
            let default = lim(d, None);
            let exception = e.map(|v| lim(v, None));
            resolve_member_limit(Some(&default), exception.as_ref()).map(|c| c.requests_per_minute)
        };
        // No exception row at all.
        assert_eq!(rpm(None, None), None);
        assert_eq!(rpm(Some(60), None), Some(60));
        // Exception inherits this metric.
        assert_eq!(rpm(None, Some(None)), None);
        assert_eq!(rpm(Some(60), Some(None)), Some(60));
        // Exception says unlimited — beats a default.
        assert_eq!(rpm(None, Some(Some(0))), None);
        assert_eq!(rpm(Some(60), Some(Some(0))), None);
        // Exception value replaces the default — lower AND higher.
        assert_eq!(rpm(None, Some(Some(5))), Some(5));
        assert_eq!(rpm(Some(60), Some(Some(5))), Some(5));
        assert_eq!(rpm(Some(60), Some(Some(600))), Some(600));
    }

    /// Replacement is per metric: raising one leaves the others inherited.
    #[test]
    fn an_exception_replaces_only_the_metrics_it_sets() {
        let default = MemberLimits { requests_per_minute: Some(60), daily_budget: Some(5.0), ..Default::default() };
        let exception = lim(Some(120), None);
        let c = resolve_member_limit(Some(&default), Some(&exception)).unwrap();
        assert_eq!(c.requests_per_minute, 120);
        assert_eq!(c.daily_budget, 5.0);
    }

    /// An unlimited metric on an otherwise-limited member stays unlimited
    /// (0), and the bucket still exists for the limited metric.
    #[test]
    fn unlimited_on_one_metric_keeps_the_bucket_for_the_others() {
        let default = MemberLimits { requests_per_minute: Some(60), daily_budget: Some(5.0), ..Default::default() };
        let exception = lim(None, Some(0.0));
        let c = resolve_member_limit(Some(&default), Some(&exception)).unwrap();
        assert_eq!(c.requests_per_minute, 60);
        assert_eq!(c.daily_budget, 0.0);
    }

    #[test]
    fn the_budget_mode_follows_whoever_set_the_budget() {
        let default = MemberLimits { daily_budget: Some(5.0), budget_alert_only: true, ..Default::default() };
        // An exception that touches only the rate keeps the default's mode.
        let rate_only = MemberLimits { requests_per_minute: Some(10), budget_alert_only: false, ..Default::default() };
        assert!(resolve_member_limit(Some(&default), Some(&rate_only)).unwrap().budget_alert_only);
        // One that sets its own budget brings its own mode.
        let own_budget = MemberLimits { daily_budget: Some(9.0), budget_alert_only: false, ..Default::default() };
        assert!(!resolve_member_limit(Some(&default), Some(&own_budget)).unwrap().budget_alert_only);
    }

    /// Making one budget unlimited sets no cap, so the inherited budget keeps
    /// the default's mode — an alert-only monthly default must not start
    /// blocking because the member's daily budget was lifted.
    #[test]
    fn an_unlimited_budget_does_not_bring_its_own_mode() {
        let default = MemberLimits {
            daily_budget: Some(5.0),
            monthly_budget: Some(50.0),
            budget_alert_only: true,
            ..Default::default()
        };
        let lifted = MemberLimits { daily_budget: Some(0.0), budget_alert_only: false, ..Default::default() };
        let c = resolve_member_limit(Some(&default), Some(&lifted)).unwrap();
        assert_eq!(c.daily_budget, 0.0);
        assert_eq!(c.monthly_budget, 50.0);
        assert!(c.budget_alert_only, "the inherited monthly budget lost its alert-only mode");
    }

    #[test]
    fn nothing_set_means_no_member_bucket() {
        assert!(resolve_member_limit(None, None).is_none());
        let zeros = MemberLimits {
            requests_per_minute: Some(0),
            tokens_per_minute: Some(0),
            daily_budget: Some(0.0),
            monthly_budget: Some(0.0),
            budget_alert_only: false,
        };
        assert!(resolve_member_limit(Some(&zeros), None).is_none());
    }

    #[test]
    fn a_membership_id_is_distinct_per_workspace_and_stable() {
        let (ws_a, ws_b, user) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        assert_ne!(member_scope_id(ws_a, user), member_scope_id(ws_b, user));
        assert_eq!(member_scope_id(ws_a, user), member_scope_id(ws_a, user));
        assert_ne!(member_scope_id(ws_a, user), user);
        // Pinned: the value Python's uuid.uuid5 produces over the same text,
        // which the e2e suite uses to find a member's counter.
        assert_eq!(
            member_scope_id(ws_a, user).to_string(),
            "255e6963-f48b-5a29-a645-d4901b32f83e"
        );
    }
}
