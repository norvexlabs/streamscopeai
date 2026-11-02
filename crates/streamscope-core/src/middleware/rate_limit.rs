//! Approximate rate limiting on the fleet-convergent counter primitive.
//!
//! Dual-bucket RPM (requests per minute), TPM (tokens per minute), and budget
//! limits with minute-/day-/month-aligned windows, all carried on the same
//! [`UsageTracker`](crate::usage::UsageTracker). A cap therefore converges
//! across every proxy replica sharing one edge token: each edge reports its
//! monotonic cumulative, admin SUM-merges to a fleet total and echoes it back,
//! and enforcement reads `authoritative_total + this edge's unreported delta`.
//! That estimate has bounded overshoot and is never a hard ledger — see the
//! [`crate::usage`] module docs.
//!
//! Every request is checked against up to four buckets:
//!
//! - the **tenant** bucket — the org-total ceiling, present only when an
//!   operator has set one ([`UserContext::tenant_budget`]), keyed by
//!   `tenant_id`. Budget-only, and the widest bucket: it caps the organisation
//!   rather than any one team. A workspace the organisation does not fund is
//!   baked with no `tenant_budget` at all (`workspaces.counts_toward_tenant_budget`
//!   off), which drops it from this bucket for BOTH the check and the accrual —
//!   never one without the other, or its traffic would be blocked by a counter
//!   it cannot move.
//! - the **workspace** bucket — the workspace's pool, shared across all
//!   members, keyed by `workspace_id`: its own caps, with a budget it leaves
//!   unset inheriting the tenant default budget (the Agent workspace included —
//!   it is governed like any other). A pool that resolves to no cap at all
//!   carries [`RateLimitConfig::unlimited`] so its checks short-circuit.
//! - the **member** bucket — present only when the member's limit inside this
//!   workspace resolves to something ([`crate::auth::member_limits`]: the
//!   workspace's default member limit, replaced per metric by an exception),
//!   baked into [`UserContext::user_rate_override`]. Keyed by the MEMBERSHIP
//!   ([`member_scope_id`]), so a user's usage in one workspace never counts
//!   against their limit in another.
//! - the **per-key budget** bucket — present only when the key carries an
//!   explicit per-key cap ([`UserContext::key_budget`]), keyed by `key_id`.
//!   Budget-only: it has no RPM/TPM, just the daily/monthly budget.
//!
//! "Stricter wins": a request must pass every applicable bucket. A limit of 0
//! means unlimited; exempt buckets are skipped.

use crate::auth::member_limits::member_scope_id;
use crate::auth::{RateLimitConfig, UserContext};
use crate::error::AppError;
use crate::usage::{
    BUDGET_UNITS_PER_CURRENCY_UNIT, UsageMetric, UsageScope, UsageScopeKind, UsageTracker, UsageWindowKind,
};
use uuid::Uuid;

/// Which limit refused a request — the typed `bucket` of a 429 and of its
/// audit row. Clients and the UI branch on this, never on the message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitBucket {
    /// The organisation ceiling.
    Organisation,
    /// The workspace pool, shared by its members.
    Workspace,
    /// One member's limit inside the workspace.
    Member,
    /// One key's own budget.
    Key,
}

impl LimitBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Organisation => "organisation",
            Self::Workspace => "workspace",
            Self::Member => "member",
            Self::Key => "key",
        }
    }

    fn of(kind: UsageScopeKind) -> Self {
        match kind {
            UsageScopeKind::Tenant => Self::Organisation,
            UsageScopeKind::Workspace => Self::Workspace,
            UsageScopeKind::User => Self::Member,
            UsageScopeKind::Key => Self::Key,
        }
    }

    /// The readable owner of a limit, for the refusal message.
    fn owner(self) -> &'static str {
        match self {
            Self::Organisation => "organisation",
            Self::Workspace => "workspace",
            Self::Member => "your member",
            Self::Key => "this key's",
        }
    }
}

/// The rate-limit buckets that apply to this request, as fleet-counter scopes.
/// Tenant bucket only when the tenant carries an org-total ceiling; workspace
/// bucket always; member bucket only when a member limit was baked; per-key
/// budget bucket only when this key carries an explicit cap. Callers
/// enforce *every* returned bucket (stricter wins). The per-minute RPM / TPM
/// accrual also keys on this selection, so a never-enforced member counter is
/// never created (the per-key bucket is budget-only — RPM/TPM are 0 there).
fn buckets(user: &UserContext) -> Vec<(UsageScopeKind, Uuid, &RateLimitConfig)> {
    let mut out = Vec::with_capacity(4);
    // Widest first: the org-total ceiling, when the tenant has one AND this
    // workspace's spend belongs in it — a key in a workspace the organisation
    // does not fund is baked with `tenant_budget: None`, so the exclusion needs
    // no branch here. Budget only, so it is inert in the RPM/TPM checks that
    // share this list.
    if let Some(tb) = &user.tenant_budget {
        out.push((UsageScopeKind::Tenant, user.tenant_id, tb));
    }
    out.push((UsageScopeKind::Workspace, user.workspace_id, &user.rate_limit));
    if let Some(member) = &user.user_rate_override {
        out.push((UsageScopeKind::User, member_scope_id(user.workspace_id, user.user_id), member));
    }
    if let (Some(kb), Some(key_id)) = (&user.key_budget, user.key_id) {
        out.push((UsageScopeKind::Key, key_id, kb));
    }
    out
}

/// Approximate RPM check + increment. Rejects if *any* applicable bucket is at
/// its limit; otherwise increments every checked bucket.
pub fn check_rate_limit(user: &UserContext, usage: &UsageTracker) -> Result<(), AppError> {
    let now_ms = crate::usage::now_ms();

    // Check all buckets first so a rejected request doesn't inflate the
    // buckets that were under their limit.
    let mut pending = Vec::new();
    for (scope_kind, scope_id, cfg) in buckets(user) {
        if cfg.exempt || cfg.requests_per_minute == 0 {
            continue;
        }
        let scope = UsageScope {
            tenant_id: user.tenant_id,
            scope_kind,
            scope_id,
            metric: UsageMetric::RequestsPerMinute,
        };
        if usage.estimate(scope, UsageWindowKind::Minute, now_ms) >= cfg.requests_per_minute as u64
        {
            let bucket = LimitBucket::of(scope_kind);
            return Err(AppError::RateLimited {
                message: format!("{} requests-per-minute limit reached", bucket.owner()),
                bucket: Some(bucket),
            });
        }
        pending.push(scope);
    }
    for scope in pending {
        usage.accrue(scope, UsageWindowKind::Minute, now_ms, 1);
    }
    Ok(())
}

/// Approximate TPM check (token accrual happens post-response in
/// [`update_token_usage`]). Rejects if any applicable bucket is over.
pub fn check_tpm_limit(user: &UserContext, usage: &UsageTracker) -> Result<(), AppError> {
    let now_ms = crate::usage::now_ms();

    for (scope_kind, scope_id, cfg) in buckets(user) {
        if cfg.exempt || cfg.tokens_per_minute == 0 {
            continue;
        }
        let scope = UsageScope {
            tenant_id: user.tenant_id,
            scope_kind,
            scope_id,
            metric: UsageMetric::TokensPerMinute,
        };
        if usage.estimate(scope, UsageWindowKind::Minute, now_ms) >= cfg.tokens_per_minute as u64 {
            let bucket = LimitBucket::of(scope_kind);
            return Err(AppError::RateLimited {
                message: format!("{} tokens-per-minute limit reached", bucket.owner()),
                bucket: Some(bucket),
            });
        }
    }
    Ok(())
}

/// Pre-request budget check: reject if any applicable bucket has already
/// exceeded its daily or monthly budget.
///
/// Spend converges fleet-wide via [`UsageTracker`](crate::usage::UsageTracker):
/// the estimate is `authoritative_total (all edges, last heartbeat) + this
/// edge's unreported delta`, in integer micro-dollars. A budget of 0.0 means unlimited;
/// exempt buckets are skipped. Enforcement is intentionally an estimate (bounded
/// overshoot, never a hard ledger) — see the [`crate::usage`] module docs.
pub fn check_budget(
    user: &UserContext,
    usage: &UsageTracker,
    currency: crate::pricing::Currency,
) -> Result<(), AppError> {
    let now_ms = crate::usage::now_ms();

    for (scope_kind, scope_id, cfg) in buckets(user) {
        // Alert-only buckets never block — the crossing still accrues and the
        // proactive-alert producer still fires; enforcement is suppressed here.
        if cfg.exempt || cfg.budget_alert_only {
            continue;
        }
        let scope = UsageScope {
            tenant_id: user.tenant_id,
            scope_kind,
            scope_id,
            metric: UsageMetric::BudgetMicros,
        };

        // Convert the cap into the counter's own unit, which the counter accrues
        // in too. Both are in the tenant's accounting currency by the time they
        // meet here. A cap of 0 (or one below one millionth of a unit, which
        // rounds to 0) is no cap: `spent >= 0` would block every request.
        for (window, budget, label, per) in [
            (UsageWindowKind::Daily, cfg.daily_budget, "daily", "day"),
            (UsageWindowKind::Monthly, cfg.monthly_budget, "monthly", "month"),
        ] {
            let limit_units = to_budget_units(budget);
            if limit_units == 0 {
                continue;
            }
            if usage.estimate(scope, window, now_ms) >= limit_units {
                let bucket = LimitBucket::of(scope_kind);
                return Err(AppError::BudgetExceeded {
                    message: format!("{} {label} budget reached ({budget:.2} {currency}/{per})", bucket.owner()),
                    bucket,
                });
            }
        }
    }

    Ok(())
}

/// An amount in the budget counter's unit (micro-units of the accounting
/// currency). A cap of 0, a negative one or one too small to count is 0 — no
/// cap: the float-to-integer cast saturates at 0 (and reads NaN as 0). An
/// infinite amount is 0 as well: the cast would saturate `+inf` to `u64::MAX`,
/// and one such cost would pin the counter above every cap for the window.
fn to_budget_units(amount: f64) -> u64 {
    if amount.is_infinite() {
        return 0;
    }
    (amount * BUDGET_UNITS_PER_CURRENCY_UNIT).round() as u64
}

/// Post-response budget accrual: add cost to the daily + monthly counters in the
/// edge's cumulative store. The workspace counter is always accrued (its bucket
/// is always enforced). The tenant, per-user and per-key counters are accrued
/// only when their bucket is actually enforced — `tenant_capped` (the tenant
/// carries an org-total ceiling), `user_override` (an override row was baked),
/// and `key_id` is `Some` (the key carries a budget) — because those counters
/// are read only when the matching cap exists. Gating keeps a `usage_counters`
/// row from being created for every uncapped tenant / user / key, and matches
/// the per-user TPM gating in [`update_token_usage`]. The cumulative is
/// reported up on the next heartbeat (see [`crate::usage`]).
// Four scope ids, each paired with whether its bucket is enforced. Bundling
// them into a struct would only move the same fields behind a name the two
// production call sites (a `RequestMeta`, a `UserContext`) would have to build.
#[allow(clippy::too_many_arguments)]
pub fn update_budget_usage(
    tenant_id: Uuid,
    tenant_capped: bool,
    workspace_id: Uuid,
    user_id: Uuid,
    user_override: bool,
    key_id: Option<Uuid>,
    cost: f64,
    usage: &UsageTracker,
) {
    if cost <= 0.0 {
        return;
    }
    // Millionths, not hundredths: an ordinary request costs a fraction of a cent,
    // and a cent-resolution counter rounds every one of those to zero — a budget
    // that never advances no matter how much traffic runs against it.
    let units = to_budget_units(cost);
    let now_ms = crate::usage::now_ms();

    let mut scopes = Vec::with_capacity(4);
    if tenant_capped {
        scopes.push((UsageScopeKind::Tenant, tenant_id));
    }
    scopes.push((UsageScopeKind::Workspace, workspace_id));
    if user_override {
        scopes.push((UsageScopeKind::User, member_scope_id(workspace_id, user_id)));
    }
    if let Some(key_id) = key_id {
        scopes.push((UsageScopeKind::Key, key_id));
    }
    for (scope_kind, scope_id) in scopes {
        let scope = UsageScope {
            tenant_id,
            scope_kind,
            scope_id,
            metric: UsageMetric::BudgetMicros,
        };
        for window_kind in [UsageWindowKind::Daily, UsageWindowKind::Monthly] {
            usage.accrue(scope, window_kind, now_ms, units);
        }
    }
}

/// Post-response TPM accrual: add tokens to the per-minute counters for the
/// workspace bucket always, plus the member bucket only when a member limit was
/// baked (`rate_override`). Gating the member bucket on it keeps a
/// never-enforced member minute counter from being created. Callers invoke this
/// only when the tenant has rate limiting enabled (the workspace bucket itself is
/// always accrued, like the budget counter — the TPM check, not this accrual,
/// applies the exempt / cap-0 skip). The cumulative is reported up on the next
/// usage-sync tick (see [`crate::usage`]).
pub fn update_token_usage(
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    rate_override: bool,
    total_tokens: u32,
    usage: &UsageTracker,
) {
    if total_tokens == 0 {
        return;
    }
    let now_ms = crate::usage::now_ms();

    let mut scopes = vec![(UsageScopeKind::Workspace, workspace_id)];
    if rate_override {
        scopes.push((UsageScopeKind::User, member_scope_id(workspace_id, user_id)));
    }
    for (scope_kind, scope_id) in scopes {
        let scope = UsageScope {
            tenant_id,
            scope_kind,
            scope_id,
            metric: UsageMetric::TokensPerMinute,
        };
        usage.accrue(scope, UsageWindowKind::Minute, now_ms, total_tokens as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use crate::auth::RateLimitConfig;

    fn ctx(workspace_id: Uuid, user_id: Uuid, ws: RateLimitConfig, ovr: Option<RateLimitConfig>) -> UserContext {
        UserContext {
            inline_ai: false,
            qos_class_id: None,
            qos_class_elevated: false,
            user_id,
            tenant_id: Uuid::nil(),
            email: None,
            display_name: None,
            real_api_key: String::new(),
            model_map: std::sync::Arc::default(),
            rate_limit: ws,
            user_rate_override: ovr,
            key_budget: None,
            tenant_budget: None,
            expires_at: None,
            key_id: None,
            app_id: None,
            session_id: None,
            workspace_id,
            allowed_provider_ids: Vec::new(),
            allowed_virtual_server_ids: Vec::new(),
            allowed_a2a_agent_ids: Vec::new(),
            mcp_scope: None,
            forward_auth: false,
            byok_passthrough: Vec::new(),
        }
    }

    fn rpm(n: u32) -> RateLimitConfig {
        RateLimitConfig { requests_per_minute: n, ..RateLimitConfig::unlimited() }
    }

    /// Context with an uncapped workspace plus a per-key budget bucket.
    fn key_budget_ctx(key_id: Uuid, kb: RateLimitConfig) -> UserContext {
        let mut u = ctx(Uuid::from_u128(100), Uuid::from_u128(101), RateLimitConfig::unlimited(), None);
        u.key_id = Some(key_id);
        u.key_budget = Some(kb);
        u
    }

    #[test]
    fn workspace_cap_enforced_then_rejects() {
        let usage = UsageTracker::new();
        let u = ctx(Uuid::from_u128(1), Uuid::from_u128(2), rpm(2), None);
        // Two requests within the window pass, the third is rejected.
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert_matches!(check_rate_limit(&u, &usage), Err(AppError::RateLimited { .. }));
    }

    #[test]
    fn uncapped_workspace_never_rejects() {
        let usage = UsageTracker::new();
        // A workspace with no configured cap: unlimited() bucket → never rejects.
        let u = ctx(Uuid::from_u128(3), Uuid::from_u128(4), RateLimitConfig::unlimited(), None);
        for _ in 0..50 {
            assert!(check_rate_limit(&u, &usage).is_ok());
        }
    }

    #[test]
    fn per_user_override_stricter_wins() {
        let usage = UsageTracker::new();
        // Workspace allows 10, but the member limit allows only 2 → the member
        // bucket binds first.
        let u = ctx(Uuid::from_u128(5), Uuid::from_u128(6), rpm(10), Some(rpm(2)));
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert_matches!(check_rate_limit(&u, &usage), Err(AppError::RateLimited { .. }));
    }

    #[test]
    fn rejected_request_does_not_inflate_under_limit_bucket() {
        let usage = UsageTracker::new();
        // Workspace cap 1, member limit 5. The workspace bucket rejects the
        // 2nd request; the member bucket (under its limit) must NOT have been
        // incremented by the rejected request — so once the workspace cap is
        // lifted the same member still has exactly 4 left.
        let ws_id = Uuid::from_u128(7);
        let user_id = Uuid::from_u128(8);
        let u = ctx(ws_id, user_id, rpm(1), Some(rpm(5)));
        assert!(check_rate_limit(&u, &usage).is_ok()); // ws=1, member=1
        assert_matches!(check_rate_limit(&u, &usage), Err(AppError::RateLimited { .. })); // ws over → reject
        let lifted = ctx(ws_id, user_id, RateLimitConfig::unlimited(), Some(rpm(5)));
        for _ in 0..4 {
            assert!(check_rate_limit(&lifted, &usage).is_ok());
        }
        assert_matches!(check_rate_limit(&lifted, &usage), Err(AppError::RateLimited { .. }));
    }

    /// A member's limit is per MEMBERSHIP: exhausting it in one workspace
    /// leaves the same person's limit in another workspace untouched.
    #[test]
    fn a_members_usage_in_one_workspace_never_counts_in_another() {
        let usage = UsageTracker::new();
        let user_id = Uuid::from_u128(30);
        let in_a = ctx(Uuid::from_u128(31), user_id, RateLimitConfig::unlimited(), Some(rpm(2)));
        let in_b = ctx(Uuid::from_u128(32), user_id, RateLimitConfig::unlimited(), Some(rpm(2)));
        assert!(check_rate_limit(&in_a, &usage).is_ok());
        assert!(check_rate_limit(&in_a, &usage).is_ok());
        assert_matches!(check_rate_limit(&in_a, &usage), Err(AppError::RateLimited { .. }));
        assert!(check_rate_limit(&in_b, &usage).is_ok());
        assert!(check_rate_limit(&in_b, &usage).is_ok());
        assert_matches!(check_rate_limit(&in_b, &usage), Err(AppError::RateLimited { .. }));

        // Budget and tokens follow the same key.
        update_budget_usage(Uuid::nil(), false, in_a.workspace_id, user_id, true, None, 3.0, &usage);
        let mut budget_b = in_b.clone();
        budget_b.user_rate_override = Some(RateLimitConfig::budget_only(1.0, 0.0, false));
        assert!(check_budget(&budget_b, &usage, crate::pricing::Currency::USD).is_ok());
        let mut budget_a = in_a.clone();
        budget_a.user_rate_override = Some(RateLimitConfig::budget_only(1.0, 0.0, false));
        assert_matches!(check_budget(&budget_a, &usage, crate::pricing::Currency::USD), Err(AppError::BudgetExceeded { .. }));
    }

    /// A member limit RAISED above the workspace pool still stops at the pool:
    /// every bucket applies, the tightest wins.
    #[test]
    fn a_raised_member_limit_never_lifts_the_pool() {
        let usage = UsageTracker::new();
        let u = ctx(Uuid::from_u128(40), Uuid::from_u128(41), rpm(2), Some(rpm(100)));
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert!(check_rate_limit(&u, &usage).is_ok());
        assert_matches!(check_rate_limit(&u, &usage), Err(AppError::RateLimited { .. }));
    }

    /// Both sides of a member budget cap: one micro under passes, the cap
    /// itself blocks.
    #[test]
    fn a_member_budget_blocks_at_the_cap_and_not_before() {
        let usage = UsageTracker::new();
        let (ws, user) = (Uuid::from_u128(50), Uuid::from_u128(51));
        let u = ctx(ws, user, RateLimitConfig::unlimited(), Some(RateLimitConfig::budget_only(1.0, 0.0, false)));
        update_budget_usage(Uuid::nil(), false, ws, user, true, None, 0.999_999, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(Uuid::nil(), false, ws, user, true, None, 0.000_001, &usage);
        assert_matches!(check_budget(&u, &usage, crate::pricing::Currency::USD), Err(AppError::BudgetExceeded { .. }));
    }

    #[test]
    fn per_key_budget_blocks_when_over_cap() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(20);
        // $1/day per-key cap; accrue $1.50 to the key scope → over cap → blocks.
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(1.0, 0.0, false));
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 1.5, &usage);
        assert_matches!(check_budget(&u, &usage, crate::pricing::Currency::USD), Err(AppError::BudgetExceeded { .. }));
    }

    #[test]
    fn per_key_alert_only_never_blocks() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(21);
        // Same $1/day cap, but alert-only → over-cap does not block.
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(1.0, 0.0, true));
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 5.0, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
    }

    #[test]
    fn uncapped_key_accrues_no_key_scope() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(22);
        // No per-key budget configured → caller passes None → no key-scope counter.
        let mut u = ctx(Uuid::from_u128(102), Uuid::from_u128(103), RateLimitConfig::unlimited(), None);
        u.key_id = Some(key_id);
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, None, 9.0, &usage);
        let key_scope = UsageScope {
            tenant_id: u.tenant_id,
            scope_kind: UsageScopeKind::Key,
            scope_id: key_id,
            metric: UsageMetric::BudgetMicros,
        };
        assert_eq!(usage.estimate(key_scope, UsageWindowKind::Daily, crate::usage::now_ms()), 0);
    }

    #[test]
    fn no_override_accrues_no_user_scope() {
        let usage = UsageTracker::new();
        let ws_id = Uuid::from_u128(110);
        let user_id = Uuid::from_u128(111);
        // No member limit → the member budget counter must not be created
        // (it would never be read — only the workspace bucket is enforced).
        let u = ctx(ws_id, user_id, RateLimitConfig::unlimited(), None);
        update_budget_usage(u.tenant_id, false, ws_id, user_id, false, None, 9.0, &usage);
        let user_scope = UsageScope {
            tenant_id: u.tenant_id,
            scope_kind: UsageScopeKind::User,
            scope_id: member_scope_id(ws_id, user_id),
            metric: UsageMetric::BudgetMicros,
        };
        assert_eq!(usage.estimate(user_scope, UsageWindowKind::Daily, crate::usage::now_ms()), 0);
        // The workspace scope is always accrued.
        let ws_scope = UsageScope {
            tenant_id: u.tenant_id,
            scope_kind: UsageScopeKind::Workspace,
            scope_id: ws_id,
            metric: UsageMetric::BudgetMicros,
        };
        assert_eq!(
            usage.estimate(ws_scope, UsageWindowKind::Daily, crate::usage::now_ms()),
            9_000_000
        );
    }

    /// The org ceiling is ONE counter for the whole tenant: spend booked
    /// against one workspace is what stops a request arriving on another.
    /// That cross-workspace reach is the entire point of the scope — the
    /// per-workspace cap already covers the single-team case.
    #[test]
    fn tenant_cap_is_shared_across_workspaces() {
        let usage = UsageTracker::new();
        let cap = RateLimitConfig::budget_only(1.0, 0.0, false);
        let mut spender = ctx(
            Uuid::from_u128(200),
            Uuid::from_u128(201),
            RateLimitConfig::unlimited(),
            None,
        );
        spender.tenant_budget = Some(cap.clone());
        let mut neighbour = ctx(
            Uuid::from_u128(202),
            Uuid::from_u128(203),
            RateLimitConfig::unlimited(),
            None,
        );
        neighbour.tenant_budget = Some(cap);
        assert_eq!(spender.tenant_id, neighbour.tenant_id);
        assert_ne!(spender.workspace_id, neighbour.workspace_id);

        assert!(check_budget(&neighbour, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(
            spender.tenant_id,
            true,
            spender.workspace_id,
            spender.user_id,
            false,
            None,
            1.5,
            &usage,
        );
        assert_matches!(
            check_budget(&neighbour, &usage, crate::pricing::Currency::USD),
            Err(AppError::BudgetExceeded { .. })
        );
    }

    /// An uncapped tenant creates no tenant-scope counter — the same gating the
    /// per-user and per-key buckets get, so the default case keeps zero extra
    /// rows in the fleet counter.
    #[test]
    fn uncapped_tenant_accrues_no_tenant_scope() {
        let usage = UsageTracker::new();
        let u = ctx(
            Uuid::from_u128(210),
            Uuid::from_u128(211),
            RateLimitConfig::unlimited(),
            None,
        );
        assert!(u.tenant_budget.is_none());
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, None, 9.0, &usage);
        let tenant_scope = UsageScope {
            tenant_id: u.tenant_id,
            scope_kind: UsageScopeKind::Tenant,
            scope_id: u.tenant_id,
            metric: UsageMetric::BudgetMicros,
        };
        assert_eq!(
            usage.estimate(tenant_scope, UsageWindowKind::Daily, crate::usage::now_ms()),
            0
        );
    }

    /// `alert_only` on the org ceiling records the crossing without blocking —
    /// the same warn-without-cutting-off contract the other buckets carry.
    #[test]
    fn tenant_cap_in_alert_only_mode_never_blocks() {
        let usage = UsageTracker::new();
        let mut u = ctx(
            Uuid::from_u128(220),
            Uuid::from_u128(221),
            RateLimitConfig::unlimited(),
            None,
        );
        u.tenant_budget = Some(RateLimitConfig::budget_only(1.0, 0.0, true));
        update_budget_usage(u.tenant_id, true, u.workspace_id, u.user_id, false, None, 5.0, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
    }

    #[test]
    fn cap_below_the_counter_resolution_is_treated_as_uncapped() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(120);
        // A cap under one micro-dollar rounds to 0 units — must NOT block every
        // request, since `spent >= 0` is true before any spend at all.
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(0.0000004, 0.0, false));
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 0.01, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
    }

    /// A single ordinary request costs a small fraction of a cent. It must still
    /// move the counter — a cent-resolution counter rounded every such request to
    /// zero, so a budget could never be reached however much traffic ran against
    /// it.
    #[test]
    fn a_sub_cent_request_accrues() {
        let usage = UsageTracker::new();
        let ws_id = Uuid::from_u128(130);
        let user_id = Uuid::from_u128(131);
        let u = ctx(ws_id, user_id, RateLimitConfig::unlimited(), None);
        // 1k prompt tokens at $3/1M.
        update_budget_usage(u.tenant_id, false, ws_id, user_id, false, None, 0.003, &usage);
        let ws_scope = UsageScope {
            tenant_id: u.tenant_id,
            scope_kind: UsageScopeKind::Workspace,
            scope_id: ws_id,
            metric: UsageMetric::BudgetMicros,
        };
        assert_eq!(
            usage.estimate(ws_scope, UsageWindowKind::Daily, crate::usage::now_ms()),
            3_000
        );
    }

    /// The end of the same story: enough sub-cent requests reach a real cap and
    /// the budget actually stops them.
    #[test]
    fn sub_cent_requests_accumulate_until_the_cap_trips() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(140);
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(0.10, 0.0, false));
        for _ in 0..33 {
            assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
            update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 0.003, &usage);
        }
        // 33 × $0.003 = $0.099 — still under the $0.10 cap.
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 0.003, &usage);
        assert_matches!(check_budget(&u, &usage, crate::pricing::Currency::USD), Err(AppError::BudgetExceeded { .. }));
    }

    fn tpm(n: u32) -> RateLimitConfig {
        RateLimitConfig { tokens_per_minute: n, ..RateLimitConfig::unlimited() }
    }

    /// Both sides of a TPM cap, in the member bucket: one token under passes,
    /// the cap itself refuses — and names the member bucket.
    #[test]
    fn a_member_tpm_cap_refuses_at_the_cap_and_not_before() {
        let usage = UsageTracker::new();
        let (ws, user) = (Uuid::from_u128(60), Uuid::from_u128(61));
        let u = ctx(ws, user, RateLimitConfig::unlimited(), Some(tpm(100)));
        update_token_usage(u.tenant_id, ws, user, true, 99, &usage);
        assert!(check_tpm_limit(&u, &usage).is_ok());
        update_token_usage(u.tenant_id, ws, user, true, 1, &usage);
        assert_matches!(
            check_tpm_limit(&u, &usage),
            Err(AppError::RateLimited { bucket: Some(LimitBucket::Member), .. })
        );
    }

    /// A TPM cap of 0 is "no cap", an exempt bucket never refuses, and the
    /// workspace pool refuses under its own name.
    #[test]
    fn tpm_zero_and_exempt_never_refuse_and_the_pool_names_itself() {
        let usage = UsageTracker::new();
        let (ws, user) = (Uuid::from_u128(62), Uuid::from_u128(63));
        update_token_usage(Uuid::nil(), ws, user, false, 1_000, &usage);
        assert!(check_tpm_limit(&ctx(ws, user, tpm(0), None), &usage).is_ok());
        let exempt = RateLimitConfig { exempt: true, ..tpm(10) };
        assert!(check_tpm_limit(&ctx(ws, user, exempt, None), &usage).is_ok());
        assert_matches!(
            check_tpm_limit(&ctx(ws, user, tpm(10), None), &usage),
            Err(AppError::RateLimited { bucket: Some(LimitBucket::Workspace), .. })
        );
    }

    /// Tokens accrue to the pool always, to the member bucket only when a
    /// member limit exists, and a zero-token response accrues nothing.
    #[test]
    fn token_usage_accrues_where_it_is_enforced() {
        let usage = UsageTracker::new();
        let (ws, user) = (Uuid::from_u128(64), Uuid::from_u128(65));
        let now = crate::usage::now_ms();
        let scope = |kind, id| UsageScope { tenant_id: Uuid::nil(), scope_kind: kind, scope_id: id, metric: UsageMetric::TokensPerMinute };
        let pool = scope(UsageScopeKind::Workspace, ws);
        let member = scope(UsageScopeKind::User, member_scope_id(ws, user));
        update_token_usage(Uuid::nil(), ws, user, false, 0, &usage);
        assert_eq!(usage.estimate(pool, UsageWindowKind::Minute, now), 0);
        update_token_usage(Uuid::nil(), ws, user, false, 7, &usage);
        assert_eq!(usage.estimate(pool, UsageWindowKind::Minute, now), 7);
        assert_eq!(usage.estimate(member, UsageWindowKind::Minute, now), 0);
        update_token_usage(Uuid::nil(), ws, user, true, 5, &usage);
        assert_eq!(usage.estimate(pool, UsageWindowKind::Minute, now), 12);
        assert_eq!(usage.estimate(member, UsageWindowKind::Minute, now), 5);
    }

    /// Both sides of a MONTHLY cap (the daily path is covered above): the
    /// cap is converted to the counter's micro-units the same way.
    #[test]
    fn a_monthly_budget_blocks_at_the_cap_and_not_before() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(70);
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(0.0, 2.0, false));
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 1.999_999, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 0.000_001, &usage);
        assert_matches!(
            check_budget(&u, &usage, crate::pricing::Currency::USD),
            Err(AppError::BudgetExceeded { bucket: LimitBucket::Key, .. })
        );
    }

    /// Every amount that is not a positive, countable cap converts to 0 —
    /// the "no cap" value `check_budget` skips — and a countable one to its
    /// micro-units, on both sides of the rounding boundary.
    #[test]
    fn only_a_countable_positive_amount_is_a_cap() {
        for none in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.000_000_4] {
            assert_eq!(to_budget_units(none), 0, "{none}");
        }
        assert_eq!(to_budget_units(0.000_000_6), 1);
        assert_eq!(to_budget_units(0.01), 10_000);
        assert_eq!(to_budget_units(2.0), 2_000_000);
        // The largest finite amount is a real (huge) number, not "no cap".
        assert_eq!(to_budget_units(f64::MAX), u64::MAX);
    }

    /// A budget of 0 is no cap: it never blocks, whatever was spent.
    #[test]
    fn a_zero_budget_never_blocks() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(72);
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(0.0, 0.0, false));
        update_budget_usage(u.tenant_id, false, u.workspace_id, u.user_id, false, Some(key_id), 50.0, &usage);
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
    }

    /// A monthly cap below the counter's resolution rounds to no cap, exactly
    /// like a daily one.
    #[test]
    fn a_monthly_cap_below_the_resolution_is_no_cap() {
        let usage = UsageTracker::new();
        let key_id = Uuid::from_u128(71);
        let u = key_budget_ctx(key_id, RateLimitConfig::budget_only(0.0, 0.000_000_4, false));
        assert!(check_budget(&u, &usage, crate::pricing::Currency::USD).is_ok());
    }

    /// The bucket names are a wire contract (the typed `bucket` of a 429 and of
    /// the audit row) and the refusal message names whose limit it was.
    #[test]
    fn each_bucket_has_its_wire_name_and_its_owner_in_the_message() {
        assert_eq!(LimitBucket::Organisation.as_str(), "organisation");
        assert_eq!(LimitBucket::Workspace.as_str(), "workspace");
        assert_eq!(LimitBucket::Member.as_str(), "member");
        assert_eq!(LimitBucket::Key.as_str(), "key");
        for (bucket, kind) in [
            (LimitBucket::Organisation, UsageScopeKind::Tenant),
            (LimitBucket::Workspace, UsageScopeKind::Workspace),
            (LimitBucket::Member, UsageScopeKind::User),
            (LimitBucket::Key, UsageScopeKind::Key),
        ] {
            assert_eq!(LimitBucket::of(kind), bucket);
            let json = serde_json::to_value(bucket).unwrap();
            assert_eq!(json, bucket.as_str());
        }
        let usage = UsageTracker::new();
        let u = ctx(Uuid::from_u128(72), Uuid::from_u128(73), RateLimitConfig::unlimited(), Some(rpm(1)));
        assert!(check_rate_limit(&u, &usage).is_ok());
        match check_rate_limit(&u, &usage) {
            Err(AppError::RateLimited { message, bucket }) => {
                assert_eq!(bucket, Some(LimitBucket::Member));
                assert!(message.contains("your member"), "{message}");
            }
            other => panic!("expected a member refusal, got {other:?}"),
        }
    }
}
