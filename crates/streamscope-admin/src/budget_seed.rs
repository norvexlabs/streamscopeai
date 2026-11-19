//! A newly set budget counts the spend already made in its window.
//!
//! The gateway accrues a member's, a key's and the organisation's budget
//! counter only while a limit for that scope exists (the workspace pool's is
//! always accrued). So when a limit write gives one of those scopes a daily or
//! monthly cap it did not have, the write seeds the scope's counter for the
//! CURRENT window from the spend already made: a $50 monthly limit set after
//! $40 of spend in the block stops the member at $50, not $90.
//!
//! One source per scope. A member's and a key's spend is read from the audit
//! (`audit_store::usage::budget_window_spend` — no counter was accrued for
//! them). The organisation's is the sum of the always-accrued pool counters of
//! the workspaces that count toward its ceiling: the same amounts the tenant
//! counter would have accrued, O(workspaces), and they include spend an edge
//! has reported but whose audit rows are still in its outbox.
//!
//! The order every limit write keeps, inside its one transaction:
//!
//! 1. Take the lock that orders this scope's limit writers — a member write
//!    the workspace row, a key write the key row ([`lock_key_budget`], whose
//!    `SELECT … FOR UPDATE` also reads the key's caps before), a ceiling write
//!    the tenant's ceiling lock ([`lock_ceiling`]). It is part of the write,
//!    outside any savepoint: if it cannot be taken, the write fails. Because
//!    the writers take turns, each one's before-read sees the other's commit,
//!    so two writes that each newly cap nothing cannot together newly cap a
//!    scope without either seeding it.
//! 2. Read the caps before ([`read_member_buckets`] — one member's for a
//!    write to that member's exception, the workspace's for its default —
//!    and [`read_ceiling`]) — best-effort, under a savepoint. A key's were
//!    read by its lock in step 1.
//! 3. Write the limit.
//! 4. Seed ([`seed_members`], [`seed_key`], [`seed_organisation`]) under a
//!    savepoint: read the caps after, and only for a scope × window that went
//!    from no cap to a cap read the spend and upsert its counter. Everything
//!    here is best-effort: a failure is logged, rolled back to the savepoint,
//!    and the limit is still written.
//!
//! Every caller first asks whether the write can newly cap anything at all
//! (`could_*` / [`sets_a_cap`]) and skips steps 2 and 4 when it cannot — a
//! rate-only edit, an unchanged budget, a removal that falls back to no budget.
//!
//! Why the seed never counts a request twice: an edge accrues a scope only
//! once it holds a config that bakes the scope's limit, and config sync reads
//! committed rows — so it bakes this limit only after the transaction commits,
//! and every request accrued under it starts after the spend was read. The
//! seed never touches `usage_counter_watermarks`, so the watermark/delta merge
//! adds every edge's later delta to the seeded total as it adds any delta. The
//! upsert keeps `GREATEST(existing, seed)`: a scope already accrued (a member
//! whose rate-only limit gets a budget) keeps its counter when it is ahead; the
//! only overlap left there is a request its edge accrued but has not reported
//! whose spend was read — counted twice, in the strict direction.
//!
//! What the seed leaves out: for a member or a key, a request finished before
//! the commit whose audit row lands after the read (an edge's outbox backlog)
//! and rows past the tenant's retention; for the organisation, spend an edge
//! accrued but had not reported. All undercount, never overcount.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use streamscope_core::auth::RateLimitConfig;
use streamscope_core::middleware::rate_limit::to_budget_units;
use streamscope_core::usage::{UsageMetric, UsageScopeKind, UsageWindowKind};
use uuid::Uuid;

use crate::audit_store::usage::{BudgetSpendOf, BudgetWindows};
use crate::db::tenant::Scoped;

/// The daily and monthly caps of one scope (`0` = none).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Caps {
    pub daily: f64,
    pub monthly: f64,
}

impl Caps {
    pub fn of(daily: Option<f64>, monthly: Option<f64>) -> Self {
        Self { daily: daily.unwrap_or(0.0), monthly: monthly.unwrap_or(0.0) }
    }

    fn of_bucket(c: Option<&RateLimitConfig>) -> Self {
        c.map_or_else(Self::default, |c| Self { daily: c.daily_budget, monthly: c.monthly_budget })
    }

    /// Which windows `after` caps that `self` did not: the ones to seed.
    pub fn newly_capped(self, after: Caps) -> NewlyCapped {
        // A NaN or negative cap is no cap, as the gateway reads it.
        let capped = |v: f64| v > 0.0;
        NewlyCapped {
            daily: !capped(self.daily) && capped(after.daily),
            monthly: !capped(self.monthly) && capped(after.monthly),
        }
    }
}

/// The windows a limit write newly caps for one scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NewlyCapped {
    pub daily: bool,
    pub monthly: bool,
}

impl NewlyCapped {
    pub fn any(self) -> bool {
        self.daily || self.monthly
    }
}

/// Whether a budget write can newly cap anything: it sets a positive cap.
pub(crate) fn sets_a_cap(daily: Option<f64>, monthly: Option<f64>) -> bool {
    [daily, monthly].into_iter().flatten().any(|v| v > 0.0)
}

/// Spend already made in the current budget windows, per scope id, in the
/// counter's unit (micro-units of the accounting currency).
struct SpendSnapshot {
    windows: BudgetWindows,
    spend: HashMap<Uuid, (i64, i64)>,
}

impl SpendSnapshot {
    /// The windows of the database clock's instant: the clock the janitor ages
    /// windows by, read once so both windows come from one instant.
    async fn windows(conn: &mut Scoped) -> sqlx::Result<BudgetWindows> {
        let now_ms: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut *conn)
            .await?;
        Ok(windows_at(now_ms.max(0) as u64))
    }

    /// A member's or a key's spend, from the audit.
    async fn from_audit(conn: &mut Scoped, of: BudgetSpendOf) -> sqlx::Result<Self> {
        let windows = Self::windows(conn).await?;
        let currency = crate::routes::pricing::accounting_currency(&mut *conn).await.to_string();
        let rows = crate::audit_store::usage::budget_window_spend(&mut *conn, of, &currency, windows).await?;
        let units = |amount: f64| i64::try_from(to_budget_units(amount)).unwrap_or(i64::MAX);
        Ok(Self { windows, spend: rows.into_iter().map(|(id, d, m)| (id, (units(d), units(m)))).collect() })
    }

    /// The organisation's spend: the sum of the pool counters of the
    /// workspaces counting toward its ceiling, in the current windows.
    async fn organisation(conn: &mut Scoped, tenant_id: Uuid) -> sqlx::Result<Self> {
        let windows = Self::windows(conn).await?;
        let (daily, monthly): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(c.total) FILTER (WHERE c.window_kind = $2 AND c.window_start = $3), 0)::bigint, \
                    COALESCE(SUM(c.total) FILTER (WHERE c.window_kind = $4 AND c.window_start = $5), 0)::bigint \
               FROM usage_counters c \
               JOIN workspaces w ON w.id = c.scope_id AND w.counts_toward_tenant_budget \
              WHERE c.tenant_id = $1 AND c.scope_kind = $6 AND c.metric = $7 \
                AND ((c.window_kind = $2 AND c.window_start = $3) OR (c.window_kind = $4 AND c.window_start = $5))",
        )
        .bind(tenant_id)
        .bind(UsageWindowKind::Daily.as_str())
        .bind(windows.daily.0)
        .bind(UsageWindowKind::Monthly.as_str())
        .bind(windows.monthly.0)
        .bind(UsageScopeKind::Workspace.as_str())
        .bind(UsageMetric::BudgetMicros.as_str())
        .fetch_one(&mut *conn)
        .await?;
        Ok(Self { windows, spend: HashMap::from([(tenant_id, (daily, monthly))]) })
    }
}

/// The budget windows containing `now_ms`, aligned exactly as the gateway
/// aligns the counters it accrues (`UsageWindowKind::window_start_ms`).
fn windows_at(now_ms: u64) -> BudgetWindows {
    let window = |kind: UsageWindowKind| {
        let start = kind.window_start_ms(now_ms);
        (at(start), at(start + kind.window_ms()))
    };
    BudgetWindows { daily: window(UsageWindowKind::Daily), monthly: window(UsageWindowKind::Monthly) }
}

fn at(ms: u64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(ms as i64).unwrap_or_default()
}

/// One counter to seed: the scope it belongs to, the spend id the snapshot
/// keys it by, and the windows the write newly capped.
struct Seed {
    scope_kind: UsageScopeKind,
    /// The counter's scope id (a member's is its membership id).
    scope_id: Uuid,
    /// The id the snapshot's spend is keyed by (a member's user id).
    spend_id: Uuid,
    windows: NewlyCapped,
}

/// `(scope_kind, scope_id, window_kind, window_start, total)` of every counter
/// to seed, in a fixed order (two writers seeding the same rows lock them in
/// the same order). A window with no spend needs no row.
fn seed_rows(snapshot: &SpendSnapshot, seeds: &[Seed]) -> Vec<(&'static str, Uuid, &'static str, DateTime<Utc>, i64)> {
    let mut rows = Vec::new();
    for s in seeds {
        let (daily, monthly) = snapshot.spend.get(&s.spend_id).copied().unwrap_or_default();
        for (on, kind, start, total) in [
            (s.windows.daily, UsageWindowKind::Daily, snapshot.windows.daily.0, daily),
            (s.windows.monthly, UsageWindowKind::Monthly, snapshot.windows.monthly.0, monthly),
        ] {
            if on && total > 0 {
                rows.push((s.scope_kind.as_str(), s.scope_id, kind.as_str(), start, total));
            }
        }
    }
    rows.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    rows
}

async fn write_seeds(
    conn: &mut Scoped,
    tenant_id: Uuid,
    rows: &[(&'static str, Uuid, &'static str, DateTime<Utc>, i64)],
) -> sqlx::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let kinds: Vec<&str> = rows.iter().map(|r| r.0).collect();
    let ids: Vec<Uuid> = rows.iter().map(|r| r.1).collect();
    let windows: Vec<&str> = rows.iter().map(|r| r.2).collect();
    let starts: Vec<DateTime<Utc>> = rows.iter().map(|r| r.3).collect();
    let totals: Vec<i64> = rows.iter().map(|r| r.4).collect();
    sqlx::query(
        "INSERT INTO usage_counters (tenant_id, scope_kind, scope_id, metric, window_kind, window_start, total, updated_at) \
         SELECT $1, s.kind, s.id, $2, s.window_kind, s.window_start, s.total, now() \
           FROM unnest($3::text[], $4::uuid[], $5::text[], $6::timestamptz[], $7::bigint[]) \
                WITH ORDINALITY AS s(kind, id, window_kind, window_start, total, n) \
          ORDER BY s.n \
         ON CONFLICT (tenant_id, scope_kind, scope_id, metric, window_kind, window_start) \
         DO UPDATE SET total = GREATEST(usage_counters.total, EXCLUDED.total), updated_at = now()",
    )
    .bind(tenant_id)
    .bind(UsageMetric::BudgetMicros.as_str())
    .bind(&kinds)
    .bind(&ids)
    .bind(&windows)
    .bind(&starts)
    .bind(&totals)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Run `what` under a savepoint of `tx`, best-effort: an error is logged with
/// `step` and rolled back to the savepoint, leaving the transaction usable.
macro_rules! best_effort {
    ($tx:expr, $tenant_id:expr, $step:literal, |$sp:ident| $body:expr) => {{
        match $tx.begin().await {
            Ok(mut savepoint) => {
                let result = {
                    let $sp: &mut Scoped = &mut savepoint;
                    $body.await
                };
                match result {
                    Ok(value) => match savepoint.commit().await {
                        Ok(()) => Some(value),
                        Err(e) => {
                            tracing::warn!(tenant_id = %$tenant_id, "budget seed ({}): {e} — the limit counts from now", $step);
                            None
                        }
                    },
                    Err(e) => {
                        let _ = savepoint.rollback().await;
                        tracing::warn!(tenant_id = %$tenant_id, "budget seed ({}): {e} — the limit counts from now", $step);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!(tenant_id = %$tenant_id, "budget seed ({}): {e} — the limit counts from now", $step);
                None
            }
        }
    }};
}

/// The member seeds a write to a workspace's member limits calls for: every
/// membership whose resolved daily or monthly budget went from none to a value
/// between `before` and `after` (both from `limits::load_member_buckets`).
fn member_seeds(
    before: &HashMap<(Uuid, Uuid), RateLimitConfig>,
    after: &HashMap<(Uuid, Uuid), RateLimitConfig>,
) -> Vec<Seed> {
    after
        .iter()
        .filter_map(|(&(ws, uid), now)| {
            let windows = Caps::of_bucket(before.get(&(ws, uid))).newly_capped(Caps::of_bucket(Some(now)));
            windows.any().then(|| Seed {
                scope_kind: UsageScopeKind::User,
                scope_id: streamscope_core::auth::member_limits::member_scope_id(ws, uid),
                spend_id: uid,
                windows,
            })
        })
        .collect()
}

/// Whether a member-limit write can leave any member of the workspace with a
/// budget: some member's resolved daily or monthly budget is a value after it.
/// `after_default` and `after_exception` are the workspace default and — for
/// a write to one member — that member's exception as the write leaves them
/// (`None` exception: the member falls back to the default). A `false` skips
/// the seed's reads altogether.
pub(crate) fn could_cap_a_member(
    after_default: (Option<f64>, Option<f64>),
    after_exception: Option<(Option<f64>, Option<f64>)>,
) -> bool {
    let (d_daily, d_monthly) = after_default;
    match after_exception {
        // The exception's own value, else the default's.
        Some((e_daily, e_monthly)) => sets_a_cap(e_daily.or(d_daily), e_monthly.or(d_monthly)),
        None => sets_a_cap(d_daily, d_monthly),
    }
}

/// The workspace default's `(daily, monthly)` member budget as it stands,
/// best-effort (`None` seeds nothing) — what an exception write's
/// [`could_cap_a_member`] reads, under the member-limit lock.
pub(crate) async fn read_member_default_budget(
    tx: &mut Scoped,
    tenant_id: Uuid,
    ws: Uuid,
) -> Option<(Option<f64>, Option<f64>)> {
    best_effort!(tx, tenant_id, "member default before", |sp| async move {
        let row: Option<(Option<f64>, Option<f64>)> = sqlx::query_as(
            "SELECT member_daily_budget, member_monthly_budget FROM workspace_rate_limits WHERE workspace_id = $1",
        )
        .bind(ws)
        .fetch_optional(&mut *sp)
        .await?;
        Ok::<_, sqlx::Error>(row.unwrap_or_default())
    })
}

/// The resolved member bucket of every membership of `ws` (only `user`'s,
/// when set: a write to one member's exception concerns no other) as it
/// stands — step 2 for a member-limit write, best-effort (`None` seeds
/// nothing).
pub(crate) async fn read_member_buckets(
    tx: &mut Scoped,
    tenant_id: Uuid,
    ws: Uuid,
    user: Option<Uuid>,
) -> Option<HashMap<(Uuid, Uuid), RateLimitConfig>> {
    best_effort!(tx, tenant_id, "member limits before", |sp| crate::limits::load_member_buckets(sp, Some(ws), user))
}

/// Step 4 for a member-limit write: seed every member of `ws` (only `user`,
/// when set — the same scope `before` was read with) whose budget the write
/// newly capped.
pub(crate) async fn seed_members(
    tx: &mut Scoped,
    tenant_id: Uuid,
    ws: Uuid,
    user: Option<Uuid>,
    before: &HashMap<(Uuid, Uuid), RateLimitConfig>,
) {
    best_effort!(tx, tenant_id, "member seed", |sp| async move {
        let after = crate::limits::load_member_buckets(&mut *sp, Some(ws), user).await?;
        let seeds = member_seeds(before, &after);
        if seeds.is_empty() {
            return Ok(());
        }
        let snapshot =
            SpendSnapshot::from_audit(&mut *sp, BudgetSpendOf::Members { workspace_id: ws, user_id: user }).await?;
        write_seeds(sp, tenant_id, &seed_rows(&snapshot, &seeds)).await
    });
}

/// Step 1 + 2 for a key's budget write: lock the key row and read its budget
/// as it stands (`None`: no such key). The lock is part of the write — an
/// error fails it.
pub(crate) async fn lock_key_budget(tx: &mut Scoped, key_id: Uuid) -> sqlx::Result<Option<Caps>> {
    let row: Option<(Option<f64>, Option<f64>)> =
        sqlx::query_as("SELECT daily_budget, monthly_budget FROM api_keys WHERE id = $1 FOR UPDATE")
            .bind(key_id)
            .fetch_optional(&mut *tx)
            .await?;
    Ok(row.map(|(daily, monthly)| Caps::of(daily, monthly)))
}

/// Step 4 for a key's budget write: seed the key's counter for every window
/// its new budget newly caps.
pub(crate) async fn seed_key(tx: &mut Scoped, tenant_id: Uuid, key_id: Uuid, before: Caps, after: Caps) {
    let windows = before.newly_capped(after);
    if !windows.any() {
        return;
    }
    best_effort!(tx, tenant_id, "key seed", |sp| async move {
        let snapshot = SpendSnapshot::from_audit(&mut *sp, BudgetSpendOf::Key(key_id)).await?;
        let seeds = [Seed { scope_kind: UsageScopeKind::Key, scope_id: key_id, spend_id: key_id, windows }];
        write_seeds(sp, tenant_id, &seed_rows(&snapshot, &seeds)).await
    });
}

/// Step 1 for a ceiling write: the transaction lock that orders a tenant's
/// ceiling writes. The ceiling lives in `system_settings` rows that may not
/// exist yet, so no row can be locked; the lock class is
/// `crate::leader::LOCK_ORG_CEILING`, keyed by the tenant. It is part of the
/// write — an error fails it.
pub(crate) async fn lock_ceiling(tx: &mut Scoped, tenant_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2::text))")
        .bind(crate::leader::LOCK_ORG_CEILING)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// Step 2 for a ceiling write: the ceiling as it stands, best-effort.
pub(crate) async fn read_ceiling(tx: &mut Scoped, tenant_id: Uuid) -> Option<Caps> {
    best_effort!(tx, tenant_id, "ceiling before", |sp| async move {
        let s = crate::limits::load_tenant_budget_settings(sp).await?;
        Ok::<_, sqlx::Error>(Caps { daily: s.org_daily, monthly: s.org_monthly })
    })
}

/// Step 4 for a ceiling write: seed the organisation's counter for every
/// window the ceiling newly caps, from the pool counters.
pub(crate) async fn seed_organisation(tx: &mut Scoped, tenant_id: Uuid, before: Caps) {
    best_effort!(tx, tenant_id, "organisation seed", |sp| async move {
        let s = crate::limits::load_tenant_budget_settings(&mut *sp).await?;
        let windows = before.newly_capped(Caps { daily: s.org_daily, monthly: s.org_monthly });
        if !windows.any() {
            return Ok(());
        }
        let snapshot = SpendSnapshot::organisation(&mut *sp, tenant_id).await?;
        let seeds = [Seed { scope_kind: UsageScopeKind::Tenant, scope_id: tenant_id, spend_id: tenant_id, windows }];
        write_seeds(sp, tenant_id, &seed_rows(&snapshot, &seeds)).await
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::auth::RateLimitConfig;
    use streamscope_core::usage::{DAY_MS, MONTH_MS};

    /// Both sides of "newly capped", per window: none → value seeds; value →
    /// value, value → none and none → none do not.
    #[test]
    fn only_a_window_going_from_no_cap_to_a_cap_is_seeded() {
        let none = Caps::default();
        let daily = Caps { daily: 5.0, monthly: 0.0 };
        let monthly = Caps { daily: 0.0, monthly: 50.0 };
        let both = Caps { daily: 5.0, monthly: 50.0 };
        assert_eq!(none.newly_capped(daily), NewlyCapped { daily: true, monthly: false });
        assert_eq!(none.newly_capped(both), NewlyCapped { daily: true, monthly: true });
        assert_eq!(daily.newly_capped(both), NewlyCapped { daily: false, monthly: true });
        assert_eq!(monthly.newly_capped(both), NewlyCapped { daily: true, monthly: false });
        assert!(!both.newly_capped(both).any());
        assert!(!both.newly_capped(none).any());
        assert!(!none.newly_capped(none).any());
        // A stray negative or NaN cap is no cap: it seeds once a real one comes.
        assert!(Caps { daily: f64::NAN, monthly: -1.0 }.newly_capped(both).daily);
    }

    /// The windows are exactly the ones the gateway keys its counters by, on
    /// both sides of a day and a block boundary.
    #[test]
    fn the_windows_are_the_gateways_own() {
        let block = 7 * MONTH_MS;
        for now in [block, block + 1, block + DAY_MS - 1, block + DAY_MS, block + MONTH_MS - 1] {
            let w = windows_at(now);
            let d = UsageWindowKind::Daily.window_start_ms(now);
            let m = UsageWindowKind::Monthly.window_start_ms(now);
            assert_eq!(w.daily, (at(d), at(d + DAY_MS)), "{now}");
            assert_eq!(w.monthly, (at(m), at(m + MONTH_MS)), "{now}");
            assert!(w.monthly.0 <= w.daily.0 && w.daily.1 <= w.monthly.1, "{now}");
        }
        assert_eq!(windows_at(block + MONTH_MS).monthly.0, at(block + MONTH_MS));
    }

    fn snapshot(spend: &[(Uuid, i64, i64)]) -> SpendSnapshot {
        SpendSnapshot { windows: windows_at(7 * MONTH_MS + 3 * DAY_MS), spend: spend.iter().map(|&(id, d, m)| (id, (d, m))).collect() }
    }

    /// A seed row carries the spend of exactly the windows newly capped, at
    /// the window's start; a window without spend has no row.
    #[test]
    fn a_seed_carries_only_the_newly_capped_windows_spend() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let snap = snapshot(&[(a, 1_500_000, 40_000_000)]);
        let seeds = [
            Seed { scope_kind: UsageScopeKind::Key, scope_id: a, spend_id: a, windows: NewlyCapped { daily: false, monthly: true } },
            Seed { scope_kind: UsageScopeKind::Key, scope_id: b, spend_id: b, windows: NewlyCapped { daily: true, monthly: true } },
        ];
        let rows = seed_rows(&snap, &seeds);
        assert_eq!(rows, vec![("key", a, "monthly", snap.windows.monthly.0, 40_000_000)]);
        let both = [Seed { scope_kind: UsageScopeKind::Key, scope_id: a, spend_id: a, windows: NewlyCapped { daily: true, monthly: true } }];
        assert_eq!(
            seed_rows(&snap, &both),
            vec![("key", a, "daily", snap.windows.daily.0, 1_500_000), ("key", a, "monthly", snap.windows.monthly.0, 40_000_000)]
        );
    }

    fn member(daily: f64, monthly: f64, rpm: u32) -> RateLimitConfig {
        RateLimitConfig { requests_per_minute: rpm, ..RateLimitConfig::budget_only(daily, monthly, false) }
    }

    /// Every membership whose budget went from none to a value is seeded —
    /// a new bucket, and an existing rate-only bucket gaining a budget — and
    /// none other; the counter is the membership's, the spend the user's.
    #[test]
    fn a_member_is_seeded_only_where_their_budget_appears() {
        let ws = Uuid::from_u128(10);
        let (new, rate_only, kept, lifted) = (Uuid::from_u128(11), Uuid::from_u128(12), Uuid::from_u128(13), Uuid::from_u128(14));
        let before = HashMap::from([
            ((ws, rate_only), member(0.0, 0.0, 60)),
            ((ws, kept), member(5.0, 0.0, 0)),
            ((ws, lifted), member(5.0, 0.0, 0)),
        ]);
        let after = HashMap::from([
            ((ws, new), member(0.0, 50.0, 0)),
            ((ws, rate_only), member(5.0, 0.0, 60)),
            ((ws, kept), member(5.0, 0.0, 0)),
        ]);
        let mut seeds = member_seeds(&before, &after);
        seeds.sort_by_key(|s| s.spend_id);
        let got: Vec<_> = seeds.iter().map(|s| (s.spend_id, s.scope_id, s.windows)).collect();
        use streamscope_core::auth::member_limits::member_scope_id;
        assert_eq!(
            got,
            vec![
                (new, member_scope_id(ws, new), NewlyCapped { daily: false, monthly: true }),
                (rate_only, member_scope_id(ws, rate_only), NewlyCapped { daily: true, monthly: false }),
            ]
        );
    }

    /// Whether a write can leave a member with a budget, on both sides: a
    /// rate-only write, an explicit unlimited and a fallback to a default
    /// without a budget cannot; a value, an inherited default budget and a
    /// fallback to a default with one can.
    #[test]
    fn only_a_write_that_can_leave_a_budget_reads_the_spend() {
        let none = (None, None);
        let daily = (Some(5.0), None);
        // Default PUT (no exception in play).
        assert!(!could_cap_a_member(none, None));
        assert!(!could_cap_a_member((Some(0.0), Some(0.0)), None));
        assert!(could_cap_a_member(daily, None));
        assert!(could_cap_a_member((None, Some(0.01)), None));
        // Exception PUT: its own value, else the default's.
        assert!(!could_cap_a_member(none, Some(none)));
        assert!(!could_cap_a_member(daily, Some((Some(0.0), None))), "an explicit unlimited is no budget");
        assert!(could_cap_a_member(daily, Some(none)), "an inherited default budget is a budget");
        assert!(could_cap_a_member(none, Some((None, Some(50.0)))));
        // Exception removed: the member falls back to the default.
        assert!(!could_cap_a_member(none, None));
        assert!(could_cap_a_member(daily, None));
        assert!(!sets_a_cap(Some(-1.0), Some(f64::NAN)));
    }
}
