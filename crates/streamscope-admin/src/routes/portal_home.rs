//! Portal — Home: the landing page's one read.
//!
//! Every figure here is cheap by construction, because every portal user loads
//! it on sign-in, and each reads only the caller's own rows or a counter: their
//! own keys (a few rows), their own spend per UTC day over the last 7 (one
//! aggregate on the per-user audit index), the effective-limit stack of the
//! header workspace (the fleet counters — one probe), the MCP servers waiting
//! for their sign-in (SQL only, no upstream call), the hosts their `ssai` CLI
//! last ran on (their own CLI token rows of the last 30 days) and their five
//! latest sessions (the per-user sessions index). No tenant-wide count, no
//! other user's rows. Per-key detail is on the API keys page.

use axum::extract::Query;
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::audit::{SessionListQuery, SessionSummary};
use super::portal::PortalDataScope;
use super::portal_view::MemberView;
use super::portal_auth::PortalUser;
use super::portal_manager::confine_to_key_workspace;
use super::portal_mcp::{PortalMcpSignInNeeded, servers_needing_sign_in};
use super::{ApiError, ApiErrorCode, ApiErrorResponse, SpendTotal};
use crate::audit_store::AuditScope;
use crate::audit_store::sessions::list_sessions_impl;
use crate::db::tenant::TenantConn;
use crate::limits::{EffectiveLimitStack, LimitBucket, LimitMeter, StackViewer};

const RECENT_SESSIONS: i64 = 5;
/// At most this many expiring keys, sign-in items and out-of-date CLI hosts
/// are listed.
const MAX_ITEMS: i64 = 5;
/// The daily strip's length, today included.
const STRIP_DAYS: i64 = 7;
/// A CLI host not seen for this long is not listed.
const CLI_HOST_SEEN_DAYS: i64 = 30;
/// At most this many of the caller's most recently seen CLI hosts are
/// compared with the served version.
const CLI_HOSTS_READ: i64 = 20;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalHomeQuery {
    /// The workspace picked in the portal header: its limits are answered,
    /// and its team block to a manager. Absent = no workspace block (a caller
    /// with no membership yet).
    pub workspace_id: Option<Uuid>,
}

/// The portal Home: what needs doing, the caller's spend, their limits, their
/// team (managers), and their latest sessions.
#[derive(Serialize, ToSchema)]
pub struct PortalHome {
    /// The caller holds at least one live (unrevoked, unexpired) key.
    pub has_active_key: bool,
    /// The caller's unrevoked keys that expire within 7 days or expired in the
    /// last 7 (at most 5): those still working first, soonest first — a key
    /// about to stop is never pushed out by keys that already have. A key created to live 7 days or less
    /// (a per-run CI key) is not one.
    pub expiring_keys: Vec<PortalExpiringKey>,
    /// MCP servers the caller may use that wait for their sign-in (at most 5).
    pub mcp_sign_in: Vec<PortalMcpSignInNeeded>,
    /// How many MCP servers wait for the caller's sign-in, `mcp_sign_in`'s
    /// first five included.
    pub mcp_sign_in_total: i64,
    /// The `ssai` version this gateway serves — what `/api/v1/cli/version`
    /// advertises and `ssai update` installs.
    pub cli_version: String,
    /// The hosts whose `ssai` last reported a version older than
    /// `cli_version` (at most 5), most recently seen first. A host not seen
    /// in 30 days, one on the served version or newer, one whose version is
    /// not a dotted number, and one on an OS whose served binary does not
    /// carry `cli_version` (`ssai update` would not bring it) are not listed.
    pub cli_updates: Vec<PortalCliHost>,
    /// The caller's own LLM traffic since 00:00 UTC.
    pub today: PortalSpendWindow,
    /// The caller's own LLM traffic over the last 7 UTC days, today included:
    /// the sum of `daily`.
    pub last_7_days: PortalSpendWindow,
    /// The caller's own LLM traffic per UTC day, the 7 days ending today,
    /// oldest first — a day without traffic included, with zeros.
    pub daily: Vec<PortalSpendDay>,
    /// Every limit that applies to the caller in the header workspace, as the
    /// caller may see it (a manager sees the pool's use, a member only when
    /// the workspace shares it) — `null` when no workspace is named or
    /// nothing limits the caller there.
    pub limits: Option<EffectiveLimitStack>,
    /// The header workspace's pool — answered to its managers only.
    pub team: Option<PortalHomeTeam>,
    /// The caller's 5 latest sessions — `null` while the Sessions page is
    /// hidden for the caller (`sessions` in `hidden_pages`), which is not
    /// "no session yet".
    pub recent_sessions: Option<Vec<SessionSummary>>,
}

/// A host the caller's `ssai` CLI ran on, as it reported itself.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalCliHost {
    /// The host name the CLI reported (its first label).
    pub host: String,
    /// `linux` | `macos` | `windows`, as the CLI reported it.
    pub os: String,
    /// The version it last reported on this host.
    pub version: String,
    /// When it was last seen (to about a minute).
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalExpiringKey {
    pub id: Uuid,
    pub name: Option<String>,
    pub key_prefix: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalSpendWindow {
    pub requests: i64,
    /// `null` when the window straddles a change of the accounting currency.
    pub spend: Option<SpendTotal>,
}

/// One UTC day of the caller's own LLM traffic.
#[derive(Serialize, ToSchema)]
pub struct PortalSpendDay {
    /// 00:00 UTC of the day.
    pub day: DateTime<Utc>,
    pub requests: i64,
    /// `null` when the day straddles a change of the accounting currency.
    pub spend: Option<SpendTotal>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalHomeTeam {
    pub workspace_id: Uuid,
    pub name: String,
    pub members: i64,
    /// The pool's spend in the current UTC day and 30-day period, with its
    /// caps (`null` = no cap).
    pub daily: LimitMeter,
    pub monthly: LimitMeter,
    /// The accounting currency the pool figures are in.
    pub currency: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/home",
    tag = "Portal",
    params(PortalHomeQuery),
    responses(
        (status = 200, description = "The portal Home", body = PortalHome),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Not a member of `workspace_id`, or a key bound to another workspace", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn home(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Extension(hidden): Extension<super::portal_pages::HiddenPages>,
    Query(q): Query<PortalHomeQuery>,
) -> Result<Json<PortalHome>, ApiError> {
    let internal = |what: &'static str| {
        move |e: sqlx::Error| {
            tracing::error!("portal home {what}: {e}");
            ApiError::internal("internal error")
        }
    };
    let tenant_id = db.tenant_uuid();

    // The header workspace, when named: a member's own, never another's.
    let role = match q.workspace_id {
        Some(ws) => {
            confine_to_key_workspace(&user, ws)?;
            match crate::routes::workspaces::member_role(&mut db, ws, user.user_id).await? {
                Some(role) => Some((ws, role)),
                None => {
                    return Err(ApiError::forbidden("you are not a member of this workspace")
                        .code(ApiErrorCode::WorkspaceMembershipRequired));
                }
            }
        }
        None => None,
    };

    // Keys: the caller's own, as every portal key list confines them.
    let has_active_key: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT EXISTS (SELECT 1 FROM api_keys WHERE user_id = $1 AND {} AND ($2::uuid IS NULL OR workspace_id = $2))",
        super::keys::KEY_LIVE
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(internal("keys"))?;
    // An expiry notice, ended at most 7 days ago: a key that stopped working
    // last week is still something to renew; older ones are left alone.
    let expiring_keys: Vec<PortalExpiringKey> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT id, name, COALESCE(key_prefix, LEFT(key_hash, 8)) AS key_prefix, expires_at FROM api_keys \
          WHERE user_id = $1 AND {} AND expires_at > NOW() - INTERVAL '7 days' \
            AND ($2::uuid IS NULL OR workspace_id = $2) \
          ORDER BY expires_at <= NOW(), expires_at LIMIT $3",
        super::keys::KEY_EXPIRY_NOTICE
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .bind(MAX_ITEMS)
    .fetch_all(db.conn())
    .await
    .map_err(internal("expiring keys"))?;

    let mcp_sign_in = servers_needing_sign_in(db.conn(), &user, tenant_id, MAX_ITEMS)
        .await
        .map_err(internal("mcp sign-in"))?;
    let mcp_sign_in_total = if (mcp_sign_in.len() as i64) < MAX_ITEMS {
        mcp_sign_in.len() as i64
    } else {
        super::portal_mcp::count_servers_needing_sign_in(db.conn(), &user, tenant_id)
            .await
            .map_err(internal("mcp sign-in count"))?
    };

    // A To do hint, not the page: a failed read lists no host and Home stays up.
    let (cli_version, cli_updates) = match cli_updates(db.conn(), user.user_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("portal home: cli hosts: {e}");
            (streamscope_core::VERSION.to_string(), Vec::new())
        }
    };

    // Spend: the caller's own rows (no workspace widening), the population
    // the API keys page's per-key figures count, per UTC day over the strip.
    let own = PortalDataScope::resolve(db.conn(), &user, None).await?;
    let now = Utc::now();
    let midnight = now.date_naive().and_hms_opt(0, 0, 0).map_or(now, |t| t.and_utc());
    let strip_start = midnight - Duration::days(STRIP_DAYS - 1);
    let fallback = super::pricing::accounting_currency(db.conn()).await;
    let rows = crate::audit_store::usage::portal_daily(db.conn(), &own, (strip_start, now))
        .await
        .map_err(internal("daily"))?;
    let strip = SpendStrip::fold(&rows, strip_start, STRIP_DAYS, fallback);

    // Limits and the team block, from the one effective-limit stack.
    let mut limits = None;
    let mut team = None;
    if let Some((ws, role)) = &role {
        let viewer = StackViewer::for_member_role(role);
        let manager = viewer == StackViewer::Manager;
        let stack = crate::limits::effective_stack(db.conn(), tenant_id, *ws, user.user_id, viewer)
            .await
            .map_err(internal("limits"))?;
        if manager {
            // The stack has a pool layer only when the pool is limited, and
            // then carries its caps and spend (a manager sees it). Otherwise
            // the spend comes from the pool's counter, which always runs.
            let pool = stack.layers.iter().find(|l| l.bucket == LimitBucket::Workspace);
            let (daily_used, monthly_used) = match pool.and_then(|p| p.daily_budget.used.zip(p.monthly_budget.used)) {
                Some(used) => used,
                None => crate::limits::workspace_spend(db.conn(), tenant_id, *ws)
                    .await
                    .map_err(internal("team spend"))?,
            };
            let meter = |limit: Option<&LimitMeter>, used: f64| LimitMeter {
                cap: limit.and_then(|m| m.cap),
                used: Some(used),
                inherited: limit.is_some_and(|m| m.inherited),
            };
            // Counted as the Members & limits roster lists them: the internal
            // agent user is not a member anyone manages.
            let (name, members): (String, i64) = sqlx::query_as(
                "SELECT w.name, (SELECT COUNT(*) FROM workspace_members m JOIN users u ON u.id = m.user_id \
                                  WHERE m.workspace_id = w.id AND u.email <> $2)::bigint \
                   FROM workspaces w WHERE w.id = $1",
            )
            .bind(ws)
            .bind(crate::agent::AGENT_EMAIL)
            .fetch_one(db.conn())
            .await
            .map_err(internal("team"))?;
            team = Some(PortalHomeTeam {
                workspace_id: *ws,
                name,
                members,
                daily: meter(pool.map(|p| &p.daily_budget), daily_used),
                monthly: meter(pool.map(|p| &p.monthly_budget), monthly_used),
                currency: stack.currency.clone(),
            });
        }
        // The stack lists only the layers that limit something.
        if !stack.layers.is_empty() {
            limits = Some(stack);
        }
    }

    // Recent sessions: the caller's own, as the Sessions page lists them —
    // and none while that page is hidden for the caller: the Home is on no
    // fence (its other fields are the caller's keys, sign-ins and hosts,
    // counts, spend and limits — nothing a conversation said), so it leaves
    // the sessions out here, not only in the portal's markup.
    let recent_sessions = if hidden.hides(super::portal_pages::PortalPage::Sessions) {
        None
    } else {
        let mut query = SessionListQuery::default();
        query.limit = Some(RECENT_SESSIONS);
        let rows = list_sessions_impl(db.conn(), query, &AuditScope::portal(&own))
            .await
            .map_err(|e| {
                tracing::error!("portal home sessions: {e}");
                ApiError::internal("internal error")
            })?
            .rows;
        Some(rows.for_member())
    };

    Ok(Json(PortalHome {
        has_active_key,
        expiring_keys,
        mcp_sign_in,
        mcp_sign_in_total,
        cli_version,
        cli_updates,
        today: strip.today,
        last_7_days: strip.total,
        daily: strip.days,
        limits,
        team,
        recent_sessions,
    }))
}

/// The daily strip, today and the strip's total, from [`portal_daily`]'s rows.
///
/// [`portal_daily`]: crate::audit_store::usage::portal_daily
struct SpendStrip {
    days: Vec<PortalSpendDay>,
    today: PortalSpendWindow,
    total: PortalSpendWindow,
}

impl SpendStrip {
    /// `count` days from `start` (00:00 UTC), oldest first, a day without a
    /// row zero; the last day is today. The total is the window row's, never
    /// re-summed: its currency count is the window's, which the days' counts
    /// do not give.
    fn fold(
        rows: &[crate::audit_store::usage::PortalDayUsage],
        start: DateTime<Utc>,
        count: i64,
        fallback: streamscope_core::pricing::Currency,
    ) -> Self {
        let window = |r: Option<&crate::audit_store::usage::PortalDayUsage>| match r {
            Some(r) => PortalSpendWindow {
                requests: r.requests,
                spend: super::spend_total(r.currency_count, r.currency.clone(), r.amount, fallback),
            },
            None => PortalSpendWindow { requests: 0, spend: super::spend_total(0, None, 0.0, fallback) },
        };
        let days: Vec<PortalSpendDay> = (0..count)
            .map(|i| {
                let day = start + Duration::days(i);
                let w = window(rows.iter().find(|r| r.day == Some(day)));
                PortalSpendDay { day, requests: w.requests, spend: w.spend }
            })
            .collect();
        let today = days
            .last()
            .map_or_else(|| window(None), |d| PortalSpendWindow { requests: d.requests, spend: d.spend });
        let total = window(rows.iter().find(|r| r.day.is_none()));
        SpendStrip { days, today, total }
    }
}

/// The served `ssai` version, and the caller's hosts whose CLI last reported
/// an older one.
///
/// Cost: the caller's own CLI token rows issued in the last 30 days plus one
/// access-token lifetime, on `idx_oauth_issued_tokens_user (tenant_id,
/// user_id, issued_at DESC)` — one access/refresh pair per hour a CLI was in
/// use; no other user's rows.
async fn cli_updates(
    conn: &mut crate::db::tenant::Scoped,
    user_id: Uuid,
) -> sqlx::Result<(String, Vec<PortalCliHost>)> {
    let served = streamscope_core::VERSION;
    // A host's latest report is its newest-seen row, whichever login or
    // rotation of the token it came from. A row seen in the window was issued
    // at most one access lifetime before it, which bounds the index range.
    let hosts: Vec<PortalCliHost> = sqlx::query_as(
        "SELECT host, os, version, last_seen_at FROM ( \
           SELECT DISTINCT ON (cli_host, cli_os) cli_host AS host, cli_os AS os, cli_version AS version, \
                  last_used_at AS last_seen_at \
             FROM oauth_issued_tokens \
            WHERE user_id = $1 AND surface = 'cli' \
              AND issued_at > NOW() - make_interval(days => $2::int) - make_interval(secs => $3::double precision) \
              AND last_used_at > NOW() - make_interval(days => $2::int) \
              AND cli_host IS NOT NULL AND cli_os IS NOT NULL AND cli_version IS NOT NULL \
            ORDER BY cli_host, cli_os, last_used_at DESC \
         ) h ORDER BY last_seen_at DESC, host LIMIT $4",
    )
    .bind(user_id)
    .bind(CLI_HOST_SEEN_DAYS as i32)
    .bind(super::oauth_common::ACCESS_TOKEN_TTL_SECS as f64)
    .bind(CLI_HOSTS_READ)
    .fetch_all(&mut *conn)
    .await?;
    // A host is called out of date only where `ssai update` would bring the
    // served version: the gateway's binary for that OS carries it.
    let mut outdated = Vec::new();
    for h in hosts {
        if outdated.len() == MAX_ITEMS as usize {
            break;
        }
        if version_is_older(&h.version, served) == Some(true)
            && super::cli_dist::serves_current_for_os(&h.os).await
        {
            outdated.push(h);
        }
    }
    Ok((served.to_string(), outdated))
}

/// Whether dotted-number version `a` is older than `b`, field by field as
/// numbers (CalVer `YYYY.M.MICRO`: `2026.11.9` < `2026.11.30`), a missing
/// trailing field older than a present one. `None` when either is not a
/// dotted number (a pre-release or a build suffix): such a version is never
/// called out of date.
fn version_is_older(a: &str, b: &str) -> Option<bool> {
    fn fields(v: &str) -> Option<Vec<u64>> {
        v.split('.')
            .map(|f| if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) { f.parse::<u64>().ok() } else { None })
            .collect()
    }
    Some(fields(a)? < fields(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_store::usage::PortalDayUsage;
    use streamscope_core::pricing::Currency;

    #[test]
    fn calver_compares_each_field_as_a_number() {
        assert_eq!(version_is_older("2026.11.9", "2026.11.30"), Some(true));
        assert_eq!(version_is_older("2026.11.30", "2026.11.9"), Some(false));
        assert_eq!(version_is_older("2026.9.40", "2026.11.1"), Some(true));
        assert_eq!(version_is_older("2025.12.400", "2026.1.1"), Some(true));
        // Equal is not older, either way round.
        assert_eq!(version_is_older("2026.11.29", "2026.11.29"), Some(false));
        // One step on each side of the boundary.
        assert_eq!(version_is_older("2026.11.28", "2026.11.29"), Some(true));
        assert_eq!(version_is_older("2026.11.30", "2026.11.29"), Some(false));
        // A missing trailing field is older than a present one.
        assert_eq!(version_is_older("2026.11", "2026.11.0"), Some(true));
    }

    #[test]
    fn a_version_that_is_not_a_dotted_number_is_never_out_of_date() {
        for v in ["", "2026.11.x", "2026.11.29-dev", "v2026.11.29", "2026..29", "+1.2", "2026.11.+1"] {
            assert_eq!(version_is_older(v, "2026.11.29"), None, "{v:?}");
            assert_eq!(version_is_older("2026.11.29", v), None, "{v:?}");
        }
    }

    fn row(day: Option<DateTime<Utc>>, requests: i64, amount: f64, currencies: &[&str]) -> PortalDayUsage {
        PortalDayUsage {
            day,
            requests,
            amount,
            currency_count: currencies.len() as i64,
            currency: currencies.iter().min().map(|c| c.to_string()),
        }
    }

    #[test]
    fn the_strip_has_every_day_oldest_first_and_today_last() {
        let start = DateTime::parse_from_rfc3339("2026-11-05T00:00:00Z").expect("a date").to_utc();
        let rows = [
            row(Some(start + Duration::days(1)), 2, 1.5, &["USD"]),
            row(Some(start + Duration::days(6)), 3, 0.5, &["USD"]),
            row(None, 5, 2.0, &["USD"]),
        ];
        let strip = SpendStrip::fold(&rows, start, 7, Currency::USD);
        let days: Vec<(DateTime<Utc>, i64)> = strip.days.iter().map(|d| (d.day, d.requests)).collect();
        assert_eq!(days, (0..7).map(|i| (start + Duration::days(i), [0, 2, 0, 0, 0, 0, 3][i as usize])).collect::<Vec<_>>());
        // A day without traffic is a priced zero, not "mixed".
        assert_eq!(strip.days[0].spend.as_ref().map(|s| s.amount), Some(0.0));
        assert_eq!(strip.today.requests, 3);
        assert_eq!(strip.today.spend.as_ref().map(|s| s.amount), Some(0.5));
        assert_eq!(strip.total.requests, 5);
        assert_eq!(strip.total.spend.as_ref().map(|s| s.amount), Some(2.0));
    }

    #[test]
    fn the_total_states_mixed_currencies_even_when_no_day_does() {
        let start = DateTime::parse_from_rfc3339("2026-11-05T00:00:00Z").expect("a date").to_utc();
        let rows = [
            row(Some(start), 1, 1.0, &["USD"]),
            row(Some(start + Duration::days(1)), 1, 1.0, &["EUR"]),
            row(None, 2, 2.0, &["EUR", "USD"]),
        ];
        let strip = SpendStrip::fold(&rows, start, 7, Currency::USD);
        assert!(strip.days[0].spend.is_some() && strip.days[1].spend.is_some());
        assert!(strip.total.spend.is_none(), "the week spans two currencies: no single figure");
        // Today had no traffic: zero in the fallback currency.
        assert_eq!(strip.today.requests, 0);
        assert_eq!(strip.today.spend.as_ref().map(|s| s.amount), Some(0.0));
    }

    #[test]
    fn no_rows_is_a_week_of_zeros() {
        let start = Utc::now();
        let strip = SpendStrip::fold(&[], start, 7, Currency::USD);
        assert_eq!(strip.days.len(), 7);
        assert!(strip.days.iter().all(|d| d.requests == 0));
        assert_eq!(strip.total.requests, 0);
        assert_eq!(strip.total.spend.as_ref().map(|s| s.amount), Some(0.0));
    }
}
