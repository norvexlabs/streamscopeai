//! Portal — Home: the landing page's one read.
//!
//! Every figure here is cheap by construction, because every portal user loads
//! it on sign-in: the caller's own keys (a few rows), their own spend over two
//! short windows (the per-user audit index), the effective-limit stack of the
//! header workspace (the fleet counters — one probe), the MCP servers waiting
//! for their sign-in (SQL only, no upstream call) and their five latest
//! sessions (the per-user sessions index). Longer windows and per-key detail
//! stay on the Usage page.

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
use crate::limits::{LimitBucket, LimitMeter, StackViewer};

const RECENT_SESSIONS: i64 = 5;
/// At most this many expiring keys and sign-in items are listed.
const MAX_ITEMS: i64 = 5;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalHomeQuery {
    /// The workspace picked in the portal header: its limits feed the
    /// warnings, and its team block is answered to a manager. Absent = no
    /// workspace block (a caller with no membership yet).
    pub workspace_id: Option<Uuid>,
}

/// The portal Home: what needs doing, the caller's spend, their team (managers),
/// and their latest sessions.
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
    /// Budgets in the header workspace at 80 % of their cap or more, as the
    /// caller may see them (a manager sees the pool's use, a member only when
    /// the workspace shares it).
    pub limit_warnings: Vec<PortalLimitWarning>,
    /// The caller's own LLM traffic since 00:00 UTC.
    pub today: PortalSpendWindow,
    /// The caller's own LLM traffic over the last 7 days.
    pub last_7_days: PortalSpendWindow,
    /// The header workspace's pool — answered to its managers only.
    pub team: Option<PortalHomeTeam>,
    /// The caller's 5 latest sessions.
    pub recent_sessions: Vec<SessionSummary>,
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

/// Which budget window a warning or a figure is about: the UTC day, or the
/// fixed 30-day period.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetWindow {
    Daily,
    Monthly,
}

#[derive(Serialize, ToSchema)]
pub struct PortalLimitWarning {
    pub bucket: LimitBucket,
    /// The key, on a `key` warning: its name, and the prefix that names it
    /// when it has none.
    pub key_name: Option<String>,
    pub key_prefix: Option<String>,
    pub window: BudgetWindow,
    pub used: f64,
    pub cap: f64,
    /// The accounting currency `used` and `cap` are in.
    pub currency: String,
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

    // Spend: the caller's own rows (no workspace widening), the same totals
    // the Usage page sums, over two short windows.
    let own = PortalDataScope::resolve(db.conn(), &user, None).await?;
    let now = Utc::now();
    let midnight = now.date_naive().and_hms_opt(0, 0, 0).map_or(now, |t| t.and_utc());
    let fallback = super::pricing::accounting_currency(db.conn()).await;
    let window = |u: crate::audit_store::usage::PortalUsage| PortalSpendWindow {
        requests: u.requests,
        spend: super::spend_total(u.currency_count, u.currency, u.amount, fallback),
    };
    let today = crate::audit_store::usage::portal_totals(db.conn(), &own, (midnight, now))
        .await
        .map_err(internal("today"))?;
    let week = crate::audit_store::usage::portal_totals(db.conn(), &own, (now - Duration::days(7), now))
        .await
        .map_err(internal("last 7 days"))?;

    // Limits and the team block, from the one effective-limit stack.
    let mut limit_warnings = Vec::new();
    let mut team = None;
    if let Some((ws, role)) = &role {
        let viewer = StackViewer::for_member_role(role);
        let manager = viewer == StackViewer::Manager;
        let stack = crate::limits::effective_stack(db.conn(), tenant_id, *ws, user.user_id, viewer)
            .await
            .map_err(internal("limits"))?;
        for layer in &stack.layers {
            for (window, meter) in [(BudgetWindow::Daily, &layer.daily_budget), (BudgetWindow::Monthly, &layer.monthly_budget)] {
                if let (Some(cap), Some(used)) = (meter.cap, meter.used)
                    && super::analytics::budget_band(used, cap) >= 1
                {
                    limit_warnings.push(PortalLimitWarning {
                        bucket: layer.bucket,
                        key_name: layer.key_name.clone(),
                        key_prefix: layer.key_prefix.clone(),
                        window,
                        used,
                        cap,
                        currency: stack.currency.clone(),
                    });
                }
            }
        }
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
    }

    // Recent sessions: the caller's own, as the Sessions page lists them.
    let mut query = SessionListQuery::default();
    query.limit = Some(RECENT_SESSIONS);
    let recent_sessions = list_sessions_impl(db.conn(), query, &AuditScope::portal(&own))
        .await
        .map_err(|e| {
            tracing::error!("portal home sessions: {e}");
            ApiError::internal("internal error")
        })?
        .rows
        .for_member();

    Ok(Json(PortalHome {
        has_active_key,
        expiring_keys,
        mcp_sign_in,
        limit_warnings,
        today: window(today),
        last_7_days: window(week),
        team,
        recent_sessions,
    }))
}
