//! The limits that apply inside a workspace, read once and resolved the same
//! way everywhere: the workspace POOL (shared by every member), the DEFAULT
//! member limit, and the per-member EXCEPTIONS.
//!
//! Every admin reader goes through here — the key bake, the config snapshot
//! the spec-OAuth path reads, the budget evaluation behind notifications and
//! the attention tile, the effective-limit endpoints — so what is enforced,
//! what is reported and what is shown come from one reading of the same rows.

use std::collections::HashMap;

use streamscope_core::auth::member_limits::MemberLimits;
use streamscope_core::auth::RateLimitConfig;
use uuid::Uuid;
use crate::db::tenant::Scoped;

/// A stored integer limit as a member-limit field (negative values are refused
/// at write; clamped here so a stray one reads as "unlimited", never wraps).
fn rate(v: Option<i32>) -> Option<u32> {
    v.map(|n| n.max(0) as u32)
}

fn budget(v: Option<f64>) -> Option<f64> {
    v.map(|n| n.max(0.0))
}

/// The tenant's DEFAULT workspace budget — what a workspace with no budget of
/// its own is held to (`0` = none). Not the organisation ceiling, which caps
/// the tenant as a whole.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TenantBudgetDefault {
    pub daily: f64,
    pub monthly: f64,
}

pub async fn load_tenant_budget_default(conn: &mut Scoped) -> Result<TenantBudgetDefault, sqlx::Error> {
    Ok(load_tenant_budget_settings(conn).await?.default)
}

/// A tenant's budget settings — the organisation ceiling (`0` = none) and the
/// default workspace budget — in one read. Every reader of these keys goes
/// through here, so a key is spelled once.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TenantBudgetSettings {
    pub org_daily: f64,
    pub org_monthly: f64,
    pub org_alert_only: bool,
    pub default: TenantBudgetDefault,
}

pub async fn load_tenant_budget_settings(conn: &mut Scoped) -> Result<TenantBudgetSettings, sqlx::Error> {
    let s = read_settings(
        &mut *conn,
        &["tenant_daily_budget", "tenant_monthly_budget", "tenant_budget_mode", "default_daily_budget", "default_monthly_budget"],
    )
    .await?;
    let num = |k: &str| s.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0).max(0.0);
    Ok(TenantBudgetSettings {
        org_daily: num("tenant_daily_budget"),
        org_monthly: num("tenant_monthly_budget"),
        org_alert_only: s.get("tenant_budget_mode").and_then(|v| v.as_str()) == Some("alert_only"),
        default: TenantBudgetDefault { daily: num("default_daily_budget"), monthly: num("default_monthly_budget") },
    })
}

/// Several `system_settings` values of this tenant in one read.
async fn read_settings(
    conn: &mut Scoped,
    keys: &[&'static str],
) -> Result<HashMap<String, serde_json::Value>, sqlx::Error> {
    let rows: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT key, value FROM system_settings WHERE key = ANY($1)")
            .bind(keys)
            .fetch_all(&mut *conn)
            .await?;
    Ok(rows.into_iter().collect())
}

/// A workspace's pool as stored in `workspace_rate_limits` (pool columns only).
#[derive(Debug, Clone, Default, PartialEq, sqlx::FromRow)]
pub struct PoolRow {
    pub requests_per_minute: Option<i32>,
    pub tokens_per_minute: Option<i32>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    pub budget_mode: String,
}

/// The pool that applies to a workspace.
///
/// A rate left unset is unlimited — there is no tenant default rate. A budget
/// left unset inherits the tenant's default budget, and that holds whether or
/// not the workspace has a row at all: a workspace that never saved its limits
/// is held to the default exactly like one that saved them blank. `0` is
/// explicitly unlimited.
pub fn resolve_pool(row: Option<&PoolRow>, default: TenantBudgetDefault) -> RateLimitConfig {
    let r = |v: Option<i32>| v.map(|n| n.max(0) as u32).unwrap_or(0);
    RateLimitConfig {
        requests_per_minute: row.map_or(0, |p| r(p.requests_per_minute)),
        tokens_per_minute: row.map_or(0, |p| r(p.tokens_per_minute)),
        daily_budget: row.and_then(|p| p.daily_budget).unwrap_or(default.daily).max(0.0),
        monthly_budget: row.and_then(|p| p.monthly_budget).unwrap_or(default.monthly).max(0.0),
        budget_alert_only: row.is_some_and(|p| p.budget_mode == "alert_only"),
        exempt: false,
    }
}

fn is_unlimited(c: &RateLimitConfig) -> bool {
    c.requests_per_minute == 0 && c.tokens_per_minute == 0 && c.daily_budget <= 0.0 && c.monthly_budget <= 0.0
}

/// Every workspace's effective pool, keyed by workspace id. A workspace whose
/// pool resolves to unlimited on every metric is absent — the readers treat a
/// missing entry as unlimited.
pub async fn load_pools(conn: &mut Scoped) -> Result<HashMap<Uuid, RateLimitConfig>, sqlx::Error> {
    let default = load_tenant_budget_default(&mut *conn).await?;
    load_pools_with_default(conn, default).await
}

/// [`load_pools`] for a caller that has already read the tenant default.
pub async fn load_pools_with_default(
    conn: &mut Scoped,
    default: TenantBudgetDefault,
) -> Result<HashMap<Uuid, RateLimitConfig>, sqlx::Error> {
    type Row = (Uuid, Option<i32>, Option<i32>, Option<f64>, Option<f64>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT w.id, r.requests_per_minute, r.tokens_per_minute, r.daily_budget, r.monthly_budget, r.budget_mode \
           FROM workspaces w \
           LEFT JOIN workspace_rate_limits r ON r.workspace_id = w.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(ws, rpm, tpm, daily, monthly, mode)| {
            let row = mode.map(|budget_mode| PoolRow {
                requests_per_minute: rpm,
                tokens_per_minute: tpm,
                daily_budget: daily,
                monthly_budget: monthly,
                budget_mode,
            });
            let pool = resolve_pool(row.as_ref(), default);
            (!is_unlimited(&pool)).then_some((ws, pool))
        })
        .collect())
}

/// Every workspace's DEFAULT member limit, keyed by workspace id. A workspace
/// with no default on any metric is absent.
///
/// The Agent and Inline-AI workspaces never carry one: each runs the whole
/// organisation's automated traffic through ONE service member, so a per-member
/// default there would throttle every analysis or every intercepted call at
/// once. Writes refuse it; this read ignores a stray one as well.
pub async fn load_defaults(conn: &mut Scoped) -> Result<HashMap<Uuid, MemberLimits>, sqlx::Error> {
    load_defaults_where(conn, None).await
}

/// [`load_defaults`], narrowed to one workspace when `workspace` is set.
async fn load_defaults_where(
    conn: &mut Scoped,
    workspace: Option<Uuid>,
) -> Result<HashMap<Uuid, MemberLimits>, sqlx::Error> {
    type Row = (Uuid, Option<i32>, Option<i32>, Option<f64>, Option<f64>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r.workspace_id, r.member_requests_per_minute, r.member_tokens_per_minute, \
                r.member_daily_budget, r.member_monthly_budget, r.member_budget_mode \
           FROM workspace_rate_limits r \
           JOIN workspaces w ON w.id = r.workspace_id \
          WHERE w.role NOT IN ('agent', 'inline') \
            AND ($1::uuid IS NULL OR r.workspace_id = $1) \
            AND (r.member_requests_per_minute IS NOT NULL OR r.member_tokens_per_minute IS NOT NULL \
                 OR r.member_daily_budget IS NOT NULL OR r.member_monthly_budget IS NOT NULL)",
    )
    .bind(workspace)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ws, rpm, tpm, daily, monthly, mode)| {
            (
                ws,
                MemberLimits {
                    requests_per_minute: rate(rpm),
                    tokens_per_minute: rate(tpm),
                    daily_budget: budget(daily),
                    monthly_budget: budget(monthly),
                    budget_alert_only: mode.as_deref() == Some("alert_only"),
                },
            )
        })
        .collect())
}

/// Every member EXCEPTION, keyed by `(workspace_id, user_id)`. A NULL column
/// inherits the workspace default for that metric.
pub async fn load_exceptions(
    conn: &mut Scoped,
) -> Result<HashMap<(Uuid, Uuid), MemberLimits>, sqlx::Error> {
    load_exceptions_where(conn, None, None).await
}

/// [`load_exceptions`], narrowed to one workspace and/or one user.
async fn load_exceptions_where(
    conn: &mut Scoped,
    workspace: Option<Uuid>,
    user: Option<Uuid>,
) -> Result<HashMap<(Uuid, Uuid), MemberLimits>, sqlx::Error> {
    type Row = (Uuid, Uuid, Option<i32>, Option<i32>, Option<f64>, Option<f64>, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT workspace_id, user_id, requests_per_minute, tokens_per_minute, \
                daily_budget, monthly_budget, budget_mode \
           FROM workspace_user_rate_limit_overrides \
          WHERE ($1::uuid IS NULL OR workspace_id = $1) AND ($2::uuid IS NULL OR user_id = $2)",
    )
    .bind(workspace)
    .bind(user)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ws, uid, rpm, tpm, daily, monthly, mode)| {
            (
                (ws, uid),
                MemberLimits {
                    requests_per_minute: rate(rpm),
                    tokens_per_minute: rate(tpm),
                    daily_budget: budget(daily),
                    monthly_budget: budget(monthly),
                    budget_alert_only: mode == "alert_only",
                },
            )
        })
        .collect())
}

/// The resolved member bucket of every membership something limits — each
/// member of a workspace with a default, plus every member with an exception.
/// Keyed by `(workspace_id, user_id)`; `workspace_filter` narrows to one
/// workspace. Only memberships that still exist are returned, so a stale
/// exception row never reports a limit for someone who left.
pub async fn load_member_buckets(
    conn: &mut Scoped,
    workspace_filter: Option<Uuid>,
) -> Result<HashMap<(Uuid, Uuid), RateLimitConfig>, sqlx::Error> {
    let defaults = load_defaults_where(&mut *conn, workspace_filter).await?;
    let exceptions = load_exceptions_where(&mut *conn, workspace_filter, None).await?;
    let limited_workspaces: Vec<Uuid> = defaults
        .keys()
        .copied()
        .chain(exceptions.keys().map(|(ws, _)| *ws))
        .filter(|ws| workspace_filter.is_none_or(|f| f == *ws))
        .collect();
    if limited_workspaces.is_empty() {
        return Ok(HashMap::new());
    }
    let members: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT workspace_id, user_id FROM workspace_members WHERE workspace_id = ANY($1)",
    )
    .bind(&limited_workspaces)
    .fetch_all(&mut *conn)
    .await?;
    Ok(members
        .into_iter()
        .filter_map(|(ws, uid)| {
            streamscope_core::auth::member_limits::resolve_member_limit(
                defaults.get(&ws),
                exceptions.get(&(ws, uid)),
            )
            .map(|bucket| ((ws, uid), bucket))
        })
        .collect())
}

/// Which bucket a limit belongs to — the same type a refusal names, so the
/// stack and a 429's `bucket` can never spell a bucket differently.
pub use streamscope_core::middleware::rate_limit::LimitBucket;

/// One metric of one bucket: its cap (`None` = no cap) and the fleet-estimate
/// use in the current window.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct LimitMeter {
    pub cap: Option<f64>,
    /// Use in the current window; null where the viewer may not see it —
    /// another person's spend (the viewer rules are `StackViewer`'s).
    pub used: Option<f64>,
    /// The cap is not set on this scope but taken from its default: the
    /// tenant default budget on a `workspace` layer, the workspace's default
    /// member limit on a `member` layer. Never true without a cap.
    pub inherited: bool,
}

/// One bucket of the effective-limit stack.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct LimitLayer {
    pub bucket: LimitBucket,
    /// The key this layer is — set on a `key` layer only, with its name and
    /// its prefix (what names an unnamed key).
    pub key_id: Option<Uuid>,
    pub key_name: Option<String>,
    pub key_prefix: Option<String>,
    pub requests_per_minute: LimitMeter,
    pub tokens_per_minute: LimitMeter,
    pub daily_budget: LimitMeter,
    pub monthly_budget: LimitMeter,
    /// `enforce` | `alert_only` — how this layer's budgets act at the cap.
    pub budget_mode: String,
    /// Where this layer's limits come from: `own` (set on this scope),
    /// `tenant_default` (a workspace whose every cap is the tenant default
    /// budget), `member_default` (the workspace's default member limit),
    /// `exception` (the member's own exception, replacing the default). A
    /// layer mixing its own caps with its default's is `own` / `exception`,
    /// and each metric's `inherited` says which caps are the default's.
    pub source: String,
    /// This is the layer that will stop the member first (at most one layer
    /// of a stack — two key layers share a bucket, so the bucket alone cannot
    /// say which).
    pub binding: bool,
}

/// What actually limits one member inside one workspace: every bucket that
/// applies, widest first, with the one closest to its cap named.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct EffectiveLimitStack {
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub layers: Vec<LimitLayer>,
    /// The layer with the least headroom (highest use/cap across its metrics),
    /// or `None` when nothing caps the member.
    pub binding: Option<LimitBucket>,
    /// The tenant's accounting currency the budgets are expressed in.
    pub currency: String,
}

fn meter(cap: f64, used: f64, inherited: bool) -> LimitMeter {
    let cap = (cap > 0.0).then_some(cap);
    LimitMeter { inherited: inherited && cap.is_some(), cap, used: Some(used) }
}

/// Which of `[rpm, tpm, daily, monthly]` a workspace pool takes from the
/// tenant default: a budget its row leaves unset (or that has no row). There
/// is no tenant default rate.
fn pool_inherits(row: Option<&PoolRow>) -> [bool; 4] {
    [
        false,
        false,
        row.is_none_or(|r| r.daily_budget.is_none()),
        row.is_none_or(|r| r.monthly_budget.is_none()),
    ]
}

/// Which of `[rpm, tpm, daily, monthly]` a member bucket takes from the
/// workspace default: every metric without an exception, and each metric the
/// exception leaves unset with one.
fn member_inherits(exception: Option<&MemberLimits>) -> [bool; 4] {
    exception.map_or([true; 4], |e| {
        [
            e.requests_per_minute.is_none(),
            e.tokens_per_minute.is_none(),
            e.daily_budget.is_none(),
            e.monthly_budget.is_none(),
        ]
    })
}

impl LimitLayer {
    fn from_config(
        bucket: LimitBucket,
        c: &RateLimitConfig,
        used: [f64; 4],
        inherited: [bool; 4],
        source: &str,
    ) -> Self {
        Self {
            bucket,
            key_id: None,
            key_name: None,
            key_prefix: None,
            requests_per_minute: meter(c.requests_per_minute as f64, used[0], inherited[0]),
            tokens_per_minute: meter(c.tokens_per_minute as f64, used[1], inherited[1]),
            daily_budget: meter(c.daily_budget, used[2], inherited[2]),
            monthly_budget: meter(c.monthly_budget, used[3], inherited[3]),
            budget_mode: if c.budget_alert_only { "alert_only" } else { "enforce" }.to_string(),
            source: source.to_string(),
            binding: false,
        }
    }

    fn meters(&self) -> [&LimitMeter; 4] {
        [&self.requests_per_minute, &self.tokens_per_minute, &self.daily_budget, &self.monthly_budget]
    }

    /// Whether every capped metric of this layer comes from its default.
    fn all_inherited(&self) -> bool {
        self.meters().into_iter().all(|m| m.cap.is_none() || m.inherited)
    }

    fn meters_mut(&mut self) -> [&mut LimitMeter; 4] {
        [&mut self.requests_per_minute, &mut self.tokens_per_minute, &mut self.daily_budget, &mut self.monthly_budget]
    }

    fn set_use(&mut self, used: [f64; 4]) {
        for (m, u) in self.meters_mut().into_iter().zip(used) {
            m.used = Some(u);
        }
    }

    /// Highest use/cap across the metrics that have a cap.
    fn pressure(&self) -> Option<f64> {
        self.meters()
            .into_iter()
            .filter_map(|m| m.cap.zip(m.used).map(|(c, u)| u / c))
            .fold(None, |acc, r| Some(acc.map_or(r, |a: f64| a.max(r))))
    }
}

/// Who reads an effective-limit stack, which decides whose USE it may show.
/// Caps are shown to everyone the stack is served to — they say what limits
/// the member — but a layer's use is other people's spend unless it is the
/// member's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackViewer {
    /// A tenant administrator: every layer's use.
    Admin,
    /// A workspace manager (or a portal `ak-` confined to the workspace): the
    /// pool's, the member's and their keys' use — never the organisation's,
    /// which is spend in workspaces they do not manage.
    Manager,
    /// The member: their own and their keys' use; the pool's only when the
    /// workspace shares usage among its members (`member_visibility =
    /// 'members'`); never the organisation's.
    Member,
}

impl StackViewer {
    /// A portal member looking at their own stack, by their LIVE role in the
    /// workspace: a manager sees the pool's use as on their team page, any
    /// other role is a member. Every portal view of one's own limits reads
    /// this, so two pages never disagree about the same pool.
    pub(crate) fn for_member_role(role: &str) -> Self {
        if role == "manager" { StackViewer::Manager } else { StackViewer::Member }
    }

    fn sees_use_of(self, bucket: LimitBucket, pool_shared: bool) -> bool {
        match (self, bucket) {
            (StackViewer::Admin, _) => true,
            (_, LimitBucket::Member | LimitBucket::Key) => true,
            (_, LimitBucket::Organisation) => false,
            (StackViewer::Manager, LimitBucket::Workspace) => true,
            (StackViewer::Member, LimitBucket::Workspace) => pool_shared,
        }
    }
}

/// The layer closest to its cap — the one that will stop the member first —
/// or `None` while nothing has been used (every layer is equally far from its
/// cap, so naming one would be a guess). On a tie the WIDEST layer is named:
/// it is the one the member shares with the most people.
fn binding_layer(layers: &[LimitLayer]) -> Option<usize> {
    let mut best: Option<(usize, f64)> = None;
    for (i, l) in layers.iter().enumerate() {
        if let Some(p) = l.pressure().filter(|p| *p > 0.0)
            && best.is_none_or(|(_, b)| p > b)
        {
            best = Some((i, p));
        }
    }
    best.map(|(i, _)| i)
}

/// Current-window use of each counter scope, `[rpm, tpm, daily, monthly]`
/// per `(scope_kind, scope_id)`, the budgets converted from millionths to
/// whole units — one read for every layer of a stack.
async fn scopes_use(
    conn: &mut Scoped,
    tenant_id: Uuid,
    scopes: &[(&'static str, Uuid)],
) -> Result<HashMap<(String, Uuid), [f64; 4]>, sqlx::Error> {
    use streamscope_core::usage::UsageWindowKind as W;
    let now = streamscope_core::usage::now_ms();
    let at = |w: W| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(w.window_start_ms(now) as i64);
    let kinds: Vec<&str> = scopes.iter().map(|s| s.0).collect();
    let ids: Vec<Uuid> = scopes.iter().map(|s| s.1).collect();
    let rows: Vec<(String, Uuid, String, String, i64)> = sqlx::query_as(
        "SELECT scope_kind, scope_id, metric, window_kind, total FROM usage_counters \
          WHERE tenant_id = $1 \
            AND (scope_kind, scope_id) IN (SELECT * FROM unnest($2::text[], $3::uuid[])) \
            AND ((window_kind = 'minute' AND window_start = $4) \
              OR (window_kind = 'daily' AND window_start = $5) \
              OR (window_kind = 'monthly' AND window_start = $6))",
    )
    .bind(tenant_id)
    .bind(&kinds)
    .bind(&ids)
    .bind(at(W::Minute))
    .bind(at(W::Daily))
    .bind(at(W::Monthly))
    .fetch_all(&mut *conn)
    .await?;
    let mut used: HashMap<(String, Uuid), [f64; 4]> = HashMap::new();
    for (kind, id, metric, window, total) in rows {
        if let Some((slot, value)) = use_slot(&metric, &window, total) {
            used.entry((kind, id)).or_default()[slot] = value;
        }
    }
    Ok(used)
}

/// The workspace pool's spend in the current UTC day and 30-day period, from
/// the workspace counter — accrued for every priced request whether or not the
/// pool has a budget, so it answers where the effective stack has no pool layer.
pub(crate) async fn workspace_spend(
    conn: &mut Scoped,
    tenant_id: Uuid,
    workspace_id: Uuid,
) -> Result<(f64, f64), sqlx::Error> {
    let used = scopes_use(conn, tenant_id, &[("workspace", workspace_id)]).await?;
    let [_, _, daily, monthly] = used.get(&("workspace".to_string(), workspace_id)).copied().unwrap_or_default();
    Ok((daily, monthly))
}

/// Where a counter row lands in `[rpm, tpm, daily, monthly]`, and its value
/// there — budgets converted from millionths to whole units. `None` for a row
/// no meter shows.
fn use_slot(metric: &str, window: &str, total: i64) -> Option<(usize, f64)> {
    match (metric, window) {
        ("rpm", "minute") => Some((0, total as f64)),
        ("tpm", "minute") => Some((1, total as f64)),
        ("budget_micros", "daily") => Some((2, total as f64 / 1_000_000.0)),
        ("budget_micros", "monthly") => Some((3, total as f64 / 1_000_000.0)),
        _ => None,
    }
}

/// Build the effective-limit stack for `user_id` in `workspace_id`, on a
/// tenant-scoped connection, as `viewer` may see it. The same resolvers the
/// key bake uses, so this is exactly what the gateway enforces; the binding
/// layer is named from every layer's use before any is hidden (a refusal
/// already names its bucket).
pub async fn effective_stack(
    conn: &mut Scoped,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    viewer: StackViewer,
) -> Result<EffectiveLimitStack, sqlx::Error> {
    // Each layer beside the counter scope its use is read from.
    let mut layers: Vec<(LimitLayer, (&'static str, Uuid))> = Vec::new();

    let (counts_toward_tenant, pool_shared): (bool, bool) = sqlx::query_as(
        "SELECT counts_toward_tenant_budget, member_visibility = 'members' FROM workspaces WHERE id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut *conn)
    .await?
    .unwrap_or((true, false));
    let settings = load_tenant_budget_settings(&mut *conn).await?;
    if counts_toward_tenant && (settings.org_daily > 0.0 || settings.org_monthly > 0.0) {
        let c = RateLimitConfig::budget_only(settings.org_daily, settings.org_monthly, settings.org_alert_only);
        let layer = LimitLayer::from_config(LimitBucket::Organisation, &c, [0.0; 4], [false; 4], "own");
        layers.push((layer, ("tenant", tenant_id)));
    }

    let default = settings.default;
    let row: Option<PoolRow> = sqlx::query_as(
        "SELECT requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode \
           FROM workspace_rate_limits WHERE workspace_id = $1",
    )
    .bind(workspace_id)
    .fetch_optional(&mut *conn)
    .await?;
    let pool = resolve_pool(row.as_ref(), default);
    if !is_unlimited(&pool) {
        let mut layer = LimitLayer::from_config(LimitBucket::Workspace, &pool, [0.0; 4], pool_inherits(row.as_ref()), "own");
        if layer.all_inherited() {
            layer.source = "tenant_default".to_string();
        }
        layers.push((layer, ("workspace", workspace_id)));
    }

    let defaults = load_defaults_where(&mut *conn, Some(workspace_id)).await?;
    let exceptions = load_exceptions_where(&mut *conn, Some(workspace_id), Some(user_id)).await?;
    let exception = exceptions.get(&(workspace_id, user_id));
    if let Some(bucket) =
        streamscope_core::auth::member_limits::resolve_member_limit(defaults.get(&workspace_id), exception)
    {
        let layer = LimitLayer::from_config(
            LimitBucket::Member,
            &bucket,
            [0.0; 4],
            member_inherits(exception),
            if exception.is_some() { "exception" } else { "member_default" },
        );
        let member = streamscope_core::auth::member_limits::member_scope_id(workspace_id, user_id);
        layers.push((layer, ("user", member)));
    }

    type KeyRow = (Uuid, Option<String>, String, Option<f64>, Option<f64>, String);
    // Only a key that still authenticates can be stopped by its budget: an
    // expired or revoked one is no limit on anything.
    let keys: Vec<KeyRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT id, name, COALESCE(key_prefix, LEFT(key_hash, 8)), daily_budget, monthly_budget, budget_mode FROM api_keys \
          WHERE workspace_id = $1 AND user_id = $2 AND {} \
            AND (daily_budget > 0 OR monthly_budget > 0) \
          ORDER BY created_at",
        crate::routes::keys::KEY_LIVE
    )))
    .bind(workspace_id)
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?;
    for (key_id, name, prefix, daily, monthly, mode) in keys {
        let c = RateLimitConfig::budget_only(daily.unwrap_or(0.0), monthly.unwrap_or(0.0), mode == "alert_only");
        let mut layer = LimitLayer::from_config(LimitBucket::Key, &c, [0.0; 4], [false; 4], "own");
        layer.key_id = Some(key_id);
        layer.key_name = name;
        layer.key_prefix = Some(prefix);
        layers.push((layer, ("key", key_id)));
    }

    let scopes: Vec<(&'static str, Uuid)> = layers.iter().map(|(_, scope)| *scope).collect();
    let used = scopes_use(&mut *conn, tenant_id, &scopes).await?;
    let mut layers: Vec<LimitLayer> = layers
        .into_iter()
        .map(|(mut layer, (kind, id))| {
            layer.set_use(used.get(&(kind.to_string(), id)).copied().unwrap_or_default());
            layer
        })
        .collect();

    let binding_at = binding_layer(&layers);
    if let Some(i) = binding_at {
        layers[i].binding = true;
    }
    let binding = binding_at.map(|i| layers[i].bucket);
    for layer in &mut layers {
        if !viewer.sees_use_of(layer.bucket, pool_shared) {
            for m in layer.meters_mut() {
                m.used = None;
            }
        }
    }
    let currency = crate::routes::pricing::accounting_currency(&mut *conn).await.to_string();
    Ok(EffectiveLimitStack { workspace_id, user_id, layers, binding, currency })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: TenantBudgetDefault = TenantBudgetDefault { daily: 10.0, monthly: 100.0 };

    /// A workspace that never saved its limits is held to the tenant default
    /// budget exactly like one that saved them blank.
    #[test]
    fn a_workspace_without_a_row_inherits_the_default_budget() {
        let none = resolve_pool(None, DEFAULT);
        let blank = resolve_pool(Some(&PoolRow { budget_mode: "enforce".into(), ..Default::default() }), DEFAULT);
        assert_eq!((none.daily_budget, none.monthly_budget), (10.0, 100.0));
        assert_eq!((blank.daily_budget, blank.monthly_budget), (10.0, 100.0));
        // No tenant default rate: an unset rate is unlimited either way.
        assert_eq!((none.requests_per_minute, none.tokens_per_minute), (0, 0));
    }

    #[test]
    fn an_explicit_zero_is_unlimited_and_a_value_wins() {
        let row = PoolRow { daily_budget: Some(0.0), monthly_budget: Some(40.0), budget_mode: "alert_only".into(), ..Default::default() };
        let pool = resolve_pool(Some(&row), DEFAULT);
        assert_eq!((pool.daily_budget, pool.monthly_budget), (0.0, 40.0));
        assert!(pool.budget_alert_only);
    }

    fn layer(bucket: LimitBucket, used: f64, cap: f64) -> LimitLayer {
        let c = RateLimitConfig::budget_only(cap, 0.0, false);
        LimitLayer::from_config(bucket, &c, [0.0, 0.0, used, 0.0], [false; 4], "own")
    }

    /// Each metric names its own provenance: a pool that sets its daily
    /// budget but not its monthly one shows only the monthly as the tenant
    /// default's, and an exception that raises the rate keeps the default's
    /// budget marked as the default's.
    #[test]
    fn provenance_is_per_metric() {
        let row = PoolRow { requests_per_minute: Some(60), daily_budget: Some(5.0), budget_mode: "enforce".into(), ..Default::default() };
        let pool = resolve_pool(Some(&row), DEFAULT);
        let l = LimitLayer::from_config(LimitBucket::Workspace, &pool, [0.0; 4], pool_inherits(Some(&row)), "own");
        let flags = |l: &LimitLayer| {
            [&l.requests_per_minute, &l.tokens_per_minute, &l.daily_budget, &l.monthly_budget].map(|m| m.inherited)
        };
        assert_eq!(flags(&l), [false, false, false, true]);
        assert!(!l.all_inherited());
        assert_eq!(pool_inherits(None), [false, false, true, true]);
        let none = resolve_pool(None, DEFAULT);
        assert!(LimitLayer::from_config(LimitBucket::Workspace, &none, [0.0; 4], pool_inherits(None), "own").all_inherited());

        use streamscope_core::auth::member_limits::resolve_member_limit;
        let default = MemberLimits { requests_per_minute: Some(10), daily_budget: Some(2.0), ..Default::default() };
        let exception = MemberLimits { requests_per_minute: Some(100), ..Default::default() };
        let bucket = resolve_member_limit(Some(&default), Some(&exception)).unwrap();
        let l = LimitLayer::from_config(LimitBucket::Member, &bucket, [0.0; 4], member_inherits(Some(&exception)), "exception");
        // tpm and monthly carry no cap, so nothing is inherited there.
        assert_eq!(flags(&l), [false, false, true, false]);
        let bucket = resolve_member_limit(Some(&default), None).unwrap();
        let l = LimitLayer::from_config(LimitBucket::Member, &bucket, [0.0; 4], member_inherits(None), "member_default");
        assert_eq!(flags(&l), [true, false, true, false]);
    }

    /// Every viewer × bucket cell: an administrator sees all use; nobody
    /// else sees the organisation's; the pool's use reaches a plain member
    /// only where the workspace shares usage.
    #[test]
    fn a_viewer_sees_only_the_use_it_may() {
        use LimitBucket::*;
        for shared in [false, true] {
            for b in [Organisation, Workspace, Member, Key] {
                assert!(StackViewer::Admin.sees_use_of(b, shared));
            }
            for v in [StackViewer::Manager, StackViewer::Member] {
                assert!(!v.sees_use_of(Organisation, shared), "{v:?}");
                assert!(v.sees_use_of(Member, shared), "{v:?}");
                assert!(v.sees_use_of(Key, shared), "{v:?}");
            }
            assert!(StackViewer::Manager.sees_use_of(Workspace, shared));
        }
        assert!(!StackViewer::Member.sees_use_of(Workspace, false));
        assert!(StackViewer::Member.sees_use_of(Workspace, true));
    }

    /// Each counter row lands on its own meter, budgets in whole units; a row
    /// no meter shows (another window, another metric) lands nowhere.
    #[test]
    fn each_counter_row_lands_on_its_meter() {
        assert_eq!(use_slot("rpm", "minute", 7), Some((0, 7.0)));
        assert_eq!(use_slot("tpm", "minute", 900), Some((1, 900.0)));
        assert_eq!(use_slot("budget_micros", "daily", 2_500_000), Some((2, 2.5)));
        assert_eq!(use_slot("budget_micros", "monthly", 40_000_000), Some((3, 40.0)));
        assert_eq!(use_slot("budget_micros", "minute", 1), None);
        assert_eq!(use_slot("unknown_metric", "daily", 1), None);
        let mut l = layer(LimitBucket::Member, 0.0, 10.0);
        l.set_use([1.0, 2.0, 3.0, 4.0]);
        assert_eq!(l.meters().map(|m| m.used), [Some(1.0), Some(2.0), Some(3.0), Some(4.0)]);
    }

    /// A hidden use never makes a layer bind: the binding is named before
    /// use is hidden, and a layer without use carries no pressure.
    #[test]
    fn a_layer_with_hidden_use_has_no_pressure() {
        let mut l = layer(LimitBucket::Organisation, 90.0, 100.0);
        assert_eq!(l.pressure(), Some(0.9));
        for m in l.meters_mut() {
            m.used = None;
        }
        assert_eq!(l.pressure(), None);
    }

    #[test]
    fn nothing_binds_while_nothing_is_used() {
        let layers = [layer(LimitBucket::Workspace, 0.0, 100.0), layer(LimitBucket::Member, 0.0, 5.0)];
        assert_eq!(binding_layer(&layers), None);
    }

    #[test]
    fn the_layer_closest_to_its_cap_binds_and_a_tie_names_the_widest() {
        let layers = [layer(LimitBucket::Workspace, 10.0, 100.0), layer(LimitBucket::Member, 1.0, 5.0)];
        assert_eq!(binding_layer(&layers), Some(1));
        let tied = [layer(LimitBucket::Workspace, 50.0, 100.0), layer(LimitBucket::Member, 2.5, 5.0)];
        assert_eq!(binding_layer(&tied), Some(0));
    }

    /// Two key layers share a bucket: the binding one is named by position,
    /// not by bucket, so the other key is not marked with it.
    #[test]
    fn of_two_keys_only_the_one_nearer_its_cap_binds() {
        let keys = [layer(LimitBucket::Key, 1.0, 20.0), layer(LimitBucket::Key, 9.0, 10.0)];
        assert_eq!(binding_layer(&keys), Some(1));
    }

    /// A stored limit reads as itself, unset as unset, and a stray negative
    /// as unlimited (0) — never wrapping into a huge cap.
    #[test]
    fn a_stored_limit_reads_as_itself_and_a_negative_as_unlimited() {
        assert_eq!(rate(Some(60)), Some(60));
        assert_eq!(rate(Some(0)), Some(0));
        assert_eq!(rate(Some(-5)), Some(0));
        assert_eq!(rate(None), None);
        assert_eq!(budget(Some(2.5)), Some(2.5));
        assert_eq!(budget(Some(-1.0)), Some(0.0));
        assert_eq!(budget(None), None);
    }

    /// Unlimited only when EVERY metric is uncapped; any one cap makes it a
    /// pool that is baked and enforced.
    #[test]
    fn a_pool_is_unlimited_only_with_no_cap_at_all() {
        let none = RateLimitConfig::budget_only(0.0, 0.0, false);
        assert!(is_unlimited(&none));
        for capped in [
            RateLimitConfig { requests_per_minute: 1, ..none.clone() },
            RateLimitConfig { tokens_per_minute: 1, ..none.clone() },
            RateLimitConfig::budget_only(0.01, 0.0, false),
            RateLimitConfig::budget_only(0.0, 0.01, false),
        ] {
            assert!(!is_unlimited(&capped), "{capped:?}");
        }
    }

    #[test]
    fn no_default_and_no_row_is_unlimited() {
        let pool = resolve_pool(None, TenantBudgetDefault::default());
        assert!(is_unlimited(&pool));
    }
}
