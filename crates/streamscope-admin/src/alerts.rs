//! Leader-elected alert dispatcher.
//!
//! One cycle does two things per tenant (a single tenant pass, because
//! `notifications` is FORCE-RLS so reads must be tenant-scoped):
//!
//! 1. **Produce** — evaluate every capped budget scope's spend against its cap
//!    and `notify()` on each crossing. The `UNIQUE (tenant_id, dedup_key)`
//!    constraint makes re-evaluation idempotent (fire once per crossing).
//! 2. **Dispatch** — deliver this tenant's `pending` notifications (budget
//!    crossings plus event-driven ones like agent major-session alerts) to the
//!    configured channels and mark them.
//!
//! Single-runner via [`leader::LOCK_ALERTS`] so an alarm fires once fleet-wide;
//! the unique constraint is the correctness backstop for the brief two-leaders
//! window during a lock handoff. Woken on demand by `pg_notify('notify_pending')`
//! (a producer inserted a row) with a periodic fallback.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use streamscope_core::guardrail::GuardrailCategory;
use uuid::Uuid;

use crate::AdminState;
use crate::db::tenant::TenantConn;
use crate::leader;
use crate::notifications::{NewNotification, NotificationKind, NOTIFY_PENDING_CHANNEL};
use crate::routes::analytics::evaluate_budget_scopes;

/// A pending notification row, read tenant-scoped for delivery.
#[derive(sqlx::FromRow)]
struct PendingNotification {
    id: Uuid,
    kind: String,
    severity: i16,
    title: String,
    summary: String,
    target_kind: Option<String>,
    target_id: Option<Uuid>,
}

/// Background dispatcher task. Mirrors the config-sweeper shape: a PG listener
/// for immediate wake plus a periodic fallback, with leader election gating the
/// actual work.
pub async fn alert_dispatcher(state: Arc<AdminState>, token: tokio_util::sync::CancellationToken) {
    // Brief startup stagger so the heavier leader workers settle first.
    tokio::select! {
        _ = token.cancelled() => return,
        _ = tokio::time::sleep(Duration::from_secs(15)) => {}
    }

    // Outer loop: (re)connect the PG listener on failure.
    loop {
        if token.is_cancelled() {
            tracing::info!("alert dispatcher: shutdown signalled, exiting");
            return;
        }
        let mut listener = match crate::db::listener().await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("alert dispatcher PG LISTEN connect failed: {e}");
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }
        };
        if let Err(e) = listener.listen(NOTIFY_PENDING_CHANNEL).await {
            tracing::error!("alert dispatcher PG LISTEN subscribe failed: {e}");
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            continue;
        }
        tracing::info!("alert dispatcher started (leader-elected, event-driven)");

        // Inner loop: wait for a wake signal (or the periodic fallback), then run.
        loop {
            let interval =
                Duration::from_secs(crate::settings::admin_settings().alert_dispatch_interval_secs);
            // Producers (e.g. agent major-session alerts) fire
            // `pg_notify('notify_pending')` when they insert a row. An
            // event-driven wake only needs to DELIVER pending rows — it must not
            // re-run the budget producer (whose own inserts emit the same notify,
            // which would re-wake us into an unnecessary full tenant scan). The
            // budget producer is window-polled, so it runs on the periodic tick.
            let produce = tokio::select! {
                _ = token.cancelled() => {
                    tracing::info!("alert dispatcher: shutdown signalled, exiting");
                    return;
                }
                result = listener.recv() => {
                    if let Err(e) = result {
                        tracing::warn!("alert dispatcher PG LISTEN error: {e} — reconnecting");
                        break; // Reconnect via outer loop.
                    }
                    false // event-driven wake: dispatch only
                }
                _ = tokio::time::sleep(interval) => true, // periodic tick: produce + dispatch
            };

            // Try to acquire leader lock. Non-leaders skip.
            let Some(leader_conn) =
                leader::try_acquire_leader(&state.db, leader::LOCK_ALERTS).await
            else {
                continue;
            };
            run_cycle(&state.db, produce).await;
            leader::release_leader(leader_conn, leader::LOCK_ALERTS).await;
        }
    }
}

/// One dispatch cycle per tenant: optionally produce budget crossings (periodic
/// tick only), then deliver pending rows. Errors in one tenant are logged and
/// never abort the others. The SYSTEM tenant carries no workloads/budgets, so
/// it is skipped (matching the agent / config-sync convention).
async fn run_cycle(pool: &crate::db::Db, produce: bool) {
    let res = crate::db::tenant::for_each_tenant(pool, |mut db| async move {
        let tenant_id = db.tenant_uuid();
        if tenant_id == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
            return Ok(());
        }
        if produce {
            produce_budget_crossings(&mut db, tenant_id).await;
            produce_expiring_credentials(&mut db, tenant_id).await;
            produce_guardrail_detections(&mut db, tenant_id).await;
            produce_unusable_mcp_upstreams(&mut db, tenant_id).await;
        }
        dispatch_pending(&mut db, tenant_id).await;
        Ok(())
    })
    .await;
    if let Err(e) = res {
        tracing::warn!("alert dispatcher: iterate tenants failed: {e}");
    }
}

/// Evaluate budget scopes for one tenant and emit a notification for each scope
/// that has reached the approaching (≥80%) or breached (≥100%) band.
///
/// Member scopes are ROLLED UP per workspace: a default member limit applies to
/// every member, so one notification per member could flood the feed (and the
/// dispatcher's per-cycle batch) the day a team hits its default. One
/// notification per (workspace, window, band) names how many members crossed.
async fn produce_budget_crossings(db: &mut TenantConn, tenant_id: Uuid) {
    let scopes = match evaluate_budget_scopes(db.conn(), tenant_id, None).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, "alert: budget evaluation failed: {e}");
            return;
        }
    };

    // Read once per tenant per cycle: every scope below is denominated in it.
    let currency = crate::routes::pricing::accounting_currency(db.conn()).await;

    // (workspace, window_kind, window_start, band) → the members at that band.
    type MemberGroupKey = (Uuid, String, DateTime<Utc>, i16);
    let mut member_groups: std::collections::BTreeMap<MemberGroupKey, Vec<&crate::routes::analytics::BudgetScopeStatus>> =
        std::collections::BTreeMap::new();

    for s in &scopes {
        let band = s.band();
        if band < 1 {
            continue;
        }
        if s.scope_kind == "user" {
            member_groups
                .entry((s.workspace_id, s.window_kind.clone(), s.window_start, band))
                .or_default()
                .push(s);
            continue;
        }
        let kind = if band == 2 {
            NotificationKind::BudgetBreach
        } else {
            NotificationKind::BudgetApproaching
        };
        // `band` is part of the key so approaching → breached in the same window
        // is a distinct notification, while re-evaluation at the same band is a
        // no-op. `window_start` rolls the key to a fresh row each new window.
        // These scopes (organisation, workspace, key) are each unique on their
        // own id; only a member is one person in one workspace, and members
        // roll up under their workspace below.
        let dedup_key = format!(
            "budget:{}:{}:{}:{}:{}",
            s.scope_kind,
            s.scope_id,
            s.window_kind,
            s.window_start.timestamp(),
            band,
        );
        let pct = (s.ratio() * 100.0).round() as i64;
        let verb = if band == 2 { "reached" } else { "approaching" };
        let title = format!("Budget {verb}: {} {} cap", s.scope_kind, s.window_kind);
        let summary = format!(
            "{} {} spend is at {pct}% of cap ({:.2} of {:.2} {currency}).",
            s.scope_kind,
            s.window_kind,
            s.spent,
            s.cap,
        );
        // scope_kind is one of 'tenant' | 'workspace' | 'key' here — mapped to
        // the notification's deep-link target kind. `tenant` has no per-row
        // detail page; it links to the settings page that owns the cap.
        let target_kind = match s.scope_kind.as_str() {
            "tenant" => "tenant",
            "workspace" => "workspace",
            _ => "api_key",
        };
        let n = NewNotification {
            workspace_id: Some(s.workspace_id),
            kind,
            dedup_key,
            title,
            summary,
            target_kind: Some(target_kind),
            target_id: Some(s.scope_id),
            payload: serde_json::json!({
                "scope_kind": s.scope_kind,
                "window_kind": s.window_kind,
                "spent": s.spent,
                "cap": s.cap,
                "ratio": s.ratio(),
            }),
        };
        let _ = crate::notifications::notify(db.conn(), tenant_id, n).await;
    }

    if member_groups.is_empty() {
        return;
    }
    let workspace_ids: Vec<Uuid> = member_groups.keys().map(|k| k.0).collect();
    let names: std::collections::HashMap<Uuid, String> =
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM workspaces WHERE id = ANY($1)")
            .bind(&workspace_ids)
            .fetch_all(db.conn())
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    for ((ws, window_kind, window_start, band), members) in member_groups {
        let kind = if band == 2 {
            NotificationKind::BudgetBreach
        } else {
            NotificationKind::BudgetApproaching
        };
        let ws_name = names.get(&ws).cloned().unwrap_or_else(|| ws.to_string());
        let count = members.len();
        let worst = members
            .iter()
            .max_by(|a, b| a.ratio().partial_cmp(&b.ratio()).unwrap_or(std::cmp::Ordering::Equal));
        let what = if band == 2 { "reached" } else { "passed 80% of" };
        let noun = if count == 1 { "member" } else { "members" };
        let title = format!("Budget {}: {count} {noun} of {ws_name}", if band == 2 { "reached" } else { "approaching" });
        let summary = match worst {
            Some(w) => format!(
                "{count} {noun} of {ws_name} {what} their {window_kind} member budget (highest: {}% — {:.2} of {:.2} {currency}).",
                (w.ratio() * 100.0).round() as i64,
                w.spent,
                w.cap,
            ),
            None => format!("{count} {noun} of {ws_name} {what} their {window_kind} member budget."),
        };
        let n = NewNotification {
            workspace_id: Some(ws),
            kind,
            dedup_key: format!("budget:member:{ws}:{window_kind}:{}:{band}", window_start.timestamp()),
            title,
            summary,
            target_kind: Some("workspace"),
            target_id: Some(ws),
            payload: serde_json::json!({
                "scope_kind": "member",
                "window_kind": window_kind,
                "members": members.iter().take(50).map(|m| m.scope_id).collect::<Vec<_>>(),
                "count": count,
            }),
        };
        // The count grows as more members cross in the window: the row is
        // refreshed in place, never re-delivered.
        let _ = crate::notifications::notify_rollup(db.conn(), tenant_id, n).await;
    }
}

/// Emit a notification for each long-lived API key within the expiry
/// window (or already past expiry but unrevoked). Deduped per key per expiry
/// date, so rotating/extending a key re-alerts when its new expiry approaches.
/// MCP OAuth credentials are excluded — they auto-refresh. Keys *born* inside
/// the warning window (lifetime ≤ 7 days — the CLI's per-run CI keys) never
/// alert: expiring is their design, not an operator-attention event.
async fn produce_expiring_credentials(db: &mut TenantConn, tenant_id: Uuid) {
    // (id, workspace_id, name, expires_at, days_left)
    type ExpiringRow = (Uuid, Uuid, Option<String>, DateTime<Utc>, i64);
    let rows: Vec<ExpiringRow> = match sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT id, workspace_id, name, expires_at, \
                FLOOR(EXTRACT(EPOCH FROM (expires_at - NOW())) / 86400)::int8 AS days_left \
           FROM api_keys \
          WHERE tenant_id = $1 AND {}",
        crate::routes::keys::KEY_EXPIRY_NOTICE
    )))
    .bind(tenant_id)
    .fetch_all(db.conn())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, "alert: expiring-credential query failed: {e}");
            return;
        }
    };

    for (id, workspace_id, name, expires_at, days_left) in rows {
        // Expiry day as the dedup discriminator — a rotated/extended key carries
        // a new expires_at and so re-alerts; the same key/date is a no-op.
        let dedup_key = format!("cred_expiring:api_key:{id}:{}", expires_at.timestamp() / 86400);
        let label = name.unwrap_or_else(|| "Unnamed".to_string());
        let summary = if days_left < 0 {
            format!("API key \"{label}\" has expired and is not yet revoked.")
        } else if days_left == 0 {
            format!("API key \"{label}\" expires within a day.")
        } else {
            format!("API key \"{label}\" expires in {days_left} day(s).")
        };
        let n = NewNotification {
            workspace_id: Some(workspace_id),
            kind: NotificationKind::CredentialExpiring,
            dedup_key,
            title: format!("API key expiring: {label}"),
            summary,
            target_kind: Some("api_key"),
            target_id: Some(id),
            payload: serde_json::json!({
                "expires_at": expires_at.to_rfc3339(),
                "days_left": days_left,
            }),
        };
        let _ = crate::notifications::notify(db.conn(), tenant_id, n).await;
    }
}

/// How long an edited MCP upstream is left to its administrator before the
/// alert scan reports it unusable.
const MCP_UNUSABLE_GRACE_MINUTES: i32 = 10;

/// Notify once per enabled MCP upstream that every call fails on, whoever
/// makes it ([`crate::routes::mcp::upstream_unusable`]: an administrator value
/// missing or unreadable, an incomplete OAuth client). The dedup key carries
/// the administrator-value version (`cred_version`, moved by every change of
/// the declaration, an administrator value, the URL or the OAuth secret), so a
/// change that leaves it unusable notifies again; an OAuth token URL or client
/// ID is only ever set, never cleared, so filling one cannot break it again.
/// An upstream edited in the last [`MCP_UNUSABLE_GRACE_MINUTES`] is not
/// reported yet: an administrator who just adopted it is still filling it in.
/// A built-in upstream carries no declared inputs and is skipped.
async fn produce_unusable_mcp_upstreams(db: &mut TenantConn, tenant_id: Uuid) {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        name: String,
        auth_mode: String,
        cred_version: i64,
        remote: sqlx::types::Json<streamscope_core::mcp::header_inputs::Remote>,
        encrypted_admin_inputs: sqlx::types::Json<std::collections::HashMap<String, String>>,
        oauth_token_url: Option<String>,
        oauth_client_id: Option<String>,
    }
    let rows = match sqlx::query_as::<_, Row>(
        "SELECT id, name, auth_mode, cred_version, remote, encrypted_admin_inputs, \
                oauth_token_url, oauth_client_id \
           FROM mcp_upstream_servers \
          WHERE tenant_id = $1 AND enabled AND NOT built_in \
            AND updated_at < NOW() - make_interval(mins => $2) \
            AND NOT EXISTS (SELECT 1 FROM notifications n \
                             WHERE n.tenant_id = mcp_upstream_servers.tenant_id \
                               AND n.dedup_key = 'mcp_upstream_unusable:' || mcp_upstream_servers.id::text \
                                                 || ':' || mcp_upstream_servers.cred_version::text)",
    )
    .bind(tenant_id)
    .bind(MCP_UNUSABLE_GRACE_MINUTES)
    .fetch_all(db.conn())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, "alert: mcp upstream scan failed: {e}");
            return;
        }
    };
    for r in rows {
        let Err(reason) = crate::routes::mcp::upstream_unusable(
            &r.remote.0,
            &r.auth_mode,
            &r.encrypted_admin_inputs.0,
            r.oauth_token_url.as_deref(),
            r.oauth_client_id.as_deref(),
            crate::routes::mcp::Log::Quiet,
        ) else {
            continue;
        };
        let n = NewNotification {
            workspace_id: None,
            kind: NotificationKind::McpUpstreamUnusable,
            dedup_key: format!("mcp_upstream_unusable:{}:{}", r.id, r.cred_version),
            title: format!("MCP server cannot be called: {}", r.name),
            summary: format!(
                "Every call to the MCP server \"{}\" fails until an administrator fixes it: {reason}.",
                r.name
            ),
            target_kind: Some("mcp_upstream_server"),
            target_id: Some(r.id),
            payload: serde_json::json!({ "reason": reason }),
        };
        let _ = crate::notifications::notify(db.conn(), tenant_id, n).await;
    }
}

/// Emit daily, deduped guardrail-detection notifications for a tenant that
/// opted into `notify_on_detection`. Tenant-level (spans workspaces) and
/// fire-once per UTC day: observe mode is the noisy false-positive-bake phase,
/// so each alarm is a single "go look at the dashboard" nudge per day, not one
/// per detection (the live count stays on the attention tile). Agent-origin
/// traffic is counted — a detection in content the agent autonomously fetched
/// is a security signal, not noise to hide behind the agent-traffic filter.
///
/// PII and prompt-injection share the `guardrail` badge **code** (they differ
/// only in the badge's `categories`), so the alarm is split **per category**:
/// each notification carries the right title and deep-links to a row of its own
/// category. A category-blind count would mislabel a PII redaction as a
/// prompt-injection (and point the operator at the wrong audit row).
async fn produce_guardrail_detections(db: &mut TenantConn, tenant_id: Uuid) {
    let backend = match crate::routes::guardrail::load_backend(db.conn()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, "alert: guardrail settings load failed: {e:?}");
            return;
        }
    };
    // Only alarm when the operator opted into the observe-mode alarm
    // (tenant-wide backend setting). Default off keeps the FP-bake phase silent.
    // Whether the guardrail is "on" is now per-profile; the detection counts
    // below only exist when it actually ran, so the notify flag is the gate.
    if !backend.notify_on_detection {
        return;
    }

    // UTC-midnight floor — same epoch alignment the budget evaluator uses, so
    // the dedup key rolls to a fresh row each day and the count covers "today".
    let now_ms = streamscope_core::usage::now_ms();
    let Some(day_start) = DateTime::<Utc>::from_timestamp_millis(
        streamscope_core::usage::UsageWindowKind::Daily.window_start_ms(now_ms) as i64,
    ) else {
        return;
    };

    // One alarm per category class (see `GuardrailAlarm`), each scoped to its
    // own categories so a PII redaction never reads as "Prompt-injection". The
    // category→alarm mapping (`GuardrailAlarm::for_category`) is exhaustive over
    // `GuardrailCategory`, so a new variant forces a compile-time alarm choice
    // (and, added to `GuardrailCategory::ALL`, is then counted here).
    for alarm in GuardrailAlarm::ALL {
        let cats: Vec<&'static str> = GuardrailCategory::ALL
            .iter()
            .filter(|c| GuardrailAlarm::for_category(**c) == alarm)
            .map(|c| c.badge_str())
            .collect();
        emit_guardrail_alarm(db, tenant_id, day_start, &cats, alarm).await;
    }
}

/// The operator notification a guardrail category rolls up into. Splitting the
/// alarm by class is what keeps the title + deep-link matching the detection (a
/// PII redaction must not surface as a prompt-injection alarm).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardrailAlarm {
    /// Prompt-attack signals: indirect injection + direct jailbreak.
    Injection,
    /// Sensitive-data (PII) detections.
    Pii,
}

impl GuardrailAlarm {
    const ALL: [GuardrailAlarm; 2] = [GuardrailAlarm::Injection, GuardrailAlarm::Pii];

    /// Which alarm a category belongs to. **Exhaustive over `GuardrailCategory`**
    /// — a new variant fails to compile here until it is assigned an alarm, so a
    /// category can never silently escape the operator notifications.
    fn for_category(c: GuardrailCategory) -> GuardrailAlarm {
        match c {
            GuardrailCategory::PromptInjection | GuardrailCategory::Jailbreak => {
                GuardrailAlarm::Injection
            }
            GuardrailCategory::Pii => GuardrailAlarm::Pii,
        }
    }

    fn title(self) -> &'static str {
        match self {
            GuardrailAlarm::Injection => "Prompt-injection detected",
            GuardrailAlarm::Pii => "Sensitive data (PII) detected",
        }
    }

    /// Detection noun for the summary line.
    fn noun(self) -> &'static str {
        match self {
            GuardrailAlarm::Injection => "prompt-injection",
            GuardrailAlarm::Pii => "PII",
        }
    }

    /// Per-class dedup prefix so the two alarms dedup independently per day.
    fn dedup_prefix(self) -> &'static str {
        match self {
            GuardrailAlarm::Injection => "guardrail_detection",
            GuardrailAlarm::Pii => "pii_detection",
        }
    }
}

/// Emit one category-scoped guardrail-detection notification (see
/// [`produce_guardrail_detections`]). `cats` are the canonical
/// [`GuardrailCategory::badge_str`] tokens that share this `alarm`; the title /
/// summary noun / dedup prefix come from the alarm. All string inputs are
/// compile-time constants — no user data reaches the SQL (the category tokens
/// are matched inside the badge JSON via `@>` containment).
async fn emit_guardrail_alarm(
    db: &mut TenantConn,
    tenant_id: Uuid,
    day_start: DateTime<Utc>,
    cats: &[&'static str],
    alarm: GuardrailAlarm,
) {
    if cats.is_empty() {
        return; // an alarm class with no categories has nothing to count
    }
    let noun = alarm.noun();

    // Per-surface counts since the day boundary.
    let (inbound, web, blocked) =
        match crate::audit_store::guardrail::detection_counts(db.conn(), tenant_id, day_start, cats).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(tenant_id = %tenant_id, "alert: guardrail detection query failed: {e}");
                return;
            }
        };
    let total = inbound + web;
    if total == 0 {
        return;
    }

    // Deep-link target: the most-recent flagged request OF THIS CATEGORY across
    // both surfaces, so the notification focuses the exact audit row (a
    // `request_id` deep-link bypasses the /audit period window) and the row's
    // category matches the notification's title.
    let target_id: Option<Uuid> =
        crate::audit_store::guardrail::latest_detection(db.conn(), tenant_id, day_start, cats)
            .await
            .ok()
            .flatten();

    let dedup_key = format!("{}:{}", alarm.dedup_prefix(), day_start.timestamp());
    let breakdown = match (inbound > 0, web > 0) {
        (true, true) => format!(
            "{total} {noun} detection(s) today ({inbound} inbound prompt, {web} web content)"
        ),
        (true, false) => format!("{inbound} inbound {noun} detection(s) today"),
        (false, true) => format!("{web} {noun} detection(s) in fetched web content today"),
        (false, false) => return, // unreachable: total > 0 is guaranteed above
    };
    let summary = if blocked > 0 {
        format!("{breakdown} ({blocked} stripped). Review the guardrail audit trail.")
    } else {
        format!("{breakdown}. Review the guardrail audit trail.")
    };
    let n = NewNotification {
        workspace_id: None,
        kind: NotificationKind::GuardrailDetection,
        dedup_key,
        title: alarm.title().to_string(),
        summary,
        target_kind: Some("guardrail"),
        target_id,
        payload: serde_json::json!({
            "inbound": inbound,
            "web": web,
            "total": total,
            "blocked": blocked,
            "categories": cats,
            "window": "daily",
            "window_start": day_start.to_rfc3339(),
        }),
    };
    let _ = crate::notifications::notify(db.conn(), tenant_id, n).await;
}

/// Deliver one tenant's pending notifications and mark each delivered/failed.
async fn dispatch_pending(db: &mut TenantConn, tenant_id: Uuid) {
    let pending: Vec<PendingNotification> = match sqlx::query_as(
        "SELECT id, kind, severity, title, summary, target_kind, target_id \
         FROM notifications \
         WHERE tenant_id = $1 AND delivery_state = 'pending' \
         ORDER BY created_at LIMIT 500",
    )
    .bind(tenant_id)
    .fetch_all(db.conn())
    .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(tenant_id = %tenant_id, "alert: pending fetch failed: {e}");
            return;
        }
    };

    for n in pending {
        let delivered = deliver(tenant_id, &n);
        let new_state = if delivered { "delivered" } else { "failed" };
        if let Err(e) = sqlx::query(
            "UPDATE notifications \
                SET delivery_state = $2, attempts = attempts + 1, \
                    delivered_at = CASE WHEN $2 = 'delivered' THEN now() ELSE delivered_at END \
             WHERE id = $1 AND tenant_id = $3",
        )
        .bind(n.id)
        .bind(new_state)
        .bind(tenant_id)
        .execute(db.conn())
        .await
        {
            tracing::warn!(tenant_id = %tenant_id, "alert: mark delivery failed: {e}");
        }
    }
}

/// Deliver one notification. v1 ships the operator-log channel only; webhook /
/// email channels slot in here (read per-tenant channel config, fan out) without
/// touching producers or the dispatch loop. Returns whether delivery succeeded.
fn deliver(tenant_id: Uuid, n: &PendingNotification) -> bool {
    tracing::warn!(
        tenant_id = %tenant_id,
        kind = %n.kind,
        severity = n.severity,
        target_kind = n.target_kind.as_deref().unwrap_or(""),
        target_id = ?n.target_id,
        summary = %n.summary,
        "operator notification: {}",
        n.title,
    );
    true
}
