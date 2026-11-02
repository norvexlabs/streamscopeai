//! Generic operator notifications — the push layer over "needs operator
//! attention" signals (budget breach/approach, agent major-session alerts, …).
//!
//! Producers call [`notify`] from wherever they detect a condition; the row's
//! `UNIQUE (tenant_id, dedup_key)` constraint is the "fire once per crossing"
//! debounce, so re-detecting the same condition is a silent no-op. The
//! leader-elected dispatcher ([`crate::alerts`]) delivers `pending` rows to the
//! configured channels.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::db::tenant::Scoped;

/// The kind of a notification. **Append-only** — never rename a variant (the
/// string is persisted in `notifications.kind` and matched by dispatch /
/// future UI), add a new one. Mirrors the `AuditBadge` / `ApiErrorCode` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    /// A workspace, per-user, or per-key scope reached or exceeded its budget cap.
    BudgetBreach,
    /// A workspace, per-user, or per-key scope crossed ~80% of its budget cap.
    BudgetApproaching,
    /// The agent flagged a session at the `major` alert level.
    SessionMajorAlert,
    /// A long-lived API key is within the expiry window (or already past it,
    /// unrevoked). Auto-refreshing MCP OAuth credentials are intentionally not
    /// included — they rotate on their own and would be noise.
    CredentialExpiring,
    /// The inline guardrail flagged untrusted content — emitted per category
    /// class (prompt-injection / jailbreak, or PII) so the title and deep-link
    /// match the detection, across both the inbound-prompt and fetched-web-content
    /// surfaces. Observe-mode signal, gated behind the per-tenant
    /// `notify_on_detection` toggle and deduped per category per day so the
    /// false-positive-bake phase can't flood the operator.
    GuardrailDetection,
    /// An upstream server stopped responding (the proxy's circuit breaker tripped
    /// it out of rotation after repeated transport failures). Deduped per outage
    /// episode so a flapping server re-notifies only when it goes down again.
    UpstreamUnhealthy,
    /// An upstream server that had tripped is responding again (breaker closed).
    UpstreamRecovered,
    /// A newer Streamscope OS version is available for the Kairos VM appliance
    /// (the upgrade-check worker found a registry tag newer than the running
    /// one). Deduped per available version so it fires once per new release.
    ApplianceUpgradeAvailable,
    /// One expert analysis cycle skipped many sessions on repeated
    /// deterministic upstream rejections — systematic (bad judge-model config,
    /// schema rejection), not a one-off poison payload. Deduped per day.
    AgentAnalysisFailing,
    /// Edge sync dropped rows the database refused for their content (so they
    /// could never be stored, and holding them would stall the channel).
    /// Deduped per sync channel per day; the admin-api log names each row.
    EdgeSyncRowsDropped,
}

impl NotificationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NotificationKind::BudgetBreach => "budget_breach",
            NotificationKind::BudgetApproaching => "budget_approaching",
            NotificationKind::SessionMajorAlert => "session_major_alert",
            NotificationKind::CredentialExpiring => "credential_expiring",
            NotificationKind::GuardrailDetection => "guardrail_detection",
            NotificationKind::UpstreamUnhealthy => "upstream_unhealthy",
            NotificationKind::UpstreamRecovered => "upstream_recovered",
            NotificationKind::ApplianceUpgradeAvailable => "appliance_upgrade_available",
            NotificationKind::AgentAnalysisFailing => "agent_analysis_failing",
            NotificationKind::EdgeSyncRowsDropped => "edge_sync_rows_dropped",
        }
    }

    /// Default severity for this kind: 0 info, 1 warning, 2 critical.
    pub fn severity(self) -> i16 {
        match self {
            NotificationKind::BudgetBreach | NotificationKind::SessionMajorAlert => 2,
            NotificationKind::BudgetApproaching
            | NotificationKind::CredentialExpiring
            | NotificationKind::GuardrailDetection
            | NotificationKind::UpstreamUnhealthy
            | NotificationKind::ApplianceUpgradeAvailable
            | NotificationKind::AgentAnalysisFailing
            | NotificationKind::EdgeSyncRowsDropped => 1,
            NotificationKind::UpstreamRecovered => 0,
        }
    }
}

/// A notification to emit. `dedup_key` carries the crossing identity — the same
/// key collapses to one row; encode the band / window / target so that a
/// genuinely new crossing produces a distinct key.
pub struct NewNotification {
    pub workspace_id: Option<Uuid>,
    pub kind: NotificationKind,
    pub dedup_key: String,
    pub title: String,
    pub summary: String,
    pub target_kind: Option<&'static str>,
    pub target_id: Option<Uuid>,
    pub payload: serde_json::Value,
}

/// PG NOTIFY channel the dispatcher LISTENs on to deliver without waiting for
/// its periodic tick.
pub const NOTIFY_PENDING_CHANNEL: &str = "notify_pending";

/// Insert a notification, deduplicated on `(tenant_id, dedup_key)`.
///
/// Returns `Ok(true)` when a new row was created (a genuinely new crossing) and
/// `Ok(false)` when the key already existed (no-op). On a new row, wakes the
/// dispatcher via `pg_notify`. `tenant_id` is bound explicitly per the tenant
/// isolation invariant even though the connection is RLS-scoped.
///
/// Best-effort callers should ignore the result — a notification failure must
/// never break the producer's primary write (graceful degradation).
/// [`notify`] for a ROLL-UP whose `payload.count` grows during its window (the
/// member-budget notification: "N members of <workspace> passed 80%"). The
/// first crossing inserts and is delivered once. A later, LARGER count
/// rewrites that row's title, summary and payload in place — the feed shows
/// the current count — without delivering it again, which would bring back
/// the flood the roll-up exists to prevent. A count no larger changes nothing.
/// Returns whether a row was created.
pub async fn notify_rollup(
    conn: &mut Scoped,
    tenant_id: Uuid,
    n: NewNotification,
) -> Result<bool, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as(
        "INSERT INTO notifications \
            (tenant_id, workspace_id, kind, severity, dedup_key, title, summary, \
             target_kind, target_id, payload) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, dedup_key) DO UPDATE \
            SET title = EXCLUDED.title, summary = EXCLUDED.summary, payload = EXCLUDED.payload \
          WHERE COALESCE((notifications.payload->>'count')::bigint, 0) \
              < COALESCE((EXCLUDED.payload->>'count')::bigint, 0) \
         RETURNING (xmax = 0)",
    )
    .bind(tenant_id)
    .bind(n.workspace_id)
    .bind(n.kind.as_str())
    .bind(n.kind.severity())
    .bind(&n.dedup_key)
    .bind(&n.title)
    .bind(&n.summary)
    .bind(n.target_kind)
    .bind(n.target_id)
    .bind(&n.payload)
    .fetch_optional(&mut *conn)
    .await?;
    // `xmax = 0` only on the row this statement inserted; an updated row
    // keeps its delivery state and is not dispatched again.
    let created = row.is_some_and(|r| r.0);
    if created {
        // Propagated, never swallowed: on a caller's transaction a failed
        // statement aborts it, and its COMMIT would then roll back in silence.
        sqlx::query("SELECT pg_notify($1, '')")
            .bind(NOTIFY_PENDING_CHANNEL)
            .execute(&mut *conn)
            .await?;
    }
    Ok(created)
}

pub async fn notify(
    conn: &mut Scoped,
    tenant_id: Uuid,
    n: NewNotification,
) -> Result<bool, sqlx::Error> {
    let created: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO notifications \
            (tenant_id, workspace_id, kind, severity, dedup_key, title, summary, \
             target_kind, target_id, payload) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, dedup_key) DO NOTHING \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(n.workspace_id)
    .bind(n.kind.as_str())
    .bind(n.kind.severity())
    .bind(&n.dedup_key)
    .bind(&n.title)
    .bind(&n.summary)
    .bind(n.target_kind)
    .bind(n.target_id)
    .bind(&n.payload)
    .fetch_optional(&mut *conn)
    .await?;

    if created.is_some() {
        // Wake the dispatcher immediately (cross-instance via PG NOTIFY).
        // Propagated, never swallowed: on a caller's transaction a failed
        // statement aborts it, and its COMMIT would then roll back in silence.
        sqlx::query("SELECT pg_notify($1, '')")
            .bind(NOTIFY_PENDING_CHANNEL)
            .execute(&mut *conn)
            .await?;
    }

    Ok(created.is_some())
}
