//! Background retention purge — deletes expired audit, session, and message data.
//!
//! Iterates all tenants, reading per-tenant `retention_days` from `system_settings`
//! (default 30 days). Deletes in batches with short sleeps between batches to
//! avoid long-held locks. Also manages the weekly partitions of the audit tables
//! and `conversation_turns`: creates future partitions and drops expired ones.
//!
//! The content stores (messages, tool definitions, system prompts, history
//! chunks, media blobs) are purged by their `last_referenced_at` stamp, never by
//! scanning what references them: every write that names a body stamps it (at
//! most once a day), so a body whose stamp is older than the tenant's cutoff less
//! [`CONTENT_STAMP_MARGIN_DAYS`] is named by no row inside the window.

use crate::db::{Db, Maintenance, MaintenanceConn, Global};
use tracing::{error, info, warn};

use crate::audit_store::purge;
use crate::batch_delete::batch_delete_conn;
use crate::db::tenant::{Scoped, TenantId, for_each_tenant};

pub const DEFAULT_RETENTION_DAYS: i64 = 30;

/// The longest retention a tenant may set, in days (a century): the purge's
/// cutoff is `now - days`, and a date past chrono's range would panic it.
pub const RETENTION_DAYS_MAX: i64 = 36_500;

/// How much older than the tenant's cutoff a content body's stamp must be before
/// it goes: the writers renew a stamp only once it is [`STAMP_RENEW_DAYS`] old,
/// and a turn's timestamp is the edge's clock, which may run ahead of the
/// database's. Safe while that skew stays under this margin less the renewal
/// throttle — the arithmetic locked by
/// `a_stamped_body_survives_every_turn_still_in_the_window`, the writers' renewal
/// by `test_a_turn_renews_the_stamp_of_every_body_it_names`, and the purge's
/// cutoff by `test_the_message_purge_takes_only_stale_stamps_under_rls`.
pub const CONTENT_STAMP_MARGIN_DAYS: i64 = 2;

/// How old a content body's stamp must be before an ingest that names it
/// renews it: a body every turn names is then rewritten (and its row locked)
/// at most once per this many days. The one source for every stamping writer.
pub const STAMP_RENEW_DAYS: i32 = 1;

#[derive(Debug, Default, serde::Serialize, utoipa::ToSchema)]
pub struct PurgeSummary {
    pub retention_days: i64,
    pub sessions_deleted: u64,
    pub audit_deleted: u64,
    pub turns_deleted: u64,
    pub messages_deleted: u64,
    pub tool_definitions_deleted: u64,
    pub system_prompts_deleted: u64,
    pub history_chunks_deleted: u64,
    pub suggestions_deleted: u64,
    pub media_blobs_deleted: u64,
    pub admin_audit_deleted: u64,
    pub portal_audit_deleted: u64,
    pub dead_keys_deleted: u64,
    pub security_audit_deleted: u64,
    pub edge_stats_deleted: u64,
    pub load_samples_deleted: u64,
    pub partitions_dropped: Vec<String>,
}

/// The longest the live per-endpoint load samples are kept. A replica writes
/// one row per gated endpoint per heartbeat; the server dashboard charts them
/// for a recent window, and past this they are volume nothing reads. A tenant
/// whose own retention is shorter keeps them for that shorter window
/// ([`load_sample_horizon_days`]), which is what the dashboard states.
pub const LOAD_SAMPLE_RETENTION_DAYS: i64 = 7;

/// How far back a tenant's live load samples reach: the purge below keeps them
/// for the shorter of [`LOAD_SAMPLE_RETENTION_DAYS`] and the tenant's
/// retention. Runs on the tenant's own connection.
pub(crate) async fn load_sample_horizon_days(conn: &mut Scoped) -> i64 {
    load_retention_days_conn(conn).await.min(LOAD_SAMPLE_RETENTION_DAYS)
}

/// Run a complete retention purge cycle, iterating all tenants. Uses each
/// tenant's configured `retention_days` from `system_settings`.
pub async fn run_purge(pool: &Db) -> Result<PurgeSummary, sqlx::Error> {
    run_purge_with_override(pool, None).await
}

/// Same as [`run_purge`] but substitutes `override_days` for every tenant's
/// configured `retention_days` when `Some`. Used by the host daemon's
/// disk-pressure path to force a shorter effective window across all tenants
/// without changing their per-tenant setting. The override is also applied to
/// partition drops and global edge-stats telemetry purge so the whole pass
/// uses one consistent cutoff.
pub async fn run_purge_with_override(
    pool: &Db,
    override_days: Option<i64>,
) -> Result<PurgeSummary, sqlx::Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let sessions = Arc::new(AtomicU64::new(0));
    let audit = Arc::new(AtomicU64::new(0));
    let turns = Arc::new(AtomicU64::new(0));
    let messages = Arc::new(AtomicU64::new(0));
    let tool_defs = Arc::new(AtomicU64::new(0));
    let prompts = Arc::new(AtomicU64::new(0));
    let chunks = Arc::new(AtomicU64::new(0));
    let suggestions = Arc::new(AtomicU64::new(0));
    let media_blobs = Arc::new(AtomicU64::new(0));
    let admin_audit = Arc::new(AtomicU64::new(0));
    let portal_audit = Arc::new(AtomicU64::new(0));
    let dead_keys = Arc::new(AtomicU64::new(0));
    let load_samples = Arc::new(AtomicU64::new(0));

    let s = sessions.clone();
    let a = audit.clone();
    let t = turns.clone();
    let m = messages.clone();
    let td = tool_defs.clone();
    let sp = prompts.clone();
    let ch = chunks.clone();
    let sg = suggestions.clone();
    let mb = media_blobs.clone();
    let aa = admin_audit.clone();
    let pa = portal_audit.clone();
    let dk = dead_keys.clone();
    let ls = load_samples.clone();

    for_each_tenant(pool, |mut db| {
        let s = s.clone();
        let a = a.clone();
        let t = t.clone();
        let m = m.clone();
        let td = td.clone();
        let sp = sp.clone();
        let ch = ch.clone();
        let sg = sg.clone();
        let mb = mb.clone();
        let aa = aa.clone();
        let pa = pa.clone();
        let dk = dk.clone();
        let ls = ls.clone();
        async move {
            let tenant_summary = run_purge_tenant_with_override(db.conn(), override_days).await
                .map_err(|e| anyhow::anyhow!(e))?;

            s.fetch_add(tenant_summary.sessions_deleted, Ordering::Relaxed);
            a.fetch_add(tenant_summary.audit_deleted, Ordering::Relaxed);
            t.fetch_add(tenant_summary.turns_deleted, Ordering::Relaxed);
            m.fetch_add(tenant_summary.messages_deleted, Ordering::Relaxed);
            td.fetch_add(tenant_summary.tool_definitions_deleted, Ordering::Relaxed);
            sp.fetch_add(tenant_summary.system_prompts_deleted, Ordering::Relaxed);
            ch.fetch_add(tenant_summary.history_chunks_deleted, Ordering::Relaxed);
            sg.fetch_add(tenant_summary.suggestions_deleted, Ordering::Relaxed);
            mb.fetch_add(tenant_summary.media_blobs_deleted, Ordering::Relaxed);
            aa.fetch_add(tenant_summary.admin_audit_deleted, Ordering::Relaxed);
            pa.fetch_add(tenant_summary.portal_audit_deleted, Ordering::Relaxed);
            dk.fetch_add(tenant_summary.dead_keys_deleted, Ordering::Relaxed);
            ls.fetch_add(tenant_summary.load_samples_deleted, Ordering::Relaxed);

            Ok(())
        }
    }).await?;

    // Global-infra telemetry (edge stats/instances, security audit) is not tenant
    // data: it follows the platform-level window.
    let infra_days = match override_days {
        Some(d) => d,
        None => load_retention_days_platform(pool).await,
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::days(infra_days);

    // Dropping a partition is PHYSICAL and spans every tenant, so its window must
    // be the LONGEST any tenant asks for — a partition still holding un-expired
    // rows for the tenant with the widest `retention_days` must survive, even when
    // other tenants have long since aged out of it. Each tenant's own rows are
    // already removed at its own (shorter) window by the per-tenant purge above;
    // this only governs when the now-empty physical partition may go.
    let partition_days = match override_days {
        Some(d) => d,
        None => load_max_retention_days(pool).await?,
    };
    let partition_cutoff = chrono::Utc::now() - chrono::Duration::days(partition_days);
    let partitions_dropped = drop_old_partitions(pool, &partition_cutoff).await?;
    let edge_stats_deleted = purge_old_edge_stats(pool, &cutoff).await?;
    let edge_instances_reaped = reap_stale_edge_instances(pool, &cutoff).await?;
    if edge_instances_reaped > 0 {
        tracing::info!(reaped = edge_instances_reaped, "reaped stale edge instances");
    }
    // security_audit is a global (non-RLS) table — pre-auth events have no
    // reliable tenant, so it's purged once on the raw pool, not per-tenant.
    let security_audit_deleted = purge_old_security_audit(pool, &cutoff).await?;

    tracing::info!(
        infra_days,
        partition_days,
        "retention: infra window + partition-drop window (max across tenants)"
    );

    let summary = PurgeSummary {
        retention_days: infra_days,
        sessions_deleted: sessions.load(Ordering::Relaxed),
        audit_deleted: audit.load(Ordering::Relaxed),
        turns_deleted: turns.load(Ordering::Relaxed),
        messages_deleted: messages.load(Ordering::Relaxed),
        tool_definitions_deleted: tool_defs.load(Ordering::Relaxed),
        system_prompts_deleted: prompts.load(Ordering::Relaxed),
        history_chunks_deleted: chunks.load(Ordering::Relaxed),
        suggestions_deleted: suggestions.load(Ordering::Relaxed),
        media_blobs_deleted: media_blobs.load(Ordering::Relaxed),
        admin_audit_deleted: admin_audit.load(Ordering::Relaxed),
        portal_audit_deleted: portal_audit.load(Ordering::Relaxed),
        dead_keys_deleted: dead_keys.load(Ordering::Relaxed),
        security_audit_deleted,
        edge_stats_deleted,
        load_samples_deleted: load_samples.load(Ordering::Relaxed),
        partitions_dropped,
    };

    info!(?summary, "data retention purge complete");
    Ok(summary)
}

/// Run a retention purge cycle scoped to a single tenant (via RLS connection).
///
/// Unlike `run_purge` (which iterates every tenant on its own scoped connection),
/// this uses a tenant-scoped connection so RLS filters ensure only the
/// current tenant's data is deleted.
pub async fn run_purge_tenant(conn: &mut Scoped) -> Result<PurgeSummary, sqlx::Error> {
    run_purge_tenant_with_override(conn, None).await
}

/// Same as [`run_purge_tenant`] but substitutes `override_days` for the
/// tenant's configured `retention_days` when `Some`. Used by the cross-tenant
/// pressure path inside [`run_purge_with_override`].
pub async fn run_purge_tenant_with_override(
    conn: &mut Scoped,
    override_days: Option<i64>,
) -> Result<PurgeSummary, sqlx::Error> {
    let retention_days = match override_days {
        Some(d) => d,
        None => load_retention_days_conn(conn).await,
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);

    info!(retention_days, %cutoff, "starting tenant-scoped data retention purge");

    let mut summary = PurgeSummary {
        retention_days,
        ..Default::default()
    };

    // Sessions (not partitioned) — RLS filters to current tenant. Batched by
    // key like the stores below: each session's message membership goes with
    // it (cascade), one row per distinct message it carried.
    summary.sessions_deleted = batch_delete_conn(
        &mut *conn,
        "DELETE FROM sessions WHERE updated_at < $1 AND (tenant_id, session_id) IN \
         (SELECT tenant_id, session_id FROM sessions WHERE updated_at < $1 LIMIT $2)",
        &cutoff,
        crate::settings::admin_settings().retention_batch_size,
    )
    .await?;

    // Cross-session relations reference sessions BY VALUE (no FK), so purging a
    // member session above would otherwise leave stale members — drifting
    // `child_count` / `has_children` and growing the tables unbounded.
    // Reference-driven cleanup (RLS-scoped), run after the session delete:
    //  - a linkage is a pair, so drop the whole relation if EITHER endpoint is
    //    gone (its members cascade);
    //  - an issue spans a set, so drop only the purged `subject` members, then
    //    any relation left with none.
    let linkage_gone = sqlx::query(
        "DELETE FROM cross_session_relations r WHERE r.kind = 'linkage' \
         AND EXISTS (SELECT 1 FROM cross_session_relation_members m \
           WHERE m.relation_id = r.id \
           AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = m.session_id))",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM cross_session_relation_members m WHERE m.role = 'subject' \
         AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = m.session_id)",
    )
    .execute(&mut *conn)
    .await?;
    let issue_gone = sqlx::query(
        "DELETE FROM cross_session_relations r WHERE r.kind = 'issue' \
         AND NOT EXISTS (SELECT 1 FROM cross_session_relation_members m WHERE m.relation_id = r.id)",
    )
    .execute(&mut *conn)
    .await?;
    let relations_gone = linkage_gone.rows_affected() + issue_gone.rows_affected();
    if relations_gone > 0 {
        info!(relations_gone, "purged orphaned cross-session relations");
    }

    summary.audit_deleted =
        purge::expired_audit(&mut *conn, &cutoff, crate::settings::admin_settings().retention_batch_size).await?;
    summary.turns_deleted =
        purge::expired_turns(&mut *conn, &cutoff, crate::settings::admin_settings().retention_batch_size).await?;

    // The content stores, by stamp: a body no row inside the window still names.
    let stamp_cutoff = cutoff - chrono::Duration::days(CONTENT_STAMP_MARGIN_DAYS);
    let content = crate::content_store::purge::expired(
        &mut *conn,
        &stamp_cutoff,
        crate::settings::admin_settings().retention_batch_messages(),
    )
    .await?;
    summary.messages_deleted = content.messages;
    summary.tool_definitions_deleted = content.tool_definitions;
    summary.system_prompts_deleted = content.system_prompts;
    summary.history_chunks_deleted = content.history_chunks;
    summary.media_blobs_deleted = content.media_blobs;

    // Agent-generated suggestions — accumulate per analysis cycle, purge by age
    let prog_result = sqlx::query("DELETE FROM program_suggestions WHERE created_at < $1")
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;
    let tool_result = sqlx::query("DELETE FROM tool_rule_suggestions WHERE created_at < $1")
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;
    summary.suggestions_deleted = prog_result.rows_affected() + tool_result.rows_affected();

    // Admin-action audit log — operator mutations on /api/v1/admin/*. Plain
    // (non-partitioned) table; RLS-scoped DELETE on `at < cutoff`.
    let admin_audit_result = sqlx::query("DELETE FROM admin_audit WHERE at < $1")
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;
    summary.admin_audit_deleted = admin_audit_result.rows_affected();

    // Portal-action audit log — end-user mutations on /api/v1/portal/*. Plain
    // (non-partitioned) table; RLS-scoped DELETE on `at < cutoff`.
    let portal_audit_result = sqlx::query("DELETE FROM portal_audit WHERE at < $1")
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;
    summary.portal_audit_deleted = portal_audit_result.rows_affected();

    // Dead API keys — rows kept past revocation/expiry only for audit
    // linkage (gateway_audit.key_id is a soft reference). A key can't be
    // used after revocation/expiry, so once it has been dead for a full
    // retention window every audit row that could reference it has aged out
    // above and the row itself goes. Keeps per-run short-TTL CI keys from
    // accumulating forever. RLS-scoped like the sibling deletes.
    let dead_keys_result = sqlx::query(
        "DELETE FROM api_keys \
         WHERE revoked_at < $1 OR (revoked_at IS NULL AND expires_at < $1)",
    )
    .bind(cutoff)
    .execute(&mut *conn)
    .await?;
    summary.dead_keys_deleted = dead_keys_result.rows_affected();

    // Live load samples — the shorter of the tenant's window and the samples'
    // own horizon. Not partitioned, but batched by primary key like the
    // partitioned purges so the pattern cannot be copied onto one that is.
    let load_cutoff =
        cutoff.max(chrono::Utc::now() - chrono::Duration::days(LOAD_SAMPLE_RETENTION_DAYS));
    summary.load_samples_deleted = batch_delete_conn(
        &mut *conn,
        "DELETE FROM upstream_load_samples WHERE (tenant_id, id) IN \
         (SELECT tenant_id, id FROM upstream_load_samples WHERE sampled_at < $1 LIMIT $2)",
        &load_cutoff,
        crate::settings::admin_settings().retention_batch_size,
    )
    .await?;

    // Note: security_audit is global (non-RLS) and purged once on the raw pool
    // in run_purge_with_override — not here, where the connection is
    // tenant-scoped.

    // Note: partition DDL (drop_old_partitions) is not run here — that's
    // infrastructure-level and handled by the background retention task.

    info!(?summary, "tenant-scoped data retention purge complete");
    Ok(summary)
}

async fn load_retention_days_conn(conn: &mut Scoped) -> i64 {
    // A value that is not a positive number of days reads as unset: a zero or
    // negative window would put the cutoff at or past now and purge everything.
    // `retention_days_max()` (the partition sweep's window) ignores it the same way.
    load_setting_conn(conn, "retention_days")
        .await
        .filter(|days| (1..=RETENTION_DAYS_MAX).contains(days))
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// Load an integer setting from system_settings by key.
async fn load_setting_conn(conn: &mut Scoped, key: &str) -> Option<i64> {
    sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = $1",
    )
    .bind(key)
    .fetch_optional(&mut *conn)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.as_i64())
}

/// Ensure hourly partitions for `mcp_sse_events` cover the current + next
/// 4 hours. Hourly cadence (vs. the weekly pattern for audit) keeps
/// partition retention granular for the `Last-Event-ID` replay window
/// (configurable via `MCP_SSE_RETENTION_SECS`, default 1h).
pub async fn ensure_future_sse_event_partitions(pool: &Db) -> Result<(), sqlx::Error> {
    let mut conn = pool.maintenance(Maintenance::PartitionDdl).await?;
    use chrono::Timelike;
    let now = chrono::Utc::now();
    let now_hour_start = now
        .with_minute(0)
        .and_then(|d| d.with_second(0))
        .and_then(|d| d.with_nanosecond(0))
        .unwrap_or(now);

    for offset_hours in 0..=4i64 {
        let start_dt = now_hour_start + chrono::Duration::hours(offset_hours);
        let end_dt = start_dt + chrono::Duration::hours(1);
        let suffix = start_dt.format("%Y_%m_%d_%H").to_string();
        let partition_name = format!("mcp_sse_events_{suffix}");
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)",
        )
        .bind(&partition_name)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            let start = start_dt.format("%Y-%m-%d %H:00:00+00").to_string();
            let end = end_dt.format("%Y-%m-%d %H:00:00+00").to_string();
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS {partition_name} \
                 PARTITION OF mcp_sse_events \
                 FOR VALUES FROM ('{start}') TO ('{end}')"
            );
            match sqlx::query(sqlx::AssertSqlSafe(&*sql)).execute(&mut *conn).await {
                Ok(_) => info!(partition = %partition_name, "created hourly partition for mcp_sse_events"),
                Err(e) => warn!(
                    partition = %partition_name,
                    "failed to create hourly partition (data in DEFAULT?): {e}"
                ),
            }
        }
    }
    Ok(())
}

/// Drop hourly `mcp_sse_events` partitions older than `cutoff`. Mirrors the
/// pattern in `drop_old_partitions` but with hourly granularity — kept
/// separate so the daily mcp_audit cadence isn't conflated with the hourly
/// SSE-event cadence.
pub async fn drop_old_sse_event_partitions(
    pool: &Db,
    cutoff: &chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut conn = pool.maintenance(Maintenance::PartitionDdl).await?;
    let mut dropped = Vec::new();
    let parent = "mcp_sse_events";
    let default_name = format!("{parent}_default");
    let partitions: Vec<(String,)> = sqlx::query_as(
        "SELECT c.relname::text FROM pg_inherits i \
         JOIN pg_class c ON i.inhrelid = c.oid \
         JOIN pg_class p ON i.inhparent = p.oid \
         WHERE p.relname = $1 AND c.relname != $2",
    )
    .bind(parent)
    .bind(&default_name)
    .fetch_all(&mut *conn)
    .await?;

    for (partition_name,) in partitions {
        let bound_expr: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_expr(relpartbound, oid) FROM pg_class WHERE relname = $1",
        )
        .bind(&partition_name)
        .fetch_optional(&mut *conn)
        .await?;

        let Some(expr) = bound_expr else {
            continue;
        };
        // Parse "FOR VALUES FROM ('2026-...') TO ('YYYY-MM-DD HH:00:00...')"
        let Some(to_idx) = expr.find("TO ('") else {
            continue;
        };
        let date_start = to_idx + 5;
        // Length of "YYYY-MM-DD HH:00:00" is 19.
        if expr.len() < date_start + 19 {
            continue;
        }
        let dt_str = &expr[date_start..date_start + 19];
        let Ok(to_dt_naive) =
            chrono::NaiveDateTime::parse_from_str(dt_str, "%Y-%m-%d %H:%M:%S")
        else {
            continue;
        };
        let to_dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            to_dt_naive,
            chrono::Utc,
        );
        if to_dt < *cutoff {
            let is_ref = is_referenced(&mut conn, parent).await;
            if matches!(
                drop_partition(&mut conn, parent, is_ref, &partition_name).await,
                PartitionDrop::Dropped
            ) {
                dropped.push(partition_name);
            }
        }
    }
    Ok(dropped)
}

/// The longest a partition drop waits for its locks before giving way.
///
/// Dropping a partition takes an ACCESS EXCLUSIVE lock on its partitioned
/// parent, and a lock request queued behind a long statement on that parent (a
/// large analytics read, an app re-classification) blocks every statement
/// queued after it — every audit INSERT, for every tenant — until it is
/// granted. Keep this short: it is the longest ingestion can stall for one
/// drop attempt.
const PARTITION_DROP_LOCK_TIMEOUT: &str = "SET LOCAL lock_timeout = '2s'";

/// The longest any one statement of a drop attempt may run, lock wait included
/// — Postgres starts this clock with the statement, so it MUST stay well above
/// [`PARTITION_DROP_LOCK_TIMEOUT`]: were the two equal, a busy parent would
/// always surface as a statement timeout and never as the lock timeout that
/// means "give way". Once the lock is held, the rest of this budget bounds how
/// long ingestion queues behind the attempt. Detaching a partition that a
/// foreign key references runs a reference check against every referencing
/// table under the parent's ACCESS EXCLUSIVE lock; it fetches each dead tuple
/// of the partition from the heap, which is why [`drop_partition`] vacuums the
/// partition first (unvacuumed, 2M dead rows took 5.9 s; vacuumed, it meets an
/// empty relation).
const PARTITION_DROP_STATEMENT_TIMEOUT: &str = "SET LOCAL statement_timeout = '5s'";

/// What one [`drop_partition`] attempt did.
enum PartitionDrop {
    /// This sweep removed the partition.
    Dropped,
    /// It was already gone — a concurrent sweep removed it (a platform purge
    /// runs outside the retention leader lock).
    AlreadyGone,
    /// Left for the next sweep: busy, or refused.
    Left,
}

/// Drop one expired partition of `parent`, giving way to whatever holds the
/// parent: a lock not granted within [`PARTITION_DROP_LOCK_TIMEOUT`], or a
/// statement past [`PARTITION_DROP_STATEMENT_TIMEOUT`], leaves the partition
/// for the next sweep.
///
/// When a foreign key references `parent` (`llm_audit` → `gateway_audit`), the
/// partition is DETACHED before it is dropped: that constraint depends on every
/// partition of the referenced table, so a bare `DROP` of one is refused even
/// when it is empty. Never `DROP … CASCADE`, which would drop the foreign key
/// itself. The detach validates that no child row still points into the week
/// (with FORCE lifted on the referencing tables for this transaction, so the
/// owner sees every row) and refuses if one does — `23503`, logged as an error:
/// the children's week is dropped first and the per-tenant purge cascades from
/// `gateway_audit`, so a refusal means a row the sweep should have removed. A partition nothing references is dropped directly:
/// detaching one that holds a foreign key would first turn its inherited
/// constraint into a standalone one, only for the drop to remove it.
///
/// `referenced` is [`is_referenced`] for `parent`. `partition_name` must be a
/// catalog-derived identifier (read from `pg_inherits`) — it is spliced into
/// the DDL, which takes no bind.
async fn drop_partition(
    conn: &mut MaintenanceConn,
    parent: &'static str,
    referenced: bool,
    partition_name: &str,
) -> PartitionDrop {
    let attempt = async {
        if referenced {
            // The per-tenant purge has just emptied this week, leaving every
            // deleted row as a dead tuple: the detach's reference check would
            // fetch each one from the heap while holding the parent's ACCESS
            // EXCLUSIVE lock (measured: 5.9 s for 2M dead rows). Vacuum it
            // first, outside the drop transaction — VACUUM cannot run in one,
            // and it takes only a SHARE UPDATE EXCLUSIVE lock on this expired
            // partition, so ingestion never waits on it. SKIP_LOCKED: a
            // partition busy right now is vacuumed on a later sweep.
            let vacuum_sql = format!("VACUUM (ANALYZE, SKIP_LOCKED) {partition_name}");
            sqlx::query(sqlx::AssertSqlSafe(&*vacuum_sql))
                .execute(&mut **conn)
                .await?;
        }
        let mut tx = conn.begin().await?;
        sqlx::query(PARTITION_DROP_LOCK_TIMEOUT).execute(&mut *tx).await?;
        sqlx::query(PARTITION_DROP_STATEMENT_TIMEOUT).execute(&mut *tx).await?;
        if referenced {
            // The detach validates that no row of a referencing table still
            // points into the partition. Under FORCE RLS, as the owning runtime
            // role, RLS would hide every child row from that validation (and
            // PostgreSQL can fail it internally: "could not find tuple for
            // parent of relation …"). So, inside this transaction
            // only, the referencing tables that are FORCE drop it, which makes
            // the owner's validation see every row; FORCE is restored before
            // commit. The change is never visible to another session, and a
            // failure anywhere rolls it back with the rest.
            let forced: Vec<(String,)> = sqlx::query_as(
                "SELECT DISTINCT c.conrelid::regclass::text FROM pg_constraint c \
                 JOIN pg_class r ON r.oid = c.conrelid \
                 JOIN pg_class p ON p.oid = c.confrelid \
                 WHERE c.contype = 'f' AND c.conparentid = 0 AND p.relname = $1 \
                   AND r.relforcerowsecurity",
            )
            .bind(parent)
            .fetch_all(&mut *tx)
            .await?;
            for (table,) in &forced {
                let sql = format!("ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY");
                sqlx::query(sqlx::AssertSqlSafe(&*sql)).execute(&mut *tx).await?;
            }
            let detach_sql = format!("ALTER TABLE {parent} DETACH PARTITION {partition_name}");
            sqlx::query(sqlx::AssertSqlSafe(&*detach_sql)).execute(&mut *tx).await?;
            for (table,) in &forced {
                let sql = format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY");
                sqlx::query(sqlx::AssertSqlSafe(&*sql)).execute(&mut *tx).await?;
            }
        }
        let drop_sql = format!("DROP TABLE {partition_name}");
        sqlx::query(sqlx::AssertSqlSafe(&*drop_sql)).execute(&mut *tx).await?;
        tx.commit().await
    };
    match attempt.await {
        Ok(()) => {
            info!(partition = %partition_name, "dropped old partition");
            PartitionDrop::Dropped
        }
        // Removed by a concurrent sweep after this one listed it.
        Err(e) if sqlstate_is(&e, UNDEFINED_TABLE) => PartitionDrop::AlreadyGone,
        // Contention in any of its forms: a lock not granted in time, a
        // deadlock with a concurrent sweep or writer, or a multi-lock statement
        // whose combined waits ran past the statement bound. Give way.
        Err(e)
            if sqlstate_is(&e, LOCK_NOT_AVAILABLE)
                || sqlstate_is(&e, DEADLOCK_DETECTED)
                || sqlstate_is(&e, QUERY_CANCELED) =>
        {
            warn!(
                partition = %partition_name,
                "partition busy, drop left for the next retention sweep: {e}"
            );
            PartitionDrop::Left
        }
        Err(e) => {
            error!(partition = %partition_name, "failed to drop partition: {e}");
            PartitionDrop::Left
        }
    }
}

/// `lock_not_available`: what a statement returns when `lock_timeout` expires.
const LOCK_NOT_AVAILABLE: &str = "55P03";
/// `query_canceled`: what a statement returns when `statement_timeout` expires.
const QUERY_CANCELED: &str = "57014";
/// `deadlock_detected`: one side of a lock-order cycle, aborted by Postgres.
const DEADLOCK_DETECTED: &str = "40P01";
/// `undefined_table`: the partition is already gone.
const UNDEFINED_TABLE: &str = "42P01";

fn sqlstate_is(e: &sqlx::Error, code: &str) -> bool {
    e.as_database_error().and_then(|d| d.code()).is_some_and(|c| c == code)
}

/// Whether a foreign key references `parent`, so its partitions must be
/// detached before they can be dropped. Asked only for a partition that has
/// expired. A failed lookup answers "referenced": detaching first is correct
/// for every partition, only slower, and the sweep must not abort over it.
async fn is_referenced(conn: &mut MaintenanceConn, parent: &'static str) -> bool {
    let lookup: Result<bool, sqlx::Error> = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint c \
         JOIN pg_class p ON p.oid = c.confrelid \
         WHERE c.contype = 'f' AND p.relname = $1)",
    )
    .bind(parent)
    .fetch_one(&mut **conn)
    .await;
    lookup.unwrap_or_else(|e| {
        warn!(parent, "foreign-key lookup failed, detaching as if referenced: {e}");
        true
    })
}

/// Ensure the weekly partitions exist for the current week and the next
/// [`PARTITION_WEEKS_AHEAD`].
pub async fn ensure_future_partitions(pool: &Db) -> Result<(), sqlx::Error> {
    let mut conn = pool.maintenance(Maintenance::PartitionDdl).await?;
    let this_week = week_start(chrono::Utc::now().date_naive());

    for offset_weeks in 0..=PARTITION_WEEKS_AHEAD {
        let start = this_week + chrono::Days::new(7 * offset_weeks);
        let end = start + chrono::Days::new(7);
        let suffix = week_suffix(start);

        for table in PARTITIONED_BY_WEEK {
            let partition_name = format!("{table}_{suffix}");

            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1)",
            )
            .bind(&partition_name)
            .fetch_one(&mut *conn)
            .await?;

            if !exists {
                // Explicit UTC: a bare date would be read in the session's
                // time zone, and the week would not start at Monday 00:00 UTC.
                let sql = format!(
                    "CREATE TABLE IF NOT EXISTS {partition_name} \
                     PARTITION OF {table} \
                     FOR VALUES FROM ('{start} 00:00:00+00') TO ('{end} 00:00:00+00')"
                );
                match sqlx::query(sqlx::AssertSqlSafe(&*sql)).execute(&mut *conn).await {
                    Ok(_) => info!(table, partition = %partition_name, "created weekly partition"),
                    Err(e) => warn!(
                        table,
                        partition = %partition_name,
                        "failed to create partition (data in DEFAULT?): {e}"
                    ),
                }
            }
        }
    }
    Ok(())
}

/// The tables partitioned by week (Monday 00:00 UTC to the next Monday), in
/// creation order. [`drop_old_partitions`] drops the children before
/// `gateway_audit`, which they reference.
const PARTITIONED_BY_WEEK: [&str; 6] =
    ["gateway_audit", "llm_audit", "mcp_audit", "a2a_audit", "web_audit", "conversation_turns"];

/// How many weeks past the current one have their partition made ahead.
const PARTITION_WEEKS_AHEAD: u64 = 2;

/// The Monday that starts `date`'s week (UTC weeks: the partition bounds are
/// UTC midnights).
fn week_start(date: chrono::NaiveDate) -> chrono::NaiveDate {
    use chrono::Datelike;
    date - chrono::Days::new(u64::from(date.weekday().num_days_from_monday()))
}

/// A weekly partition's name suffix, `w<YYYY>_<MM>_<DD>` of its Monday — the
/// same for every table of one week, which is how [`drop_old_partitions`]
/// keeps a week's tables in lockstep.
fn week_suffix(monday: chrono::NaiveDate) -> String {
    format!("w{}", monday.format("%Y_%m_%d"))
}

// ---------------------------------------------------------------------------
// Internal purge functions
// ---------------------------------------------------------------------------

/// The platform-level window, from the SYSTEM tenant's `retention_days`.
///
/// Governs global-infra telemetry only (edge stats/instances, `security_audit`) —
/// none of which is tenant data. `system_settings` is RLS-scoped, so this reads on
/// a SYSTEM-scoped connection; an unscoped read would match zero rows.
async fn load_retention_days_platform(pool: &Db) -> i64 {
    let Ok(mut db) = pool.tenant(TenantId::SYSTEM).await else {
        return DEFAULT_RETENTION_DAYS;
    };
    load_retention_days_conn(db.conn()).await
}

/// The widest `retention_days` any tenant asks for, floored at the default.
///
/// This is the ONLY safe window for dropping a partition: a partition is physical
/// and holds every tenant's rows for its time range, so it may only be dropped once
/// it can hold no un-expired row for ANY tenant. Taking the platform default (or a
/// single tenant's value) here would physically destroy rows a longer-retention
/// tenant is still entitled to.
///
/// Errors propagate rather than falling back to a default: a window derived from an
/// incomplete tenant list could be too short, and a partition drop is irreversible.
async fn load_max_retention_days(pool: &Db) -> Result<i64, sqlx::Error> {
    let widest: Option<i64> = sqlx::query_scalar("SELECT retention_days_max()")
        .fetch_one(pool.global(Global::TenantIteration))
        .await?;
    Ok(widest.unwrap_or(DEFAULT_RETENTION_DAYS).max(DEFAULT_RETENTION_DAYS))
}

/// Delete `edge_stats_samples` rows older than the cutoff. Global-infrastructure
/// telemetry (not tenant-scoped) — pruned on the platform window alongside partition
/// DDL, by the same `retention_days` window. Batched (LIMIT + sleep) like the
/// tenant-scoped purges so a large backlog can't hold one long lock.
async fn purge_old_edge_stats(
    pool: &Db,
    cutoff: &chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    let batch = crate::settings::admin_settings().retention_batch_size;
    let mut total: u64 = 0;
    loop {
        // ctid batching is valid here ONLY because `edge_stats_samples` is a
        // plain (non-partitioned) table — on a partitioned table ctids repeat
        // across partitions and this pattern deletes unexpired rows (see the
        // PK-batched gateway_audit purge above).
        let result = sqlx::query(
            "DELETE FROM edge_stats_samples WHERE ctid IN \
             (SELECT ctid FROM edge_stats_samples WHERE sampled_at < $1 LIMIT $2)",
        )
        .bind(cutoff)
        .bind(batch)
        .execute(pool.global(Global::Infra))
        .await?;

        let deleted = result.rows_affected();
        total += deleted;
        if deleted < batch as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            crate::settings::admin_settings().retention_batch_sleep_ms,
        ))
        .await;
    }
    Ok(total)
}

/// Reap edge *instance* rows not seen since the retention cutoff — a process
/// whose store is gone never comes back under its id. `ON DELETE CASCADE` drops the
/// instance's `edge_stats_samples` and `usage_counter_watermarks` with it —
/// the spend each contributed is already folded into the persistent
/// `usage_counters` total, so dropping the watermark neither double-counts nor
/// loses spend. Keeps the edge fleet from accumulating a row per ephemeral
/// replica (K8s autoscale churn).
async fn reap_stale_edge_instances(
    pool: &Db,
    cutoff: &chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM edge_instances ei \
         WHERE COALESCE(ei.last_seen_at, ei.created_at) < $1",
    )
    .bind(cutoff)
    .execute(pool.global(Global::Infra))
    .await?;
    Ok(result.rows_affected())
}

/// Delete `security_audit` rows older than the cutoff. Global pre-auth security
/// log (no tenant scoping) — pruned on the platform window by
/// the same `retention_days` window. Batched like the other purges.
async fn purge_old_security_audit(
    pool: &Db,
    cutoff: &chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    let batch = crate::settings::admin_settings().retention_batch_size;
    let mut total: u64 = 0;
    loop {
        // ctid batching is valid here ONLY because `security_audit` is a
        // plain (non-partitioned) table — see the PK-batched gateway_audit
        // purge for the partitioned-table rule.
        let result = sqlx::query(
            "DELETE FROM security_audit WHERE ctid IN \
             (SELECT ctid FROM security_audit WHERE at < $1 LIMIT $2)",
        )
        .bind(cutoff)
        .bind(batch)
        .execute(pool.global(Global::Infra))
        .await?;

        let deleted = result.rows_affected();
        total += deleted;
        if deleted < batch as u64 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            crate::settings::admin_settings().retention_batch_sleep_ms,
        ))
        .await;
    }
    Ok(total)
}

/// Drop weekly partitions whose upper bound is before the cutoff. A partition
/// that cannot be dropped now ([`drop_partition`]) is left for the next sweep,
/// with the same week of every table after it.
async fn drop_old_partitions(
    pool: &Db,
    cutoff: &chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut conn = pool.maintenance(Maintenance::PartitionDdl).await?;
    let mut dropped = Vec::new();
    // Weeks a partition of was left in place (busy or failed): the same
    // week's partitions of the tables after it are left too, since a
    // `gateway_audit` partition cannot go while a child's rows reference it.
    let mut weeks_left: Vec<String> = Vec::new();

    // Drop in this order so the FKs from llm_audit / mcp_audit / a2a_audit /
    // web_audit -> gateway_audit don't block the parent partition
    // removal (children must go first).
    for parent_table in [
        "llm_audit",
        "mcp_audit",
        "a2a_audit",
        "web_audit",
        "gateway_audit",
        "conversation_turns",
    ] {
        let default_name = format!("{parent_table}_default");
        let partitions: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname::text FROM pg_inherits i \
             JOIN pg_class c ON i.inhrelid = c.oid \
             JOIN pg_class p ON i.inhparent = p.oid \
             WHERE p.relname = $1 AND c.relname != $2",
        )
        .bind(parent_table)
        .bind(&default_name)
        .fetch_all(&mut *conn)
        .await?;

        for (partition_name,) in partitions {
            // The upper bound of "FOR VALUES FROM ('…') TO ('…')", read as a
            // timestamptz by the server: its text carries the session's offset.
            let to_dt: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
                "SELECT (regexp_match(pg_get_expr(relpartbound, oid), 'TO \\(''([^'']+)''\\)'))[1]::timestamptz \
                 FROM pg_class WHERE relname = $1",
            )
            .bind(&partition_name)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();

            let Some(to_dt) = to_dt else { continue };
            if to_dt >= *cutoff {
                continue;
            }
            let week = partition_name
                .strip_prefix(parent_table)
                .unwrap_or(&partition_name)
                .to_string();
            if weeks_left.contains(&week) {
                continue;
            }
            let is_ref = is_referenced(&mut conn, parent_table).await;
            match drop_partition(&mut conn, parent_table, is_ref, &partition_name).await {
                PartitionDrop::Dropped => dropped.push(partition_name),
                PartitionDrop::AlreadyGone => {}
                PartitionDrop::Left => weeks_left.push(week),
            }
        }
    }

    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A turn kept by the purge (timestamp at or after the cutoff) names bodies
    /// whose stamp is at least its own timestamp less the renewal throttle and
    /// the edge's clock lead; such a body must never fall under the stamp
    /// cutoff. Both sides of the skew bound: inside it every kept turn's bodies
    /// survive, one day past it they do not — the margin is exactly what it
    /// claims, no more.
    #[test]
    fn a_stamped_body_survives_every_turn_still_in_the_window() {
        let renew = i64::from(STAMP_RENEW_DAYS);
        let skew_bound = CONTENT_STAMP_MARGIN_DAYS - renew;
        assert!(skew_bound >= 1, "the margin leaves no room for an edge clock running ahead");
        // Day numbers relative to the cutoff; the stamp cutoff is `-margin`.
        let survives = |turn_day: i64, skew: i64| {
            let oldest_stamp = turn_day - skew - renew;
            oldest_stamp >= -CONTENT_STAMP_MARGIN_DAYS
        };
        for turn_day in 0..30 {
            for skew in 0..=skew_bound {
                assert!(survives(turn_day, skew), "turn at +{turn_day}d, skew {skew}d");
            }
        }
        // The bound is exact: at it a turn on the cutoff keeps its bodies, one
        // day past it that turn loses them.
        assert!(survives(0, skew_bound), "at the skew bound the guarantee holds");
        assert!(!survives(0, skew_bound + 1), "past the skew bound the guarantee no longer holds");
    }

    #[test]
    fn a_week_starts_on_its_monday_and_is_named_for_it() {
        let day = |d: &str| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").expect("a date");
        // Monday is its own week's start; Sunday belongs to the Monday before,
        // across a month and a year boundary.
        assert_eq!(week_start(day("2026-10-12")), day("2026-10-12"));
        assert_eq!(week_start(day("2026-10-18")), day("2026-10-12"));
        assert_eq!(week_start(day("2026-11-01")), day("2026-10-26"));
        assert_eq!(week_start(day("2027-01-02")), day("2026-12-28"));
        assert_eq!(week_suffix(day("2026-12-28")), "w2026_12_28");
    }
}
