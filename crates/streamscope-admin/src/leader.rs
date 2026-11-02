//! Leader election and distributed coordination for multi-instance admin-api.
//!
//! Uses PostgreSQL advisory locks for leader election. Each background task
//! (retention, agent, …) acquires its own advisory lock — only the holder runs.
//! Callers call [`release_leader`] after work completes. Dropping the connection
//! instead releases the lock too — the pool's `after_release` unlocks every
//! session advisory lock on a returned connection, and drops one it cannot reset.
//! On process crash the PG connection closes, auto-releasing the lock (instant
//! failover).

use crate::db::{Db, Maintenance, MaintenanceConn, Global};

// Advisory lock IDs — arbitrary constants in the 737xxx range to avoid collisions.
pub const LOCK_RETENTION: i64 = 737002;
pub const LOCK_AGENT: i64 = 737003;
/// Leader-elected sweeper that reaps expired
/// `mcp_pending_authorizations` rows. Cadence is fixed at 5 minutes.
pub const LOCK_MCP_OAUTH_CLEANUP: i64 = 737004;
/// Leader-elected worker that periodically re-discovers and mirrors models for
/// upstream servers marked `auto_sync_enabled`. Cadence is the
/// `MODEL_AUTOSYNC_INTERVAL_HOURS` setting; per-server due-ness gates the work.
pub const LOCK_MODEL_AUTOSYNC: i64 = 737005;
/// Leader-elected janitor that garbage-collects elapsed-window fleet usage
/// counters + watermarks (see [`crate::usage_rollup`]). Cadence is the
/// `USAGE_JANITOR_INTERVAL_SECS` setting. The hot-path merge is leader-free
/// (any instance folds its own edges' reports into the shared total); only this
/// GC needs single-runner election.
pub const LOCK_USAGE_JANITOR: i64 = 737006;

/// Leader-elected alert dispatcher (see [`crate::alerts`]). Evaluates budget
/// crossings into the generic `notifications` table and delivers `pending`
/// rows to the configured channels. Single-runner so an alarm fires once
/// fleet-wide; the `UNIQUE (tenant_id, dedup_key)` constraint is the
/// correctness backstop. Cadence is `ALERT_DISPATCH_INTERVAL_SECS`, also woken
/// on demand by `pg_notify('notify_pending')`.
pub const LOCK_ALERTS: i64 = 737007;

/// Leader-elected appliance upgrade-check worker. Polls the Kairos host daemon
/// for a newer OS version and raises a deduped `ApplianceUpgradeAvailable`
/// notification. Single-runner so the check fires once fleet-wide (N=1 on the
/// VM appliance anyway). Inert unless `STOWAGE_HOST_SOCKET` is set.
pub const LOCK_APPLIANCE_UPGRADE: i64 = 737008;

/// Leader-elected startup seed reconcile (see [`crate::seed_scripts`]). The
/// pass merges the shipped `seeds/` tree into every existing tenant's builtin
/// rows, so its writes are identical on every instance — without election, N
/// replicas each rewrite all tenants and contend on the same rows, and they do
/// it simultaneously on a rolling upgrade (every replica boots at once, and a
/// new build invalidates every tenant's seed stamp). Runs once at startup, not
/// on a cadence. A non-leader instance skips the pass entirely: the leader's
/// writes are shared state, and a tenant is stamped only after a clean pass, so
/// an instance that loses the race has nothing to do.
pub const LOCK_SEED_SYNC: i64 = 737009;
/// Taken per transaction (`pg_advisory_xact_lock`) by every `edge_events`
/// insert, so event ids are assigned in commit order.
pub const LOCK_EDGE_EVENTS: i64 = 737010;
/// Taken at commit by every transaction that bumped a config resource
/// (`config_bump_commit` in migration 020 spells the number), so bump ids are
/// assigned in commit order.
pub const LOCK_CONFIG_BUMPS: i64 = 737011;

/// Try to acquire a session-level advisory lock on a dedicated connection.
///
/// Returns the connection if the lock was acquired; the lock lives as long as the
/// caller holds it. Release it with [`release_leader`] when done.
pub async fn try_acquire_leader(
    pool: &Db,
    lock_id: i64,
) -> Option<MaintenanceConn> {
    let mut conn = match pool.maintenance(Maintenance::LeaderLock).await {
        Ok(c) => c,
        Err(_) => return None,
    };
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(false);
    if acquired { Some(conn) } else { None }
}

/// Release a leader lock and return the connection to the pool.
///
/// The explicit unlock frees the lock at once; should it fail, returning the
/// connection still frees it (the pool's `after_release` unlocks every session
/// advisory lock, and drops a connection it cannot reset).
pub async fn release_leader(mut conn: MaintenanceConn, lock_id: i64) {
    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)").bind(lock_id).execute(&mut *conn).await {
        tracing::warn!(lock_id, "advisory unlock failed — the pool releases it on return: {e}");
    }
}

/// Insert a manual agent trigger request.
pub async fn insert_agent_trigger(pool: &Db, tenant_id: Option<uuid::Uuid>) {
    let _ = sqlx::query(
        "INSERT INTO agent_trigger_requests (tenant_id) VALUES ($1)",
    )
    .bind(tenant_id)
    .execute(pool.global(Global::Infra))
    .await;
}

/// Check if there are pending agent trigger requests and drain them.
/// Returns tenant IDs (None = all tenants).
pub async fn drain_agent_triggers(pool: &Db) -> Vec<Option<uuid::Uuid>> {
    sqlx::query_scalar::<_, Option<uuid::Uuid>>(
        "DELETE FROM agent_trigger_requests RETURNING tenant_id",
    )
    .fetch_all(pool.global(Global::Infra))
    .await
    .unwrap_or_default()
}

/// Check if any agent trigger requests exist (cheap EXISTS check).
pub async fn has_agent_triggers(pool: &Db) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM agent_trigger_requests)",
    )
    .fetch_one(pool.global(Global::Infra))
    .await
    .unwrap_or(false)
}
