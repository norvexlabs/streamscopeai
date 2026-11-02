//! Leader-elected janitor for fleet-convergent usage counters.
//!
//! The hot-path merge (folding each edge's reported cumulative into the global
//! total) is leader-free — any admin instance applies its own edges' deltas to
//! the shared `usage_counters` rows. This janitor only garbage-collects rows for
//! windows that have fully elapsed, so the tables don't grow without bound. A
//! generous grace beyond the window length tolerates late heartbeats from an
//! edge that was briefly disconnected.

use crate::db::{Db, Global};
use streamscope_core::usage::UsageWindowKind;

/// Keep-for horizon of each window kind as seconds, bound as `$1` (minute),
/// `$2` (daily), `$3` (monthly) — the same horizon past which the merge
/// settles a report instead of merging it, so a restated counter never meets
/// a deleted watermark.
macro_rules! expired {
    () => {
        "(window_kind = 'minute'  AND window_start < now() - make_interval(secs => $1)) \
                    OR (window_kind = 'daily'   AND window_start < now() - make_interval(secs => $2)) \
                    OR (window_kind = 'monthly' AND window_start < now() - make_interval(secs => $3))"
    };
}

fn kept_for_secs(kind: UsageWindowKind) -> f64 {
    kind.kept_for_ms() as f64 / 1000.0
}

/// Delete `usage_counters` (per tenant, FORCE RLS) and `usage_counter_watermarks`
/// (global) rows whose window is past [`UsageWindowKind::kept_for_ms`].
pub async fn gc_elapsed_windows(pool: &Db) {
    // usage_counters is tenant-scoped + FORCE RLS, so a raw-pool DELETE without
    // `app.tenant_id` set would match zero rows. Run it under each tenant's GUC.
    let res = crate::db::tenant::for_each_tenant(pool, |mut db| async move {
        let r = sqlx::query(concat!("DELETE FROM usage_counters WHERE ", expired!()))
            .bind(kept_for_secs(UsageWindowKind::Minute))
            .bind(kept_for_secs(UsageWindowKind::Daily))
            .bind(kept_for_secs(UsageWindowKind::Monthly))
            .execute(db.conn())
            .await;
        if let Ok(r) = r
            && r.rows_affected() > 0
        {
            tracing::debug!(deleted = r.rows_affected(), "usage janitor: pruned counters");
        }
        Ok(())
    })
    .await;
    if let Err(e) = res {
        tracing::warn!("usage janitor: counter GC iterate tenants failed: {e}");
    }

    // Watermarks carry no RLS (edge-keyed bookkeeping) — one global DELETE.
    if let Err(e) = sqlx::query(concat!("DELETE FROM usage_counter_watermarks WHERE ", expired!()))
        .bind(kept_for_secs(UsageWindowKind::Minute))
        .bind(kept_for_secs(UsageWindowKind::Daily))
        .bind(kept_for_secs(UsageWindowKind::Monthly))
        .execute(pool.global(Global::Infra))
        .await
    {
        tracing::warn!("usage janitor: watermark GC failed: {e}");
    }
}
