//! The fact row deletes: the retention purge's batched deletes, tenant
//! deletion's and Wipe All Data's. Every row delete of a fact is written here;
//! expiry by dropping whole weekly partitions is partition DDL, in
//! `retention.rs`.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::batch_delete::batch_delete_conn;
use crate::db::tenant::Scoped;

/// Delete the tenant's `gateway_audit` rows older than `cutoff` (their
/// children with them), `batch_size` at a time; the number deleted.
pub(crate) async fn expired_audit(
    conn: &mut Scoped,
    cutoff: &DateTime<Utc>,
    batch_size: i64,
) -> sqlx::Result<u64> {
    // Gateway audit (partitioned) — batched deletes, RLS-scoped. The FK on
    // llm_audit (and every kind-specific child) is ON DELETE CASCADE, so deleting
    // parent rows cleans the children.
    //
    // PARTITIONED tables MUST batch by primary key, never `WHERE ctid IN
    // (SELECT ctid …)`: a ctid is a physical (page, slot) position unique
    // only WITHIN one partition, so ctids harvested from expired rows in one
    // partition (e.g. the `_default` catch-all) also match — and delete —
    // unexpired rows sitting at the same positions in every other partition.
    // The outer `timestamp < $1` is redundant with the subquery but keeps
    // partition pruning on the outer side under every join strategy — without
    // it a hash-semijoin plan scans all partitions per batch.
    batch_delete_conn(
        conn,
        "DELETE FROM gateway_audit WHERE timestamp < $1 AND (tenant_id, request_id, timestamp) IN \
         (SELECT tenant_id, request_id, timestamp FROM gateway_audit WHERE timestamp < $1 LIMIT $2)",
        cutoff,
        batch_size,
    )
    .await
}

/// Delete the tenant's `conversation_turns` rows older than `cutoff`,
/// `batch_size` at a time; the number deleted.
pub(crate) async fn expired_turns(
    conn: &mut Scoped,
    cutoff: &DateTime<Utc>,
    batch_size: i64,
) -> sqlx::Result<u64> {
    // Conversation turns (partitioned) — batched deletes, RLS-scoped. Same
    // PK-batching + outer-pruning shape as `expired_audit`.
    batch_delete_conn(
        conn,
        "DELETE FROM conversation_turns WHERE timestamp < $1 AND (tenant_id, request_id, timestamp) IN \
         (SELECT tenant_id, request_id, timestamp FROM conversation_turns WHERE timestamp < $1 LIMIT $2)",
        cutoff,
        batch_size,
    )
    .await
}

/// Delete every fact row of `tenant_id`, before the tenant row itself: the
/// partitioned tables are not reached by the `tenants` CASCADE. Turns first,
/// then `gateway_audit` (its children cascade from it).
pub(crate) async fn delete_tenant_facts(conn: &mut Scoped, tenant_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM conversation_turns WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

    sqlx::query("DELETE FROM gateway_audit WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Wipe All Data's fact deletes: every turn, then every `gateway_audit` row
/// (its children cascade). A DELETE, not a TRUNCATE, so RLS confines it to the
/// connection's tenant.
pub(crate) async fn wipe_facts(conn: &mut Scoped) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM conversation_turns")
        .execute(&mut *conn)
        .await?;

    // Cascade FK on llm_audit takes care of the child rows.
    sqlx::query("DELETE FROM gateway_audit")
        .execute(&mut *conn)
        .await?;
    Ok(())
}
