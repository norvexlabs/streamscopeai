//! The content row deletes: the retention purge's stamp deletes and Wipe All
//! Data's. Tenant deletion removes a tenant's content by the `tenants` cascade.

use chrono::{DateTime, Utc};

use crate::batch_delete::batch_delete_conn;
use crate::db::tenant::Scoped;

/// How many rows of each content store a purge deleted.
pub(crate) struct ExpiredContent {
    pub(crate) messages: u64,
    pub(crate) tool_definitions: u64,
    pub(crate) system_prompts: u64,
    pub(crate) history_chunks: u64,
    pub(crate) media_blobs: u64,
}

/// Delete the tenant's bodies whose stamp is older than `stamp_cutoff` — a
/// body no row inside the window still names (every ingest that stores or
/// names one stamps it) — `batch` rows at a time, batched by primary key.
/// The outer `last_referenced_at < $1` re-checks the stamp on the row it
/// deletes: an ingest that renews it concurrently holds the row, and the
/// delete then sees the renewed stamp and leaves it.
pub(crate) async fn expired(
    conn: &mut Scoped,
    stamp_cutoff: &DateTime<Utc>,
    batch: i64,
) -> sqlx::Result<ExpiredContent> {
    let messages = batch_delete_conn(
        &mut *conn,
        "DELETE FROM conversation_messages WHERE last_referenced_at < $1 AND (tenant_id, hash) IN \
         (SELECT tenant_id, hash FROM conversation_messages WHERE last_referenced_at < $1 LIMIT $2)",
        stamp_cutoff,
        batch,
    )
    .await?;
    let tool_definitions = batch_delete_conn(
        &mut *conn,
        "DELETE FROM tool_definitions WHERE last_referenced_at < $1 AND (tenant_id, hash) IN \
         (SELECT tenant_id, hash FROM tool_definitions WHERE last_referenced_at < $1 LIMIT $2)",
        stamp_cutoff,
        batch,
    )
    .await?;
    let system_prompts = batch_delete_conn(
        &mut *conn,
        "DELETE FROM system_prompts WHERE last_referenced_at < $1 AND (tenant_id, hash) IN \
         (SELECT tenant_id, hash FROM system_prompts WHERE last_referenced_at < $1 LIMIT $2)",
        stamp_cutoff,
        batch,
    )
    .await?;
    let history_chunks = batch_delete_conn(
        &mut *conn,
        "DELETE FROM turn_history_chunks WHERE last_referenced_at < $1 AND (tenant_id, hash) IN \
         (SELECT tenant_id, hash FROM turn_history_chunks WHERE last_referenced_at < $1 LIMIT $2)",
        stamp_cutoff,
        batch,
    )
    .await?;
    let media_blobs = batch_delete_conn(
        &mut *conn,
        "DELETE FROM audit_media_blobs WHERE last_referenced_at < $1 AND (tenant_id, content_hash, blob_type) IN \
         (SELECT tenant_id, content_hash, blob_type FROM audit_media_blobs WHERE last_referenced_at < $1 LIMIT $2)",
        stamp_cutoff,
        batch,
    )
    .await?;
    Ok(ExpiredContent { messages, tool_definitions, system_prompts, history_chunks, media_blobs })
}

/// Wipe All Data's content deletes: every body of the connection's tenant, in
/// every content store; the caller runs them inside its wipe transaction.
/// `DELETE`, not `TRUNCATE`, so RLS confines each statement to that tenant.
/// Keep this list equal to the module's stores.
pub(crate) async fn wipe(conn: &mut Scoped) -> sqlx::Result<()> {
    for sql in [
        "DELETE FROM conversation_messages",
        "DELETE FROM tool_definitions",
        "DELETE FROM system_prompts",
        "DELETE FROM turn_history_chunks",
        "DELETE FROM audit_media_blobs",
    ] {
        sqlx::query(sql).execute(&mut *conn).await?;
    }
    Ok(())
}
