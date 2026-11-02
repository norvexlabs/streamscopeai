//! `conversation_messages`: one message body per `(tenant_id, hash)`.

use std::collections::HashMap;

use crate::db::tenant::{IngestConn, Scoped};

/// Insert content-addressed conversation messages (`{tenant_id, hash, message,
/// content_size}` elements, any tenants); a message already stored is left as
/// it is, and stamped.
pub(crate) async fn insert_messages_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE conversation_messages c SET last_referenced_at = now() \
           FROM (SELECT DISTINCT (j->>'tenant_id')::uuid AS tenant_id, j->>'hash' AS hash FROM jsonb_array_elements($1) AS j) n \
          WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
            AND c.last_referenced_at < now() - make_interval(days => $2)",
    )
    .bind(payload)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO conversation_messages (tenant_id, hash, message, content_size) \
         SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'hash') \
                (j->>'tenant_id')::uuid, j->>'hash', j->'message', COALESCE((j->>'content_size')::int, 0) \
         FROM jsonb_array_elements($1) AS j \
         ON CONFLICT (tenant_id, hash) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// The messages of `tenant_id` named by `hashes`, by hash, in one round trip.
/// A hash the tenant holds no message for is absent from the map; a caller
/// rendering a history walks its own hash list, so a hash it names twice is
/// rendered twice.
pub(crate) async fn get_many(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    hashes: &[String],
) -> sqlx::Result<HashMap<String, serde_json::Value>> {
    if hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT hash, message FROM conversation_messages WHERE tenant_id = $1 AND hash = ANY($2::text[])",
    )
    .bind(tenant_id)
    .bind(hashes)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}
