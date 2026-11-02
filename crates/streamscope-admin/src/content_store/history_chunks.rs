//! `turn_history_chunks`: a history's message hashes, in chained chunks keyed
//! by `(tenant_id, hash)`. A chunk holds keys, not bodies, so it stays in
//! Postgres wherever the bodies live.

use crate::db::tenant::IngestConn;

/// Store history chunks (`{tenant_id, hash, parent_hash, hashes}` elements, any
/// tenants, in key order); a chunk already stored is left as it is, and stamped.
pub(crate) async fn insert_chunks_jsonb(conn: &mut IngestConn, payload: &serde_json::Value) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE turn_history_chunks c SET last_referenced_at = now() \
           FROM (SELECT DISTINCT (j->>'tenant_id')::uuid AS tenant_id, j->>'hash' AS hash FROM jsonb_array_elements($1) AS j) n \
          WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
            AND c.last_referenced_at < now() - make_interval(days => $2)",
    )
    .bind(payload)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO turn_history_chunks (tenant_id, hash, parent_hash, hashes) \
         SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'hash') \
                (j->>'tenant_id')::uuid, j->>'hash', j->>'parent_hash', \
                ARRAY(SELECT jsonb_array_elements_text(j->'hashes')) \
           FROM jsonb_array_elements($1) AS j \
         ON CONFLICT (tenant_id, hash) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}
