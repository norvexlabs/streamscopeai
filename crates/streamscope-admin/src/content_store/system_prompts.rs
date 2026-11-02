//! `system_prompts`: one system prompt per `(tenant_id, hash)`.

use std::collections::HashMap;

use crate::db::tenant::{IngestConn, Scoped};

/// Store system prompts (`{tenant_id, hash, prompt, content_size}` elements,
/// any tenants, in key order); a prompt already stored is left as it is, and
/// stamped.
pub(crate) async fn insert_prompts_jsonb(conn: &mut IngestConn, payload: &serde_json::Value) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE system_prompts c SET last_referenced_at = now() \
           FROM (SELECT DISTINCT (j->>'tenant_id')::uuid AS tenant_id, j->>'hash' AS hash FROM jsonb_array_elements($1) AS j) n \
          WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
            AND c.last_referenced_at < now() - make_interval(days => $2)",
    )
    .bind(payload)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO system_prompts (tenant_id, hash, prompt, content_size) \
         SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'hash') \
                (j->>'tenant_id')::uuid, j->>'hash', j->>'prompt', COALESCE((j->>'content_size')::int, 0) \
           FROM jsonb_array_elements($1) AS j \
         ON CONFLICT (tenant_id, hash) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// The system prompts of `tenant_id` named by `hashes`, by hash, in one round
/// trip. A hash the tenant holds no prompt for is absent from the map.
pub(crate) async fn get_many(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    hashes: &[String],
) -> sqlx::Result<HashMap<String, String>> {
    if hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT hash, prompt FROM system_prompts WHERE tenant_id = $1 AND hash = ANY($2::text[])",
    )
    .bind(tenant_id)
    .bind(hashes)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}
