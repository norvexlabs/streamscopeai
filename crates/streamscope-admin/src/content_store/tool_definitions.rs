//! `tool_definitions`: one declared tool set (the client's `tools` array, in
//! its own protocol's shape) per `(tenant_id, hash)`.

use std::collections::HashMap;

use crate::db::tenant::{IngestConn, Scoped};

/// Insert content-addressed tool-definition sets (`{tenant_id, hash,
/// definition, content_size}` elements, any tenants); a set already stored is
/// left as it is, and stamped.
pub(crate) async fn insert_tool_definitions_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE tool_definitions c SET last_referenced_at = now() \
           FROM (SELECT DISTINCT (j->>'tenant_id')::uuid AS tenant_id, j->>'hash' AS hash FROM jsonb_array_elements($1) AS j) n \
          WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
            AND c.last_referenced_at < now() - make_interval(days => $2)",
    )
    .bind(payload)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO tool_definitions (tenant_id, hash, definition, content_size) \
         SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'hash') \
                (j->>'tenant_id')::uuid, j->>'hash', j->'definition', COALESCE((j->>'content_size')::int, 0) \
         FROM jsonb_array_elements($1) AS j \
         ON CONFLICT (tenant_id, hash) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// One tool set and its stored size, by `(tenant, hash)`; `None` when the
/// tenant holds no such set.
pub(crate) async fn get(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    hash: &str,
) -> sqlx::Result<Option<(serde_json::Value, i32)>> {
    sqlx::query_as("SELECT definition, content_size FROM tool_definitions WHERE tenant_id = $1 AND hash = $2")
        .bind(tenant_id)
        .bind(hash)
        .fetch_optional(&mut *conn)
        .await
}

/// The tool sets of `tenant_id` named by `hashes`, by hash, in one round trip.
/// A hash the tenant holds no set for is absent from the map.
pub(crate) async fn get_many(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    hashes: &[String],
) -> sqlx::Result<HashMap<String, serde_json::Value>> {
    if hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT hash, definition FROM tool_definitions WHERE tenant_id = $1 AND hash = ANY($2::text[])",
    )
    .bind(tenant_id)
    .bind(hashes)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}

/// How many tool sets [`for_each`] holds at once. A client that declares a
/// large set and changes it every turn stores one per turn, so a reader that
/// needs many sets walks them by chunk, keeping only what it takes from each.
pub(crate) const SET_CHUNK: usize = 16;

/// Visit the tool sets of `tenant_id` named by `hashes`, read [`SET_CHUNK`] at
/// a time; a set is dropped once visited. A hash the tenant holds no set for
/// is not visited.
pub(crate) async fn for_each(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    hashes: &[String],
    mut visit: impl FnMut(&str, &serde_json::Value),
) -> sqlx::Result<()> {
    for chunk in hashes.chunks(SET_CHUNK) {
        for (hash, set) in get_many(&mut *conn, tenant_id, chunk).await? {
            visit(&hash, &set);
        }
    }
    Ok(())
}
