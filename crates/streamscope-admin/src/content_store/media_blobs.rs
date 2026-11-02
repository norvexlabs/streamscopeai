//! `audit_media_blobs`: one decoded media body per `(tenant_id, content_hash,
//! blob_type)`. A stored blob is never rewritten; only its stamp moves.

use streamscope_core::audit::BlobType;
use streamscope_edge_api::ingest::BlobRef;

use crate::db::tenant::{IngestConn, Scoped};

/// Insert media blobs (`{tenant_id, content_hash, blob_type, media_type,
/// data_base64}` elements, any tenants, decoded by the database). A blob
/// already stored keeps its bytes; either way it is stamped, which holds off
/// the stamp purge while the records that reference it are on their way.
pub(crate) async fn insert_blobs(conn: &mut IngestConn, payload: &serde_json::Value) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE audit_media_blobs c SET last_referenced_at = now() \
           FROM (SELECT DISTINCT (j->>'tenant_id')::uuid AS tenant_id, j->>'content_hash' AS content_hash, j->>'blob_type' AS blob_type FROM jsonb_array_elements($1) AS j) n \
          WHERE c.tenant_id = n.tenant_id AND c.content_hash = n.content_hash AND c.blob_type = n.blob_type \
            AND c.last_referenced_at < now() - make_interval(days => $2)",
    )
    .bind(payload)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO audit_media_blobs (tenant_id, content_hash, blob_type, media_type, data, size_bytes) \
         SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'content_hash', j->>'blob_type') \
                (j->>'tenant_id')::uuid, j->>'content_hash', j->>'blob_type', j->>'media_type', d.data, octet_length(d.data) \
           FROM jsonb_array_elements($1) AS j \
          CROSS JOIN LATERAL (SELECT decode(j->>'data_base64', 'base64') AS data) d \
         ON CONFLICT (tenant_id, content_hash, blob_type) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// Of the `(tenant, blob)` pairs in `named` (distinct, in key order) — blobs
/// shares name but do not carry — those not held; every held one with a stale
/// stamp is renewed first.
pub(crate) async fn missing_blobs(
    conn: &mut IngestConn,
    named: &[(uuid::Uuid, BlobRef)],
) -> Result<Vec<(uuid::Uuid, BlobRef)>, sqlx::Error> {
    let tenants: Vec<uuid::Uuid> = named.iter().map(|(t, _)| *t).collect();
    let hashes: Vec<&str> = named.iter().map(|(_, b)| b.content_hash.as_str()).collect();
    let types: Vec<&str> = named.iter().map(|(_, b)| b.blob_type.as_str()).collect();
    // Renewed first, then read: the renewal locks every stale row — the only
    // rows a stamp purge may take — for the rest of the transaction, so a purge
    // either finished before it (the blob is then not held, and asked for
    // again) or waits and re-checks the renewed stamp. A fresh row is read
    // without a lock.
    sqlx::query(
        "UPDATE audit_media_blobs b SET last_referenced_at = now() \
           FROM unnest($1::uuid[], $2::text[], $3::text[]) AS s(tenant_id, content_hash, blob_type) \
          WHERE b.tenant_id = s.tenant_id AND b.content_hash = s.content_hash AND b.blob_type = s.blob_type \
            AND b.last_referenced_at < now() - make_interval(days => $4)",
    )
    .bind(&tenants)
    .bind(&hashes)
    .bind(&types)
    .bind(crate::retention::STAMP_RENEW_DAYS)
    .execute(&mut *conn)
    .await?;
    let held: std::collections::HashSet<(uuid::Uuid, String, String)> = sqlx::query_as(
        "SELECT b.tenant_id, b.content_hash, b.blob_type FROM audit_media_blobs b \
           JOIN unnest($1::uuid[], $2::text[], $3::text[]) AS s(tenant_id, content_hash, blob_type) \
             ON b.tenant_id = s.tenant_id AND b.content_hash = s.content_hash AND b.blob_type = s.blob_type",
    )
    .bind(&tenants)
    .bind(&hashes)
    .bind(&types)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    Ok(named
        .iter()
        .filter(|(t, b)| !held.contains(&(*t, b.content_hash.clone(), b.blob_type.as_str().to_string())))
        .cloned()
        .collect())
}

/// Stamp one uploaded blob if the tenant already holds it; the result's
/// `rows_affected()` is 1 when it does, 0 when it does not.
pub(crate) async fn stamp_held(
    conn: &mut Scoped,
    tenant: uuid::Uuid,
    content_hash: &str,
    blob_type: BlobType,
) -> sqlx::Result<sqlx::postgres::PgQueryResult> {
    sqlx::query(
        "UPDATE audit_media_blobs SET last_referenced_at = now() WHERE tenant_id = $1 AND content_hash = $2 AND blob_type = $3",
    )
    .bind(tenant)
    .bind(content_hash)
    .bind(blob_type.as_str())
    .execute(&mut *conn)
    .await
}

/// Store one uploaded blob, stamped now; one already stored keeps its bytes and
/// is stamped. Nothing is written for a deleted tenant: the result's
/// `rows_affected()` is then 0.
pub(crate) async fn insert_uploaded(
    conn: &mut Scoped,
    tenant: uuid::Uuid,
    content_hash: &str,
    blob_type: BlobType,
    media_type: &str,
    data: &[u8],
) -> sqlx::Result<sqlx::postgres::PgQueryResult> {
    sqlx::query(
        "INSERT INTO audit_media_blobs (tenant_id, content_hash, blob_type, media_type, data, size_bytes, last_referenced_at) \
         SELECT $1, $2, $3, $4, $5, $6, now() WHERE EXISTS (SELECT 1 FROM tenants WHERE id = $1) \
         ON CONFLICT (tenant_id, content_hash, blob_type) DO UPDATE SET last_referenced_at = now()",
    )
    .bind(tenant)
    .bind(content_hash)
    .bind(blob_type.as_str())
    .bind(media_type)
    .bind(data)
    .bind(data.len() as i64)
    .execute(&mut *conn)
    .await
}

/// One blob's media type and bytes, by `(tenant, content_hash, blob_type)`;
/// `None` when the tenant holds no such blob.
pub(crate) async fn get(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    content_hash: &str,
    blob_type: BlobType,
) -> sqlx::Result<Option<(String, Vec<u8>)>> {
    sqlx::query_as(
        "SELECT media_type, data FROM audit_media_blobs \
         WHERE tenant_id = $1 AND content_hash = $2 AND blob_type = $3",
    )
    .bind(tenant_id)
    .bind(content_hash)
    .bind(blob_type.as_str())
    .fetch_optional(&mut *conn)
    .await
}
