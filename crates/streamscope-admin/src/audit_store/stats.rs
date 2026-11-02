//! The fact reads behind the database statistics page: how much the content
//! stores deduplicate, counted against the turns and audit rows that name
//! their bodies.

use crate::db::tenant::Scoped;

/// `(unique messages, message references, stored bytes, projected bytes)`:
/// every turn records its history's length and stored size, so the logical
/// volume is a sum over turns, never a walk of their histories.
pub(crate) async fn message_dedup(conn: &mut Scoped) -> sqlx::Result<(i64, i64, i64, i64)> {
    sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT \
           (SELECT COUNT(*) FROM conversation_messages)::bigint, \
           (SELECT COALESCE(SUM(message_count), 0) FROM conversation_turns)::bigint, \
           (SELECT COALESCE(SUM(content_size), 0) FROM conversation_messages)::bigint, \
           (SELECT COALESCE(SUM(message_bytes), 0) FROM conversation_turns)::bigint",
    )
    .fetch_one(&mut *conn)
    .await
}

/// `(blobs, unique hashes, references, stored bytes)`: references counted where
/// the purge looks for them — the blob_ref blocks of a media call and the
/// entries of a chat's media summary.
pub(crate) async fn media_dedup(conn: &mut Scoped) -> sqlx::Result<(i64, i64, i64, i64)> {
    sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT \
           COUNT(*)::bigint, \
           COUNT(DISTINCT content_hash)::bigint, \
           (SELECT COUNT(*) FROM llm_audit la, \
                   jsonb_array_elements(coalesce(la.media_call -> 'input', '[]'::jsonb) \
                                        || coalesce(la.media_call -> 'output', '[]'::jsonb)) AS blk \
             WHERE la.media_call IS NOT NULL AND blk ->> 'type' = 'blob_ref')::bigint \
           + (SELECT COUNT(*) FROM llm_audit la, \
                     jsonb_array_elements(la.chat_media_summary) AS entry \
               WHERE jsonb_typeof(la.chat_media_summary) = 'array' AND entry ? 'content_hash')::bigint, \
           COALESCE(SUM(size_bytes), 0)::bigint \
         FROM audit_media_blobs",
    )
    .fetch_one(&mut *conn)
    .await
}

/// `(unique tool sets, references, stored bytes, projected bytes)`, references
/// counted across both `tools_available_hash` and `tools_effective_hash`.
pub(crate) async fn tool_definition_dedup(conn: &mut Scoped) -> sqlx::Result<(i64, i64, i64, i64)> {
    sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT \
           COUNT(*)::bigint, \
           COALESCE(SUM(refs.ref_count), 0)::bigint, \
           COALESCE(SUM(td.content_size), 0)::bigint, \
           COALESCE(SUM(td.content_size * refs.ref_count), 0)::bigint \
         FROM tool_definitions td \
         JOIN ( \
           SELECT hash, COUNT(*)::bigint AS ref_count FROM ( \
             SELECT tools_available_hash AS hash FROM conversation_turns \
               WHERE tools_available_hash IS NOT NULL \
             UNION ALL \
             SELECT tools_effective_hash AS hash FROM conversation_turns \
               WHERE tools_effective_hash IS NOT NULL \
           ) x GROUP BY hash \
         ) refs ON td.hash = refs.hash",
    )
    .fetch_one(&mut *conn)
    .await
}
