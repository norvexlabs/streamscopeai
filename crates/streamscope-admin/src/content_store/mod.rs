//! The content stores: the bodies a fact names by hash — conversation messages,
//! tool-definition sets, system prompts and media blobs — and the history
//! chunks that list a turn's message hashes. This module holds the writes, the
//! deletes (all in `purge.rs`) and the keyed reads of those tables, so the
//! bodies can move out of Postgres (to object storage) behind it while their
//! key `(tenant_id, hash)`, size and stamp stay Postgres columns. A chunk's hash
//! array is a key list, not a body: chunks stay in Postgres whole.
//!
//! * The ingest's batch writers stamp before they insert (`last_referenced_at`),
//!   renewing a stamp only once it is `STAMP_RENEW_DAYS` old. The edge's blob
//!   upload is the exception: it stamps on every write, with no throttle, and
//!   stores and stamps in one statement (`media_blobs::insert_uploaded`).
//! * The purge deletes by stamp, never by asking what still references a body.
//! * A read is by `(tenant, key)`, the tenant bound explicitly, a batch of keys
//!   in one round trip (`get_many`). A reader outside the module selects the
//!   hashes a fact names (the `conversation_turns_resolved` view's
//!   `system_prompt_hash`, never its reassembled `system_prompt`) and reads
//!   the bodies here.
//!
//! Outside the module, `lint-content-access.sh` lists the only reads of a
//! content table: the counts and size sums that read no body. The trigram
//! search lookups are SQL functions and read the bodies they search in the
//! database, by design.

pub(crate) mod history_chunks;
pub(crate) mod media_blobs;
pub(crate) mod messages;
pub(crate) mod purge;
pub(crate) mod system_prompts;
pub(crate) mod tool_definitions;

use std::collections::HashSet;

use streamscope_edge_api::ingest::{BlobRef, ContentKey};

use crate::db::tenant::IngestConn;

/// A content-addressed store a turn names bodies in by hash.
#[derive(Clone, Copy)]
pub(crate) enum ContentStore {
    Messages,
    ToolDefinitions,
    SystemPrompts,
}

impl ContentStore {
    fn key(self, hash: &str) -> ContentKey {
        let hash = hash.to_string();
        match self {
            ContentStore::Messages => ContentKey::Message { hash },
            ContentStore::ToolDefinitions => ContentKey::ToolDefinition { hash },
            ContentStore::SystemPrompts => ContentKey::SystemPrompt { hash },
        }
    }
}

/// Renew the stamp of every (tenant, hash) body named here (each named once, in
/// key order) — only where it is
/// [`STAMP_RENEW_DAYS`](crate::retention::STAMP_RENEW_DAYS) old, so a body every turn names is not rewritten (and its row not
/// locked) on every turn. The retention sweep removes a body only once its
/// stamp is older than the window, so a body named inside it is never purged.
pub(crate) async fn stamp_content(
    conn: &mut IngestConn,
    store: ContentStore,
    named: &[(uuid::Uuid, String)],
) -> Result<(), sqlx::Error> {
    if named.is_empty() {
        return Ok(());
    }
    let (tenants, hashes): (Vec<uuid::Uuid>, Vec<&str>) = named.iter().map(|(t, h)| (*t, h.as_str())).unzip();
    // Each arm hands its own statement literal to `sqlx::query`, so the
    // ingest lint reads every one for its tenant predicate.
    let query = match store {
        ContentStore::Messages => sqlx::query(
            "UPDATE conversation_messages c SET last_referenced_at = now() \
               FROM unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
              WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
                AND c.last_referenced_at < now() - make_interval(days => $3)",
        ),
        ContentStore::ToolDefinitions => sqlx::query(
            "UPDATE tool_definitions c SET last_referenced_at = now() \
               FROM unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
              WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
                AND c.last_referenced_at < now() - make_interval(days => $3)",
        ),
        ContentStore::SystemPrompts => sqlx::query(
            "UPDATE system_prompts c SET last_referenced_at = now() \
               FROM unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
              WHERE c.tenant_id = n.tenant_id AND c.hash = n.hash \
                AND c.last_referenced_at < now() - make_interval(days => $3)",
        ),
    };
    query
        .bind(&tenants)
        .bind(&hashes)
        .bind(crate::retention::STAMP_RENEW_DAYS)
        .execute(&mut *conn)
        .await
        .map(|_| ())
}

/// Of the `(tenant, body)` pairs in `keys`, those not held — every tenant's
/// in one pass: one stamp and one read per store, the pairs handed over in
/// `(tenant, key)` order and the stores always in the same order. The order the
/// stamp locks rows in is its plan's, so two requests stamping the same rows
/// can still deadlock: the request is then retried once, and then written
/// share by share. Every held one with a stale stamp is renewed first, then
/// all are read: the renewal locks every stale row — the only rows a stamp
/// purge may take — for the rest of the transaction, so a purge either
/// finished before it (the body is then not held, and reported) or waits and
/// re-checks the renewed stamp. A fresh row is read without a lock.
pub(crate) async fn not_held(
    conn: &mut IngestConn,
    keys: &HashSet<(uuid::Uuid, ContentKey)>,
) -> Result<HashSet<(uuid::Uuid, ContentKey)>, sqlx::Error> {
    let (mut messages, mut tools, mut prompts) = (Vec::new(), Vec::new(), Vec::new());
    let mut blobs: Vec<(uuid::Uuid, BlobRef)> = Vec::new();
    for (tenant, key) in keys {
        match key {
            ContentKey::Message { hash } => messages.push((*tenant, hash.clone())),
            ContentKey::ToolDefinition { hash } => tools.push((*tenant, hash.clone())),
            ContentKey::SystemPrompt { hash } => prompts.push((*tenant, hash.clone())),
            ContentKey::Blob { content_hash, blob_type } => {
                blobs.push((*tenant, BlobRef { content_hash: content_hash.clone(), blob_type: *blob_type }))
            }
        }
    }
    let mut absent = HashSet::new();
    for (store, mut named) in
        [(ContentStore::Messages, messages), (ContentStore::ToolDefinitions, tools), (ContentStore::SystemPrompts, prompts)]
    {
        if named.is_empty() {
            continue;
        }
        named.sort();
        let held = held_hashes(conn, store, &named).await?;
        absent.extend(named.into_iter().filter(|n| !held.contains(n)).map(|(t, h)| (t, store.key(&h))));
    }
    if !blobs.is_empty() {
        blobs.sort_by(|a, b| (a.0, &a.1.content_hash, a.1.blob_type.as_str()).cmp(&(b.0, &b.1.content_hash, b.1.blob_type.as_str())));
        let missing = media_blobs::missing_blobs(conn, &blobs).await?;
        absent.extend(missing.into_iter().map(|(t, b)| (t, ContentKey::from(b))));
    }
    Ok(absent)
}

/// Of `named` (distinct, in key order), the pairs `store` holds, each stale
/// stamp renewed first ([`not_held`]).
async fn held_hashes(
    conn: &mut IngestConn,
    store: ContentStore,
    named: &[(uuid::Uuid, String)],
) -> Result<HashSet<(uuid::Uuid, String)>, sqlx::Error> {
    stamp_content(conn, store, named).await?;
    let (tenants, hashes): (Vec<uuid::Uuid>, Vec<&str>) = named.iter().map(|(t, h)| (*t, h.as_str())).unzip();
    // Each arm hands its own statement literal to `sqlx::query_as`, so the
    // ingest lint reads every one for its tenant predicate.
    let read = match store {
        ContentStore::Messages => sqlx::query_as(
            "SELECT c.tenant_id, c.hash FROM conversation_messages c \
               JOIN unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
                 ON c.tenant_id = n.tenant_id AND c.hash = n.hash",
        ),
        ContentStore::ToolDefinitions => sqlx::query_as(
            "SELECT c.tenant_id, c.hash FROM tool_definitions c \
               JOIN unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
                 ON c.tenant_id = n.tenant_id AND c.hash = n.hash",
        ),
        ContentStore::SystemPrompts => sqlx::query_as(
            "SELECT c.tenant_id, c.hash FROM system_prompts c \
               JOIN unnest($1::uuid[], $2::text[]) AS n(tenant_id, hash) \
                 ON c.tenant_id = n.tenant_id AND c.hash = n.hash",
        ),
    };
    let held: Vec<(uuid::Uuid, String)> = read.bind(&tenants).bind(&hashes).fetch_all(&mut *conn).await?;
    Ok(held.into_iter().collect())
}
