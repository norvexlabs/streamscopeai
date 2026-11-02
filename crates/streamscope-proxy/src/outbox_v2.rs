//! The edge's durable outbox for `POST /api/v2/edge/ingest`.
//!
//! Every record the proxy produces is written here first and leaves only when
//! admin-api has answered the share that carried it. The schema is built for
//! share assembly: one `records` table for every kind (one row per record,
//! unique on its natural key), the content-addressed `content` the records
//! point at, and `refs` naming, per record, the content it needs.
//!
//! Invariants to preserve:
//! - **Content never leaves before its last referencing record has
//!   committed**: a share carries its records' content with them, and content
//!   is deleted only when no remaining `refs` row names it.
//! - **A record's `refs` are every body it needs, whether or not a content
//!   row holds it**: for an LLM turn, exactly what its stored body names
//!   ([`Record::content_keys`] — so a turn stripped to fit names, and needs,
//!   less). A share accounts for each: carried, left out (admin-api acked
//!   it), or named in `unavailable` (neither acked nor held in a content
//!   row) — admin-api checks every key a record names, asks again for any it
//!   does not hold and the share does not name unavailable, and writes nothing
//!   until then.
//! - **Only a share admin-api committed is an ack**, and an ack is forgotten
//!   the moment admin-api names its body missing: an acked body admin-api
//!   lacks is always asked for, and carried again if a row holds it.
//! - **A share is deleted only on an outcome that says it can never be
//!   stored again differently** (`Committed`, `Rejected`, `TenantDeleted`);
//!   `Retry` and a transport failure keep everything.
//! - The persisted `process_epoch` counter only grows: every process start
//!   takes the next value.


use std::collections::BTreeSet;
use std::str::FromStr;

use streamscope_core::audit::BlobType;
use streamscope_edge_api::ingest::{
    BlobContent, BlobRef, Content, ContentKey, MessageContent, Record, RecordKind, SHARE_BUDGET_BYTES, ShareOutcome,
    TenantShare,
};
use streamscope_edge_api::sync::Epoch;

/// The shape of what the store holds, in its file's name: two builds of
/// different shapes never share a store, whichever order they run in. Bump it
/// whenever a buffered row would not read, or would not ship, the way this
/// build reads and ships it.
const STORE_VERSION: u32 = 2;
/// Every outbox file's name starts with this; this build's is
/// [`store_file`].
const STORE_PREFIX: &str = "outbox_v2";
/// Held for the life of the process, whatever the store's version: one
/// process per data directory.
const LOCK_FILE: &str = "outbox_v2.db.lock";

/// This build's outbox file, beside the persisted config.
pub(crate) fn store_file() -> String {
    format!("{STORE_PREFIX}.s{STORE_VERSION}.db")
}

/// The store version an outbox file named `name` holds:
/// `outbox_v2.s<version>.db` holds its version. Nothing else in the data
/// directory is a store — a copy an operator left beside it
/// (`outbox_v2.s1.bak.db`) included.
fn store_version(name: &str) -> Option<u32> {
    let v = name.strip_prefix(STORE_PREFIX)?.strip_prefix(".s")?.strip_suffix(".db")?;
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// Name every other build's outbox file in `data_dir`, which this build
/// never serves from: its records reach admin-api only if the build that wrote
/// it runs here again (a rollback), so a store holding any is left for that and
/// named, with its count, on every start. One that holds none is removed — it
/// has nothing to deliver. A store that cannot be read is left and named.
async fn note_other_stores(data_dir: &str) {
    let Ok(entries) = std::fs::read_dir(data_dir) else { return };
    let current = store_file();
    let names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| store_version(name).is_some() && *name != current)
        .collect();
    for name in names {
        let path = format!("{data_dir}/{name}");
        match count_records(&path).await {
            Ok(0) => {
                // The database file last: a journal left beside a missing
                // database would be recovered into one created under its name.
                for suffix in ["-wal", "-shm", "-journal", ""] {
                    match std::fs::remove_file(format!("{path}{suffix}")) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            tracing::warn!(file = %name, "another build's empty edge outbox could not be removed: {e}");
                            break;
                        }
                    }
                }
            }
            Ok(records) => tracing::warn!(
                file = %name, records,
                "another build's edge outbox holds undelivered records — they reach admin-api only if that build runs here again"
            ),
            Err(e) => tracing::warn!(file = %name, "another build's edge outbox could not be read, left in place: {e}"),
        }
    }
}

/// How many records the outbox store at `path` holds, its journal included.
async fn count_records(path: &str) -> Result<i64, anyhow::Error> {
    use sqlx::Connection;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(path).create_if_missing(false);
    let mut conn = sqlx::sqlite::SqliteConnection::connect_with(&options).await?;
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM records").fetch_one(&mut conn).await?;
    conn.close().await?;
    Ok(n)
}

/// SQLite's bound-parameter limit is 999; id lists are chunked under it.
const ID_CHUNK: usize = 500;
/// Records evicted per pass while over the size cap.
const EVICT_CHUNK: i64 = 64;
/// An ack no share named for this long is forgotten: a body named again
/// after it is carried once more. It bounds the acks to the bodies of
/// sessions active within it.
const ACK_TTL_MS: i64 = 24 * 3600 * 1000;
/// Acks deleted per statement.
const ACK_SWEEP_CHUNK: i64 = 5000;
/// An ack is renewed at most once per this, so a session's history is not
/// rewritten into the table on every turn.
const ACK_RENEW_MS: i64 = 3600 * 1000;
/// The most one share may weigh when it is a request's only share: what the
/// request may carry, less room for its envelope. Content past it is shed for
/// good, so the bound is fixed — a caller whose request is otherwise full
/// leaves its own parts out for that request rather than lowering it.
const LONE_SHARE_MAX_BYTES: usize = streamscope_edge_api::ingest::INGEST_REQUEST_MAX_BYTES - 2 * 1024 * 1024;

/// A pool on the outbox file, created if missing.
async fn connect(path: &str) -> Result<sqlx::SqlitePool, anyhow::Error> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        // `refs` rows cascade from their record.
        .foreign_keys(true);
    Ok(sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(crate::settings::proxy_settings().sqlite_pool_size)
        .connect_with(options)
        .await?)
}

/// Read back a stored row under the bound it was admitted with
/// ([`EDGE_ENVELOPE_MAX_DEPTH`](streamscope_core::edge_wire::EDGE_ENVELOPE_MAX_DEPTH)),
/// not serde_json's default of 128 — a record the outbox accepted must read.
fn read_stored<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    let text = std::str::from_utf8(body).map_err(|e| e.to_string())?;
    streamscope_core::edge_wire::from_str_bounded(text).map_err(|e| e.to_string())
}

/// One piece of content a record needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentRef {
    Message(String),
    ToolDefinition(String),
    SystemPrompt(String),
    Blob(BlobRef),
}

impl ContentRef {
    /// `(kind, hash)` as stored in `content` / `refs`.
    fn key(&self) -> (String, String) {
        match self {
            ContentRef::Message(h) => ("message".into(), h.clone()),
            ContentRef::ToolDefinition(h) => ("tool_definition".into(), h.clone()),
            ContentRef::SystemPrompt(h) => ("system_prompt".into(), h.clone()),
            ContentRef::Blob(b) => (format!("blob:{}", b.blob_type.as_str()), b.content_hash.clone()),
        }
    }

    fn from_key(kind: &str, hash: String) -> Option<Self> {
        match kind {
            "message" => Some(ContentRef::Message(hash)),
            "tool_definition" => Some(ContentRef::ToolDefinition(hash)),
            "system_prompt" => Some(ContentRef::SystemPrompt(hash)),
            _ => {
                let blob_type = BlobType::from_str(kind.strip_prefix("blob:")?).ok()?;
                Some(ContentRef::Blob(BlobRef { content_hash: hash, blob_type }))
            }
        }
    }

    /// As the wire names it.
    fn content_key(self) -> ContentKey {
        match self {
            ContentRef::Message(hash) => ContentKey::Message { hash },
            ContentRef::ToolDefinition(hash) => ContentKey::ToolDefinition { hash },
            ContentRef::SystemPrompt(hash) => ContentKey::SystemPrompt { hash },
            ContentRef::Blob(b) => ContentKey::from(b),
        }
    }

    fn from_content_key(key: &ContentKey) -> Self {
        match key {
            ContentKey::Message { hash } => ContentRef::Message(hash.clone()),
            ContentKey::ToolDefinition { hash } => ContentRef::ToolDefinition(hash.clone()),
            ContentKey::SystemPrompt { hash } => ContentRef::SystemPrompt(hash.clone()),
            ContentKey::Blob { content_hash, blob_type } => {
                ContentRef::Blob(BlobRef { content_hash: content_hash.clone(), blob_type: *blob_type })
            }
        }
    }
}

/// `(kind, hash)` of the content row and `refs` rows a wire key names.
fn row_key(key: &ContentKey) -> (String, String) {
    ContentRef::from_content_key(key).key()
}

/// What a record's keys add to a share at most: every body it names named as a
/// key, none carried. A record is stored only when it and this fit
/// [`CONTENT_MAX_BYTES`](streamscope_edge_api::ingest::CONTENT_MAX_BYTES), so
/// once its content is shed it fits a request on its own.
fn key_cost(record: &Record) -> usize {
    record.content_keys().iter().map(|k| { let (kind, hash) = row_key(k); key_bytes(&kind, &hash) }).sum()
}

/// What naming the content row `(kind, hash)` in `unavailable` adds
/// to a share: its key on the wire (`{"kind":"<kind>","hash":"<hash>"}`, or
/// `{"kind":"blob","content_hash":"<hash>","blob_type":"<type>"}`), and the
/// comma before it. Counted, not serialized: a hash is hex, which JSON writes
/// as it is (locked by `key_bytes_is_the_keys_length_on_the_wire`).
fn key_bytes(kind: &str, hash: &str) -> usize {
    let key = match kind.strip_prefix("blob:") {
        Some(blob_type) => r#"{"kind":"blob","content_hash":"","blob_type":""}"#.len() + blob_type.len(),
        None => r#"{"kind":"","hash":""}"#.len() + kind.len(),
    };
    key + hash.len() + 1
}

/// A record to enqueue. The content it needs is read off it as stored
/// ([`Record::content_keys`]).
pub struct Enqueued {
    pub record: Record,
}

/// A share assembled from the outbox, with what its outcome applies to.
#[derive(Debug)]
pub struct PendingShare {
    pub share: TenantShare,
    /// The outbox rows of its records.
    record_ids: Vec<i64>,
    /// The content it carries, holds or names unavailable, as `(kind, hash)`.
    content_keys: Vec<(String, String)>,
    /// Set for a content-only share: the blob it ships ahead of its records.
    ships: Option<BlobRef>,
    /// The bytes of the content it carries, as stored — the JSON it travels as.
    content_bytes: usize,
}

impl PendingShare {
    /// The blob this share goes up alone, ahead of its records: sent raw by
    /// itself rather than inside an ingest request.
    pub fn upload(&self) -> Option<&BlobContent> {
        self.ships.as_ref().and(self.share.content.blobs.first())
    }

    /// The blob this share goes up alone, as [`assemble`](OutboxV2::assemble)
    /// names one on its way up.
    pub fn upload_key(&self) -> Option<UploadKey> {
        self.ships.as_ref().map(|b| {
            let (kind, hash) = ContentRef::Blob(b.clone()).key();
            (self.share.tenant, kind, hash)
        })
    }

    /// How many bodies it carries, and their bytes as they travel in an
    /// ingest request.
    pub fn content_weight(&self) -> (u64, u64) {
        let c = &self.share.content;
        let bodies = c.messages.len() + c.tool_definitions.len() + c.system_prompts.len() + c.blobs.len();
        (bodies as u64, self.content_bytes as u64)
    }

    /// What admin-api holds once it commits the share: every key its records
    /// name — carried or acked earlier — but the ones it names unavailable.
    fn acks(&self) -> Vec<(String, String)> {
        let unavailable: BTreeSet<(String, String)> = self.share.unavailable.iter().map(row_key).collect();
        self.content_keys
            .iter()
            .filter(|(kind, hash)| !unavailable.contains(&(kind.clone(), hash.clone())) && ContentRef::from_key(kind, hash.clone()).is_some())
            .cloned()
            .collect()
    }

    /// Take the blob out of an upload share, leaving what [`OutboxV2::apply`]
    /// reads: the blob need not be held twice while it goes up.
    pub fn take_upload(&mut self) -> Option<BlobContent> {
        self.ships.as_ref()?;
        self.share.content.blobs.pop()
    }
}

/// A blob going up by itself: `(tenant, kind, hash)` of its content row.
pub type UploadKey = (uuid::Uuid, String, String);

/// The blobs going up by themselves, as [`OutboxV2::assemble`] reads them.
pub struct Uploads {
    /// On their way up, or waiting to be sent again: a record that needs one
    /// is passed over, and the records after it still go.
    pub held: Vec<UploadKey>,
    /// Whether another blob may start going up now.
    pub may_start: bool,
}

impl Uploads {
    /// None going up, and one may start.
    #[cfg(test)]
    pub fn idle() -> Self {
        Self { held: Vec::new(), may_start: true }
    }
}

/// What [`OutboxV2::apply`] did with a share, for the caller's log.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// Its records (and content no other record needs) are gone.
    Deleted,
    /// Its blob is now on admin-api; the records that need it travel without it.
    Shipped,
    /// Kept for another attempt.
    Kept,
    /// Kept, with the acks of bodies admin-api named missing forgotten: the
    /// next share carries them (or names them unavailable), so it can be
    /// answered differently.
    Asked,
}

pub struct OutboxV2 {
    pool: sqlx::SqlitePool,
    page_size: u64,
    /// Held for the life of the store: one process per data directory.
    _lock: std::fs::File,
}

impl OutboxV2 {
    /// Open (or create) this build's store in `data_dir` ([`store_file`]);
    /// another build's is never served from ([`note_other_stores`]). A store created
    /// here is a new instance.
    pub async fn open(data_dir: &str) -> Result<Self, anyhow::Error> {
        // The store carries the instance id: two processes on one data
        // directory would be one instance with two process epochs, the older
        // one refused for good. The second is refused at start instead.
        let lock_path = format!("{data_dir}/{LOCK_FILE}");
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
                "another proxy process holds the data directory {data_dir} — each replica needs its own"
            ),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        note_other_stores(data_dir).await;
        let pool = connect(&format!("{data_dir}/{}", store_file())).await?;
        for ddl in [
            // AUTOINCREMENT: an id is never reused, so a share in flight that
            // deletes its rows by id on commit cannot take a later row with it.
            "CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
                natural_key TEXT NOT NULL, body BLOB NOT NULL, created_at INTEGER NOT NULL,
                UNIQUE (tenant_id, kind, natural_key))",
            "CREATE TABLE IF NOT EXISTS content (
                tenant_id TEXT NOT NULL, kind TEXT NOT NULL, hash TEXT NOT NULL,
                body BLOB NOT NULL, PRIMARY KEY (tenant_id, kind, hash))",
            // A body admin-api answered for: named by a share it committed,
            // or a blob it stored by itself. A share leaves it out instead
            // of carrying it, until admin-api names it
            // missing (its copy purged or restored away) or the tenant is
            // deleted. Kept apart from `content`: an ack outlives the records
            // that needed the body.
            "CREATE TABLE IF NOT EXISTS acked (
                tenant_id TEXT NOT NULL, kind TEXT NOT NULL, hash TEXT NOT NULL,
                acked_at INTEGER NOT NULL, PRIMARY KEY (tenant_id, kind, hash))",
            "CREATE INDEX IF NOT EXISTS acked_by_age ON acked (acked_at)",
            "CREATE TABLE IF NOT EXISTS refs (
                record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
                tenant_id TEXT NOT NULL, kind TEXT NOT NULL, hash TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS refs_by_content ON refs (tenant_id, kind, hash)",
            "CREATE INDEX IF NOT EXISTS refs_by_record ON refs (record_id)",
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
            // The instance id this store belongs to, created with it: a lost
            // store is a new instance, so admin-api orders epochs only within
            // one store.
            "CREATE TABLE IF NOT EXISTS identity (one INTEGER PRIMARY KEY CHECK (one = 1), instance TEXT NOT NULL)",
        ] {
            sqlx::query(ddl).execute(&pool).await?;
        }
        let (page_size,): (i64,) = sqlx::query_as("PRAGMA page_size").fetch_one(&pool).await?;
        Ok(Self { pool, page_size: page_size.max(0) as u64, _lock: lock })
    }

    /// The instance id this store belongs to, created on first use.
    pub async fn instance(&self) -> Result<uuid::Uuid, anyhow::Error> {
        sqlx::query("INSERT INTO identity (one, instance) VALUES (1, ?) ON CONFLICT DO NOTHING")
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&self.pool)
            .await?;
        let (id,): (String,) = sqlx::query_as("SELECT instance FROM identity WHERE one = 1").fetch_one(&self.pool).await?;
        Ok(uuid::Uuid::parse_str(&id)?)
    }

    /// Take this process's epoch: the persisted counter, incremented. Called
    /// once per process start.
    pub async fn start_process(&self) -> Result<Epoch, anyhow::Error> {
        // At least the wall clock in seconds: a store restored from an older
        // backup keeps its instance id with a lower counter, and admin-api
        // refuses an epoch below the one it last saw — the clock has moved
        // past it, unless this store's processes started faster than once a
        // second on average. Still one more than the last, should the clock
        // step back.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let (epoch,): (i64,) = sqlx::query_as(
            "INSERT INTO meta (key, value) VALUES ('process_epoch', MAX(1, ?1)) \
             ON CONFLICT (key) DO UPDATE SET value = MAX(value + 1, ?1) RETURNING value",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(epoch as Epoch)
    }

    /// Buffer one tenant's records and the content they reference, in one
    /// transaction. A record already buffered under its natural key is kept
    /// as it is — except a credential rotation, replaced by one with a later
    /// `expires_at`. Content already buffered is kept. Returns the indexes in
    /// `records` of those the outbox holds: one dropped here (logged) is not
    /// among them.
    pub async fn enqueue(&self, tenant: uuid::Uuid, records: &[Enqueued], content: &Content) -> Result<Vec<usize>, anyhow::Error> {
        let tenant = tenant.to_string();
        let now = chrono::Utc::now().timestamp_millis();
        // Everything is fitted before the transaction: the write lock it takes
        // at its first INSERT is held for the inserts alone, not for the
        // serializing and shrinking every other writer would wait on.
        let mut bodies: Vec<(String, String, Vec<u8>)> = Vec::new();
        for (r, body) in content_rows(content) {
            let (kind, hash) = r.key();
            let Some(body) = fit_content(&r, body) else {
                tracing::error!(
                    %tenant, %kind, %hash,
                    "content too large or too deeply nested for any ingest request — not buffered; its records ship without it"
                );
                continue;
            };
            bodies.push((kind, hash, body));
        }
        let mut fitted_records: Vec<ToStore<'_>> = Vec::new();
        for (index, Enqueued { record }) in records.iter().enumerate() {
            let kind = record.kind();
            let natural_key = record.natural_key();
            let fitted = match fit_record(record) {
                Ok(fitted) => fitted,
                Err(e) => {
                    tracing::error!(%tenant, kind = kind.as_str(), %natural_key, "record does not serialize — dropped: {e}");
                    continue;
                }
            };
            let Some(Fitted { body, whole }) = fitted else {
                tracing::error!(
                    %tenant, kind = kind.as_str(), %natural_key,
                    "record too large to shrink or too deeply nested for any ingest request — dropped"
                );
                continue;
            };
            // A record needs exactly what it names as stored: one shrunk or
            // stripped to fit is read back, and names what it kept.
            let stored = if whole {
                None
            } else {
                match read_stored::<Record>(&body) {
                    Ok(stored) => Some(stored),
                    Err(e) => {
                        tracing::error!(
                            %tenant, kind = kind.as_str(), %natural_key,
                            "record fitted to travel does not read back — dropped: {e}"
                        );
                        continue;
                    }
                }
            };
            let refs: Vec<(String, String)> = stored.as_ref().unwrap_or(record).content_keys().iter().map(row_key).collect();
            fitted_records.push(ToStore { index, record, natural_key, body, refs });
        }

        if fitted_records.is_empty() {
            // Nothing needs the content: a body only a dropped record named is
            // not kept.
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;
        // The content rows this call adds, and the keys its records need.
        let mut added: BTreeSet<(String, String)> = BTreeSet::new();
        let mut needed: BTreeSet<(String, String)> = BTreeSet::new();
        for (kind, hash, body) in bodies {
            let inserted = sqlx::query("INSERT INTO content (tenant_id, kind, hash, body) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING")
                .bind(&tenant)
                .bind(&kind)
                .bind(&hash)
                .bind(body)
                .execute(&mut *tx)
                .await?;
            if inserted.rows_affected() > 0 {
                added.insert((kind, hash));
            }
        }
        let held: Vec<usize> = fitted_records.iter().map(|r| r.index).collect();
        for ToStore { record, natural_key, body, refs, .. } in fitted_records {
            let inserted: Option<(i64,)> = sqlx::query_as(
                "INSERT INTO records (tenant_id, kind, natural_key, body, created_at) VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT DO NOTHING RETURNING id",
            )
            .bind(&tenant)
            .bind(record.kind().as_str())
            .bind(&natural_key)
            .bind(&body)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((id,)) = inserted else {
                if let Record::CredentialRotation(newer) = record {
                    replace_if_newer(&mut tx, &tenant, &natural_key, newer.expires_at, &body).await?;
                }
                continue;
            };
            // Kept whether or not a content row holds the body: one refused
            // above is still needed, and named unavailable when the record goes.
            for (rkind, hash) in refs {
                sqlx::query("INSERT INTO refs (record_id, tenant_id, kind, hash) VALUES (?, ?, ?, ?)")
                    .bind(id)
                    .bind(&tenant)
                    .bind(&rkind)
                    .bind(&hash)
                    .execute(&mut *tx)
                    .await?;
                needed.insert((rkind, hash));
            }
        }
        // A body this call added that none of its records needs (its turn
        // stripped to fit) is not kept — unless an earlier record needs it.
        for (kind, hash) in added.difference(&needed) {
            sqlx::query(
                "DELETE FROM content WHERE tenant_id = ? AND kind = ? AND hash = ? \
                   AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.tenant_id = ? AND r.kind = ? AND r.hash = ?)",
            )
            .bind(&tenant)
            .bind(kind)
            .bind(hash)
            .bind(&tenant)
            .bind(kind)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(held)
    }

    /// Records still buffered.
    pub async fn pending(&self) -> Result<u64, anyhow::Error> {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM records").fetch_one(&self.pool).await?;
        Ok(n.max(0) as u64)
    }

    /// Assemble shares for one request, oldest records first, up to
    /// `request_budget` bytes in all: per tenant, its oldest records up to
    /// [`SHARE_BUDGET_BYTES`] with every content row they reference that
    /// admin-api has not acked — one it has is left out, and a body a
    /// record names that is neither acked nor held in a row in `unavailable`. A blob too
    /// large to travel with records goes first,
    /// alone, as a content-only share sent up by itself ([`PendingShare::upload`]). The request's first share always
    /// carries at least one record (or that blob) however large, so nothing
    /// waits forever behind a budget; a record whose content would not fit
    /// even a request of its own sheds its largest content (logged), and a
    /// record whose body cannot be read is dropped with an error.
    ///
    /// A record whose blob cannot go up now (`uploads`) is passed over; the
    /// records after it still go.
    pub async fn assemble(&self, request_budget: usize, uploads: &Uploads) -> Result<Vec<PendingShare>, anyhow::Error> {
        self.assemble_with(request_budget, SHARE_BUDGET_BYTES, uploads).await
    }

    async fn assemble_with(
        &self,
        request_budget: usize,
        share_budget: usize,
        uploads: &Uploads,
    ) -> Result<Vec<PendingShare>, anyhow::Error> {
        let tenants: Vec<(String,)> =
            sqlx::query_as("SELECT tenant_id FROM records GROUP BY tenant_id ORDER BY MIN(id)").fetch_all(&self.pool).await?;
        let mut shares = Vec::new();
        let mut total = 0usize;
        // One blob starts going up per request at most: another read now
        // would only be read again once it may go.
        let mut may_start = uploads.may_start;
        for (tenant,) in tenants {
            if total >= request_budget {
                break;
            }
            let Ok(tenant_id) = uuid::Uuid::parse_str(&tenant) else {
                tracing::error!(tenant = %tenant, "outbox records under an unreadable tenant id — dropped");
                self.drop_tenant(&tenant).await?;
                continue;
            };
            let budget = share_budget.min(request_budget - total);
            // The first share of records — a blob going up by itself is no
            // part of the request.
            let first = shares.iter().all(|s: &PendingShare| s.ships.is_some());
            let lone_max = first.then_some(LONE_SHARE_MAX_BYTES);
            if let Some(share) = self.assemble_tenant(&tenant, tenant_id, budget, lone_max, &uploads.held, may_start).await? {
                // A blob going up by itself is no part of the request.
                if share.ships.is_none() {
                    total += share_size(&share.share);
                } else {
                    may_start = false;
                }
                shares.push(share);
            }
        }
        Ok(shares)
    }

    /// `lone_max`: set when this is the request's first share, which carries
    /// its first record (or blob) whatever the budget, up to this many bytes.
    async fn assemble_tenant(
        &self,
        tenant: &str,
        tenant_id: uuid::Uuid,
        budget: usize,
        lone_max: Option<usize>,
        held: &[UploadKey],
        may_start: bool,
    ) -> Result<Option<PendingShare>, anyhow::Error> {
        let alone = lone_max.is_some();
        let lone_max = lone_max.unwrap_or(LONE_SHARE_MAX_BYTES);
        // More rows than the budget can carry is never needed: every record
        // costs at least its own body. A record that cannot go in this request
        // because of a blob — one on its way up, or one too large for a share
        // when no blob may start going up — is left out of the read, so
        // however many wait, the records after them are still reached.
        let held_here: Vec<&UploadKey> = held.iter().filter(|(t, _, _)| *t == tenant_id).collect();
        // A blob going up is no part of the request: any tenant may start
        // one, not only the request's first.
        let starts_here = may_start;
        let mut sql = String::from("SELECT r.id, r.body FROM records r WHERE r.tenant_id = ?");
        if !held_here.is_empty() || !starts_here {
            sql.push_str(
                " AND NOT EXISTS (SELECT 1 FROM refs f JOIN content c \
                   ON c.tenant_id = f.tenant_id AND c.kind = f.kind AND c.hash = f.hash \
                   WHERE f.record_id = r.id AND NOT EXISTS (SELECT 1 FROM acked a \
                     WHERE a.tenant_id = c.tenant_id AND a.kind = c.kind AND a.hash = c.hash) AND (",
            );
            sql.push_str(if starts_here { "0" } else { "(c.kind LIKE 'blob:%' AND length(c.body) > ?)" });
            for _ in &held_here {
                sql.push_str(" OR (c.kind = ? AND c.hash = ?)");
            }
            sql.push_str("))");
        }
        if !starts_here {
            // Nor one whose blobs only together pass what a request carries:
            // its largest goes up first.
            sql.push_str(
                " AND (SELECT COALESCE(SUM(length(c.body)), 0) FROM refs f JOIN content c \
                   ON c.tenant_id = f.tenant_id AND c.kind = f.kind AND c.hash = f.hash \
                   WHERE f.record_id = r.id AND c.kind LIKE 'blob:%' AND NOT EXISTS (SELECT 1 FROM acked a \
                     WHERE a.tenant_id = c.tenant_id AND a.kind = c.kind AND a.hash = c.hash)) <= ?",
            );
        }
        sql.push_str(" ORDER BY r.id LIMIT 1000");
        let mut query = sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(tenant);
        if !held_here.is_empty() || !starts_here {
            if !starts_here {
                query = query.bind(i64::try_from(budget).unwrap_or(i64::MAX));
            }
            for (_, kind, hash) in &held_here {
                query = query.bind(kind).bind(hash);
            }
            if !starts_here {
                query = query.bind(i64::try_from(lone_max).unwrap_or(i64::MAX));
            }
        }
        let rows: Vec<(i64, Vec<u8>)> = query.fetch_all(&self.pool).await?;
        let mut share = TenantShare { tenant: tenant_id, ..Default::default() };
        let mut record_ids = Vec::new();
        let mut content_keys: BTreeSet<(String, String)> = BTreeSet::new();
        // Bodies the share's records name that are neither acked nor held in a row.
        let mut unavailable: BTreeSet<(String, String)> = BTreeSet::new();
        let mut size = 0usize;
        let mut unreadable = Vec::new();
        let mut content_bytes = 0usize;
        for (id, body) in rows {
            let record: Record = match read_stored(&body) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(id, "outbox record cannot be read — dropped: {e}");
                    unreadable.push(id);
                    continue;
                }
            };
            // The content this record needs that the share does not carry yet.
            let refs: Vec<(String, String)> = sqlx::query_as("SELECT kind, hash FROM refs WHERE record_id = ?")
                .bind(id)
                .fetch_all(&self.pool)
                .await?;
            // `(kind, hash, size, acked)`; a body is read only once it goes,
            // and one admin-api acked is left out.
            let mut needed: Vec<(String, String, usize, bool)> = Vec::new();
            // Needed, neither acked nor held in a content row.
            let mut lost: Vec<(String, String)> = Vec::new();
            let mut waits = false;
            for (kind, hash) in refs {
                if content_keys.contains(&(kind.clone(), hash.clone())) || unavailable.contains(&(kind.clone(), hash.clone())) {
                    continue;
                }
                if held.iter().any(|(t, k, h)| *t == tenant_id && *k == kind && *h == hash) {
                    waits = true; // its blob is on its way up, or waits to be sent again
                    break;
                }
                let (len, acked): (Option<i64>, bool) = sqlx::query_as(
                    "SELECT (SELECT length(body) FROM content WHERE tenant_id = ?1 AND kind = ?2 AND hash = ?3), \
                            EXISTS (SELECT 1 FROM acked WHERE tenant_id = ?1 AND kind = ?2 AND hash = ?3)",
                )
                .bind(tenant)
                .bind(&kind)
                .bind(&hash)
                .fetch_one(&self.pool)
                .await?;
                match (len, acked) {
                    (_, true) => needed.push((kind, hash, 0, true)),
                    (Some(len), false) => needed.push((kind, hash, len.max(0) as usize, false)),
                    (None, false) => lost.push((kind, hash)),
                }
            }
            if waits {
                // Only this record waits: admin writes every record on its
                // own (records of one tenant reach it from many instances,
                // in any order), so the ones after it go now.
                continue;
            }
            // What the record adds to the share: its body, the content it
            // carries, and the keys it names `unavailable`.
            let cost_of = |needed: &[(String, String, usize, bool)], lost: &[(String, String)]| {
                let carried: usize = needed.iter().filter(|n| !n.3).map(|n| n.2).sum();
                body.len() + carried + lost.iter().map(|(k, h)| key_bytes(k, h)).sum::<usize>()
            };
            let mut cost = cost_of(&needed, &lost);
            // A blob that cannot travel with records goes up first, by itself:
            // one larger than a share, or the largest of a record whose
            // content no request could carry with it.
            let blobs = || needed.iter().filter(|n| !n.3 && n.0.starts_with("blob:"));
            let goes_alone = blobs()
                .find(|n| n.2 > budget)
                .or_else(|| if record_ids.is_empty() && cost > lone_max { blobs().max_by_key(|n| n.2) } else { None });
            if let Some((kind, hash, _, _)) = goes_alone {
                if !record_ids.is_empty() || !may_start {
                    continue; // its blob goes up first, in a later request; the rest go now
                }
                self.delete_ids(&unreadable).await?;
                let blob: Result<BlobContent, String> = match self.content_body(tenant, kind, hash).await? {
                    Some(cbody) => read_stored(&cbody),
                    None => Err("gone".to_string()),
                };
                let blob = match blob {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(%hash, "outbox blob cannot be read — dropped; its records ship without it: {e}");
                        self.drop_content(tenant, kind, hash).await?;
                        return Ok(None);
                    }
                };
                let ships = blob.blob_ref();
                let share = TenantShare {
                    tenant: tenant_id,
                    content: Content { blobs: vec![blob], ..Default::default() },
                    ..Default::default()
                };
                return Ok(Some(PendingShare {
                    share,
                    record_ids: Vec::new(),
                    content_keys: vec![(kind.clone(), hash.clone())],
                    ships: Some(ships),
                    content_bytes: 0,
                }));
            }
            if (!record_ids.is_empty() || !alone) && size + cost > budget {
                break;
            }
            // Alone and still past what a request carries once its blobs are
            // up: its largest content can never travel with it, and would hold
            // back every record behind it. It is dropped; the record ships
            // without it.
            while record_ids.is_empty() && cost > lone_max {
                let Some(largest) = needed
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| !n.3)
                    .max_by_key(|(_, n)| n.2)
                    .map(|(i, _)| i)
                else {
                    break;
                };
                let (kind, hash, bytes, _) = needed.remove(largest);
                tracing::error!(
                    %tenant, %kind, %hash, bytes,
                    "a record's content cannot fit any ingest request with it — dropped; the record ships without it"
                );
                self.drop_content(tenant, &kind, &hash).await?;
                lost.push((kind, hash));
                cost = cost_of(&needed, &lost);
            }
            size += cost;
            record_ids.push(id);
            share.records.push(record);
            unavailable.extend(lost);
            for (kind, hash, _, acked) in needed {
                // A kind this build cannot read is named nowhere, and never
                // acked ([`PendingShare::acks`]); its row is collected.
                content_keys.insert((kind.clone(), hash.clone()));
                if acked {
                    continue; // left out: admin-api holds it
                }
                let Some(r) = ContentRef::from_key(&kind, hash.clone()) else {
                    tracing::error!(%kind, %hash, "outbox content of an unknown kind — not sent");
                    continue;
                };
                // A content row that cannot be read back is dropped (logged);
                // its records ship without it, as with one admin refused.
                let read: Result<(), String> = match self.content_body(tenant, &kind, &hash).await? {
                    None => Err("gone".to_string()),
                    Some(cbody) => {
                        let read = match r {
                            ContentRef::Blob(_) => read_stored(&cbody).map(|c| share.content.blobs.push(c)),
                            ContentRef::Message(_) => read_stored(&cbody).map(|c| share.content.messages.push(c)),
                            ContentRef::ToolDefinition(_) => read_stored(&cbody).map(|c| share.content.tool_definitions.push(c)),
                            ContentRef::SystemPrompt(_) => read_stored(&cbody).map(|c| share.content.system_prompts.push(c)),
                        };
                        if read.is_ok() {
                            content_bytes += cbody.len();
                        }
                        read
                    }
                };
                if let Err(e) = read {
                    tracing::error!(%hash, %kind, "outbox content cannot be read — dropped; its records ship without it: {e}");
                    content_keys.remove(&(kind.clone(), hash.clone()));
                    self.drop_content(tenant, &kind, &hash).await?;
                    unavailable.insert((kind, hash));
                }
            }
        }
        self.delete_ids(&unreadable).await?;
        if record_ids.is_empty() {
            return Ok(None);
        }
        // A row for an unavailable key may arrive while the share is out;
        // it is collected with the rest once the share is answered.
        content_keys.extend(unavailable.iter().cloned());
        share.unavailable = unavailable
            .into_iter()
            .filter_map(|(kind, hash)| ContentRef::from_key(&kind, hash).map(ContentRef::content_key))
            .collect();
        Ok(Some(PendingShare { share, record_ids, content_keys: content_keys.into_iter().collect(), ships: None, content_bytes }))
    }

    /// Apply admin-api's outcome for a share.
    pub async fn apply(&self, pending: &PendingShare, outcome: &ShareOutcome) -> Result<Applied, anyhow::Error> {
        let tenant = pending.share.tenant.to_string();
        match outcome {
            ShareOutcome::Rejected { reason, .. } if pending.ships.is_some() => {
                // The blob itself was refused: it is not on admin-api, and
                // every resend would be refused the same way. The records that
                // reference it ship without it.
                tracing::error!(%tenant, %reason, "admin-api refused a blob for its data — dropped from the outbox");
                for (kind, hash) in &pending.content_keys {
                    self.drop_content(&tenant, kind, hash).await?;
                }
                Ok(Applied::Deleted)
            }
            ShareOutcome::Committed | ShareOutcome::Rejected { .. } => {
                match outcome {
                    ShareOutcome::Rejected { rows, reason } if rows.is_empty() => tracing::error!(
                        %tenant, %reason,
                        "admin-api refused a body the share carried for its data"
                    ),
                    ShareOutcome::Rejected { rows, reason } => tracing::error!(
                        %tenant, rows = rows.len(), %reason,
                        "admin-api refused records for their data — dropped from the outbox"
                    ),
                    _ => {}
                }
                self.delete_ids(&pending.record_ids).await?;
                // Only a share admin-api stored whole is an ack: one it
                // refused part of may not hold what the share carried. An ack
                // only saves a resend, so failing to write one is no reason
                // to send the share again.
                if matches!(outcome, ShareOutcome::Committed)
                    && let Err(e) = self.ack(&tenant, &pending.acks()).await
                {
                    // A blob that went up by itself is let go by its ack
                    // alone: without one it would go up again at once, so
                    // the upload backs off instead.
                    if pending.ships.is_some() {
                        return Err(e);
                    }
                    tracing::warn!(%tenant, "recording what admin-api holds failed — those bodies are carried again: {e}");
                }
                self.collect_content(&tenant, &pending.content_keys).await?;
                Ok(if pending.ships.is_some() { Applied::Shipped } else { Applied::Deleted })
            }
            ShareOutcome::TenantDeleted => {
                tracing::info!(%tenant, "tenant deleted on admin-api — its buffered records are dropped");
                self.drop_tenant(&tenant).await?;
                Ok(Applied::Deleted)
            }
            ShareOutcome::Retry { missing } => {
                // Admin-api no longer holds these: they are carried again with
                // the records, and one whose row is gone is named unavailable
                // next (every key a record names has a ref).
                if missing.is_empty() {
                    return Ok(Applied::Kept);
                }
                let mut tx = self.pool.begin().await?;
                let mut forgotten = 0;
                for key in missing {
                    let (kind, hash) = row_key(key);
                    forgotten += sqlx::query("DELETE FROM acked WHERE tenant_id = ? AND kind = ? AND hash = ?")
                        .bind(&tenant)
                        .bind(kind)
                        .bind(hash)
                        .execute(&mut *tx)
                        .await?
                        .rows_affected();
                }
                tx.commit().await?;
                // Asked for a body that was not acked: the same share
                // would be asked the same again.
                Ok(if forgotten > 0 { Applied::Asked } else { Applied::Kept })
            }
        }
    }

    /// Bound the outbox file to `cap_bytes` of live pages, down to 90% of the
    /// cap: first forget every ack — an ack only saves a resend, so the cap
    /// never costs an audit row for one, and acks of random hashes free their
    /// pages only all together — then evict the oldest records (and the
    /// content only they referenced). Returns how many records were evicted —
    /// each an audit row admin-api will never receive, named in an `error`.
    pub async fn enforce_cap(&self, cap_bytes: u64) -> Result<u64, anyhow::Error> {
        if self.logical_size().await? <= cap_bytes {
            return Ok(0);
        }
        let low_water = cap_bytes / 10 * 9;
        // In chunks: one statement over every ack would hold the write lock
        // an `enqueue` waits on.
        let mut forgotten = 0;
        loop {
            let gone = sqlx::query("DELETE FROM acked WHERE rowid IN (SELECT rowid FROM acked LIMIT ?)")
                .bind(ACK_SWEEP_CHUNK)
                .execute(&self.pool)
                .await?
                .rows_affected();
            forgotten += gone;
            if gone < ACK_SWEEP_CHUNK as u64 {
                break;
            }
        }
        if forgotten > 0 {
            tracing::warn!(forgotten, cap_bytes, "edge outbox over its size cap — every ack forgotten; the bodies they named are carried again once");
        }
        let mut evicted = 0u64;
        while self.logical_size().await? > low_water {
            let ids: Vec<(i64,)> = sqlx::query_as("SELECT id FROM records ORDER BY id LIMIT ?")
                .bind(EVICT_CHUNK)
                .fetch_all(&self.pool)
                .await?;
            if ids.is_empty() {
                break;
            }
            let ids: Vec<i64> = ids.into_iter().map(|(id,)| id).collect();
            self.delete_ids(&ids).await?;
            evicted += ids.len() as u64;
            sqlx::query(
                "DELETE FROM content WHERE NOT EXISTS (SELECT 1 FROM refs r \
                   WHERE r.tenant_id = content.tenant_id AND r.kind = content.kind AND r.hash = content.hash)",
            )
            .execute(&self.pool)
            .await?;
        }
        if evicted > 0 {
            tracing::error!(evicted, cap_bytes, "edge outbox over its size cap — the oldest records were evicted and will not reach admin-api");
        }
        Ok(evicted)
    }

    /// Forget the acks no share named for [`ACK_TTL_MS`].
    /// Deleted in chunks, so no one statement holds the write lock an
    /// `enqueue` waits on for long.
    pub async fn forget_stale_acks(&self) -> Result<u64, anyhow::Error> {
        let cutoff = chrono::Utc::now().timestamp_millis() - ACK_TTL_MS;
        let mut forgotten = 0;
        loop {
            let gone = sqlx::query("DELETE FROM acked WHERE rowid IN (SELECT rowid FROM acked WHERE acked_at < ? LIMIT ?)")
                .bind(cutoff)
                .bind(ACK_SWEEP_CHUNK)
                .execute(&self.pool)
                .await?
                .rows_affected();
            forgotten += gone;
            if gone < ACK_SWEEP_CHUNK as u64 {
                return Ok(forgotten);
            }
            tokio::task::yield_now().await;
        }
    }

    async fn logical_size(&self) -> Result<u64, anyhow::Error> {
        let (pages,): (i64,) = sqlx::query_as("PRAGMA page_count").fetch_one(&self.pool).await?;
        let (free,): (i64,) = sqlx::query_as("PRAGMA freelist_count").fetch_one(&self.pool).await?;
        Ok((pages - free).max(0) as u64 * self.page_size)
    }

    async fn delete_ids(&self, ids: &[i64]) -> Result<(), anyhow::Error> {
        for chunk in ids.chunks(ID_CHUNK) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!("DELETE FROM records WHERE id IN ({placeholders})");
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for id in chunk {
                q = q.bind(id);
            }
            q.execute(&self.pool).await?;
        }
        Ok(())
    }

    /// Record that admin-api holds `keys`, now: a later share leaves them
    /// out. A key acked more than [`ACK_RENEW_MS`] ago is renewed, so an
    /// ack lives while shares keep naming it ([`forget_stale_acks`](Self::forget_stale_acks)).
    async fn ack(&self, tenant: &str, keys: &[(String, String)]) -> Result<(), anyhow::Error> {
        if keys.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp_millis();
        // One statement for a share's keys, however long the history.
        sqlx::query(
            "INSERT INTO acked (tenant_id, kind, hash, acked_at) \
             SELECT ?1, json_extract(value, '$[0]'), json_extract(value, '$[1]'), ?2 FROM json_each(?3) WHERE true \
             ON CONFLICT (tenant_id, kind, hash) DO UPDATE SET acked_at = excluded.acked_at \
             WHERE acked.acked_at <= excluded.acked_at - ?4",
        )
        .bind(tenant)
        .bind(now)
        .bind(serde_json::to_string(keys)?)
        .bind(ACK_RENEW_MS)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete the given content rows that no remaining record references.
    /// One statement, however many keys: a write per key would take the
    /// write lock an `enqueue` waits on once per body of the session.
    async fn collect_content(&self, tenant: &str, keys: &[(String, String)]) -> Result<(), anyhow::Error> {
        if keys.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "DELETE FROM content WHERE tenant_id = ?1 \
               AND (kind, hash) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?2)) \
               AND NOT EXISTS (SELECT 1 FROM refs r WHERE r.tenant_id = content.tenant_id AND r.kind = content.kind AND r.hash = content.hash)",
        )
        .bind(tenant)
        .bind(serde_json::to_string(keys)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn content_body(&self, tenant: &str, kind: &str, hash: &str) -> Result<Option<Vec<u8>>, anyhow::Error> {
        Ok(sqlx::query_scalar("SELECT body FROM content WHERE tenant_id = ? AND kind = ? AND hash = ?")
            .bind(tenant)
            .bind(kind)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Drop one content row. The records that need it keep their `refs`, and
    /// travel naming it unavailable.
    async fn drop_content(&self, tenant: &str, kind: &str, hash: &str) -> Result<(), anyhow::Error> {
        sqlx::query("DELETE FROM content WHERE tenant_id = ? AND kind = ? AND hash = ?")
            .bind(tenant)
            .bind(kind)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn drop_tenant(&self, tenant: &str) -> Result<(), anyhow::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM records WHERE tenant_id = ?").bind(tenant).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM content WHERE tenant_id = ?").bind(tenant).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM acked WHERE tenant_id = ?").bind(tenant).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Replace a buffered credential rotation with `body` when `expires_at` is
/// later than the buffered one's (or the buffered one has none).
async fn replace_if_newer(
    tx: &mut sqlx::SqliteConnection,
    tenant: &str,
    natural_key: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    body: &[u8],
) -> Result<(), anyhow::Error> {
    let kind = RecordKind::CredentialRotation.as_str();
    let held: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT body FROM records WHERE tenant_id = ? AND kind = ? AND natural_key = ?")
            .bind(tenant)
            .bind(kind)
            .bind(natural_key)
            .fetch_optional(&mut *tx)
            .await?;
    let held_expires = held
        .and_then(|(b,)| read_stored::<Record>(&b).ok())
        .and_then(|r| match r {
            Record::CredentialRotation(c) => c.expires_at,
            _ => None,
        });
    // Where either side has no expiry the two cannot be ordered, and the later
    // rotation is taken — admin-api's rule for the same pair.
    let newer = match (held_expires, expires_at) {
        (Some(held), Some(new)) => new > held,
        _ => true,
    };
    if newer {
        // A new row, never an update in place: the older one may be in a share
        // already on its way, whose commit deletes its row by id — that must
        // not take the newer rotation with it.
        sqlx::query("DELETE FROM records WHERE tenant_id = ? AND kind = ? AND natural_key = ?")
            .bind(tenant)
            .bind(kind)
            .bind(natural_key)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO records (tenant_id, kind, natural_key, body, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(tenant)
            .bind(kind)
            .bind(natural_key)
            .bind(body)
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// The most JSON levels admin-api parses in one ingest request.
const MAX_DEPTH: usize = streamscope_core::edge_wire::EDGE_ENVELOPE_MAX_DEPTH;

/// A record as stored: its JSON, shrunk to [`CONTENT_MAX_BYTES`] when larger —
/// counting, beside it, every body it names as a key ([`key_cost`]) —
/// ([`shrink_json_to_fit`]); kept to its identity ([`stripped_record`]) when
/// it cannot shrink that far or nests deeper than admin-api parses inside a
/// request — either would refuse every request carrying it, and hold back
/// every record behind it. `None` when even that cannot travel, and for an
/// SSE event or a credential rotation that does not fit whole.
///
/// [`CONTENT_MAX_BYTES`]: streamscope_edge_api::ingest::CONTENT_MAX_BYTES
fn fit_record(record: &Record) -> Result<Option<Fitted>, serde_json::Error> {
    let json = serde_json::to_string(record)?;
    let depth = MAX_DEPTH - streamscope_edge_api::ingest::RECORD_ENCLOSING_DEPTH;
    let max = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
    let too_deep = !streamscope_core::edge_wire::nesting_within(&json, depth);
    if !too_deep && json.len() + key_cost(record) <= max {
        return Ok(Some(Fitted { body: json.into_bytes(), whole: true }));
    }
    // An SSE event or a credential is only worth delivering whole: a noted or
    // emptied event would be replayed under a made-up id or as nothing, a noted
    // token would replace a working credential.
    if matches!(record, Record::McpSseEvent(_) | Record::CredentialRotation(_)) {
        return Ok(None);
    }
    let reason = if too_deep { "too_deep" } else { "oversized" };
    tracing::error!(kind = record.kind().as_str(), bytes = json.len(), max, reason, "record cannot travel whole in an ingest request — its largest strings are replaced by notes, or its payload is left out");
    // The shrunk record must still read back as a record of its kind.
    let shrunk = (!too_deep)
        .then(|| shrink_json_to_fit(&json, max.saturating_sub(key_cost(record))))
        .flatten()
        .filter(|small| serde_json::from_str::<Record>(small).is_ok_and(|r| small.len() + key_cost(&r) <= max));
    Ok(shrunk
        .or_else(|| stripped_record(record, reason, max, depth))
        .map(|json| Fitted { body: json.into_bytes(), whole: false }))
}

/// A record fitted to travel, ready for [`OutboxV2::enqueue`]'s transaction:
/// its stored body and the content keys that body names.
struct ToStore<'a> {
    /// Its place in the records handed to `enqueue`.
    index: usize,
    record: &'a Record,
    natural_key: String,
    body: Vec<u8>,
    refs: Vec<(String, String)>,
}

/// A record as stored, and whether it is the record whole.
struct Fitted {
    body: Vec<u8>,
    whole: bool,
}

/// A record kept to its identity: every field holding an object or an array
/// is left out (each reads back as its default) except its badges and the
/// small ones its row is read through ([`KEPT_STRUCTURE`]), and an audit
/// record is badged [`AuditBadge::RecordStripped`] beside the badges it had,
/// so its row still appears — ids, status, counters, cost — and says what it
/// lost. Where that is still too large, it gives up more, in order, until it
/// fits: its long strings become notes (empty where a note is not a value of
/// the field), then the kept fields but the bill go (and with them the keys
/// only its turn reads, [`TURN_ONLY`]), then all but one badge of each code,
/// then every badge but this one. `None` when even that does not read back as a record
/// of its kind or does not fit.
///
/// [`AuditBadge::RecordStripped`]: streamscope_core::audit::AuditBadge::RecordStripped
fn stripped_record(record: &Record, reason: &str, max: usize, depth: usize) -> Option<String> {
    let fits = |framed: &serde_json::Value| -> Option<String> {
        let json = serde_json::to_string(framed).ok()?;
        (streamscope_core::edge_wire::nesting_within(&json, depth)
            && serde_json::from_str::<Record>(&json).is_ok_and(|r| json.len() + key_cost(&r) <= max))
        .then_some(json)
    };
    let badge = serde_json::to_value(streamscope_core::audit::AuditBadge::RecordStripped { reason: reason.into() }).ok()?;
    let mut framed = serde_json::to_value(record).ok()?;
    let body = framed.get_mut("body")?.as_object_mut()?;
    body.retain(|key, v| key == "badges" || KEPT_STRUCTURE.contains(&key.as_str()) || !(v.is_array() || v.is_object()));
    let badged = match body.get_mut("badges") {
        Some(serde_json::Value::Array(badges)) => {
            badges.push(badge.clone());
            true
        }
        _ => false,
    };
    if let Some(json) = fits(&framed) {
        return Some(json);
    }
    // A long string becomes a note — or, where a note is not a value of its
    // field (bytes carried as base64), empty.
    let long: Vec<String> = framed
        .get("body")?
        .as_object()?
        .iter()
        .filter(|(_, v)| v.as_str().is_some_and(|s| s.len() > NOTE_ROOM))
        .map(|(k, _)| k.clone())
        .collect();
    for key in long {
        let slot = framed.get_mut("body")?.as_object_mut()?.get_mut(&key)?;
        let len = slot.as_str().map_or(0, str::len);
        *slot = serde_json::Value::String(format!("[not stored: {len} bytes]"));
        if serde_json::from_value::<Record>(framed.clone()).is_err() {
            *framed.get_mut("body")?.as_object_mut()?.get_mut(&key)? = serde_json::Value::String(String::new());
        }
    }
    if let Some(json) = fits(&framed) {
        return Some(json);
    }
    // The per-unit bill stays: the row's `cost` is its sum. With its message
    // hashes the record has no turn, so the bodies only a turn names go too —
    // it then names, and needs, no content.
    let body = framed.get_mut("body")?.as_object_mut()?;
    body.retain(|key, _| {
        key == "billed_units" || !(KEPT_STRUCTURE.contains(&key.as_str()) || TURN_ONLY.contains(&key.as_str()))
    });
    if let Some(json) = fits(&framed) {
        return Some(json);
    }
    if !badged {
        return None;
    }
    // One badge of each code it had (the first), so the row keeps every signal
    // it raised; then this one alone.
    let badges = framed.get_mut("body")?.as_object_mut()?.get_mut("badges")?;
    let mut codes = std::collections::BTreeSet::new();
    if let serde_json::Value::Array(all) = badges {
        all.retain(|b| codes.insert(b.get("code").and_then(serde_json::Value::as_str).unwrap_or_default().to_string()));
    }
    if let Some(json) = fits(&framed) {
        return Some(json);
    }
    framed.get_mut("body")?.as_object_mut()?.insert("badges".into(), serde_json::Value::Array(vec![badge]));
    fits(&framed)
}

/// The structured fields a stripped record keeps, each small: those its row is
/// read through — an LLM call's per-unit bill (its `cost` is their sum), the
/// links from its turn to its messages, the attempts it moved on from (counted
/// on their servers), its media call and its end user's groups — and the
/// blobs it names (`buffered_blobs`), which no row stores but which name what
/// the turn's messages embed, so its images still reach admin-api with it.
const KEPT_STRUCTURE: &[&str] =
    &["billed_units", "message_hashes", "moved_on_from", "media_call", "end_user_groups", "buffered_blobs"];

/// The keys only a record's turn reads: once its message hashes go, so do they.
const TURN_ONLY: &[&str] = &["tools_available_hash", "tools_effective_hash", "system_prompt_hash"];

/// The largest blob content row for a blob of at most `blob_max` bytes:
/// base64 takes 4 bytes per 3, and the row's own fields get 4 KiB.
fn blob_row_max_bytes(blob_max: usize) -> usize {
    blob_max.div_ceil(3).saturating_mul(4).saturating_add(4096)
}

/// A content row as stored: a message too large or too deep becomes the
/// marker the conversation view renders ([`oversized_message_marker`]), a
/// tool-definition set or system prompt too large is shrunk, a blob is held to the platform's
/// blob cap (the proxy captures none larger; one too large for a share goes
/// up by itself); `None` when it still cannot travel.
fn fit_content(r: &ContentRef, body: Vec<u8>) -> Option<Vec<u8>> {
    fit_content_under(r, body, streamscope_core::settings::core_settings().edge_blob_max_bytes())
}

fn fit_content_under(r: &ContentRef, body: Vec<u8>, blob_max: usize) -> Option<Vec<u8>> {
    if let ContentRef::Blob(_) = r {
        return (body.len() <= blob_row_max_bytes(blob_max)).then_some(body);
    }
    let max = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
    let depth = MAX_DEPTH - streamscope_edge_api::ingest::CONTENT_ENCLOSING_DEPTH;
    let fits = |b: &[u8]| {
        b.len() <= max && std::str::from_utf8(b).is_ok_and(|s| streamscope_core::edge_wire::nesting_within(s, depth))
    };
    if fits(&body) {
        return Some(body);
    }
    let fitted = match r {
        ContentRef::Message(_) => {
            let m: MessageContent = read_stored(&body).ok()?;
            // Room for the item's own fields around the message.
            let marker = oversized_message_marker(&m.message, body.len(), max - 1024);
            let content_size = serde_json::to_string(&marker).map_or(0, |s| s.len() as i32);
            serde_json::to_vec(&MessageContent { hash: m.hash, message: marker, content_size }).ok()?
        }
        ContentRef::ToolDefinition(_) | ContentRef::SystemPrompt(_) => {
            shrink_json_to_fit(std::str::from_utf8(&body).ok()?, max)?.into_bytes()
        }
        ContentRef::Blob(_) => return None,
    };
    tracing::error!(bytes = body.len(), max, "content too large for an ingest request — stored with its largest content replaced by notes");
    fits(&fitted).then_some(fitted)
}

/// A conversation message too large to deliver, replaced by a marker the
/// conversation view renders. A stored message is in its client's wire format,
/// so the marker keeps the message's shape: only its content channel —
/// `content` (Chat Completions, Anthropic, a Responses message) or `parts`
/// (Gemini) — is replaced, by the parts that pair a tool call with its result
/// ([`pairing_part`]), a text note and the canonical stripped part
/// (`DomainContentBlock::Stripped`, reason `oversized`). Every other field is
/// kept, so a call and its result still pair up in replay whether the id sits
/// on the message (Chat Completions `tool_call_id`, a Responses item's
/// `call_id`) or on a part. Both the note and the stripped part, because not
/// every walk keeps a non-text part: Chat Completions reads only the text of
/// an assistant or tool message. Where the bulk is elsewhere (a Responses
/// `output`), the marker is then shrunk like any record
/// ([`shrink_json_to_fit`]) to `max_bytes`.
fn oversized_message_marker(message: &serde_json::Value, bytes: usize, max_bytes: usize) -> serde_json::Value {
    let note = format!(
        "[message not stored: {bytes} bytes exceeds the edge sync limit of {} bytes]",
        streamscope_edge_api::ingest::CONTENT_MAX_BYTES
    );
    let stripped = serde_json::json!({ "type": "stripped", "size_bytes": bytes, "reason": "oversized" });
    let channel = |parts: Option<&serde_json::Value>, text: serde_json::Value| {
        let pairing = parts.and_then(serde_json::Value::as_array).into_iter().flatten();
        serde_json::Value::Array(pairing.filter_map(|p| pairing_part(p, &note)).chain([text, stripped.clone()]).collect())
    };
    let anthropic_text = || serde_json::json!({ "type": "text", "text": note });
    let minimal = || {
        serde_json::json!({
            "role": message.get("role").cloned().unwrap_or(serde_json::Value::Null),
            "content": channel(None, anthropic_text()),
        })
    };
    let Some(fields) = message.as_object() else {
        return minimal();
    };
    let mut marker = serde_json::Map::new();
    for (key, value) in fields {
        let replacement = match key.as_str() {
            "parts" => channel(Some(value), serde_json::json!({ "text": note })),
            "content" => channel(Some(value), anthropic_text()),
            _ => value.clone(),
        };
        marker.insert(key.clone(), replacement);
    }
    let marker = serde_json::Value::Object(marker);
    let Ok(json) = serde_json::to_string(&marker) else {
        return minimal();
    };
    if json.len() <= max_bytes {
        return marker;
    }
    shrink_json_to_fit(&json, max_bytes)
        .and_then(|small| streamscope_core::edge_wire::from_str_bounded(&small).ok())
        .unwrap_or_else(minimal)
}

/// The part of a replaced message that pairs a tool call with its result,
/// kept to its scalar fields (ids, name, flags) with its payload replaced: an
/// Anthropic `tool_use` / `server_tool_use` / `mcp_tool_use` (`input` emptied) or a
/// `tool_result` / `*_tool_result` (`content` becomes the note), a Gemini
/// `functionCall` (`args` emptied) or `functionResponse` (`response` holds the
/// note). `None` for any other part.
fn pairing_part(part: &serde_json::Value, note: &str) -> Option<serde_json::Value> {
    type Fields = serde_json::Map<String, serde_json::Value>;
    fn scalars(fields: &Fields) -> Fields {
        fields.iter().filter(|(_, v)| !(v.is_array() || v.is_object())).map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    let fields = part.as_object()?;
    let mut kept = scalars(fields);
    match fields.get("type").and_then(serde_json::Value::as_str) {
        Some("tool_use" | "server_tool_use" | "mcp_tool_use") => {
            kept.insert("input".into(), serde_json::json!({}));
            return Some(kept.into());
        }
        Some(t) if t == "tool_result" || t.ends_with("_tool_result") => {
            kept.insert("content".into(), serde_json::json!(note));
            return Some(kept.into());
        }
        _ => {}
    }
    for (wrapper, payload, value) in [
        ("functionCall", "args", serde_json::json!({})),
        ("functionResponse", "response", serde_json::json!({ "note": note })),
    ] {
        if let Some(serde_json::Value::Object(inner)) = fields.get(wrapper) {
            let mut inner = scalars(inner);
            inner.insert(payload.into(), value);
            kept.insert(wrapper.into(), inner.into());
            return Some(kept.into());
        }
    }
    None
}

/// A string this short is not worth replacing — the note is about as long.
const NOTE_ROOM: usize = 256;

/// Shrink one JSON value until it serializes within `max_bytes`, by replacing
/// its largest string values — wherever they sit — with a note naming their
/// size, largest first. The value keeps its shape and every other field, so
/// it still lands and shows what was not stored. One pass: the strings are
/// ranked once and the size is tracked as they are replaced, then the value
/// is serialized once. `None` when replacing every string large enough to make
/// a difference is still not enough.
fn shrink_json_to_fit(raw: &str, max_bytes: usize) -> Option<String> {
    fn large_strings(v: &serde_json::Value, path: &mut String, out: &mut Vec<(usize, String)>) {
        match v {
            serde_json::Value::String(s) if s.len() > NOTE_ROOM => out.push((s.len(), path.clone())),
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push_str(&format!("/{i}"));
                    large_strings(item, path, out);
                    path.truncate(len);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, item) in map {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&k.replace('~', "~0").replace('/', "~1"));
                    large_strings(item, path, out);
                    path.truncate(len);
                }
            }
            _ => {}
        }
    }
    fn serialized_len(v: &serde_json::Value) -> usize {
        serde_json::to_string(v).map_or(0, |s| s.len())
    }
    if raw.len() <= max_bytes {
        return Some(raw.to_string());
    }
    let mut value: serde_json::Value = streamscope_core::edge_wire::from_str_bounded(raw).ok()?;
    let mut strings = Vec::new();
    large_strings(&value, &mut String::new(), &mut strings);
    strings.sort_unstable_by_key(|(len, _)| std::cmp::Reverse(*len));
    let mut size = raw.len();
    for (len, pointer) in strings {
        if size <= max_bytes {
            break;
        }
        let slot = value.pointer_mut(&pointer)?;
        let note = serde_json::Value::String(format!(
            "[not stored: {len} bytes — the record exceeds the edge sync limit of {} bytes]",
            streamscope_edge_api::ingest::CONTENT_MAX_BYTES
        ));
        size = size - serialized_len(slot) + serialized_len(&note);
        *slot = note;
    }
    let json = serde_json::to_string(&value).ok()?;
    (json.len() <= max_bytes).then_some(json)
}

/// The content rows of `content`, keyed, as stored.
/// A body that does not serialize is left out (logged): its records name it
/// unavailable, as they do one too large to buffer.
fn content_rows(content: &Content) -> Vec<(ContentRef, Vec<u8>)> {
    let rows = content.messages.iter().map(|m| (ContentRef::Message(m.hash.clone()), serde_json::to_vec(m)))
        .chain(content.tool_definitions.iter().map(|t| (ContentRef::ToolDefinition(t.hash.clone()), serde_json::to_vec(t))))
        .chain(content.system_prompts.iter().map(|p| (ContentRef::SystemPrompt(p.hash.clone()), serde_json::to_vec(p))))
        .chain(content.blobs.iter().map(|b| (ContentRef::Blob(b.blob_ref()), serde_json::to_vec(b))));
    rows.filter_map(|(r, body)| match body {
        Ok(body) => Some((r, body)),
        Err(e) => {
            let (kind, hash) = r.key();
            tracing::error!(%kind, %hash, "content does not serialize — not buffered; its records ship without it: {e}");
            None
        }
    })
    .collect()
}

/// A share's size on the wire, as the request budget counts it.
fn share_size(share: &TenantShare) -> usize {
    serde_json::to_vec(share).map(|v| v.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::audit::McpAuditRecord;
    use streamscope_core::config::mcp::McpUserCredential;
    use streamscope_core::mcp::sse_events::McpSseEventRecord;
    use streamscope_edge_api::ingest::RowRef;
    use std::collections::BTreeMap;

    /// The keys a share's records name that it neither carries nor names
    /// unavailable: the bodies admin-api acked, left out.
    fn left_out(p: &PendingShare) -> Vec<ContentKey> {
        let carried: BTreeSet<(String, String)> = content_rows(&p.share.content).into_iter().map(|(r, _)| r.key()).collect();
        let unavailable: BTreeSet<(String, String)> = p.share.unavailable.iter().map(row_key).collect();
        let mut seen = BTreeSet::new();
        p.share
            .records
            .iter()
            .flat_map(Record::content_keys)
            .filter(|k| {
                let key = row_key(k);
                !carried.contains(&key) && !unavailable.contains(&key) && seen.insert(key)
            })
            .collect()
    }

    /// A share's content keys, by kind.
    fn content_key_set(share: &TenantShare) -> BTreeMap<&'static str, BTreeSet<String>> {
        let mut out: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        out.entry("message").or_default().extend(share.content.messages.iter().map(|m| m.hash.clone()));
        out.entry("tool_definition").or_default().extend(share.content.tool_definitions.iter().map(|t| t.hash.clone()));
        out.entry("blob").or_default().extend(share.content.blobs.iter().map(|b| b.content_hash.clone()));
        out
    }

    async fn outbox() -> OutboxV2 {
        let dir = std::env::temp_dir().join(format!("streamscope_outbox_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        OutboxV2::open(dir.to_str().unwrap()).await.unwrap()
    }

    fn event(tenant: uuid::Uuid, seq: i64) -> Record {
        Record::McpSseEvent(Box::new(McpSseEventRecord {
            tenant_id: tenant,
            user_id: uuid::Uuid::nil(),
            mcp_session_id: "s".into(),
            virtual_server_id: None,
            event_id: format!("e{seq}"),
            sequence: seq,
            event_data: vec![b'x'; 16],
            created_at: "2026-10-03T10:00:00Z".parse().unwrap(),
        }))
    }

    fn rotation(tenant: uuid::Uuid, token: &str, expires: Option<&str>) -> Record {
        Record::CredentialRotation(Box::new(McpUserCredential {
            tenant_id: tenant,
            user_id: uuid::Uuid::from_u128(1),
            upstream_server_id: uuid::Uuid::from_u128(2),
            encrypted_access_token: token.into(),
            encrypted_refresh_token: None,
            expires_at: expires.map(|s| s.parse().unwrap()),
            scope: None,
        }))
    }

    fn message(hash: &str) -> MessageContent {
        MessageContent { hash: hash.into(), message: serde_json::json!({"role": "user", "content": hash}), content_size: 1 }
    }

    fn blob(hash: &str, len: usize) -> BlobContent {
        BlobContent {
            content_hash: hash.into(),
            blob_type: BlobType::ChatImage,
            media_type: "image/png".into(),
            data_base64: "A".repeat(len),
        }
    }

    fn blob_ref(hash: &str) -> ContentRef {
        ContentRef::Blob(BlobRef { content_hash: hash.into(), blob_type: BlobType::ChatImage })
    }

    /// A blob at the platform's cap is buffered whole, past the room other
    /// content gets; one past the cap's row is not.
    #[test]
    fn a_blob_at_the_platform_cap_is_buffered_and_one_past_its_row_is_not() {
        let encoded = |decoded: usize| serde_json::to_vec(&blob("h", decoded.div_ceil(3) * 4)).unwrap();
        let cap = streamscope_edge_api::ingest::CONTENT_MAX_BYTES + 1024 * 1024;
        assert!(fit_content_under(&blob_ref("h"), encoded(cap), cap).is_some(), "the cap is buffered");
        let past = blob_row_max_bytes(cap) + 1;
        assert!(fit_content_under(&blob_ref("h"), vec![b'x'; past], cap).is_none(), "past the cap's row it is refused");
        assert!(fit_content_under(&blob_ref("h"), vec![b'x'; past - 1], cap).is_some(), "the row's bound itself is buffered");
    }

    fn with(record: Record) -> Enqueued {
        Enqueued { record }
    }

    /// An LLM turn of `tenant`, keyed by `seq`, naming `refs` — as its
    /// history, tool set, system prompt and blobs: the content it needs.
    fn turn_naming(tenant: uuid::Uuid, seq: i64, refs: Vec<ContentRef>) -> Enqueued {
        let mut turn = streamscope_core::audit::AuditRecord {
            request_id: uuid::Uuid::from_u128(1 << 64 | seq as u128),
            timestamp: "2026-10-03T10:00:00Z".parse().unwrap(),
            tenant_id: tenant,
            ..Default::default()
        };
        for r in refs {
            match r {
                ContentRef::Message(h) => turn.message_hashes.get_or_insert_with(Vec::new).push(h),
                ContentRef::ToolDefinition(h) => turn.tools_available_hash = Some(h),
                ContentRef::SystemPrompt(h) => turn.system_prompt_hash = Some(h),
                ContentRef::Blob(b) => turn.buffered_blobs.push(b),
            }
        }
        Enqueued { record: Record::LlmAudit(Box::new(turn)) }
    }

    async fn content_count(o: &OutboxV2) -> i64 {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM content").fetch_one(&o.pool).await.unwrap().0
    }

    #[tokio::test]
    async fn the_process_epoch_grows_with_every_start_survives_a_reopen_and_a_restore() {
        let dir = std::env::temp_dir().join(format!("streamscope_outbox_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let o = OutboxV2::open(path).await.unwrap();
        let first = o.start_process().await.unwrap();
        assert!(first >= now, "at least the clock");
        let second = o.start_process().await.unwrap();
        assert!(second > first, "and always more than the last, however fast the restarts");
        drop(o);
        let reopened = OutboxV2::open(path).await.unwrap();
        let third = reopened.start_process().await.unwrap();
        assert!(third > second);
        // A store restored from an older backup: its counter is far behind.
        // The next start is the clock again — past every epoch a process of
        // this store started at before the restore (one per second, at most).
        sqlx::query("UPDATE meta SET value = 5 WHERE key = 'process_epoch'").execute(&reopened.pool).await.unwrap();
        let restored = reopened.start_process().await.unwrap();
        assert!(restored >= now && restored > 5, "a restored counter restarts at the clock, not at its own value");
    }

    #[tokio::test]
    async fn a_record_is_buffered_once_per_natural_key_and_content_once_per_hash() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let content = Content { messages: vec![message("m1")], ..Default::default() };
        o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("m1".into())])], &content).await.unwrap();
        o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("m1".into())])], &content).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 1);
        assert_eq!(content_count(&o).await, 1);
        // Positive control: another key is another record.
        o.enqueue(t, &[with(event(t, 2))], &Content::default()).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_share_carries_its_records_content_and_tenants_never_mix() {
        let o = outbox().await;
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        o.enqueue(
            a,
            &[turn_naming(a, 1, vec![ContentRef::Message("m1".into()), blob_ref("b1")])],
            &Content { messages: vec![message("m1"), message("unused")], blobs: vec![blob("b1", 8)], ..Default::default() },
        )
        .await
        .unwrap();
        o.enqueue(b, &[turn_naming(b, 1, vec![ContentRef::Message("m2".into())])], &Content { messages: vec![message("m2")], ..Default::default() })
            .await
            .unwrap();
        let shares = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap();
        assert_eq!(shares.len(), 2);
        // Oldest tenant first.
        assert_eq!(shares[0].share.tenant, a);
        let keys = content_key_set(&shares[0].share);
        assert_eq!(keys["message"], BTreeSet::from(["m1".to_string()]), "only referenced content travels");
        assert_eq!(keys["blob"], BTreeSet::from(["b1".to_string()]));
        assert!(shares[0].share.records.iter().all(|r| r.tenant_id() == a));
        assert_eq!(shares[1].share.tenant, b);
        assert_eq!(content_key_set(&shares[1].share)["message"], BTreeSet::from(["m2".to_string()]));
    }

    #[tokio::test]
    async fn content_survives_until_its_last_referencing_record_commits() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let content = Content { messages: vec![message("shared")], ..Default::default() };
        o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("shared".into())])], &content).await.unwrap();
        // The first share holds only the first record (a budget one record wide).
        let first = o.assemble_with(usize::MAX, 1, &Uploads::idle()).await.unwrap().remove(0);
        o.enqueue(t, &[turn_naming(t, 2, vec![ContentRef::Message("shared".into())])], &content).await.unwrap();
        assert_eq!(first.share.records.len(), 1);
        assert_eq!(o.apply(&first, &ShareOutcome::Committed).await.unwrap(), Applied::Deleted);
        assert_eq!(o.pending().await.unwrap(), 1);
        assert_eq!(content_count(&o).await, 1, "the second record still needs the content");
        // Admin-api acked it with the first: the second record names it.
        let second = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert!(second.share.content.messages.is_empty());
        assert_eq!(left_out(&second), vec![ContentKey::Message { hash: "shared".into() }]);
        o.apply(&second, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 0);
        assert_eq!(content_count(&o).await, 0);
    }

    #[tokio::test]
    async fn retry_keeps_everything_and_rejected_drops_like_committed() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("m".into())])], &Content { messages: vec![message("m")], ..Default::default() })
            .await
            .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(o.apply(&share, &ShareOutcome::Retry { missing: vec![] }).await.unwrap(), Applied::Kept);
        assert_eq!(o.pending().await.unwrap(), 1);
        assert_eq!(content_count(&o).await, 1);
        let again = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(again.share.records.len(), 1, "a kept share is assembled again");
        let rejected = ShareOutcome::Rejected {
            rows: vec![RowRef { kind: RecordKind::McpSseEvent, key: again.share.records[0].natural_key() }],
            reason: "22003".into(),
        };
        assert_eq!(o.apply(&again, &rejected).await.unwrap(), Applied::Deleted);
        assert_eq!(o.pending().await.unwrap(), 0);
        assert_eq!(content_count(&o).await, 0);
    }

    #[tokio::test]
    async fn tenant_deleted_drops_that_tenant_only() {
        let o = outbox().await;
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        for t in [a, b] {
            o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("m".into())])], &Content { messages: vec![message("m")], ..Default::default() })
                .await
                .unwrap();
        }
        let shares = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap();
        let of_a = shares.iter().find(|s| s.share.tenant == a).unwrap();
        o.apply(of_a, &ShareOutcome::TenantDeleted).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 1);
        assert_eq!(content_count(&o).await, 1);
        assert_eq!(o.assemble(usize::MAX, &Uploads::idle()).await.unwrap()[0].share.tenant, b);
    }

    /// A blob larger than any request carries is buffered whole (up to the
    /// platform's cap, see `fit_content_under`) and goes up by itself, first;
    /// the records then name it.
    #[tokio::test]
    async fn a_blob_past_what_a_request_carries_is_buffered_and_goes_up_by_itself() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        o.enqueue(t, &[turn_naming(t, 1, vec![blob_ref("huge"), blob_ref("fits")])], &Content {
            blobs: vec![blob("huge", limit), blob("fits", 1024)],
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(content_count(&o).await, 2, "both are buffered");
        let shares = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap();
        assert_eq!(shares[0].upload().map(|b| b.content_hash.as_str()), Some("huge"), "the large one goes up first");
        assert!(shares[0].share.records.is_empty());
        o.apply(&shares[0], &ShareOutcome::Committed).await.unwrap();
        let shares = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap();
        assert!(shares[0].upload().is_none());
        assert_eq!(left_out(&shares[0]), vec![ContentKey::Blob { content_hash: "huge".into(), blob_type: BlobType::ChatImage }]);
        let carried: BTreeSet<String> = shares[0].share.content.blobs.iter().map(|b| b.content_hash.clone()).collect();
        assert_eq!(carried, BTreeSet::from(["fits".to_string()]), "the small one travels with its record");
    }

    #[tokio::test]
    async fn an_oversized_message_is_stored_as_a_marker_that_keeps_its_shape() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        let big = MessageContent {
            hash: "m".into(),
            message: serde_json::json!({"role": "tool", "tool_call_id": "c1", "content": "x".repeat(limit)}),
            content_size: limit as i32,
        };
        o.enqueue(t, &[turn_naming(t, 1, vec![ContentRef::Message("m".into())])], &Content {
            messages: vec![big],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0).share;
        let m = &share.content.messages[0].message;
        assert_eq!(m["tool_call_id"], "c1", "every other field is kept");
        assert_eq!(m["content"][1]["type"], "stripped");
        assert!(serde_json::to_vec(m).unwrap().len() < limit);
    }

    #[tokio::test]
    async fn an_oversized_message_keeps_the_parts_that_pair_a_call_with_its_result() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        let bulk = "x".repeat(limit);
        let anthropic = MessageContent {
            hash: "a".into(),
            message: serde_json::json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "is_error": false, "content": [{"type": "text", "text": bulk}]},
                {"type": "text", "text": "and a remark"},
                {"type": "mcp_tool_use", "id": "mcptoolu_1", "name": "search", "server_name": "s", "input": {"q": "x"}},
            ]}),
            content_size: limit as i32,
        };
        let gemini = MessageContent {
            hash: "g".into(),
            message: serde_json::json!({"role": "user", "parts": [
                {"functionResponse": {"name": "read_file", "id": "fc_1", "response": {"output": bulk},
                                      "parts": [{"inlineData": {"mimeType": "image/png", "data": bulk}}]}},
            ]}),
            content_size: limit as i32,
        };
        let refs = vec![ContentRef::Message("a".into()), ContentRef::Message("g".into())];
        o.enqueue(t, &[turn_naming(t, 1, refs)], &Content { messages: vec![anthropic, gemini], ..Default::default() })
            .await
            .unwrap();
        let messages = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().into_iter().flat_map(|s| s.share.content.messages).collect::<Vec<_>>();
        let by_hash = |h: &str| messages.iter().find(|m| m.hash == h).unwrap().message.clone();

        let a = by_hash("a");
        let a_parts = a["content"].as_array().unwrap();
        assert_eq!(a_parts.len(), 4, "the result, the call, the note and the stripped part — not the plain text: {a}");
        assert_eq!((&a_parts[0]["type"], &a_parts[0]["tool_use_id"], &a_parts[0]["is_error"]), (&"tool_result".into(), &"toolu_1".into(), &false.into()));
        assert!(a_parts[0]["content"].as_str().unwrap().starts_with("[message not stored:"));
        assert_eq!((&a_parts[1]["id"], &a_parts[1]["name"], &a_parts[1]["input"]), (&"mcptoolu_1".into(), &"search".into(), &serde_json::json!({})));
        assert_eq!(a_parts[3]["type"], "stripped");

        let g = by_hash("g");
        let g_parts = g["parts"].as_array().unwrap();
        assert_eq!(g_parts.len(), 3, "{g}");
        let fr = &g_parts[0]["functionResponse"];
        assert_eq!((&fr["name"], &fr["id"]), (&"read_file".into(), &"fc_1".into()), "the call's name and id pair it");
        assert!(fr["response"]["note"].as_str().unwrap().starts_with("[message not stored:"));
        assert!(fr.get("parts").is_none(), "its bulk is gone");
        assert!(serde_json::to_vec(&g).unwrap().len() < limit);
    }

    #[tokio::test]
    async fn a_record_too_large_is_shrunk_and_one_that_cannot_be_keeps_its_identity() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        // Built, not parsed: a value this deep is past what serde_json reads.
        let mut deep_params = serde_json::Value::Null;
        for _ in 0..MAX_DEPTH {
            deep_params = serde_json::Value::Array(vec![deep_params]);
        }
        // Bulk no string replacement can remove.
        let wide_params = serde_json::Value::Array(vec![serde_json::json!(1234567); limit / 4]);
        let mcp = |seq: u128, params: serde_json::Value| -> Record {
            let mut r: McpAuditRecord = serde_json::from_value(serde_json::json!({
                "request_id": uuid::Uuid::from_u128(seq), "timestamp": "2026-10-03T10:00:00Z",
                "tenant_id": t, "workspace_id": t, "user_id": t, "latency_total_ms": 1,
                "virtual_server_id": t, "method": "tools/call", "status_code": 200,
                "badges": [{"code": "mcp_legacy_sse"}], "error_message": "why".repeat(200),
            }))
            .unwrap();
            r.params = Some(params);
            Record::McpAudit(Box::new(r))
        };
        let mut large = mcp(0, serde_json::json!([1]));
        if let Record::McpAudit(r) = &mut large {
            r.error_detail = Some("e".repeat(limit));
        }
        o.enqueue(
            t,
            &[
                with(large),
                with(mcp(1, deep_params)),
                with(mcp(2, serde_json::json!([1]))),
                with(mcp(3, wide_params)),
            ],
            &Content::default(),
        )
        .await
        .unwrap();
        assert_eq!(o.pending().await.unwrap(), 4, "nothing is dropped");
        let records = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().into_iter().flat_map(|s| s.share.records).collect::<Vec<_>>();
        let Record::McpAudit(r) = &records[0] else { unreachable!() };
        assert!(r.error_detail.as_deref().unwrap().starts_with("[not stored:"), "the largest string became a note");
        assert!(!r.badges.iter().any(|b| b.code() == "record_stripped"), "shrunk, not stripped");
        assert!(matches!(&records[2], Record::McpAudit(r) if r.params == Some(serde_json::json!([1]))), "a record that fits is untouched");
        for (record, seq, reason) in [(&records[1], 1, "too_deep"), (&records[3], 3, "oversized")] {
            let Record::McpAudit(r) = record else { unreachable!() };
            assert_eq!(r.request_id, uuid::Uuid::from_u128(seq), "its identity is kept");
            assert_eq!((r.status_code, r.method.as_str()), (Some(200), "tools/call"), "its status is kept");
            assert_eq!(r.params, None, "its payload is left out");
            assert_eq!(r.error_message.as_deref(), Some("why".repeat(200).as_str()), "a string that fits is kept whole");
            assert_eq!(
                r.badges,
                vec![
                    streamscope_core::audit::AuditBadge::McpLegacySse,
                    streamscope_core::audit::AuditBadge::RecordStripped { reason: reason.into() }
                ],
                "badged beside the badges it had"
            );
        }
    }

    #[test]
    fn an_llm_audit_record_that_cannot_travel_keeps_its_identity_and_its_counters() {
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        let t = uuid::Uuid::new_v4();
        let record = streamscope_core::audit::AuditRecord {
            request_id: uuid::Uuid::from_u128(7),
            tenant_id: t,
            model_used: "m".into(),
            prompt_tokens: 11,
            cost: 0.5,
            status_code: Some(200),
            request_params: Some(serde_json::Value::Array(vec![serde_json::json!(1234567); limit / 4])),
            message_hashes: Some(vec!["h1".into()]),
            ..Default::default()
        };
        let body = fit_record(&Record::LlmAudit(Box::new(record))).unwrap().expect("kept, not dropped").body;
        let Record::LlmAudit(r) = serde_json::from_slice::<Record>(&body).unwrap() else { unreachable!() };
        assert_eq!((r.request_id, r.tenant_id, r.model_used.as_str()), (uuid::Uuid::from_u128(7), t, "m"));
        assert_eq!((r.prompt_tokens, r.cost, r.status_code), (11, 0.5, Some(200)), "its counters are kept");
        assert_eq!(r.request_params, None);
        assert_eq!(r.message_hashes, Some(vec!["h1".to_string()]), "its turn still links its messages");
        assert_eq!(r.badges, vec![streamscope_core::audit::AuditBadge::RecordStripped { reason: "oversized".into() }]);
    }

    #[test]
    fn an_event_or_a_credential_that_cannot_travel_whole_is_not_stripped() {
        let mut record = event(uuid::Uuid::new_v4(), 3);
        if let Record::McpSseEvent(e) = &mut record {
            e.event_data = vec![b'x'; streamscope_edge_api::ingest::CONTENT_MAX_BYTES];
        }
        assert!(fit_record(&record).unwrap().is_none(), "an emptied event would be replayed as nothing");
        let mut renamed = event(uuid::Uuid::new_v4(), 4);
        if let Record::McpSseEvent(e) = &mut renamed {
            e.event_id = "e".repeat(streamscope_edge_api::ingest::CONTENT_MAX_BYTES);
        }
        assert!(fit_record(&renamed).unwrap().is_none(), "a noted id would replay under a made-up id");
        let token = "t".repeat(streamscope_edge_api::ingest::CONTENT_MAX_BYTES);
        let credential = rotation(uuid::Uuid::new_v4(), &token, None);
        assert!(fit_record(&credential).unwrap().is_none(), "a noted token would replace a working credential");
        assert!(fit_record(&rotation(uuid::Uuid::new_v4(), "small", None)).unwrap().is_some());
        // Positive control: the same event, small, travels.
        assert!(fit_record(&event(uuid::Uuid::new_v4(), 3)).unwrap().is_some());
    }

    #[test]
    fn a_record_whose_badges_are_the_bulk_keeps_one_of_each_code() {
        let limit = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        // Bulk no string replacement can remove: many badges, each short.
        let alert = |n: usize| streamscope_core::audit::AuditBadge::AgentAlert {
            axis: format!("x{n}"),
            level: streamscope_core::audit::badge::AlertLevel::Minor,
        };
        let record = streamscope_core::audit::AuditRecord {
            request_id: uuid::Uuid::from_u128(8),
            badges: std::iter::once(streamscope_core::audit::AuditBadge::Unpriced).chain((0..limit / 32).map(alert)).collect(),
            message_hashes: Some(vec!["m".into()]),
            tools_available_hash: Some("t".into()),
            system_prompt_hash: Some("p".into()),
            ..Default::default()
        };
        let body = fit_record(&Record::LlmAudit(Box::new(record))).unwrap().expect("kept, not dropped").body;
        let stripped = serde_json::from_slice::<Record>(&body).unwrap();
        // Past keeping its turn, it names no body: none is stored with no turn.
        assert!(stripped.content_keys().is_empty(), "{:?}", stripped.content_keys());
        let Record::LlmAudit(r) = stripped else { unreachable!() };
        assert_eq!(r.request_id, uuid::Uuid::from_u128(8));
        assert_eq!(
            r.badges,
            vec![
                streamscope_core::audit::AuditBadge::Unpriced,
                alert(0),
                streamscope_core::audit::AuditBadge::RecordStripped { reason: "oversized".into() }
            ],
            "one badge of each code it raised, and the stripped one"
        );
    }

    #[tokio::test]
    async fn a_record_nested_past_the_default_parse_limit_but_within_the_bound_ships() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        // Deeper than serde_json's default of 128, well within what the outbox admits.
        let mut params = serde_json::Value::Null;
        for _ in 0..200 {
            params = serde_json::Value::Array(vec![params]);
        }
        let mut r: McpAuditRecord = serde_json::from_value(serde_json::json!({
            "request_id": uuid::Uuid::from_u128(1), "timestamp": "2026-10-03T10:00:00Z",
            "tenant_id": t, "workspace_id": t, "user_id": t, "latency_total_ms": 1,
            "virtual_server_id": t, "method": "tools/call",
        }))
        .unwrap();
        r.params = Some(params.clone());
        o.enqueue(t, &[with(Record::McpAudit(Box::new(r)))], &Content::default()).await.unwrap();
        let shares = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap();
        assert_eq!(shares.len(), 1, "read back, not dropped");
        assert!(matches!(&shares[0].share.records[0], Record::McpAudit(r) if r.params == Some(params)));
    }

    #[tokio::test]
    async fn a_lone_record_sheds_content_no_request_could_carry_with_it() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let each = streamscope_edge_api::ingest::CONTENT_MAX_BYTES - 4096;
        let msg = |h: &str| MessageContent {
            hash: h.into(),
            message: serde_json::json!({"role": "user", "content": "y".repeat(each - 64)}),
            content_size: 1,
        };
        o.enqueue(
            t,
            &[turn_naming(t, 1, vec![ContentRef::Message("a".into()), ContentRef::Message("b".into())])],
            &Content { messages: vec![msg("a"), msg("b")], ..Default::default() },
        )
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0).share;
        assert_eq!(share.records.len(), 1, "the record still ships");
        assert_eq!(share.content.messages.len(), 1, "one message was shed so the share fits a request");
        assert!(serde_json::to_vec(&share).unwrap().len() <= LONE_SHARE_MAX_BYTES);
        assert_eq!(content_count(&o).await, 1);
    }

    #[tokio::test]
    async fn only_a_requests_first_share_may_pass_the_budget() {
        let o = outbox().await;
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        o.enqueue(a, &[with(event(a, 1))], &Content::default()).await.unwrap();
        o.enqueue(b, &[with(event(b, 1))], &Content::default()).await.unwrap();
        let one = serde_json::to_vec(&event(a, 1)).unwrap().len();
        // Room for about one record: the first tenant's goes, the second waits.
        let shares = o.assemble_with(one + one / 2, usize::MAX, &Uploads::idle()).await.unwrap();
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].share.tenant, a);
    }

    #[tokio::test]
    async fn an_oversized_blob_travels_alone_first_and_is_then_named_not_carried() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[turn_naming(t, 1, vec![blob_ref("big"), ContentRef::Message("m".into())])], &Content {
            messages: vec![message("m")],
            blobs: vec![blob("big", 4096)],
            ..Default::default()
        })
        .await
        .unwrap();
        let budget = 2048;
        let first = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert!(first.share.records.is_empty(), "content-only share");
        assert_eq!(content_key_set(&first.share)["blob"], BTreeSet::from(["big".to_string()]));
        // Until it commits, it is offered again as is.
        let retried = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert!(retried.share.records.is_empty());
        assert_eq!(o.apply(&first, &ShareOutcome::Committed).await.unwrap(), Applied::Shipped);
        assert_eq!(o.pending().await.unwrap(), 1, "the record is still buffered");
        let records = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(records.share.records.len(), 1);
        assert!(records.share.content.blobs.is_empty(), "a shipped blob is not carried again");
        assert_eq!(left_out(&records), vec![ContentKey::Blob { content_hash: "big".into(), blob_type: BlobType::ChatImage }]);
        assert_eq!(content_key_set(&records.share)["message"], BTreeSet::from(["m".to_string()]));
        // admin-api lost it: the next assembly ships it again.
        let missing = vec![ContentKey::Blob { content_hash: "big".into(), blob_type: BlobType::ChatImage }];
        o.apply(&records, &ShareOutcome::Retry { missing }).await.unwrap();
        let reship = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert!(reship.share.records.is_empty());
        assert_eq!(content_key_set(&reship.share)["blob"], BTreeSet::from(["big".to_string()]));
        // Once the records commit, the blob goes with them.
        o.apply(&reship, &ShareOutcome::Committed).await.unwrap();
        let last = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        o.apply(&last, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 0);
        assert_eq!(content_count(&o).await, 0);
    }

    /// An LLM turn of `tenant` naming `hashes` as its history.
    fn turn(tenant: uuid::Uuid, request: u128, hashes: &[&str]) -> Record {
        Record::LlmAudit(Box::new(streamscope_core::audit::AuditRecord {
            request_id: uuid::Uuid::from_u128(request),
            tenant_id: tenant,
            message_hashes: Some(hashes.iter().map(|h| h.to_string()).collect()),
            ..Default::default()
        }))
    }

    #[tokio::test]
    async fn a_body_a_turn_names_that_the_outbox_does_not_hold_is_named_unavailable() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        // "kept" was buffered with the turn; "lost" never was (refused when
        // buffered, say): the record still names both.
        o.enqueue(t, &[with(turn(t, 1, &["kept", "lost"]))], &Content {
            messages: vec![message("kept")],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(content_key_set(&share.share)["message"], BTreeSet::from(["kept".to_string()]), "what it holds is carried");
        assert_eq!(share.share.unavailable, vec![ContentKey::Message { hash: "lost".into() }]);
        assert!(left_out(&share).is_empty());
        // A body named twice in a share is accounted for once.
        o.enqueue(t, &[with(turn(t, 2, &["lost"]))], &Content::default()).await.unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.records.len(), 2);
        assert_eq!(share.share.unavailable, vec![ContentKey::Message { hash: "lost".into() }]);
        // Content buffered beside a turn that does not name it is not kept,
        // and the share carries only what its turns name.
        o.enqueue(t, &[with(turn(t, 3, &[]))], &Content {
            messages: vec![message("unnamed")],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.records.len(), 3);
        assert_eq!(content_key_set(&share.share)["message"], BTreeSet::from(["kept".to_string()]), "only what a turn names");
    }

    #[tokio::test]
    async fn an_sse_event_needs_no_content_and_content_buffered_with_it_is_not_kept() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[with(event(t, 1))], &Content { messages: vec![message("beside")], ..Default::default() })
            .await
            .unwrap();
        assert_eq!(content_count(&o).await, 0, "an event names nothing, so nothing is kept");
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.records.len(), 1);
        assert!(share.share.content.is_empty() && left_out(&share).is_empty() && share.share.unavailable.is_empty());
        // Positive control: a turn naming the same body keeps it.
        o.enqueue(t, &[turn_naming(t, 2, vec![ContentRef::Message("beside".into())])], &Content {
            messages: vec![message("beside")],
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(content_count(&o).await, 1);
    }

    #[tokio::test]
    async fn a_turn_stripped_past_its_blob_ships_while_another_blob_goes_up_and_its_blob_is_not_kept() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        // Bulk no string replacement can remove: stripped to its identity,
        // it no longer names its blob.
        let alert = |n: usize| streamscope_core::audit::AuditBadge::AgentAlert {
            axis: format!("x{n}"),
            level: streamscope_core::audit::badge::AlertLevel::Minor,
        };
        let big = BlobRef { content_hash: "big".into(), blob_type: BlobType::ChatImage };
        let record = Record::LlmAudit(Box::new(streamscope_core::audit::AuditRecord {
            request_id: uuid::Uuid::from_u128(9),
            tenant_id: t,
            badges: (0..streamscope_edge_api::ingest::CONTENT_MAX_BYTES / 32).map(alert).collect(),
            buffered_blobs: vec![big.clone()],
            ..Default::default()
        }));
        assert_eq!(record.content_keys(), vec![ContentKey::from(big)], "named before it is stripped");
        o.enqueue(t, &[with(record)], &Content { blobs: vec![blob("big", 4096)], ..Default::default() })
            .await
            .unwrap();
        assert_eq!(content_count(&o).await, 0, "a blob the stored turn does not name is not kept");
        // Another blob is on its way up: nothing may start, and the turn
        // needs nothing that waits.
        let busy = Uploads { held: vec![(t, "blob:chat_image".into(), "other".into())], may_start: false };
        let shares = o.assemble_with(usize::MAX, 2048, &busy).await.unwrap();
        let [share] = shares.as_slice() else { panic!("{} shares", shares.len()) };
        assert!(share.upload().is_none());
        assert_eq!(share.share.records.len(), 1, "read and shipped");
        assert!(share.share.content.is_empty() && left_out(share).is_empty() && share.share.unavailable.is_empty());
    }

    #[tokio::test]
    async fn each_build_opens_only_its_own_store_and_leaves_every_other() {
        let dir = std::env::temp_dir().join(format!("streamscope_outbox_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let o = OutboxV2::open(path).await.unwrap();
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[with(event(t, 1))], &Content::default()).await.unwrap();
        let first = o.instance().await.unwrap();
        o.pool.close().await;
        drop(o);
        // Positive control: this build's store reopens with what it held.
        let o = OutboxV2::open(path).await.unwrap();
        assert_eq!((o.pending().await.unwrap(), o.instance().await.unwrap()), (1, first));
        o.pool.close().await;
        drop(o);
        // The same store under other builds' names (an older one's, a later
        // one's) and a copy beside it: none is read, none is touched.
        let others = ["outbox_v2.s1.db", "outbox_v2.s99.db", "outbox_v2.s1.bak.db"];
        for other in others {
            std::fs::copy(dir.join(store_file()), dir.join(other)).unwrap();
        }
        std::fs::remove_file(dir.join(store_file())).unwrap();
        let o = OutboxV2::open(path).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 0, "another build's records are never read");
        assert_ne!(o.instance().await.unwrap(), first, "and a store created here is a new instance");
        let second = o.instance().await.unwrap();
        for other in others {
            assert!(dir.join(other).exists(), "{other} is left");
        }
        o.pool.close().await;
        drop(o);
        // Beside them, this build's store is kept whole; another build's
        // store that holds nothing is removed, having nothing to deliver.
        std::fs::copy(dir.join(store_file()), dir.join("outbox_v2.s97.db")).unwrap();
        let o = OutboxV2::open(path).await.unwrap();
        assert_eq!(o.instance().await.unwrap(), second);
        assert!(!dir.join("outbox_v2.s97.db").exists(), "an empty store of another build is removed");
        for other in others {
            assert!(dir.join(other).exists(), "{other}, holding a record, is still left");
        }
    }

    #[test]
    fn a_store_file_names_its_version_and_nothing_else_is_a_store() {
        for (name, v) in [("outbox_v2.s0.db", 0), ("outbox_v2.s1.db", 1), ("outbox_v2.s12.db", 12)] {
            assert_eq!(store_version(name), Some(v), "{name}");
        }
        assert_eq!(store_version(&store_file()), Some(STORE_VERSION));
        for name in [
            "outbox_v2.db",
            "outbox_v2.db.lock",
            "outbox_v2.s1.db-wal",
            "outbox_v2.s1.bak.db",
            "outbox_v2.old.db",
            "outbox_v2.s.db",
            "outbox_v2.sx.db",
            "outbox_v3.s1.db",
        ] {
            assert_eq!(store_version(name), None, "{name}");
        }
    }

    #[test]
    fn a_turn_whose_keys_would_not_fit_beside_it_is_stored_stripped() {
        let max = streamscope_edge_api::ingest::CONTENT_MAX_BYTES;
        let turn_of = |n: usize| {
            Record::LlmAudit(Box::new(streamscope_core::audit::AuditRecord {
                message_hashes: Some((0..n).map(|i| format!("{i:064x}")).collect()),
                ..Default::default()
            }))
        };
        // Each hash costs about 67 bytes in the body and 93 as a key.
        let past = turn_of(max / 120);
        assert!(serde_json::to_vec(&past).unwrap().len() < max, "the body alone fits");
        let Fitted { body, whole } = fit_record(&past).unwrap().expect("kept");
        assert!(!whole, "but not beside its keys");
        let stored: Record = serde_json::from_slice(&body).unwrap();
        assert!(body.len() + key_cost(&stored) <= max, "stored, it fits a request with every key it names");
        // Positive control: one that fits beside its keys is kept whole.
        let within = turn_of(max / 200);
        let Fitted { body, whole } = fit_record(&within).unwrap().expect("kept");
        assert!(whole && body.len() + key_cost(&within) <= max);
    }

    #[test]
    fn key_bytes_is_the_keys_length_on_the_wire() {
        let hash = "0123456789abcdef".repeat(4);
        let mut refs = vec![
            ContentRef::Message(hash.clone()),
            ContentRef::ToolDefinition(hash.clone()),
            ContentRef::SystemPrompt(hash.clone()),
        ];
        refs.extend(BlobType::ALL.iter().map(|t| ContentRef::Blob(BlobRef { content_hash: hash.clone(), blob_type: *t })));
        for r in refs {
            let (kind, h) = r.key();
            assert_eq!(key_bytes(&kind, &h), serde_json::to_vec(&r.content_key()).unwrap().len() + 1, "{kind}");
        }
    }

    #[tokio::test]
    async fn the_keys_a_share_names_count_toward_its_budget() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let hashes = |r: u128| (0..200).map(|i| format!("{r}-{i:062x}")).collect::<Vec<String>>();
        for r in 1..=2u128 {
            let named = hashes(r);
            let refs: Vec<&str> = named.iter().map(String::as_str).collect();
            // None of its bodies is held: each is named unavailable.
            o.enqueue(t, &[with(turn(t, r, &refs))], &Content::default()).await.unwrap();
        }
        let first = hashes(1);
        let body = serde_json::to_vec(&turn(t, 1, &first.iter().map(String::as_str).collect::<Vec<_>>())).unwrap().len();
        // Room for two bodies, not for two bodies and their keys.
        let budget = body * 5 / 2;
        let share = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.unavailable.len(), 200);
        assert_eq!(share.share.records.len(), 1, "the second turn's keys do not fit beside the first's");
        assert!(share_size(&share.share) <= budget, "{} > {budget}", share_size(&share.share));
    }

    #[tokio::test]
    async fn a_body_shed_because_no_request_could_carry_it_is_named_unavailable() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        // Each fits what a request carries; together they do not.
        let big = |h: &str| MessageContent {
            hash: h.into(),
            message: serde_json::json!({"role": "user", "content": "x".repeat(10 * 1024 * 1024)}),
            content_size: 1,
        };
        o.enqueue(t, &[with(turn(t, 1, &["a", "b", "c"]))], &Content {
            messages: vec![big("a"), big("b"), big("c")],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        let carried = content_key_set(&share.share)["message"].clone();
        assert_eq!(carried.len() + share.share.unavailable.len(), 3, "every body it names is carried or named lost");
        assert!(!carried.is_empty(), "what fits is still carried");
        for key in &share.share.unavailable {
            let ContentKey::Message { hash } = key else { panic!("{key:?}") };
            assert!(!carried.contains(hash));
        }
    }

    #[tokio::test]
    async fn a_turn_carries_its_system_prompt_as_content() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let hash = streamscope_core::audit::system_prompt_hash("be brief");
        let Record::LlmAudit(mut r) = turn(t, 1, &[]) else { unreachable!() };
        r.system_prompt_hash = Some(hash.clone());
        let prompt = streamscope_edge_api::ingest::SystemPromptContent { hash: hash.clone(), prompt: "be brief".into(), content_size: 8 };
        o.enqueue(t, &[with(Record::LlmAudit(r))], &Content {
            system_prompts: vec![prompt],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.content.system_prompts.len(), 1);
        assert_eq!(share.share.content.system_prompts[0].prompt, "be brief");
        assert!(share.share.unavailable.is_empty());
        o.apply(&share, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(content_count(&o).await, 0, "collected with its last record");
        // The next turn names it: admin-api acked it.
        let Record::LlmAudit(mut r) = turn(t, 2, &[]) else { unreachable!() };
        r.system_prompt_hash = Some(hash.clone());
        o.enqueue(t, &[with(Record::LlmAudit(r))], &Content::default()).await.unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert!(share.share.content.system_prompts.is_empty());
        assert_eq!(left_out(&share), vec![ContentKey::SystemPrompt { hash }]);
    }

    #[tokio::test]
    async fn a_body_admin_asks_for_is_carried_again() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[with(turn(t, 1, &["m"]))], &Content {
            messages: vec![message("m")],
            ..Default::default()
        })
        .await
        .unwrap();
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        let missing = vec![ContentKey::Message { hash: "m".into() }];
        assert_eq!(o.apply(&share, &ShareOutcome::Retry { missing }).await.unwrap(), Applied::Kept);
        let again = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(content_key_set(&again.share)["message"], BTreeSet::from(["m".to_string()]));
        assert!(left_out(&again).is_empty() && again.share.unavailable.is_empty());
    }

    #[tokio::test]
    async fn a_record_whose_blobs_no_request_could_carry_together_sends_them_up_one_by_one() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let mb = 1024 * 1024;
        o.enqueue(t, &[turn_naming(t, 1, vec![blob_ref("a"), blob_ref("b"), blob_ref("c")])], &Content {
            blobs: vec![blob("a", 13 * mb), blob("b", 12 * mb), blob("c", 11 * mb)],
            ..Default::default()
        })
        .await
        .unwrap();
        // Each fits a share; together they pass what a request carries.
        let first = o.assemble_with(usize::MAX, usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(first.upload().map(|b| b.content_hash.as_str()), Some("a"), "the largest goes up first");
        o.apply(&first, &ShareOutcome::Committed).await.unwrap();
        let records = o.assemble_with(usize::MAX, usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert!(records.upload().is_none(), "the rest now fit with their record");
        assert_eq!(records.share.records.len(), 1);
        let carried: BTreeSet<String> = records.share.content.blobs.iter().map(|b| b.content_hash.clone()).collect();
        assert_eq!(carried, BTreeSet::from(["b".to_string(), "c".to_string()]), "nothing is dropped");
        assert_eq!(left_out(&records), vec![ContentKey::Blob { content_hash: "a".into(), blob_type: BlobType::ChatImage }]);
    }

    #[tokio::test]
    async fn a_record_waits_for_its_blob_on_its_way_up_and_the_rest_still_go() {
        let o = outbox().await;
        let (a, b, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let big = |t: uuid::Uuid, h: &str, seq| (vec![turn_naming(t, seq, vec![blob_ref(h)])], Content { blobs: vec![blob(h, 4096)], ..Default::default() });
        let (records, content) = big(a, "big-a", 1);
        o.enqueue(a, &records, &content).await.unwrap();
        o.enqueue(b, &[with(event(b, 1))], &Content::default()).await.unwrap();
        let (records, content) = big(c, "big-c", 1);
        o.enqueue(c, &records, &content).await.unwrap();
        o.enqueue(a, &[with(event(a, 2))], &Content::default()).await.unwrap();
        let budget = 2048;
        let shares = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap();
        let key = shares[0].upload_key().expect("a's blob goes up first");
        assert_eq!(key.0, a);
        // b's record is the request's first share of records, so it may pass the budget.
        assert_eq!(shares.iter().map(|s| s.share.tenant).collect::<Vec<_>>(), [a, b], "c's blob waits its turn");
        assert_eq!(shares.iter().filter(|s| s.upload().is_some()).count(), 1, "one blob is read to go up per request");
        // While it is on its way: a's record waits and a's next one goes, b's
        // goes, and no other blob starts.
        let held = Uploads { held: vec![key.clone()], may_start: false };
        let shares = o.assemble_with(usize::MAX, budget, &held).await.unwrap();
        assert_eq!(shares.iter().map(|s| s.share.tenant).collect::<Vec<_>>(), [a, b]);
        assert!(shares.iter().all(|s| s.upload().is_none()));
        assert!(matches!(&shares[0].share.records[..], [Record::McpSseEvent(e)] if e.sequence == 2));
        // Positive control: without it on its way, it is offered again.
        assert_eq!(o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap()[0].upload_key(), Some(key));
    }

    #[tokio::test]
    async fn records_past_a_thousand_waiting_for_a_blob_are_still_reached() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let waiting: Vec<Enqueued> = (1..=1001).map(|i| turn_naming(t, i, vec![blob_ref("big")])).collect();
        o.enqueue(t, &waiting, &Content { blobs: vec![blob("big", 4096)], ..Default::default() }).await.unwrap();
        o.enqueue(t, &[with(event(t, 2000))], &Content::default()).await.unwrap();
        let key = o.assemble_with(usize::MAX, 2048, &Uploads::idle()).await.unwrap()[0].upload_key().expect("the blob goes up");
        let held = Uploads { held: vec![key], may_start: false };
        let shares = o.assemble_with(usize::MAX, 2048, &held).await.unwrap();
        assert!(
            matches!(&shares[..], [s] if matches!(&s.share.records[..], [Record::McpSseEvent(e)] if e.sequence == 2000)),
            "the record after the waiting ones goes"
        );
        // With no blob on its way but none allowed to start, a record whose blob
        // is too large for a share is left out the same way (the first read
        // above is the control: there, it went up).
        let blocked = Uploads { held: vec![], may_start: false };
        let shares = o.assemble_with(usize::MAX, 2048, &blocked).await.unwrap();
        assert!(shares.iter().all(|s| s.upload().is_none() && s.share.records.len() == 1));
    }

    #[tokio::test]
    async fn a_blob_waiting_to_be_sent_again_holds_back_no_other_tenants_blob() {
        let o = outbox().await;
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        o.enqueue(a, &[turn_naming(a, 1, vec![blob_ref("big-a")])], &Content { blobs: vec![blob("big-a", 4096)], ..Default::default() })
            .await
            .unwrap();
        o.enqueue(a, &[with(event(a, 2))], &Content::default()).await.unwrap();
        o.enqueue(b, &[turn_naming(b, 1, vec![blob_ref("big-b")])], &Content { blobs: vec![blob("big-b", 4096)], ..Default::default() })
            .await
            .unwrap();
        let a_key = o.assemble_with(usize::MAX, 2048, &Uploads::idle()).await.unwrap()[0].upload_key().unwrap();
        // a's blob waits out its backoff; a still sorts first and ships its
        // next record, and b's blob may go up.
        let waiting = Uploads { held: vec![a_key], may_start: true };
        let shares = o.assemble_with(usize::MAX, 2048, &waiting).await.unwrap();
        assert!(shares.iter().any(|s| s.share.tenant == a && s.share.records.len() == 1));
        assert_eq!(shares.iter().filter_map(|s| s.upload_key()).map(|k| k.0).collect::<Vec<_>>(), [b]);
    }

    #[tokio::test]
    async fn one_request_reads_one_blob_to_go_up() {
        let o = outbox().await;
        let (a, c) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        for (t, h) in [(a, "big-a"), (c, "big-c")] {
            o.enqueue(t, &[turn_naming(t, 1, vec![blob_ref(h)])], &Content { blobs: vec![blob(h, 4096)], ..Default::default() })
                .await
                .unwrap();
        }
        let shares = o.assemble_with(usize::MAX, 2048, &Uploads::idle()).await.unwrap();
        assert_eq!(shares.len(), 1, "c's blob is not read while a's is the one going up");
        assert_eq!(shares[0].upload_key().map(|k| k.0), Some(a));
        o.apply(&shares[0], &ShareOutcome::Committed).await.unwrap();
        // Positive control: once a's record has gone too, c's blob goes up.
        let shares = o.assemble_with(usize::MAX, 2048, &Uploads::idle()).await.unwrap();
        assert_eq!(shares[0].share.records.len(), 1, "a's record, naming its blob");
        o.apply(&shares[0], &ShareOutcome::Committed).await.unwrap();
        let shares = o.assemble_with(usize::MAX, 2048, &Uploads::idle()).await.unwrap();
        assert_eq!(shares[0].upload_key().map(|k| k.0), Some(c));
    }

    #[tokio::test]
    async fn a_refused_blob_is_dropped_and_its_record_ships_without_it() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[turn_naming(t, 1, vec![blob_ref("big")])], &Content {
            blobs: vec![blob("big", 4096)],
            ..Default::default()
        })
        .await
        .unwrap();
        let budget = 2048;
        let first = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert!(first.share.records.is_empty(), "content-only share");
        let refused = ShareOutcome::Rejected { rows: vec![], reason: "refused".into() };
        assert_eq!(o.apply(&first, &refused).await.unwrap(), Applied::Deleted);
        assert_eq!(content_count(&o).await, 0, "the refused blob is gone");
        let records = o.assemble_with(usize::MAX, budget, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(records.share.records.len(), 1, "the record still ships");
        assert!(records.share.content.blobs.is_empty() && left_out(&records).is_empty(), "without the blob");
        o.apply(&records, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_second_process_cannot_open_a_store_in_use() {
        let dir = std::env::temp_dir().join(format!("streamscope_outbox_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let first = OutboxV2::open(path).await.unwrap();
        let second = OutboxV2::open(path).await;
        assert!(second.is_err_and(|e| e.to_string().contains("another proxy process")), "one process per data directory");
        drop(first);
        assert!(OutboxV2::open(path).await.is_ok(), "released with the store");
    }

    #[tokio::test]
    async fn the_instance_id_is_created_once_with_the_store() {
        let dir = std::env::temp_dir().join(format!("streamscope_outbox_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let o = OutboxV2::open(path).await.unwrap();
        let id = o.instance().await.unwrap();
        assert_eq!(o.instance().await.unwrap(), id);
        drop(o);
        assert_eq!(OutboxV2::open(path).await.unwrap().instance().await.unwrap(), id, "kept across a reopen");
        assert_ne!(outbox().await.instance().await.unwrap(), id, "another store is another instance");
    }

    #[tokio::test]
    async fn a_share_stops_at_the_budget_and_the_request_at_its_own() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let records: Vec<Enqueued> = (1..=10).map(|i| with(event(t, i))).collect();
        o.enqueue(t, &records, &Content::default()).await.unwrap();
        let one = serde_json::to_vec(&event(t, 1)).unwrap().len();
        let shares = o.assemble_with(usize::MAX, one * 3, &Uploads::idle()).await.unwrap();
        assert_eq!(shares[0].share.records.len(), 3);
        // Oldest first.
        let seqs: Vec<i64> = shares[0]
            .share
            .records
            .iter()
            .map(|r| match r {
                Record::McpSseEvent(e) => e.sequence,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(seqs, vec![1, 2, 3]);
        // A record larger than the budget still travels, alone.
        assert_eq!(o.assemble_with(usize::MAX, 1, &Uploads::idle()).await.unwrap()[0].share.records.len(), 1);
        // No budget left in the request: nothing assembled.
        assert!(o.assemble_with(0, one * 3, &Uploads::idle()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_newer_rotation_survives_the_commit_of_an_older_one_in_flight() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        o.enqueue(t, &[with(rotation(t, "old", Some("2030-01-01T00:00:00Z")))], &Content::default())
            .await
            .unwrap();
        let in_flight = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        o.enqueue(t, &[with(rotation(t, "new", Some("2031-01-01T00:00:00Z")))], &Content::default())
            .await
            .unwrap();
        o.apply(&in_flight, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(o.pending().await.unwrap(), 1, "the newer rotation is still buffered");
        let next = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert!(serde_json::to_string(&next.share.records).unwrap().contains("new"));
    }

    #[tokio::test]
    async fn a_buffered_rotation_is_replaced_only_by_a_later_expiry() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let token_of = |o: &OutboxV2| {
            let pool = o.pool.clone();
            async move {
                let (b,): (Vec<u8>,) = sqlx::query_as("SELECT body FROM records").fetch_one(&pool).await.unwrap();
                match serde_json::from_slice::<Record>(&b).unwrap() {
                    Record::CredentialRotation(c) => c.encrypted_access_token,
                    _ => unreachable!(),
                }
            }
        };
        o.enqueue(t, &[with(rotation(t, "first", Some("2026-10-03T10:00:00Z")))], &Content::default()).await.unwrap();
        o.enqueue(t, &[with(rotation(t, "older", Some("2026-10-03T09:00:00Z")))], &Content::default()).await.unwrap();
        assert_eq!(token_of(&o).await, "first");
        o.enqueue(t, &[with(rotation(t, "newer", Some("2026-10-03T11:00:00Z")))], &Content::default()).await.unwrap();
        assert_eq!(token_of(&o).await, "newer");
        assert_eq!(o.pending().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn the_cap_evicts_the_oldest_records_and_only_their_content() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        for i in 1..=200 {
            let hash = format!("m{i}");
            let mut m = message(&hash);
            m.message = serde_json::json!({"content": "x".repeat(2000)});
            o.enqueue(t, &[turn_naming(t, i, vec![ContentRef::Message(hash)])], &Content { messages: vec![m], ..Default::default() })
                .await
                .unwrap();
        }
        let full = o.logical_size().await.unwrap();
        assert_eq!(o.enforce_cap(full).await.unwrap(), 0, "at the cap nothing is evicted");
        let evicted = o.enforce_cap(full / 2).await.unwrap();
        assert!(evicted > 0);
        let left = o.pending().await.unwrap();
        assert_eq!(left + evicted, 200);
        // Every remaining record still has its content, and no orphan is kept.
        assert_eq!(content_count(&o).await, left as i64);
        let oldest: (i64,) = sqlx::query_as("SELECT MIN(id) FROM records").fetch_one(&o.pool).await.unwrap();
        assert_eq!(oldest.0, evicted as i64 + 1, "the oldest went first");
    }

    async fn ack_count(o: &OutboxV2) -> i64 {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM acked").fetch_one(&o.pool).await.unwrap().0
    }

    /// One turn of a session whose history is `1..=n`, with the bodies it
    /// names, as the proxy enqueues it.
    async fn enqueue_history(o: &OutboxV2, t: uuid::Uuid, n: usize) {
        let hashes: Vec<String> = (1..=n).map(|i| format!("m{i}")).collect();
        let refs = hashes.iter().map(|h| h.as_str()).collect::<Vec<_>>();
        let content = Content { messages: hashes.iter().map(|h| message(h)).collect(), ..Default::default() };
        o.enqueue(t, &[with(turn(t, n as u128, &refs))], &content).await.unwrap();
    }

    #[tokio::test]
    async fn a_session_carries_each_body_once_and_names_the_rest() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let (mut carried, mut left) = (0usize, 0usize);
        for n in 1..=30 {
            enqueue_history(&o, t, n).await;
            let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
            assert_eq!(share.share.content.messages.len(), 1, "turn {n} carries only the body it added");
            assert_eq!(share.share.content.messages[0].hash, format!("m{n}"));
            carried += share.share.content.messages.len();
            left += left_out(&share).len();
            assert_eq!(o.apply(&share, &ShareOutcome::Committed).await.unwrap(), Applied::Deleted);
        }
        // Linear, where carrying the whole history would be 30·31/2 = 465.
        assert_eq!(carried, 30);
        assert_eq!(left, 29 * 30 / 2, "every earlier body is named by the turn and left out");
        assert_eq!(content_count(&o).await, 0, "a body acked and needed by no record is not kept");
        assert_eq!(ack_count(&o).await, 30);
    }

    #[tokio::test]
    async fn only_a_committed_share_is_an_ack() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        enqueue_history(&o, t, 1).await;
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        o.apply(&share, &ShareOutcome::Retry { missing: vec![] }).await.unwrap();
        assert_eq!(ack_count(&o).await, 0, "nothing was written");
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        let rejected = ShareOutcome::Rejected { rows: vec![], reason: "22021".into() };
        o.apply(&share, &rejected).await.unwrap();
        assert_eq!(ack_count(&o).await, 0, "a share admin-api refused part of may not hold what it carried");
        // So the next turn carries it again; and a commit acks it.
        enqueue_history(&o, t, 2).await;
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(share.share.content.messages.len(), 2);
        o.apply(&share, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(ack_count(&o).await, 2);
    }

    #[tokio::test]
    async fn a_body_admin_names_missing_after_its_ack_is_carried_again() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        enqueue_history(&o, t, 1).await;
        let first = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        o.apply(&first, &ShareOutcome::Committed).await.unwrap();
        // The next turn is buffered with its whole history, acked or not.
        enqueue_history(&o, t, 2).await;
        let second = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(left_out(&second), vec![ContentKey::Message { hash: "m1".into() }]);
        // Admin-api purged its copy.
        let missing = vec![ContentKey::Message { hash: "m1".into() }];
        assert_eq!(o.apply(&second, &ShareOutcome::Retry { missing }).await.unwrap(), Applied::Asked);
        let again = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(content_key_set(&again.share)["message"], BTreeSet::from(["m1".to_string(), "m2".to_string()]));
        assert!(left_out(&again).is_empty() && again.share.unavailable.is_empty());
    }

    #[tokio::test]
    async fn an_acked_body_admin_lost_and_the_edge_no_longer_holds_is_named_unavailable() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        enqueue_history(&o, t, 1).await;
        let first = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        o.apply(&first, &ShareOutcome::Committed).await.unwrap();
        // A later turn names the body without it: the outbox holds no row.
        o.enqueue(t, &[with(turn(t, 2, &["m1"]))], &Content::default()).await.unwrap();
        let second = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert_eq!(left_out(&second), vec![ContentKey::Message { hash: "m1".into() }], "acked: named, though no row holds it");
        let missing = vec![ContentKey::Message { hash: "m1".into() }];
        o.apply(&second, &ShareOutcome::Retry { missing }).await.unwrap();
        let again = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        assert!(left_out(&again).is_empty());
        assert_eq!(again.share.unavailable, vec![ContentKey::Message { hash: "m1".into() }]);
        o.apply(&again, &ShareOutcome::Committed).await.unwrap();
        assert_eq!(ack_count(&o).await, 0, "a body named unavailable is no ack");
    }

    #[tokio::test]
    async fn a_deleted_tenant_forgets_its_acks_only() {
        let o = outbox().await;
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        for t in [a, b] {
            enqueue_history(&o, t, 1).await;
            let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
            o.apply(&share, &ShareOutcome::Committed).await.unwrap();
        }
        enqueue_history(&o, a, 2).await;
        let share = o.assemble(usize::MAX, &Uploads::idle()).await.unwrap().remove(0);
        o.apply(&share, &ShareOutcome::TenantDeleted).await.unwrap();
        let left: Vec<(String,)> = sqlx::query_as("SELECT tenant_id FROM acked").fetch_all(&o.pool).await.unwrap();
        assert_eq!(left, vec![(b.to_string(),)]);
    }

    #[tokio::test]
    async fn the_cap_forgets_every_ack_before_it_evicts_a_record() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let keys: Vec<(String, String)> =
            (0..20_000).map(|_| ("message".to_string(), format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple()))).collect();
        o.ack(&t.to_string(), &keys).await.unwrap();
        for seq in 0..10 {
            o.enqueue(t, &[with(event(t, seq))], &Content::default()).await.unwrap();
        }
        let full = o.logical_size().await.unwrap();
        assert_eq!(o.enforce_cap(full).await.unwrap(), 0, "at the cap nothing is forgotten");
        assert_eq!(ack_count(&o).await, 20_000);
        assert_eq!(o.enforce_cap(full / 2).await.unwrap(), 0, "the acks alone made the room: no record evicted");
        assert_eq!(o.pending().await.unwrap(), 10);
        assert_eq!(ack_count(&o).await, 0);
        // With no ack left to forget, records go.
        assert!(o.enforce_cap(o.page_size).await.unwrap() > 0);
    }

    #[tokio::test]
    async fn an_ack_no_share_named_for_a_day_is_forgotten_and_one_named_lives_on() {
        let o = outbox().await;
        let t = uuid::Uuid::new_v4();
        let keys = [("message".to_string(), "old".to_string()), ("message".to_string(), "named".to_string())];
        o.ack(&t.to_string(), &keys).await.unwrap();
        let stale = chrono::Utc::now().timestamp_millis() - ACK_TTL_MS - 1;
        sqlx::query("UPDATE acked SET acked_at = ?").bind(stale).execute(&o.pool).await.unwrap();
        // Named again by a committed share: renewed, past the renewal interval.
        o.ack(&t.to_string(), &keys[1..]).await.unwrap();
        assert_eq!(o.forget_stale_acks().await.unwrap(), 1);
        let left: Vec<(String,)> = sqlx::query_as("SELECT hash FROM acked").fetch_all(&o.pool).await.unwrap();
        assert_eq!(left, vec![("named".to_string(),)]);
        // Renewed at most once per interval: a fresh ack is not rewritten.
        let before: (i64,) = sqlx::query_as("SELECT acked_at FROM acked").fetch_one(&o.pool).await.unwrap();
        sqlx::query("UPDATE acked SET acked_at = acked_at - 1").execute(&o.pool).await.unwrap();
        o.ack(&t.to_string(), &keys[1..]).await.unwrap();
        let after: (i64,) = sqlx::query_as("SELECT acked_at FROM acked").fetch_one(&o.pool).await.unwrap();
        assert_eq!(after.0, before.0 - 1);
    }
}
