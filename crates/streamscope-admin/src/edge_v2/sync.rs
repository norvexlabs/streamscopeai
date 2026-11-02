//! `POST /api/v2/edge/sync` — the edge states the digest of the config it
//! holds; the admin answers with every resource whose digest differs and the
//! resources it should drop.
//!
//! Every replica keeps its own cache of built bodies, refreshed every
//! `EDGE_SYNC_REFRESH_MS`: a resource is rebuilt only when its change counters
//! (`config_bumps`, its own and `global`'s) differ from the pair its cached
//! body was built at. Before a cached body is SENT, its counters are read again
//! and a moved resource is rebuilt there and then — a replica one refresh
//! behind must never hand an edge a body older than one a fresher replica
//! already sent it. What each instance holds is stored on `edge_instances`, so
//! any replica can answer its next poll. Whether a tenant still exists is read
//! from `tenants` at request time, never from the cache.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use futures::{FutureExt, StreamExt};
use streamscope_edge_api::config::GlobalConfig;
use streamscope_edge_api::digest::{Digest, canonical_value, held_digest};
use streamscope_edge_api::sync::{
    Held, Nack, Resource, ResourceName, SYNC_BODY_BUDGET_BYTES, SYNC_ENVELOPE_RESERVE_BYTES,
    SYNC_RESPONSE_MAX_BYTES, SyncRequest, SyncResponse,
};
use tokio::sync::RwLock;

use crate::AdminState;
use crate::db::tenant::{Scoped, TenantConn, TenantId};
use crate::routes::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::{Db, Global};

/// A built body and the counters it was built at.
#[derive(Clone)]
struct Built {
    /// When this build started, in this process: of two builds of one
    /// resource, the one that started later read the later snapshot.
    seq: u64,
    counter: i64,
    global_counter: i64,
    digest: Digest,
    /// The body's encoded size, measured once at build so packing an answer
    /// never re-encodes bodies it will not send.
    size: usize,
    /// The canonical bytes, as sent.
    body: Arc<serde_json::value::RawValue>,
}

#[derive(Default)]
struct Cache {
    /// False until this replica holds a body for every resource, or has tried
    /// [`READY_AFTER_REFRESHES`] times (a body that keeps failing must not
    /// keep the replica out of rotation); requests are answered 503 until then.
    ready: bool,
    /// Completed refreshes, counted until `ready`.
    refreshes: u32,
    resources: HashMap<ResourceName, Built>,
}

/// Bodies one refresh, or one request, builds at once. Each build holds a pool
/// connection for its transaction.
const BUILD_CONCURRENCY: usize = 4;

/// Refreshes after which a replica is ready even with bodies still unbuilt:
/// a failure that outlasts them belongs to that body (logged per build), not
/// to the boot.
const READY_AFTER_REFRESHES: u32 = 3;

static CACHE: LazyLock<RwLock<Cache>> = LazyLock::new(|| RwLock::new(Cache::default()));

static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Keep `b` unless the cache already holds a build that started later. Build
/// order — not the counters, which run backwards after a database restore —
/// decides which of two builds is the newer. A kept body with a new digest
/// wakes the held answers, whichever path rebuilt it.
fn store(cache: &mut Cache, r: ResourceName, b: Built) {
    match cache.resources.get(&r) {
        Some(old) if old.seq > b.seq => {}
        old => {
            if old.is_none_or(|old| old.digest != b.digest) {
                wake();
            }
            cache.resources.insert(r, b);
        }
    }
}

/// Every table a build on this replica read without it being in
/// `config_builder::BODY_TABLES` — a config change to one never reaches an
/// edge. Reported by the edge-sync status endpoint; empty is the only
/// correct value.
static UNTRACKED: LazyLock<std::sync::Mutex<BTreeSet<String>>> =
    LazyLock::new(|| std::sync::Mutex::new(BTreeSet::new()));

pub fn untracked_tables() -> Vec<String> {
    UNTRACKED.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
}

/// This replica's current digest of every resource, `None` until its first
/// refresh completes.
pub async fn current_digests() -> Option<BTreeMap<ResourceName, Digest>> {
    let cache = CACHE.read().await;
    cache.ready.then(|| cache.resources.iter().map(|(r, b)| (*r, b.digest)).collect())
}

/// Consecutive refreshes that failed outright (an error before any body was
/// built, or a panic); a completed refresh resets it. Distinct from
/// `Cache::refreshes`, which counts the refreshes that completed.
static REFRESH_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Whether this replica counts as ready (`/ready`): its cache is ready, or its
/// refresh has failed outright [`READY_AFTER_REFRESHES`] times in a row — an edge-cache
/// fault must not take the console down with it. The edges then still get
/// 503, and each failing refresh logs at `error`.
pub async fn cache_ready() -> bool {
    FAILED_INTO_READY.load(std::sync::atomic::Ordering::Relaxed) || CACHE.read().await.ready
}

/// Set once [`READY_AFTER_REFRESHES`] refreshes in a row failed outright; never
/// cleared, so `/ready` does not flap back to 503.
static FAILED_INTO_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Moved whenever an edge may have something new to be sent: an event
/// appended on any replica (heard through `LISTEN`, see
/// [`super::events::spawn_listener`]) or a body this replica's cache rebuilt
/// to a new digest. A held sync answer wakes on it.
static WAKE: LazyLock<tokio::sync::watch::Sender<u64>> = LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Wake every held sync answer on this replica.
pub(crate) fn wake() {
    WAKE.send_modify(|n| *n = n.wrapping_add(1));
}

/// The most sync answers this replica holds at once; past it a quiet answer
/// is sent at once, as without a hold.
const HELD_ANSWERS_MAX: usize = 4096;
static HELD_ANSWERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(HELD_ANSWERS_MAX);

/// The longest an answer is held, whatever the edge asks: an instance whose
/// last sync is older than `INSTANCE_LIVE_SECS` is no longer live.
const HOLD_MAX: Duration = Duration::from_secs(streamscope_edge_api::ingest::INSTANCE_LIVE_SECS / 3);

/// After a wake, how long a held answer lets further changes gather before it
/// is re-read: a burst of changes goes in one answer, not one each.
const WAKE_GATHER: Duration = Duration::from_millis(50);

/// An answer that carries nothing for the edge to apply or dispatch.
fn quiet(r: &SyncResponse) -> bool {
    !r.send_held && !r.more && r.resources.is_empty() && r.removed.is_empty() && r.events.is_empty()
}

/// Answer `req`, holding a quiet answer up to the request's `wait_ms` until a
/// wake gives it something to carry. The wake is subscribed to before the
/// first answer, so a change between that answer and the hold is not missed.
async fn answer_held(db: &Db, instance: uuid::Uuid, req: &SyncRequest) -> Result<SyncResponse, AnswerError> {
    let mut wake = WAKE.subscribe();
    let mut resp = answer(db, instance, req, false).await?;
    if req.wait_ms == 0 || !quiet(&resp) {
        return Ok(resp);
    }
    let Ok(_permit) = HELD_ANSWERS.try_acquire() else {
        return Ok(resp);
    };
    let deadline = tokio::time::Instant::now() + Duration::from_millis(req.wait_ms).min(HOLD_MAX);
    while let Ok(Ok(())) = tokio::time::timeout_at(deadline, wake.changed()).await {
        tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + WAKE_GATHER)).await;
        wake.mark_unchanged();
        // A re-read that fails sends the quiet answer already recorded: the
        // poll itself succeeded, and the edge must not back off for it.
        match answer(db, instance, req, true).await {
            Ok(fresh) if !quiet(&fresh) => return Ok(fresh),
            Ok(fresh) => resp = fresh,
            Err(e) => {
                if let AnswerError::Db(e) = e {
                    tracing::warn!(%instance, "edge sync: re-reading a held answer failed: {e}");
                }
                break;
            }
        }
    }
    Ok(resp)
}

/// Refresh this replica's cache every `EDGE_SYNC_REFRESH_MS`, from boot, so a
/// restarted replica builds before it reports ready rather than when the
/// first edge reaches it.
pub(crate) fn spawn_refresh(db: Db, token: tokio_util::sync::CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let every = Duration::from_millis(crate::settings::admin_settings().edge_sync_refresh_ms.max(50));
        loop {
            // A panic here must not end the loop: readiness depends on it.
            let outcome = tokio::select! {
                () = token.cancelled() => break,
                o = std::panic::AssertUnwindSafe(refresh(&db)).catch_unwind() => o,
            };
            let failure = match outcome {
                Ok(Ok(())) => {
                    REFRESH_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
                    None
                }
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some("the refresh panicked".to_string()),
            };
            if let Some(e) = failure {
                let failures = REFRESH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if failures >= READY_AFTER_REFRESHES {
                    // Latched: once the console is in rotation, a later refresh
                    // that completes without every body must not take it out.
                    FAILED_INTO_READY.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                if failures >= READY_AFTER_REFRESHES && !CACHE.read().await.ready {
                    tracing::error!("edge sync refresh failed: {e} — this replica answers every edge sync 503");
                } else {
                    tracing::warn!("edge sync refresh failed: {e}");
                }
            }
            tokio::select! {
                () = token.cancelled() => break,
                () = tokio::time::sleep(every) => {}
            }
        }
    })
}

/// The current counter of every resource that has one.
async fn counters(db: &Db) -> Result<HashMap<String, i64>, sqlx::Error> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT resource, MAX(id) FROM config_bumps GROUP BY resource")
            .fetch_all(db.global(Global::Infra))
            .await?;
    Ok(rows.into_iter().collect())
}

/// The active customer tenants (SYSTEM carries no workload config).
async fn active_tenants(db: &Db) -> Result<BTreeSet<uuid::Uuid>, sqlx::Error> {
    let rows: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM tenants WHERE is_active AND id <> $1")
        .bind(TenantId::SYSTEM.as_uuid())
        .fetch_all(db.global(Global::TenantRegistry))
        .await?;
    Ok(rows.into_iter().collect())
}

async fn refresh(db: &Db) -> Result<(), sqlx::Error> {
    let counters = counters(db).await?;
    let tenants = active_tenants(db).await?;
    let global_counter = counters.get("global").copied().unwrap_or(0);
    let stale = |cache: &Cache, r: &ResourceName, counter: i64| {
        cache
            .resources
            .get(r)
            .is_none_or(|b| b.counter != counter || b.global_counter != global_counter)
    };

    let mut wanted: Vec<ResourceName> = Vec::new();
    {
        let cache = CACHE.read().await;
        if stale(&cache, &ResourceName::Global, global_counter) {
            wanted.push(ResourceName::Global);
        }
        for t in &tenants {
            let r = ResourceName::Tenant(*t);
            if stale(&cache, &r, counters.get(&r.to_string()).copied().unwrap_or(0)) {
                wanted.push(r);
            }
        }
    }

    let results: Vec<(ResourceName, Result<Built, String>)> = futures::stream::iter(wanted)
        .map(|r| async move {
            // A panicking build is a failed build: it must not end the refresh
            // loop, which readiness depends on.
            let built = std::panic::AssertUnwindSafe(build(db, r)).catch_unwind().await;
            (r, match built {
                Ok(b) => b.map_err(|e| e.to_string()),
                Err(_) => Err("the build panicked".to_string()),
            })
        })
        .buffer_unordered(BUILD_CONCURRENCY)
        .collect()
        .await;
    let mut built = Vec::with_capacity(results.len());
    for (r, result) in results {
        match result {
            Ok(b) => built.push((r, b)),
            // One tenant that fails to build keeps its previous body and is
            // retried next refresh; it never holds back the others.
            Err(e) => tracing::warn!(resource = %r, "edge sync: building the config body failed: {e}"),
        }
    }

    let mut cache = CACHE.write().await;
    for (r, b) in built {
        store(&mut cache, r, b);
    }
    let held = cache.resources.len();
    cache
        .resources
        .retain(|r, _| matches!(r, ResourceName::Global) || matches!(r, ResourceName::Tenant(t) if tenants.contains(t)));
    if cache.resources.len() != held {
        wake();
    }
    if !cache.ready {
        cache.refreshes += 1;
        let complete = cache.resources.contains_key(&ResourceName::Global)
            && tenants.iter().all(|t| cache.resources.contains_key(&ResourceName::Tenant(*t)));
        cache.ready = ready_after(complete, cache.refreshes);
    }
    Ok(())
}

fn ready_after(every_body_built: bool, refreshes: u32) -> bool {
    every_body_built || refreshes >= READY_AFTER_REFRESHES
}

/// Build one resource's body inside one REPEATABLE READ transaction, reading
/// the counters it is labelled with from the same snapshot as its rows.
async fn build(db: &Db, r: ResourceName) -> Result<Built, sqlx::Error> {
    let seq = BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tenant = match r {
        ResourceName::Global => TenantId::SYSTEM,
        ResourceName::Tenant(t) => TenantId::from_row(t),
    };
    let mut tdb = TenantConn::acquire(db, tenant).await?;
    let mut tx = tdb.conn().begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").execute(&mut *tx).await?;
    let conn: &mut Scoped = &mut tx;
    let scans_before = crate::config_builder::scan_counts(conn).await?;
    let (counter, global_counter) = read_counters(conn, r).await?;
    let body = match r {
        ResourceName::Global => canonical_value(&build_global(conn).await?),
        ResourceName::Tenant(t) => {
            let slug: String = sqlx::query_scalar("SELECT slug FROM tenants WHERE id = $1")
                .bind(t)
                .fetch_one(&mut *conn)
                .await?;
            let body = crate::config_builder::build_tenant_body(conn, t, slug).await?;
            let untracked = crate::config_builder::untracked_reads(conn, &scans_before, &["config_bumps"]).await?;
            if !untracked.is_empty() {
                tracing::error!(tenant_id = %t, tables = ?untracked, "config build read tables missing from config_builder::BODY_TABLES");
                UNTRACKED.lock().unwrap_or_else(|e| e.into_inner()).extend(untracked);
            }
            canonical_value(&body)
        }
    }
    .map_err(|e| sqlx::Error::Protocol(format!("encoding the config body: {e}")))?;
    tx.commit().await?;
    let text = serde_json::to_string(&body).map_err(|e| sqlx::Error::Protocol(format!("encoding the config body: {e}")))?;
    let digest = Digest::of(text.as_bytes());
    let size = text.len();
    let raw = serde_json::value::RawValue::from_string(text)
        .map_err(|e| sqlx::Error::Protocol(format!("encoding the config body: {e}")))?;
    Ok(Built { seq, counter, global_counter, digest, size, body: Arc::from(raw) })
}

/// `(resource counter, global counter)` on `conn`; 0 for a resource never bumped.
async fn read_counters(conn: &mut Scoped, r: ResourceName) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT (SELECT COALESCE(MAX(id), 0) FROM config_bumps WHERE resource = $1), \
                (SELECT COALESCE(MAX(id), 0) FROM config_bumps WHERE resource = 'global')",
    )
    .bind(r.to_string())
    .fetch_one(conn)
    .await
}

/// The `global` body, on a SYSTEM-scoped connection.
async fn build_global(conn: &mut Scoped) -> Result<GlobalConfig, sqlx::Error> {
    let log_level: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = 'log_level'")
            .fetch_optional(&mut *conn)
            .await?;
    let overrides: Vec<(String, String)> =
        sqlx::query_as("SELECT token, value FROM platform_setting_overrides ORDER BY token")
            .fetch_all(&mut *conn)
            .await?;
    let egress: Vec<(String, Vec<String>)> =
        sqlx::query_as("SELECT surface, entries FROM platform_egress WHERE cardinality(entries) > 0 ORDER BY surface")
            .fetch_all(&mut *conn)
            .await?;
    Ok(GlobalConfig {
        log_level: log_level.and_then(|v| v.as_str().map(str::to_string)),
        runtime_overrides: overrides.into_iter().collect(),
        egress: egress.into_iter().collect(),
    })
}

// ---------------------------------------------------------------------------
// Request planning — pure, so every rule below is a unit test.
// ---------------------------------------------------------------------------

/// The current body of each of `resources`: the cached one when its counters
/// have not moved, else rebuilt now (and cached). A resource that cannot be
/// built now (a failing loader, a tenant removed meanwhile) is left out.
async fn fresh(db: &Db, resources: Vec<ResourceName>) -> Result<Vec<(ResourceName, Built)>, sqlx::Error> {
    let names: Vec<String> = resources.iter().map(|r| r.to_string()).chain(["global".to_string()]).collect();
    let now: HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT resource, MAX(id) FROM config_bumps WHERE resource = ANY($1) GROUP BY resource",
    )
    .bind(&names)
    .fetch_all(db.global(Global::Infra))
    .await?
    .into_iter()
    .collect();
    let global_now = now.get("global").copied().unwrap_or(0);
    let mut bodies = Vec::with_capacity(resources.len());
    let mut moved = Vec::new();
    {
        let cache = CACHE.read().await;
        for r in resources {
            let counter_now = now.get(&r.to_string()).copied().unwrap_or(0);
            match cache.resources.get(&r) {
                Some(b) if b.counter == counter_now && b.global_counter == global_now => bodies.push((r, b.clone())),
                _ => moved.push(r),
            }
        }
    }
    let rebuilt: Vec<(ResourceName, Result<Built, sqlx::Error>)> = futures::stream::iter(moved)
        .map(|r| async move { (r, build(db, r).await) })
        .buffer_unordered(BUILD_CONCURRENCY)
        .collect()
        .await;
    for (r, result) in rebuilt {
        match result {
            Ok(b) => {
                store(&mut *CACHE.write().await, r, b.clone());
                bodies.push((r, b));
            }
            Err(e) => tracing::warn!(resource = %r, "edge sync: rebuilding a moved resource failed: {e}"),
        }
    }
    Ok(bodies)
}

/// The digest of the current body of each of `resources`, read as an answer
/// would send it (see [`fresh`]); absent where it cannot be built now.
pub(crate) async fn fresh_digests(
    db: &Db,
    resources: Vec<ResourceName>,
) -> Result<BTreeMap<ResourceName, Digest>, sqlx::Error> {
    Ok(fresh(db, resources).await?.into_iter().map(|(r, b)| (r, b.digest)).collect())
}

/// What an instance holds, by resource.
pub type HeldMap = BTreeMap<ResourceName, Digest>;

/// The held set of a request: the full set when the edge sent it, else the set
/// stored at the last answer when the digests agree, else the empty set when
/// the edge states it holds nothing, else unknown (`None` ⇒ ask for it).
fn resolve_held(req: &SyncRequest, stored: Option<&HeldMap>) -> Option<HeldMap> {
    if let Some(held) = &req.held {
        return Some(held.iter().map(|h| (h.resource, h.digest)).collect());
    }
    if let Some(stored) = stored
        && digest_of_held(stored) == req.held_digest
    {
        return Some(stored.clone());
    }
    let empty = HeldMap::new();
    (digest_of_held(&empty) == req.held_digest).then_some(empty)
}

fn digest_of_held(held: &HeldMap) -> Digest {
    let names: Vec<(String, Digest)> = held.iter().map(|(r, d)| (r.to_string(), *d)).collect();
    held_digest(names.iter().map(|(r, d)| (r.as_str(), d)))
}

/// The resources whose current digest the instance does not hold and has not
/// refused, in resource order; and the held resources that no longer exist.
fn diff(
    held: &HeldMap,
    current: &BTreeMap<ResourceName, Digest>,
    nacked: &HeldMap,
    live: &BTreeSet<ResourceName>,
) -> (Vec<ResourceName>, Vec<ResourceName>) {
    let send = current
        .iter()
        .filter(|(r, d)| live.contains(r) && held.get(r) != Some(d) && nacked.get(r) != Some(d))
        .map(|(r, _)| *r)
        .collect();
    let removed = held.keys().filter(|r| !live.contains(r)).copied().collect();
    (send, removed)
}

/// The prefix of `sizes` that fits `budget`, never fewer than one.
fn pack(sizes: &[usize], budget: usize) -> usize {
    let mut used = 0;
    for (i, s) in sizes.iter().enumerate() {
        if i > 0 && used + s > budget {
            return i;
        }
        used += s;
    }
    sizes.len()
}

/// What the instance holds once it applies this answer.
fn predicted(held: &HeldMap, sent: &[(ResourceName, Digest)], removed: &[ResourceName]) -> HeldMap {
    let mut next = held.clone();
    for r in removed {
        next.remove(r);
    }
    for (r, d) in sent {
        next.insert(*r, *d);
    }
    next
}

/// The refusals to remember: the stored ones for resources still held or
/// current, plus this request's.
fn merge_nacks(stored: &HeldMap, new: &[Nack], keep: impl Fn(&ResourceName) -> bool) -> HeldMap {
    let mut out: HeldMap = stored.iter().filter(|(r, _)| keep(r)).map(|(r, d)| (*r, *d)).collect();
    for n in new {
        out.insert(n.resource, n.digest);
    }
    out
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct InstanceRow {
    held: Option<serde_json::Value>,
    confirmed: Option<serde_json::Value>,
    nacked: Option<serde_json::Value>,
    sync_epoch: Option<i64>,
}

fn held_from_json(v: Option<serde_json::Value>) -> Option<HeldMap> {
    v.and_then(|v| serde_json::from_value::<Vec<Held>>(v).ok())
        .map(|hs| hs.into_iter().map(|h| (h.resource, h.digest)).collect())
}

fn held_to_json(h: &HeldMap) -> serde_json::Value {
    let v: Vec<Held> = h.iter().map(|(r, d)| Held { resource: *r, digest: *d }).collect();
    serde_json::to_value(v).unwrap_or_default()
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!("edge sync: {e}");
    ApiError::internal("Failed to answer the edge sync").into_response()
}

#[utoipa::path(
    post,
    path = "/api/v2/edge/sync",
    request_body = SyncRequest,
    responses(
        (status = 200, description = "The resources to apply and drop", body = SyncResponse),
        (status = 400, description = "Malformed sync request", body = ApiErrorResponse),
        (status = 401, description = "Missing or unknown edge token", body = ApiErrorResponse),
        (status = 503, description = "This replica has not built its config cache yet", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "Edge Nodes"
)]
pub async fn sync_handler(State(state): State<Arc<AdminState>>, request: axum::extract::Request) -> Response {
    let db = &state.db;
    // The token is checked from the headers before the body is read: an
    // unauthenticated caller costs one lookup.
    let (node, body) =
        match super::auth::authenticated_body(request, db, SYNC_RESPONSE_MAX_BYTES).await {
            Ok(parts) => parts,
            Err(r) => return r,
        };
    let req: SyncRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return ApiError::bad_request("Malformed sync request").into_response(),
    };
    let instance = match super::auth::instance_id(db, node, req.instance).await {
        Ok(i) => i,
        Err(e) => return internal(e),
    };
    match answer_held(db, instance, &req).await {
        Ok(resp) => {
            let mut r = Json(resp).into_response();
            if let Ok(v) = HeaderValue::from_str(&state.instance_id.to_string()) {
                r.headers_mut().insert("x-admin-replica", v);
            }
            r
        }
        Err(AnswerError::NotReady) => ApiError::service_unavailable("The config cache is being built; poll again")
            .code(ApiErrorCode::EdgeSyncNotReady)
            .into_response(),
        Err(AnswerError::Db(e)) => internal(e),
    }
}

enum AnswerError {
    NotReady,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for AnswerError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

/// `reread`: the request was answered once already and is being held; a
/// re-read that is still quiet records nothing, since the first answer
/// recorded the same poll.
async fn answer(db: &Db, instance: uuid::Uuid, req: &SyncRequest, reread: bool) -> Result<SyncResponse, AnswerError> {
    let pool = db.global(Global::Infra);
    let row: InstanceRow = sqlx::query_as("SELECT held, confirmed, nacked, sync_epoch FROM edge_instances WHERE id = $1")
        .bind(instance)
        .fetch_one(pool)
        .await?;
    let epoch = i64::try_from(req.process_epoch).unwrap_or(i64::MAX);
    let same_process = row.sync_epoch == Some(epoch);
    let stored_held = held_from_json(row.held);
    // A refusal belongs to the process that made it: a restarted (possibly
    // upgraded) edge is offered every body again.
    let stored_nacked = if same_process { held_from_json(row.nacked).unwrap_or_default() } else { HeldMap::new() };

    let Some(held) = resolve_held(req, stored_held.as_ref()) else {
        let nacked = merge_nacks(&stored_nacked, &req.nacks, |_| true);
        record(
            db,
            instance,
            Recorded {
                held: None,
                confirmed: None,
                nacked: (nacked != stored_nacked || !same_process).then_some(&nacked),
            },
            epoch,
            req.outbox_pending,
        )
        .await?;
        // The cursor stays where it is, unless it is past the head.
        let events_cursor = req.events_after.min(super::events::head(db).await?);
        return Ok(SyncResponse { send_held: true, events_cursor, ..Default::default() });
    };

    let (current, sizes): (BTreeMap<ResourceName, Digest>, HashMap<ResourceName, usize>) = {
        let cache = CACHE.read().await;
        if !cache.ready {
            drop(cache);
            // Not answered, but heard: the instance stays live while this
            // replica builds its cache.
            // A new process's refusals start empty here too, as on any answer.
            let fresh_nacks = HeldMap::new();
            let nacked = (!same_process).then_some(&fresh_nacks);
            record(db, instance, Recorded { held: None, confirmed: None, nacked }, epoch, req.outbox_pending).await?;
            return Err(AnswerError::NotReady);
        }
        (
            cache.resources.iter().map(|(r, b)| (*r, b.digest)).collect(),
            cache.resources.iter().map(|(r, b)| (*r, b.size)).collect(),
        )
    };

    // Existence is the database's answer, read now — never this replica's cache.
    let candidates: Vec<uuid::Uuid> = held
        .keys()
        .chain(current.keys())
        .filter_map(|r| match r {
            ResourceName::Tenant(t) => Some(*t),
            ResourceName::Global => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let live_tenants: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE is_active AND id = ANY($1) AND id <> $2")
            .bind(&candidates)
            .bind(TenantId::SYSTEM.as_uuid())
            .fetch_all(db.global(Global::TenantRegistry))
            .await?;
    let live: BTreeSet<ResourceName> = live_tenants
        .into_iter()
        .map(ResourceName::Tenant)
        .chain([ResourceName::Global])
        .collect();

    let nacked = merge_nacks(&stored_nacked, &req.nacks, |r| live.contains(r));
    let (mut send, removed) = diff(&held, &current, &nacked, &live);
    // A body that cannot fit in any answer an edge reads is never sent.
    send.retain(|r| {
        let fits = sizes.get(r).copied().unwrap_or(0) + SYNC_ENVELOPE_RESERVE_BYTES <= SYNC_RESPONSE_MAX_BYTES;
        if !fits {
            tracing::error!(resource = %r, "edge sync: config body exceeds the largest answer an edge reads — not sent");
        }
        fits
    });
    // Pack by the sizes measured at build: only what fits is read further.
    let send_sizes: Vec<usize> = send.iter().map(|r| sizes.get(r).copied().unwrap_or(0)).collect();
    let wanted = send.len();
    send.truncate(pack(&send_sizes, SYNC_BODY_BUDGET_BYTES));
    let mut more = send.len() < wanted;

    // Re-read the counters of everything about to be sent; a resource that
    // moved since this replica's refresh is rebuilt now, so the body sent is
    // never older than the database.
    let asked = send.clone();
    let mut bodies = if send.is_empty() { Vec::new() } else { fresh(db, send).await? };
    // A resource that could not be rebuilt now: an edge holding no body for it
    // is sent the last one this replica built — it regresses nothing, and the
    // edge is not left without the tenant. One that holds a body keeps it, and
    // is sent the new one once a rebuild succeeds. Neither is `more`: a body
    // that keeps failing to build must not hold every new edge unready, which
    // would turn one tenant's error into an outage (likewise a body too large
    // for any answer, logged at `error` where it is left out).
    let built: BTreeSet<ResourceName> = bodies.iter().map(|(r, _)| *r).collect();
    let missing: Vec<ResourceName> = asked.into_iter().filter(|r| !built.contains(r) && !held.contains_key(r)).collect();
    if !missing.is_empty() {
        let cache = CACHE.read().await;
        bodies.extend(missing.into_iter().filter_map(|r| cache.resources.get(&r).map(|b| (r, b.clone()))));
    }
    bodies.sort_by_key(|(r, _)| *r);
    bodies.retain(|(r, b)| held.get(r) != Some(&b.digest) && nacked.get(r) != Some(&b.digest));
    // A rebuilt body may have grown: fit and pack again by the sizes sent.
    bodies.retain(|(r, b)| {
        let fits = b.size + SYNC_ENVELOPE_RESERVE_BYTES <= SYNC_RESPONSE_MAX_BYTES;
        if !fits {
            tracing::error!(resource = %r, "edge sync: config body exceeds the largest answer an edge reads — not sent");
        }
        fits
    });
    let sent_sizes: Vec<usize> = bodies.iter().map(|(_, b)| b.size).collect();
    let fitting = pack(&sent_sizes, SYNC_BODY_BUDGET_BYTES);
    more |= fitting < bodies.len();
    bodies.truncate(fitting);

    let sent: Vec<(ResourceName, Digest)> = bodies.iter().map(|(r, b)| (*r, b.digest)).collect();
    let next = predicted(&held, &sent, &removed);

    let holds: Vec<uuid::Uuid> = next
        .keys()
        .filter_map(|r| match r {
            ResourceName::Tenant(t) => Some(*t),
            ResourceName::Global => None,
        })
        .collect();
    // The head first: every event up to it has committed, so the read below
    // sees all of them and the cursor may move to it.
    let head = super::events::head(db).await?;
    let (events, events_cursor) = super::events::after(db, req.events_after, head, req.instance, &holds).await?;

    if !(reread && bodies.is_empty() && removed.is_empty() && !more && events.is_empty()) {
        record(
            db,
            instance,
            Recorded {
                held: (stored_held.as_ref() != Some(&next)).then_some(&next),
                confirmed: (held_from_json(row.confirmed).as_ref() != Some(&held)).then_some(&held),
                nacked: (nacked != stored_nacked || !same_process).then_some(&nacked),
            },
            epoch,
            req.outbox_pending,
        )
        .await?;
    }

    Ok(SyncResponse {
        send_held: false,
        resources: bodies
            .into_iter()
            .map(|(resource, b)| Resource { resource, digest: b.digest, counter: b.counter, body: (*b.body).to_owned() })
            .collect(),
        removed,
        more,
        events,
        events_cursor,
    })
}

/// The sets one answer changes; `None` keeps the stored one.
struct Recorded<'a> {
    /// What the instance will hold once this answer is applied.
    held: Option<&'a HeldMap>,
    /// What the instance's request said it holds — the only set status reads.
    confirmed: Option<&'a HeldMap>,
    nacked: Option<&'a HeldMap>,
}

/// Record a poll. The sets are written only when they changed: the
/// steady-state poll writes the instance's timestamps, its epoch and its
/// outbox count. A poll from an epoch older than the one recorded records
/// nothing: an answer still held for a process that has since restarted
/// must not overwrite what the new one stated.
async fn record(
    db: &Db,
    instance: uuid::Uuid,
    sets: Recorded<'_>,
    sync_epoch: i64,
    outbox_pending: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE edge_instances SET \
            held = COALESCE($2, held), held_digest = COALESCE($3, held_digest), nacked = COALESCE($4, nacked), \
            sync_epoch = $5, last_sync_at = now(), last_seen_at = now(), outbox_pending = $6, \
            confirmed = COALESCE($7, confirmed) \
          WHERE id = $1 AND (sync_epoch IS NULL OR sync_epoch <= $5)",
    )
    .bind(instance)
    .bind(sets.held.map(held_to_json))
    .bind(sets.held.map(|h| digest_of_held(h).to_hex()))
    .bind(sets.nacked.map(held_to_json))
    .bind(sync_epoch)
    .bind(i64::try_from(outbox_pending).unwrap_or(i64::MAX))
    .bind(sets.confirmed.map(held_to_json))
    .execute(db.global(Global::Infra))
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u8) -> ResourceName {
        ResourceName::Tenant(uuid::Uuid::from_bytes([n; 16]))
    }
    fn d(s: &str) -> Digest {
        Digest::of(s.as_bytes())
    }
    fn req(held_digest: Digest, held: Option<Vec<Held>>) -> SyncRequest {
        SyncRequest {
            instance: uuid::Uuid::nil(),
            process_epoch: 1,
            held_digest,
            held,
            nacks: Vec::new(),
            events_after: 0,
            outbox_pending: 0,
            wait_ms: 0,
        }
    }

    #[test]
    fn held_comes_from_the_request_the_stored_set_or_nothing() {
        let stored: HeldMap = [(t(1), d("a"))].into();
        // A full set in the request is taken as is.
        let full = vec![Held { resource: t(2), digest: d("b") }];
        assert_eq!(resolve_held(&req(d("x"), Some(full)), Some(&stored)), Some([(t(2), d("b"))].into()));
        // The stored set when its digest is the one stated.
        assert_eq!(resolve_held(&req(digest_of_held(&stored), None), Some(&stored)), Some(stored.clone()));
        // An edge holding nothing says so without a round trip.
        assert_eq!(resolve_held(&req(digest_of_held(&HeldMap::new()), None), None), Some(HeldMap::new()));
        // Anything else is unknown: ask for the set.
        assert_eq!(resolve_held(&req(d("other"), None), Some(&stored)), None);
    }

    #[test]
    fn diff_sends_what_is_not_held_or_refused_and_drops_what_is_gone() {
        let live: BTreeSet<_> = [ResourceName::Global, t(1), t(2), t(3)].into();
        let current: BTreeMap<_, _> =
            [(ResourceName::Global, d("g")), (t(1), d("1")), (t(2), d("2new")), (t(3), d("3"))].into();
        let held: HeldMap = [(ResourceName::Global, d("g")), (t(2), d("2old")), (t(9), d("9"))].into();
        let nacked: HeldMap = [(t(3), d("3"))].into();
        let (send, removed) = diff(&held, &current, &nacked, &live);
        assert_eq!(send, [t(1), t(2)], "unheld and changed are sent; held and refused are not");
        assert_eq!(removed, [t(9)], "a held resource that no longer exists is dropped");
        // A refusal covers only that digest: a later body for it is sent.
        let (send, _) = diff(&held, &[(t(3), d("3b"))].into(), &nacked, &live);
        assert_eq!(send, [t(3)]);
        // A cached resource the database no longer has is neither sent nor kept.
        let not_live: BTreeSet<_> = [ResourceName::Global].into();
        let (send, removed) = diff(&held, &current, &nacked, &not_live);
        assert!(send.is_empty());
        assert_eq!(removed, [t(2), t(9)]);
    }

    #[test]
    fn a_replica_is_ready_once_every_body_is_built_or_its_failures_have_had_their_retries() {
        assert!(ready_after(true, 1), "every body built on the first refresh");
        assert!(!ready_after(false, 1), "a build that failed on the first refresh gets retried first");
        assert!(!ready_after(false, READY_AFTER_REFRESHES - 1));
        assert!(ready_after(false, READY_AFTER_REFRESHES), "a body that keeps failing does not hold the replica out");
    }

    #[test]
    fn pack_fills_the_budget_and_never_sends_nothing() {
        assert_eq!(pack(&[], 10), 0);
        assert_eq!(pack(&[4, 4, 4], 10), 2, "the third would pass the budget");
        assert_eq!(pack(&[4, 6], 10), 2, "exactly the budget fits");
        assert_eq!(pack(&[25, 1], 10), 1, "an oversized first resource still goes, alone");
    }

    #[test]
    fn the_prediction_is_held_plus_sent_minus_removed() {
        let held: HeldMap = [(t(1), d("1")), (t(2), d("2")), (t(9), d("9"))].into();
        let next = predicted(&held, &[(t(2), d("2b")), (t(3), d("3"))], &[t(9)]);
        assert_eq!(next, [(t(1), d("1")), (t(2), d("2b")), (t(3), d("3"))].into());
    }

    #[test]
    fn refusals_are_kept_for_live_resources_and_added_from_the_request() {
        let stored: HeldMap = [(t(1), d("1")), (t(9), d("9"))].into();
        let new = [Nack { resource: t(2), digest: d("2"), detail: String::new() }];
        let out = merge_nacks(&stored, &new, |r| *r != t(9));
        assert_eq!(out, [(t(1), d("1")), (t(2), d("2"))].into());
    }
}
