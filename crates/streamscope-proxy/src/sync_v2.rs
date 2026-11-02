//! The edge side of `POST /api/v2/edge/sync`: state the digest of the config
//! held, apply what the answer sends, persist it, and serve from it offline.
//!
//! Applied bodies reach the process through the same path every config change
//! takes ([`config_sync::apply_update`]) and the same on-disk snapshot; the
//! digests this instance holds are persisted beside it
//! (`config_held_v2.json`), written AFTER the snapshot — a crash between the
//! two leaves a held set older than the bodies on disk, which costs one
//! re-send, never a body the instance claims but does not have.
//!
//! A tenant in the snapshot without a held digest (a snapshot this instance
//! did not write through this module) is reported under [`unheld()`], a digest
//! no body has: admin-api then sends its body, or removes it.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;

use streamscope_edge_api::config::{ConfigResponse, GlobalConfig};
use streamscope_edge_api::digest::{Digest, held_digest};
use streamscope_edge_api::sync::{Event, EventId, Held, Nack, ResourceName, SyncRequest, SyncResponse};

use crate::config_snapshot;
use crate::config_sync::{self, ConfigTargets, IncrementalConfigUpdate};

const HELD_FILE: &str = "config_held_v2.json";

/// What this instance persists beside the snapshot.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct HeldFile {
    held: Vec<Held>,
    events_after: EventId,
    /// An answer once left nothing unsent: the snapshot is a whole config.
    complete: bool,
}

/// The digest reported for a resource held without a known digest. A body's
/// digest is over canonical JSON; these bytes are not JSON, so it matches none.
fn unheld() -> Digest {
    Digest::of(b"unheld")
}

pub struct SyncV2 {
    targets: ConfigTargets,
    data_dir: String,
    held: BTreeMap<ResourceName, Digest>,
    events_after: EventId,
    /// The last answer asked for the full held set.
    send_full: bool,
    /// Refusals not yet reported.
    nacks: Vec<Nack>,
    /// Per tenant, the response-cache generations of the body last applied.
    generations: HashMap<uuid::Uuid, Generations>,
    /// An answer has left nothing unsent since the config on disk began.
    complete: bool,
    /// The last answer left work for the next poll at once: more bodies, or
    /// the full held set asked for.
    poll_again: bool,
    /// The last answer left nothing unsent (`more` false, no held set asked for).
    answered_whole: bool,
    /// When the held file (and its event cursor) was last written.
    cursor_persisted_at: std::time::Instant,
}

/// How long a moved event cursor may go unwritten (see `cursor_due`).
const CURSOR_PERSIST_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// A tenant's response-cache generations: its own, and each route's.
#[derive(Clone, Debug, Default, PartialEq)]
struct Generations {
    tenant: i64,
    routes: HashMap<String, i64>,
}

impl Generations {
    fn of(c: &ConfigResponse) -> Self {
        Self {
            tenant: c.settings.get("response_cache_generation").and_then(|v| v.as_i64()).unwrap_or(0),
            routes: c.model_mappings.iter().map(|m| (m.id.clone(), m.cache_generation)).collect(),
        }
    }

    /// What `next` asks to drop relative to `self`: the whole tenant, or the
    /// routes whose generation rose.
    fn flushes(&self, next: &Self) -> Flush {
        if next.tenant != self.tenant {
            return Flush::Tenant;
        }
        let mut routes: Vec<String> = next
            .routes
            .iter()
            .filter(|(id, g)| self.routes.get(*id).is_some_and(|old| old != *g))
            .map(|(id, _)| id.clone())
            .collect();
        routes.sort();
        Flush::Routes(routes)
    }
}

#[derive(Debug, PartialEq)]
enum Flush {
    Tenant,
    Routes(Vec<String>),
}

impl SyncV2 {
    /// Resume from what this instance persisted (nothing ⇒ hold nothing).
    pub fn load(targets: ConfigTargets, data_dir: &str) -> Self {
        let path = format!("{data_dir}/{HELD_FILE}");
        let file = match std::fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str::<HeldFile>(&json).unwrap_or_else(|e| {
                tracing::warn!(path = %path, "discarding unreadable held set ({e}); the next sync re-sends every resource");
                HeldFile::default()
            }),
            Err(_) => HeldFile::default(),
        };
        let mut held: BTreeMap<ResourceName, Digest> = file.held.into_iter().map(|h| (h.resource, h.digest)).collect();
        let mut complete = file.complete;
        // The generations of the bodies held come from the snapshot they were
        // applied from, so a flush raised after a restart is still honoured.
        let mut generations = HashMap::new();
        match config_snapshot::load_snapshot(data_dir) {
            Ok(Some(snapshot)) => {
                // Held only what the snapshot carries: a digest for a body that
                // is not on disk would never be re-sent.
                let before = held.len();
                held.retain(|r, _| match r {
                    ResourceName::Global => true,
                    ResourceName::Tenant(t) => snapshot.tenants.contains_key(&t.to_string()),
                });
                // A body the held set claimed is missing: the config on disk
                // is not whole.
                if held.len() != before {
                    complete = false;
                }
                for (t, c) in &snapshot.tenants {
                    let Ok(tenant) = uuid::Uuid::parse_str(t) else { continue };
                    generations.insert(tenant, Generations::of(c));
                    held.entry(ResourceName::Tenant(tenant)).or_insert_with(unheld);
                }
            }
            // No bodies on disk: nothing is held, whatever the held file says.
            _ => {
                held.clear();
                complete = false;
            }
        }
        Self {
            targets,
            data_dir: data_dir.to_string(),
            held,
            events_after: file.events_after,
            send_full: false,
            nacks: Vec::new(),
            generations,
            complete,
            poll_again: false,
            answered_whole: false,
            cursor_persisted_at: std::time::Instant::now(),
        }
    }

    /// Whether the config on disk is whole: some answer since it began left
    /// nothing unsent. Until then the process holds only part of its tenants.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// Whether the last answer left nothing unsent: the control plane has
    /// nothing newer for this process. A refused body does not count against
    /// it: admin records the refusal and does not send that body again.
    pub fn current(&self) -> bool {
        self.answered_whole
    }

    /// Whether the next poll should go at once rather than after the interval.
    pub fn poll_again(&self) -> bool {
        self.poll_again
    }

    pub fn held_digest(&self) -> Digest {
        let names: Vec<(String, Digest)> = self.held.iter().map(|(r, d)| (r.to_string(), *d)).collect();
        held_digest(names.iter().map(|(r, d)| (r.as_str(), d)))
    }

    /// The next request.
    pub fn request(&mut self, instance: uuid::Uuid, process_epoch: u64, ask: Ask) -> SyncRequest {
        let held = self
            .send_full
            .then(|| self.held.iter().map(|(r, d)| Held { resource: *r, digest: *d }).collect());
        SyncRequest {
            instance,
            process_epoch,
            held_digest: self.held_digest(),
            held,
            nacks: std::mem::take(&mut self.nacks),
            events_after: self.events_after,
            outbox_pending: ask.outbox_pending,
            wait_ms: u64::try_from(ask.wait.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// Apply an answer: every body that parses, every removal; a body that does
    /// not parse is refused (reported on the next request) and not held. The
    /// process is made serveable once an answer leaves nothing unsent. Returns
    /// the answer's events, for the caller to dispatch.
    pub async fn apply(&mut self, resp: SyncResponse) -> Vec<Event> {
        self.send_full = resp.send_held;
        // At once only while answers make progress: `more` with nothing sent
        // (a body admin could not build) waits the interval. An answer that
        // carried a config change was sent as it happened, before the wait
        // ended: the next poll waits for the one after it. Events go at once
        // only while a full page says more are waiting; otherwise the next
        // poll waits out the interval, so a stream of events reaches an edge
        // at most about once an interval after the first, never once per event.
        self.poll_again = resp.send_held
            || !resp.resources.is_empty()
            || !resp.removed.is_empty()
            || resp.events.len() >= streamscope_edge_api::sync::EVENTS_PER_POLL;
        self.answered_whole = !resp.send_held && !resp.more;
        let cursor_before = self.events_after;
        self.events_after = resp.events_cursor;
        if resp.send_held {
            if self.cursor_due(cursor_before, &resp.events) {
                self.persist_held();
            }
            return resp.events;
        }
        let completes = !resp.more && !self.complete;
        if completes {
            self.complete = true;
        }
        if resp.resources.is_empty() && resp.removed.is_empty() {
            // Nothing to apply: the steady-state poll touches no config, no
            // script cache and no file but the cursor's.
            if self.cursor_due(cursor_before, &resp.events) || completes {
                self.persist_held();
            }
            self.mark_ready();
            return resp.events;
        }
        let mut update = IncrementalConfigUpdate {
            updates: HashMap::new(),
            removed_tenants: Vec::new(),
            log_level: None,
            runtime_overrides: None,
            egress: None,
        };
        let mut applied: Vec<(ResourceName, Digest)> = Vec::new();
        for r in resp.resources {
            let parsed = match r.resource {
                ResourceName::Global => serde_json::from_str::<GlobalConfig>(r.body.get()).map(|g| {
                    // No level set is the default level, applied like any other.
                    update.log_level = Some(g.log_level.unwrap_or_else(|| "info".to_string()));
                    update.runtime_overrides = Some(g.runtime_overrides);
                    update.egress = Some(g.egress);
                }),
                ResourceName::Tenant(t) => serde_json::from_str::<ConfigResponse>(r.body.get()).map(|c| {
                    update.updates.insert(t.to_string(), c);
                }),
            };
            match parsed {
                Ok(()) => applied.push((r.resource, r.digest)),
                Err(e) => {
                    tracing::error!(resource = %r.resource, "refusing a config body that does not parse: {e}");
                    self.nacks.push(Nack { resource: r.resource, digest: r.digest, detail: e.to_string() });
                }
            }
        }
        for r in &resp.removed {
            if let ResourceName::Tenant(t) = r {
                update.removed_tenants.push(t.to_string());
            }
        }

        config_sync::apply_update(&self.targets, &update);

        // A tenant applied for the first time flushes nothing: there is no
        // older body whose generations could have moved.
        for (t, c) in &update.updates {
            let Ok(tenant) = uuid::Uuid::parse_str(t) else { continue };
            let next = Generations::of(c);
            if let Some(prev) = self.generations.get(&tenant) {
                match prev.flushes(&next) {
                    Flush::Tenant => {
                        let dropped = self.targets.response_cache.flush_tenant(tenant);
                        tracing::info!(%tenant, dropped, "response cache flushed (tenant generation)");
                    }
                    Flush::Routes(routes) => {
                        for route in routes.iter().filter_map(|r| uuid::Uuid::parse_str(r).ok()) {
                            let dropped = self.targets.response_cache.flush_route(tenant, route);
                            tracing::info!(%tenant, %route, dropped, "response cache flushed (route generation)");
                        }
                    }
                }
            }
            self.generations.insert(tenant, next);
        }
        for t in &update.removed_tenants {
            if let Ok(tenant) = uuid::Uuid::parse_str(t) {
                self.generations.remove(&tenant);
            }
        }

        for r in &resp.removed {
            self.held.remove(r);
        }
        for (r, d) in &applied {
            self.held.insert(*r, *d);
        }
        let data_dir = self.data_dir.clone();
        let held = self.held_file();
        let persisted = tokio::task::spawn_blocking(move || persist(&data_dir, &update, &held)).await;
        let failed = match persisted {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(e) => Some(e.to_string()),
        };
        if let Some(e) = failed {
            // Served from memory, but not on disk: held as nothing, so the next
            // poll is sent these bodies again and persisting them is retried —
            // a held set never claims a body the disk does not have.
            tracing::warn!("persisting applied config failed — the bodies will be sent again: {e}");
            for (r, _) in applied {
                self.held.insert(r, unheld());
            }
            // Not at once: the same bodies would come straight back, and a
            // disk that cannot take them would be asked to again at full speed.
            self.poll_again = false;
        } else {
            self.cursor_persisted_at = std::time::Instant::now();
        }
        self.mark_ready();
        resp.events
    }

    /// Readiness is "holds its whole config": set once an answer left nothing
    /// unsent, never cleared.
    fn mark_ready(&self) {
        if self.complete {
            self.targets.config_ready.store(true, Ordering::Relaxed);
        }
    }

    fn held_file(&self) -> HeldFile {
        HeldFile {
            held: self.held.iter().map(|(r, d)| Held { resource: *r, digest: *d }).collect(),
            events_after: self.events_after,
            complete: self.complete,
        }
    }

    /// Whether a moved event cursor is written now: when the answer carried
    /// events for this instance, else at most once a minute — the cursor moves
    /// with every tenant's events, and one left behind only replays events
    /// this instance already dispatched.
    fn cursor_due(&self, before: EventId, events: &[Event]) -> bool {
        self.events_after != before
            && (!events.is_empty() || self.cursor_persisted_at.elapsed() >= CURSOR_PERSIST_EVERY)
    }

    fn persist_held(&mut self) {
        self.cursor_persisted_at = std::time::Instant::now();
        if let Err(e) = write_held(&self.data_dir, &self.held_file()) {
            tracing::warn!("persisting the held set failed: {e}");
        }
    }

    /// One poll: send the request, apply the answer, return its events.
    pub async fn poll_once(
        &mut self,
        client: &reqwest::Client,
        url: &str,
        token: &str,
        instance: uuid::Uuid,
        process_epoch: u64,
        ask: Ask,
    ) -> Result<Vec<Event>, anyhow::Error> {
        let req = self.request(instance, process_epoch, ask);
        // A complete edge's answer is small and quick once its hold ends; one
        // whose head has not come by then is on a connection that is gone
        // (a replica that died without closing it). A cold edge's answers may
        // take long to build and are left to the read timeout.
        let head_within = self.complete.then_some(ask.wait + ANSWER_HEAD_MARGIN);
        match exchange(client, url, token, &req, head_within).await {
            Ok(answer) => Ok(self.apply(answer).await),
            Err(e) => {
                // Whatever failed, the refusals were not delivered: report them again.
                self.nacks.extend(req.nacks);
                Err(e)
            }
        }
    }
}

/// What a poll reports beside the held set, and how long admin-api may hold
/// a quiet answer.
#[derive(Clone, Copy, Default)]
pub struct Ask {
    pub outbox_pending: u64,
    pub wait: std::time::Duration,
}

/// How long past its hold a complete edge waits for an answer's head before
/// taking the connection as lost ([`AnswerLost`]).
pub const ANSWER_HEAD_MARGIN: std::time::Duration = std::time::Duration::from_secs(3);

/// An answer whose head did not come within `head_within`: the connection is
/// taken as lost, and the poll is made again at once rather than backed off.
#[derive(Debug)]
pub struct AnswerLost;

impl std::fmt::Display for AnswerLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no answer within the hold — the connection is taken as lost")
    }
}

impl std::error::Error for AnswerLost {}

/// One sync request and its answer, read under the cap every answer fits.
async fn exchange(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    req: &SyncRequest,
    head_within: Option<std::time::Duration>,
) -> Result<SyncResponse, anyhow::Error> {
    // The client's read timeout ends a stalled answer; a slow one of any size
    // completes.
    use streamscope_edge_api::compression;
    let sent = client
        .post(url)
        .bearer_auth(token)
        .header(reqwest::header::ACCEPT_ENCODING, compression::GZIP)
        .json(req)
        .send();
    let resp = match head_within {
        Some(within) => tokio::time::timeout(within, sent).await.map_err(|_| AnswerLost)??,
        None => sent.await?,
    };
    let status = resp.status();
    let encoding = resp
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).trim().to_ascii_lowercase());
    let cap = streamscope_edge_api::sync::SYNC_RESPONSE_MAX_BYTES;
    let body = streamscope_core::http_body::read_body_capped(resp, cap as u64).await?;
    if !status.is_success() {
        anyhow::bail!("sync answered {status}");
    }
    // A steady-state poll is a few hundred bytes, parsed in place; a cold
    // edge's answer is megabytes, decoded and parsed off the request workers.
    // The decoded answer is held to the same cap as a plain one.
    if encoding.is_none() && body.len() < 64 * 1024 {
        return Ok(serde_json::from_slice(&body)?);
    }
    tokio::task::spawn_blocking(move || -> Result<SyncResponse, anyhow::Error> {
        match encoding.as_deref() {
            None | Some("identity") => Ok(serde_json::from_slice(&body)?),
            Some(compression::GZIP) => Ok(serde_json::from_slice(&compression::gunzip_capped(&body, cap)?)?),
            Some(other) => anyhow::bail!("sync answered in an encoding this edge does not read: {other}"),
        }
    })
    .await?
}

/// Snapshot first, held set second (see the module doc).
fn persist(data_dir: &str, update: &IncrementalConfigUpdate, held: &HeldFile) -> Result<(), anyhow::Error> {
    config_snapshot::merge_incremental_update(data_dir, update)?;
    if let Some(overrides) = &update.runtime_overrides {
        config_snapshot::persist_runtime_overrides(data_dir, overrides);
    }
    write_held(data_dir, held)
}

fn write_held(data_dir: &str, held: &HeldFile) -> Result<(), anyhow::Error> {
    let path = format!("{data_dir}/{HELD_FILE}");
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, serde_json::to_vec(held)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use streamscope_core::config::TenantId;
    use streamscope_edge_api::digest::{canonical_value, digest_of};
    use streamscope_edge_api::sync::{Event, Resource};

    fn targets() -> ConfigTargets {
        ConfigTargets {
            tenant_registry: streamscope_core::config::new_tenant_registry(),
            script_engine: Arc::new(streamscope_core::scripting::ScriptEngine::new()),
            active_programs: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            config_ready: Arc::default(),
            response_cache: Arc::new(streamscope_core::proxy::response_cache::ResponseCache::new(1 << 20, 100)),
        }
    }

    fn data_dir() -> String {
        let dir = std::env::temp_dir().join(format!("streamscope_sync_v2_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn tenant_body(slug: &str) -> serde_json::Value {
        crate::config_sync::tests::body_json(serde_json::json!({ "tenant_slug": slug }))
    }

    fn resource(r: ResourceName, body: serde_json::Value) -> Resource {
        let body = canonical_value(&body).unwrap();
        let digest = digest_of(&body).unwrap();
        Resource { resource: r, digest, counter: 1, body: serde_json::value::to_raw_value(&body).unwrap() }
    }

    fn answer(resources: Vec<Resource>, removed: Vec<ResourceName>) -> SyncResponse {
        SyncResponse { resources, removed, ..Default::default() }
    }

    const T: uuid::Uuid = uuid::Uuid::from_u128(0xa);

    /// Held by every test that applies a `global` body: it sets the
    /// process-wide log level, which tests running in parallel would
    /// otherwise overwrite between an apply and its assertion.
    static GLOBAL_BODY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn an_applied_body_serves_holds_and_survives_a_restart() {
        let _global = GLOBAL_BODY.lock().await;
        let (t, dir) = (targets(), data_dir());
        let mut s = SyncV2::load(t.clone(), &dir);
        let tenant = resource(ResourceName::Tenant(T), tenant_body("acme"));
        let global = resource(ResourceName::Global, serde_json::json!({ "log_level": null, "runtime_overrides": {}, "egress": {} }));
        s.apply(answer(vec![tenant.clone(), global.clone()], vec![])).await;

        assert_eq!(t.tenant_registry.load().get(&TenantId(T)).map(|c| c.tenant_slug.clone()), Some("acme".into()));
        assert!(t.config_ready.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(s.held.get(&ResourceName::Tenant(T)), Some(&tenant.digest));

        let reloaded = SyncV2::load(targets(), &dir);
        assert_eq!(reloaded.held, s.held);
        assert_eq!(reloaded.held_digest(), s.held_digest());
        assert!(config_snapshot::load_snapshot(&dir).unwrap().unwrap().tenants.contains_key(&T.to_string()));
    }

    #[tokio::test]
    async fn a_body_that_does_not_parse_is_refused_once_and_not_held() {
        let (t, dir) = (targets(), data_dir());
        let mut s = SyncV2::load(t.clone(), &dir);
        let bad = resource(ResourceName::Tenant(T), serde_json::json!({ "tenant_slug": 7 }));
        s.apply(answer(vec![bad.clone()], vec![])).await;
        assert!(!s.held.contains_key(&ResourceName::Tenant(T)));
        assert!(t.tenant_registry.load().get(&TenantId(T)).is_none());

        let req = s.request(uuid::Uuid::nil(), 1, Ask::default());
        assert_eq!(req.nacks.len(), 1);
        assert_eq!((req.nacks[0].resource, req.nacks[0].digest), (bad.resource, bad.digest));
        assert!(s.request(uuid::Uuid::nil(), 1, Ask::default()).nacks.is_empty(), "a refusal is reported once");
    }

    #[tokio::test]
    async fn the_config_is_current_only_after_an_answer_that_left_nothing_unsent() {
        let mut s = SyncV2::load(targets(), &data_dir());
        let mut partial = answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![]);
        partial.more = true;
        s.apply(partial).await;
        assert!(!s.current(), "part of the config");
        s.apply(answer(vec![], vec![])).await;
        assert!(s.current(), "control: the whole config");
        let mut later = answer(vec![], vec![]);
        later.more = true;
        s.apply(later).await;
        assert!(!s.current(), "an answer leaving bodies unsent");
        s.apply(answer(vec![], vec![])).await;
        assert!(s.current());
        s.apply(SyncResponse { send_held: true, ..Default::default() }).await;
        assert!(!s.current(), "an answer asking for the held set");
        s.apply(answer(vec![], vec![])).await;
        assert!(s.current());
    }

    #[tokio::test]
    async fn a_removed_tenant_stops_serving_and_is_no_longer_held() {
        let (t, dir) = (targets(), data_dir());
        let mut s = SyncV2::load(t.clone(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        s.apply(answer(vec![], vec![ResourceName::Tenant(T)])).await;
        assert!(t.tenant_registry.load().get(&TenantId(T)).is_none());
        assert!(s.held.is_empty());
        assert!(SyncV2::load(targets(), &dir).held.is_empty());
    }

    #[tokio::test]
    async fn the_full_held_set_is_sent_only_when_asked() {
        let mut s = SyncV2::load(targets(), &data_dir());
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        assert!(s.request(uuid::Uuid::nil(), 1, Ask::default()).held.is_none());
        s.apply(SyncResponse { send_held: true, ..Default::default() }).await;
        let req = s.request(uuid::Uuid::nil(), 1, Ask::default());
        assert_eq!(req.held.map(|h| h.len()), Some(1));
        assert_eq!(req.held_digest, s.held_digest());
    }

    #[test]
    fn a_raised_generation_flushes_exactly_what_it_names() {
        let g = |tenant, routes: &[(&str, i64)]| Generations {
            tenant,
            routes: routes.iter().map(|(r, n)| (r.to_string(), *n)).collect(),
        };
        let prev = g(1, &[("r1", 0), ("r2", 4)]);
        assert_eq!(prev.flushes(&prev.clone()), Flush::Routes(vec![]), "unchanged: nothing");
        assert_eq!(prev.flushes(&g(2, &[("r1", 0), ("r2", 4)])), Flush::Tenant);
        assert_eq!(prev.flushes(&g(1, &[("r1", 0), ("r2", 5)])), Flush::Routes(vec!["r2".into()]));
        assert_eq!(
            prev.flushes(&g(1, &[("r1", 0), ("r2", 4), ("r3", 7)])),
            Flush::Routes(vec![]),
            "a route seen for the first time has nothing cached to drop"
        );
    }

    #[tokio::test]
    async fn generations_are_read_from_the_applied_body_and_forgotten_on_removal() {
        let mut s = SyncV2::load(targets(), &data_dir());
        let mut body = tenant_body("acme");
        body["settings"] = serde_json::json!({ "response_cache_generation": 3 });
        body["model_mappings"] = serde_json::json!([crate::config_sync::tests::mapping_json(serde_json::json!({
            "id": "11111111-1111-1111-1111-111111111111", "cache_generation": 2,
        }))]);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), body)], vec![])).await;
        let g = s.generations.get(&T).expect("applied tenant tracked");
        assert_eq!(g.tenant, 3);
        assert_eq!(g.routes.get("11111111-1111-1111-1111-111111111111"), Some(&2));
        s.apply(answer(vec![], vec![ResourceName::Tenant(T)])).await;
        assert!(!s.generations.contains_key(&T));
    }

    #[tokio::test]
    async fn an_empty_answer_rewrites_nothing() {
        let (t, dir) = (targets(), data_dir());
        let mut s = SyncV2::load(t.clone(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        let snapshot = format!("{dir}/config_snapshot_mt.json");
        let modified = std::fs::metadata(&snapshot).unwrap().modified().unwrap();
        let programs = t.active_programs.load_full();
        std::thread::sleep(std::time::Duration::from_millis(20));
        s.apply(answer(vec![], vec![])).await;
        assert_eq!(std::fs::metadata(&snapshot).unwrap().modified().unwrap(), modified);
        assert!(Arc::ptr_eq(&programs, &t.active_programs.load_full()), "programs not rebuilt");
    }

    #[tokio::test]
    async fn a_restart_keeps_the_generations_and_the_event_cursor() {
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        let mut body = tenant_body("acme");
        body["settings"] = serde_json::json!({ "response_cache_generation": 5 });
        let event = Event { id: 7, tenant: T, body: serde_json::json!({}) };
        let mut resp = answer(vec![resource(ResourceName::Tenant(T), body)], vec![]);
        resp.events = vec![event];
        resp.events_cursor = 7;
        s.apply(resp).await;
        let reloaded = SyncV2::load(targets(), &dir);
        assert_eq!(reloaded.generations.get(&T).map(|g| g.tenant), Some(5));
        assert_eq!(reloaded.events_after, 7);
    }

    #[tokio::test]
    async fn the_event_cursor_is_the_answers_and_its_events_are_handed_back() {
        let mut s = SyncV2::load(targets(), &data_dir());
        let event = |id| Event { id, tenant: T, body: serde_json::json!({}) };
        let events = s.apply(SyncResponse { events: vec![event(4), event(9)], events_cursor: 12, ..Default::default() }).await;
        assert_eq!(events.iter().map(|e| e.id).collect::<Vec<_>>(), vec![4, 9]);
        assert_eq!(s.request(uuid::Uuid::nil(), 1, Ask::default()).events_after, 12);
        s.apply(SyncResponse { events_cursor: 3, ..Default::default() }).await;
        assert_eq!(s.request(uuid::Uuid::nil(), 1, Ask::default()).events_after, 3, "a restored database's head wins");
        s.apply(SyncResponse { send_held: true, events_cursor: 5, ..Default::default() }).await;
        assert_eq!(s.request(uuid::Uuid::nil(), 1, Ask::default()).events_after, 5, "also on a send_held answer");
    }

    #[tokio::test]
    async fn the_process_is_ready_only_once_an_answer_leaves_nothing_unsent() {
        let (t, dir) = (targets(), data_dir());
        let ready = || t.config_ready.load(Ordering::Relaxed);
        let mut s = SyncV2::load(t.clone(), &dir);
        let mut partial = answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![]);
        partial.more = true;
        s.apply(partial).await;
        assert!(!ready(), "part of the config is not ready");
        assert!(!SyncV2::load(targets(), &dir).complete(), "nor after a restart");
        s.apply(answer(vec![], vec![])).await;
        assert!(ready());
        assert!(SyncV2::load(targets(), &dir).complete(), "a whole config on disk is ready at start");
        let mut later = answer(vec![], vec![]);
        later.more = true;
        s.apply(later).await;
        assert!(ready(), "once ready, a later partial answer does not take it back");
    }

    #[tokio::test]
    async fn a_cleared_log_level_reaches_the_edge_as_the_default() {
        let _global = GLOBAL_BODY.lock().await;
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        let global = |level: serde_json::Value| resource(ResourceName::Global, serde_json::json!({ "log_level": level, "runtime_overrides": {}, "egress": {} }));
        s.apply(answer(vec![global(serde_json::json!("debug"))], vec![])).await;
        let level = || config_snapshot::load_snapshot(&dir).unwrap().unwrap().log_level;
        assert_eq!(level().as_deref(), Some("debug"), "control");
        assert_eq!(crate::log_level::current(), "debug", "control: applied");
        s.apply(answer(vec![global(serde_json::Value::Null)], vec![])).await;
        assert_eq!(level().as_deref(), Some("info"), "no level set is the default, not the last level");
        assert_eq!(crate::log_level::current(), "info", "and it is applied, not only saved");
    }

    /// The lists persist with the snapshot a restart applies first, and an
    /// answer without the `global` body leaves them as they were. (That they
    /// are installed is the e2e suite's: the store is process-wide, and other
    /// tests of this binary install lists of their own concurrently.)
    #[tokio::test]
    async fn the_egress_lists_ride_the_global_body_into_the_snapshot() {
        let _global = GLOBAL_BODY.lock().await;
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        let global = |lists: serde_json::Value| {
            resource(ResourceName::Global, serde_json::json!({ "log_level": null, "runtime_overrides": {}, "egress": lists }))
        };
        let lists = || config_snapshot::load_snapshot(&dir).unwrap().unwrap().egress;
        s.apply(answer(vec![global(serde_json::json!({ "mcp": ["10.0.0.0/8"] }))], vec![])).await;
        assert_eq!(lists().get("mcp").map(Vec::as_slice), Some(&["10.0.0.0/8".to_string()][..]));
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        assert!(lists().contains_key("mcp"), "an answer without the global body keeps the lists");
        s.apply(answer(vec![global(serde_json::json!({}))], vec![])).await;
        assert!(lists().is_empty(), "an emptied set is persisted empty, not kept");
    }

    #[tokio::test]
    async fn a_body_that_could_not_be_persisted_is_held_as_nothing() {
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        assert_ne!(s.held.get(&ResourceName::Tenant(T)), Some(&unheld()), "control: persisted, held");
        // The snapshot can no longer be written: a directory stands in its place.
        let snapshot = format!("{dir}/config_snapshot_mt.json");
        std::fs::remove_file(&snapshot).unwrap();
        std::fs::create_dir(&snapshot).unwrap();
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme-2"))], vec![])).await;
        assert_eq!(s.held.get(&ResourceName::Tenant(T)), Some(&unheld()), "not on disk: held as nothing, so sent again");
    }

    #[tokio::test]
    async fn a_held_set_claiming_a_tenant_the_snapshot_lacks_is_not_complete() {
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        assert!(SyncV2::load(targets(), &dir).complete(), "control");
        // The held file claims a second tenant the snapshot does not carry.
        let mut file: HeldFile = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{HELD_FILE}")).unwrap()).unwrap();
        let other = ResourceName::Tenant(uuid::Uuid::from_u128(0xb));
        file.held.push(Held { resource: other, digest: Digest::of(b"other") });
        write_held(&dir, &file).unwrap();
        let reloaded = SyncV2::load(targets(), &dir);
        assert!(!reloaded.held.contains_key(&other), "a body not on disk is not held");
        assert!(!reloaded.complete(), "and the config on disk is not whole");
    }

    #[tokio::test]
    async fn a_held_set_without_its_snapshot_is_discarded_and_not_complete() {
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        assert!(SyncV2::load(targets(), &dir).complete(), "control: held set and snapshot together");
        assert!(SyncV2::load(targets(), &dir).held.contains_key(&ResourceName::Tenant(T)));
        std::fs::remove_file(format!("{dir}/config_snapshot_mt.json")).unwrap();
        let reloaded = SyncV2::load(targets(), &dir);
        assert!(reloaded.held.is_empty(), "no body on disk: nothing held, so admin re-sends every one");
        assert!(!reloaded.complete());
    }

    #[tokio::test]
    async fn an_answer_with_more_or_asking_for_the_held_set_polls_again_at_once() {
        let mut s = SyncV2::load(targets(), &data_dir());
        let mut partial = answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![]);
        partial.more = true;
        s.apply(partial).await;
        assert!(s.poll_again());
        s.apply(SyncResponse { send_held: true, ..Default::default() }).await;
        assert!(s.poll_again());
        s.apply(answer(vec![], vec![])).await;
        assert!(!s.poll_again(), "a whole answer waits the interval");
    }

    #[tokio::test]
    async fn a_snapshot_tenant_without_a_held_digest_is_reported_as_unheld() {
        let dir = data_dir();
        let mut s = SyncV2::load(targets(), &dir);
        s.apply(answer(vec![resource(ResourceName::Tenant(T), tenant_body("acme"))], vec![])).await;
        std::fs::remove_file(format!("{dir}/{HELD_FILE}")).unwrap();
        let reloaded = SyncV2::load(targets(), &dir);
        assert_eq!(reloaded.held.get(&ResourceName::Tenant(T)), Some(&unheld()));
        assert!(!reloaded.complete());
    }
}
