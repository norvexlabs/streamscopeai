//! Provider-aware model sync pipeline.
//!
//! One transactional spine shared by the manual diff endpoint, the "sync now"
//! action, the background autosync worker, a new server's first sync and an
//! added endpoint's first look. Discovery (an HTTP call to each enabled
//! endpoint's `/models`, concurrently) is done outside the transaction; the
//! apply step runs entirely inside the caller's transaction so a mid-sequence
//! failure rolls back to the pre-sync state — model rows, memberships and
//! routes are never left half-applied.
//!
//! The endpoints' answers are fused by [`super::model_fusion`]: only an answer
//! is evidence, an answer removes only when trusted, and a model retires only
//! when every endpoint that listed it answered without it. AUTO mode applies
//! the plan (add + refresh + remove) and refuses to write when every endpoint
//! answered and together they named implausibly few models (empty, or fewer
//! than half the current count), so a transient provider blip can never wipe a
//! configured fleet. MANUAL mode computes the diff a person reviews and writes
//! nothing — the UI drives the apply via the model create and delete
//! endpoints. Its diff judges no answer's length: every model the answering
//! endpoints no longer list is offered for removal, so a server that really
//! shrank can be reconciled.

use uuid::Uuid;

use streamscope_core::config::upstream_transport::UpstreamTransport;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::upstream_endpoints::{load_endpoints, EndpointRow, ReportedFacts};
use super::upstreams::{call_discover_models, DiscoveredModel, RemovedModelInfo};
use crate::db::tenant::Scoped;

#[derive(sqlx::FromRow)]
struct ExistingModel {
    id: Uuid,
    upstream_model: String,
    enabled: bool,
}

/// Marker set on a hand-built (`auto_synced = false`) route when autosync finds
/// its upstream model has vanished from the provider. SOFT: the route is disabled
/// (not deleted) and the model row is kept while referenced, so the route is
/// **reinstated** automatically if the model reappears. See [`DISABLED_REASON_ORPHANED`].
pub const DISABLED_REASON_VANISHED: &str = "upstream_model_vanished";

/// Marker set on a curated (`auto_synced = false`) route when the operator deletes
/// its upstream model (or the whole server). HARD: the model row is gone and the
/// route's `model_id` is nulled (FK `ON DELETE SET NULL`), so the route is an
/// **orphan** — surfaced for cleanup, never reinstated (unlike a vanish).
pub const DISABLED_REASON_ORPHANED: &str = "upstream_model_deleted";

/// Counts from retiring a single model (vanish path).
pub struct RetireCounts {
    pub routes_deleted: u32,
    pub routes_disabled: u32,
    pub model_removed: bool,
}

/// Soft-retire a vanished model: delete its auto routes; disable + flag its curated
/// routes (only those still `enabled = true`, so an operator's existing disable
/// keeps its own reason and is never auto-reinstated on reappear); drop the model
/// only when nothing curated still references it, else disable it so it stops
/// serving but stays reinstatable if the provider re-offers it.
pub async fn retire_model_soft(
    conn: &mut Scoped,
    model_id: Uuid,
) -> Result<RetireCounts, SyncError> {
    let del = sqlx::query("DELETE FROM downstream_routes WHERE model_id = $1 AND auto_synced = true")
        .bind(model_id)
        .execute(&mut *conn)
        .await
        .map_err(SyncError::Db)?;

    let dis = sqlx::query(
        "UPDATE downstream_routes SET enabled = false, disabled_reason = $2 \
         WHERE model_id = $1 AND auto_synced = false AND enabled = true",
    )
    .bind(model_id)
    .bind(DISABLED_REASON_VANISHED)
    .execute(&mut *conn)
    .await
    .map_err(SyncError::Db)?;

    let remaining_routes: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM downstream_routes WHERE model_id = $1")
            .bind(model_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
    let model_removed = remaining_routes == 0;
    if model_removed {
        sqlx::query("DELETE FROM upstream_models WHERE id = $1")
            .bind(model_id)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
    } else {
        sqlx::query("UPDATE upstream_models SET enabled = false WHERE id = $1")
            .bind(model_id)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
    }

    Ok(RetireCounts {
        routes_deleted: del.rows_affected() as u32,
        routes_disabled: dis.rows_affected() as u32,
        model_removed,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncMode {
    /// Compute the diff a person reviews, write nothing. No length floor:
    /// every model the answering endpoints no longer list is offered.
    Manual,
    /// Apply the diff: add new models, refresh caps/pricing, remove vanished ones.
    /// The worker's mode once a server has synced: an endpoint's FIRST answer
    /// still only adds (see [`super::model_fusion`]).
    Auto,
    /// An operator's "Sync now": apply the diff and trust every answer, an
    /// endpoint's first included — the operator asked for a full reconcile.
    Explicit,
    /// Apply adds + refreshes but NEVER remove/disable. Used by the background
    /// worker until a server has had a *successful* autosync: the operator has
    /// just hand-configured the server and there is no trusted discovery baseline
    /// yet, so a discovery that doesn't list a configured model must augment —
    /// never tear down — that fresh config. Full reconciliation (including
    /// removal) resumes once a sync succeeds; an explicit operator `Sync now`
    /// (`Explicit`) always reconciles fully.
    AutoFirstSync,
}

impl SyncMode {
    /// The mode the worker (and any sync not asked for by an operator) uses:
    /// add-only until the server has had a successful sync.
    pub fn for_worker(has_synced_ok: bool) -> Self {
        if has_synced_ok { SyncMode::Auto } else { SyncMode::AutoFirstSync }
    }
}

/// Failure modes the caller must turn into either an HTTP error (endpoint) or a
/// recorded `last_auto_sync_status` (worker).
pub enum SyncError {
    /// The server does not exist (in this tenant).
    ServerNotFound,
    /// Provider discovery (HTTP/parse) failed on every endpoint asked.
    Discovery(crate::routes::ApiError),
    /// Every endpoint answered, and together they named implausibly few models
    /// — refused to apply anything.
    Implausible { discovered: usize, existing: usize },
    /// The mirror downstream name is already taken by a different downstream
    /// provider — refused to hijack it onto this server.
    NameConflict { name: String },
    /// A database statement failed (the transaction is rolled back by the caller).
    Db(sqlx::Error),
}

impl SyncError {
    /// One-line reason for `last_auto_sync_status` / logs.
    pub fn reason(&self) -> String {
        match self {
            SyncError::ServerNotFound => "server not found".to_string(),
            SyncError::Discovery(e) => format!("discovery failed: {}", e.message),
            SyncError::Implausible { discovered, existing } => implausible_message(*discovered, *existing),
            SyncError::NameConflict { name } => format!(
                "downstream name '{name}' is already in use by another downstream — refusing to mirror"
            ),
            SyncError::Db(e) => format!("database error: {e}"),
        }
    }
}

/// Why an implausible discovery was refused, and what the operator can do: a
/// list that names nothing is a server not up yet (a review removes nothing
/// on it either); a short one may be a real shrink, which a review of the
/// fully-up server accepts (a review keeps a short answer's floor while one
/// of the server's endpoints is silent, and an empty answer's always).
fn implausible_message(discovered: usize, existing: usize) -> String {
    if discovered == 0 {
        format!("implausible discovery: provider listed no models vs {existing} configured — refusing to remove; check the server is up and sync again")
    } else {
        format!("implausible discovery: provider returned {discovered} models vs {existing} configured — refusing to remove; once every endpoint of the server is up and answering, review the sync to accept the change")
    }
}

/// Map a pipeline error to the HTTP error surfaced by the manual-sync and
/// sync-now endpoints.
pub fn sync_error_to_api(e: SyncError) -> crate::routes::ApiError {
    use crate::routes::{ApiError, ApiErrorCode};
    match e {
        SyncError::ServerNotFound => ApiError::not_found("server not found", ApiErrorCode::ServerNotFound),
        SyncError::Discovery(api) => api,
        SyncError::Implausible { discovered, existing } => ApiError::bad_gateway(implausible_message(discovered, existing))
            .code(ApiErrorCode::UpstreamUnreachable),
        SyncError::NameConflict { name } => ApiError::conflict(format!(
            "downstream name '{name}' is already in use by another downstream provider"
        ), ApiErrorCode::DownstreamNameTaken),
        SyncError::Db(err) => {
            tracing::error!("model sync db error: {err}");
            ApiError::internal("model sync failed")
        }
    }
}

/// What one endpoint contributed to a sync.
#[derive(Serialize, ToSchema, Clone, Debug)]
pub struct EndpointSyncReport {
    pub endpoint_id: Uuid,
    pub url: String,
    /// Whether it answered with a model list. An endpoint that did not answer
    /// changed nothing: every model it served was kept.
    pub answered: bool,
    /// How many models its answer named.
    pub listed: u32,
    /// Why the models its answer omitted were kept rather than removed:
    /// `first_answer`, `server_first_sync` or `short_answer`. Absent when the
    /// answer was trusted to remove them, or it did not answer.
    pub kept: Option<String>,
    /// Why it did not answer.
    pub reason: Option<String>,
}

/// Result of a sync run. Diff fields are always populated; apply counts are zero
/// in `Manual` mode.
#[derive(Default)]
pub struct SyncOutcome {
    pub discovered: Vec<DiscoveredModel>,
    pub new_models: Vec<DiscoveredModel>,
    pub removed: Vec<RemovedModelInfo>,
    /// One report per enabled endpoint, primary first.
    pub endpoints: Vec<EndpointSyncReport>,
    /// Manual only: "Sync now" on the same answers would not make every one
    /// of `removed` — it judges an answer implausibly short.
    pub unattended_refuses: bool,
    // Apply counts (Auto only).
    pub added: u32,
    pub refreshed: u32,
    pub models_removed: u32,
    pub routes_deleted: u32,
    pub routes_disabled: u32,
    pub skipped_overrides: u32,
}

/// The last autosync run's outcome as the API reports it: `ok` with the
/// counts on success, `ok: false` with `reason` and `at` on failure. Read from
/// the stored `upstream_servers.last_auto_sync_status`; every field but `ok` is
/// optional because each outcome writes a different subset.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct AutoSyncStatus {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the failure was recorded (database clock).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshed: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models_removed: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_deleted: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_disabled: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped_overrides: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints_unanswered: Option<u32>,
}

impl AutoSyncStatus {
    /// The stored JSON read as the typed outcome. A recorded value that does
    /// not parse still reports a run: as a failure unless it says `ok: true`,
    /// keeping its `reason` when it has one — never as no run at all, which the
    /// console would show as healthy.
    pub fn from_stored(v: serde_json::Value) -> Option<Self> {
        if v.is_null() {
            return None;
        }
        serde_json::from_value(v.clone()).ok().or_else(|| {
            Some(Self {
                ok: v.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false),
                reason: v.get("reason").and_then(serde_json::Value::as_str).map(str::to_string),
                at: None,
                added: None,
                refreshed: None,
                models_removed: None,
                routes_deleted: None,
                routes_disabled: None,
                skipped_overrides: None,
                endpoints: None,
                endpoints_unanswered: None,
            })
        })
    }
}

impl SyncOutcome {
    /// Compact success summary stored in `upstream_servers.last_auto_sync_status`.
    pub fn status_json(&self) -> serde_json::Value {
        let unanswered = self.endpoints.iter().filter(|e| !e.answered).count();
        serde_json::json!({
            "ok": true,
            "added": self.added,
            "refreshed": self.refreshed,
            "models_removed": self.models_removed,
            "routes_deleted": self.routes_deleted,
            "routes_disabled": self.routes_disabled,
            "skipped_overrides": self.skipped_overrides,
            "endpoints": self.endpoints.len(),
            "endpoints_unanswered": unanswered,
        })
    }
}

/// Everything a sync of one server needs, loaded once.
pub(crate) struct SyncServer {
    pub id: Uuid,
    pub name: String,
    provider: String,
    api_key: Option<String>,
    chat_endpoint_path: Option<String>,
    transport: UpstreamTransport,
    /// The server has had a successful sync (the worker's add-only switch).
    pub has_synced_ok: bool,
    /// Every endpoint, primary order.
    pub endpoints: Vec<EndpointRow>,
}

/// Load a server for a sync. `None` when it does not exist in this tenant.
pub(crate) async fn load_sync_server(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Option<SyncServer>, SyncError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, Option<String>, Option<String>, String, bool)> = sqlx::query_as(
        "SELECT name, provider, encrypted_key, chat_endpoint_path, transport, \
                COALESCE((last_auto_sync_status->>'ok')::boolean, false) \
         FROM upstream_servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(SyncError::Db)?;
    let Some((name, provider, encrypted_key, chat_endpoint_path, transport, has_synced_ok)) = row else {
        return Ok(None);
    };
    let api_key = super::upstreams::decrypt_server_key(encrypted_key).map_err(SyncError::Discovery)?;
    let endpoints = load_endpoints(conn, server_id).await.map_err(SyncError::Db)?;
    Ok(Some(SyncServer {
        id: server_id,
        name,
        provider,
        api_key,
        chat_endpoint_path,
        transport: UpstreamTransport::from_str_relaxed(&transport),
        has_synced_ok,
        endpoints,
    }))
}

/// What discovery got from one endpoint.
pub(crate) enum Discovery {
    /// It answered with this list.
    Answered(Vec<DiscoveredModel>),
    /// It was asked and did not answer.
    Failed(crate::routes::ApiError),
    /// It was not asked: a disabled endpoint. It changes nothing and keeps
    /// what it serves.
    NotAsked,
    /// It was added, or pointed at another host, while the others were asked:
    /// enabled and silent, so it holds the server gate off like a failure, but
    /// nothing is recorded on it — it was never asked as it is now.
    Changed,
}

impl Discovery {
    fn answered(&self) -> Option<&Vec<DiscoveredModel>> {
        match self {
            Discovery::Answered(l) => Some(l),
            _ => None,
        }
    }
}

/// One endpoint of the server and what discovery got from it.
pub(crate) struct EndpointAnswer {
    pub endpoint: EndpointRow,
    pub answer: Discovery,
}

/// Ask every enabled endpoint for its model list, concurrently. Run this
/// BEFORE opening the apply transaction so the (up to 10 s each) HTTP calls do
/// not hold it open. Every endpoint of the server gets an entry — a disabled
/// one as not asked, since it still serves its models; [`nobody_answered`]
/// says whether the sync can go on.
pub(crate) async fn discover_all(server: &SyncServer) -> Vec<EndpointAnswer> {
    let answers = futures::future::join_all(server.endpoints.iter().map(|e| async move {
        if !e.enabled {
            return Discovery::NotAsked;
        }
        match call_discover_models(
            &server.provider,
            &e.url,
            server.api_key.as_deref(),
            server.chat_endpoint_path.as_deref(),
            server.transport,
        )
        .await
        {
            Ok(list) => Discovery::Answered(list),
            Err(err) => Discovery::Failed(err),
        }
    }))
    .await;
    server
        .endpoints
        .iter()
        .zip(answers)
        .map(|(e, answer)| EndpointAnswer { endpoint: e.clone(), answer })
        .collect()
}

/// The sync's failure when no endpoint answered: the primary's own failure,
/// exactly as a single-URL server reported it. `None` when one did.
pub(crate) fn nobody_answered(answers: &[EndpointAnswer]) -> Option<SyncError> {
    if answers.iter().all(|a| matches!(a.answer, Discovery::NotAsked)) {
        return Some(SyncError::Discovery(
            crate::routes::ApiError::bad_request("server has no enabled endpoint to discover against")
                .code(crate::routes::ApiErrorCode::UpstreamUrlMissing),
        ));
    }
    if answers.iter().any(|a| a.answer.answered().is_some()) {
        return None;
    }
    let first = answers.iter().find_map(|a| match &a.answer {
        Discovery::Failed(e) => Some(e.clone()),
        _ => None,
    });
    Some(SyncError::Discovery(first.unwrap_or_else(|| crate::routes::ApiError::bad_gateway("discovery failed"))))
}

/// Record, on each endpoint that did not answer, why — on the plain
/// connection, before the sync's transaction, so it survives a sync that is
/// then refused or rolls back.
async fn record_unanswered(conn: &mut Scoped, answers: &[EndpointAnswer]) -> Result<(), SyncError> {
    for a in answers {
        if let Discovery::Failed(err) = &a.answer {
            sqlx::query(
                "UPDATE upstream_server_endpoints SET last_discovery_at = NOW(), \
                 last_discovery_status = $2 WHERE id = $1 AND url = $3",
            )
            .bind(a.endpoint.id)
            .bind(serde_json::json!({ "ok": false, "reason": err.message }))
            .bind(&a.endpoint.url)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
        }
    }
    Ok(())
}

/// Line the answers up with the server's endpoints as they are NOW. The
/// transaction holds the server row and its endpoint rows (`FOR UPDATE`) from
/// here to its commit. An answer from an endpoint removed, or pointed at
/// another host, while discovery ran is dropped — it described a host the
/// endpoint no longer is — and such an endpoint, like one added meanwhile, is
/// [`Discovery::Changed`]. A disabled endpoint is not asked and keeps what it
/// serves.
async fn revalidate_answers(
    tx: &mut Scoped,
    server_id: Uuid,
    answers: Vec<EndpointAnswer>,
) -> Result<Vec<EndpointAnswer>, SyncError> {
    let now = super::upstream_endpoints::load_endpoints_for_update(tx, server_id).await.map_err(SyncError::Db)?;
    let mut by_id: HashMap<Uuid, EndpointAnswer> = answers.into_iter().map(|a| (a.endpoint.id, a)).collect();
    Ok(now
        .into_iter()
        .map(|current| {
            // An endpoint disabled meanwhile takes no traffic: whatever it
            // answered, it lists nothing another endpoint may lean on.
            let answer = match by_id.remove(&current.id) {
                _ if !current.enabled => Discovery::NotAsked,
                Some(a) if a.endpoint.url == current.url => a.answer,
                _ => Discovery::Changed,
            };
            EndpointAnswer { endpoint: current, answer }
        })
        .collect())
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    endpoint_id: Uuid,
    upstream_model: String,
    kind: String,
}

/// Apply (or, in Manual mode, just compute) a sync of the endpoints' answers
/// against the models currently configured for the server. Must run inside
/// the caller's transaction in the applying modes.
///
/// [`super::model_fusion::fuse`] decides everything set-shaped; this function
/// loads its inputs and writes its plan. For a server with one endpoint the
/// plan is exactly the single-URL reconcile.
pub(crate) async fn apply_sync(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server: &SyncServer,
    answers: &[EndpointAnswer],
    mode: SyncMode,
) -> Result<SyncOutcome, SyncError> {
    use super::model_fusion::{Answer, EndpointPlan, EndpointState, Judge, MemberKind};
    use std::collections::{BTreeMap, BTreeSet};

    let server_id = server.id;
    let existing: Vec<ExistingModel> =
        sqlx::query_as("SELECT id, upstream_model, enabled FROM upstream_models WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
    let existing_names: BTreeSet<String> = existing.iter().map(|m| m.upstream_model.clone()).collect();

    let rows: Vec<MemberRow> = sqlx::query_as(
        "SELECT me.endpoint_id, m.upstream_model, me.kind FROM upstream_model_endpoints me \
         JOIN upstream_models m ON m.id = me.model_id WHERE me.server_id = $1",
    )
    .bind(server_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(SyncError::Db)?;
    // A disabled model with no row is a retired one: no endpoint serves it,
    // and no assumption gives it back — only an answer naming it, or the
    // operator turning it on.
    let rowed: BTreeSet<&str> = rows.iter().map(|r| r.upstream_model.as_str()).collect();
    let retired: BTreeSet<String> = existing
        .iter()
        .filter(|m| !m.enabled && !rowed.contains(m.upstream_model.as_str()))
        .map(|m| m.upstream_model.clone())
        .collect();
    let mut members_of: HashMap<Uuid, BTreeMap<String, MemberKind>> = HashMap::new();
    for r in rows {
        let kind = if r.kind == "listed" { MemberKind::Listed } else { MemberKind::Assumed };
        members_of.entry(r.endpoint_id).or_default().insert(r.upstream_model, kind);
    }

    // An operator's sync (and its preview) trusts every answer: an endpoint
    // that never answered, and answers NOW, is read as having answered before,
    // serving what it serves now — every model — so its first answer may
    // remove. One that does not answer stays outside every quorum, as in the
    // worker's pass.
    let trust_first_answers = matches!(mode, SyncMode::Manual | SyncMode::Explicit);
    let states: Vec<EndpointState> = answers
        .iter()
        .map(|a| {
            let e = &a.endpoint;
            let members = members_of.remove(&e.id).unwrap_or_default();
            if trust_first_answers && !e.listed && a.answer.answered().is_some() {
                EndpointState {
                    listed: true,
                    members: existing_names
                        .iter()
                        .filter(|n| !retired.contains(*n))
                        .map(|n| (n.clone(), MemberKind::Assumed))
                        .collect(),
                }
            } else {
                EndpointState { listed: e.listed, members }
            }
        })
        .collect();
    let answer_sets: Vec<Answer> = answers
        .iter()
        .map(|a| match &a.answer {
            Discovery::Answered(l) => Answer::Listed(l.iter().map(|d| d.id.clone()).collect()),
            Discovery::Failed(_) | Discovery::Changed => Answer::Failed,
            Discovery::NotAsked => Answer::NotAsked,
        })
        .collect();

    let mut plan = super::model_fusion::fuse(
        &existing_names,
        &states,
        &answer_sets,
        mode == SyncMode::AutoFirstSync,
        if mode == SyncMode::Manual { Judge::Reviewed } else { Judge::Unattended },
    )
    .map_err(|i| SyncError::Implausible { discovered: i.discovered, existing: i.existing })?;
    // The review offers removals an unattended sync ("Sync now", on the same
    // reading of the endpoints) refuses as implausible; it says so, from that
    // sync's own decision rather than a restatement of its floors.
    let unattended_refuses = mode == SyncMode::Manual
        && !plan.retire.is_empty()
        && match super::model_fusion::fuse(&existing_names, &states, &answer_sets, false, Judge::Unattended) {
            Err(_) => true,
            Ok(unattended) => plan.retire.iter().any(|name| !unattended.retire.contains(name)),
        };
    // A first answer keeps every current model assumed: not a retired one.
    for p in &mut plan.endpoints {
        if let EndpointPlan::Answered { members, .. } = p {
            members.retain(|name, kind| *kind == MemberKind::Listed || !retired.contains(name));
        }
    }

    // The fresh answers, per model name, in primary order.
    let mut fresh: BTreeMap<String, Vec<&DiscoveredModel>> = BTreeMap::new();
    for a in answers {
        if let Some(list) = a.answer.answered() {
            for d in list {
                fresh.entry(d.id.clone()).or_default().push(d);
            }
        }
    }
    let discovered: Vec<DiscoveredModel> = fresh.iter().map(|(name, ds)| fold_answers(name, ds)).collect();
    let new_models: Vec<DiscoveredModel> =
        discovered.iter().filter(|d| plan.new_models.contains(&d.id)).cloned().collect();

    // Every retired model's routes, counted in one round trip: a review may
    // offer a whole fleet.
    let by_name: HashMap<&str, &ExistingModel> = existing.iter().map(|m| (m.upstream_model.as_str(), m)).collect();
    let retiring: Vec<&ExistingModel> = plan.retire.iter().filter_map(|name| by_name.get(name.as_str()).copied()).collect();
    let ids: Vec<Uuid> = retiring.iter().map(|m| m.id).collect();
    let counts: HashMap<Uuid, (i64, i64)> = if ids.is_empty() {
        HashMap::new()
    } else {
        sqlx::query_as::<_, (Uuid, i64, i64)>(
            "SELECT model_id, COUNT(*), COUNT(*) FILTER (WHERE auto_synced = false) \
             FROM downstream_routes WHERE model_id = ANY($1) GROUP BY model_id",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(SyncError::Db)?
        .into_iter()
        .map(|(id, all, manual)| (id, (all, manual)))
        .collect()
    };
    let removed: Vec<RemovedModelInfo> = retiring
        .iter()
        .map(|m| {
            let (route_count, manual_routes) = counts.get(&m.id).copied().unwrap_or((0, 0));
            RemovedModelInfo {
                id: m.id,
                upstream_model: m.upstream_model.clone(),
                route_count,
                in_use: manual_routes > 0,
            }
        })
        .collect();

    // One report per endpoint that was asked.
    let reports: Vec<EndpointSyncReport> = answers
        .iter()
        .zip(&plan.endpoints)
        .filter(|(a, _)| !matches!(a.answer, Discovery::NotAsked))
        .map(|(a, p)| EndpointSyncReport {
            endpoint_id: a.endpoint.id,
            url: a.endpoint.url.clone(),
            answered: a.answer.answered().is_some(),
            listed: a.answer.answered().map(|l| l.len() as u32).unwrap_or(0),
            kept: match p {
                EndpointPlan::Answered { kept: Some(k), .. } => Some(k.as_str().to_string()),
                _ => None,
            },
            reason: match &a.answer {
                Discovery::Failed(e) => Some(e.message.clone()),
                Discovery::Changed => Some("the endpoint changed while it was being asked".to_string()),
                _ => None,
            },
        })
        .collect();

    let mut outcome = SyncOutcome {
        discovered: discovered.clone(),
        new_models: new_models.clone(),
        removed,
        endpoints: reports,
        unattended_refuses,
        ..Default::default()
    };
    if mode == SyncMode::Manual {
        return Ok(outcome);
    }

    // --- apply ---------------------------------------------------------------

    // 1. Add new models (catalog-COALESCE + discovered caps/pricing win).
    for d in &new_models {
        insert_discovered(conn, tenant_id, server_id, d).await?;
        outcome.added += 1;
    }
    let ids: HashMap<String, Uuid> = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT upstream_model, id FROM upstream_models WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(SyncError::Db)?
    .into_iter()
    .collect();

    // 2. What each endpoint serves now. An answering endpoint's rows are
    //    rewritten from the plan (a listed row carries what the endpoint
    //    reported, for the fold); one that did not answer keeps its rows (why
    //    it did not is already recorded, by `record_unanswered`).
    for (a, p) in answers.iter().zip(&plan.endpoints) {
        let e = &a.endpoint;
        if let (EndpointPlan::Answered { members, kept }, Discovery::Answered(list)) = (p, &a.answer) {
            let by_name: HashMap<&str, &DiscoveredModel> = list.iter().map(|d| (d.id.as_str(), d)).collect();
            let keep_ids: Vec<Uuid> = members.keys().filter_map(|n| ids.get(n).copied()).collect();
            sqlx::query("DELETE FROM upstream_model_endpoints WHERE endpoint_id = $1 AND NOT (model_id = ANY($2))")
                .bind(e.id)
                .bind(&keep_ids)
                .execute(&mut *conn)
                .await
                .map_err(SyncError::Db)?;
            for (name, kind) in members {
                let Some(model_id) = ids.get(name) else { continue };
                let reported = by_name.get(name.as_str()).filter(|_| *kind == MemberKind::Listed);
                sqlx::query(
                    "INSERT INTO upstream_model_endpoints \
                         (tenant_id, model_id, endpoint_id, server_id, kind, discovered, \
                          discovered_identity, discovered_parent, last_listed_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $5 = 'listed' THEN NOW() END) \
                     ON CONFLICT (tenant_id, model_id, endpoint_id) DO UPDATE SET \
                         kind = EXCLUDED.kind, \
                         discovered = COALESCE(EXCLUDED.discovered, upstream_model_endpoints.discovered), \
                         discovered_identity = COALESCE(EXCLUDED.discovered_identity, upstream_model_endpoints.discovered_identity), \
                         discovered_parent = COALESCE(EXCLUDED.discovered_parent, upstream_model_endpoints.discovered_parent), \
                         last_listed_at = COALESCE(EXCLUDED.last_listed_at, upstream_model_endpoints.last_listed_at)",
                )
                .bind(tenant_id)
                .bind(model_id)
                .bind(e.id)
                .bind(server_id)
                .bind(kind.as_str())
                .bind(reported.map(|d| sqlx::types::Json(reported_facts(d))))
                .bind(reported.and_then(|d| d.root.clone()))
                .bind(reported.and_then(|d| d.parent.clone()))
                .execute(&mut *conn)
                .await
                .map_err(SyncError::Db)?;
            }
            let status = serde_json::json!({
                "ok": true,
                "listed": list.len(),
                "kept": kept.map(|k| k.as_str()),
            });
            sqlx::query(
                "UPDATE upstream_server_endpoints SET listed = true, last_discovery_at = NOW(), \
                 last_answer_at = NOW(), last_discovery_status = $2 WHERE id = $1",
            )
            .bind(e.id)
            .bind(&status)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
        }
    }

    // 3. Refresh the models the answers named: folded caps and limits (from
    //    the membership rows just written, so a replica that did not answer
    //    this time still counts with what it last reported), the price from the
    //    first endpoint that published one, and a model that previously
    //    vanished and has reappeared is reinstated.
    for d in &discovered {
        if !existing_names.contains(&d.id) {
            continue;
        }
        let Some(model_id) = ids.get(&d.id) else { continue };
        let (mut folded, complete) = fold_members(conn, *model_id).await?;
        folded.id = d.id.clone();
        folded.rates = d.rates.clone();
        refresh_discovered(conn, server_id, &folded, !complete).await?;
        reinstate_if_vanished(conn, server_id, &d.id).await?;
        outcome.refreshed += 1;
    }

    // Count of refreshed models carrying operator-pinned caps (reported, not blocked).
    if !discovered.is_empty() {
        let names: Vec<String> = discovered.iter().map(|d| d.id.clone()).collect();
        outcome.skipped_overrides = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM upstream_models \
             WHERE server_id = $1 AND upstream_model = ANY($2) \
               AND COALESCE(array_length(user_overridden_caps, 1), 0) > 0",
        )
        .bind(server_id)
        .bind(&names)
        .fetch_one(&mut *conn)
        .await
        .map_err(SyncError::Db)? as u32;
    }

    // 4. Soft-retire the models the plan retires (never on a first sync).
    for r in &outcome.removed.clone() {
        let counts = retire_model_soft(conn, r.id).await?;
        outcome.routes_deleted += counts.routes_deleted;
        outcome.routes_disabled += counts.routes_disabled;
        if counts.model_removed {
            outcome.models_removed += 1;
        }
    }

    // 5. Mirror: ensure every enabled model has its auto route. Always run it
    //    (it's idempotent — only inserts missing routes) so a reinstated model,
    //    not just a freshly-added one, gets its mirror route back. No-op when the
    //    server is in manual mode; a foreign same-name downstream surfaces as a
    //    typed NameConflict (no hijack).
    super::downstream::mirror_sync_downstream(conn, server_id, &server.name, tenant_id).await?;

    Ok(outcome)
}

/// What one endpoint's answer reported for a model, as stored on its row.
fn reported_facts(d: &DiscoveredModel) -> ReportedFacts {
    let caps = [
        ("supports_vision", d.supports_vision),
        ("supports_reasoning", d.supports_reasoning),
        ("supports_function_calling", d.supports_function_calling),
        ("supports_caching", d.supports_caching),
        ("supports_audio_input", d.supports_audio_input),
        ("supports_audio_output", d.supports_audio_output),
        ("supports_video_input", d.supports_video_input),
        ("supports_pdf_input", d.supports_pdf_input),
        ("supports_response_schema", d.supports_response_schema),
        ("supports_system_messages", d.supports_system_messages),
    ];
    ReportedFacts {
        context_window: d.context_window,
        max_output_tokens: d.max_output_tokens,
        capabilities: caps.into_iter().filter_map(|(k, v)| v.map(|v| (k.to_string(), v))).collect(),
    }
}

/// The conservative fold of what several members reported for one model: the
/// smallest window and output cap any member reported; a capability `false`
/// when any member denies it, `true` when some member claims it and none
/// denies it, unknown when none reports it. A member that reports nothing
/// neither narrows nor widens — replicas of one engine report alike, and an
/// engine that publishes no capabilities (vLLM) must not erase the catalog's.
pub(crate) fn fold_facts<'a>(members: impl IntoIterator<Item = &'a ReportedFacts>) -> ReportedFacts {
    let mut out = ReportedFacts::default();
    for f in members {
        out.context_window = min_known(out.context_window, f.context_window);
        out.max_output_tokens = min_known(out.max_output_tokens, f.max_output_tokens);
        for (k, v) in &f.capabilities {
            out.capabilities
                .entry(k.clone())
                .and_modify(|cur| *cur = *cur && *v)
                .or_insert(*v);
        }
    }
    out
}

fn min_known(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// A discovered model built from folded facts.
fn discovered_from_facts(name: &str, f: &ReportedFacts) -> DiscoveredModel {
    let cap = |k: &str| f.capabilities.get(k).copied();
    DiscoveredModel {
        id: name.to_string(),
        context_window: f.context_window,
        max_output_tokens: f.max_output_tokens,
        supports_vision: cap("supports_vision"),
        supports_reasoning: cap("supports_reasoning"),
        supports_function_calling: cap("supports_function_calling"),
        supports_caching: cap("supports_caching"),
        supports_audio_input: cap("supports_audio_input"),
        supports_audio_output: cap("supports_audio_output"),
        supports_video_input: cap("supports_video_input"),
        supports_pdf_input: cap("supports_pdf_input"),
        supports_response_schema: cap("supports_response_schema"),
        supports_system_messages: cap("supports_system_messages"),
        ..Default::default()
    }
}

/// Fold this sync's answers for one model (primary order): the facts folded,
/// the price from the first answer that published one, the identity from the
/// first that reported one.
fn fold_answers(name: &str, answers: &[&DiscoveredModel]) -> DiscoveredModel {
    let facts: Vec<ReportedFacts> = answers.iter().map(|d| reported_facts(d)).collect();
    let mut out = discovered_from_facts(name, &fold_facts(&facts));
    out.rates = answers.iter().find_map(|d| d.rates.clone());
    out.root = answers.iter().find_map(|d| d.root.clone());
    out.parent = answers.iter().find_map(|d| d.parent.clone());
    out
}

/// Fold what a model's members last reported (the rows are the record — a
/// member kept after a short answer keeps what it reported before), and say
/// whether every endpoint serving it has reported: when one has not (it never
/// answered, or was re-pointed), the fold may only narrow the stored values.
async fn fold_members(conn: &mut Scoped, model_id: Uuid) -> Result<(DiscoveredModel, bool), SyncError> {
    let reported: Vec<Option<sqlx::types::Json<ReportedFacts>>> = sqlx::query_scalar(
        "SELECT discovered FROM upstream_model_endpoints WHERE model_id = $1",
    )
    .bind(model_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(SyncError::Db)?;
    let unlisted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM upstream_server_endpoints e \
                        JOIN upstream_models m ON m.server_id = e.server_id \
                        WHERE m.id = $1 AND NOT e.listed)",
    )
    .bind(model_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(SyncError::Db)?;
    let complete = !unlisted && !reported.is_empty() && reported.iter().all(Option::is_some);
    let facts: Vec<ReportedFacts> = reported.into_iter().flatten().map(|j| j.0).collect();
    Ok((discovered_from_facts("", &fold_facts(&facts)), complete))
}

/// Re-fold every model of a server from its membership rows — after an
/// operator changed what the endpoints serve (an endpoint removed or pointed at
/// another host), the advertised window and capabilities follow the members
/// that remain. A model no listed member reports on keeps its stored values.
pub(crate) async fn refold_server(conn: &mut Scoped, server_id: Uuid) -> Result<(), SyncError> {
    let models: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, upstream_model FROM upstream_models WHERE server_id = $1")
            .bind(server_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
    for (id, name) in models {
        let (mut folded, complete) = fold_members(conn, id).await?;
        folded.id = name;
        refresh_discovered(conn, server_id, &folded, !complete).await?;
    }
    Ok(())
}

/// Discover, apply in one transaction, and record the outcome on the server:
/// the shared body of "Sync now", a new server's first sync, the autosync
/// worker, and an added endpoint's first look. `mode` `None` = the worker's
/// rule ([`SyncMode::for_worker`]). On error nothing is written — the caller
/// decides whether to record the failure.
pub(crate) async fn run_sync(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    mode: Option<SyncMode>,
) -> Result<SyncOutcome, SyncError> {
    let server = load_sync_server(conn, server_id).await?.ok_or(SyncError::ServerNotFound)?;
    let mode = mode.unwrap_or_else(|| SyncMode::for_worker(server.has_synced_ok));
    // Discover OUTSIDE the transaction so the HTTP calls do not hold it open.
    let answers = discover_all(&server).await;
    record_unanswered(conn, &answers).await?;
    if let Some(e) = nobody_answered(&answers) {
        return Err(e);
    }
    let mut tx = conn.begin().await.map_err(SyncError::Db)?;
    let answers = revalidate_answers(&mut tx, server_id, answers).await?;
    let outcome = apply_sync(&mut tx, tenant_id, &server, &answers, mode).await?;
    sqlx::query(
        "UPDATE upstream_servers SET last_auto_sync_at = NOW(), last_auto_sync_status = $2 WHERE id = $1",
    )
    .bind(server_id)
    .bind(outcome.status_json())
    .execute(&mut *tx)
    .await
    .map_err(SyncError::Db)?;
    tx.commit().await.map_err(SyncError::Db)?;
    Ok(outcome)
}

/// Run one autosync pass for a single tenant: discover + mirror every upstream
/// server that is due (`auto_sync_enabled`, enabled, and past the interval).
/// Each server runs in its own transaction so one failure can't roll back
/// another's progress. On success the status row is updated; on
/// failure the transaction is rolled back and a failure status is recorded
/// OUTSIDE the rolled-back transaction (otherwise the record would vanish too).
pub async fn run_tenant_autosync(
    db: &mut crate::db::tenant::TenantConn,
    interval_hours: i64,
) {
    let tenant_id = db.tenant_uuid();
    // A provider with no models-listing endpoint is excluded: discovery cannot
    // succeed, so selecting it would log a perpetual failure status no operator
    // can see or turn off, and the gateway UI hides the toggle for the same
    // reason. The set is BOUND, not spliced, and is the same one the write-time
    // reachability probe skips — one list, so the worker and the probe can never
    // disagree about which providers publish a list. Trimmed and case-folded on
    // this side too, because the other readers are: nothing normalises
    // `provider` on the way in, so a row stored as " Perplexity " is excluded
    // by all three or the set is not one set.
    // A second exclusion — a transport with no model list — is applied below,
    // where the transport itself can be asked.
    let mut due: Vec<DueServer> = match sqlx::query_as(
        "SELECT id, name, transport FROM upstream_servers \
         WHERE auto_sync_enabled = true AND enabled = true AND NOT (lower(btrim(provider)) = ANY($2)) \
           AND (last_auto_sync_at IS NULL OR last_auto_sync_at < NOW() - make_interval(hours => $1))",
    )
    .bind(interval_hours as i32)
    .bind(super::upstreams::PROVIDERS_WITHOUT_MODELS_ENDPOINT)
    .fetch_all(db.conn())
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(tenant_id = %tenant_id, "autosync: list due servers: {e}");
            return;
        }
    };

    // A transport whose endpoint publishes no model list cannot be discovered
    // either — the same reason the provider exclusion above exists. Filtered here
    // rather than in the query so the rule stays the transport's own.
    due.retain(|s| UpstreamTransport::from_str_relaxed(&s.transport).publishes_model_list());

    for DueServer { id: server_id, name, .. } in due {
        // Until the server has had a SUCCESSFUL autosync, every pass is add-only
        // so the reconciler never disables the operator's just-configured routes
        // against an unestablished discovery baseline (first contact, or a server
        // whose discovery has only ever failed). Full reconciliation resumes once
        // a sync succeeds.
        match run_sync(db.conn(), tenant_id, server_id, None).await {
            Ok(outcome) => {
                tracing::info!(
                    server = %name, added = outcome.added, refreshed = outcome.refreshed,
                    models_removed = outcome.models_removed, "autosync applied"
                );
            }
            Err(e) => {
                let reason = e.reason();
                // The failure status MUST be written outside the rolled-back tx.
                let _ = record_sync_failure(db.conn(), server_id, &reason, true).await;
                tracing::warn!(server = %name, "autosync skipped: {reason}");
            }
        }
    }
}

/// A server the autosync worker has selected to re-discover this pass.
#[derive(sqlx::FromRow)]
struct DueServer {
    id: Uuid,
    name: String,
    /// How this server is addressed — a transport that publishes no model list
    /// is skipped.
    transport: String,
}

/// Record a failed sync on the server row. Written on the plain
/// (post-rollback) connection so it survives a rolled-back apply transaction.
///
/// Every path that discovers models owes this on failure, not only the worker:
/// a success writes the status inside `run_sync`'s own transaction, so a
/// failure that records nothing leaves the row reading exactly like a server
/// nobody has asked about yet — and the operator's only way to learn why is to
/// ask for a sync again.
///
/// The status carries its OWN `at`, because `last_auto_sync_at` answers a
/// different question: it is what the worker's due window is measured from, and
/// a path that must leave the row due therefore cannot touch it. Reading the
/// column as the failure's time would then stamp a fresh failure with the
/// previous SUCCESSFUL run's timestamp — "Failed 3 days ago" for something that
/// happened a moment ago.
///
/// Writing `ok: false` also resets `has_synced_ok`, which puts the worker's
/// NEXT pass back into add-only mode (`SyncMode::for_worker`). That is the
/// intended direction — a server whose last discovery failed has no baseline
/// worth reconciling against, so the pass adds and refreshes but retires
/// nothing — and one successful run restores it. Only a path that actually
/// attempted to discover may write this.
///
/// `mark_attempt` moves that due window. The WORKER sets it: it just ran, and
/// retrying every tick would hammer a failing upstream. Every other path leaves
/// it alone — a fresh server is immediately due by design, and an operator who
/// asked for a sync, or who added a replica, has not consumed the worker's
/// turn — so a blip there cannot hide the server from the worker for a whole
/// interval.
/// Returns the status blob it wrote, so a caller answering a request that
/// predates the write can report exactly what the row now holds rather than
/// reconstructing something close to it.
pub(crate) async fn record_sync_failure(
    conn: &mut Scoped,
    server_id: Uuid,
    reason: &str,
    mark_attempt: bool,
) -> Option<serde_json::Value> {
    // `at` is built by POSTGRES, not by this process: a success stamps
    // `last_auto_sync_at` with the database clock, one surface renders whichever
    // of the two it finds, and two clocks that drift apart make a failure date
    // from the future ("Failed in 4 minutes") or read as older than the success
    // it followed. One fact, one clock.
    match sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "UPDATE upstream_servers \
         SET last_auto_sync_at = CASE WHEN $3 THEN NOW() ELSE last_auto_sync_at END, \
             last_auto_sync_status = jsonb_build_object( \
                 'ok', false, 'reason', $2::text, 'at', to_jsonb(NOW())) \
         WHERE id = $1 \
         RETURNING last_auto_sync_status",
    )
    .bind(server_id)
    .bind(reason)
    .bind(mark_attempt)
    .fetch_optional(conn)
    .await
    {
        Ok(row) => row.flatten(),
        Err(e) => {
            tracing::error!(server_id = %server_id, "sync failure-status write: {e}");
            None
        }
    }
}

/// Insert a discovered model, letting the catalog backfill anything the provider
/// didn't advertise. Discovered (non-NULL) values win over the catalog; what
/// stays NULL resolves to the standard default at the proxy.
async fn insert_discovered(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    d: &DiscoveredModel,
) -> Result<(), SyncError> {
    // Store only what the provider advertised; NULL columns inherit live from the
    // catalog at read time (never baked in here). catalog_model_id is left NULL so
    // the row resolves via the canonical name auto-match — an explicit link is only
    // ever set by an operator picking one in the editor.
    let new_id: Option<Uuid> = sqlx::query_scalar::<_, Uuid>(
        r#"WITH cat_match AS (
               SELECT model_type
               FROM model_catalog
               WHERE model_key = canonical_catalog_key($2)
                     AND tenant_id = $3 AND NOT suppressed
                     AND (server_id IS NULL OR server_id = $1)
               -- model_type is a capability, so it takes the capability ladder:
               -- this server's own catalog row first, then its provider, then any
               -- provider, with a deterministic final tie-break.
               ORDER BY COALESCE(server_id = $1, false) DESC,
                        (provider_key
                         = canonical_provider_key((SELECT s.provider FROM upstream_servers s WHERE s.tenant_id = $3 AND s.id = $1))) DESC,
                        (model = $2) DESC,
                        model, provider_key
               LIMIT 1
           )
           INSERT INTO upstream_models (server_id, upstream_model, tenant_id, context_window, max_output_tokens, model_type,
               supports_vision, supports_reasoning, supports_function_calling, supports_caching,
               supports_audio_input, supports_audio_output, supports_video_input, supports_pdf_input,
               supports_response_schema, supports_system_messages,
               rates)
           VALUES ($1, $2, $3, $4, $5,
               COALESCE((SELECT model_type FROM cat_match), 'text'),
               $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
               $16)
           ON CONFLICT (tenant_id, server_id, upstream_model) DO NOTHING
           RETURNING id"#,
    )
    .bind(server_id)
    .bind(&d.id)
    .bind(tenant_id)
    .bind(d.context_window.map(|v| v as i32))
    .bind(d.max_output_tokens.map(|v| v as i32))
    .bind(d.supports_vision)
    .bind(d.supports_reasoning)
    .bind(d.supports_function_calling)
    .bind(d.supports_caching)
    .bind(d.supports_audio_input)
    .bind(d.supports_audio_output)
    .bind(d.supports_video_input)
    .bind(d.supports_pdf_input)
    .bind(d.supports_response_schema)
    .bind(d.supports_system_messages)
    // A provider that published no price leaves the column NULL, which inherits
    // the catalog's map; a JSON `null` would be a stored value that inherits
    // nothing.
    .bind(d.rates.as_ref().map(sqlx::types::Json))
    .fetch_optional(&mut *conn)
    .await
    .map_err(SyncError::Db)?;

    // Discovery only ever seeds the empty default preset; it NEVER authors a
    // non-default preset's settings (those are operator-owned).
    if let Some(model_id) = new_id {
        super::model_presets::ensure_default_preset(conn, tenant_id, model_id)
            .await
            .map_err(SyncError::Db)?;
    }
    Ok(())
}

/// Reinstate a model that previously vanished and has now reappeared in
/// discovery. A vanished model with hand-built routes was left disabled with its
/// routes flagged `upstream_model_vanished` (a vanished model with no manual
/// route was deleted outright, so it returns through the add path, not here).
/// We re-enable the model and clear the flag on its routes so the mirror is
/// whole again — scoped to the vanished marker so an operator's own manual
/// disable is never overridden.
async fn reinstate_if_vanished(
    conn: &mut Scoped,
    server_id: Uuid,
    model_name: &str,
) -> Result<(), SyncError> {
    let cleared = sqlx::query(
        "UPDATE downstream_routes SET enabled = true, disabled_reason = NULL \
         WHERE disabled_reason = $3 \
           AND model_id = (SELECT id FROM upstream_models WHERE server_id = $1 AND upstream_model = $2)",
    )
    .bind(server_id)
    .bind(model_name)
    .bind(DISABLED_REASON_VANISHED)
    .execute(&mut *conn)
    .await
    .map_err(SyncError::Db)?;

    // Only re-enable the model if it was disabled by the vanish path (evidenced
    // by the routes we just cleared) — never undo an operator's manual disable.
    if cleared.rows_affected() > 0 {
        sqlx::query(
            "UPDATE upstream_models SET enabled = true \
             WHERE server_id = $1 AND upstream_model = $2 AND enabled = false",
        )
        .bind(server_id)
        .bind(model_name)
        .execute(&mut *conn)
        .await
        .map_err(SyncError::Db)?;
    }
    Ok(())
}

/// Refresh a still-present model. ONE rule governs every inheritable field —
/// caps, pricing and token limits alike: the freshly discovered value wins unless
/// the operator pinned that field (`user_overridden_caps`, stamped by every path
/// on which an operator supplies a value — the model editor's PATCH and a
/// hand-added model's create, but never a discovery-sourced create, whose values
/// must keep tracking the provider). A provider that stops publishing a field keeps the last
/// known value rather than blanking it, so `COALESCE($new, existing)` is the
/// unpinned arm.
///
/// Pricing MUST follow the same rule as capabilities: a stored price and an
/// operator's price live in the same column, so "only fill NULLs" would freeze a
/// model at whatever the provider charged the day it was first discovered and
/// silently under- or over-bill every request after a repricing.
// `narrow_only`: some endpoint serving the model has no reported facts (it
// never answered, or was re-pointed), so its limits are unknown — the stored
// window and output cap may only shrink and a capability may not turn back on
// until it answers. Without it the advertised window could widen past what a
// replica in rotation serves.
async fn refresh_discovered(
    conn: &mut Scoped,
    server_id: Uuid,
    d: &DiscoveredModel,
    narrow_only: bool,
) -> Result<(), SyncError> {
    sqlx::query(
        r#"UPDATE upstream_models SET
               context_window = CASE WHEN 'context_window' = ANY(user_overridden_caps) THEN context_window WHEN $16 THEN LEAST(COALESCE($3, context_window), context_window) ELSE COALESCE($3, context_window) END,
               max_output_tokens = CASE WHEN 'max_output_tokens' = ANY(user_overridden_caps) THEN max_output_tokens WHEN $16 THEN LEAST(COALESCE($4, max_output_tokens), max_output_tokens) ELSE COALESCE($4, max_output_tokens) END,
               supports_vision = CASE WHEN 'supports_vision' = ANY(user_overridden_caps) THEN supports_vision WHEN $16 AND supports_vision = false THEN false ELSE COALESCE($5, supports_vision) END,
               supports_reasoning = CASE WHEN 'supports_reasoning' = ANY(user_overridden_caps) THEN supports_reasoning WHEN $16 AND supports_reasoning = false THEN false ELSE COALESCE($6, supports_reasoning) END,
               supports_function_calling = CASE WHEN 'supports_function_calling' = ANY(user_overridden_caps) THEN supports_function_calling WHEN $16 AND supports_function_calling = false THEN false ELSE COALESCE($7, supports_function_calling) END,
               supports_caching = CASE WHEN 'supports_caching' = ANY(user_overridden_caps) THEN supports_caching WHEN $16 AND supports_caching = false THEN false ELSE COALESCE($8, supports_caching) END,
               supports_audio_input = CASE WHEN 'supports_audio_input' = ANY(user_overridden_caps) THEN supports_audio_input WHEN $16 AND supports_audio_input = false THEN false ELSE COALESCE($9, supports_audio_input) END,
               supports_audio_output = CASE WHEN 'supports_audio_output' = ANY(user_overridden_caps) THEN supports_audio_output WHEN $16 AND supports_audio_output = false THEN false ELSE COALESCE($10, supports_audio_output) END,
               supports_video_input = CASE WHEN 'supports_video_input' = ANY(user_overridden_caps) THEN supports_video_input WHEN $16 AND supports_video_input = false THEN false ELSE COALESCE($11, supports_video_input) END,
               supports_pdf_input = CASE WHEN 'supports_pdf_input' = ANY(user_overridden_caps) THEN supports_pdf_input WHEN $16 AND supports_pdf_input = false THEN false ELSE COALESCE($12, supports_pdf_input) END,
               supports_response_schema = CASE WHEN 'supports_response_schema' = ANY(user_overridden_caps) THEN supports_response_schema WHEN $16 AND supports_response_schema = false THEN false ELSE COALESCE($13, supports_response_schema) END,
               supports_system_messages = CASE WHEN 'supports_system_messages' = ANY(user_overridden_caps) THEN supports_system_messages WHEN $16 AND supports_system_messages = false THEN false ELSE COALESCE($14, supports_system_messages) END,
               rates = CASE WHEN 'rates' = ANY(user_overridden_caps) THEN rates ELSE COALESCE($15, rates) END
           WHERE server_id = $1 AND upstream_model = $2"#,
    )
    .bind(server_id)
    .bind(&d.id)
    .bind(d.context_window.map(|v| v as i32))
    .bind(d.max_output_tokens.map(|v| v as i32))
    .bind(d.supports_vision)
    .bind(d.supports_reasoning)
    .bind(d.supports_function_calling)
    .bind(d.supports_caching)
    .bind(d.supports_audio_input)
    .bind(d.supports_audio_output)
    .bind(d.supports_video_input)
    .bind(d.supports_pdf_input)
    .bind(d.supports_response_schema)
    .bind(d.supports_system_messages)
    // NULL keeps the stored map: a provider that stops publishing prices must not
    // blank the last known ones.
    .bind(d.rates.as_ref().map(sqlx::types::Json))
    .bind(narrow_only)
    .execute(&mut *conn)
    .await
    .map_err(SyncError::Db)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(window: Option<i64>, caps: &[(&str, bool)]) -> ReportedFacts {
        ReportedFacts {
            context_window: window,
            max_output_tokens: None,
            capabilities: caps.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn the_fold_takes_the_smallest_window_any_member_reported() {
        let f = fold_facts(&[facts(Some(32_768), &[]), facts(Some(16_384), &[]), facts(None, &[])]);
        assert_eq!(f.context_window, Some(16_384));
        // A member that reports nothing neither narrows nor widens.
        assert_eq!(fold_facts(&[facts(None, &[])]).context_window, None);
    }

    #[test]
    fn a_capability_is_denied_by_any_member_and_claimed_only_without_a_denial() {
        let f = fold_facts(&[
            facts(None, &[("supports_vision", true), ("supports_reasoning", true)]),
            facts(None, &[("supports_vision", false)]),
        ]);
        assert_eq!(f.capabilities.get("supports_vision"), Some(&false));
        // Claimed by one member, denied by none: claimed.
        assert_eq!(f.capabilities.get("supports_reasoning"), Some(&true));
        // Reported by none: unknown, so the catalog's value stands.
        assert_eq!(f.capabilities.get("supports_caching"), None);
    }

    #[test]
    fn answers_fold_with_the_first_price_and_identity_in_primary_order() {
        let a = DiscoveredModel { id: "m".into(), context_window: Some(8_192), root: Some("/w/a".into()), ..Default::default() };
        let b = DiscoveredModel { id: "m".into(), context_window: Some(4_096), root: Some("/w/b".into()), ..Default::default() };
        let folded = fold_answers("m", &[&a, &b]);
        assert_eq!(folded.context_window, Some(4_096));
        assert_eq!(folded.root.as_deref(), Some("/w/a"));
    }
}

#[cfg(test)]
mod auto_sync_status_tests {
    use super::AutoSyncStatus;
    use serde_json::json;

    #[test]
    fn a_stored_failure_reads_as_a_failure_with_its_reason_and_time() {
        let s = AutoSyncStatus::from_stored(json!({"ok": false, "reason": "401", "at": "2026-10-11T19:08:49.123456+02:00"}))
            .expect("a recorded run");
        assert!(!s.ok);
        assert_eq!(s.reason.as_deref(), Some("401"));
        assert!(s.at.is_some());
    }

    #[test]
    fn a_stored_value_that_does_not_parse_is_still_a_run_and_not_a_success() {
        let s = AutoSyncStatus::from_stored(json!({"ok": false, "reason": "x", "at": "garbage"})).expect("a recorded run");
        assert!(!s.ok);
        assert_eq!(s.reason.as_deref(), Some("x"));
        let s = AutoSyncStatus::from_stored(json!({"added": "many"})).expect("a recorded run");
        assert!(!s.ok, "a status that does not say ok:true is a failure");
        let s = AutoSyncStatus::from_stored(json!({"ok": true, "added": -1})).expect("a recorded run");
        assert!(s.ok);
        assert!(AutoSyncStatus::from_stored(serde_json::Value::Null).is_none());
    }
}
