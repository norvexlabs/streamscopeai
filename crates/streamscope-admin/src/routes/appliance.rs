//! Web Appliance surface — super-admin lifecycle, backup and network control
//! for the Kairos VM appliance, bridged to the host daemon's app socket.
//!
//! Mounted under `/api/v1/admin/global/appliance/*` (super-admin-fenced +
//! audited via the global router chain). Every handler is a thin client of the
//! daemon's `/v1` API on the unix socket `STOWAGE_HOST_SOCKET`, authenticated
//! with `Authorization: Bearer $STOWAGE_HOST_TOKEN`. The daemon is the
//! privilege boundary and owns every decision; admin-api only forwards.
//!
//! **Disabled on every non-appliance shape.** `STOWAGE_HOST_SOCKET` is set only
//! on the Kairos VM; everywhere else (Kubernetes, Docker, dev) it is empty and
//! every handler short-circuits with `ApplianceUnavailable` (404) via the single
//! [`Host::from_settings`] gate. There is no other way in.
//!
//! **Errors.** A daemon refusal that describes the operator's input (400), the
//! appliance's state (409) or an action kept for the operator over SSH (403,
//! `ApplianceOperatorOnly`: a backup setting the operator locked) reaches the
//! caller with the daemon's own reason: it is our host daemon's text about the
//! operator's own appliance, not an upstream's body. A daemon that does not
//! answer (no socket, past the deadline, an answer cut short) is
//! `HostDaemonUnreachable` (502); one that refuses admin-api's token (401) is
//! `HostDaemonRefused` (502); every other failure —
//! a 5xx, an answer over the cap — is logged and answered with the sanitized
//! `HostDaemonError` (502).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Query, Request, State};
use axum::http::{Method, StatusCode};
use axum::routing::{get, post};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::AdminState;
use crate::db::tenant::{TenantConn, TenantId};
use crate::notifications::{NewNotification, NotificationKind, notify};
use crate::routes::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::settings::admin_settings;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Appliance endpoints, mounted at `/api/v1/admin/global/appliance`.
pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/status", get(get_status))
        .route("/updates", get(get_updates))
        .route("/job", get(get_job))
        .route("/events", get(get_events))
        .route("/rollback", get(get_rollback_plan))
        .route("/backup/config", get(get_backup_config).put(put_backup_config))
        .route("/backup/status", get(get_backup_status))
        .route("/backup/list", get(get_backup_list))
        .route("/actions/restart", post(action_restart))
        .route("/actions/shutdown", post(action_shutdown))
        .route("/actions/upgrade", post(action_upgrade))
        .route("/actions/rollback", post(action_rollback))
        .route("/actions/check-updates", post(action_check_updates))
        .route("/actions/backup-run", post(action_backup_run))
        .route("/actions/backup-test", post(action_backup_test))
        .route("/network", get(get_network).put(put_network))
        .route("/network/actions/confirm", post(action_network_confirm))
        .route("/network/actions/revert", post(action_network_revert))
        .route("/network/actions/reset", post(action_network_reset))
}

// ---------------------------------------------------------------------------
// Host daemon client
// ---------------------------------------------------------------------------

/// Bound on a daemon response body. The daemon is ours and its replies are
/// small JSON documents (the largest is a job log), so the cap is not a defence
/// against the daemon so much as against admin-api buffering without limit when
/// it misbehaves — the same rule every other egress read here follows.
const HOST_BODY_CAP: u64 = 16 * 1024 * 1024;

/// A daemon call's deadline. Every long operation is a job the daemon answers
/// at once (202), so a call is short.
const HOST_TIMEOUT: Duration = Duration::from_secs(90);
/// The status and the job are read from the daemon's memory and a few local
/// files — slower while an upgrade writes the disk; the console polls them, and
/// a daemon that cannot answer them this fast is shown as not answering rather
/// than leaving the page on its last reading.
const HOST_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest a caller may ask the event journal to wait for an entry; the
/// call's deadline is that wait and `HOST_READ_TIMEOUT` beyond it.
pub(crate) const EVENTS_MAX_WAIT_SECS: u32 = 25;

/// Longest daemon reason forwarded to a caller.
const HOST_REASON_CAP: usize = 2000;

/// The daemon's API is served on the socket alone: the authority in the URL is
/// never resolved, it only names the request.
const HOST_ORIGIN: &str = "http://stowage-host";


/// One appliance's host daemon: the app socket and its token.
pub(crate) struct Host {
    socket: PathBuf,
    token: String,
}

impl Host {
    /// The appliance's daemon, or `ApplianceUnavailable` when this is not an
    /// appliance deploy — the single off-switch every handler consults.
    fn from_settings() -> Result<Self, ApiError> {
        let socket = admin_settings().stowage_host_socket.clone();
        if socket.is_empty() {
            return Err(ApiError::not_found(
                "appliance management is not available on this deployment",
                ApiErrorCode::ApplianceUnavailable,
            ));
        }
        Ok(Self::at(socket, std::env::var("STOWAGE_HOST_TOKEN").unwrap_or_default()))
    }

    pub(crate) fn at(socket: impl Into<PathBuf>, token: impl Into<String>) -> Self {
        Self { socket: socket.into(), token: token.into() }
    }

    /// The error propagates rather than falling back to a default client: that
    /// fallback would drop both the socket and the timeout.
    fn client(&self, timeout: Duration) -> Result<reqwest::Client, ApiError> {
        reqwest::Client::builder()
            .unix_socket(self.socket.as_path())
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| host_err("client build", e))
    }

    async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        timeout: Duration,
    ) -> Result<T, ApiError> {
        let mut req = self
            .client(timeout)?
            .request(method, format!("{HOST_ORIGIN}{path}"))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.map_err(|e| host_unreachable(path, e))?;
        let status = resp.status();
        let bytes = streamscope_core::http_body::read_body_capped(resp, HOST_BODY_CAP)
            .await
            .map_err(|e| match e {
                streamscope_core::http_body::CappedReadError::Transport(e) => host_unreachable(path, e),
                oversized => host_err(path, oversized),
            })?;
        if !status.is_success() {
            return Err(map_host_refusal(path, status, &bytes));
        }
        serde_json::from_slice::<T>(&bytes).map_err(|e| host_decode_err(path, e))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.call::<(), T>(Method::GET, path, None, HOST_TIMEOUT).await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        self.call(Method::POST, path, Some(body), HOST_TIMEOUT).await
    }

    pub(crate) async fn status(&self) -> Result<HostStatus, ApiError> {
        self.call::<(), _>(Method::GET, "/v1/status", None, HOST_READ_TIMEOUT).await
    }

    /// The release an upgrade would install, on the install's own channel.
    pub(crate) async fn updates(&self) -> Result<ApplianceUpdates, ApiError> {
        self.get("/v1/updates").await
    }

    pub(crate) async fn upgrade(&self, req: &UpgradeRequest) -> Result<HostAccepted, ApiError> {
        self.post("/v1/upgrade", req).await.map(HostAccepted::scrubbed)
    }

    pub(crate) async fn job(&self, since: u32) -> Result<ApplianceJob, ApiError> {
        let mut j: ApplianceJob =
            self.call::<(), _>(Method::GET, &format!("/v1/job?since={since}"), None, HOST_READ_TIMEOUT).await?;
        // The daemon's own words, as every daemon reason reaches a caller.
        j.error = daemon_text(j.error);
        j.result = daemon_text(j.result);
        j.target = daemon_text(j.target);
        Ok(j)
    }

    pub(crate) async fn rollback_plan(&self) -> Result<ApplianceRollbackPlan, ApiError> {
        self.get("/v1/rollback").await
    }

    pub(crate) async fn rollback(&self, confirm: &HostVersion) -> Result<HostAccepted, ApiError> {
        self.post("/v1/rollback", &HostConfirm { confirm }).await.map(HostAccepted::scrubbed)
    }

    pub(crate) async fn reboot(&self, body: &DrainBody) -> Result<serde::de::IgnoredAny, ApiError> {
        self.post("/v1/reboot", body).await
    }

    pub(crate) async fn shutdown(&self, body: &DrainBody) -> Result<serde::de::IgnoredAny, ApiError> {
        self.post("/v1/shutdown", body).await
    }

    pub(crate) async fn backup_config(&self) -> Result<BackupConfig, ApiError> {
        self.get("/v1/backup/config").await
    }

    pub(crate) async fn set_backup_config(&self, req: &BackupConfigUpdate) -> Result<BackupConfig, ApiError> {
        self.post("/v1/backup/config", &req.on_the_wire()).await
    }

    pub(crate) async fn backup_status(&self) -> Result<HostBackupStatus, ApiError> {
        let mut s: HostBackupStatus = self.get("/v1/backup/status").await?;
        if let Some(run) = s.last.as_mut() {
            run.error = daemon_text(run.error.take());
            run.prune_error = daemon_text(run.prune_error.take());
        }
        Ok(s)
    }

    pub(crate) async fn backup_list(&self) -> Result<Vec<BackupObject>, ApiError> {
        self.get("/v1/backup/list").await
    }

    pub(crate) async fn backup(&self, req: &BackupRunRequest) -> Result<HostAccepted, ApiError> {
        self.post("/v1/backup", req).await.map(HostAccepted::scrubbed)
    }

    /// Starts a job that tries the proposed settings (`None`: the saved ones)
    /// against their destination; nothing is saved. Its result, or the
    /// destination's failure, is the job's. While the operator locked the
    /// settings the daemon tries the saved ones alone, and refuses a proposal.
    pub(crate) async fn verify_backup(&self, req: Option<&BackupConfigUpdate>) -> Result<HostAccepted, ApiError> {
        let accepted = match req {
            Some(r) => self.post("/v1/backup/verify", &r.on_the_wire()).await,
            None => self.post("/v1/backup/verify", &serde_json::json!({})).await,
        };
        accepted.map(HostAccepted::scrubbed)
    }

    /// The journal's entries after `after`, waiting up to `wait` seconds for one.
    pub(crate) async fn events(&self, after: u64, wait: u32) -> Result<ApplianceEvents, ApiError> {
        let timeout = HOST_READ_TIMEOUT + Duration::from_secs(u64::from(wait));
        let raw: HostEvents =
            self.call::<(), _>(Method::GET, &format!("/v1/events?after={after}&wait={wait}"), None, timeout).await?;
        let next = raw.next_after(after);
        Ok(ApplianceEvents {
            events: raw.events.iter().filter_map(ApplianceEvent::from_wire).collect(),
            last: raw.last,
            truncated: raw.truncated,
            next,
        })
    }

    pub(crate) async fn network(&self) -> Result<ApplianceNetwork, ApiError> {
        self.get::<HostNetwork>("/v1/network").await.map(Into::into)
    }

    pub(crate) async fn set_network(&self, req: &ApplianceNetworkUpdate) -> Result<ApplianceNetworkApplied, ApiError> {
        self.post::<_, HostNetAnswer>("/v1/network", req).await.map(Into::into)
    }

    pub(crate) async fn confirm_network(&self) -> Result<ApplianceNetworkApplied, ApiError> {
        self.post::<_, HostNetAnswer>("/v1/network/confirm", &Empty {}).await.map(Into::into)
    }

    pub(crate) async fn revert_network(&self) -> Result<ApplianceNetworkApplied, ApiError> {
        self.post::<_, HostNetAnswer>("/v1/network/revert", &Empty {}).await.map(Into::into)
    }

    pub(crate) async fn reset_network(&self) -> Result<ApplianceNetworkApplied, ApiError> {
        self.post::<_, HostNetAnswer>("/v1/network/reset", &Empty {}).await.map(Into::into)
    }
}

/// Map a daemon answer that is not forwarded — a 5xx, an answer over the cap —
/// to a sanitized `HostDaemonError` (502). The raw detail is logged, never
/// forwarded.
fn host_err(ctx: &str, detail: impl std::fmt::Display) -> ApiError {
    tracing::warn!("host daemon {ctx} failed: {detail}");
    ApiError::bad_gateway("host service is unavailable or returned an error").code(ApiErrorCode::HostDaemonError)
}

/// The daemon did not answer: no socket, a refused connection, no answer within
/// the deadline, an answer cut short. Kept apart from `host_err` (it answered,
/// with a status that is not forwarded) so the two are told apart from the
/// error alone.
fn host_unreachable(ctx: &str, detail: impl std::fmt::Display) -> ApiError {
    tracing::warn!("host daemon {ctx} did not answer: {detail}");
    ApiError::bad_gateway("host service did not answer").code(ApiErrorCode::HostDaemonUnreachable)
}

/// The daemon answered 2xx with a body that does not decode into the expected
/// type — a contract drift between the daemon and admin-api, kept apart from
/// `host_err` so it is diagnosable from the error alone.
fn host_decode_err(ctx: &str, detail: impl std::fmt::Display) -> ApiError {
    tracing::warn!("host daemon {ctx} returned an unexpected response shape: {detail}");
    ApiError::bad_gateway("host service returned an unexpected response").code(ApiErrorCode::HostDaemonBadResponse)
}

/// The daemon's error body.
#[derive(Deserialize)]
struct HostErrorBody {
    error: Option<String>,
}

/// A reason the daemon gave, as the caller may see it: NUL-free, trimmed, and at
/// most `HOST_REASON_CAP` bytes, cut on a character boundary.
fn daemon_reason(raw: &str) -> String {
    let mut r = streamscope_core::pg_text::storable_str(raw.trim()).into_owned();
    if r.len() > HOST_REASON_CAP {
        r.truncate(r.floor_char_boundary(HOST_REASON_CAP));
    }
    r
}

/// An optional daemon text, as a caller may see it (`daemon_reason`); absent
/// when nothing is left of it.
fn daemon_text(t: Option<String>) -> Option<String> {
    t.map(|t| daemon_reason(&t)).filter(|t| !t.is_empty())
}

/// Turn a daemon non-2xx into the caller's error. Pure, so the mapping is
/// testable without a daemon.
fn map_host_refusal(path: &str, status: StatusCode, body: &[u8]) -> ApiError {
    if status == StatusCode::UNAUTHORIZED {
        // admin-api's own credential, refused: a misconfiguration waiting
        // does not mend, told apart from a daemon fault. The daemon answers a
        // token it refuses with 401 alone; its 403 is an action it keeps for
        // the operator, refused with its reason below.
        tracing::error!("host daemon {path} refused admin-api's token: {status}");
        return ApiError::bad_gateway("the host service refused this console's credential")
            .code(ApiErrorCode::HostDaemonRefused);
    }
    // Each refusal's text without a daemon reason, and its error: a refusal
    // keeps its status, so the caller does not retry an action refused for its
    // input, the appliance's state or the operator's keeping as if the daemon broke.
    let (fallback, refuse): (&str, fn(String) -> ApiError) = match status {
        StatusCode::BAD_REQUEST => ("the appliance refused the request", |r| {
            ApiError::bad_request(r).code(ApiErrorCode::ApplianceRequestInvalid)
        }),
        // Not a credential's refusal: no `auth_error` type.
        StatusCode::FORBIDDEN => ("the appliance keeps this action for its operator, over SSH", |r| ApiError {
            status: StatusCode::FORBIDDEN,
            message: r,
            error_type: "invalid_request",
            code: ApiErrorCode::ApplianceOperatorOnly,
        }),
        StatusCode::CONFLICT => ("the appliance refused the action in its current state", |r| {
            ApiError::conflict(r, ApiErrorCode::ApplianceRefused)
        }),
        _ => return host_err(path, status),
    };
    let reason = serde_json::from_slice::<HostErrorBody>(body)
        .ok()
        .and_then(|b| b.error)
        .map(|r| daemon_reason(&r))
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| fallback.to_owned());
    tracing::info!("host daemon {path} refused: {status} {reason}");
    refuse(reason)
}

// ---------------------------------------------------------------------------
// Wire types shared by the daemon and the public bodies
// ---------------------------------------------------------------------------

/// A release: the project version at a package revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HostVersion {
    pub version: String,
    pub revision: i64,
}

impl std::fmt::Display for HostVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (revision {})", self.version, self.revision)
    }
}

/// A job's acceptance (`202`): what it runs, towards which release.
#[derive(Debug, Deserialize)]
pub(crate) struct HostAccepted {
    /// Absent, `null` or blank when the daemon names none.
    #[serde(default)]
    pub target: Option<String>,
}

impl HostAccepted {
    /// The target as a caller may see it (`daemon_reason`).
    fn scrubbed(self) -> Self {
        Self { target: daemon_text(self.target) }
    }

    /// The target as it reads in a sentence, after `lead`: nothing when the
    /// daemon named none.
    fn named(&self, lead: &str) -> String {
        self.target.as_deref().map(|t| format!("{lead}{t}")).unwrap_or_default()
    }
}

#[derive(Serialize)]
struct HostConfirm<'a> {
    confirm: &'a HostVersion,
}

#[derive(Serialize)]
struct Empty {}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// The persistent partition's space.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceDisk {
    pub path: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

/// The daemon's disk-pressure reading.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceDiskPressure {
    /// `none`, `soft` or `hard`; `unknown` when the disk cannot be read.
    pub level: String,
    pub used_pct: f64,
    pub soft_pct: i64,
    pub hard_pct: i64,
}

/// The last boot the health gate found unhealthy.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceFailedBoot {
    pub release: HostVersion,
    pub at: DateTime<Utc>,
    pub reason: String,
    /// Set when the gate kept the failed system because going back was refused;
    /// the reason it was refused.
    #[serde(default)]
    pub kept: Option<String>,
}

/// `GET /v1/status`.
#[derive(Debug, Deserialize)]
pub(crate) struct HostStatus {
    name: String,
    os: HostVersion,
    #[serde(default)]
    installed: Option<HostVersion>,
    #[serde(default)]
    installing: bool,
    #[serde(default)]
    install_failed: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    disk: Option<ApplianceDisk>,
    #[serde(default)]
    disk_pressure: Option<ApplianceDiskPressure>,
    #[serde(default)]
    boot: Option<String>,
    #[serde(default)]
    fallback: bool,
    #[serde(default)]
    on_trial: bool,
    #[serde(default)]
    failed_boot: Option<ApplianceFailedBoot>,
    #[serde(default)]
    reboot_pending: bool,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(default)]
    events: Option<u64>,
    #[serde(default)]
    events_error: Option<String>,
    job: String,
}

/// The appliance at a glance — the page header, its Software card and the
/// storage tiles.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplianceStatus {
    pub name: String,
    /// The release the running OS carries.
    pub os: HostVersion,
    /// The release the install runs; absent before the first install finished.
    pub installed: Option<HostVersion>,
    /// The boot's install runs: its services are coming up, or a first install
    /// finishes.
    pub installing: bool,
    /// Why the boot's install failed, as the daemon says it.
    pub install_failed: Option<String>,
    /// The release channel the appliance follows.
    pub channel: Option<String>,
    /// The system that booted: `active`, `passive` (the fallback) or `recovery`.
    pub boot: Option<String>,
    /// The appliance runs its fallback system: the last upgrade's boot failed its
    /// health gate, or a rollback chose it.
    pub fallback: bool,
    /// The boot runs an upgrade's new system, which the health gate has not
    /// judged yet: healthy, it is kept; not, the appliance goes back (or keeps
    /// it, as `failed_boot` then says).
    pub on_trial: bool,
    pub failed_boot: Option<ApplianceFailedBoot>,
    /// A reboot or power-off is scheduled.
    pub reboot_pending: bool,
    /// The kernel's id of this boot: it changes with every reboot.
    pub boot_id: Option<String>,
    /// The event journal's last entry (0 before the first): a client reads the
    /// status, then follows `…/events?after=` from here. Absent when the journal
    /// cannot be read — never a made-up 0, which would replay it all.
    pub events: Option<u64>,
    /// Why the journal cannot be read, when it cannot.
    pub events_error: Option<String>,
    /// The last job's state: `idle`, `running`, `done` or `failed`.
    pub job: String,
    pub disk: Option<ApplianceDisk>,
    pub disk_pressure: Option<ApplianceDiskPressure>,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/status", tag = "Appliance",
    responses(
        (status = 200, description = "Appliance status", body = ApplianceStatus),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_status() -> Result<Json<ApplianceStatus>, ApiError> {
    let s = Host::from_settings()?.status().await?;
    Ok(Json(ApplianceStatus {
        name: s.name,
        os: s.os,
        installed: s.installed,
        installing: s.installing,
        install_failed: daemon_text(s.install_failed),
        channel: s.channel.filter(|c| !c.is_empty()),
        boot: s.boot.filter(|b| !b.is_empty()),
        fallback: s.fallback,
        on_trial: s.on_trial,
        failed_boot: s.failed_boot.map(|mut fb| {
            fb.reason = daemon_reason(&fb.reason);
            fb.kept = daemon_text(fb.kept);
            fb
        }),
        reboot_pending: s.reboot_pending,
        boot_id: daemon_text(s.boot_id),
        events: s.events,
        events_error: daemon_text(s.events_error),
        job: s.job,
        disk: s.disk,
        disk_pressure: s.disk_pressure,
    }))
}

// ---------------------------------------------------------------------------
// Updates, upgrade, job, rollback
// ---------------------------------------------------------------------------

/// The release an upgrade would install.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceUpdates {
    pub channel: String,
    pub current: HostVersion,
    pub target: HostVersion,
    /// The target comes after the running release and may be installed.
    pub available: bool,
    /// The appliance went back from the target, and does not upgrade to it again.
    #[serde(default)]
    pub left_by_rollback: bool,
    /// The target's changelog (markdown).
    #[serde(default)]
    pub changelog: String,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/updates", tag = "Appliance",
    responses(
        (status = 200, description = "The release an upgrade would install, with its changelog", body = ApplianceUpdates),
        (status = 400, description = "The appliance follows no channel", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_updates() -> Result<Json<ApplianceUpdates>, ApiError> {
    Ok(Json(Host::from_settings()?.updates().await?))
}

/// Forwarded to `POST /v1/upgrade` as is. No channel and no version: the
/// daemon resolves the install's own channel, and `confirm` only checks what
/// it found.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpgradeRequest {
    /// The release the operator confirmed (from `GET …/updates`): the daemon
    /// refuses when the channel now offers another.
    pub confirm: HostVersion,
    /// Reboot into the new system once it is written. Otherwise the next reboot
    /// runs it.
    #[serde(default)]
    pub reboot: bool,
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/upgrade", tag = "Appliance",
    request_body = UpgradeRequest,
    responses(
        (status = 200, description = "Upgrade started (follow it on …/job)", body = ActionResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "Refused: another release is offered now, a job runs, or the appliance is not ready", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_upgrade(Json(req): Json<UpgradeRequest>) -> Result<Json<ActionResponse>, ApiError> {
    let accepted = Host::from_settings()?
        .upgrade(&req)
        .await?;
    Ok(Json(ActionResponse::ok().with_message(if req.reboot {
        format!("upgrade{} started — the appliance restarts once it is written", accepted.named(" to "))
    } else {
        format!("upgrade{} started — restart to run it once it is written", accepted.named(" to "))
    })))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct JobQuery {
    /// Count of log lines the client already holds; the answer carries the rest.
    #[serde(default)]
    pub since: u32,
}

/// The daemon's last job (an upgrade, a rollback, a backup).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceJob {
    /// When the job started: its identity, telling two jobs of one kind and
    /// target apart. Absent when none ran.
    #[serde(default)]
    pub started: Option<DateTime<Utc>>,
    #[serde(default)]
    pub kind: Option<String>,
    /// `idle` (none ran since the daemon started), `running`, `done` or `failed`.
    pub state: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// The log lines after `since`.
    #[serde(default)]
    pub log: Vec<String>,
    /// Lines the job logged in all.
    pub log_total: u32,
    /// What a job that is done found (the backup test's verdict).
    #[serde(default)]
    pub result: Option<String>,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/job", tag = "Appliance",
    params(JobQuery),
    responses(
        (status = 200, description = "The last job and its progress", body = ApplianceJob),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_job(Query(q): Query<JobQuery>) -> Result<Json<ApplianceJob>, ApiError> {
    Ok(Json(Host::from_settings()?.job(q.since).await?))
}

/// What going back would do: the release running now, and the one the fallback
/// system carries.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceRollbackPlan {
    pub from: HostVersion,
    pub to: HostVersion,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/rollback", tag = "Appliance",
    responses(
        (status = 200, description = "The release a rollback would run", body = ApplianceRollbackPlan),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "Going back is refused, with the reason", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_rollback_plan() -> Result<Json<ApplianceRollbackPlan>, ApiError> {
    Ok(Json(Host::from_settings()?.rollback_plan().await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RollbackRequest {
    /// The release the operator confirmed going back to (from `GET …/rollback`).
    pub confirm: HostVersion,
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/rollback", tag = "Appliance",
    request_body = RollbackRequest,
    responses(
        (status = 200, description = "Rollback started: the appliance reboots into the fallback system", body = ActionResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "Refused, with the reason", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_rollback(Json(req): Json<RollbackRequest>) -> Result<Json<ActionResponse>, ApiError> {
    let accepted = Host::from_settings()?.rollback(&req.confirm).await?;
    Ok(Json(ActionResponse::ok().with_message(format!(
        "rollback{} started — the appliance reboots into it",
        accepted.named(" to ")
    ))))
}

// ---------------------------------------------------------------------------
// Power
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DrainBody {
    /// Seconds the stack drains before the action fires, 0 to 600.
    #[serde(default = "default_drain")]
    pub drain_secs: u32,
}
fn default_drain() -> u32 {
    30
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/restart", tag = "Appliance",
    request_body = DrainBody,
    responses(
        (status = 200, description = "Restart scheduled", body = ActionResponse),
        (status = 400, description = "Drain out of range", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "A job runs or a reboot is scheduled", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_restart(Json(body): Json<DrainBody>) -> Result<Json<ActionResponse>, ApiError> {
    Host::from_settings()?.reboot(&body).await?;
    Ok(Json(ActionResponse::ok().with_message("restart scheduled")))
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/shutdown", tag = "Appliance",
    request_body = DrainBody,
    responses(
        (status = 200, description = "Shutdown scheduled", body = ActionResponse),
        (status = 400, description = "Drain out of range", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "A job runs or a reboot is scheduled", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_shutdown(Json(body): Json<DrainBody>) -> Result<Json<ActionResponse>, ApiError> {
    Host::from_settings()?.shutdown(&body).await?;
    Ok(Json(ActionResponse::ok().with_message("power-off scheduled")))
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

/// Who saved the rclone config, as the daemon knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RcloneConfigFrom {
    /// The operator, over SSH: backups run with it.
    Operator,
    /// Not known to be the operator's (saved before the daemon kept that, or
    /// edited on the host): nothing runs with it until the operator saves one
    /// over SSH. A value the daemon reports that this build does not know
    /// reads as this one: shown as not run, never as the operator's.
    #[serde(other)]
    Unknown,
}

/// The backup settings, the rclone config's secrets left out.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupConfig {
    /// Settings were saved; otherwise the rest are the defaults.
    pub configured: bool,
    /// Where backups go: an rclone remote and a path in it.
    #[serde(default)]
    pub destination: Option<String>,
    /// An rclone config is saved. It is never returned.
    pub rclone_config_set: bool,
    /// Who saved it; absent when none is saved.
    #[serde(default)]
    pub rclone_config_from: Option<RcloneConfigFrom>,
    /// The age public keys a backup is encrypted to.
    #[serde(default)]
    pub recipients: Vec<String>,
    /// A backup older than this is deleted after a backup; 0 keeps every one.
    pub retention_days: i64,
    /// The schedule, as a systemd calendar event.
    pub schedule: String,
    /// The profile a scheduled backup takes.
    pub profile: String,
    /// The profiles the release declares.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// The operator locked the settings over SSH: a save, or a test of settings
    /// other than the saved ones, is refused (403 `appliance_operator_only`);
    /// they are still read, tested as saved and run. A daemon that does not
    /// lock them omits it: false.
    #[serde(default)]
    pub locked: bool,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/backup/config", tag = "Appliance",
    responses(
        (status = 200, description = "Backup settings (credentials masked)", body = BackupConfig),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_backup_config() -> Result<Json<BackupConfig>, ApiError> {
    Ok(Json(Host::from_settings()?.backup_config().await?))
}

/// Backup settings to save, or to test, over the saved rclone config. That
/// config (the remotes and their credentials) is the operator's, set over SSH:
/// rclone runs programs its options name, as root on the host, so the daemon
/// refuses one from the console. A field this body does not name, an
/// `rclone_config` included, is refused (422), never dropped: a credential
/// change must not answer as saved.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupConfigUpdate {
    /// `remote:path`, the remote one the operator's rclone config defines.
    pub destination: String,
    /// age public keys to encrypt to; any one's private key decrypts a backup.
    pub recipients: Vec<String>,
    pub retention_days: i64,
    pub schedule: String,
    pub profile: String,
}

/// `POST /v1/backup/config` and `/v1/backup/verify` with settings: every one
/// the console edits; the daemon keeps the saved rclone config.
#[derive(Debug, Serialize)]
pub(crate) struct HostBackupConfigRequest<'a> {
    destination: &'a str,
    recipients: &'a [String],
    retention_days: i64,
    schedule: &'a str,
    profile: &'a str,
}

impl BackupConfigUpdate {
    fn on_the_wire(&self) -> HostBackupConfigRequest<'_> {
        HostBackupConfigRequest {
            destination: &self.destination,
            recipients: &self.recipients,
            retention_days: self.retention_days,
            schedule: &self.schedule,
            profile: &self.profile,
        }
    }
}

#[utoipa::path(
    put, path = "/api/v1/admin/global/appliance/backup/config", tag = "Appliance",
    request_body = BackupConfigUpdate,
    responses(
        (status = 200, description = "Saved; the settings as they now stand", body = BackupConfig),
        (status = 400, description = "Settings refused, with the reason", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 403, description = "Refused: the operator locked the settings, with the reason", body = ApiErrorResponse),
        (status = 422, description = "A body that is not the settings (an unknown field, `rclone_config` included)", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn put_backup_config(Json(body): Json<BackupConfigUpdate>) -> Result<Json<BackupConfig>, ApiError> {
    Ok(Json(Host::from_settings()?.set_backup_config(&body).await?))
}

/// A backup that ran.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupRun {
    pub object: String,
    pub profile: String,
    pub release: HostVersion,
    pub started: DateTime<Utc>,
    pub finished: DateTime<Utc>,
    #[serde(default)]
    pub bytes: i64,
    /// Why it failed; absent when it succeeded.
    #[serde(default)]
    pub error: Option<String>,
    /// Why pruning older backups failed, after a backup that succeeded.
    #[serde(default)]
    pub prune_error: Option<String>,
}

/// `GET /v1/backup/status`; its `settings` are `GET …/backup/config`'s.
#[derive(Debug, Deserialize)]
pub(crate) struct HostBackupStatus {
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    running: bool,
    #[serde(default)]
    last: Option<BackupRun>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BackupStatus {
    /// The schedule's next run, as systemd prints it.
    pub next: Option<String>,
    pub running: bool,
    /// The last backup, whether it succeeded or not.
    pub last: Option<BackupRun>,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/backup/status", tag = "Appliance",
    responses(
        (status = 200, description = "The last backup and the next one", body = BackupStatus),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_backup_status() -> Result<Json<BackupStatus>, ApiError> {
    let s = Host::from_settings()?.backup_status().await?;
    Ok(Json(BackupStatus { next: s.next.filter(|n| !n.is_empty()), running: s.running, last: s.last }))
}

/// One backup in the destination.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupObject {
    pub name: String,
    pub size: i64,
    pub time: DateTime<Utc>,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/backup/list", tag = "Appliance",
    params(PageQuery),
    responses(
        (status = 200, description = "The destination's backups, newest first", body = OffsetPage<BackupObject>),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "No backup is configured", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_backup_list(Query(page): Query<PageQuery>) -> Result<Json<OffsetPage<BackupObject>>, ApiError> {
    let (limit, offset) = page.resolve();
    let mut all = Host::from_settings()?.backup_list().await?;
    all.sort_by(|a, b| b.time.cmp(&a.time).then_with(|| a.name.cmp(&b.name)));
    let rows: Vec<_> = all.into_iter().skip(offset as usize).take(limit as usize + 1).collect();
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupRunRequest {
    /// The profile to take; absent takes the settings' profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/backup-run", tag = "Appliance",
    request_body(content = Option<BackupRunRequest>, description = "Optional: without a body the settings' profile is taken"),
    responses(
        (status = 200, description = "Backup started", body = ActionResponse),
        (status = 400, description = "Unknown profile, or malformed JSON", body = ApiErrorResponse),
        (status = 415, description = "A body without a JSON Content-Type", body = ApiErrorResponse),
        (status = 422, description = "A body that is not the request (an unknown field included)", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "No backup is configured, or a job runs", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_backup_run(OptionalJson(body): OptionalJson<BackupRunRequest>) -> Result<Json<ActionResponse>, ApiError> {
    let body = body.unwrap_or(BackupRunRequest { profile: None });
    let accepted = Host::from_settings()?.backup(&body).await?;
    Ok(Json(ActionResponse::ok().with_message(format!("backup{} started", accepted.named(" ")))))
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/backup-test", tag = "Appliance",
    request_body(content = Option<BackupConfigUpdate>, description = "Optional: the settings to try; without a body the saved ones are tried"),
    responses(
        (status = 200, description = "The test started as a job: its result, or the destination's failure, is the job's (…/job, …/events); nothing is saved", body = ActionResponse),
        (status = 400, description = "Settings refused, with the reason, or malformed JSON", body = ApiErrorResponse),
        (status = 403, description = "Refused: the operator locked the settings, so only the saved ones are tried", body = ApiErrorResponse),
        (status = 415, description = "A body without a JSON Content-Type", body = ApiErrorResponse),
        (status = 422, description = "A body that is not the settings (an unknown field, `rclone_config` included)", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "A job runs or a reboot is scheduled", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_backup_test(OptionalJson(body): OptionalJson<BackupConfigUpdate>) -> Result<Json<ActionResponse>, ApiError> {
    let accepted = Host::from_settings()?.verify_backup(body.as_ref()).await?;
    Ok(Json(ActionResponse::ok().with_message(format!("testing the destination{}", accepted.named(" ")))))
}

/// An optional JSON body: an empty one is none; any other is read by `Json`,
/// so it needs a JSON Content-Type (else 415), well-formed JSON (else 400) and
/// the request's fields alone (else 422), as on every other route. `Option<Json<_>>` instead reads a body sent
/// without a Content-Type as none, taking a proposal for "the saved ones".
pub(crate) struct OptionalJson<T>(pub Option<T>);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for OptionalJson<T> {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let bytes = Bytes::from_request(Request::from_parts(parts.clone(), body), state)
            .await
            .map_err(IntoResponse::into_response)?;
        if bytes.trim_ascii().is_empty() {
            return Ok(Self(None));
        }
        let Json(v) = Json::<Option<T>>::from_request(Request::from_parts(parts, Body::from(bytes)), state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self(v))
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// One entry of the daemon's event journal: what happened to the appliance, as
/// the daemon (and its health gate) wrote it — a job started, ended or lost, a
/// reboot scheduled or cancelled, a boot started or judged, the install
/// finished or failed. One shape for every kind; a field a kind does not carry
/// is absent.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceEvent {
    /// Its number, increasing for the journal's life.
    pub seq: u64,
    pub at: DateTime<Utc>,
    /// `job.started`, `job.ended`, `job.lost`, `reboot.scheduled`,
    /// `reboot.cancelled`, `boot.started`, `boot.judged`, `install.finished`,
    /// `install.failed`, `backup.config` (a backup setting this console
    /// changed); a kind a newer daemon adds passes through.
    pub kind: String,
    /// The job, by its start (the job's `started`).
    #[serde(default)]
    pub job: Option<DateTime<Utc>>,
    #[serde(default)]
    pub job_kind: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    /// A job that ended: `done` or `failed`.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// What a job that ended done found (the backup test's verdict).
    #[serde(default)]
    pub result: Option<String>,
    /// Why: a job lost, a reboot cancelled, a boot judged, an install failed;
    /// for `backup.config`, the settings this console changed.
    #[serde(default)]
    pub reason: Option<String>,
    /// `reboot` or `poweroff`.
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub drain_secs: Option<u32>,
    /// The job that scheduled the reboot; absent when it was asked for directly.
    #[serde(default)]
    pub by: Option<DateTime<Utc>>,
    #[serde(default)]
    pub boot_id: Option<String>,
    #[serde(default)]
    pub release: Option<HostVersion>,
    /// The system that booted: `active`, `passive` or `recovery`.
    #[serde(default)]
    pub slot: Option<String>,
    #[serde(default)]
    pub fallback: Option<bool>,
    /// A judged boot ran an upgrade's new system on trial.
    #[serde(default)]
    pub on_trial: Option<bool>,
    /// A job that ended done: the reboot (or power-off) it scheduled, journaled
    /// before it runs; absent when the job schedules none.
    #[serde(default)]
    pub reboot: Option<ApplianceEventReboot>,
    /// A judged boot: `healthy`, `went_back` or `kept_unhealthy`.
    #[serde(default)]
    pub verdict: Option<String>,
    /// Why a boot found unhealthy keeps running.
    #[serde(default)]
    pub kept: Option<String>,
}

/// `GET /v1/events`, each entry decoded on its own: one entry a newer daemon
/// shapes differently must not fail the answer, or the cursor never moves
/// past it.
#[derive(Debug, Deserialize)]
pub(crate) struct HostEvents {
    events: Vec<serde_json::Value>,
    last: u64,
    /// Every entry up to it is gone.
    #[serde(default)]
    dropped: u64,
    #[serde(default)]
    truncated: bool,
}

impl HostEvents {
    /// The number to ask after next, by the daemon's client rule: past the last
    /// entry answered — read off each entry's `seq`, whether the rest decodes or
    /// not, so one entry this side cannot read is still passed — and, when none
    /// was, from the floor of a truncated answer (from 0 when the journal started
    /// again below `after`).
    fn next_after(&self, after: u64) -> u64 {
        // A journal that started again below the cursor is followed from its
        // start: every number it answers is behind `after`.
        let from = if self.truncated && after > self.last { 0 } else { after };
        let seq = |e: &serde_json::Value| e.get("seq").and_then(serde_json::Value::as_u64);
        // Past the highest number answered — never past entries a capped answer
        // left out. An answer with no readable number at all is passed whole
        // only when it is not full (a full one may have left readable entries
        // out); a full one is asked for again, its entries said unreadable.
        if !self.events.is_empty() && self.events.iter().all(|e| seq(e).is_none()) {
            return if self.events.len() < HOST_EVENTS_ANSWER_CAP { self.last.max(from) } else { from };
        }
        match self.events.iter().filter_map(seq).max() {
            Some(seq) => seq.max(from),
            None if self.truncated => from.max(self.dropped),
            None => after,
        }
    }
}

/// The most entries the daemon answers at once.
const HOST_EVENTS_ANSWER_CAP: usize = 200;

/// What every entry carries.
#[derive(Debug, Deserialize)]
struct HostEventHead {
    seq: u64,
    at: DateTime<Utc>,
    kind: String,
}

impl ApplianceEvent {
    /// The entry, field by field: a field whose shape this side does not know is
    /// absent, never the reason the rest is lost — a failed job's `state` and
    /// `error` survive a changed `reboot`. `None` only for an entry without a
    /// number, time and kind, which is logged.
    fn from_wire(raw: &serde_json::Value) -> Option<Self> {
        let head = match HostEventHead::deserialize(raw) {
            Ok(h) => h,
            Err(e) => {
                // Nothing is passed over silently: an entry with a number but no
                // readable time or kind reaches the caller as `unreadable`.
                let seq = raw.get("seq").and_then(serde_json::Value::as_u64)?;
                tracing::warn!("host daemon event {seq} has no readable time or kind: {e}");
                HostEventHead { seq, at: Utc::now(), kind: "unreadable".to_owned() }
            }
        };
        fn field<T: DeserializeOwned>(raw: &serde_json::Value, name: &str) -> Option<T> {
            let v = raw.get(name)?;
            match T::deserialize(v) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!("host daemon event field `{name}` of an unknown shape left out: {e}");
                    None
                }
            }
        }
        Some(Self {
            seq: head.seq,
            at: head.at,
            kind: head.kind,
            job: field(raw, "job"),
            job_kind: field(raw, "job_kind"),
            target: daemon_text(field(raw, "target")),
            state: field(raw, "state"),
            // The daemon's own words, as every daemon reason reaches a caller.
            error: daemon_text(field(raw, "error")),
            result: daemon_text(field(raw, "result")),
            reason: daemon_text(field(raw, "reason")),
            action: field(raw, "action"),
            drain_secs: field(raw, "drain_secs"),
            by: field(raw, "by"),
            boot_id: daemon_text(field(raw, "boot_id")),
            release: field(raw, "release"),
            slot: field(raw, "slot"),
            fallback: field(raw, "fallback"),
            on_trial: field(raw, "on_trial"),
            reboot: field(raw, "reboot"),
            verdict: field(raw, "verdict"),
            kept: daemon_text(field(raw, "kept")),
        })
    }
}

/// The reboot a job scheduled as its last step.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceEventReboot {
    /// `reboot` or `poweroff`.
    pub action: String,
    pub drain_secs: u32,
}

/// The journal's entries after a number — a cursor feed, not a page: the
/// client asks again after `next`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceEvents {
    /// Oldest first; at most a few hundred.
    pub events: Vec<ApplianceEvent>,
    /// The journal's last entry. An answer is capped: ask again after `next`,
    /// not after this.
    pub last: u64,
    /// The journal no longer holds the entry after `after` — entries were
    /// dropped, or the journal started again below it; `next` already accounts
    /// for it, and the entries still held after it are in `events`.
    pub truncated: bool,
    /// The number to ask after next: past every entry answered (one this side
    /// cannot read included), or the floor of a truncated answer.
    pub next: u64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    /// The last entry the client holds: the status's `events` at first, then
    /// each answer's `next`.
    #[serde(default)]
    pub after: u64,
    /// Seconds to wait for an entry when there is none yet (a long poll), at
    /// most 25.
    #[serde(default)]
    pub wait: u32,
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/events", tag = "Appliance",
    params(EventsQuery),
    responses(
        (status = 200, description = "The journal's entries after `after`", body = ApplianceEvents),
        (status = 400, description = "`wait` out of range", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_events(Query(q): Query<EventsQuery>) -> Result<Json<ApplianceEvents>, ApiError> {
    if q.wait > EVENTS_MAX_WAIT_SECS {
        return Err(ApiError::bad_request(format!("wait is at most {EVENTS_MAX_WAIT_SECS} seconds"))
            .code(ApiErrorCode::ValidationFailed));
    }
    Ok(Json(Host::from_settings()?.events(q.after, q.wait).await?))
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------
//
// The appliance's own addressing, editable after install. The daemon owns the
// decision (validation, precedence, the auto-revert window); its 400 names the
// field that was wrong and its 409 the change in the way.

/// What sets the appliance's addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplianceNetworkSource {
    /// An override set here or with the appliance CLI.
    Override,
    /// The network given at install, DHCP or static (`install` says which).
    Install,
    /// Neither — the operating system's default, a DHCP lease.
    Dhcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplianceNetworkMode {
    Dhcp,
    Static,
}

/// The network the appliance runs, as the kernel and the resolver report it —
/// never read from a config file.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceNetworkLive {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    /// The interface's global IPv4 and IPv6 addresses, with their prefix.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The IPv4 default route's gateway.
    #[serde(default)]
    pub gateway: Option<String>,
    /// The IPv6 default routes' gateways, static or advertised (a router each).
    #[serde(default)]
    pub gateways6: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

/// Network settings. `address` (IPv4, with its prefix, `192.168.1.50/24`) and
/// `gateway` are static only; `ipv6` turns IPv6 on in either mode (off, the
/// link has none), with an optional static `address6` beside the advertised
/// ones and its `gateway6`; `dns` replaces the lease's resolvers.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceNetworkConfig {
    pub mode: ApplianceNetworkMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway6: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

/// A change awaiting confirmation: past `deadline`, `previous` comes back
/// (absent: the install-time settings).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceNetworkPending {
    #[serde(default)]
    pub previous: Option<ApplianceNetworkConfig>,
    pub deadline: DateTime<Utc>,
    pub secs_left: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApplianceNetwork {
    pub live: ApplianceNetworkLive,
    pub source: ApplianceNetworkSource,
    /// The override set here; absent when none is.
    pub override_config: Option<ApplianceNetworkConfig>,
    /// The network given at install, which **Reset to install settings**
    /// returns to; absent on an appliance whose install did not record it.
    pub install_config: Option<ApplianceNetworkConfig>,
    pub pending: Option<ApplianceNetworkPending>,
}

/// The daemon names the override `override`, a reserved word in Rust and a poor
/// field name in a generated client; the public body renames it here.
#[derive(Debug, Deserialize)]
pub(crate) struct HostNetwork {
    live: ApplianceNetworkLive,
    source: ApplianceNetworkSource,
    #[serde(rename = "override", default)]
    override_config: Option<ApplianceNetworkConfig>,
    #[serde(rename = "install", default)]
    install_config: Option<ApplianceNetworkConfig>,
    #[serde(default)]
    pending: Option<ApplianceNetworkPending>,
}

impl From<HostNetwork> for ApplianceNetwork {
    fn from(d: HostNetwork) -> Self {
        Self {
            live: d.live,
            source: d.source,
            override_config: d.override_config,
            install_config: d.install_config,
            pending: d.pending,
        }
    }
}

/// The new settings. Optional fields are omitted on the wire when absent: the
/// daemon decodes strictly, and an omitted `revert_secs` takes its default.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApplianceNetworkUpdate {
    pub mode: ApplianceNetworkMode,
    /// Static only. The IPv4 address with its prefix: `192.168.1.50/24`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Static only. Inside the address's own subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IPv6 on, in either mode: router advertisements (and DHCPv6 with
    /// `dhcp`) address the link. Off, the appliance has no IPv6. Required: a
    /// change states IPv6 whole, so a body without it is refused rather than
    /// read as off.
    pub ipv6: bool,
    /// A static IPv6 address with its prefix, beside the advertised ones;
    /// needs `ipv6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address6: Option<String>,
    /// The IPv6 gateway (link-local, or in `address6`'s subnet); needs
    /// `address6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway6: Option<String>,
    /// Resolvers, in preference order; empty keeps the lease's own.
    #[serde(default)]
    pub dns: Vec<String>,
    /// Seconds an addressing change has to be confirmed in before it is undone:
    /// default 90, `0` for none, else 30 to 3600. A resolver-only change arms
    /// nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_secs: Option<u32>,
}

/// A network change's outcome.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApplianceNetworkApplied {
    pub message: String,
    pub override_config: Option<ApplianceNetworkConfig>,
    pub pending: Option<ApplianceNetworkPending>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HostNetAnswer {
    /// Absent, `null` or blank when the daemon says nothing.
    #[serde(default)]
    message: Option<String>,
    #[serde(rename = "override", default)]
    override_config: Option<ApplianceNetworkConfig>,
    #[serde(default)]
    pending: Option<ApplianceNetworkPending>,
}

impl From<HostNetAnswer> for ApplianceNetworkApplied {
    fn from(a: HostNetAnswer) -> Self {
        // A blank answer claims nothing: the page shows what the network now is.
        let message = daemon_text(a.message).unwrap_or_else(|| "the appliance answered without a message".to_owned());
        Self { message, override_config: a.override_config, pending: a.pending }
    }
}

#[utoipa::path(
    get, path = "/api/v1/admin/global/appliance/network", tag = "Appliance",
    responses(
        (status = 200, description = "Current network settings", body = ApplianceNetwork),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn get_network() -> Result<Json<ApplianceNetwork>, ApiError> {
    Ok(Json(Host::from_settings()?.network().await?))
}

/// The override as it stands, for the audit row's before/after. Best-effort: a
/// failed read must not stop the operator fixing the network, which is often
/// exactly why they are here.
async fn current_override(host: &Host) -> Option<ApplianceNetworkConfig> {
    host.network().await.ok().and_then(|n| n.override_config)
}

#[utoipa::path(
    put, path = "/api/v1/admin/global/appliance/network", tag = "Appliance",
    request_body = ApplianceNetworkUpdate,
    responses(
        (status = 200, description = "Applied", body = ApplianceNetworkApplied),
        (status = 400, description = "Invalid settings, with the field", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "A previous change awaits confirmation, or a reboot is scheduled", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn put_network(
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<ApplianceNetworkUpdate>,
) -> Result<Json<ApplianceNetworkApplied>, ApiError> {
    let host = Host::from_settings()?;
    let before = current_override(&host).await;
    let applied = host.set_network(&body).await?;
    audit_sink.record(before.as_ref(), applied.override_config.as_ref());
    Ok(Json(applied))
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/network/actions/confirm", tag = "Appliance",
    responses(
        (status = 200, description = "Confirmed — the auto-revert is disarmed", body = ActionResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "Nothing awaits confirmation, or its window ended", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_network_confirm() -> Result<Json<ActionResponse>, ApiError> {
    let a = Host::from_settings()?.confirm_network().await?;
    Ok(Json(ActionResponse::ok().with_message(a.message)))
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/network/actions/revert", tag = "Appliance",
    responses(
        (status = 200, description = "Back to the settings before the change", body = ActionResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "No change awaits confirmation", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_network_revert(
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let host = Host::from_settings()?;
    let before = current_override(&host).await;
    let a = host.revert_network().await?;
    audit_sink.record(before.as_ref(), a.override_config.as_ref());
    Ok(Json(ActionResponse::ok().with_message(a.message)))
}

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/network/actions/reset", tag = "Appliance",
    responses(
        (status = 200, description = "Override dropped — the install-time settings are back", body = ActionResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 409, description = "A change awaits confirmation, or a reboot is scheduled", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_network_reset(
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let host = Host::from_settings()?;
    let before = current_override(&host).await;
    let a = host.reset_network().await?;
    audit_sink.record(before.as_ref(), a.override_config.as_ref());
    Ok(Json(ActionResponse::ok().with_message(a.message)))
}

// ---------------------------------------------------------------------------
// Update check + notification
// ---------------------------------------------------------------------------

#[utoipa::path(
    post, path = "/api/v1/admin/global/appliance/actions/check-updates", tag = "Appliance",
    responses(
        (status = 200, description = "Update check ran", body = ApplianceUpdates),
        (status = 400, description = "The appliance follows no channel", body = ApiErrorResponse),
        (status = 404, description = "Not an appliance deployment", body = ApiErrorResponse),
        (status = 502, description = "Host daemon error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub(crate) async fn action_check_updates(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<ApplianceUpdates>, ApiError> {
    let updates = Host::from_settings()?.updates().await?;
    // Best-effort: a notification failure never fails the check.
    if updates.available
        && let Err(e) = raise_upgrade_notification(&state.db, &updates.target).await
    {
        tracing::warn!("appliance upgrade notification failed: {e}");
    }
    Ok(Json(updates))
}

/// Worker entry: ask the host daemon for an available upgrade and, if one is
/// offered, raise the deduped notification. An error on any non-appliance shape
/// (`STOWAGE_HOST_SOCKET` unset); errors are returned for the caller to log —
/// never fatal.
pub async fn check_upgrade_and_notify(pool: &crate::db::Db) -> Result<bool, ApiError> {
    let updates = Host::from_settings()?.updates().await?;
    if !updates.available {
        return Ok(false);
    }
    raise_upgrade_notification(pool, &updates.target)
        .await
        .map_err(|e| host_err("upgrade-notify", e))
}

/// Raise the deduped `ApplianceUpgradeAvailable` notification under the SYSTEM
/// tenant. Shared by the force-check action and the periodic worker.
pub async fn raise_upgrade_notification(pool: &crate::db::Db, target: &HostVersion) -> Result<bool, sqlx::Error> {
    // The daemon's text lands in `text` / `jsonb` columns, which refuse U+0000.
    let label = target.to_string();
    let label = &*streamscope_core::pg_text::storable_str(&label);
    let mut db = TenantConn::acquire(pool, TenantId::SYSTEM).await?;
    notify(
        db.conn(),
        TenantId::SYSTEM.as_uuid(),
        NewNotification {
            workspace_id: None,
            kind: NotificationKind::ApplianceUpgradeAvailable,
            dedup_key: format!("appliance_upgrade:{label}"),
            title: format!("Appliance update available: {label}"),
            summary: "A newer Streamscope release is available. Open the Appliance page to review and upgrade."
                .to_string(),
            target_kind: Some("appliance"),
            target_id: None,
            payload: serde_json::json!({ "target_version": label }),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    //! The daemon's wire, held at the lowest level that can see it: a fake of
    //! the app socket's `/v1` API, in process, on a real unix socket. Each case
    //! asserts what admin-api sends (method, path, bearer, body) and decodes a
    //! reply shaped as the daemon's own structs encode it.

    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    const TOKEN: &str = "host-token-for-tests";

    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        uri: String,
        auth: Option<String>,
        body: serde_json::Value,
    }

    type Replies = Vec<(&'static str, &'static str, u16, serde_json::Value)>;

    struct Fake {
        host: Host,
        seen: Arc<Mutex<Vec<Seen>>>,
        socket: PathBuf,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    impl Fake {
        fn only(&self) -> Seen {
            let seen = self.seen.lock().expect("lock");
            assert_eq!(seen.len(), 1, "one request expected, got {seen:?}");
            seen[0].clone()
        }
    }

    /// Serve `replies` — `(method, path with query, status, body)` — on a fresh
    /// socket. Anything else answers 404, as the daemon's mux does.
    async fn fake(replies: Replies) -> Fake {
        static N: AtomicU32 = AtomicU32::new(0);
        let socket = std::env::temp_dir().join(format!(
            "ss-host-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the fake socket");
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = seen.clone();
        let replies = Arc::new(replies);
        let app = Router::new().fallback(move |req: axum::extract::Request| {
            let log = log.clone();
            let replies = replies.clone();
            async move {
                let method = req.method().to_string();
                let uri = req.uri().to_string();
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let bytes = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap_or_default();
                let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
                log.lock().expect("lock").push(Seen { method: method.clone(), uri: uri.clone(), auth, body });
                let (status, reply) = replies
                    .iter()
                    .find(|(m, p, _, _)| *m == method && *p == uri)
                    .map(|(_, _, s, b)| (*s, b.clone()))
                    .unwrap_or((404, serde_json::json!({"error": "404 page not found"})));
                (StatusCode::from_u16(status).expect("status"), Json(reply))
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Fake { host: Host::at(&socket, TOKEN), seen, socket }
    }

    fn assert_sent(seen: &Seen, method: &str, uri: &str, body: serde_json::Value) {
        assert_eq!(seen.method, method);
        assert_eq!(seen.uri, uri);
        assert_eq!(seen.auth.as_deref(), Some(format!("Bearer {TOKEN}").as_str()));
        assert_eq!(seen.body, body, "{method} {uri}");
    }

    fn v(version: &str, revision: i64) -> HostVersion {
        HostVersion { version: version.into(), revision }
    }

    #[tokio::test]
    async fn status_decodes_the_daemons_status() {
        let f = fake(vec![(
            "GET",
            "/v1/status",
            200,
            serde_json::json!({
                "name": "streamscope", "os": {"version": "2026.10.50", "revision": 1},
                "installed": {"version": "2026.10.50", "revision": 1}, "channel": "stable",
                "installing": true, "install_failed": "the provision hook failed",
                "disk": {"path": "/usr/local", "total_bytes": 100, "available_bytes": 40, "used_bytes": 60},
                "disk_pressure": {"level": "none", "used_pct": 60.0, "soft_pct": 75, "hard_pct": 90,
                                  "last_post": {"at": "2026-10-14T10:00:00Z", "level": "soft", "used_pct": 76.0, "result": "200", "ok": true}},
                "boot": "passive", "fallback": true, "on_trial": true,
                "failed_boot": {"release": {"version": "2026.10.51", "revision": 2}, "at": "2026-10-14T09:00:00.123Z",
                                "reason": "not ready", "kept": "barrier", "dir": "/usr/local/x"},
                "reboot_pending": false, "boot_id": "6f1c2d3e", "events": 41, "job": "idle"
            }),
        )])
        .await;
        let s = f.host.status().await.expect("status");
        assert_sent(&f.only(), "GET", "/v1/status", serde_json::Value::Null);
        assert_eq!(s.os, v("2026.10.50", 1));
        assert_eq!(s.installed, Some(v("2026.10.50", 1)));
        assert_eq!(s.channel.as_deref(), Some("stable"));
        assert_eq!(s.disk.as_ref().map(|d| d.used_bytes), Some(60));
        assert_eq!(s.disk_pressure.as_ref().map(|p| p.hard_pct), Some(90));
        assert!(s.fallback && s.on_trial && s.installing);
        assert_eq!(s.install_failed.as_deref(), Some("the provision hook failed"));
        let fb = s.failed_boot.expect("failed boot");
        assert_eq!(fb.release, v("2026.10.51", 2));
        assert_eq!(fb.kept.as_deref(), Some("barrier"));
        assert_eq!(s.job, "idle");
        assert_eq!(s.boot_id.as_deref(), Some("6f1c2d3e"));
        assert_eq!((s.events, s.events_error.as_deref()), (Some(41), None));
    }

    #[test]
    fn a_daemon_reason_is_scrubbed_and_capped() {
        let r = daemon_reason("  lock: busy\0 ");
        assert!(r.starts_with("lock: busy") && !r.contains('\0'), "{r:?}");
        let long = "é".repeat(HOST_REASON_CAP);
        let cut = daemon_reason(&long);
        assert!(cut.len() <= HOST_REASON_CAP && cut.chars().all(|c| c == 'é'));
    }

    #[tokio::test]
    async fn status_before_the_first_install_has_only_the_required_fields() {
        // The daemon omits every `omitempty` field and sends `installed: null`.
        let f = fake(vec![(
            "GET",
            "/v1/status",
            200,
            serde_json::json!({"name": "streamscope", "os": {"version": "1", "revision": 1},
                               "installed": null, "reboot_pending": false, "job": "idle"}),
        )])
        .await;
        let s = f.host.status().await.expect("status");
        assert!(s.installed.is_none() && s.disk.is_none() && s.failed_boot.is_none() && !s.fallback);
    }

    #[tokio::test]
    async fn updates_ask_the_installs_own_channel() {
        let f = fake(vec![(
            "GET",
            "/v1/updates",
            200,
            serde_json::json!({"channel": "stable", "current": {"version": "1.0", "revision": 1},
                               "target": {"version": "1.1", "revision": 1}, "available": true, "changelog": "## 1.1"}),
        )])
        .await;
        let u = f.host.updates().await.expect("updates");
        assert_sent(&f.only(), "GET", "/v1/updates", serde_json::Value::Null);
        assert!(u.available && !u.left_by_rollback);
        assert_eq!(u.target, v("1.1", 1));
        assert_eq!(u.changelog, "## 1.1");
    }

    #[tokio::test]
    async fn upgrade_sends_the_confirmed_release_and_no_channel() {
        let f = fake(vec![("POST", "/v1/upgrade", 202, serde_json::json!({"job": "upgrade", "target": "v1.1-1"}))]).await;
        // A field the body does not declare is ignored and never sent on: an
        // upgrade from the console always takes its backup.
        let stale = serde_json::json!({"confirm": {"version": "1.1", "revision": 1}, "reboot": false, "skip_backup": false});
        assert!(serde_json::from_value::<UpgradeRequest>(stale).is_ok());
        let req = UpgradeRequest { confirm: v("1.1", 1), reboot: false };
        let a = f.host.upgrade(&req).await.expect("upgrade");
        assert_eq!(a.target.as_deref(), Some("v1.1-1"));
        // A daemon target reaches the caller scrubbed; a blank one is not named.
        let dirty = fake(vec![("POST", "/v1/upgrade", 202, serde_json::json!({"job": "upgrade", "target": "  v1\u{0}x  "}))]).await;
        let d = dirty.host.upgrade(&req).await.expect("upgrade");
        let t = d.target.expect("a target");
        assert!(t.starts_with("v1") && !t.contains('\0') && !t.ends_with(' '), "{t:?}");
        assert_eq!(HostAccepted { target: None }.named(" to "), "");
        assert_eq!(HostAccepted { target: Some("v2".into()) }.named(" to "), " to v2");
        // A 202 naming no target, null included, is still a job that started.
        let null = fake(vec![("POST", "/v1/upgrade", 202, serde_json::json!({"job": "upgrade", "target": null}))]).await;
        assert_eq!(null.host.upgrade(&req).await.expect("upgrade").target, None);
        assert_sent(
            &f.only(),
            "POST",
            "/v1/upgrade",
            serde_json::json!({"confirm": {"version": "1.1", "revision": 1}, "reboot": false}),
        );
    }

    #[tokio::test]
    async fn job_passes_the_lines_already_held() {
        let f = fake(vec![(
            "GET",
            "/v1/job?since=7",
            200,
            serde_json::json!({"started": "2026-10-14T09:00:00.000000001Z", "kind": "upgrade", "state": "failed", "target": "v1.1-1", "error": "kairos-agent upgrade: exit 1",
                               "log": ["line 8"], "log_total": 8}),
        )])
        .await;
        let j = f.host.job(7).await.expect("job");
        assert_sent(&f.only(), "GET", "/v1/job?since=7", serde_json::Value::Null);
        // The daemon's text reaches the caller scrubbed; blank is absent.
        let long = "x".repeat(HOST_REASON_CAP + 10);
        let f2 = fake(vec![("GET", "/v1/job?since=0", 200, serde_json::json!({
            "state": "failed", "error": long, "result": "   ", "log": [], "log_total": 0}))]).await;
        let j2 = f2.host.job(0).await.expect("job");
        assert_eq!(j2.error.as_deref().map(str::len), Some(HOST_REASON_CAP));
        assert_eq!(j2.result, None);
        assert_eq!((j.state.as_str(), j.log_total, j.log.len()), ("failed", 8, 1));
        assert_eq!(j.error.as_deref(), Some("kairos-agent upgrade: exit 1"));
        assert!(j.started.is_some());
    }

    #[tokio::test]
    async fn an_idle_job_carries_only_its_state() {
        let f = fake(vec![("GET", "/v1/job?since=0", 200, serde_json::json!({"state": "idle", "log": [], "log_total": 0}))]).await;
        let j = f.host.job(0).await.expect("job");
        assert!(j.kind.is_none() && j.target.is_none() && j.error.is_none() && j.started.is_none() && j.state == "idle");
    }

    #[tokio::test]
    async fn rollback_reads_the_plan_then_confirms_its_target() {
        let f = fake(vec![
            ("GET", "/v1/rollback", 200, serde_json::json!({"from": {"version": "1.1", "revision": 1}, "to": {"version": "1.0", "revision": 1}})),
            ("POST", "/v1/rollback", 202, serde_json::json!({"job": "rollback", "target": "1.0 (revision 1)"})),
        ])
        .await;
        let plan = f.host.rollback_plan().await.expect("plan");
        assert_eq!((plan.from.clone(), plan.to.clone()), (v("1.1", 1), v("1.0", 1)));
        let a = f.host.rollback(&plan.to).await.expect("rollback");
        assert_eq!(a.target.as_deref(), Some("1.0 (revision 1)"));
        let seen = f.seen.lock().expect("lock").clone();
        assert_sent(&seen[0], "GET", "/v1/rollback", serde_json::Value::Null);
        assert_sent(&seen[1], "POST", "/v1/rollback", serde_json::json!({"confirm": {"version": "1.0", "revision": 1}}));
    }

    #[tokio::test]
    async fn power_sends_the_drain() {
        let f = fake(vec![
            ("POST", "/v1/reboot", 202, serde_json::json!({"action": "reboot", "drain_secs": 5})),
            ("POST", "/v1/shutdown", 202, serde_json::json!({"action": "poweroff", "drain_secs": 30})),
        ])
        .await;
        f.host.reboot(&DrainBody { drain_secs: 5 }).await.expect("reboot");
        f.host.shutdown(&DrainBody { drain_secs: 30 }).await.expect("shutdown");
        let seen = f.seen.lock().expect("lock").clone();
        assert_sent(&seen[0], "POST", "/v1/reboot", serde_json::json!({"drain_secs": 5}));
        assert_sent(&seen[1], "POST", "/v1/shutdown", serde_json::json!({"drain_secs": 30}));
    }

    fn settings_reply() -> serde_json::Value {
        serde_json::json!({"configured": true, "destination": "b:bucket/x", "rclone_config_set": true,
                           "recipients": ["age1abc"], "retention_days": 30, "schedule": "daily",
                           "profile": "full", "profiles": ["config", "full"]})
    }

    fn update() -> BackupConfigUpdate {
        BackupConfigUpdate {
            destination: "b:bucket/x".into(),
            recipients: vec!["age1abc".into()],
            retention_days: 30,
            schedule: "daily".into(),
            profile: "full".into(),
        }
    }

    #[tokio::test]
    async fn backup_config_reads_and_saves_the_settings() {
        let f = fake(vec![("GET", "/v1/backup/config", 200, settings_reply()), ("POST", "/v1/backup/config", 200, settings_reply())]).await;
        let c = f.host.backup_config().await.expect("config");
        assert!(c.configured && c.rclone_config_set && !c.locked);
        assert_eq!(c.profiles, ["config", "full"]);
        f.host.set_backup_config(&update()).await.expect("save");
        let seen = f.seen.lock().expect("lock").clone();
        assert_sent(&seen[0], "GET", "/v1/backup/config", serde_json::Value::Null);
        assert_sent(
            &seen[1],
            "POST",
            "/v1/backup/config",
            serde_json::json!({"destination": "b:bucket/x", "recipients": ["age1abc"],
                               "retention_days": 30, "schedule": "daily", "profile": "full"}),
        );
    }

    #[tokio::test]
    async fn settings_the_operator_locked_are_shown_locked_and_a_save_is_refused_with_the_reason() {
        let mut locked = settings_reply();
        locked["locked"] = serde_json::json!(true);
        let f = fake(vec![
            ("GET", "/v1/backup/config", 200, locked),
            ("POST", "/v1/backup/config", 403, serde_json::json!({"error": "the backup settings are locked: the operator changes them, backup config over SSH"})),
        ])
        .await;
        assert!(f.host.backup_config().await.expect("config").locked);
        let err = f.host.set_backup_config(&update()).await.expect_err("locked");
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, ApiErrorCode::ApplianceOperatorOnly));
        assert!(err.message.starts_with("the backup settings are locked"), "{}", err.message);
    }

    #[tokio::test]
    async fn who_saved_the_rclone_config_is_shown_as_the_daemon_knows_it() {
        for (from, want) in [
            (Some("operator"), Some(RcloneConfigFrom::Operator)),
            (Some("unknown"), Some(RcloneConfigFrom::Unknown)),
            (Some("a_value_this_build_does_not_know"), Some(RcloneConfigFrom::Unknown)),
            (None, None),
        ] {
            let mut reply = settings_reply();
            if let Some(from) = from {
                reply["rclone_config_from"] = serde_json::json!(from);
            }
            let f = fake(vec![("GET", "/v1/backup/config", 200, reply)]).await;
            assert_eq!(f.host.backup_config().await.expect("config").rclone_config_from, want, "{from:?}");
        }
    }

    #[test]
    fn a_body_carrying_an_rclone_config_is_refused_not_dropped() {
        let body = |extra: serde_json::Value| {
            let mut b = serde_json::json!({"destination": "b:bucket/x", "recipients": ["age1abc"],
                                           "retention_days": 30, "schedule": "daily", "profile": "full"});
            b.as_object_mut().expect("object").extend(extra.as_object().expect("object").clone());
            serde_json::from_value::<BackupConfigUpdate>(b)
        };
        // Positive control: the settings the console edits parse.
        assert!(body(serde_json::json!({})).is_ok());
        let err = body(serde_json::json!({"rclone_config": "[b]\ntype = sftp\nssh = touch /x\n"})).expect_err("refused");
        assert!(err.to_string().contains("rclone_config"), "{err}");
    }

    #[tokio::test]
    async fn an_optional_body_is_none_only_when_empty_and_never_drops_one() {
        async fn read(content_type: Option<&str>, body: &'static str) -> Result<Option<BackupRunRequest>, StatusCode> {
            let mut req = Request::builder().method("POST").uri("/");
            if let Some(ct) = content_type {
                req = req.header("content-type", ct);
            }
            let req = req.body(Body::from(body)).expect("request");
            OptionalJson::<BackupRunRequest>::from_request(req, &()).await.map(|OptionalJson(b)| b).map_err(|r| r.status())
        }
        for (ct, body) in [(None, ""), (Some("application/json"), ""), (Some("application/json"), " \n"), (Some("application/json"), "null")] {
            assert_eq!(read(ct, body).await.expect("none").map(|b| b.profile), None, "{ct:?} {body:?}");
        }
        let some = read(Some("application/json"), r#"{"profile": "config"}"#).await.expect("some").expect("a body");
        assert_eq!(some.profile.as_deref(), Some("config"));
        // A proposal without a JSON Content-Type is refused, never read as none.
        for ct in [None, Some("text/plain")] {
            assert_eq!(read(ct, r#"{"profile": "config"}"#).await.expect_err("refused"), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{ct:?}");
        }
        for body in [r#"{"profle": "config"}"#, r#"{"profile": "config""#] {
            let status = read(Some("application/json"), body).await.expect_err("refused");
            assert!(status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST, "{body}: {status}");
        }
    }

    #[tokio::test]
    async fn a_locked_test_of_proposed_settings_is_refused_with_the_reason() {
        let f = fake(vec![("POST", "/v1/backup/verify", 403, serde_json::json!({"error": "the backup settings are locked: verify the saved ones (a request without settings), or the operator verifies others over SSH"}))]).await;
        let err = f.host.verify_backup(Some(&update())).await.expect_err("locked");
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, ApiErrorCode::ApplianceOperatorOnly));
        assert!(err.message.starts_with("the backup settings are locked"), "{}", err.message);
    }

    #[tokio::test]
    async fn verify_sends_the_proposed_settings() {
        let f = fake(vec![("POST", "/v1/backup/verify", 202, serde_json::json!({"job": "backup-verify", "target": "b:bucket/x"}))]).await;
        let a = f.host.verify_backup(Some(&update())).await.expect("verify");
        assert_eq!(a.target.as_deref(), Some("b:bucket/x"));
        let seen = f.only();
        assert_eq!((seen.method.as_str(), seen.uri.as_str()), ("POST", "/v1/backup/verify"));
        assert_eq!(seen.body["destination"], "b:bucket/x");
        assert_eq!(seen.body["recipients"], serde_json::json!(["age1abc"]));
    }

    #[tokio::test]
    async fn verify_without_settings_tries_the_saved_ones() {
        let f = fake(vec![("POST", "/v1/backup/verify", 202, serde_json::json!({"job": "backup-verify", "target": "b:bucket/x"}))]).await;
        f.host.verify_backup(None).await.expect("verify");
        let seen = f.only();
        assert_eq!((seen.method.as_str(), seen.uri.as_str()), ("POST", "/v1/backup/verify"));
        // The daemon tries the saved settings only for a request setting none,
        // the one it accepts while they are locked.
        assert_eq!(seen.body, serde_json::json!({}));
    }

    #[tokio::test]
    async fn backup_status_list_and_run() {
        let f = fake(vec![
            ("GET", "/v1/backup/status", 200, serde_json::json!({"settings": settings_reply(), "next": "Wed 2026-10-15 03:00:00 UTC",
                "running": false, "last": {"object": "streamscope-full-x.age", "profile": "full", "release": {"version": "1.0", "revision": 1},
                "started": "2026-10-14T03:00:00Z", "finished": "2026-10-14T03:01:00Z", "bytes": 1234, "prune_error": "denied", "error": "  "}})),
            ("GET", "/v1/backup/list", 200, serde_json::json!([{"name": "a.age", "size": 5, "time": "2026-10-13T03:00:00Z"}])),
            ("POST", "/v1/backup", 202, serde_json::json!({"job": "backup", "target": "streamscope-config-y.age"})),
        ])
        .await;
        let st = f.host.backup_status().await.expect("status");
        let last = st.last.expect("last");
        // A blank error is absent: the daemon's text goes through daemon_text.
        assert_eq!((last.bytes, last.error, last.prune_error.as_deref()), (1234, None, Some("denied")));
        assert_eq!(f.host.backup_list().await.expect("list")[0].size, 5);
        let a = f.host.backup(&BackupRunRequest { profile: Some("config".into()) }).await.expect("run");
        assert_eq!(a.target.as_deref(), Some("streamscope-config-y.age"));
        f.host.backup(&BackupRunRequest { profile: None }).await.expect("run default");
        let seen = f.seen.lock().expect("lock").clone();
        assert_sent(&seen[2], "POST", "/v1/backup", serde_json::json!({"profile": "config"}));
        // No profile: the daemon takes the settings' one, so none is sent.
        assert_sent(&seen[3], "POST", "/v1/backup", serde_json::json!({}));
    }

    #[tokio::test]
    async fn network_reads_and_renames_the_override() {
        let f = fake(vec![(
            "GET",
            "/v1/network",
            200,
            serde_json::json!({"live": {"interface": "eth0", "mac": "aa", "addresses": ["10.0.0.5/24", "2001:db8::5/64"], "gateway": "10.0.0.1",
                                        "gateways6": ["fe80::1"], "dns": ["1.1.1.1"]},
                               "source": "override", "override": {"mode": "static", "address": "10.0.0.5/24", "gateway": "10.0.0.1",
                                                                  "ipv6": true, "address6": "2001:db8::5/64"},
                               "pending": {"previous": null, "deadline": "2026-10-14T10:00:00.5Z", "secs_left": 42}}),
        )])
        .await;
        let n = f.host.network().await.expect("network");
        assert_eq!(n.source, ApplianceNetworkSource::Override);
        assert_eq!(n.live.addresses, ["10.0.0.5/24", "2001:db8::5/64"]);
        assert_eq!(n.live.gateways6, ["fe80::1"]);
        let o = n.override_config.expect("override");
        assert_eq!((o.mode, o.address.as_deref()), (ApplianceNetworkMode::Static, Some("10.0.0.5/24")));
        assert_eq!((o.ipv6, o.address6.as_deref(), o.gateway6.as_deref()), (true, Some("2001:db8::5/64"), None));
        let p = n.pending.expect("pending");
        assert_eq!(p.secs_left, 42);
        assert!(p.previous.is_none());
    }

    #[tokio::test]
    async fn network_reads_the_install_settings_and_what_the_daemon_leaves_out() {
        // The daemon omits a false `ipv6` and an empty `gateways6`: both read as
        // off and none, never as a failure to decode.
        let f = fake(vec![(
            "GET",
            "/v1/network",
            200,
            serde_json::json!({"live": {"addresses": ["10.0.0.5/24"], "dns": []}, "source": "install", "override": null,
                               "install": {"mode": "dhcp", "dns": ["10.0.0.1"]}}),
        )])
        .await;
        let n = f.host.network().await.expect("network");
        assert_eq!(n.source, ApplianceNetworkSource::Install);
        assert!(n.live.gateways6.is_empty() && n.override_config.is_none());
        let i = n.install_config.expect("install");
        assert_eq!((i.mode, i.ipv6, i.dns.as_slice()), (ApplianceNetworkMode::Dhcp, false, ["10.0.0.1".to_string()].as_slice()));
    }

    #[test]
    fn a_network_change_without_ipv6_is_refused() {
        let err = serde_json::from_value::<ApplianceNetworkUpdate>(serde_json::json!({"mode": "dhcp", "dns": []}))
            .expect_err("ipv6 is required");
        assert!(err.to_string().contains("ipv6"), "{err}");
        let ok = serde_json::from_value::<ApplianceNetworkUpdate>(serde_json::json!({"mode": "dhcp", "ipv6": false, "dns": []}));
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[tokio::test]
    async fn network_changes_send_their_bodies() {
        let answer = serde_json::json!({"message": "applied", "override": {"mode": "dhcp", "dns": ["9.9.9.9"]}});
        let f = fake(vec![
            ("POST", "/v1/network", 200, answer.clone()),
            ("POST", "/v1/network/confirm", 200, serde_json::json!({"message": "confirmed", "override": null})),
            ("POST", "/v1/network/revert", 200, serde_json::json!({"message": "reverted", "override": null})),
            ("POST", "/v1/network/reset", 200, serde_json::json!({"message": null, "override": null})),
        ])
        .await;
        let dhcp = ApplianceNetworkUpdate {
            mode: ApplianceNetworkMode::Dhcp,
            address: None,
            gateway: None,
            ipv6: false,
            address6: None,
            gateway6: None,
            dns: vec!["9.9.9.9".into()],
            revert_secs: None,
        };
        let a = f.host.set_network(&dhcp).await.expect("set");
        assert_eq!(a.override_config.map(|o| o.dns), Some(vec!["9.9.9.9".to_string()]));
        let fixed = ApplianceNetworkUpdate {
            mode: ApplianceNetworkMode::Static,
            address: Some("10.0.0.6/24".into()),
            gateway: Some("10.0.0.1".into()),
            ipv6: true,
            address6: Some("2001:db8::6/64".into()),
            gateway6: Some("fe80::1".into()),
            dns: vec![],
            revert_secs: Some(120),
        };
        f.host.set_network(&fixed).await.expect("set static");
        assert_eq!(f.host.confirm_network().await.expect("confirm").message, "confirmed");
        assert_eq!(f.host.revert_network().await.expect("revert").message, "reverted");
        // A null message decodes, and says nothing of what happened.
        assert_eq!(f.host.reset_network().await.expect("reset").message, "the appliance answered without a message");
        let seen = f.seen.lock().expect("lock").clone();
        // An omitted field is omitted on the wire: the daemon decodes strictly.
        // `ipv6` is always stated: the daemon reads its absence as IPv6 off.
        assert_sent(&seen[0], "POST", "/v1/network", serde_json::json!({"mode": "dhcp", "ipv6": false, "dns": ["9.9.9.9"]}));
        assert_sent(
            &seen[1],
            "POST",
            "/v1/network",
            serde_json::json!({"mode": "static", "address": "10.0.0.6/24", "gateway": "10.0.0.1", "ipv6": true,
                               "address6": "2001:db8::6/64", "gateway6": "fe80::1", "dns": [], "revert_secs": 120}),
        );
        assert_sent(&seen[2], "POST", "/v1/network/confirm", serde_json::json!({}));
        assert_sent(&seen[3], "POST", "/v1/network/revert", serde_json::json!({}));
        assert_sent(&seen[4], "POST", "/v1/network/reset", serde_json::json!({}));
    }

    // -- refusals -----------------------------------------------------------

    #[tokio::test]
    async fn a_refusal_for_the_appliances_state_reaches_the_caller_with_its_reason() {
        let f = fake(vec![("POST", "/v1/upgrade", 409, serde_json::json!({"error": "an upgrade is running: wait for it to finish"}))]).await;
        let err = f
            .host
            .upgrade(&UpgradeRequest { confirm: v("1", 1), reboot: true })
            .await
            .expect_err("refused");
        assert_eq!((err.status, err.code), (StatusCode::CONFLICT, ApiErrorCode::ApplianceRefused));
        assert_eq!(err.message, "an upgrade is running: wait for it to finish");
    }

    #[tokio::test]
    async fn a_refusal_of_the_operators_input_is_a_bad_request_with_its_reason() {
        let f = fake(vec![("POST", "/v1/network", 400, serde_json::json!({"error": "gateway 10.9.9.1 is not in 10.0.0.0/24"}))]).await;
        let req = ApplianceNetworkUpdate { mode: ApplianceNetworkMode::Static, address: None, gateway: None, ipv6: false, address6: None, gateway6: None, dns: vec![], revert_secs: None };
        let err = f.host.set_network(&req).await.expect_err("refused");
        assert_eq!((err.status, err.code), (StatusCode::BAD_REQUEST, ApiErrorCode::ApplianceRequestInvalid));
        assert!(err.message.contains("not in 10.0.0.0/24"), "{}", err.message);
    }

    #[tokio::test]
    async fn a_daemon_502_is_its_own_failure_and_its_text_stays_out() {
        let f = fake(vec![("POST", "/v1/backup/verify", 502, serde_json::json!({"error": "writing b:x/verify.txt: 403 denied"}))]).await;
        let err = f.host.verify_backup(Some(&update())).await.expect_err("bad gateway");
        assert_eq!(err.code, ApiErrorCode::HostDaemonError);
        assert!(!err.message.contains("403"), "{}", err.message);
    }

    #[tokio::test]
    async fn events_long_poll_from_the_cursor_and_decode_every_kind() {
        let f = fake(vec![(
            "GET",
            "/v1/events?after=7&wait=25",
            200,
            serde_json::json!({"events": [
                {"seq": 8, "at": "2026-10-14T09:00:00Z", "kind": "job.ended", "job": "2026-10-14T08:59:00.000000001Z",
                 "job_kind": "backup-verify", "target": "b:x", "state": "failed", "error": "writing b:x/verify.txt: 403"},
                {"seq": 9, "at": "2026-10-14T09:00:30Z", "kind": "job.ended", "job": "2026-10-14T08:00:00Z",
                 "job_kind": "upgrade", "state": "done", "reboot": {"action": "reboot", "drain_secs": 30}, "result": "written"},
                {"seq": 10, "at": "2026-10-14T09:01:00Z", "kind": "reboot.scheduled", "action": "reboot", "drain_secs": 30,
                 "by": "2026-10-14T08:00:00Z", "boot_id": "b-1"},
                {"seq": 11, "at": "2026-10-14T09:03:00Z", "kind": "boot.judged", "boot_id": "b-2",
                 "release": {"version": "1.1", "revision": 1}, "on_trial": true, "verdict": "went_back", "reason": "not ready"},
                {"seq": 12, "at": "2026-10-14T09:04:00Z", "kind": "something.new"}
            ], "last": 12, "truncated": false}),
        )])
        .await;
        let e = f.host.events(7, 25).await.expect("events");
        assert_sent(&f.only(), "GET", "/v1/events?after=7&wait=25", serde_json::Value::Null);
        assert_eq!((e.last, e.truncated, e.events.len()), (12, false, 5));
        assert_eq!(e.events[0].error.as_deref(), Some("writing b:x/verify.txt: 403"));
        assert!(e.events[0].reboot.is_none());
        let reboot = e.events[1].reboot.as_ref().expect("the reboot the upgrade scheduled");
        assert_eq!((reboot.action.as_str(), reboot.drain_secs), ("reboot", 30));
        assert_eq!(e.events[1].result.as_deref(), Some("written"));
        assert_eq!((e.events[2].drain_secs, e.events[2].by.is_some()), (Some(30), true));
        assert_eq!(e.events[3].verdict.as_deref(), Some("went_back"));
        // A kind this side does not know passes through.
        assert_eq!(e.events[4].kind, "something.new");
    }

    #[test]
    fn the_next_number_passes_every_entry_and_follows_the_floor() {
        let answer = |events: serde_json::Value, last: u64, dropped: u64, truncated: bool| HostEvents {
            events: serde_json::from_value(events).expect("entries"),
            last,
            dropped,
            truncated,
        };
        // Past the last entry answered, the cap leaving the rest for later.
        assert_eq!(answer(serde_json::json!([{"seq": 8}, {"seq": 9}]), 400, 0, false).next_after(7), 9);
        // A last entry with no number is passed too, never asked again in a loop.
        assert_eq!(answer(serde_json::json!([{"kind": "x"}]), 12, 0, false).next_after(11), 12);
        // Behind a readable one, the highest readable number: a capped answer's
        // unseen entries are never skipped.
        assert_eq!(answer(serde_json::json!([{"seq": 12}, {"kind": "x"}]), 900, 0, false).next_after(11), 12);
        // One inside a capped answer does not skip what the cap left out.
        assert_eq!(answer(serde_json::json!([{"kind": "x"}, {"seq": 13}]), 500, 0, false).next_after(11), 13);
        // Nothing new: the same number.
        assert_eq!(answer(serde_json::json!([]), 11, 0, false).next_after(11), 11);
        // Truncated by rotation: from the floor.
        assert_eq!(answer(serde_json::json!([]), 3000, 1000, true).next_after(500), 1000);
        // The journal started again below the cursor: from its start.
        assert_eq!(answer(serde_json::json!([]), 5, 0, true).next_after(120), 0);
        // … also when the answer carries its entries: past them, not back to the old cursor.
        assert_eq!(answer(serde_json::json!([{"seq": 1}, {"seq": 5}]), 5, 0, true).next_after(120), 5);
    }

    #[tokio::test]
    async fn a_field_shaped_otherwise_is_left_out_and_the_rest_of_the_entry_stays() {
        let f = fake(vec![(
            "GET",
            "/v1/events?after=0&wait=0",
            200,
            serde_json::json!({"events": [
                {"seq": 1, "at": "2026-10-14T09:00:00Z", "kind": "boot.started", "release": {"version": "1.1"}, "boot_id": "b"},
                {"seq": 2, "at": "2026-10-14T09:00:01Z", "kind": "job.ended", "job_kind": "upgrade", "state": "failed",
                 "error": "kairos-agent: exit 1", "reboot": "a shape of its own"},
                {"kind": "headless"},
                {"seq": 3, "at": "not a time", "kind": "job.ended"}
            ], "last": 3, "truncated": false}),
        )])
        .await;
        let e = f.host.events(0, 0).await.expect("one odd entry does not fail the answer");
        // The headless one (no number) is dropped; the one with a number but an
        // unreadable time is said as `unreadable`.
        assert_eq!(e.events.len(), 3);
        assert_eq!((e.events[2].seq, e.events[2].kind.as_str()), (3, "unreadable"));
        // The field of another shape is left out; the rest of the entry stays.
        assert_eq!((e.events[0].seq, e.events[0].release.is_none(), e.events[0].boot_id.as_deref()), (1, true, Some("b")));
        assert!(e.events[1].reboot.is_none());
        assert_eq!((e.events[1].state.as_deref(), e.events[1].error.as_deref()), (Some("failed"), Some("kairos-agent: exit 1")));
        assert_eq!((e.last, e.next), (3, 3));
    }

    #[tokio::test]
    async fn every_other_failure_is_sanitized() {
        let f = fake(vec![
            ("GET", "/v1/status", 401, serde_json::json!({"error": "needs the install's token"})),
            ("GET", "/v1/updates", 500, serde_json::json!({"error": "open /var/lib/secret: denied"})),
            ("GET", "/v1/rollback", 409, serde_json::json!({})),
            ("POST", "/v1/network", 400, serde_json::json!({"error": "  "})),
            ("GET", "/v1/network", 200, serde_json::json!({"live": "not an object"})),
        ])
        .await;
        // A refused credential is its own code; its text stays out too.
        let err = f.host.status().await.expect_err("401");
        assert_eq!((err.status, err.code), (StatusCode::BAD_GATEWAY, ApiErrorCode::HostDaemonRefused));
        assert!(!err.message.contains("install's token"), "{}", err.message);
        // A 403 is an action the daemon keeps for the operator: a refusal with
        // its reason, never the credential's error.
        let err = map_host_refusal("/v1/backup/config", StatusCode::FORBIDDEN, br#"{"error": "the backup settings are locked"}"#);
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, ApiErrorCode::ApplianceOperatorOnly));
        assert_eq!(err.message, "the backup settings are locked");
        assert_eq!(err.error_type, "invalid_request");
        let err = map_host_refusal("/v1/backup/config", StatusCode::FORBIDDEN, b"");
        assert_eq!((err.status, err.code), (StatusCode::FORBIDDEN, ApiErrorCode::ApplianceOperatorOnly));
        assert!(err.message.contains("operator"), "{}", err.message);
        let err = map_host_refusal("/v1/x", StatusCode::BAD_REQUEST, br#"{"error": "bad"}"#);
        assert_eq!(err.code, ApiErrorCode::ApplianceRequestInvalid);
        let err = f.host.updates().await.expect_err("500");
        assert_eq!((err.status, err.code), (StatusCode::BAD_GATEWAY, ApiErrorCode::HostDaemonError));
        assert!(!err.message.contains("secret"), "{}", err.message);
        // A refusal without a reason stays a refusal, its text ours.
        let err = f.host.rollback_plan().await.expect_err("409");
        assert_eq!((err.status, err.code), (StatusCode::CONFLICT, ApiErrorCode::ApplianceRefused));
        let req = ApplianceNetworkUpdate { mode: ApplianceNetworkMode::Dhcp, address: None, gateway: None, ipv6: false, address6: None, gateway6: None, dns: vec![], revert_secs: None };
        let err = f.host.set_network(&req).await.expect_err("400");
        assert_eq!((err.status, err.code), (StatusCode::BAD_REQUEST, ApiErrorCode::ApplianceRequestInvalid));
        // A 2xx that does not decode is the contract drifting, told apart.
        assert_eq!(f.host.network().await.expect_err("drift").code, ApiErrorCode::HostDaemonBadResponse);
    }

    #[tokio::test]
    async fn a_daemon_that_is_not_there_is_a_sanitized_502() {
        let host = Host::at(std::env::temp_dir().join("ss-host-absent.sock"), TOKEN);
        let err = host.status().await.expect_err("no socket");
        // Told apart from a daemon that answered with an error.
        assert_eq!((err.status, err.code), (StatusCode::BAD_GATEWAY, ApiErrorCode::HostDaemonUnreachable));
    }

    #[test]
    fn a_long_reason_is_cut_on_a_character_boundary() {
        let reason = "é".repeat(HOST_REASON_CAP);
        let body = serde_json::to_vec(&serde_json::json!({"error": reason})).expect("json");
        let err = map_host_refusal("/v1/x", StatusCode::CONFLICT, &body);
        assert!(err.message.len() <= HOST_REASON_CAP && !err.message.is_empty());
    }
}
