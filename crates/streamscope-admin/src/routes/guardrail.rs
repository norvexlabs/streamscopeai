//! Guardrail admin endpoints — split along the backend / policy line.
//!
//! - **Backend (tenant-wide)** — `GET/PATCH /api/v1/admin/settings/guardrail`
//!   manages [`GuardrailBackendSettings`] (the classifier deployment shared by
//!   every guardrail profile: URL, protocol, label, timeout, windows, spotlight,
//!   notify-on-detection). Stored in `system_settings.guardrail`.
//! - **Policy (per-profile)** — `GET/PATCH /api/v1/admin/profiles/{id}/guardrail`
//!   manages a guardrail profile's [`GuardrailPolicy`] (posture: enabled, mode,
//!   scan_inbound, threshold, fail_mode, PII). Stored one row per profile in the
//!   `guardrail_policies` table (PK `(tenant_id, profile_id)`), so concurrent
//!   edits to different profiles touch different rows — no shared-blob clobber.
//!
//! The proxy folds the backend with each reachable profile's policy into one
//! resolved `GuardrailSettings` per profile at snapshot load. A mutation reaches
//! the proxies through the config change triggers.


use axum::extract::Path;
use axum::Json;
use serde::{Deserialize, Serialize};
use streamscope_core::config::ProfileKind;
use streamscope_core::guardrail::{
    ClassifierProtocol, GuardrailBackendSettings, GuardrailFailMode, GuardrailMode,
    GuardrailPolicy, GuardrailSettings, PiiSettings, PII_ENTITY_TYPES,
};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};

const GUARDRAIL_SETTINGS_KEY: &str = "guardrail";

// ===========================================================================
// Backend (tenant-wide) — system_settings.guardrail
// ===========================================================================

/// Response for `GET /api/v1/admin/settings/guardrail`: the tenant-wide
/// classifier backend.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GuardrailBackendResponse {
    #[serde(flatten)]
    pub settings: GuardrailBackendSettings,
}

/// Body for `PATCH /api/v1/admin/settings/guardrail`. All fields optional.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateGuardrailBackendRequest {
    #[serde(default, deserialize_with = "crate::routes::double_option::null_as_blank")]
    pub classifier_url: Option<String>,
    pub protocol: Option<ClassifierProtocol>,
    pub positive_label: Option<String>,
    pub timeout_ms: Option<u64>,
    pub max_windows: Option<u32>,
    pub max_windows_content: Option<u32>,
    pub spotlight: Option<bool>,
    pub notify_on_detection: Option<bool>,
}

fn pii_entity_types() -> Vec<String> {
    PII_ENTITY_TYPES.iter().map(|s| s.to_string()).collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/guardrail",
    tag = "Guardrail",
    responses(
        (status = 200, description = "Current guardrail backend settings", body = GuardrailBackendResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_guardrail_settings(
    mut db: TenantConn,
) -> Result<Json<GuardrailBackendResponse>, ApiError> {
    let settings = load_backend(db.conn()).await?;
    Ok(Json(GuardrailBackendResponse { settings }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings/guardrail",
    tag = "Guardrail",
    request_body = UpdateGuardrailBackendRequest,
    responses(
        (status = 200, description = "Updated backend settings", body = GuardrailBackendResponse),
        (status = 400, description = "Invalid body", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_guardrail_settings(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<UpdateGuardrailBackendRequest>,
) -> Result<Json<GuardrailBackendResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Build the partial patch from only the fields the caller set, normalized
    // exactly as the typed apply would (trim, empty classifier → clear). The
    // single-statement merge composes it onto the stored value atomically — the
    // `ON CONFLICT` row lock serializes concurrent backend writers, so no
    // advisory lock and no lost update. Validate the patch's own fields before
    // the write (an unpatched value was already validated on its own write).
    let patch = backend_patch_json(&body);
    validate_backend_patch(&patch)?;
    let base = super::default_merged::<GuardrailBackendSettings>(&patch);
    let (old, new) =
        super::merge_settings_blob(db.conn(), GUARDRAIL_SETTINGS_KEY, tenant_id, &base, &patch)
            .await?;

    let before: GuardrailBackendSettings =
        old.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    let current: GuardrailBackendSettings = serde_json::from_value(new).map_err(|e| {
        tracing::error!("deserialize merged guardrail backend: {e}");
        ApiError::internal("failed to update settings")
    })?;

    audit_sink.record(Some(&before), Some(&current));

    Ok(Json(GuardrailBackendResponse { settings: current }))
}

/// The constrained fields of a backend patch: a positive `timeout_ms`, and a
/// set `classifier_url` that passes the write-time SSRF check
/// (`extension_http::validate_endpoint`: an http(s) URL with a host, never the
/// metadata address, an internal IP literal only when the platform's
/// `extensions` egress list lists it; a host name is resolved only at call
/// time).
fn validate_backend_patch(patch: &serde_json::Value) -> Result<(), ApiError> {
    if patch.get("timeout_ms").and_then(serde_json::Value::as_u64) == Some(0) {
        return Err(ApiError::bad_request("timeout_ms must be greater than 0"));
    }
    if let Some(url) = patch.get("classifier_url").and_then(serde_json::Value::as_str)
        && let Err(reason) = streamscope_core::extension_http::validate_endpoint(url)
    {
        return Err(ApiError::bad_request(format!("classifier_url {reason}")));
    }
    Ok(())
}

/// Partial JSON patch of only the fields the caller set, normalized exactly as
/// the typed struct expects. Keys MUST be the serde field names of
/// [`GuardrailBackendSettings`] — the round-trip test guards against drift.
fn backend_patch_json(body: &UpdateGuardrailBackendRequest) -> serde_json::Value {
    let mut p = serde_json::Map::new();
    if let Some(v) = &body.classifier_url {
        let t = v.trim();
        p.insert(
            "classifier_url".into(),
            if t.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(t.to_string()) },
        );
    }
    if let Some(v) = &body.protocol {
        p.insert("protocol".into(), serde_json::to_value(v).unwrap_or(serde_json::Value::Null));
    }
    if let Some(v) = &body.positive_label {
        let t = v.trim();
        if !t.is_empty() {
            p.insert("positive_label".into(), serde_json::Value::String(t.to_string()));
        }
    }
    if let Some(v) = body.timeout_ms {
        p.insert("timeout_ms".into(), serde_json::json!(v));
    }
    if let Some(v) = body.max_windows {
        p.insert("max_windows".into(), serde_json::json!(v));
    }
    if let Some(v) = body.max_windows_content {
        p.insert("max_windows_content".into(), serde_json::json!(v));
    }
    if let Some(v) = body.spotlight {
        p.insert("spotlight".into(), serde_json::json!(v));
    }
    if let Some(v) = body.notify_on_detection {
        p.insert("notify_on_detection".into(), serde_json::json!(v));
    }
    serde_json::Value::Object(p)
}

// ===========================================================================
// Policy (per-profile) — system_settings.guardrail_profiles[<profile id>]
// ===========================================================================

/// Response for `GET /api/v1/admin/profiles/{id}/guardrail`. The profile's
/// policy plus the closed PII entity-type set the editor offers.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GuardrailPolicyResponse {
    #[serde(flatten)]
    pub policy: GuardrailPolicy,
    /// The closed set of PII entity types the in-process detector recognizes —
    /// the options the UI offers in the PII entity allowlist. Server-owned.
    pub pii_entity_types: Vec<String>,
}

/// Body for `PATCH /api/v1/admin/profiles/{id}/guardrail`. All fields optional.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateGuardrailPolicyRequest {
    pub enabled: Option<bool>,
    pub mode: Option<GuardrailMode>,
    pub scan_inbound: Option<bool>,
    pub threshold: Option<f32>,
    pub fail_mode: Option<GuardrailFailMode>,
    pub pii: Option<PiiSettingsUpdate>,
}

/// Partial update for the PII detector sub-block. All fields optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct PiiSettingsUpdate {
    pub enabled: Option<bool>,
    pub mode: Option<GuardrailMode>,
    pub scan_request: Option<bool>,
    pub scan_response: Option<bool>,
    pub entities: Option<Vec<String>>,
    pub threshold: Option<f32>,
    pub redaction_placeholder: Option<String>,
    pub fail_mode: Option<GuardrailFailMode>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}/guardrail",
    tag = "Guardrail",
    params(("id" = Uuid, Path, description = "Guardrail profile id")),
    responses(
        (status = 200, description = "Profile guardrail policy", body = GuardrailPolicyResponse),
        (status = 404, description = "Profile not found / not a guardrail profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_profile_guardrail_policy(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<GuardrailPolicyResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    ensure_guardrail_profile(db.conn(), id).await?;
    let policy = load_policy(db.conn(), tenant_id, id).await?;
    Ok(Json(GuardrailPolicyResponse {
        policy,
        pii_entity_types: pii_entity_types(),
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/profiles/{id}/guardrail",
    tag = "Guardrail",
    params(("id" = Uuid, Path, description = "Guardrail profile id")),
    request_body = UpdateGuardrailPolicyRequest,
    responses(
        (status = 200, description = "Updated policy", body = GuardrailPolicyResponse),
        (status = 400, description = "Invalid body", body = ApiErrorResponse),
        (status = 404, description = "Profile not found / not a guardrail profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_profile_guardrail_policy(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateGuardrailPolicyRequest>,
) -> Result<Json<GuardrailPolicyResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    ensure_guardrail_profile(db.conn(), id).await?;

    // The profile's policy is its own `guardrail_policies` row. Lock just that
    // row for the read→patch→write (`FOR UPDATE`) so a concurrent PATCH to the
    // SAME profile serializes; edits to other profiles touch other rows and
    // never contend (the per-row table is what replaces the old blob lock).
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin guardrail policy tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    let mut current = load_policy_for_update(&mut tx, tenant_id, id).await?;
    let before = current.clone();
    apply_policy_patch(&mut current, body);

    // Validate the merged shape: threshold range, the PII placeholder must keep
    // its `{entity}` token (else an enforce mask drops the entity label), and
    // every requested entity must be a recognizer the detector ships.
    if !(0.0..=1.0).contains(&current.threshold) {
        return Err(ApiError::bad_request("threshold must be between 0.0 and 1.0"));
    }
    if !(0.0..=1.0).contains(&current.pii.threshold) {
        return Err(ApiError::bad_request(
            "pii.threshold must be between 0.0 and 1.0",
        ));
    }
    if !current.pii.redaction_placeholder.contains("{entity}") {
        return Err(ApiError::bad_request(
            "pii.redaction_placeholder must contain the {entity} token",
        ));
    }
    if let Some(bad) = current
        .pii
        .entities
        .iter()
        .find(|e| !PII_ENTITY_TYPES.contains(&e.as_str()))
    {
        return Err(ApiError::bad_request(format!(
            "unknown PII entity type: {bad}"
        )));
    }

    upsert_policy(&mut tx, tenant_id, id, &current).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("commit guardrail policy tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    audit_sink.record(Some(&before), Some(&current));

    Ok(Json(GuardrailPolicyResponse {
        policy: current,
        pii_entity_types: pii_entity_types(),
    }))
}

fn apply_policy_patch(current: &mut GuardrailPolicy, body: UpdateGuardrailPolicyRequest) {
    if let Some(v) = body.enabled {
        current.enabled = v;
    }
    if let Some(v) = body.mode {
        current.mode = v;
    }
    if let Some(v) = body.scan_inbound {
        current.scan_inbound = v;
    }
    if let Some(v) = body.threshold {
        current.threshold = v;
    }
    if let Some(v) = body.fail_mode {
        current.fail_mode = v;
    }
    if let Some(pii) = body.pii {
        apply_pii_patch(&mut current.pii, pii);
    }
}

fn apply_pii_patch(current: &mut PiiSettings, body: PiiSettingsUpdate) {
    if let Some(v) = body.enabled {
        current.enabled = v;
    }
    if let Some(v) = body.mode {
        current.mode = v;
    }
    if let Some(v) = body.scan_request {
        current.scan_request = v;
    }
    if let Some(v) = body.scan_response {
        current.scan_response = v;
    }
    if let Some(v) = body.entities {
        current.entities = v;
    }
    if let Some(v) = body.threshold {
        current.threshold = v;
    }
    if let Some(v) = body.redaction_placeholder {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            current.redaction_placeholder = trimmed.to_string();
        }
    }
    if let Some(v) = body.fail_mode {
        current.fail_mode = v;
    }
}

// ===========================================================================
// helpers
// ===========================================================================

/// Load the tenant's typed guardrail **backend** settings from
/// `system_settings.guardrail` (inert default when absent/malformed). The
/// connection must be tenant-scoped (RLS). Shared with the alert producer
/// (`crate::alerts`) — both read the same tenant-wide `notify_on_detection`.
pub(crate) async fn load_backend(
    conn: &mut Scoped,
) -> Result<GuardrailBackendSettings, ApiError> {
    let raw: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(GUARDRAIL_SETTINGS_KEY)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("load guardrail backend: {e}");
                ApiError::internal("failed to load settings")
            })?;
    Ok(raw
        .and_then(|v| serde_json::from_value::<GuardrailBackendSettings>(v).ok())
        .unwrap_or_default())
}

/// The tenant's **default** guardrail profile, resolved against the backend.
/// This is the policy that screens tenant-level config
/// artifacts — surfaces where no workspace exists to resolve a per-workspace
/// profile (the A2A agent card at ingestion). No default profile row / no
/// policy row both resolve to [`GuardrailPolicy::default`], matching what the
/// proxy would run for an unassigned workspace.
pub(crate) async fn load_default_resolved(
    conn: &mut Scoped,
    tenant_id: Uuid,
) -> Result<GuardrailSettings, ApiError> {
    let backend = load_backend(conn).await?;
    let policy =
        match super::profiles::default_profile_id(conn, tenant_id, ProfileKind::Guardrail).await? {
            Some(profile_id) => load_policy(conn, tenant_id, profile_id).await?,
            None => GuardrailPolicy::default(),
        };
    Ok(GuardrailSettings::resolve(&backend, &policy))
}

/// One `guardrail_policies` row — the storage projection of [`GuardrailPolicy`]
/// (the `mode`/`fail_mode` enums as snake_case TEXT, `pii` as JSONB).
#[derive(sqlx::FromRow)]
struct PolicyRow {
    enabled: bool,
    mode: String,
    scan_inbound: bool,
    threshold: f32,
    fail_mode: String,
    pii: serde_json::Value,
}

impl PolicyRow {
    fn into_policy(self) -> Result<GuardrailPolicy, serde_json::Error> {
        Ok(GuardrailPolicy {
            enabled: self.enabled,
            mode: parse_enum(&self.mode)?,
            scan_inbound: self.scan_inbound,
            threshold: self.threshold,
            fail_mode: parse_enum(&self.fail_mode)?,
            pii: serde_json::from_value(self.pii)?,
        })
    }
}

/// `(profile_id, policy)` row for the bulk snapshot read.
#[derive(sqlx::FromRow)]
struct ProfilePolicyRow {
    profile_id: Uuid,
    #[sqlx(flatten)]
    policy: PolicyRow,
}

/// Serialize a snake_case serde enum to its string discriminant for a TEXT column.
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Parse a TEXT column back into a snake_case serde enum.
fn parse_enum<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
}

/// Load one profile's policy ([`GuardrailPolicy::default`] when no row exists).
/// Tenant bound explicitly (defense-in-depth on top of RLS).
async fn load_policy(
    conn: &mut Scoped,
    tenant_id: Uuid,
    profile_id: Uuid,
) -> Result<GuardrailPolicy, ApiError> {
    let row: Option<PolicyRow> = sqlx::query_as(
        "SELECT enabled, mode, scan_inbound, threshold, fail_mode, pii \
         FROM guardrail_policies WHERE tenant_id = $1 AND profile_id = $2",
    )
    .bind(tenant_id)
    .bind(profile_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load guardrail policy: {e}");
        ApiError::internal("failed to load settings")
    })?;
    decode_policy(row)
}

/// Same as [`load_policy`] but takes `FOR UPDATE` so the read→patch→write of
/// the PATCH serializes against a concurrent writer of the SAME profile's row.
async fn load_policy_for_update(
    conn: &mut Scoped,
    tenant_id: Uuid,
    profile_id: Uuid,
) -> Result<GuardrailPolicy, ApiError> {
    let row: Option<PolicyRow> = sqlx::query_as(
        "SELECT enabled, mode, scan_inbound, threshold, fail_mode, pii \
         FROM guardrail_policies WHERE tenant_id = $1 AND profile_id = $2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(profile_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("lock guardrail policy: {e}");
        ApiError::internal("failed to update settings")
    })?;
    decode_policy(row)
}

fn decode_policy(row: Option<PolicyRow>) -> Result<GuardrailPolicy, ApiError> {
    match row {
        Some(r) => r.into_policy().map_err(|e| {
            tracing::error!("decode guardrail policy: {e}");
            ApiError::internal("failed to load settings")
        }),
        None => Ok(GuardrailPolicy::default()),
    }
}

/// Load every profile's policy for the config snapshot (profile-id → policy).
/// Tenant bound explicitly; malformed rows are dropped with a warning rather
/// than failing the whole tenant (same discipline as tool rules).
pub(crate) async fn load_all_policies(
    conn: &mut Scoped,
    tenant_id: Uuid,
) -> Result<Vec<(Uuid, GuardrailPolicy)>, ApiError> {
    let rows: Vec<ProfilePolicyRow> = sqlx::query_as(
        "SELECT profile_id, enabled, mode, scan_inbound, threshold, fail_mode, pii \
         FROM guardrail_policies WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load guardrail policies: {e}");
        ApiError::internal("failed to load settings")
    })?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let pid = r.profile_id;
            match r.policy.into_policy() {
                Ok(p) => Some((pid, p)),
                Err(e) => {
                    tracing::warn!(profile = %pid, error = %e, "skipping malformed guardrail policy");
                    None
                }
            }
        })
        .collect())
}

/// Upsert a single profile's policy row.
pub(crate) async fn upsert_policy(
    conn: &mut Scoped,
    tenant_id: Uuid,
    profile_id: Uuid,
    p: &GuardrailPolicy,
) -> Result<(), ApiError> {
    let pii = serde_json::to_value(&p.pii).map_err(|e| {
        tracing::error!("serialize guardrail pii: {e}");
        ApiError::internal("failed to update settings")
    })?;
    sqlx::query(
        "INSERT INTO guardrail_policies \
           (tenant_id, profile_id, enabled, mode, scan_inbound, threshold, fail_mode, pii, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now()) \
         ON CONFLICT (tenant_id, profile_id) DO UPDATE SET \
           enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, scan_inbound = EXCLUDED.scan_inbound, \
           threshold = EXCLUDED.threshold, fail_mode = EXCLUDED.fail_mode, pii = EXCLUDED.pii, \
           updated_at = now()",
    )
    .bind(tenant_id)
    .bind(profile_id)
    .bind(p.enabled)
    .bind(enum_str(&p.mode))
    .bind(p.scan_inbound)
    .bind(p.threshold)
    .bind(enum_str(&p.fail_mode))
    .bind(&pii)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("upsert guardrail policy: {e}");
        ApiError::internal("failed to update settings")
    })?;
    Ok(())
}

/// Drop a profile's policy row when the profile is deleted (the per-kind delete
/// adapter for `kind='guardrail'`). A single statement — the FK also cascades,
/// this is explicit for clarity. No-op when the profile had no policy.
pub(crate) async fn remove_policy(
    conn: &mut Scoped,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM guardrail_policies WHERE tenant_id = $1 AND profile_id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("remove guardrail policy: {e}");
            ApiError::internal("failed to update settings")
        })?;
    Ok(())
}

/// Copy a source guardrail profile's policy onto a new profile (the per-kind
/// copy adapter for `kind='guardrail'`). A single statement; no-op when the
/// source had no policy.
pub(crate) async fn copy_policy(
    conn: &mut Scoped,
    tenant_id: Uuid,
    source_id: Uuid,
    dest_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO guardrail_policies \
           (tenant_id, profile_id, enabled, mode, scan_inbound, threshold, fail_mode, pii) \
         SELECT tenant_id, $3, enabled, mode, scan_inbound, threshold, fail_mode, pii \
         FROM guardrail_policies WHERE tenant_id = $1 AND profile_id = $2 \
         ON CONFLICT (tenant_id, profile_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(source_id)
    .bind(dest_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("copy guardrail policy: {e}");
        ApiError::internal("failed to update settings")
    })?;
    Ok(())
}

/// Validate that `id` is a guardrail-kind profile in the current tenant.
async fn ensure_guardrail_profile(conn: &mut Scoped, id: Uuid) -> Result<(), ApiError> {
    let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("validate guardrail profile: {e}");
            ApiError::internal("failed to validate profile")
        })?;
    match kind.as_deref() {
        Some("guardrail") => Ok(()),
        _ => Err(ApiError::not_found("guardrail profile not found", ApiErrorCode::ProfileNotFound)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Drift guard for the patch builder: a typo'd JSON key would silently no-op
    // the SQL `value || patch` merge. Setting every field to a sentinel distinct
    // from its default and round-tripping through `default_merged` (the same
    // shallow merge the SQL `||` applies) proves every key is a real serde field
    // and every normalization (trim, empty→clear) survives.
    #[test]
    fn backend_patch_round_trips_every_field() {
        let body = UpdateGuardrailBackendRequest {
            classifier_url: Some("  https://classify.example  ".into()),
            protocol: Some(ClassifierProtocol::OpenaiModerations),
            positive_label: Some("  INJECTION  ".into()),
            timeout_ms: Some(4321),
            max_windows: Some(9),
            max_windows_content: Some(21),
            spotlight: Some(false),
            notify_on_detection: Some(true),
        };
        let patch = backend_patch_json(&body);
        let merged = super::super::default_merged::<GuardrailBackendSettings>(&patch);
        let got: GuardrailBackendSettings =
            serde_json::from_value(merged).expect("merged base must deserialize");

        assert_eq!(got.classifier_url.as_deref(), Some("https://classify.example"));
        assert_eq!(got.protocol, ClassifierProtocol::OpenaiModerations);
        assert_eq!(got.positive_label, "INJECTION");
        assert_eq!(got.timeout_ms, 4321);
        assert_eq!(got.max_windows, 9);
        assert_eq!(got.max_windows_content, 21);
        assert!(!got.spotlight);
        assert!(got.notify_on_detection);
    }

    #[test]
    fn a_classifier_url_that_is_not_an_http_url_with_a_host_is_a_400() {
        for bad in [
            "classify.example:8000",
            "ftp://classify.example",
            "not a url",
            "http://",
            "http://10.0.0.5:8000",
            "http://169.254.169.254",
        ] {
            let patch = backend_patch_json(&UpdateGuardrailBackendRequest {
                classifier_url: Some(bad.into()),
                ..Default::default()
            });
            let err = validate_backend_patch(&patch).expect_err(bad);
            assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(err.code, ApiErrorCode::ValidationFailed, "{bad}");
        }
    }

    #[test]
    fn an_http_classifier_url_or_a_cleared_one_is_accepted() {
        for good in ["http://classifier.internal:8000", "https://classify.example/", "   "] {
            let patch = backend_patch_json(&UpdateGuardrailBackendRequest {
                classifier_url: Some(good.into()),
                ..Default::default()
            });
            assert!(validate_backend_patch(&patch).is_ok(), "{good:?}");
        }
        assert!(validate_backend_patch(&serde_json::json!({})).is_ok());
    }

    #[test]
    fn backend_patch_normalizes_empty_strings() {
        // Empty classifier → explicit JSON null (clears the field on merge).
        let body = UpdateGuardrailBackendRequest {
            classifier_url: Some("   ".into()),
            ..Default::default()
        };
        let patch = backend_patch_json(&body);
        assert_eq!(patch.get("classifier_url"), Some(&serde_json::Value::Null));

        // Empty positive_label → omitted entirely (keeps the existing value).
        let body = UpdateGuardrailBackendRequest {
            positive_label: Some("  ".into()),
            ..Default::default()
        };
        let patch = backend_patch_json(&body);
        assert!(patch.get("positive_label").is_none());

        // An empty body produces an empty patch (a no-op merge).
        let patch = backend_patch_json(&UpdateGuardrailBackendRequest::default());
        assert_eq!(patch.as_object().map(serde_json::Map::len), Some(0));
    }
}
