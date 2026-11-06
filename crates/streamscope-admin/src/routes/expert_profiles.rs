//! Per-profile expert membership — which agent experts a `kind='expert'` profile
//! enables. This is the CONTENT adapter for the expert profile domain.
//!
//! Default-as-base model: EVERY expert profile carries explicit
//! `expert_profile_members` rows, the editable DEFAULT included (seeded with all
//! enabled experts — the shared base). A Layered profile's effective set is the
//! Default's experts ∪ its own; a Standalone profile's is its own only; an Off
//! assignment runs none.
//!
//! Consumed admin-side by the analysis cycle (`agent::analysis`); never shipped
//! to the proxy, so mutations do **not** mark the tenant config dirty.

use axum::extract::Path;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};

/// Response for `GET /api/v1/admin/profiles/{id}/expert`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpertMembershipResponse {
    /// Expert ids enabled on this profile (its explicit membership rows). The
    /// Default is seeded with all enabled experts but is editable like any profile.
    pub expert_ids: Vec<Uuid>,
    /// True for the tenant default expert profile (the shared base). Drives the
    /// UI's "Reset to seed" affordance; no longer implies read-only.
    pub is_default: bool,
}

/// Body for `PUT /api/v1/admin/profiles/{id}/expert`. Full replace: the listed
/// experts become the profile's exact member set.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateExpertMembershipRequest {
    pub expert_ids: Vec<Uuid>,
}

/// A workspace an expert profile's analysis covers.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AnalysisStartWorkspace {
    pub id: Uuid,
    pub name: String,
}

/// Response for `GET /api/v1/admin/profiles/{id}/analysis-start`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AnalysisStartResponse {
    /// How far the profile's enabled experts have analyzed: the oldest of their
    /// cursors. `null` while any of them has no position yet.
    pub analyzed_through: Option<DateTime<Utc>>,
    /// The newest of those cursors. A restart earlier than this analyzes again
    /// what at least one expert already analyzed.
    pub furthest_through: Option<DateTime<Utc>>,
    /// False when a restart would move nothing: the profile runs no enabled
    /// expert that reads sessions, or no workspace uses it.
    pub restartable: bool,
    /// The workspaces a restart moves: analysis keeps one cursor per expert and
    /// profile, so it moves for every workspace using this profile. The Default
    /// also covers sessions attributed to no workspace.
    pub workspaces: Vec<AnalysisStartWorkspace>,
}

/// Body for `POST /api/v1/admin/profiles/{id}/actions/set-analysis-start`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SetAnalysisStartRequest {
    /// Analyze sessions with activity after this instant. Absent or `null` = now,
    /// which drops the backlog. Earlier than the current position analyzes again what
    /// was already analyzed. A future instant is refused.
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}/analysis-start",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    responses(
        (status = 200, description = "Where the profile's analysis stands and what it covers", body = AnalysisStartResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_analysis_start(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<AnalysisStartResponse>, ApiError> {
    let is_default = ensure_expert_profile(db.conn(), id).await?;
    let members = scanning_expert_ids(db.conn(), id).await?;
    let (analyzed_through, furthest_through) = analysis_position(db.conn(), id, &members).await?;
    let workspaces = covered_workspaces(db.conn(), id, is_default).await?;
    let restartable = !members.is_empty() && (is_default || !workspaces.is_empty());
    Ok(Json(AnalysisStartResponse { analyzed_through, furthest_through, restartable, workspaces }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/profiles/{id}/actions/set-analysis-start",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    request_body = SetAnalysisStartRequest,
    responses(
        (status = 200, description = "Analysis restarts from the given instant", body = ActionResponse),
        (status = 400, description = "The instant is in the future, or before 1970", body = ApiErrorResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_analysis_start(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<SetAnalysisStartRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let is_default = ensure_expert_profile(db.conn(), id).await?;
    let from = analysis_start(body.from, Utc::now()).map_err(|message| {
        ApiError::bad_request(message).code(ApiErrorCode::ValidationFailed)
    })?;
    let members = scanning_expert_ids(db.conn(), id).await?;
    if members.is_empty() {
        return Ok(Json(ActionResponse::ok().with_message(
            "This profile runs no expert that reads sessions, so there is nothing to restart.",
        )));
    }
    // Nothing reads this profile's cursors, and a workspace assigned later must
    // start from then, not from a date set long before it.
    if !is_default && covered_workspaces(db.conn(), id, false).await?.is_empty() {
        return Ok(Json(ActionResponse::ok().with_message(
            "No workspace uses this profile, so there is nothing to restart.",
        )));
    }
    let failed = |e: sqlx::Error| {
        tracing::error!("set analysis start: {e}");
        ApiError::internal("failed to set the analysis start")
    };
    let mut tx = db.conn().begin().await.map_err(failed)?;
    // Each expert's own position, locked so the audit row shows what this replaced.
    type At = Option<DateTime<Utc>>;
    let before: Vec<(Uuid, At, At)> = sqlx::query_as(
        "SELECT expert_id, last_processed_at, cluster_processed_at FROM expert_profile_watermarks \
         WHERE profile_id = $1 AND expert_id = ANY($2) ORDER BY expert_id FOR UPDATE",
    )
    .bind(id)
    .bind(&members)
    .fetch_all(&mut *tx)
    .await
    .map_err(failed)?;
    let before: Vec<serde_json::Value> = before
        .into_iter()
        .map(|(expert_id, position, cluster_position)| {
            serde_json::json!({ "expert_id": expert_id, "position": position, "cluster_position": cluster_position })
        })
        .collect();
    // Invariant: the generation moves with the cursor, in one write. A cycle
    // that read the previous generation then cannot write over this cursor. No
    // cycle is triggered: the next one, inside the tenant's run window, reads it.
    sqlx::query(
        "INSERT INTO expert_profile_watermarks \
            (profile_id, expert_id, tenant_id, last_processed_at, cursor_generation) \
         SELECT $1, e, $3, $4, 1 FROM unnest($2::uuid[]) AS e \
         ON CONFLICT (tenant_id, profile_id, expert_id) DO UPDATE SET \
            last_processed_at = EXCLUDED.last_processed_at, \
            cluster_processed_at = NULL, \
            cursor_generation = expert_profile_watermarks.cursor_generation + 1, \
            updated_at = now()",
    )
    .bind(id)
    .bind(&members)
    .bind(tenant_id)
    .bind(from)
    .execute(&mut *tx)
    .await
    .map_err(failed)?;
    // The expert's display column: the oldest of its profile cursors.
    sqlx::query(
        "UPDATE agent_experts e SET \
            last_processed_at = (SELECT MIN(NULLIF(LEAST(COALESCE(w.last_processed_at, 'epoch'), w.cluster_processed_at), 'epoch')) \
                                 FROM expert_profile_watermarks w WHERE w.expert_id = e.id), \
            updated_at = now() \
         WHERE e.id = ANY($1)",
    )
    .bind(&members)
    .execute(&mut *tx)
    .await
    .map_err(failed)?;
    tx.commit().await.map_err(failed)?;

    audit_sink.record(Some(&before), Some(&serde_json::json!({ "from": from, "expert_ids": members })));
    Ok(Json(ActionResponse::ok().with_message("Analysis restarts from this date at its next cycle.")))
}


#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}/expert",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    responses(
        (status = 200, description = "Profile expert membership", body = ExpertMembershipResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_profile_expert_membership(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ExpertMembershipResponse>, ApiError> {
    let is_default = ensure_expert_profile(db.conn(), id).await?;
    let expert_ids = effective_member_ids(db.conn(), id).await?;
    Ok(Json(ExpertMembershipResponse { expert_ids, is_default }))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/profiles/{id}/expert",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    request_body = UpdateExpertMembershipRequest,
    responses(
        (status = 200, description = "Updated membership", body = ExpertMembershipResponse),
        (status = 400, description = "Unknown expert id", body = ApiErrorResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_profile_expert_membership(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateExpertMembershipRequest>,
) -> Result<Json<ExpertMembershipResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Every expert profile is editable, the Default included (it is the shared
    // base whose membership a Layered profile inherits). `ensure_expert_profile`
    // still validates kind/tenant.
    let is_default = ensure_expert_profile(db.conn(), id).await?;

    // Dedup the requested set and validate every id is an expert in this tenant
    // (RLS scopes `agent_experts`, so this also rejects cross-tenant ids).
    let mut unique: Vec<Uuid> = body.expert_ids.clone();
    unique.sort_unstable();
    unique.dedup();
    let valid: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agent_experts WHERE id = ANY($1) AND NOT suppressed")
        .bind(&unique)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("validate expert ids: {e}");
            ApiError::internal("failed to validate experts")
        })?;
    if valid.len() != unique.len() {
        return Err(ApiError::bad_request("one or more expert ids do not exist")
            .code(ApiErrorCode::ValidationFailed));
    }

    // Sorted to match the `unique` (UUID-sorted) after-set, so an unchanged save
    // produces an empty audit diff rather than a spurious reordering.
    let mut before = effective_member_ids(db.conn(), id).await?;
    before.sort_unstable();

    // Replace the member set atomically.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update expert membership (begin): {e}");
        ApiError::internal("failed to update membership")
    })?;
    sqlx::query("DELETE FROM expert_profile_members WHERE profile_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clear expert membership: {e}");
            ApiError::internal("failed to update membership")
        })?;
    if !unique.is_empty() {
        sqlx::query(
            "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
             SELECT $1, e, $3 FROM unnest($2::uuid[]) AS e",
        )
        .bind(id)
        .bind(&unique)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("insert expert membership: {e}");
            ApiError::internal("failed to update membership")
        })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("update expert membership (commit): {e}");
        ApiError::internal("failed to update membership")
    })?;

    audit_sink.record(Some(&before), Some(&unique));
    Ok(Json(ExpertMembershipResponse { expert_ids: unique, is_default }))
}

// ---------------------------------------------------------------------------
// Shared helpers (also the create/delete content adapters for `kind='expert'`)
// ---------------------------------------------------------------------------

/// Validate that `id` is an expert-kind profile in the current tenant; returns
/// whether it is the tenant default.
async fn ensure_expert_profile(conn: &mut Scoped, id: Uuid) -> Result<bool, ApiError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT kind, is_default FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("validate expert profile: {e}");
                ApiError::internal("failed to validate profile")
            })?;
    match row {
        Some((kind, is_default)) if kind == "expert" => Ok(is_default),
        _ => Err(ApiError::not_found("expert profile not found", ApiErrorCode::ProfileNotFound)),
    }
}

/// The instant a restart moves the cursors to: the requested one, or now. Pure
/// so both sides of the boundary are held without a clock.
fn analysis_start(
    requested: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, &'static str> {
    match requested {
        Some(from) if from > now => Err("the analysis start cannot be in the future"),
        Some(from) if from < DateTime::UNIX_EPOCH => Err("the analysis start is too far in the past"),
        Some(from) => Ok(from),
        None => Ok(now),
    }
}

/// The experts a profile actually runs. Default and Standalone own their set; a
/// Layered profile runs the Default's and its own. The one statement of this
/// rule, shared by the analysis cycle and the restart.
pub(crate) fn effective_expert_ids(
    own: Vec<Uuid>,
    default_members: &[Uuid],
    is_default: bool,
    standalone: bool,
) -> Vec<Uuid> {
    let mut ids = own;
    if !is_default && !standalone {
        ids.extend_from_slice(default_members);
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// [`effective_expert_ids`] read for one profile; suppressed experts excluded.
async fn running_expert_ids(conn: &mut Scoped, id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    let failed = |e: sqlx::Error| {
        tracing::error!("load running experts: {e}");
        ApiError::internal("failed to load the profile's experts")
    };
    let (is_default, standalone): (bool, bool) =
        sqlx::query_as("SELECT is_default, standalone FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .map_err(failed)?;
    let own = effective_member_ids(conn, id).await?;
    let default_members: Vec<Uuid> = sqlx::query_scalar(
        "SELECT e.id FROM expert_profile_members m \
         JOIN profiles p ON p.tenant_id = m.tenant_id AND p.id = m.profile_id \
         JOIN agent_experts e ON e.tenant_id = m.tenant_id AND e.id = m.expert_id AND NOT e.suppressed \
         WHERE p.kind = 'expert' AND p.is_default",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(failed)?;
    Ok(effective_expert_ids(own, &default_members, is_default, standalone))
}

/// The experts a restart moves: those the profile runs that read sessions and
/// are enabled. A tool-inventory expert has no cursor, and a row written for it
/// would never move. A disabled expert keeps its own: no cycle reads it, and it
/// stays out of the position the admin confirms a restart against.
async fn scanning_expert_ids(conn: &mut Scoped, id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    let members = running_expert_ids(conn, id).await?;
    sqlx::query_scalar(
        "SELECT id FROM agent_experts \
         WHERE id = ANY($1) AND enabled AND input_types && ARRAY['session', 'session_cluster']",
    )
    .bind(&members)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load scanning experts: {e}");
        ApiError::internal("failed to load the profile's experts")
    })
}

/// The workspaces a profile's analysis covers. The partition's rule: an
/// assignment names the profile; a workspace with none follows the Default; an
/// assignment to no profile is Off.
async fn covered_workspaces(
    conn: &mut Scoped,
    id: Uuid,
    is_default: bool,
) -> Result<Vec<AnalysisStartWorkspace>, ApiError> {
    sqlx::query_as(
        "SELECT w.id, w.name FROM workspaces w \
         LEFT JOIN workspace_profile_assignments a \
           ON a.tenant_id = w.tenant_id AND a.workspace_id = w.id AND a.kind = 'expert' \
         WHERE a.profile_id = $1 OR (a.workspace_id IS NULL AND $2) \
         ORDER BY w.name, w.id",
    )
    .bind(id)
    .bind(is_default)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load analysis start workspaces: {e}");
        ApiError::internal("failed to load the analysis start")
    })
}

/// The oldest and newest cursor among those experts. The oldest is `None` while
/// any has no position yet: the cycle reads that as behind everything.
async fn analysis_position(
    conn: &mut Scoped,
    id: Uuid,
    members: &[Uuid],
) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>), ApiError> {
    sqlx::query_as(
        "SELECT CASE WHEN bool_and(NULLIF(LEAST(COALESCE(w.last_processed_at, 'epoch'), w.cluster_processed_at), 'epoch') IS NOT NULL) \
                     THEN MIN(NULLIF(LEAST(COALESCE(w.last_processed_at, 'epoch'), w.cluster_processed_at), 'epoch')) END, \
                MAX(NULLIF(GREATEST(w.last_processed_at, w.cluster_processed_at), 'epoch')) \
         FROM agent_experts e \
         LEFT JOIN expert_profile_watermarks w \
           ON w.tenant_id = e.tenant_id AND w.expert_id = e.id AND w.profile_id = $1 \
         WHERE e.id = ANY($2)",
    )
    .bind(id)
    .bind(members)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load analysis position: {e}");
        ApiError::internal("failed to load the analysis start")
    })
}

/// The profile's member ids — its explicit `expert_profile_members` rows (every
/// expert profile, the Default included, carries explicit rows). Suppressed
/// experts are filtered out.
async fn effective_member_ids(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT e.id FROM expert_profile_members m \
         JOIN agent_experts e ON e.id = m.expert_id AND NOT e.suppressed \
         WHERE m.profile_id = $1 ORDER BY e.axis",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load expert membership: {e}");
        ApiError::internal("failed to load membership")
    })
}

/// Copy a source expert profile's explicit members onto a freshly-created profile
/// (the per-kind copy adapter). Returns the number of rows created.
pub(crate) async fn copy_members(
    conn: &mut Scoped,
    tenant_id: Uuid,
    source_id: Uuid,
    dest_id: Uuid,
) -> Result<i64, ApiError> {
    let res = sqlx::query(
        "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
         SELECT $1, expert_id, $3 FROM expert_profile_members WHERE profile_id = $2 \
         ON CONFLICT DO NOTHING",
    )
    .bind(dest_id)
    .bind(source_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("copy expert membership: {e}");
        ApiError::internal("failed to copy membership")
    })?;
    Ok(res.rows_affected() as i64)
}

/// Seed an expert profile's membership with all enabled experts (the "seed"
/// content adapter — used by reset-to-seed and create-from-seed). Replaces any
/// existing rows. Returns the number of members.
pub(crate) async fn apply_seed_members(
    conn: &mut Scoped,
    tenant_id: Uuid,
    profile_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query("DELETE FROM expert_profile_members WHERE profile_id = $1")
        .bind(profile_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("clear expert membership for seed: {e}");
            ApiError::internal("failed to seed membership")
        })?;
    let res = sqlx::query(
        "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
         SELECT $1, e.id, $2 FROM agent_experts e WHERE e.enabled = true AND NOT e.suppressed \
         ON CONFLICT DO NOTHING",
    )
    .bind(profile_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("seed expert membership: {e}");
        ApiError::internal("failed to seed membership")
    })?;
    Ok(res.rows_affected() as i64)
}

/// Count of a profile's explicit members — for list/detail `rule_count`.
pub(crate) async fn member_count(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM expert_profile_members m \
         JOIN agent_experts e ON e.id = m.expert_id AND NOT e.suppressed \
         WHERE m.profile_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("count expert membership: {e}");
        ApiError::internal("failed to count membership")
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_analysis_start_may_be_now_or_earlier_and_never_later() {
        let now = Utc::now();
        assert_eq!(analysis_start(None, now), Ok(now));
        assert_eq!(analysis_start(Some(now), now), Ok(now));
        let earlier = now - chrono::Duration::milliseconds(1);
        assert_eq!(analysis_start(Some(earlier), now), Ok(earlier));
        let later = now + chrono::Duration::milliseconds(1);
        assert!(analysis_start(Some(later), now).is_err());
        assert_eq!(analysis_start(Some(DateTime::UNIX_EPOCH), now), Ok(DateTime::UNIX_EPOCH));
        let before_epoch = DateTime::UNIX_EPOCH - chrono::Duration::milliseconds(1);
        assert!(analysis_start(Some(before_epoch), now).is_err());
    }

    #[test]
    fn only_a_layered_profile_runs_the_defaults_experts() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        // Layered: its own and the Default's, once each.
        assert_eq!(effective_expert_ids(vec![b, a], &[a], false, false), vec![a, b]);
        // Standalone and the Default itself: their own set alone.
        assert_eq!(effective_expert_ids(vec![a], &[b], false, true), vec![a]);
        assert_eq!(effective_expert_ids(vec![a], &[b], true, false), vec![a]);
    }
}
