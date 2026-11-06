//! Generic profiles — named policy bundles, one per domain (`kind`).
//!
//! A profile is identity + the one-default invariant; its CONTENT lives
//! per-domain in `system_settings` (tool rules tagged by `profile_id`; guardrail
//! policy in `guardrail_profiles` keyed by profile id). A workspace selects a
//! profile per kind (`workspace_profile_assignments`); a request resolves the
//! workspace's profile for the relevant kind, else the kind's tenant default.
//!
//! This module owns the `profiles` rows and the generic CRUD. Per-kind **content**
//! (copy-on-create, drop-on-delete) is handled by a small adapter so a new kind
//! is a `ProfileKind` variant + an adapter arm, never a new endpoint.
//!
//! A mutation reaches the proxies through the config change triggers.

use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use streamscope_core::config::ProfileKind;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::tool_rules::load_rules;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};
use crate::AdminState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct ProfileRow {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub description: Option<String>,
    pub is_default: bool,
    /// Inheritance mode: `false` = Layered (inherits the Default + own diff);
    /// `true` = Standalone (owns its full content). The Default profile is
    /// standalone (it is the base).
    pub standalone: bool,
    /// Judge model, `kind='expert'` only: the model the profile's experts
    /// analyze with. `null` on a non-default profile = inherit the Default
    /// expert profile's model. Always set on the Default; other kinds carry
    /// `null`.
    pub model: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// List/detail shape: the profile row plus the count of content items assigned
/// to it (tool rules for `kind='tools'`; `0` for kinds whose content isn't a
/// rule list, e.g. guardrail, which is a single policy blob).
#[derive(Serialize, ToSchema)]
pub struct Profile {
    #[serde(flatten)]
    #[schema(inline)]
    pub profile: ProfileRow,
    /// Number of profile-specific content items (tool rules) for this profile.
    pub rule_count: i64,
}

/// `kind` query filter (required) for the list endpoint. The wire string is
/// validated against [`ProfileKind`]. (Create takes `kind` in the body.)
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct KindQuery {
    pub kind: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateProfileRequest {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// How the new profile relates to the Default and what it starts from
    /// (defaults to Layered + Blank — inherits the Default with no own content).
    #[serde(default)]
    pub start_from: ProfileStartChoice,
}

/// New-profile inheritance mode × initial content. `mode` is the tagged
/// discriminator; `content` seeds the profile's own rows.
#[derive(Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProfileStartChoice {
    /// Inherits the Default; its own rows are the diff layered on top.
    Layered {
        #[serde(default)]
        content: StartContent,
    },
    /// Owns its full content; ignores the Default.
    Standalone {
        #[serde(default)]
        content: StartContent,
    },
}

impl Default for ProfileStartChoice {
    fn default() -> Self {
        ProfileStartChoice::Layered { content: StartContent::Blank }
    }
}

/// Initial content for a new profile. `blank` = empty; `seed` = a fresh copy of
/// the kind's built-in defaults; `copy` = a deep copy of another profile's own
/// content.
#[derive(Deserialize, ToSchema, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartContent {
    #[default]
    Blank,
    Seed,
    Copy {
        id: Uuid,
    },
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub description: Option<Option<String>>,
    /// Judge model (`kind='expert'` only). Explicit `null` clears a
    /// non-default profile back to inheriting the Default's model; the
    /// Default profile's model cannot be cleared.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub model: Option<Option<String>>,
}

/// Client access has only its tenant Default: no other profile of the kind is
/// created, promoted or assigned to a workspace.
pub(crate) fn refuse_default_only(kind: ProfileKind) -> Result<(), ApiError> {
    if kind == ProfileKind::ClientAccess {
        return Err(default_only());
    }
    Ok(())
}

fn default_only() -> ApiError {
    ApiError::bad_request("client access has only its Default profile").code(ApiErrorCode::ProfileKindDefaultOnly)
}

fn parse_kind(s: &str) -> Result<ProfileKind, ApiError> {
    ProfileKind::parse(s)
        .ok_or_else(|| ApiError::bad_request("unknown profile kind").code(ApiErrorCode::ProfileKindInvalid))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Validate that a profile id exists in the current tenant with the given kind.
/// Shared by the rule-write paths so an operator can't stamp a tool rule with a
/// profile id that no workspace can select (or a profile of the wrong kind).
pub(crate) async fn ensure_profile_exists(
    conn: &mut Scoped,
    id: Uuid,
    kind: ProfileKind,
) -> Result<(), ApiError> {
    let row_kind: Option<String> = sqlx::query_scalar("SELECT kind FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(conn)
        .await
        .map_err(|e| {
            tracing::error!("validate profile: {e}");
            ApiError::internal("failed to validate profile")
        })?;
    match row_kind.as_deref() {
        Some(k) if k == kind.as_str() => Ok(()),
        _ => Err(ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound)),
    }
}

/// The id of a kind's **Default** profile (the shared base) for this tenant, if
/// one exists. The rule-write paths stamp builtins/forks against it.
pub(crate) async fn default_profile_id(
    conn: &mut Scoped,
    tenant_id: Uuid,
    kind: ProfileKind,
) -> Result<Option<Uuid>, ApiError> {
    sqlx::query_scalar("SELECT id FROM profiles WHERE tenant_id = $1 AND kind = $2 AND is_default = true")
        .bind(tenant_id)
        .bind(kind.as_str())
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("lookup default profile: {e}");
            ApiError::internal("failed to resolve default profile")
        })
}

/// `(is_default, standalone)` for a profile in this tenant, if it exists. A
/// profile is **Layered** when neither — its effective content is the Default ⊕
/// its own.
pub(crate) async fn profile_mode(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<Option<(bool, bool)>, ApiError> {
    sqlx::query_as("SELECT is_default, standalone FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("lookup profile mode: {e}");
            ApiError::internal("failed to resolve profile mode")
        })
}

/// Count of a profile's **own** content items (its diff for a Layered profile, its
/// full set for the Default / a Standalone) — tool rules / transform programs /
/// member experts; `0` for guardrail (a single posture struct).
async fn rule_count_for(
    conn: &mut Scoped,
    tenant_id: Uuid,
    kind: ProfileKind,
    id: Uuid,
) -> Result<i64, ApiError> {
    match kind {
        ProfileKind::Tools => {
            let rules = load_rules(conn, tenant_id).await?;
            Ok(rules.iter().filter(|r| r.profile_id == Some(id)).count() as i64)
        }
        ProfileKind::Transform => sqlx::query_scalar(
            "SELECT count(*) FROM transform_programs WHERE profile_id = $1 AND NOT suppressed",
        )
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("count transform programs: {e}");
            ApiError::internal("failed to count programs")
        }),
        ProfileKind::Expert => super::expert_profiles::member_count(conn, id).await,
        ProfileKind::ClientAccess => super::client_access_profiles::member_count(conn, id).await,
        ProfileKind::Guardrail => Ok(0),
    }
}

/// Materialize a kind's seeded content onto `profile_id` (the "seed" adapter,
/// shared by create-from-seed and reset-to-seed). `as_default = true` writes the
/// pristine shared base (original ids/names, `is_builtin`); `false` writes
/// independent copies. Returns the count of items written.
pub(crate) async fn apply_profile_seed(
    conn: &mut Scoped,
    tenant_id: Uuid,
    kind: ProfileKind,
    profile_id: Uuid,
    as_default: bool,
) -> Result<i64, ApiError> {
    match kind {
        ProfileKind::Tools => {
            super::tool_rules::seed_rules_onto_profile(conn, tenant_id, profile_id, as_default).await
        }
        ProfileKind::Transform => {
            super::transforms::seed_programs_onto_profile(conn, tenant_id, profile_id, as_default)
                .await
        }
        ProfileKind::Guardrail => {
            super::guardrail::upsert_policy(
                conn,
                tenant_id,
                profile_id,
                &streamscope_core::guardrail::GuardrailPolicy::default(),
            )
            .await?;
            Ok(0)
        }
        ProfileKind::Expert => {
            super::expert_profiles::apply_seed_members(conn, tenant_id, profile_id).await
        }
        ProfileKind::ClientAccess => {
            super::client_access_profiles::apply_seed(conn, tenant_id, profile_id).await
        }
    }
}

/// Deep-copy a source profile's **own** content onto `dest_id` (the per-kind copy
/// adapter for create-from-copy). Tool rules / transform programs are cloned with
/// fresh ids/names; guardrail copies the policy row; expert copies membership.
/// Returns the count.
async fn copy_profile_content(
    tx: &mut Scoped,
    tenant_id: Uuid,
    kind: ProfileKind,
    source_id: Uuid,
    dest_id: Uuid,
) -> Result<i64, ApiError> {
    match kind {
        ProfileKind::Tools => {
            let res = sqlx::query(
                "INSERT INTO tool_policy_rules \
                   (tenant_id, rule_id, profile_id, seq, title, description, risk, phase, \
                    scope, conditions, action, priority, model_filter, app_filter, \
                    mcp_server_filter, a2a_agent_filter, enabled, framework_refs, forked_from, \
                    is_builtin, suppressed) \
                 SELECT tenant_id, gen_random_uuid()::text, $3, \
                        (SELECT COALESCE(MAX(seq), 0) FROM tool_policy_rules WHERE tenant_id = $1) \
                          + 1024 * (row_number() OVER (ORDER BY seq, id))::bigint, \
                        title, description, risk, phase, scope, conditions, action, priority, \
                        model_filter, app_filter, mcp_server_filter, a2a_agent_filter, enabled, \
                        framework_refs, NULL, false, false \
                 FROM tool_policy_rules \
                 WHERE tenant_id = $1 AND profile_id = $2 AND NOT suppressed",
            )
            .bind(tenant_id)
            .bind(source_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("copy tool rules into new profile: {e}");
                ApiError::internal("failed to copy profile rules")
            })?;
            Ok(res.rows_affected() as i64)
        }
        ProfileKind::Guardrail => {
            super::guardrail::copy_policy(tx, tenant_id, source_id, dest_id).await?;
            Ok(0)
        }
        ProfileKind::Transform => {
            let res = sqlx::query(
                "INSERT INTO transform_programs \
                   (tenant_id, name, description, source, phase, scope, priority, enabled, \
                    model_filter, app_filter, trigger_regex, match_mode, is_builtin, profile_id) \
                 SELECT tenant_id, \
                        name || ' (' || substr(replace($3::text, '-', ''), 1, 8) || ')', \
                        description, source, phase, scope, priority, enabled, \
                        model_filter, app_filter, trigger_regex, match_mode, false, $3 \
                 FROM transform_programs \
                 WHERE tenant_id = $1 AND profile_id = $2 AND NOT suppressed",
            )
            .bind(tenant_id)
            .bind(source_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("create transform profile (copy programs): {e}");
                ApiError::internal("failed to copy transform programs")
            })?;
            Ok(res.rows_affected() as i64)
        }
        ProfileKind::Expert => {
            super::expert_profiles::copy_members(tx, tenant_id, source_id, dest_id).await
        }
        // Refused before any copy (`refuse_default_only`).
        ProfileKind::ClientAccess => Err(default_only()),
    }
}

/// Absorb the outgoing Default's content into the profile being promoted, so the
/// new Default is a complete, self-contained base. For tools/transform this
/// **moves** the rows (re-stamps `profile_id`), preserving the canonical
/// `rule_id`s / names and `is_builtin` flags — that keeps the "builtins live on
/// the Default" invariant, so seed-sync continues to refresh builtins on (and
/// land new builtins on) whatever profile is currently the Default. For
/// guardrail/expert there is no rule-id-keyed builtin set, so it copies. The
/// outgoing Default is left holding only what the new Default already overrode
/// (typically nothing) and is demoted to a Standalone by the caller.
async fn absorb_base_into(
    tx: &mut Scoped,
    tenant_id: Uuid,
    kind: ProfileKind,
    base_id: Uuid,
    dest_id: Uuid,
) -> Result<(), ApiError> {
    match kind {
        ProfileKind::Tools => {
            // The promoted profile's forks supersede the base rules they override
            // → retire those base origins, then move the rest of the base's rows
            // onto the promoted profile and turn its forks into plain base rules.
            // An origin the seed shipped is hidden, never removed, or the next seed
            // sync would put it back beside its fork; a user's origin is removed.
            // `seq` ordering and `rule_id` uniqueness are preserved (base and own
            // rule ids are disjoint per tenant).
            sqlx::query(
                "WITH origins AS ( \
                   SELECT forked_from FROM tool_policy_rules \
                   WHERE tenant_id = $1 AND profile_id = $3 AND forked_from IS NOT NULL), \
                 hidden AS ( \
                   UPDATE tool_policy_rules SET suppressed = true, updated_at = now() \
                   WHERE tenant_id = $1 AND profile_id = $2 AND seeded \
                     AND rule_id IN (SELECT forked_from FROM origins) \
                   RETURNING 1) \
                 DELETE FROM tool_policy_rules \
                 WHERE tenant_id = $1 AND profile_id = $2 AND NOT seeded \
                   AND rule_id IN (SELECT forked_from FROM origins)",
            )
            .bind(tenant_id)
            .bind(base_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("absorb base (drop forked origins): {e}");
                ApiError::internal("failed to set default profile")
            })?;
            sqlx::query(
                "UPDATE tool_policy_rules SET profile_id = $3 \
                 WHERE tenant_id = $1 AND profile_id = $2",
            )
            .bind(tenant_id)
            .bind(base_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("absorb base (move tool rules): {e}");
                ApiError::internal("failed to set default profile")
            })?;
            sqlx::query(
                "UPDATE tool_policy_rules SET forked_from = NULL \
                 WHERE tenant_id = $1 AND profile_id = $3 AND forked_from IS NOT NULL",
            )
            .bind(tenant_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("absorb base (clear forks): {e}");
                ApiError::internal("failed to set default profile")
            })?;
        }
        ProfileKind::Transform => {
            // Program names are tenant-unique, so base and own names are disjoint —
            // a plain move can't collide.
            sqlx::query(
                "UPDATE transform_programs SET profile_id = $3 \
                 WHERE tenant_id = $1 AND profile_id = $2",
            )
            .bind(tenant_id)
            .bind(base_id)
            .bind(dest_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("absorb base (move transform programs): {e}");
                ApiError::internal("failed to set default profile")
            })?;
        }
        ProfileKind::Expert => {
            sqlx::query(
                "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
                 SELECT $2, expert_id, $1 FROM expert_profile_members WHERE profile_id = $3 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(tenant_id)
            .bind(dest_id)
            .bind(base_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("absorb base expert members: {e}");
                ApiError::internal("failed to set default profile")
            })?;
        }
        // Refused before any promotion (`refuse_default_only`).
        ProfileKind::ClientAccess => return Err(default_only()),
        ProfileKind::Guardrail => {
            // Only when the promoted profile carries no own policy — else its own
            // posture wins and there is nothing to inherit.
            let has_own: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM guardrail_policies WHERE profile_id = $1)",
            )
            .bind(dest_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("check guardrail policy: {e}");
                ApiError::internal("failed to set default profile")
            })?;
            if !has_own {
                super::guardrail::copy_policy(tx, tenant_id, base_id, dest_id).await?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles",
    tag = "Profiles",
    params(KindQuery, PageQuery),
    responses(
        (status = 200, description = "Paginated profile list", body = OffsetPage<Profile>),
        (status = 400, description = "Unknown kind", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_profiles(
    mut db: TenantConn,
    Query(kq): Query<KindQuery>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<Profile>>, ApiError> {
    let kind = parse_kind(&kq.kind)?;
    let (limit, offset) = page.resolve();
    let tenant_id = db.tenant_uuid();

    let rows = sqlx::query_as::<_, ProfileRow>(
        "SELECT id, kind, name, description, is_default, standalone, model, created_at, updated_at \
         FROM profiles WHERE kind = $1 \
         ORDER BY is_default DESC, name ASC LIMIT $2 OFFSET $3",
    )
    .bind(kind.as_str())
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list profiles: {e}");
        ApiError::internal("failed to list profiles")
    })?;

    // Per-profile **own** content counts (the diff for a Layered profile, the full
    // set for the Default / a Standalone). Tools → profile-tagged rule tally;
    // transform → profile-tagged program tally; expert → member count; guardrail
    // carries no per-profile item count (a single posture struct).
    let counts: std::collections::HashMap<Uuid, i64> = match kind {
        ProfileKind::Tools => {
            let rules = load_rules(db.conn(), tenant_id).await?;
            let mut c = std::collections::HashMap::new();
            for r in &rules {
                if let Some(pid) = r.profile_id {
                    *c.entry(pid).or_insert(0) += 1;
                }
            }
            c
        }
        ProfileKind::Transform => {
            let grouped: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT profile_id, count(*) FROM transform_programs \
                 WHERE NOT suppressed GROUP BY profile_id",
            )
            .fetch_all(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("transform program counts: {e}");
                ApiError::internal("failed to count programs")
            })?;
            grouped.into_iter().collect()
        }
        ProfileKind::Expert => {
            let grouped: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT m.profile_id, count(*) FROM expert_profile_members m \
                 JOIN agent_experts e ON e.id = m.expert_id AND NOT e.suppressed \
                 GROUP BY m.profile_id",
            )
            .fetch_all(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("expert membership counts: {e}");
                ApiError::internal("failed to count membership")
            })?;
            grouped.into_iter().collect()
        }
        ProfileKind::ClientAccess => {
            let grouped: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT m.profile_id, count(*) FROM client_access_members m \
                 JOIN client_profiles c ON c.id = m.client_profile_id AND NOT c.suppressed \
                 GROUP BY m.profile_id",
            )
            .fetch_all(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("client access counts: {e}");
                ApiError::internal("failed to count clients")
            })?;
            grouped.into_iter().collect()
        }
        ProfileKind::Guardrail => std::collections::HashMap::new(),
    };
    let items: Vec<Profile> = rows
        .into_iter()
        .map(|profile| {
            let rule_count = counts.get(&profile.id).copied().unwrap_or(0);
            Profile { profile, rule_count }
        })
        .collect();

    Ok(Json(OffsetPage::from_overfetched(items, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/profiles",
    tag = "Profiles",
    request_body = CreateProfileRequest,
    responses(
        (status = 201, description = "Profile created", body = Profile),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_profile(
    mut db: TenantConn,
    Json(req): Json<CreateProfileRequest>,
) -> Result<(StatusCode, Json<Profile>), ApiError> {
    let kind = parse_kind(&req.kind)?;
    refuse_default_only(kind)?;
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required")
            .code(ApiErrorCode::ValidationFailed));
    }

    let tenant_id = db.tenant_uuid();
    // Inheritance mode + initial content from the tagged choice.
    let (standalone, content) = match &req.start_from {
        ProfileStartChoice::Layered { content } => (false, content),
        ProfileStartChoice::Standalone { content } => (true, content),
    };

    // One transaction: insert the row and seed its content so a mid-sequence
    // failure leaves neither a row without its content nor orphaned content
    // pointing at a non-existent profile.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create profile (begin): {e}");
        ApiError::internal("failed to create profile")
    })?;
    let mut row = sqlx::query_as::<_, ProfileRow>(
        "INSERT INTO profiles (tenant_id, kind, name, description, is_default, standalone) \
         VALUES ($1, $2, $3, $4, false, $5) \
         RETURNING id, kind, name, description, is_default, standalone, model, created_at, updated_at",
    )
    .bind(tenant_id)
    .bind(kind.as_str())
    .bind(name)
    .bind(&req.description)
    .bind(standalone)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("a profile with this name already exists for this kind", ApiErrorCode::ProfileNameTaken)
        } else {
            tracing::error!("create profile: {e}");
            ApiError::internal("failed to create profile")
        }
    })?;

    // Initial content per the chosen start-from.
    let rule_count = match content {
        StartContent::Blank => 0,
        // A new profile is never the Default, so seeds are independent copies.
        StartContent::Seed => apply_profile_seed(&mut tx, tenant_id, kind, row.id, false).await?,
        StartContent::Copy { id: source_id } => {
            // The source must exist in this tenant and match the kind — else the
            // copy would silently produce an empty profile.
            ensure_profile_exists(&mut tx, *source_id, kind).await?;
            let copied = copy_profile_content(&mut tx, tenant_id, kind, *source_id, row.id).await?;
            // The judge model is profile config, not per-row content — carry
            // it on a copy so "copy of Default, change model" starts equal.
            if kind == ProfileKind::Expert {
                row.model = sqlx::query_scalar(
                    "UPDATE profiles SET model = (SELECT model FROM profiles WHERE id = $2) \
                     WHERE id = $1 RETURNING model",
                )
                .bind(row.id)
                .bind(source_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("create profile (copy model): {e}");
                    ApiError::internal("failed to create profile")
                })?;
            }
            copied
        }
    };
    tx.commit().await.map_err(|e| {
        tracing::error!("create profile (commit): {e}");
        ApiError::internal("failed to create profile")
    })?;

    Ok((StatusCode::CREATED, Json(Profile { profile: row, rule_count })))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Profile detail", body = Profile),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_profile(mut db: TenantConn, Path(id): Path<Uuid>) -> Result<Json<Profile>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let profile = sqlx::query_as::<_, ProfileRow>(
        "SELECT id, kind, name, description, is_default, standalone, model, created_at, updated_at \
         FROM profiles WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get profile: {e}");
        ApiError::internal("failed to load profile")
    })?
    .ok_or_else(|| ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound))?;

    let kind = ProfileKind::parse(&profile.kind);
    let rule_count = match kind {
        Some(k) => rule_count_for(db.conn(), tenant_id, k, id).await?,
        None => 0,
    };
    Ok(Json(Profile { profile, rule_count }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/profiles/{id}",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Profile id")),
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "Profile updated", body = ProfileRow),
        (status = 400, description = "The judge model is not one the agent can use", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_profile(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<ProfileRow>, ApiError> {
    // The judge model rides the expert kind only; clearing it back to
    // inherit is a non-default-profile action (the Default IS the base).
    if let Some(model) = &req.model {
        let target: Option<(String, bool, Option<String>)> =
            sqlx::query_as("SELECT kind, is_default, model FROM profiles WHERE id = $1")
                .bind(id)
                .fetch_optional(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!("update profile (kind check): {e}");
                    ApiError::internal("failed to update profile")
                })?;
        let Some((kind, is_default, stored)) = target else {
            return Err(ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound));
        };
        if kind != "expert" {
            return Err(ApiError::bad_request(
                "`model` applies only to expert profiles",
            )
            .code(ApiErrorCode::ProfileKindInvalid));
        }
        let cleared = model.as_deref().is_none_or(|m| m.trim().is_empty());
        if is_default && cleared {
            return Err(ApiError::bad_request(
                "the Default expert profile's model cannot be cleared — it is the base other profiles inherit",
            )
            .code(ApiErrorCode::SettingInvalid));
        }
        // Only a change is judged: a model whose grant was since revoked does
        // not block saving the rest of the profile.
        if let Some(model) = model.as_deref().map(str::trim).filter(|m| !m.is_empty())
            && stored.as_deref() != Some(model)
        {
            crate::routes::refuse_unusable_judge_model(db.conn(), model).await?;
        }
    }
    let row = sqlx::query_as::<_, ProfileRow>(
        "UPDATE profiles SET \
            name = COALESCE($2, name), \
            description = CASE WHEN $3 THEN $4 ELSE description END, \
            model = CASE WHEN $5 THEN NULLIF(TRIM($6), '') ELSE model END, \
            updated_at = now() \
         WHERE id = $1 \
         RETURNING id, kind, name, description, is_default, standalone, model, created_at, updated_at",
    )
    .bind(id)
    .bind(req.name.as_deref().map(str::trim))
    .bind(req.description.is_some())
    .bind(req.description.flatten())
    .bind(req.model.is_some())
    .bind(req.model.clone().flatten())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update profile: {e}");
        ApiError::internal("failed to update profile")
    })?
    .ok_or_else(|| ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/profiles/{id}",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Profile deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Default profile protected", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_profile(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    let row: Option<(bool, String)> =
        sqlx::query_as("SELECT is_default, kind FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("load profile: {e}");
                ApiError::internal("failed to load profile")
            })?;
    let Some((is_default, kind_str)) = row else {
        return Err(ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound));
    };
    if is_default {
        return Err(ApiError::conflict("the default profile cannot be deleted", ApiErrorCode::ProfileDefaultProtected));
    }
    let kind = parse_kind(&kind_str)?;

    // One transaction: drop the profile's per-kind content (the delete adapter)
    // then the row. Dependent assignments cascade (ON DELETE CASCADE), so
    // workspaces revert to the kind's default profile.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete profile (begin): {e}");
        ApiError::internal("failed to delete profile")
    })?;
    match kind {
        ProfileKind::Tools => {
            // This profile's own rules — additions and forks (a fork only means
            // something inside its profile) — are dropped by the
            // `tool_policy_rules.profile_id` FK (ON DELETE CASCADE) when the profile
            // row is deleted below. The Default profile's rules are untouched.
        }
        ProfileKind::Guardrail => {
            super::guardrail::remove_policy(&mut tx, tenant_id, id).await?;
        }
        ProfileKind::Transform => {
            // This profile's programs are dropped by the `transform_programs.profile_id`
            // FK (ON DELETE CASCADE) when the profile row is deleted below. The
            // Default profile's programs are untouched.
        }
        ProfileKind::Expert => {
            // Membership rows are dropped by the `expert_profile_members.profile_id`
            // FK (ON DELETE CASCADE) when the profile row is deleted below.
        }
        ProfileKind::ClientAccess => {
            // Its clients, destinations and settings are dropped by their
            // `profile_id` FKs (ON DELETE CASCADE) when the row is deleted below.
        }
    }
    sqlx::query("DELETE FROM profiles WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete profile: {e}");
            ApiError::internal("failed to delete profile")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("delete profile (commit): {e}");
        ApiError::internal("failed to delete profile")
    })?;

    Ok(Json(ActionResponse::ok().with_message("profile deleted")))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/profiles/{id}/actions/set-default",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Default set", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default_profile(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    let kind_str: Option<String> = sqlx::query_scalar("SELECT kind FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("load profile: {e}");
            ApiError::internal("failed to load profile")
        })?;
    let Some(kind_str) = kind_str else {
        return Err(ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound));
    };
    let kind = parse_kind(&kind_str)?;
    refuse_default_only(kind)?;

    // Clear the current default for this (tenant, kind) then set the new one, in
    // one transaction — the one-default partial-unique index forbids two defaults
    // existing at once, so the clear must land before the set.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("set default profile (begin): {e}");
        ApiError::internal("failed to set default profile")
    })?;

    // Absorb the old Default's content into the new one so the new Default is a
    // complete, self-contained base. For tools/transform this MOVES the rows
    // (keeping the canonical `rule_id`s / `is_builtin` so seed-sync keeps
    // refreshing builtins on the Default — the "builtins live on the Default"
    // invariant); for guardrail/expert it copies. Runs for any target (Layered or
    // Standalone) so the builtin home always follows the Default.
    let old_default = default_profile_id(&mut tx, tenant_id, kind).await?;
    if let Some(base_id) = old_default
        && base_id != id
    {
        absorb_base_into(&mut tx, tenant_id, kind, base_id, id).await?;
    }

    sqlx::query(
        "UPDATE profiles SET is_default = false, updated_at = now() \
         WHERE tenant_id = $1 AND kind = $2 AND is_default = true AND id <> $3",
    )
    .bind(tenant_id)
    .bind(&kind_str)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("clear default profile: {e}");
        ApiError::internal("failed to set default profile")
    })?;
    // Promote: the new Default is always standalone (it is the base).
    sqlx::query(
        "UPDATE profiles SET is_default = true, standalone = true, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("set default profile: {e}");
        ApiError::internal("failed to set default profile")
    })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("set default profile (commit): {e}");
        ApiError::internal("failed to set default profile")
    })?;

    Ok(Json(ActionResponse::ok().with_message("default profile set")))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/profiles/{id}/actions/reset-to-seed",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Profile reset to seed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_profile_to_seed(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let row: Option<(String, bool, bool)> =
        sqlx::query_as("SELECT kind, is_default, standalone FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("load profile: {e}");
                ApiError::internal("failed to load profile")
            })?;
    let Some((kind_str, is_default, standalone)) = row else {
        return Err(ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound));
    };
    let kind = parse_kind(&kind_str)?;
    // Reset-to-seed restores the built-in defaults, which is only well-defined for
    // a profile that OWNS its content — the Default base or a Standalone. A Layered
    // profile inherits the Default; seeding it would duplicate the built-ins on top.
    if !is_default && !standalone {
        return Err(ApiError::bad_request(
            "reset-to-seed applies only to the Default or a Standalone profile; a Layered \
             profile inherits the Default",
        )
        .code(ApiErrorCode::ValidationFailed));
    }

    // Restore the kind's seeded content onto this profile. For the Default that is
    // the pristine shared base (original ids, builtin); for a Standalone it is a
    // fresh independent copy of the built-in defaults.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("reset profile (begin): {e}");
        ApiError::internal("failed to reset profile")
    })?;
    let count = apply_profile_seed(&mut tx, tenant_id, kind, id, is_default).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("reset profile (commit): {e}");
        ApiError::internal("failed to reset profile")
    })?;

    Ok(Json(
        ActionResponse::ok()
            .with_message("profile reset to seed")
            .with_impact(super::ActionImpact { items_restored: Some(count), ..Default::default() }),
    ))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn profiles_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/", get(list_profiles).post(create_profile))
        .route(
            "/{id}",
            get(get_profile).patch(update_profile).delete(delete_profile),
        )
        .route("/{id}/actions/set-default", post(set_default_profile))
        .route("/{id}/actions/reset-to-seed", post(reset_profile_to_seed))
        .route(
            "/{id}/analysis-start",
            get(super::expert_profiles::get_analysis_start),
        )
        .route(
            "/{id}/actions/set-analysis-start",
            post(super::expert_profiles::set_analysis_start),
        )
        // Per-profile guardrail policy sub-resource (content owned by the
        // guardrail module, validation reused).
        .route(
            "/{id}/guardrail",
            get(super::guardrail::get_profile_guardrail_policy)
                .patch(super::guardrail::update_profile_guardrail_policy),
        )
        // Per-profile expert membership sub-resource (content owned by the
        // expert_profiles module — which experts the profile enables).
        .route(
            "/{id}/expert",
            get(super::expert_profiles::get_profile_expert_membership)
                .put(super::expert_profiles::update_profile_expert_membership),
        )
        // Per-profile client access (content owned by client_access_profiles:
        // the clients offered, the sandbox's destinations and settings).
        .route(
            "/{id}/client-access",
            get(super::client_access_profiles::get_profile_client_access)
                .patch(super::client_access_profiles::update_profile_client_access),
        )
        .route(
            "/{id}/actions/attach-developer-defaults",
            post(super::client_access_profiles::attach_developer_defaults),
        )
}
