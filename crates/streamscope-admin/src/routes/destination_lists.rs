//! Destination lists — a tenant's named sets of network destinations
//! (`destination_lists`), which a consumer attaches as **allow** or **block**:
//! the sandbox through a client-access profile (`client_access_destinations`),
//! the built-in Web tool through `web_destination_lists`.
//!
//! * `GET    /api/v1/admin/destination-lists`               — list (paginated).
//! * `POST   /api/v1/admin/destination-lists`               — create.
//! * `GET    /api/v1/admin/destination-lists/{id}`          — read one.
//! * `PATCH  /api/v1/admin/destination-lists/{id}`          — partial update; an
//!   edit of a seeded list flips `is_builtin = false`, so seed sync stops
//!   overwriting it.
//! * `DELETE /api/v1/admin/destination-lists/{id}`          — a list that came
//!   from the seed is hidden (`suppressed`), any other removed; either way it
//!   is detached from every consumer.
//! * `POST   /api/v1/admin/destination-lists/{id}/actions/reset` — restore a
//!   seeded list from the seed.
//! * `POST   /api/v1/admin/destination-lists/actions/reset` — restore every
//!   seeded list, deleted ones included.
//!
//! Entries are validated and stored in canonical form
//! (`streamscope_client_templates::destination`). A list is not the platform's egress
//! list and never widens it.

use std::collections::HashSet;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use streamscope_client_templates::destination::DestinationSet;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionImpact, ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};
use crate::seed_loader::{DestinationListSeed, SeedLoader};

/// The longest list name.
const MAX_NAME_LEN: usize = 100;
/// The longest list description.
const MAX_DESCRIPTION_LEN: usize = 1000;

/// How a consumer reads an attached list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DestinationMode {
    /// The consumer may reach these.
    Allow,
    /// The consumer never reaches these, even where an allowed list matches.
    Block,
}

impl DestinationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DestinationMode::Allow => "allow",
            DestinationMode::Block => "block",
        }
    }

    /// The stored form; `None` for a value the column's check refuses.
    pub fn parse(s: &str) -> Option<DestinationMode> {
        match s {
            "allow" => Some(DestinationMode::Allow),
            "block" => Some(DestinationMode::Block),
            _ => None,
        }
    }
}

/// Which consumer attaches a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DestinationConsumer {
    /// The developers' sandbox, through a client-access profile.
    Sandbox,
    /// The built-in Web tool.
    Web,
}

/// One place a list is attached.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DestinationListUse {
    pub consumer: DestinationConsumer,
    pub mode: DestinationMode,
    /// The client-access profile attaching it (`sandbox` only).
    pub profile_id: Option<Uuid>,
}

/// A destination list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DestinationList {
    pub id: Uuid,
    /// The seed's handle for a seeded list; `null` on a list an admin created.
    pub seed_key: Option<String>,
    pub name: String,
    pub description: String,
    /// Canonical entries: `<target>:<ports>`.
    pub entries: Vec<String>,
    /// `true` while a seeded list is as the seed ships it.
    pub is_builtin: bool,
    /// The list came from the seed (a reset can restore it).
    pub seeded: bool,
    /// Where the list is attached.
    pub used_by: Vec<DestinationListUse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct ListRow {
    id: Uuid,
    seed_key: Option<String>,
    name: String,
    description: String,
    entries: serde_json::Value,
    is_builtin: bool,
    seeded: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ListRow {
    fn into_list(self, used_by: Vec<DestinationListUse>) -> DestinationList {
        DestinationList {
            id: self.id,
            seed_key: self.seed_key,
            name: self.name,
            description: self.description,
            entries: stored_entries(self.entries),
            is_builtin: self.is_builtin,
            seeded: self.seeded,
            used_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// The stored entries column as strings. The write paths store only a JSON
/// array of canonical strings; anything else reads as no entries.
pub(crate) fn stored_entries(v: serde_json::Value) -> Vec<String> {
    serde_json::from_value(v).unwrap_or_default()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDestinationListRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Entries, one destination each: a host name, `*.suffix`, an IP address
    /// or a CIDR prefix, then optionally `:` and ports (`443,8000-8100`;
    /// `443` when absent).
    pub entries: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDestinationListRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// The full new entry set.
    #[serde(default)]
    pub entries: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/destination-lists",
    tag = "Destination Lists",
    params(PageQuery),
    responses(
        (status = 200, description = "The tenant's destination lists", body = OffsetPage<DestinationList>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<DestinationList>>, ApiError> {
    let (limit, offset) = page.resolve();
    let rows: Vec<ListRow> =
        sqlx::query_as(
        "SELECT id, seed_key, name, description, entries, is_builtin, seeded, created_at, updated_at \
         FROM destination_lists WHERE NOT suppressed ORDER BY name, id LIMIT $1 OFFSET $2",
    )
            .bind(limit + 1)
            .bind(offset)
            .fetch_all(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("list destination lists: {e}");
                ApiError::internal("failed to list destination lists")
            })?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut uses = load_uses(db.conn(), &ids).await?;
    let items = rows
        .into_iter()
        .map(|r| {
            let used_by = uses.remove(&r.id).unwrap_or_default();
            r.into_list(used_by)
        })
        .collect();
    Ok(Json(OffsetPage::from_overfetched(items, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/destination-lists/{id}",
    tag = "Destination Lists",
    params(("id" = Uuid, Path, description = "Destination list id")),
    responses(
        (status = 200, description = "The destination list", body = DestinationList),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_one(mut db: TenantConn, Path(id): Path<Uuid>) -> Result<Json<DestinationList>, ApiError> {
    Ok(Json(load_one(db.conn(), id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/destination-lists",
    tag = "Destination Lists",
    request_body = CreateDestinationListRequest,
    responses(
        (status = 201, description = "Created", body = DestinationList),
        (status = 400, description = "An entry or the name is invalid", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create(
    mut db: TenantConn,
    Json(req): Json<CreateDestinationListRequest>,
) -> Result<(StatusCode, Json<DestinationList>), ApiError> {
    let name = valid_name(&req.name)?;
    let description = valid_description(&req.description)?;
    let entries = canonical_entries(&req.entries)?;
    let row: ListRow = sqlx::query_as(
        "INSERT INTO destination_lists (tenant_id, name, description, entries) VALUES ($1, $2, $3, $4) \
         RETURNING id, seed_key, name, description, entries, is_builtin, seeded, created_at, updated_at",
    )
    .bind(db.tenant_uuid())
    .bind(name)
    .bind(description)
    .bind(serde_json::json!(entries))
    .fetch_one(db.conn())
    .await
    .map_err(name_conflict("create destination list"))?;
    Ok((StatusCode::CREATED, Json(row.into_list(Vec::new()))))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/destination-lists/{id}",
    tag = "Destination Lists",
    params(("id" = Uuid, Path, description = "Destination list id")),
    request_body = UpdateDestinationListRequest,
    responses(
        (status = 200, description = "Updated", body = DestinationList),
        (status = 400, description = "An entry or the name is invalid", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDestinationListRequest>,
) -> Result<Json<DestinationList>, ApiError> {
    let name = req.name.as_deref().map(valid_name).transpose()?;
    let description = req.description.as_deref().map(valid_description).transpose()?;
    let entries = req.entries.as_deref().map(canonical_entries).transpose()?;
    // A field written with a different value makes the list the admin's own:
    // seed sync stops rewriting it. A save that changes nothing keeps it the
    // seed's (`is_builtin` is read before the SET, on the old row).
    let updated: Option<Uuid> = sqlx::query_scalar(
        "UPDATE destination_lists SET \
           name = COALESCE($2, name), \
           description = COALESCE($3, description), \
           entries = COALESCE($4, entries), \
           is_builtin = is_builtin AND COALESCE($2, name) = name AND COALESCE($3, description) = description \
             AND COALESCE($4, entries) = entries, \
           updated_at = now() \
         WHERE id = $1 AND NOT suppressed RETURNING id",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(entries.map(|e| serde_json::json!(e)))
    .fetch_optional(db.conn())
    .await
    .map_err(name_conflict("update destination list"))?;
    if updated.is_none() {
        return Err(not_found());
    }
    Ok(Json(load_one(db.conn(), id).await?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/destination-lists/{id}",
    tag = "Destination Lists",
    params(("id" = Uuid, Path, description = "Destination list id")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "The Web tool's only allowed list", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete(mut db: TenantConn, Path(id): Path<Uuid>) -> Result<Json<ActionResponse>, ApiError> {
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete destination list (begin): {e}");
        ApiError::internal("failed to delete destination list")
    })?;
    // The Web tool's last allowed list is not deleted: without it the Web tool
    // passes every public site, the opposite of what the admin set. Detaching
    // it (the Web tab) is that choice, made where it shows. The list is locked
    // first, against an attach in flight (`validate_attachments` share-locks
    // it), then the Web tool's attachments, so two deletes cannot each see the
    // other's list still attached.
    sqlx::query("SELECT 1 FROM destination_lists WHERE id = $1 FOR UPDATE")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete destination list (lock): {e}");
            ApiError::internal("failed to delete destination list")
        })?;
    sqlx::query("SELECT 1 FROM web_destination_lists FOR UPDATE")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete destination list (lock web attachments): {e}");
            ApiError::internal("failed to delete destination list")
        })?;
    let last_web_allow: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM web_destination_lists WHERE list_id = $1 AND mode = 'allow') \
           AND NOT EXISTS (SELECT 1 FROM web_destination_lists WHERE list_id <> $1 AND mode = 'allow')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("delete destination list (web allow check): {e}");
        ApiError::internal("failed to delete destination list")
    })?;
    if last_web_allow {
        return Err(ApiError::conflict(
            "this is the Web tool's only allowed destination list: detach it from the Web tool first",
            ApiErrorCode::DestinationListInUse,
        ));
    }
    // A hidden seeded list keeps its row, so its attachments are removed here;
    // a removed list's would go with it (ON DELETE CASCADE) — detached here
    // either way, so the answer can say how many uses it had.
    let mut detached = 0u64;
    for detach in [
        "DELETE FROM client_access_destinations WHERE list_id = $1",
        "DELETE FROM web_destination_lists WHERE list_id = $1",
    ] {
        detached += sqlx::query(detach).bind(id).execute(&mut *tx).await.map_err(|e| {
            tracing::error!("delete destination list (detach): {e}");
            ApiError::internal("failed to delete destination list")
        })?.rows_affected();
    }
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE destination_lists SET suppressed = true, updated_at = now() \
           WHERE id = $1 AND NOT suppressed AND seeded RETURNING 1), \
         removed AS ( \
           DELETE FROM destination_lists WHERE id = $1 AND NOT suppressed AND NOT seeded RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("delete destination list: {e}");
        ApiError::internal("failed to delete destination list")
    })?;
    if acted == 0 {
        return Err(not_found());
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("delete destination list (commit): {e}");
        ApiError::internal("failed to delete destination list")
    })?;
    Ok(Json(ActionResponse::ok().with_message(match detached {
        0 => "Destination list deleted.".to_string(),
        n => format!("Destination list deleted and detached from {n} use(s)."),
    })))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/destination-lists/{id}/actions/reset",
    tag = "Destination Lists",
    params(("id" = Uuid, Path, description = "Destination list id")),
    responses(
        (status = 200, description = "Restored from the seed", body = DestinationList),
        (status = 404, description = "Not found, or not a seeded list the seed still ships", body = ApiErrorResponse),
        (status = 409, description = "Another list holds the seed's name", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset(mut db: TenantConn, Path(id): Path<Uuid>) -> Result<Json<DestinationList>, ApiError> {
    let key: Option<String> =
        sqlx::query_scalar("SELECT seed_key FROM destination_lists WHERE id = $1 AND NOT suppressed")
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("reset destination list (lookup): {e}");
                ApiError::internal("failed to reset destination list")
            })?
            .flatten();
    let seed = key
        .and_then(|k| SeedLoader::new().load_destination_lists().into_iter().find(|s| s.key == k))
        .ok_or_else(not_found)?;
    let tenant_id = db.tenant_uuid();
    restore_seed(db.conn(), tenant_id, &seed).await?;
    Ok(Json(load_one(db.conn(), id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/destination-lists/actions/reset",
    tag = "Destination Lists",
    responses(
        (status = 200, description = "Every seeded list restored", body = ActionResponse),
        (status = 409, description = "Another list holds a seed's name", body = ApiErrorResponse),
        (status = 500, description = "No seeded lists on disk", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// Restore every seeded list from the seed, forced over an admin's edit and
/// bringing back a deleted one. A list an admin created is kept.
pub async fn reset_all(mut db: TenantConn) -> Result<Json<ActionResponse>, ApiError> {
    let seeds = SeedLoader::new().load_destination_lists();
    if seeds.is_empty() {
        tracing::error!("destination lists reset: no seeded lists on disk");
        return Err(ApiError::internal("no seeded destination lists on disk"));
    }
    let tenant_id = db.tenant_uuid();
    let keys: Vec<String> = seeds.iter().map(|s| s.key.clone()).collect();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("destination lists reset (begin): {e}");
        ApiError::internal("failed to reset destination lists")
    })?;
    let cleared: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM destination_lists WHERE suppressed AND seed_key = ANY($1)",
    )
    .bind(&keys)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("destination lists reset (count): {e}");
        ApiError::internal("failed to reset destination lists")
    })?;
    for seed in &seeds {
        restore_seed(&mut tx, tenant_id, seed).await?;
    }
    let preserved: i64 = sqlx::query_scalar("SELECT count(*) FROM destination_lists WHERE seed_key IS NULL")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("destination lists reset (count custom): {e}");
            ApiError::internal("failed to reset destination lists")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("destination lists reset (commit): {e}");
        ApiError::internal("failed to reset destination lists")
    })?;
    Ok(Json(ActionResponse::ok().with_message("Seeded destination lists restored.").with_impact(ActionImpact {
        builtins_restored: Some(seeds.len()),
        custom_preserved: Some(preserved as usize),
        deleted_builtins_cleared: Some(cleared as usize),
        ..Default::default()
    })))
}

// ---------------------------------------------------------------------------
// The Web tool's attachments
// ---------------------------------------------------------------------------

/// The lists attached to the Web tool, each with its name.
pub(crate) async fn web_attachments(
    conn: &mut Scoped,
) -> Result<Vec<super::client_access_profiles::AttachedDestinationList>, ApiError> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT l.id, l.name, w.mode FROM web_destination_lists w \
         JOIN destination_lists l ON l.id = w.list_id AND NOT l.suppressed ORDER BY l.name, l.id",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load web destination lists: {e}");
        ApiError::internal("failed to load web destination lists")
    })?;
    Ok(rows
        .into_iter()
        .filter_map(|(list_id, name, mode)| {
            Some(super::client_access_profiles::AttachedDestinationList {
                list_id,
                name,
                mode: DestinationMode::parse(&mode)?,
            })
        })
        .collect())
}

/// Replace the Web tool's attachments, inside the caller's transaction.
pub(crate) async fn set_web_attachments(
    conn: &mut Scoped,
    tenant_id: Uuid,
    attachments: &[super::client_access_profiles::DestinationAttachment],
) -> Result<(), ApiError> {
    validate_attachments(conn, attachments).await?;
    let fail = |e: sqlx::Error| {
        tracing::error!("write web destination lists: {e}");
        ApiError::internal("failed to update web destination lists")
    };
    let ids: Vec<Uuid> = attachments.iter().map(|a| a.list_id).collect();
    sqlx::query("DELETE FROM web_destination_lists WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(fail)?;
    let modes: Vec<&str> = attachments.iter().map(|a| a.mode.as_str()).collect();
    sqlx::query(
        "INSERT INTO web_destination_lists (tenant_id, list_id, mode) \
         SELECT $1, l, m FROM unnest($2::uuid[], $3::text[]) AS a(l, m)",
    )
    .bind(tenant_id)
    .bind(&ids)
    .bind(&modes)
    .execute(&mut *conn)
    .await
    .map_err(fail)?;
    Ok(())
}

/// A consumer's new attachments: each list once, every one a live list. The
/// lists are share-locked until the caller's transaction ends, so a concurrent
/// delete (which locks its list first) either finishes before — and the list
/// is no longer live here — or waits and then sees the attachment.
pub(crate) async fn validate_attachments(
    conn: &mut Scoped,
    attachments: &[super::client_access_profiles::DestinationAttachment],
) -> Result<(), ApiError> {
    let mut unique: Vec<Uuid> = attachments.iter().map(|a| a.list_id).collect();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != attachments.len() {
        return Err(ApiError::bad_request("a destination list is attached once, as allow or as block")
            .code(ApiErrorCode::ValidationFailed));
    }
    let live: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM destination_lists WHERE id = ANY($1) AND NOT suppressed FOR SHARE")
            .bind(&unique)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("validate destination lists: {e}");
                ApiError::internal("failed to validate destination lists")
            })?;
    if live.len() != unique.len() {
        return Err(ApiError::bad_request("one or more destination lists do not exist")
            .code(ApiErrorCode::DestinationListNotFound));
    }
    Ok(())
}

/// The Web tool's attached lists as the config body carries them: every
/// attached list's canonical entries, flattened by mode.
pub(crate) async fn web_lists(conn: &mut Scoped) -> Result<streamscope_core::web::WebDestinationLists, sqlx::Error> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT w.mode, l.entries FROM web_destination_lists w \
         JOIN destination_lists l ON l.id = w.list_id AND NOT l.suppressed ORDER BY l.name, l.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let flat = Flattened::from_rows(rows);
    Ok(streamscope_core::web::WebDestinationLists {
        allow: flat.allow,
        block: flat.block,
        allow_attached: flat.allow_attached,
    })
}

/// A consumer's attached lists, flattened by mode: each mode's entries in
/// list order, duplicates removed. The stored entries are canonical and
/// passed on as they are; the consumer decides what to do with one it cannot
/// read.
pub(crate) struct Flattened {
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// A list is attached as allow, even one with no entries — "only these",
    /// which an empty `allow` alone cannot say.
    pub allow_attached: bool,
}

impl Flattened {
    /// `rows`: `(mode, entries)` per attached list.
    pub(crate) fn from_rows(rows: Vec<(String, serde_json::Value)>) -> Self {
        let mut out = Flattened { allow: Vec::new(), block: Vec::new(), allow_attached: false };
        let (mut seen_allow, mut seen_block) = (HashSet::new(), HashSet::new());
        for (mode, entries) in rows {
            let (into, seen) = match DestinationMode::parse(&mode) {
                Some(DestinationMode::Allow) => {
                    out.allow_attached = true;
                    (&mut out.allow, &mut seen_allow)
                }
                Some(DestinationMode::Block) => (&mut out.block, &mut seen_block),
                None => continue,
            };
            for e in stored_entries(entries) {
                if seen.insert(e.clone()) {
                    into.push(e);
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn not_found() -> ApiError {
    ApiError::not_found("destination list not found", ApiErrorCode::DestinationListNotFound)
}

fn name_conflict(what: &'static str) -> impl Fn(sqlx::Error) -> ApiError {
    move |e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("a destination list with this name already exists", ApiErrorCode::DestinationListNameTaken)
        } else {
            tracing::error!("{what}: {e}");
            ApiError::internal("failed to write destination list")
        }
    }
}

fn valid_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::bad_request(format!("a name is 1 to {MAX_NAME_LEN} characters"))
            .code(ApiErrorCode::ValidationFailed));
    }
    Ok(name)
}

fn valid_description(description: &str) -> Result<&str, ApiError> {
    let description = description.trim();
    if description.chars().count() > MAX_DESCRIPTION_LEN {
        return Err(ApiError::bad_request(format!("a description is at most {MAX_DESCRIPTION_LEN} characters"))
            .code(ApiErrorCode::ValidationFailed));
    }
    Ok(description)
}

/// Every entry validated, in canonical form, duplicates removed.
pub(crate) fn canonical_entries(entries: &[String]) -> Result<Vec<String>, ApiError> {
    DestinationSet::parse(entries)
        .map(|set| set.canonical())
        .map_err(|e| ApiError::bad_request(e.to_string()).code(ApiErrorCode::DestinationEntryInvalid))
}

async fn load_one(conn: &mut Scoped, id: Uuid) -> Result<DestinationList, ApiError> {
    let row: ListRow = sqlx::query_as(
        "SELECT id, seed_key, name, description, entries, is_builtin, seeded, created_at, updated_at \
         FROM destination_lists WHERE id = $1 AND NOT suppressed",
    )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("load destination list: {e}");
            ApiError::internal("failed to load destination list")
        })?
        .ok_or_else(not_found)?;
    let used_by = load_uses(conn, &[id]).await?.remove(&id).unwrap_or_default();
    Ok(row.into_list(used_by))
}

/// Where each of `ids` is attached.
async fn load_uses(
    conn: &mut Scoped,
    ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, Vec<DestinationListUse>>, ApiError> {
    let rows: Vec<(Uuid, String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT list_id, 'sandbox', mode, profile_id FROM client_access_destinations WHERE list_id = ANY($1) \
         UNION ALL \
         SELECT list_id, 'web', mode, NULL FROM web_destination_lists WHERE list_id = ANY($1) \
         ORDER BY 1, 2, 4",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load destination list uses: {e}");
        ApiError::internal("failed to load destination lists")
    })?;
    let mut out: std::collections::HashMap<Uuid, Vec<DestinationListUse>> = std::collections::HashMap::new();
    for (list_id, consumer, mode, profile_id) in rows {
        let Some(mode) = DestinationMode::parse(&mode) else { continue };
        let consumer = if consumer == "web" { DestinationConsumer::Web } else { DestinationConsumer::Sandbox };
        out.entry(list_id).or_default().push(DestinationListUse { consumer, mode, profile_id });
    }
    Ok(out)
}

/// Write a seeded list back as the seed ships it — builtin, visible — forced
/// over an admin's edit. A list an admin created under the seed's name is a
/// 409: the seed is not written over it.
async fn restore_seed(conn: &mut Scoped, tenant_id: Uuid, seed: &DestinationListSeed) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO destination_lists (tenant_id, seed_key, name, description, entries, is_builtin, suppressed) \
         VALUES ($1, $2, $3, $4, $5, true, false) \
         ON CONFLICT (tenant_id, seed_key) DO UPDATE SET \
           name = EXCLUDED.name, description = EXCLUDED.description, entries = EXCLUDED.entries, \
           is_builtin = true, suppressed = false, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(&seed.key)
    .bind(&seed.name)
    .bind(&seed.description)
    .bind(serde_json::json!(seed.entries))
    .execute(&mut *conn)
    .await
    .map_err(name_conflict("restore destination list"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_destination_matcher_and_the_ssrf_guard_agree_on_the_metadata_address() {
        use std::net::IpAddr;
        let probes = [
            "169.254.169.254", "169.254.169.253", "169.254.169.255", "fd00:ec2::254", "fd00:ec2::253",
            "::ffff:169.254.169.254", "::169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b::a9fe:a9fd",
            "2002:a9fe:a9fe::", "2002:a9fe:a9fd::", "10.0.0.1", "::1",
        ];
        for p in probes {
            let ip: IpAddr = p.parse().unwrap();
            assert_eq!(
                streamscope_client_templates::destination::is_imds_ip(ip),
                streamscope_mcp_auth::ssrf::is_imds_ip(ip),
                "{p}"
            );
        }
    }

    #[test]
    fn a_bad_entry_is_refused_with_its_code() {
        let err = canonical_entries(&["github.com".into(), "*".into()]).unwrap_err();
        assert_eq!(err.code, ApiErrorCode::DestinationEntryInvalid);
        assert!(err.message.contains("entry 1"), "{}", err.message);
        assert_eq!(canonical_entries(&["GitHub.com".into(), "github.com.".into()]).unwrap(), vec!["github.com"]);
    }

    #[test]
    fn a_name_is_bounded_on_both_sides() {
        assert!(valid_name("  ").is_err());
        assert!(valid_name(&"n".repeat(MAX_NAME_LEN)).is_ok());
        assert!(valid_name(&"n".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(valid_description(&"d".repeat(MAX_DESCRIPTION_LEN)).is_ok());
        assert!(valid_description(&"d".repeat(MAX_DESCRIPTION_LEN + 1)).is_err());
    }
}
