//! Model catalog management.
//!
//! CRUD for catalog entries (per-model metadata: the published price list,
//! capabilities, context window, deprecation date). Entries can be global (all
//! servers) or server-specific. Changes trigger config sync so edge proxies
//! receive updated catalog data for cost calculation.


use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use streamscope_core::pricing::{Rate, Rates};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionImpact, ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::{Scoped, TenantConn};

/// Common SELECT column list for catalog queries (joined with upstream_servers for server_name).
const CATALOG_SELECT_COLS: &str = r#"
    p.id, p.server_id, p.is_builtin, p.provider, p.model,
    p.rates,
    p.context_window, p.max_output_tokens,
    p.supports_caching, p.supports_reasoning, p.supports_vision, p.supports_function_calling,
    p.supports_audio_input, p.supports_audio_output, p.supports_video_input,
    p.supports_pdf_input, p.supports_response_schema, p.supports_system_messages,
    p.deprecation_date, p.model_type, p.output_vector_size,
    p.updated_at, s.name as server_name
"#;

/// Reject a price the gateway could never bill honestly, before it reaches the
/// database. A negative rate credits the tenant on every request against the
/// model, and a non-finite one poisons every total it is summed into — neither
/// is recoverable once audit rows have been written against it.
fn validate_rates(rates: &Rates) -> Result<(), ApiError> {
    fn bad(r: f64) -> bool {
        !r.is_finite() || r < 0.0
    }
    for (unit, rate) in &rates.units {
        let offending = match rate {
            Rate::Flat(r) => bad(*r),
            Rate::Tiered { rate, tiers } => bad(*rate) || tiers.iter().any(|t| bad(t.rate)),
        };
        if offending {
            return Err(ApiError::bad_request(format!(
                "rate for {} must be a non-negative number",
                unit.wire()
            ))
            .code(ApiErrorCode::PriceNegative));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct CatalogEntry {
    pub id: Uuid,
    pub server_id: Option<Uuid>,
    #[serde(default)]
    #[sqlx(default)]
    pub is_builtin: bool,
    pub provider: String,
    pub model: String,
    /// Price per billing unit, plus the currency those prices are quoted in.
    /// Rates are in each unit's natural scale — per million for token units, per
    /// single unit otherwise.
    ///
    /// An empty map means no price is on file: the request is billed at a floor
    /// of zero **and** badged, which stays distinct from a rate of `0`, meaning
    /// the model is genuinely free. A catalog entry that carries only
    /// capabilities (context window, modality support) legitimately has one.
    #[serde(default = "Rates::unknown")]
    #[sqlx(json)]
    pub rates: Rates,
    #[serde(default)]
    #[sqlx(default)]
    pub context_window: Option<i32>,
    #[serde(default)]
    #[sqlx(default)]
    pub max_output_tokens: Option<i32>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_caching: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_function_calling: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_audio_input: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_audio_output: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_video_input: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_pdf_input: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_response_schema: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub supports_system_messages: Option<bool>,
    #[serde(default)]
    #[sqlx(default)]
    pub deprecation_date: Option<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub model_type: Option<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub output_vector_size: Option<i32>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(default)]
    pub server_name: Option<String>,
}

/// Input for create: `provider` and `model` are required; everything else is
/// optional. An update takes [`UpdateCatalogEntry`].
#[derive(Debug, Deserialize, ToSchema)]
pub struct CatalogInput {
    /// NULL = global entry for this model (applies to all servers).
    #[serde(default)]
    pub server_id: Option<Uuid>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// The whole price list, replaced as one atom — the prices and the currency
    /// they are quoted in are one provider's quote and are never merged
    /// field-by-field. Absent means no price is known, which the gateway badges
    /// rather than reporting as free.
    #[serde(default)]
    pub rates: Option<Rates>,
    #[serde(default)]
    pub model_type: Option<String>,
    #[serde(default)]
    pub context_window: Option<i32>,
    #[serde(default)]
    pub max_output_tokens: Option<i32>,
    #[serde(default)]
    pub supports_caching: Option<bool>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    pub supports_function_calling: Option<bool>,
    #[serde(default)]
    pub supports_audio_input: Option<bool>,
    #[serde(default)]
    pub supports_audio_output: Option<bool>,
    #[serde(default)]
    pub supports_video_input: Option<bool>,
    #[serde(default)]
    pub supports_pdf_input: Option<bool>,
    #[serde(default)]
    pub supports_response_schema: Option<bool>,
    #[serde(default)]
    pub supports_system_messages: Option<bool>,
    #[serde(default)]
    pub output_vector_size: Option<i32>,
    #[serde(default)]
    pub deprecation_date: Option<String>,
}


/// A partial update to one catalog entry. Absent leaves a field as stored.
/// Every capability is three-state: `null` clears it back to unknown, which
/// lets the resolver fall back to another provider's entry rather than read a
/// claim nobody made.
#[derive(Deserialize, ToSchema)]
pub struct UpdateCatalogEntry {
    /// The whole price list, replaced as one atom; absent leaves the stored map
    /// untouched and `{}` says no price is known.
    #[serde(default)]
    pub rates: Option<Rates>,
    #[serde(default)]
    pub model_type: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub context_window: Option<Option<i32>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub max_output_tokens: Option<Option<i32>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_caching: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_reasoning: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_vision: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_function_calling: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_audio_input: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_audio_output: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_video_input: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_pdf_input: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_response_schema: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<bool>)]
    pub supports_system_messages: Option<Option<bool>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub output_vector_size: Option<Option<i32>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub deprecation_date: Option<Option<String>>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/catalog",
    tag = "Model Catalog",
    request_body = CatalogInput,
    responses(
        (status = 201, description = "Catalog entry created", body = CatalogEntry),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_catalog_entry(
    mut db: TenantConn,
    Json(req): Json<CatalogInput>,
) -> Result<(StatusCode, Json<CatalogEntry>), ApiError> {
    let provider = req.provider.as_deref().unwrap_or("");
    let model = req.model.as_deref().unwrap_or("");

    if provider.is_empty() || model.is_empty() {
        return Err(ApiError::bad_request("provider and model are required"));
    }
    // No rate map means no price is known for this model — an entry created for
    // its capabilities alone. The gateway badges that traffic rather than
    // reporting it as free, so it needs no separate "price required" rule.
    let rates = req.rates.clone().unwrap_or_else(Rates::unknown);
    validate_rates(&rates)?;

    // A server-scoped entry must name a server of THIS tenant. Postgres enforces
    // the foreign key above RLS, so it would accept another tenant's server id
    // and leave behind a row that can never resolve — the scope tier matches on
    // the model's own server, which is never that one.
    if let Some(server_id) = req.server_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM upstream_servers WHERE id = $1)")
            .bind(server_id)
            .fetch_one(db.conn())
            .await
            .map_err(catalog_db_error)?;
        if !exists {
            return Err(ApiError::bad_request("server_id does not name a server of this tenant")
                .code(ApiErrorCode::ServerNotFound));
        }
    }

    let row = if let Some(server_id) = req.server_id {
        let sql = format!(
            r#"WITH upserted AS (
                INSERT INTO model_catalog (server_id, provider, model, rates,
                    context_window, max_output_tokens,
                    supports_caching, supports_reasoning, supports_vision, supports_function_calling,
                    supports_audio_input, supports_audio_output, supports_video_input,
                    supports_pdf_input, supports_response_schema, supports_system_messages,
                    deprecation_date, model_type, output_vector_size, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                        $17, $18, $19, $20)
                ON CONFLICT (tenant_id, server_id, provider_key, model)
                DO UPDATE SET
                    rates = EXCLUDED.rates,
                    context_window = EXCLUDED.context_window,
                    max_output_tokens = EXCLUDED.max_output_tokens,
                    supports_caching = EXCLUDED.supports_caching,
                    supports_reasoning = EXCLUDED.supports_reasoning,
                    supports_vision = EXCLUDED.supports_vision,
                    supports_function_calling = EXCLUDED.supports_function_calling,
                    supports_audio_input = EXCLUDED.supports_audio_input,
                    supports_audio_output = EXCLUDED.supports_audio_output,
                    supports_video_input = EXCLUDED.supports_video_input,
                    supports_pdf_input = EXCLUDED.supports_pdf_input,
                    supports_response_schema = EXCLUDED.supports_response_schema,
                    supports_system_messages = EXCLUDED.supports_system_messages,
                    deprecation_date = EXCLUDED.deprecation_date,
                    model_type = EXCLUDED.model_type,
                    output_vector_size = EXCLUDED.output_vector_size,
                    is_builtin = false,
                    suppressed = false,
                    updated_at = NOW()
                RETURNING *
            )
            SELECT {CATALOG_SELECT_COLS}
            FROM upserted p
            LEFT JOIN upstream_servers s ON s.id = p.server_id"#
        );
        sqlx::query_as::<_, CatalogEntry>(sqlx::AssertSqlSafe(&*sql))
            .bind(server_id)               // $1
            .bind(provider)                // $2
            .bind(model)                   // $3
            .bind(sqlx::types::Json(&rates)) // $4
            .bind(req.context_window)       // $5
            .bind(req.max_output_tokens)    // $6
            .bind(req.supports_caching)     // $7
            .bind(req.supports_reasoning)   // $8
            .bind(req.supports_vision)      // $9
            .bind(req.supports_function_calling) // $10
            .bind(req.supports_audio_input) // $11
            .bind(req.supports_audio_output) // $12
            .bind(req.supports_video_input) // $13
            .bind(req.supports_pdf_input)   // $14
            .bind(req.supports_response_schema) // $15
            .bind(req.supports_system_messages) // $16
            .bind(&req.deprecation_date)    // $17
            .bind(&req.model_type)          // $18
            .bind(req.output_vector_size)   // $19
            .bind(db.tenant_uuid())         // $20
            .fetch_one(db.conn())
            .await
    } else {
        let sql = format!(
            r#"WITH upserted AS (
                INSERT INTO model_catalog (provider, model, rates,
                    context_window, max_output_tokens,
                    supports_caching, supports_reasoning, supports_vision, supports_function_calling,
                    supports_audio_input, supports_audio_output, supports_video_input,
                    supports_pdf_input, supports_response_schema, supports_system_messages,
                    deprecation_date, model_type, output_vector_size, tenant_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                       $17, $18, $19)
               ON CONFLICT (tenant_id, server_id, provider_key, model)
               DO UPDATE SET
                   rates = EXCLUDED.rates,
                   context_window = EXCLUDED.context_window,
                   max_output_tokens = EXCLUDED.max_output_tokens,
                   supports_caching = EXCLUDED.supports_caching,
                   supports_reasoning = EXCLUDED.supports_reasoning,
                   supports_vision = EXCLUDED.supports_vision,
                   supports_function_calling = EXCLUDED.supports_function_calling,
                   supports_audio_input = EXCLUDED.supports_audio_input,
                   supports_audio_output = EXCLUDED.supports_audio_output,
                   supports_video_input = EXCLUDED.supports_video_input,
                   supports_pdf_input = EXCLUDED.supports_pdf_input,
                   supports_response_schema = EXCLUDED.supports_response_schema,
                   supports_system_messages = EXCLUDED.supports_system_messages,
                   deprecation_date = EXCLUDED.deprecation_date,
                   model_type = EXCLUDED.model_type,
                   output_vector_size = EXCLUDED.output_vector_size,
                   is_builtin = false,
                   suppressed = false,
                   updated_at = NOW()
               RETURNING *
            )
            SELECT {CATALOG_SELECT_COLS}
            FROM upserted p
            LEFT JOIN upstream_servers s ON s.id = p.server_id"#
        );
        sqlx::query_as::<_, CatalogEntry>(sqlx::AssertSqlSafe(&*sql))
            .bind(provider)                // $1
            .bind(model)                   // $2
            .bind(sqlx::types::Json(&rates)) // $3
            .bind(req.context_window)       // $4
            .bind(req.max_output_tokens)    // $5
            .bind(req.supports_caching)     // $6
            .bind(req.supports_reasoning)   // $7
            .bind(req.supports_vision)      // $8
            .bind(req.supports_function_calling) // $9
            .bind(req.supports_audio_input) // $10
            .bind(req.supports_audio_output) // $11
            .bind(req.supports_video_input) // $12
            .bind(req.supports_pdf_input)   // $13
            .bind(req.supports_response_schema) // $14
            .bind(req.supports_system_messages) // $15
            .bind(&req.deprecation_date)    // $16
            .bind(&req.model_type)          // $17
            .bind(req.output_vector_size)   // $18
            .bind(db.tenant_uuid())         // $19
            .fetch_one(db.conn())
            .await
    }
    .map_err(catalog_db_error)?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/catalog",
    tag = "Model Catalog",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of catalog entries", body = TotalPage<CatalogEntry>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_catalog(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<CatalogEntry>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM model_catalog WHERE NOT suppressed")
        .fetch_one(db.conn())
        .await
        .map_err(catalog_db_error)?;
    let sql = format!(
        r#"SELECT {CATALOG_SELECT_COLS}
           FROM model_catalog p
           LEFT JOIN upstream_servers s ON s.id = p.server_id
           WHERE NOT p.suppressed
           ORDER BY p.server_id IS NULL, s.name, p.provider, p.model
           LIMIT $1 OFFSET $2"#
    );
    let rows = sqlx::query_as::<_, CatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(catalog_db_error)?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/catalog/{id}",
    tag = "Model Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    responses(
        (status = 200, description = "Catalog entry", body = CatalogEntry),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<CatalogEntry>, ApiError> {
    let sql = format!(
        r#"SELECT {CATALOG_SELECT_COLS}
           FROM model_catalog p
           LEFT JOIN upstream_servers s ON s.id = p.server_id
           WHERE p.id = $1 AND NOT p.suppressed"#
    );
    let row = sqlx::query_as::<_, CatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(catalog_db_error)?
        .ok_or(ApiError::not_found("catalog entry not found", ApiErrorCode::CatalogEntryNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/catalog/{id}",
    tag = "Model Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    request_body = UpdateCatalogEntry,
    responses(
        (status = 200, description = "Updated catalog entry", body = CatalogEntry),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 404, description = "Catalog entry not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCatalogEntry>,
) -> Result<Json<CatalogEntry>, ApiError> {
    if let Some(rates) = &req.rates {
        validate_rates(rates)?;
    }

    let sql = format!(
        r#"WITH updated AS (
            UPDATE model_catalog SET
                rates = COALESCE($2, rates),
                model_type = COALESCE($3, model_type),
                context_window = CASE WHEN $4 THEN $5 ELSE context_window END,
                max_output_tokens = CASE WHEN $6 THEN $7 ELSE max_output_tokens END,
                supports_caching = CASE WHEN $8 THEN $9 ELSE supports_caching END,
                supports_reasoning = CASE WHEN $10 THEN $11 ELSE supports_reasoning END,
                supports_vision = CASE WHEN $12 THEN $13 ELSE supports_vision END,
                supports_function_calling = CASE WHEN $14 THEN $15 ELSE supports_function_calling END,
                supports_audio_input = CASE WHEN $16 THEN $17 ELSE supports_audio_input END,
                supports_audio_output = CASE WHEN $18 THEN $19 ELSE supports_audio_output END,
                supports_video_input = CASE WHEN $20 THEN $21 ELSE supports_video_input END,
                supports_pdf_input = CASE WHEN $22 THEN $23 ELSE supports_pdf_input END,
                supports_response_schema = CASE WHEN $24 THEN $25 ELSE supports_response_schema END,
                supports_system_messages = CASE WHEN $26 THEN $27 ELSE supports_system_messages END,
                output_vector_size = CASE WHEN $28 THEN $29 ELSE output_vector_size END,
                deprecation_date = CASE WHEN $30 THEN $31 ELSE deprecation_date END,
                is_builtin = false,
                updated_at = NOW()
            -- A deleted builtin is a suppressed tombstone: it reads as absent, so
            -- it is not edited either.
            WHERE id = $1 AND NOT suppressed
            RETURNING *
        )
        SELECT {CATALOG_SELECT_COLS}
        FROM updated p
        LEFT JOIN upstream_servers s ON s.id = p.server_id"#
    );

    let row = sqlx::query_as::<_, CatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)                           // $1
        // The whole map, replaced as one atom: an omitted `rates` leaves the
        // stored quote alone, and a supplied one replaces every unit in it. A
        // per-unit merge would let a row hold two providers' numbers at once.
        .bind(req.rates.as_ref().map(sqlx::types::Json)) // $2
        .bind(&req.model_type)              // $3
        .bind(req.context_window.is_some()).bind(req.context_window.flatten()) // $4, $5
        .bind(req.max_output_tokens.is_some()).bind(req.max_output_tokens.flatten()) // $6, $7
        .bind(req.supports_caching.is_some()).bind(req.supports_caching.flatten()) // $8, $9
        .bind(req.supports_reasoning.is_some()).bind(req.supports_reasoning.flatten()) // $10, $11
        .bind(req.supports_vision.is_some()).bind(req.supports_vision.flatten()) // $12, $13
        .bind(req.supports_function_calling.is_some()).bind(req.supports_function_calling.flatten()) // $14, $15
        .bind(req.supports_audio_input.is_some()).bind(req.supports_audio_input.flatten()) // $16, $17
        .bind(req.supports_audio_output.is_some()).bind(req.supports_audio_output.flatten()) // $18, $19
        .bind(req.supports_video_input.is_some()).bind(req.supports_video_input.flatten()) // $20, $21
        .bind(req.supports_pdf_input.is_some()).bind(req.supports_pdf_input.flatten()) // $22, $23
        .bind(req.supports_response_schema.is_some()).bind(req.supports_response_schema.flatten()) // $24, $25
        .bind(req.supports_system_messages.is_some()).bind(req.supports_system_messages.flatten()) // $26, $27
        .bind(req.output_vector_size.is_some()).bind(req.output_vector_size.flatten()) // $28, $29
        .bind(req.deprecation_date.is_some()).bind(req.deprecation_date.as_ref().and_then(|v| v.as_deref())) // $30, $31
        .fetch_optional(db.conn())
        .await
        .map_err(catalog_db_error)?
        .ok_or(ApiError::not_found("catalog entry not found", ApiErrorCode::CatalogEntryNotFound))?;

    // No write-back into upstream_models: inheritance is live, so a NULL column
    // on a linked/matched model already resolves to this catalog row at read time.
    // The config push below rebuilds edge snapshots with the new catalog values.
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/catalog/{id}",
    tag = "Model Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    responses(
        (status = 200, description = "Catalog entry deleted", body = ActionResponse),
        (status = 404, description = "Catalog entry not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // A row that came from the seed — edited or not — is soft-deleted
    // (suppressed) so seed-sync won't resurrect it on restart; a user-created
    // entry is hard-deleted. An already-deleted row answers 404, as a read does
    // — including the loser of two concurrent deletes, which waits on the row
    // lock and then finds it suppressed or gone.
    let mut tx = db.conn().begin().await.map_err(catalog_db_error)?;
    let seeded: Option<bool> =
        sqlx::query_scalar("SELECT seeded FROM model_catalog WHERE id = $1 AND NOT suppressed FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(catalog_db_error)?;
    let Some(seeded) = seeded else {
        return Err(ApiError::not_found("catalog entry not found", ApiErrorCode::CatalogEntryNotFound));
    };
    let models_unlinked = unlink_models(&mut tx, &[id]).await?;
    let sql = if seeded {
        "UPDATE model_catalog SET suppressed = true, updated_at = NOW() WHERE id = $1"
    } else {
        "DELETE FROM model_catalog WHERE id = $1"
    };
    sqlx::query(sql).bind(id).execute(&mut *tx).await.map_err(catalog_db_error)?;
    tx.commit().await.map_err(catalog_db_error)?;
    Ok(Json(ActionResponse::ok().with_impact(ActionImpact {
        models_unlinked: Some(models_unlinked),
        ..ActionImpact::default()
    })))
}

/// Unlink every upstream model whose explicit catalog link names one of `ids`,
/// answering how many — run by every catalog removal, before it removes. A hard
/// delete would clear the link through the foreign key anyway, but a suppressed
/// row keeps its id, and the catalog join honours a link as stated, so one left
/// on it would resolve the model to nothing — no capabilities and no price.
///
/// The caller holds the entries' row locks (`FOR UPDATE`), and a link write
/// share-locks its entry first ([`require_live_entries`]): a link that committed
/// while the removal waited is read here, since this runs as its own statement
/// after the lock was granted, and one that arrives later finds the entry gone.
async fn unlink_models(conn: &mut Scoped, ids: &[Uuid]) -> Result<u64, ApiError> {
    sqlx::query("UPDATE upstream_models SET catalog_model_id = NULL WHERE catalog_model_id = ANY($1)")
        .bind(ids)
        .execute(conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(catalog_db_error)
}

/// Refuse a model's catalog links to entries that are not live rows of this
/// tenant: absent, another tenant's (RLS hides it), or deleted (suppressed).
/// The catalog join honours a link as stated, so a dead one would resolve the
/// model to nothing — no capabilities, unknown price.
///
/// `FOR SHARE`, in id order, holds each entry live until the link commits, so a
/// removal waits and then unlinks (see [`unlink_models`]); removals lock in id
/// order too, so the two never deadlock. Call it before writing the model row.
pub(crate) async fn require_live_entries(conn: &mut Scoped, ids: &[Uuid]) -> Result<(), ApiError> {
    let mut wanted: Vec<Uuid> = ids.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    if wanted.is_empty() {
        return Ok(());
    }
    let live: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM model_catalog WHERE id = ANY($1) AND NOT suppressed ORDER BY id FOR SHARE",
    )
    .bind(&wanted)
    .fetch_all(conn)
    .await
    .map_err(catalog_db_error)?;
    if live.len() == wanted.len() {
        Ok(())
    } else {
        Err(ApiError::not_found("catalog entry not found", ApiErrorCode::CatalogEntryNotFound))
    }
}

// ── Bulk operations ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct CatalogBulkResult {
    pub removed: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reseeded: Option<i64>,
    /// Upstream models whose explicit link named a removed entry, unlinked so
    /// they auto-match again.
    pub models_unlinked: u64,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/catalog/actions/remove-seeded",
    tag = "Model Catalog",
    responses(
        (status = 200, description = "Seeded entries removed", body = CatalogBulkResult),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_all_seeded(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
) -> Result<Json<CatalogBulkResult>, ApiError> {

    // Soft-delete every builtin the admin has not customised — a customised
    // entry is theirs, and the console promises to keep it: a suppressed row is
    // skipped by seed-sync, so the builtins stay removed across restart without
    // a tombstone. Lock them in id order first (as a link write does), unlink
    // their models, suppress.
    let mut tx = db.conn().begin().await.map_err(catalog_db_error)?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM model_catalog WHERE is_builtin AND NOT suppressed ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(catalog_db_error)?;
    let models_unlinked = unlink_models(&mut tx, &ids).await?;
    sqlx::query("UPDATE model_catalog SET suppressed = true, updated_at = NOW() WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(catalog_db_error)?;
    tx.commit().await.map_err(catalog_db_error)?;
    let removed = ids.len() as i64;
    let summary = CatalogBulkResult {
        removed,
        reseeded: None,
        models_unlinked,
    };
    audit_sink.record(None::<&CatalogBulkResult>, Some(&summary));
    Ok(Json(summary))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/catalog/actions/reset",
    tag = "Model Catalog",
    responses(
        (status = 200, description = "Catalog reset and reseeded", body = CatalogBulkResult),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_catalog(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
) -> Result<Json<CatalogBulkResult>, ApiError> {
    let tid = db.tenant_uuid();

    // Reset wipes the catalog then re-seeds builtins fresh, atomically. Dropping
    // every row clears any suppressed soft-deletes, so re-seed restores the full
    // builtin set.
    // The loader reads an unreadable or invalid seed as no entries: a reset
    // that re-seeded nothing would leave the tenant with an empty catalog, so
    // it refuses before touching anything.
    let loader = crate::seed_loader::SeedLoader::new();
    if loader.load_catalog().is_empty() {
        tracing::error!("reset catalog: the shipped catalog yielded no entries; keeping the current catalog");
        return Err(ApiError::internal("failed to reset catalog"));
    }

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin reset catalog tx: {e}");
        ApiError::internal("internal error")
    })?;

    // Delete every catalog entry there is now, locked in id order (as a link
    // write does), unlinking and counting their models first; an entry
    // created meanwhile is not this reset's.
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM model_catalog ORDER BY id FOR UPDATE")
        .fetch_all(&mut *tx)
        .await
        .map_err(catalog_db_error)?;
    let models_unlinked = unlink_models(&mut tx, &ids).await?;
    let result = sqlx::query("DELETE FROM model_catalog WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(catalog_db_error)?;
    let removed = result.rows_affected() as i64;

    // Re-seed catalog from seed files.
    // A failed re-seed aborts the whole reset: `tx` is dropped without a commit,
    // so the DELETE above rolls back too and the caller keeps its catalog rather
    // than being left with a partially re-seeded one.
    let reseeded = crate::seed_scripts::sync_catalog(tid, &mut tx, &loader)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: reseed");
            ApiError::internal("failed to reset catalog")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("commit reset catalog tx: {e}");
        ApiError::internal("internal error")
    })?;
    let summary = CatalogBulkResult {
        removed,
        reseeded: Some(reseeded.try_into().unwrap_or(0)),
        models_unlinked,
    };
    audit_sink.record(None::<&CatalogBulkResult>, Some(&summary));
    Ok(Json(summary))
}

fn catalog_db_error(e: sqlx::Error) -> ApiError {
    tracing::error!("catalog: {e}");
    super::db_read_error(&e, "database unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::pricing::{Currency, Tier, Unit};
    use std::collections::BTreeMap;

    fn rates_with(unit: Unit, rate: Rate) -> Rates {
        Rates::from_units(BTreeMap::from([(unit, rate)]), Currency::USD)
    }

    #[test]
    fn an_empty_map_is_a_legitimate_capabilities_only_entry() {
        assert!(validate_rates(&Rates::unknown()).is_ok());
    }

    #[test]
    fn a_zero_rate_is_accepted_because_free_is_not_unknown() {
        assert!(validate_rates(&rates_with(Unit::InputToken, Rate::Flat(0.0))).is_ok());
    }

    #[test]
    fn a_negative_flat_rate_is_rejected() {
        let err = validate_rates(&rates_with(Unit::OutputToken, Rate::Flat(-1.0)))
            .expect_err("a negative rate would credit the tenant on every request");
        assert_eq!(err.code, ApiErrorCode::PriceNegative);
    }

    #[test]
    fn a_non_finite_rate_is_rejected() {
        assert!(validate_rates(&rates_with(Unit::InputToken, Rate::Flat(f64::INFINITY))).is_err());
        assert!(validate_rates(&rates_with(Unit::InputToken, Rate::Flat(f64::NAN))).is_err());
    }

    #[test]
    fn a_negative_tier_is_rejected_even_when_the_base_rate_is_sound() {
        // The base rate alone reads as valid — only the step table is bad, and
        // it is the one that applies to every long-context request.
        let tiered = Rate::Tiered {
            rate: 3.0,
            tiers: vec![Tier {
                above: 128_000,
                rate: -6.0,
            }],
        };
        assert!(validate_rates(&rates_with(Unit::InputToken, tiered)).is_err());
    }
}
