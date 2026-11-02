//! Model presets — named invocation profiles attached to a real upstream model.
//!
//! A preset is a partial request body authored in the bound model's own native
//! protocol (`upstream_api_format`). The proxy force-merges it onto the already
//! translated upstream body (see `streamscope_core::proxy::json_merge`), so the
//! same physical model can be invoked many ways ("think" / "non-think" /
//! "default"). One model has many presets + exactly one default; a downstream
//! route selects one via `preset_id` (NULL = the model's default).


use axum::extract::Path;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage};
use crate::db::tenant::{Scoped, TenantConn};

#[derive(Serialize, ToSchema, sqlx::FromRow, Clone)]
pub struct PresetResponse {
    pub id: Uuid,
    pub model_id: Uuid,
    pub name: String,
    pub is_default: bool,
    /// Native partial request body in the model's protocol vocabulary.
    #[schema(value_type = Object)]
    pub settings: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreatePresetRequest {
    pub name: String,
    /// Native partial request body. Validated against the model's resolved
    /// protocol + capability ceiling. Defaults to `{}` (passthrough).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub settings: serde_json::Value,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdatePresetRequest {
    pub name: Option<String>,
    #[serde(default)]
    /// The preset fragment in the target model's native protocol, merged after translation; replaces the stored one.
    #[schema(value_type = Object)]
    pub settings: Option<serde_json::Value>,
}

/// The model's resolved native protocol + output ceiling, for validation.
struct ModelInvocationContext {
    api_format: Option<String>,
    max_output_tokens: Option<i32>,
    /// The server's scheduling dialect. With one set, the request's priority is
    /// the GATEWAY's to state — a preset that also set it would be silently
    /// overwritten on every request.
    scheduling_dialect: String,
}

async fn load_model_context(
    conn: &mut Scoped,
    tenant_id: Uuid,
    model_id: Uuid,
) -> Result<ModelInvocationContext, ApiError> {
    let row: Option<(Option<String>, Option<i32>, String)> = sqlx::query_as(sqlx::AssertSqlSafe(
        &*crate::routes::with_catalog_join(
        concat!(r#"SELECT COALESCE(m.upstream_api_format, s.upstream_api_format),
                  "#, resolved_max_output_sql!("m", "c"), r#",
                  s.scheduling_dialect
           FROM upstream_models m
           JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
           WHERE m.id = $1 AND m.tenant_id = $2"#),
            "m",
            "s",
        ),
    ))
    .bind(model_id)
    .bind(tenant_id)
    .fetch_optional(conn)
    .await
    .map_err(|e| {
        tracing::error!("load model context: {e}");
        ApiError::internal("Failed to load model")
    })?;
    let (api_format, max_output_tokens, scheduling_dialect) =
        row.ok_or_else(|| ApiError::not_found("Model not found", ApiErrorCode::ModelNotFound))?;
    Ok(ModelInvocationContext { api_format, max_output_tokens, scheduling_dialect })
}

/// Validate a preset's native settings fragment against the model's resolved
/// protocol and output ceiling. The fragment is authored in the upstream's own
/// vocabulary, so this range-checks the well-known sampling fields wherever they
/// appear (top level + the Gemini `generationConfig` group) and rejects an
/// out-of-range value or a max-output that exceeds the model's ceiling.
fn validate_preset_settings(
    settings: &serde_json::Value,
    ctx: &ModelInvocationContext,
) -> Result<(), ApiError> {
    let serde_json::Value::Object(top) = settings else {
        return Err(ApiError::bad_request("Preset settings must be a JSON object")
            .code(ApiErrorCode::PresetSettingsInvalid));
    };

    // A preset tunes HOW a model is invoked (sampling/reasoning), never WHAT is
    // sent. Reject structural keys: force-merging them would break proxy
    // invariants — `stream` desyncs the response parser, `model` makes the
    // upstream disagree with the audited model, and the conversation/tooling keys
    // would replace the request the client actually sent.
    const STRUCTURAL_KEYS: &[&str] = &[
        "model", "stream", "stream_options", "messages", "input", "contents",
        "tools", "tool_choice", "system",
    ];
    for key in STRUCTURAL_KEYS {
        if top.contains_key(*key) {
            return Err(ApiError::bad_request(format!(
                "Preset settings may not set the structural field '{key}' — presets only tune sampling/reasoning"
            ))
            .code(ApiErrorCode::PresetSettingsInvalid));
        }
    }

    // On a server that expresses priority classes, `priority` belongs to the
    // gateway: it is written per request from the caller's class and would
    // overwrite anything a preset put there. Refusing the write is the honest
    // answer — a field that is silently replaced on every request is worse than
    // one that was never accepted.
    if top.contains_key("priority") && ctx.scheduling_dialect != "none" {
        return Err(ApiError::bad_request(
            "This server expresses a request's priority class itself, so a preset may not set \
             'priority'. Turn the scheduling dialect off on the server to set it by hand.",
        )
        .code(ApiErrorCode::PresetSettingsInvalid));
    }

    // Gemini nests sampling under `generationConfig`; every other protocol keeps
    // it top-level. Validate whichever groups are present.
    let mut groups: Vec<&serde_json::Map<String, serde_json::Value>> = vec![top];
    if let Some(serde_json::Value::Object(gc)) = top.get("generationConfig") {
        groups.push(gc);
    }

    // Anthropic caps temperature at 1.0; OpenAI (chat/responses) and Gemini allow
    // up to 2.0. Validate against the model's resolved protocol so an out-of-range
    // value is caught at save time rather than as an upstream 400.
    let temp_max = if ctx.api_format.as_deref() == Some("anthropic_messages") { 1.0 } else { 2.0 };
    for group in groups {
        check_range(group, &["temperature"], 0.0, temp_max)?;
        check_range(group, &["top_p", "topP"], 0.0, 1.0)?;
        check_range(group, &["frequency_penalty", "frequencyPenalty"], -2.0, 2.0)?;
        check_range(group, &["presence_penalty", "presencePenalty"], -2.0, 2.0)?;
        // top_k / topK is a positive integer.
        for key in ["top_k", "topK"] {
            if let Some(v) = group.get(key)
                && let Some(n) = v.as_i64()
                && n < 1
            {
                return Err(ApiError::bad_request(format!("{key} must be >= 1"))
                    .code(ApiErrorCode::PresetSettingsInvalid));
            }
        }
        // Output-token fields must be positive and within the model's ceiling.
        for key in ["max_tokens", "max_completion_tokens", "max_output_tokens", "maxOutputTokens"] {
            if let Some(v) = group.get(key)
                && let Some(n) = v.as_i64()
            {
                if n <= 0 {
                    return Err(ApiError::bad_request(format!("{key} must be > 0"))
                        .code(ApiErrorCode::PresetSettingsInvalid));
                }
                if let Some(ceiling) = ctx.max_output_tokens
                    && n > ceiling as i64
                {
                    return Err(ApiError::bad_request(format!(
                        "{key} ({n}) exceeds the model's max output tokens ({ceiling})"
                    ))
                    .code(ApiErrorCode::PresetSettingsInvalid));
                }
            }
        }
    }

    // A reasoning model that rejects sampling (e.g. an OpenAI reasoning model that
    // forbids temperature) is enforced by the upstream itself — surfaced via the
    // normal upstream-error path, never silently dropped.
    Ok(())
}

fn check_range(
    group: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    lo: f64,
    hi: f64,
) -> Result<(), ApiError> {
    for key in keys {
        if let Some(v) = group.get(*key)
            && let Some(n) = v.as_f64()
            && (n < lo || n > hi)
        {
            return Err(ApiError::bad_request(format!("{key} must be between {lo} and {hi}"))
                .code(ApiErrorCode::PresetSettingsInvalid));
        }
    }
    Ok(())
}

/// Ensure a model carries a default preset. Idempotent: inserts the empty
/// (passthrough) `default` only when the model has no presets at all, so it is
/// safe to call from every model-creation path (manual create, sync discovery).
pub async fn ensure_default_preset(
    conn: &mut Scoped,
    tenant_id: Uuid,
    model_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO model_presets (tenant_id, model_id, name, is_default, settings)
           SELECT $1, $2, 'default', true, '{}'::jsonb
           WHERE NOT EXISTS (SELECT 1 FROM model_presets WHERE model_id = $2)"#,
    )
    .bind(tenant_id)
    .bind(model_id)
    .execute(conn)
    .await
    .map(|_| ())
}

async fn verify_model(conn: &mut Scoped, tenant_id: Uuid, model_id: Uuid) -> Result<(), ApiError> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM upstream_models WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(model_id)
    .bind(tenant_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("verify model: {e}");
        ApiError::internal("Failed to verify model")
    })?;
    if !ok {
        return Err(ApiError::not_found("Model not found", ApiErrorCode::ModelNotFound));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/upstream-models/{model_id}/presets",
    tag = "Model Presets",
    params(("model_id" = Uuid, Path, description = "Upstream model ID")),
    responses(
        (status = 200, description = "Presets for the model", body = OffsetPage<PresetResponse>),
        (status = 404, description = "Model not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_presets(
    mut db: TenantConn,
    Path(model_id): Path<Uuid>,
) -> Result<Json<OffsetPage<PresetResponse>>, ApiError> {
    let tenant_id = db.tenant_uuid();
    verify_model(db.conn(), tenant_id, model_id).await?;
    let rows = sqlx::query_as::<_, PresetResponse>(
        "SELECT id, model_id, name, is_default, settings, created_at FROM model_presets \
         WHERE model_id = $1 ORDER BY is_default DESC, name",
    )
    .bind(model_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list presets: {e}");
        ApiError::internal("Failed to list presets")
    })?;
    // A model's preset set is small and unpaged — the envelope is the API-rule
    // list shape, not a real page window.
    let limit = rows.len().max(1) as i64;
    Ok(Json(OffsetPage { items: rows, limit, offset: 0, has_more: false, scan_cut: false }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/upstream-models/{model_id}/presets",
    tag = "Model Presets",
    params(("model_id" = Uuid, Path, description = "Upstream model ID")),
    request_body = CreatePresetRequest,
    responses(
        (status = 201, description = "Preset created", body = PresetResponse),
        (status = 400, description = "Invalid settings or duplicate name", body = ApiErrorResponse),
        (status = 404, description = "Model not found", body = ApiErrorResponse),
        (status = 409, description = "A preset with this name already exists for the model", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_preset(
    mut db: TenantConn,
    Path(model_id): Path<Uuid>,
    Json(req): Json<CreatePresetRequest>,
) -> Result<(StatusCode, Json<PresetResponse>), ApiError> {
    let tenant_id = db.tenant_uuid();
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("Preset name is required").code(ApiErrorCode::PresetSettingsInvalid));
    }
    let ctx = load_model_context(db.conn(), tenant_id, model_id).await?;
    let settings = if req.settings.is_null() {
        serde_json::json!({})
    } else {
        req.settings
    };
    validate_preset_settings(&settings, &ctx)?;

    let row = sqlx::query_as::<_, PresetResponse>(
        r#"INSERT INTO model_presets (tenant_id, model_id, name, is_default, settings)
           VALUES ($1, $2, $3, false, $4)
           RETURNING id, model_id, name, is_default, settings, created_at"#,
    )
    .bind(tenant_id)
    .bind(model_id)
    .bind(&name)
    .bind(&settings)
    .fetch_one(db.conn())
    .await
    .map_err(|e| map_preset_db_err(e, "create preset"))?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}",
    tag = "Model Presets",
    params(
        ("model_id" = Uuid, Path, description = "Upstream model ID"),
        ("preset_id" = Uuid, Path, description = "Preset ID"),
    ),
    request_body = UpdatePresetRequest,
    responses(
        (status = 200, description = "Preset updated", body = PresetResponse),
        (status = 400, description = "Invalid settings or duplicate name", body = ApiErrorResponse),
        (status = 404, description = "Preset not found", body = ApiErrorResponse),
        (status = 409, description = "A preset with this name already exists for the model", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_preset(
    mut db: TenantConn,
    Path((model_id, preset_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdatePresetRequest>,
) -> Result<Json<PresetResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    if let Some(settings) = &req.settings {
        let ctx = load_model_context(db.conn(), tenant_id, model_id).await?;
        validate_preset_settings(settings, &ctx)?;
    }
    let name = req.name.map(|n| n.trim().to_string());
    if let Some(n) = &name
        && n.is_empty()
    {
        return Err(ApiError::bad_request("Preset name cannot be empty").code(ApiErrorCode::PresetSettingsInvalid));
    }

    let row = sqlx::query_as::<_, PresetResponse>(
        r#"UPDATE model_presets SET
               name = COALESCE($3, name),
               settings = COALESCE($4, settings)
           WHERE id = $1 AND model_id = $2 AND tenant_id = $5
           RETURNING id, model_id, name, is_default, settings, created_at"#,
    )
    .bind(preset_id)
    .bind(model_id)
    .bind(name.as_deref())
    .bind(req.settings.as_ref())
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| map_preset_db_err(e, "update preset"))?
    .ok_or_else(|| ApiError::not_found("Preset not found", ApiErrorCode::PresetNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}",
    tag = "Model Presets",
    params(
        ("model_id" = Uuid, Path, description = "Upstream model ID"),
        ("preset_id" = Uuid, Path, description = "Preset ID"),
    ),
    responses(
        (status = 200, description = "Preset deleted", body = super::ActionResponse),
        (status = 400, description = "Cannot delete the default preset", body = ApiErrorResponse),
        (status = 404, description = "Preset not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_preset(
    mut db: TenantConn,
    Path((model_id, preset_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<super::ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let is_default: Option<bool> = sqlx::query_scalar(
        "SELECT is_default FROM model_presets WHERE id = $1 AND model_id = $2 AND tenant_id = $3",
    )
    .bind(preset_id)
    .bind(model_id)
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete preset lookup: {e}");
        ApiError::internal("Failed to delete preset")
    })?;
    let is_default = is_default
        .ok_or_else(|| ApiError::not_found("Preset not found", ApiErrorCode::PresetNotFound))?;
    if is_default {
        return Err(ApiError::bad_request("The default preset cannot be deleted")
            .code(ApiErrorCode::PresetDefaultUndeletable));
    }

    // Dependent routes' preset_id is set NULL by the FK (ON DELETE SET NULL),
    // so they fall back to the model's default preset. If a route on this preset
    // shares an (provider, alias, model) with the default-preset route, that
    // SET NULL would collide on the route unique index — surface it as a typed
    // 400 instead of an opaque 500 so the operator can resolve the conflict.
    sqlx::query("DELETE FROM model_presets WHERE id = $1 AND model_id = $2 AND tenant_id = $3")
        .bind(preset_id)
        .bind(model_id)
        .bind(tenant_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(db) = &e
                && db.constraint() == Some("idx_downstream_routes_unique")
            {
                return ApiError::bad_request(
                    "A route on this preset would collide with the model's default-preset route under the same alias. Re-point or remove that route first.",
                )
                .code(ApiErrorCode::PresetSettingsInvalid);
            }
            tracing::error!("delete preset: {e}");
            ApiError::internal("Failed to delete preset")
        })?;

    Ok(Json(super::ActionResponse {
        ok: true,
        message: Some("Preset deleted; dependent routes fall back to the model default".into()),
        impact: None,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}/actions/set-default",
    tag = "Model Presets",
    params(
        ("model_id" = Uuid, Path, description = "Upstream model ID"),
        ("preset_id" = Uuid, Path, description = "Preset ID"),
    ),
    responses(
        (status = 200, description = "Default moved", body = super::ActionResponse),
        (status = 404, description = "Preset not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default_preset(
    mut db: TenantConn,
    Path((model_id, preset_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<super::ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("set-default begin: {e}");
        ApiError::internal("Failed to set default preset")
    })?;

    // Clear the current default first, then set the new one — the partial-unique
    // index allows only one `is_default` per model, so both writes happen in one
    // tx to never transiently violate it.
    sqlx::query("UPDATE model_presets SET is_default = false WHERE model_id = $1 AND tenant_id = $2 AND is_default")
        .bind(model_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clear default preset: {e}");
            ApiError::internal("Failed to set default preset")
        })?;

    let updated = sqlx::query(
        "UPDATE model_presets SET is_default = true WHERE id = $1 AND model_id = $2 AND tenant_id = $3",
    )
    .bind(preset_id)
    .bind(model_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("set default preset: {e}");
        ApiError::internal("Failed to set default preset")
    })?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("Preset not found", ApiErrorCode::PresetNotFound));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("set-default commit: {e}");
        ApiError::internal("Failed to set default preset")
    })?;
    Ok(Json(super::ActionResponse {
        ok: true,
        message: Some("Default preset updated".into()),
        impact: None,
    }))
}

/// Map a preset write error: the `(model_id, name)` unique index → a typed
/// name-taken code; everything else → a sanitized internal error.
fn map_preset_db_err(e: sqlx::Error, ctx: &str) -> ApiError {
    // Two unique indexes can fire: the per-model name, and the
    // one-default-per-model guard (race-only). Both are conflicts, and both are
    // reported as `PresetNameTaken` — the `constraint()` check exists to give the
    // NAME case its accurate message, not because the two get different answers.
    // The SQLSTATE gates the fallback so a renamed index degrades to a conflict
    // rather than to a 500.
    if let Some(db) = e.as_database_error()
        && db.constraint() == Some("idx_model_presets_name")
    {
        return ApiError::conflict("A preset with this name already exists for the model", ApiErrorCode::PresetNameTaken);
    }
    if super::is_unique_violation(&e) {
        return ApiError::conflict("A preset with these values already exists for the model", ApiErrorCode::PresetNameTaken);
    }
    tracing::error!("{ctx}: {e}");
    ApiError::internal("Failed to save preset")
}
