//! A2A gateway CRUD — the upstream agent registry behind `/a2a/<slug>`.
//!
//! An agent is registered by its card URL: the handler fetches the AgentCard
//! server-side (SSRF-guarded by the platform's `a2a` egress list), validates
//! that it declares a JSONRPC/1.0 interface, caches the raw card, and derives
//! the upstream endpoint from that interface. The proxy serves a rewritten
//! card per request — the cached copy is never exposed verbatim to A2A
//! clients (the admin UI does read it, for the skill catalog).


use streamscope_mcp_auth::ssrf::Egress;
use streamscope_mcp_auth::egress::Surface;
use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use streamscope_core::a2a::domain::{TextSlot, card_text_slots};
use streamscope_core::guardrail::{
    ClassifierConfig, GuardrailFailMode, ScanResult, classify_with_shared_client,
};

use super::mcp::{encrypt_mcp_credential, is_valid_slug};
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::{Scoped, TenantConn};

const VALID_AUTH_MODES: &[&str] = &["no_auth", "service_account"];

/// Registration-time cap on the cached card: the card rides every config
/// snapshot to every edge, so an unbounded card would bloat the sync wire.
const MAX_CARD_BYTES: usize = 256 * 1024;

/// What admin-api's A2A egress (agent-card fetches) may reach: an internal
/// address only when the platform's `a2a` egress list lists it, as the
/// gateway's agent calls.
pub(crate) const A2A_EGRESS: Egress = Egress::Surface(Surface::A2a);

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct A2aAgentRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub slug: String,
    pub agent_url: String,
    pub card_url: String,
    /// Cached upstream agent card (raw). Feeds the admin UI's card preview +
    /// skill catalog; the proxy rewrites it before serving to A2A clients.
    #[schema(value_type = Object)]
    pub agent_card: serde_json::Value,
    pub card_fetched_at: Option<DateTime<Utc>>,
    pub auth_mode: String,
    pub has_credential: bool,
    pub credential_header: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const ROW_COLUMNS: &str = r#"id, name, description, slug, agent_url, card_url, agent_card,
        card_fetched_at, auth_mode,
        (encrypted_credential IS NOT NULL) AS has_credential,
        credential_header, enabled, created_at, updated_at"#;

#[derive(Deserialize, ToSchema)]
pub struct CreateA2aAgent {
    pub name: String,
    /// Mount handle: the agent becomes reachable at `/a2a/<slug>`. Globally
    /// unique across tenants (the card endpoint is pre-auth).
    pub slug: String,
    /// The upstream card URL (typically
    /// `https://<agent-host>/.well-known/agent-card.json`). Fetched
    /// server-side at create time.
    pub card_url: String,
    pub description: Option<String>,
    /// `no_auth` (default) or `service_account`.
    pub auth_mode: Option<String>,
    /// Upstream credential plaintext (service_account only) — encrypted at
    /// rest, never returned.
    pub credential: Option<String>,
    /// Header carrying the credential upstream. Unset = `Authorization:
    /// Bearer <credential>`.
    pub credential_header: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateA2aAgent {
    pub name: Option<String>,
    /// Absent leaves it; `null` (or blank) clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub slug: Option<String>,
    /// Changing the card URL re-fetches and re-validates the card.
    pub card_url: Option<String>,
    pub auth_mode: Option<String>,
    /// Rotate the upstream credential (service_account only).
    pub credential: Option<String>,
    /// Absent leaves it; `null` (or blank) clears it back to the default header.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub credential_header: Option<Option<String>>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct A2aAgentListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ---------------------------------------------------------------------------
// Card fetch + validation
// ---------------------------------------------------------------------------

/// Fetched-and-validated upstream card: the raw JSON plus the JSONRPC/1.0
/// endpoint it declares.
struct FetchedCard {
    card: serde_json::Value,
    agent_url: String,
}

async fn fetch_and_validate_card(card_url: &str) -> Result<FetchedCard, ApiError> {
    let egress = A2A_EGRESS;
    // `fetch_json` refuses plain http to anything but a listed private address.
    let bytes = super::mcp_discovery::fetch_json(card_url, egress)
        .await
        .map_err(|e| {
            ApiError::bad_request(format!("failed to fetch agent card: {e}"))
                .code(ApiErrorCode::A2aAgentCardInvalid)
        })?;
    if bytes.len() > MAX_CARD_BYTES {
        return Err(ApiError::bad_request(format!(
            "agent card exceeds the {} KB cap",
            MAX_CARD_BYTES / 1024
        ))
        .code(ApiErrorCode::A2aAgentCardInvalid));
    }
    let mut card: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        ApiError::bad_request(format!("agent card is not valid JSON: {e}"))
            .code(ApiErrorCode::A2aAgentCardInvalid)
    })?;
    // The card is stored as jsonb, which refuses U+0000; scrubbed before any
    // field of it is read, so what is validated is what is stored.
    streamscope_core::pg_text::scrub_nul_json(&mut card);
    let iface = streamscope_core::a2a::card::extract_jsonrpc_interface(&card).ok_or_else(|| {
        ApiError::bad_request(
            "agent card declares no JSONRPC protocol-version 1.0 interface \
             (supportedInterfaces)",
        )
        .code(ApiErrorCode::A2aAgentCardInvalid)
    })?;
    if !iface.url.starts_with("http://") && !iface.url.starts_with("https://") {
        return Err(ApiError::bad_request(
            "agent card's JSONRPC interface URL is not http(s)",
        )
        .code(ApiErrorCode::A2aAgentCardInvalid));
    }
    // The gateway sends the agent's credential to this URL on every call, so
    // plain http only to listed private addresses — proven now, any failure to
    // prove it (a refusal, a name that does not resolve yet) refused; the
    // gateway re-proves it on every call, pinned to what it resolved.
    if !iface.url.starts_with("https://")
        && streamscope_mcp_auth::ssrf::resolve_and_pin_https_or_listed(&iface.url, egress).await.is_err()
    {
        return Err(ApiError::bad_request(
            "agent card's JSONRPC interface URL must be https, unless it is a private address on the platform's a2a egress list",
        )
        .code(ApiErrorCode::A2aAgentCardInvalid));
    }
    Ok(FetchedCard {
        card,
        agent_url: iface.url,
    })
}

/// Refuse admission to a fetched card whose prose the tenant's **default**
/// guardrail profile flags — evaluated over the same slot inventory the proxy
/// screens ([`card_text_slots`]), so the two surfaces can't drift.
///
/// The screen runs HERE, at ingestion, because the card's serve path is
/// pre-auth (`GET /a2a/<slug>/.well-known/agent-card.json` — no key, so no
/// workspace, so no per-request profile to resolve) and internet-facing (a
/// per-request classifier call there would be a DoS vector). Screening where
/// the card enters the system means every consumer — the pre-auth GET, the
/// config snapshot, the admin skill catalog — serves screened-or-rejected
/// data by construction.
///
/// Admission is binary: observe-vs-enforce governs *traffic* (pass and
/// badge), but a stored config artifact has no badge channel, and a flagged
/// card would be served pre-auth from the cache to every client — so an
/// active default policy rejects a flagged card outright in either mode.
/// Prose the classifier could not FULLY scan (window-cap truncation) is
/// rejected too: accepting it would make padding past the window cap a
/// trivial bypass. Guardrail inert (disabled / no classifier) ⇒ the card
/// passes unscreened, the same posture every other surface has. A classifier
/// error honors the profile's `fail_mode` (open → accept + warn, closed →
/// reject).
async fn screen_card(
    conn: &mut Scoped,
    tenant_id: Uuid,
    card: &serde_json::Value,
) -> Result<(), ApiError> {
    let settings = super::guardrail::load_default_resolved(conn, tenant_id).await?;
    let Some(cfg) = ClassifierConfig::from_settings(&settings) else {
        return Ok(());
    };
    let slots = card_text_slots(card);
    let prose: Vec<&TextSlot> = slots.iter().filter(|s| s.prose).collect();
    if prose.is_empty() {
        return Ok(());
    }
    let texts: Vec<&str> = prose.iter().map(|s| s.text.as_str()).collect();
    // A card is third-party content the gateway fetched, so it draws on the
    // content cap — the same budget a fetched page gets. Card prose is short in
    // practice; the higher cap only means an unusually verbose (but honest) card
    // is screened in full rather than rejected as unscannable.
    let max_windows = cfg.max_windows_content;
    // The classifier may sit behind a CA a super-admin uploaded: read it fresh
    // on this replica, as every user-triggered outbound call here does.
    crate::custom_ca::refresh_from_conn(conn).await;
    match classify_with_shared_client(cfg, &texts, max_windows).await {
        Ok(results) => card_screen_decision(&prose, &results),
        Err(e) => match settings.fail_mode {
            GuardrailFailMode::Open => {
                tracing::warn!(
                    error = %e,
                    "agent-card guardrail classifier error (fail-open — card accepted unscreened)"
                );
                Ok(())
            }
            GuardrailFailMode::Closed => Err(ApiError::bad_request(
                "agent card could not be screened (guardrail classifier unavailable) \
                 and the default guardrail profile fails closed",
            )
            .code(ApiErrorCode::A2aAgentCardRejected)),
        },
    }
}

/// Pure admission decision over the classifier's per-slot verdicts: any
/// flagged slot, or any non-empty slot the classifier did not fully cover,
/// rejects the card with the offending pointers named (capped — the admin
/// needs to find the field, not read the whole card back).
fn card_screen_decision(prose: &[&TextSlot], results: &[ScanResult]) -> Result<(), ApiError> {
    const MAX_NAMED: usize = 5;
    let mut flagged: Vec<String> = Vec::new();
    let mut unscanned: Vec<&str> = Vec::new();
    for (slot, r) in prose.iter().zip(results) {
        if r.verdict.flagged {
            flagged.push(format!(
                "{} ({}, confidence {:.2})",
                slot.pointer,
                r.verdict.category.badge_str(),
                r.verdict.confidence
            ));
        } else if !r.fully_scanned && !slot.text.trim().is_empty() {
            unscanned.push(&slot.pointer);
        }
    }
    let overflow = |n: usize| {
        if n > MAX_NAMED {
            format!(" (+{} more)", n - MAX_NAMED)
        } else {
            String::new()
        }
    };
    if !flagged.is_empty() {
        let shown = flagged[..flagged.len().min(MAX_NAMED)].join(", ");
        return Err(ApiError::bad_request(format!(
            "agent card rejected by the default guardrail profile: {shown}{}",
            overflow(flagged.len())
        ))
        .code(ApiErrorCode::A2aAgentCardRejected));
    }
    if !unscanned.is_empty() {
        let shown = unscanned[..unscanned.len().min(MAX_NAMED)].join(", ");
        return Err(ApiError::bad_request(format!(
            "agent card rejected: guardrail could not fully scan {shown}{} \
             (field exceeds the scan window cap)",
            overflow(unscanned.len())
        ))
        .code(ApiErrorCode::A2aAgentCardRejected));
    }
    Ok(())
}

fn validate_auth_mode(mode: &str) -> Result<(), ApiError> {
    if !VALID_AUTH_MODES.contains(&mode) {
        return Err(ApiError::bad_request(
            "auth_mode must be one of: no_auth, service_account",
        ));
    }
    Ok(())
}

/// service_account requires a credential (on create); a credential with
/// `no_auth` is meaningless and refused — same contract as the MCP upstream.
fn validate_credential_shape(
    auth_mode: &str,
    credential: Option<&str>,
    is_create: bool,
) -> Result<(), ApiError> {
    match auth_mode {
        "service_account" => {
            if is_create && credential.is_none_or(str::is_empty) {
                return Err(ApiError::bad_request(
                    "auth_mode service_account requires a credential",
                )
                .code(ApiErrorCode::A2aCredentialRequired));
            }
        }
        _ => {
            if credential.is_some_and(|c| !c.is_empty()) {
                return Err(ApiError::bad_request(
                    "credential is only meaningful with auth_mode service_account",
                )
                .code(ApiErrorCode::A2aCredentialNotAllowed));
            }
        }
    }
    Ok(())
}

fn map_insert_error(e: sqlx::Error, action: &str) -> ApiError {
    // Two different constraints mean two different answers here — a taken slug
    // is a conflict, a malformed one is a bad request — so this asks WHICH via
    // the structured `constraint()` rather than by matching the driver's error
    // text. The SQLSTATE gates the conflict fallback, so a renamed index still
    // reads as a conflict instead of collapsing to a 500.
    let constraint = e.as_database_error().and_then(|d| d.constraint()).unwrap_or_default();
    if constraint == "idx_a2a_agents_slug_global" || super::is_unique_violation(&e) {
        ApiError::conflict("an A2A agent with this slug already exists", ApiErrorCode::A2aAgentSlugTaken)
    } else if constraint == "chk_a2a_slug_format" {
        ApiError::bad_request("slug must match ^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$")
            .code(ApiErrorCode::A2aAgentSlugInvalid)
    } else {
        tracing::error!("{action} a2a_upstream_agents: {e}");
        ApiError::internal("failed to save A2A agent")
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/agents",
    tag = "A2A Agents",
    params(A2aAgentListQuery),
    responses(
        (status = 200, description = "Paginated list of A2A upstream agents", body = TotalPage<A2aAgentRow>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_a2a_agents(
    mut db: TenantConn,
    Query(query): Query<A2aAgentListQuery>,
) -> Result<Json<TotalPage<A2aAgentRow>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM a2a_upstream_agents")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count a2a_upstream_agents: {e}");
            ApiError::internal("failed to list A2A agents")
        })?;
    let rows = sqlx::query_as::<_, A2aAgentRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {ROW_COLUMNS} FROM a2a_upstream_agents ORDER BY slug LIMIT $1 OFFSET $2"
    )))
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list a2a_upstream_agents: {e}");
        ApiError::internal("failed to list A2A agents")
    })?;
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/agents/{id}",
    tag = "A2A Agents",
    params(("id" = Uuid, Path, description = "Agent ID")),
    responses(
        (status = 200, description = "A2A upstream agent", body = A2aAgentRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_a2a_agent(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<A2aAgentRow>, ApiError> {
    fetch_agent(&mut db, id).await.map(Json)
}

async fn fetch_agent(db: &mut TenantConn, id: Uuid) -> Result<A2aAgentRow, ApiError> {
    sqlx::query_as::<_, A2aAgentRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {ROW_COLUMNS} FROM a2a_upstream_agents WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get a2a_upstream_agent: {e}");
        ApiError::internal("failed to fetch A2A agent")
    })?
    .ok_or_else(|| ApiError::not_found("A2A agent not found", ApiErrorCode::A2aAgentNotFound))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/a2a/agents",
    tag = "A2A Agents",
    request_body = CreateA2aAgent,
    responses(
        (status = 201, description = "Created", body = A2aAgentRow),
        (status = 400, description = "Invalid request or unusable agent card", body = ApiErrorResponse),
        (status = 409, description = "Slug taken", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_a2a_agent(
    mut db: TenantConn,
    Json(body): Json<CreateA2aAgent>,
) -> Result<(StatusCode, Json<A2aAgentRow>), ApiError> {
    if !is_valid_slug(&body.slug) {
        return Err(ApiError::bad_request("invalid slug").code(ApiErrorCode::A2aAgentSlugInvalid));
    }
    let auth_mode = body.auth_mode.as_deref().unwrap_or("no_auth");
    validate_auth_mode(auth_mode)?;
    validate_credential_shape(auth_mode, body.credential.as_deref(), true)?;
    let fetched = fetch_and_validate_card(&body.card_url).await?;
    let tenant_id = db.tenant_uuid();
    screen_card(db.conn(), tenant_id, &fetched.card).await?;
    let encrypted_credential = encrypt_mcp_credential(body.credential.as_deref())?;
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let credential_header = body
        .credential_header
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let row = sqlx::query_as::<_, A2aAgentRow>(sqlx::AssertSqlSafe(format!(
        r#"INSERT INTO a2a_upstream_agents
               (tenant_id, name, description, slug, agent_url, card_url, agent_card,
                card_fetched_at, auth_mode, encrypted_credential, credential_header, enabled)
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9, $10, $11)
           RETURNING {ROW_COLUMNS}"#
    )))
    .bind(db.tenant_uuid())
    .bind(&body.name)
    .bind(description)
    .bind(&body.slug)
    .bind(&fetched.agent_url)
    .bind(&body.card_url)
    .bind(&fetched.card)
    .bind(auth_mode)
    .bind(encrypted_credential)
    .bind(credential_header)
    .bind(body.enabled.unwrap_or(true))
    .fetch_one(db.conn())
    .await
    .map_err(|e| map_insert_error(e, "create"))?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/a2a/agents/{id}",
    tag = "A2A Agents",
    params(("id" = Uuid, Path, description = "Agent ID")),
    request_body = UpdateA2aAgent,
    responses(
        (status = 200, description = "Updated", body = A2aAgentRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Slug taken", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_a2a_agent(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateA2aAgent>,
) -> Result<Json<A2aAgentRow>, ApiError> {
    if let Some(slug) = &body.slug
        && !is_valid_slug(slug)
    {
        return Err(ApiError::bad_request("invalid slug").code(ApiErrorCode::A2aAgentSlugInvalid));
    }
    let current = fetch_agent(&mut db, id).await?;
    let auth_mode = body.auth_mode.as_deref().unwrap_or(&current.auth_mode);
    validate_auth_mode(auth_mode)?;
    validate_credential_shape(auth_mode, body.credential.as_deref(), false)?;
    // service_account needs a credential from somewhere: either kept from the
    // row or supplied in this PATCH.
    if auth_mode == "service_account"
        && !current.has_credential
        && body.credential.as_deref().is_none_or(str::is_empty)
    {
        return Err(ApiError::bad_request(
            "auth_mode service_account requires a credential",
        )
        .code(ApiErrorCode::A2aCredentialRequired));
    }

    // A changed card URL re-fetches + re-validates; the derived endpoint and
    // cached card move together (never a URL pointing at one agent with a
    // card cached from another).
    let refreshed = match body.card_url.as_deref().filter(|u| **u != current.card_url) {
        Some(new_url) => Some((new_url.to_string(), fetch_and_validate_card(new_url).await?)),
        None => None,
    };
    if let Some((_, fetched)) = &refreshed {
        let tenant_id = db.tenant_uuid();
        screen_card(db.conn(), tenant_id, &fetched.card).await?;
    }
    // Switching to no_auth clears the stored credential (it is meaningless
    // there and keeping it would silently re-arm on a later mode flip).
    let clear_credential = auth_mode == "no_auth" && current.auth_mode != "no_auth";
    let encrypted_credential = encrypt_mcp_credential(body.credential.as_deref())?;
    // Three-state: outer `None` leaves the column, `Some(None)` clears it. A
    // blank value clears too — a form's empty field means "none".
    let blank_is_clear = |v: &Option<Option<String>>| {
        v.as_ref()
            .map(|inner| inner.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
    };
    let description = blank_is_clear(&body.description);
    let credential_header = blank_is_clear(&body.credential_header);

    let row = sqlx::query_as::<_, A2aAgentRow>(sqlx::AssertSqlSafe(format!(
        r#"UPDATE a2a_upstream_agents SET
               name = COALESCE($2, name),
               description = CASE WHEN $13 THEN $3 ELSE description END,
               slug = COALESCE($4, slug),
               agent_url = COALESCE($5, agent_url),
               card_url = COALESCE($6, card_url),
               agent_card = COALESCE($7, agent_card),
               card_fetched_at = CASE WHEN $7 IS NULL THEN card_fetched_at ELSE NOW() END,
               auth_mode = $8,
               encrypted_credential = CASE WHEN $11 THEN NULL
                                           ELSE COALESCE($9, encrypted_credential) END,
               credential_header = CASE WHEN $11 THEN NULL
                                        WHEN $14 THEN $10
                                        ELSE credential_header END,
               enabled = COALESCE($12, enabled),
               updated_at = NOW()
           WHERE id = $1
           RETURNING {ROW_COLUMNS}"#
    )))
    .bind(id)
    .bind(&body.name)
    .bind(description.clone().flatten())
    .bind(&body.slug)
    .bind(refreshed.as_ref().map(|(_, f)| f.agent_url.clone()))
    .bind(refreshed.as_ref().map(|(url, _)| url.clone()))
    .bind(refreshed.as_ref().map(|(_, f)| f.card.clone()))
    .bind(auth_mode)
    .bind(encrypted_credential)
    .bind(credential_header.clone().flatten())
    .bind(clear_credential)
    .bind(body.enabled)
    .bind(description.is_some()) // $13
    .bind(credential_header.is_some()) // $14
    .fetch_optional(db.conn())
    .await
    .map_err(|e| map_insert_error(e, "update"))?
    .ok_or_else(|| ApiError::not_found("A2A agent not found", ApiErrorCode::A2aAgentNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/a2a/agents/{id}",
    tag = "A2A Agents",
    params(("id" = Uuid, Path, description = "Agent ID")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_a2a_agent(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let result = sqlx::query("DELETE FROM a2a_upstream_agents WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete a2a_upstream_agent: {e}");
            ApiError::internal("failed to delete A2A agent")
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("A2A agent not found", ApiErrorCode::A2aAgentNotFound));
    }
    Ok(Json(ActionResponse::ok().with_message("A2A agent deleted")))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/a2a/agents/{id}/actions/refresh-card",
    tag = "A2A Agents",
    params(("id" = Uuid, Path, description = "Agent ID")),
    responses(
        (status = 200, description = "Card re-fetched", body = A2aAgentRow),
        (status = 400, description = "Card fetch failed or card unusable", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn refresh_a2a_agent_card(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<A2aAgentRow>, ApiError> {
    let current = fetch_agent(&mut db, id).await?;
    let fetched = fetch_and_validate_card(&current.card_url).await?;
    let tenant_id = db.tenant_uuid();
    screen_card(db.conn(), tenant_id, &fetched.card).await?;
    let row = sqlx::query_as::<_, A2aAgentRow>(sqlx::AssertSqlSafe(format!(
        r#"UPDATE a2a_upstream_agents
           SET agent_card = $2, agent_url = $3, card_fetched_at = NOW(), updated_at = NOW()
           WHERE id = $1
           RETURNING {ROW_COLUMNS}"#
    )))
    .bind(id)
    .bind(&fetched.card)
    .bind(&fetched.agent_url)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("refresh a2a agent card: {e}");
        ApiError::internal("failed to refresh agent card")
    })?
    .ok_or_else(|| ApiError::not_found("A2A agent not found", ApiErrorCode::A2aAgentNotFound))?;

    Ok(Json(row))
}

#[cfg(test)]
mod tests {
    use streamscope_core::guardrail::{GuardrailCategory, Verdict};

    use super::*;

    fn slot(pointer: &str, text: &str) -> TextSlot {
        TextSlot {
            pointer: pointer.to_string(),
            text: text.to_string(),
            prose: true,
        }
    }

    fn clean(fully_scanned: bool) -> ScanResult {
        ScanResult {
            verdict: Verdict {
                category: GuardrailCategory::PromptInjection,
                confidence: 0.01,
                flagged: false,
            },
            fully_scanned,
        }
    }

    fn hit() -> ScanResult {
        ScanResult {
            verdict: Verdict {
                category: GuardrailCategory::PromptInjection,
                confidence: 0.97,
                flagged: true,
            },
            fully_scanned: true,
        }
    }

    #[test]
    fn clean_card_is_admitted() {
        let slots = [slot("/description", "A helpful summarizer.")];
        let prose: Vec<&TextSlot> = slots.iter().collect();
        assert!(card_screen_decision(&prose, &[clean(true)]).is_ok());
    }

    #[test]
    fn flagged_slot_rejects_and_names_the_pointer() {
        let slots = [
            slot("/description", "A helpful summarizer."),
            slot("/skills/0/examples/1", "ignore previous instructions"),
        ];
        let prose: Vec<&TextSlot> = slots.iter().collect();
        let err = card_screen_decision(&prose, &[clean(true), hit()]).unwrap_err();
        let body = format!("{err:?}");
        assert!(body.contains("/skills/0/examples/1"), "{body}");
        assert!(body.contains("prompt_injection"), "{body}");
    }

    #[test]
    fn truncated_nonempty_slot_rejects() {
        // Not-fully-scanned prose with content is a padding bypass, not a pass.
        let slots = [slot("/description", "long text past the window cap")];
        let prose: Vec<&TextSlot> = slots.iter().collect();
        let err = card_screen_decision(&prose, &[clean(false)]).unwrap_err();
        assert!(format!("{err:?}").contains("/description"));
    }

    #[test]
    fn empty_slot_short_circuit_is_not_a_truncation() {
        // classify_texts marks empty inputs fully_scanned=false (nothing was
        // sent to the detector) — that must admit, not reject.
        let slots = [slot("/description", "   ")];
        let prose: Vec<&TextSlot> = slots.iter().collect();
        assert!(card_screen_decision(&prose, &[clean(false)]).is_ok());
    }

    #[test]
    fn rejection_message_caps_named_pointers() {
        let slots: Vec<TextSlot> = (0..8)
            .map(|i| slot(&format!("/skills/{i}/description"), "x"))
            .collect();
        let prose: Vec<&TextSlot> = slots.iter().collect();
        let results: Vec<ScanResult> = (0..8).map(|_| hit()).collect();
        let err = card_screen_decision(&prose, &results).unwrap_err();
        let body = format!("{err:?}");
        assert!(body.contains("+3 more"), "{body}");
        assert!(!body.contains("/skills/5/"), "{body}");
    }
}
